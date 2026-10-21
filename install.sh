#!/bin/sh
# abv0 installer for Linux and macOS.
#
# Hardening notes (the previous version of this script had all of these bugs):
#   * curl ran without --fail, so a 404 HTML page was saved as "abv0", made
#     executable, and reported as a successful install;
#   * it never checked that the download was non-empty, so the 0-byte
#     abv0-darwin-x86_64 artifact installed "successfully";
#   * it never verified a checksum;
#   * it wrote directly to the final path, so an interrupted download left a
#     truncated binary behind;
#   * it allowed protocol downgrades on redirect.
set -eu

REPO="gugu8intel-i9/abv0"
REF="${ABV0_REF:-main}"
BASE="https://raw.githubusercontent.com/${REPO}/${REF}"

BIN_DIR="${ABV0_BIN_DIR:-$HOME/.abv0/bin}"
REG_DIR="${ABV0_REGISTRY_DIR:-$HOME/.abv0/registry}"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }

# BIN_DIR is written into shell profiles, so it must fit on one line.
NEWLINE='
'
case "${BIN_DIR}" in
    *"${NEWLINE}"*) die "ABV0_BIN_DIR must not contain newlines" ;;
esac

# Single-quote a value for POSIX sh, escaping embedded single quotes as '\''.
sh_quote() {
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

command -v curl >/dev/null 2>&1 || die "curl is required"

OS="$(uname -s)"
ARCH="$(uname -m)"

case "${OS}" in
    Linux)
        case "${ARCH}" in
            x86_64|amd64)   TARGET="abv0-linux-x86_64" ;;
            aarch64|arm64)  TARGET="abv0-linux-aarch64" ;;
            *) die "unsupported Linux architecture '${ARCH}'" ;;
        esac
        ;;
    Darwin)
        case "${ARCH}" in
            x86_64)         TARGET="abv0-darwin-x86_64" ;;
            arm64|aarch64)  TARGET="abv0-darwin-arm64" ;;
            *) die "unsupported macOS architecture '${ARCH}'" ;;
        esac
        ;;
    MINGW*|MSYS*|CYGWIN*)
        die "on Windows use install.ps1:
    irm https://raw.githubusercontent.com/${REPO}/${REF}/install.ps1 | iex"
        ;;
    *)
        die "unsupported operating system '${OS}'"
        ;;
esac

info "installing abv0 (${TARGET})"

# Only directories this run creates under the default ~/.abv0 are made private
# (0700). A custom ABV0_BIN_DIR / ABV0_REGISTRY_DIR, and anything that already
# exists, keeps the permissions it has.
DEFAULT_ROOT="${HOME}/.abv0"
for d in "${BIN_DIR}" "${REG_DIR}"; do
    case "${d}" in
        "${DEFAULT_ROOT}"/*) ;;
        *) continue ;;
    esac
    if [ ! -d "${d}" ]; then
        [ -d "${DEFAULT_ROOT}" ] || mkdir -m 0700 "${DEFAULT_ROOT}"
        mkdir -p "${d}"
        chmod 0700 "${d}"
    fi
done
mkdir -p "${BIN_DIR}" "${REG_DIR}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/abv0-install.XXXXXX")"
cleanup() { rm -rf "${TMP_DIR}"; }
trap cleanup EXIT INT TERM

# --fail            : a 404 is an error, not a file full of HTML
# --proto/=https    : refuse plaintext, including after a redirect
# --retry           : survive a flaky connection instead of truncating
fetch() {
    curl --fail --location --silent --show-error \
         --proto '=https' --proto-redir '=https' \
         --retry 3 --retry-delay 1 --connect-timeout 20 --max-time 300 \
         -o "$2" "$1"
}

info "downloading binary"
fetch "${BASE}/release/${TARGET}" "${TMP_DIR}/abv0" \
    || die "download failed: ${BASE}/release/${TARGET}"

[ -s "${TMP_DIR}/abv0" ] || die "downloaded binary is empty"

# Reject anything that is obviously not a program (an error page, an LFS
# pointer, a rate-limit JSON body).
case "$(head -c 4 "${TMP_DIR}/abv0" | od -An -c | tr -d ' \n')" in
    177ELF*|\\312\\376\\272\\276*|\\317\\372\\355\\376*|MZ*) ;;
    *) die "downloaded file is not an executable (the server may have returned an error page)" ;;
esac

info "verifying checksum"
if fetch "${BASE}/release/SHA256SUMS" "${TMP_DIR}/SHA256SUMS"; then
    EXPECTED="$(awk -v t="${TARGET}" '$2 == t {print $1}' "${TMP_DIR}/SHA256SUMS")"
    [ -n "${EXPECTED}" ] || die "no checksum published for ${TARGET}"

    if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL="$(sha256sum "${TMP_DIR}/abv0" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        ACTUAL="$(shasum -a 256 "${TMP_DIR}/abv0" | awk '{print $1}')"
    else
        if [ "${ABV0_ALLOW_UNVERIFIED:-0}" != "1" ]; then
            die "no sha256 tool found (need sha256sum or shasum); refusing to install an unverified binary
(set ABV0_ALLOW_UNVERIFIED=1 to override)"
        fi
        ACTUAL=""
        info "warning: no sha256 tool found; ABV0_ALLOW_UNVERIFIED=1, continuing unverified"
    fi

    if [ -n "${ACTUAL}" ] && [ "${ACTUAL}" != "${EXPECTED}" ]; then
        die "checksum mismatch
  expected ${EXPECTED}
  actual   ${ACTUAL}
Refusing to install."
    fi
elif [ "${ABV0_ALLOW_UNVERIFIED:-0}" = "1" ]; then
    info "warning: SHA256SUMS unavailable and ABV0_ALLOW_UNVERIFIED=1; continuing unverified"
else
    die "could not fetch SHA256SUMS; refusing to install an unverified binary
(set ABV0_ALLOW_UNVERIFIED=1 to override)"
fi

chmod 0755 "${TMP_DIR}/abv0"

# Sanity check before publishing: a binary that cannot report its own version
# is not one we should put on the user's PATH.
"${TMP_DIR}/abv0" version >/dev/null 2>&1 \
    || die "the downloaded binary did not run on this machine"

# Atomic publish: mv within the same filesystem replaces in one step, so a
# concurrent shell never sees a half-written abv0.
mv -f "${TMP_DIR}/abv0" "${BIN_DIR}/abv0"

info "fetching registry index"
if fetch "${BASE}/packages/index.json" "${TMP_DIR}/index.json" && [ -s "${TMP_DIR}/index.json" ]; then
    chmod 0644 "${TMP_DIR}/index.json"
    mv -f "${TMP_DIR}/index.json" "${REG_DIR}/index.json"
else
    info "warning: could not fetch the registry index; run 'abv0 update' later"
fi

info ""
info "abv0 installed to ${BIN_DIR}/abv0"
"${BIN_DIR}/abv0" version

# PATH advice. The old script edited ~/.zshrc *or* ~/.bashrc and claimed
# success either way; this one updates every profile it finds and always tells
# you what to do in the current shell.
PROFILE_UPDATED=0
for profile in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.profile"; do
    [ -f "${profile}" ] || continue
    if ! grep -q "\.abv0/bin" "${profile}" 2>/dev/null; then
        printf '\n# added by the abv0 installer\nexport PATH=%s:"$PATH"\n' "$(sh_quote "${BIN_DIR}")" >> "${profile}"
        info "added ${BIN_DIR} to ${profile}"
        PROFILE_UPDATED=1
    fi
done

info ""
if [ "${PROFILE_UPDATED}" -eq 1 ]; then
    info "open a new terminal, or run this in the current one:"
else
    info "add abv0 to your PATH:"
fi
info "    export PATH=$(sh_quote "${BIN_DIR}"):\$PATH"
info ""
info "then try:"
info "    abv0 list"
info "    abv0 install ripgrep"
