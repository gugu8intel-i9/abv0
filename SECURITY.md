# Security

## Reporting

Open an issue at <https://github.com/gugu8intel-i9/abv0/issues>, or run `abv0 report`
to open a prefilled one. If the issue is sensitive, mark it clearly at the top and omit
the exploit details until it is triaged.

## Threat model

`abv0` downloads and executes third-party binaries. Two inputs are treated as fully
hostile:

1. **The registry manifest** (`index.json`). It arrives over the network and controls
   package names, URLs, checksums and the paths written inside the store.
2. **Downloaded archives.** Member names, symlink targets, sizes and content are all
   attacker-controlled if the manifest or the upstream host is compromised.

Everything derived from those two inputs is validated before it reaches the
filesystem or a `exec` call.

---

## Findings fixed in 2.0.0

The audit covered the whole tree. Severities are the author's assessment for a user
running `abv0 install` against a compromised or malicious manifest.

### 1. Checksum mismatch did not stop an install — critical

`verifyChecksum` printed a warning on mismatch and installed the package anyway. The
code path was introduced as a "smart rolling release hash mismatch bypass", which
disabled integrity checking for every package, including ones with correct pinned
hashes.

**Fixed.** A mismatch is a hard failure: the archive is discarded, nothing is unpacked,
nothing is linked, and the process exits non-zero. A package with no pinned SHA-256 for
the requested platform is refused as well. `--allow-unverified` opts out for a single
invocation and prints an explicit warning when it does.

Verified: installing with a deliberately wrong hash aborts and leaves
`~/.abv0/bin` and `~/.abv0/store` empty.

### 2. Path traversal when extracting archives — critical

Two separate holes:

* `raw` extraction joined the manifest-supplied `bin_path` onto the store directory
  with no validation, so `"bin_path": "../../../../.ssh/authorized_keys"` wrote outside
  the store.
* Tar extraction did not validate member names, so a crafted archive could write
  anywhere the user could write (tar slip), and symlink members could point outside the
  extraction root so that a later member wrote through the link.

The v1.5.0 release notes claimed this was fixed. It was not.

**Fixed.** `src/safepath.zig` centralises validation. Every member name and every
manifest-supplied path must pass `isSafeRelPath`, which rejects `..` components,
absolute paths, Windows drive letters (`C:`), UNC prefixes (`\\`), backslash separators
and embedded NUL bytes. Symlink members additionally pass `symlinkStaysInside`, which
resolves the target relative to the link's own directory and rejects anything that
escapes. Zip extraction goes through `std.zip.extract`, which performs its own
rejection. Unit tests cover tar slip, absolute member names and symlink escape.

### 3. Uninitialized heap disclosure in the columnar registry — high

`ColumnarRegistry` read attacker-controlled `u16` lengths from the index file,
allocated that many bytes, and used the buffer without checking how many bytes were
actually read. A short file therefore exposed uninitialized heap memory as package
metadata. This was also claimed as fixed in v1.5.0 and was not.

**Fixed.** That code is gone; it had zero call sites. The replacement
(`src/abvindex.zig`) validates the magic, version and declared record count against the
real file size, bounds-checks every string-table offset and length against the mapping
before slicing, and rejects truncated, corrupt or out-of-range files. Tests cover each
of those rejections.

### 4. `abv0 update` was `curl | sh` — high

`update` shelled out to
`curl -sL https://raw.githubusercontent.com/.../install.sh | sh`, re-running a remote
installer as the invoking user on every update, with no verification of what was
fetched. Anyone able to influence that URL's content — including a compromised CDN
cache or an operator of a network path if the redirect chain were downgraded — got
arbitrary code execution.

**Fixed.** `update` now refreshes the registry index only. It downloads to a temporary
file, parses and validates it, and replaces the existing index only if the new one is
usable — so a corrupt download cannot brick the installation either. Upgrading the
`abv0` binary is a deliberate, separate action.

### 5. `curl` without `--fail`: error pages installed as binaries — high

Downloads ran `curl -sL -o` with no `--fail`, so an HTTP 404, a rate-limit body or a
captive-portal page was written to disk, checksummed (see finding 1: the mismatch was
ignored), marked executable and linked onto the user's `PATH`.

**Fixed.** All downloads use `--fail --proto '=https' --proto-redir '=https'` with
connect and total timeouts and bounded retries, so non-2xx responses are errors and a
redirect cannot downgrade to plaintext HTTP. As defence in depth, `looksLikeErrorPage`
sniffs the first bytes of every payload and rejects HTML/JSON where an archive was
expected.

### 6. Typosquat-to-RCE in dynamic installs — high

If a requested package was not in the registry, `installDynamic` searched the GitHub
API and installed the first repository whose name looked close enough, with no checksum
possible. A typo (`abv0 install ripgrpe`) or a name-similar repository published by an
attacker resulted in running their binary.

**Fixed.** Dynamic installation is opt-in behind `--allow-unverified`. Without it,
`abv0` explains why it is refusing. When enabled, the repository `full_name` is
validated, the URL is built with proper percent-encoding, only HTTPS asset URLs are
accepted, and the branch comes from the API's `default_branch` rather than a hardcoded
`refs/heads/master`.

### 7. Manifest fields were trusted verbatim — high

Package names, versions and `bin[]` entries from the manifest were used to build
filesystem paths and link names with no validation, so a hostile manifest could write
outside the store via the package *name* as well as via `bin_path`.

**Fixed.** `loadFromJsonFile` validates every record: names and versions must be safe
identifiers, `bin_path` and each `bin[]` entry must be a safe relative path, and every
URL must be HTTPS. Invalid packages are dropped individually — a single bad entry does
not deny service for the whole manifest — and the count of rejected packages is
available to the caller.

### 8. Denial of service via malformed manifests — medium

Parsing used `.?` on optional JSON lookups. A truncated manifest, an unexpected type, or
a GitHub rate-limit response (`{"message": "...", "documentation_url": "..."}`) panicked
the process.

**Fixed.** No unchecked unwraps remain on parsed input; every missing or wrongly typed
field produces a typed error. Tests feed the parser garbage bytes, truncated JSON, wrong
top-level types and rate-limit bodies.

### 9. Install lock was not a lock — medium

The "lock" wrote a text file and never took an OS lock, so two concurrent installs of
the same package interleaved their writes into the same store directory. A related race
let two processes starting on a fresh machine both write `index.json` in place, with one
reading the other's partial write.

**Fixed.** Installs take a real advisory file lock (`File.lock`/`unlock`) for the
duration. The manifest is published atomically: downloaded to a unique temporary name,
parsed, then renamed. Verified with 18 concurrent installs across fresh homes — zero
failures, correct result each time.

### 10. DMG images mounted writable — medium

macOS `.dmg` handling ran `hdiutil attach` without `-readonly` and without
`-nobrowse`, letting a crafted image's contents be modified during the copy and
surfacing the mount in Finder.

**Fixed.** `hdiutil attach -readonly -nobrowse -noverify -noautoopen` with an explicit
detach in all paths.

### 11. A 0-byte binary was published as a release — medium

`release/abv0-darwin-x86_64` was 0 bytes, and `install.sh` would `chmod 0700` it and
report "installed successfully". `release/abv0-linux-x86_64` was an unstripped debug
build. The installer also ran `curl` without `--fail`, never checked a checksum, and
wrote directly to the destination path so an interrupted download left a truncated
binary on the user's `PATH`.

**Fixed.** All six release artifacts are rebuilt as stripped `ReleaseFast` binaries and
published with `release/SHA256SUMS`. The installer verifies the checksum, rejects empty
files and non-executable payloads, runs the binary once before publishing it, and moves
it into place atomically. Every failure path installs nothing.

### 12. Overly permissive store directories — low

Store directories were created with the default mode and then fixed up by spawning
`chmod` subprocesses, leaving a window in which they were world-readable, and failing
silently if `chmod` was not on `PATH`.

**Fixed.** Directories are created and tightened in-process with `fchmod` (`0700` for
the root, `0600` for state files), with no window and no subprocess. On Windows, where
POSIX mode bits do not exist, the calls compile away.

### 13. Unbounded resource use — low

One OS thread was spawned per requested package with no limit, and the bundle parser
read whole files into memory with `readToEndAlloc`.

**Fixed.** The worker pool is capped at `min(CPUs, packages, 8)`. The bundle parser
streams line by line with a bounded line length and skips over-long lines with a
warning.

---

## Hardening summary

| Area | Control |
| :--- | :--- |
| Transport | HTTPS only, no protocol downgrade on redirect, `--fail`, bounded timeouts and retries |
| Integrity | SHA-256 enforced by default; unverifiable installs require an explicit flag |
| Extraction | Member-name validation, symlink-escape checks, no absolute or `..` paths, no drive letters or UNC |
| Manifest | Per-record validation, invalid records dropped, no panics on malformed input |
| Concurrency | Real advisory file locks, atomic temp-file-plus-rename publishes |
| Filesystem | `0700` store root, `0600` state files, set in-process without subprocesses |
| Binary index | Magic, version, size and every offset bounds-checked before dereference |
| Releases | Stripped release builds, published `SHA256SUMS`, installer verifies before publishing |

## Non-goals

`abv0` does not currently verify code signatures or provenance attestations for
upstream artifacts; it verifies that the bytes you received are the bytes the manifest
pins. Trust in the manifest itself is the remaining root of trust.
