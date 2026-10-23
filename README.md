# abv0

**A fast, verifying package manager written in Zig. Linux, macOS and Windows.**

`abv0` installs prebuilt release binaries into a content-addressed store under `~/.abv0`,
then links them onto your `PATH`. There is no interpreter to boot, no formula DSL to
evaluate and no `git` clone in the hot path.

abv0 is independent of other package managers. Its catalog is built from the GitHub
releases of upstream projects and signed with abv0's own key. Any GitHub project's release
can also be installed directly with `gh:owner/repo`.

```bash
abv0 install ripgrep jq                  # verified, parallel
abv0 install gh:BurntSushi/ripgrep       # any GitHub release, verified
abv0 run ripgrep -- --help               # run without touching PATH
abv0 shell ripgrep                       # ephemeral subshell with just that package
abv0 browse                              # pick packages from a searchable list
```

**Desktop apps.** On macOS, apps such as Rectangle, VSCodium or Obsidian install into
`~/Applications`. On Windows, portable builds (KeePassXC, VSCodium, Notepad++, ShareX,
OBS Studio and others) unpack into abv0's store and get a Start Menu shortcut under
*abv0*, so they appear in Start and in search; no installer runs and no admin rights are
needed. `abv0 uninstall` removes the app and its shortcut.

`abv0 browse` opens the whole catalog in a full-screen list: type to search, arrow keys
(or PgUp/PgDn/Home/End) to move, Space or Tab to pick, Enter to install what you picked
(or the highlighted package), Esc to quit. Installed packages are marked with a tick.

---

## Install

**1. Run the installer.**

Linux / macOS (Terminal):

```bash
curl -fsSL https://raw.githubusercontent.com/gugu8intel-i9/abv0/main/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/gugu8intel-i9/abv0/main/install.ps1 | iex
```

**2. Open a new terminal window**, so the updated `PATH` takes effect. The installer
adds `~/.abv0/bin` to your shell profile; if it could not, it prints the line to add.

**3. Check it works:**

```bash
abv0 --version
abv0 doctor          # reports anything missing, such as PATH
```

**4. Install something:**

```bash
abv0 install ripgrep jq
```

To update later: `abv0 update && abv0 upgrade --all` for your programs, and
`abv0 self-update` for abv0 itself.

The installer downloads over HTTPS only, refuses protocol downgrades on redirect,
verifies the published SHA-256 from `release/SHA256SUMS`, checks the payload is
actually an executable, runs it once, and only then moves it into place. Any failure
leaves nothing installed. Set `ABV0_ALLOW_UNVERIFIED=1` to bypass checksum
verification (not recommended). If no SHA-256 tool is found, the installer stops unless
that variable is set.

The installers also download `packages/index.json.sig` and install it with the registry
index, signature first. They do not check the Ed25519 signature themselves. If the
signature cannot be downloaded, the index is not installed, and abv0 fetches and verifies
the manifest on its first run.

**From source** — requires [Zig 0.13.0](https://ziglang.org/):

```bash
git clone https://github.com/gugu8intel-i9/abv0
cd abv0
zig build -Doptimize=ReleaseFast
./zig-out/bin/abv0 --help
```

---

## Platform support

| Platform | Status | Linking strategy |
| :--- | :--- | :--- |
| macOS arm64 / x86_64 | supported | APFS `clonefile(2)`, falls back to hard link |
| Linux x86_64 / aarch64 | supported (static musl) | hard link, falls back to symlink |
| Windows x86_64 / arm64 | supported | launcher shim (`name.exe` + `name.shim`), so DLLs next to the program load |

CI installs real packages on Linux (x86_64, arm64), macOS 15 (arm64, x86_64) and Windows
x86_64 on every push. Building abv0 itself needs Zig 0.13.0, which cannot link on macOS 26;
build on macOS 15 or cross-compile (`zig build release`).

`zig build check` type-checks the whole codebase against all six targets, so a
Windows-only or macOS-only compile error fails on any machine.

---

## Usage

```
abv0 <command> [options] [arguments]
abv0 <command> --help        help for one command (same as: abv0 help <command>)
```

Common tasks:

```bash
abv0 install jq ripgrep            # install with dependencies, in parallel
abv0 install gh:BurntSushi/ripgrep # a GitHub project's release, no recipe needed
abv0 install --dry-run jq          # show what would happen; change nothing
abv0 list --installed              # versions in the store for this platform
abv0 outdated                      # installed packages with a newer version
abv0 upgrade                       # upgrade every outdated package
abv0 pin jq                        # hold jq at its installed version
abv0 which rg                      # which package owns the rg command
abv0 cleanup --dry-run             # old versions, stale temp files, stale cache
abv0 doctor                        # PATH, permissions and link problems
```

### Commands

```
PACKAGES
  install <pkg>...         Install packages and their dependencies (verified, in parallel)
  install gh:owner/repo    Install any GitHub project's release, verified (no recipe needed)
  browse                   Pick packages to install from a full-screen list
  uninstall <pkg>...       Remove packages and the links they created
  upgrade [--all|pkg]...   Upgrade outdated packages (keeps the previous version for rollback)
  outdated                 List packages with a newer version available (pinned ones marked)
  list [--installed]       List registry packages, or what is installed
  search [--online] <q>    Search the registry (and GitHub repositories with --online)
  info <pkg>               Show metadata, installed versions, size and linked bins
  deps [--tree] <pkg>      List what a package depends on
  uses <pkg>               List installed packages that depend on it
  leaves                   List installed packages nothing else depends on
  switch <pkg> <version>   Make an installed version the active one
  rollback <pkg>           Go back to the previously installed version
  home [--open] <pkg>      Print (or open) a package's homepage
  pin <pkg>                Hold a package at its installed version
  unpin <pkg>              Let upgrade update it again
  pinned                   List pinned packages
  which <bin>              Show which package owns a command

EXECUTION
  run <pkg> [-- args]      Run a package executable
  shell <pkg>...           Ephemeral subshell with only those packages

MANIFESTS
  bundle [install|dump]    Install from, or export to, a Brewfile
  migrate --from-brew-list F | --brewfile F
                           Map Homebrew package names to the catalog (--install installs them)
  update                   Refresh the registry index
  sync                     Recompile the local index and SQL export

MAINTENANCE
  doctor                   Diagnose PATH, permissions and links
  fix                      Repair broken links and permissions
  detect <pkg>             Scan every file of an installed package for malware patterns
  benchmark                Measure local store and index performance
  gc                       Remove temporary files and stale sandboxes
  cleanup                  Remove old versions (including rollback's), keeping the newest
  completions <shell>      Print a bash, zsh, fish or pwsh completion script
  self-update [--check]    Update abv0 from a signed release
  reset                    Uninstall everything
  report [--bug]           Open a prefilled GitHub issue
  version                  Print the version
  help [command]           This message, or help for one command
```

### GitHub installs

```bash
abv0 install gh:owner/repo            # the latest release
abv0 install gh:owner/repo@v1.2.3     # a pinned tag
abv0 install owner/repo               # the same as gh:owner/repo
```

- The release asset for this platform is chosen by name. Checksum files, signatures, SBOMs,
  source archives, debug builds and builds for another OS or architecture are not candidates.
- The archive is unpacked, the executables inside it are found automatically, and they are
  linked onto `PATH`.
- The asset is checked against GitHub's sha256 digest for it. If GitHub has no digest, abv0
  uses the release's checksum file (`checksums.txt`, `SHA256SUMS`, `<asset>.sha256` and
  similar). That file comes from the same release, so it is a weaker check: whoever can
  replace the asset can usually replace the file too. A mismatch installs nothing.
- An asset with neither a digest nor a checksum file is refused. `--allow-unverified` installs
  it anyway.
- Each install records `gh:owner/repo@tag` in `.abv0-source` in its store directory. `list`,
  `outdated`, `upgrade` and `uninstall` work for these installs.
- A bare name the registry does not know is not searched on GitHub. abv0 prints the `gh:`
  spelling to try instead.
- `GITHUB_TOKEN` or `GH_TOKEN` is optional. When set, it is sent to the GitHub API to raise
  the rate limit. Without one, GitHub allows 60 requests an hour.

### Options

| Option | Meaning |
| :--- | :--- |
| `--platform <tag>` | Target platform (default: this machine) |
| `-f, --file <path>` | Manifest path for `bundle` commands (default: `Brewfile`) |
| `-j, --jobs <n>` | Parallel install workers |
| `--registry <path>` | Use this manifest instead of the cached one. `<path>.sig` must verify. |
| `--allow-unsigned-manifest` | Skip the manifest signature and replay checks (UNSAFE) |
| `--allow-unverified` | Permit installs without a verified checksum |
| `--allow-suspicious` | Install a package even if the malware scan blocks it |
| `--micro-split` | Parallel ranged download for large assets |
| `--no-stream` | Download fully before unpacking (disables the streaming install) |
| `--force` | Overwrite files and replace conflicting bin links |
| `--dry-run` | Show what install, upgrade, uninstall, bundle or cleanup would do; change nothing |
| `--json` | Machine-readable output on stdout (`list`, `search`, `info`, `outdated`, `install`, `doctor`) |
| `--installed` | With `list`: show what is installed |
| `--bug`, `--malware` | With `report`: a bug report, or a suspicious-package report |
| `-q, --quiet` | Suppress progress lines (errors still print) |
| `-v, --verbose` | Also print URLs, store paths and timings per package |
| `--color=auto\|always\|never` | When to use colour (`--no-color` is the same as `never`) |
| `-h, --help` | Help for the command |
| `-V, --version` | Version |

`--dry-run` for `install`, `upgrade`, `uninstall`, `bundle install` and `cleanup` needs an
already-cached registry.

Cross-platform installs work from any host: `abv0 install --platform aarch64-macos jq`
fetches and stores the macOS build without linking it into your `PATH`.

### Exit codes

| Code | Meaning |
| :---: | :--- |
| 0 | success |
| 1 | the operation failed (a download, a check, or a package) |
| 2 | usage error (unknown command, option or argument) |

`abv0 search` with no matches prints `no packages match` and exits 0.

### Environment variables

| Variable | Effect |
| :--- | :--- |
| `ABV0_HOME` | Root of the abv0 tree, replacing `~/.abv0` |
| `ABV0_BIN_DIR` | Bin directory for links, replacing `<root>/bin` |
| `ABV0_REGISTRY_DIR` | Registry directory, replacing `<root>/registry` |
| `ABV0_REGISTRY_URL` | Manifest URL, for a mirror. Must be `https`. The manifest is still signature-checked. |
| `ABV0_NO_CACHE` | `1` stops abv0 keeping and reusing verified downloads in `<root>/cache` |
| `ABV0_CACHE_MAX` | Size cap of the download cache, such as `512M` or `4G` (default `2G`); least recently used entries go first |
| `ABV0_NO_DEDUPE` | `1` stops abv0 hard-linking identical files between installs through `<root>/cas` |
| `ABV0_DOWNLOADER` | `builtin`, `curl` or `auto` (the default). `builtin` never uses curl; `curl` never uses the built-in client. |
| `ABV0_SPLIT_MIN` | Smallest download fetched over several connections at once, in bytes (`8M`, `512k` and `1G` work too). Default 8 MiB. |
| `ABV0_CONNECTIONS` | Connections for a split download, 1 to 16. `1` turns splitting off. Unset, a download gets one connection per 4 MiB, up to 8. |
| `GITHUB_TOKEN`, `GH_TOKEN` | Optional GitHub token for API requests. `GITHUB_TOKEN` is read first. |
| `ABV0_NO_SCAN` | `1` turns off the install-time malware scan |
| `NO_COLOR` | Disables colour, as `--no-color` does |

The three path variables must be absolute, with no NUL bytes or line breaks. Anything
else is ignored. `install.sh` honours `ABV0_BIN_DIR` and `ABV0_REGISTRY_DIR`, and
`install.ps1` honours `ABV0_HOME`.

### Shell completion

`abv0 completions <bash|zsh|fish|pwsh>` prints a completion script to stdout.

```bash
# bash (bash-completion v2)
abv0 completions bash > ~/.local/share/bash-completion/completions/abv0
```

```bash
# zsh: ~/.zfunc must be on fpath before compinit runs in ~/.zshrc
abv0 completions zsh > ~/.zfunc/_abv0
```

```bash
# fish
abv0 completions fish > ~/.config/fish/completions/abv0.fish
```

```powershell
# PowerShell: add to $PROFILE
abv0 completions pwsh | Out-String | Invoke-Expression
```

---

## Performance

Measured on the development machine (2 vCPU, Linux x86_64, ReleaseFast static build).
Reproduce with `abv0 benchmark`; the wall-clock figures below are 30-run averages of
the whole process including spawn.

| Command | v1.5.0 (previously shipped) | v2.0.0 | Change |
| :--- | ---: | ---: | ---: |
| `abv0 help` | 4.91 ms | **0.50 ms** | 9.8× faster |
| `abv0 list` | 5.14 ms | **0.63 ms** | 8.2× faster |
| `abv0 outdated` | 4.92 ms | **0.74 ms** | 6.7× faster (and it now works — see below) |
| `abv0 install ripgrep jq` (cached) | — | **0.84 ms** | — |
| `abv0 install ripgrep` (cold, 2.3 MB download) | — | **257–296 ms** | — |

Internal micro-benchmarks (`abv0 benchmark`):

```
  registry lookup         100000 ops     1.119 ms       11.2 ns/op
  index build                 13 pkgs    0.107 ms
  index mmap load             13 pkgs    0.032 ms
  fastLink (hard link)       500 ops     1.755 ms        3.5 us/op
  sha256                       8 MiB     8.426 ms      949.5 MiB/s
```

Where the old startup time went: `Store.init` spawned three `chmod` subprocesses on
*every* invocation, including `abv0 help`. Permissions are now set in-process with
`fchmod`, the registry is only loaded by commands that need it, and the shipped Linux
binary is a stripped `ReleaseFast` static build (679 KB) rather than an unstripped
debug build (3.5 MB).

Other performance work in 2.0.0:

- **One pass over each archive.** Downloads used to be read three times (curl, then
  SHA-256, then a "deduplicated block store" that wrote a full second copy of every
  archive into `~/.abv0/blockstore` and never read it back). The block store is gone;
  hashing is a single streaming pass.
- **One directory walk per install**, not one per binary. Installing `ffmpeg`
  (3 executables) previously ran three full recursive walks.
- **Bounded worker pool.** Installs used to spawn one OS thread per package with no
  limit; a 50-line Brewfile meant 50 threads fighting for bandwidth. Now
  `min(CPUs, packages, 8)`.
- **Buffered stdout.** Output went through unbuffered `std.debug.print` to *stderr*,
  so `abv0 list | grep foo` printed nothing at all. Output is now buffered and on
  stdout, with ANSI colour only when the destination is a TTY (`NO_COLOR` respected).
- **No DOM parse of the manifest.** Loading used to build a full JSON `Value` tree and
  then duplicate every string, keeping two copies of the registry alive and freeing
  neither.

### Streaming install

For tar, tar.gz, tar.xz, tar.zst and single-binary packages, `abv0` does not wait for the download to finish
before it starts on the package:

1. The response is read into a pipe, by the built-in HTTPS client or, after a transport
   fallback, by curl.
2. The bytes are hashed with SHA-256 as they arrive.
3. They are decompressed and unpacked into a private staging folder in the store.
4. The digest is compared with the manifest. Only if it matches is the staging folder
   published into the store. A mismatch is a hard failure and the staging folder is
   deleted, so unverified bytes never reach the store.

zip, 7z and dmg archives need a seekable file, so they download first, as `--no-stream` does
for every package. Both transports apply the same rules: HTTPS only, each redirect hop
checked, a size cap and timeouts. The built-in client reads proxy settings from the
environment, with `NO_PROXY` applied, and loads the CA bundle from the system store,
`SSL_CERT_FILE` or `CURL_CA_BUNDLE`.

Measured on the development machine, before the built-in client was added: ten rounds
installing ripgrep, bat and jq, median
**346 ms** streamed against **404 ms** when downloading to a file first (about 14% less).
The gain comes from overlapping the hash and unpack with the download. It should grow on
slower links and larger packages, where more of the work overlaps; that has not been
measured.

---

## How it actually works

**Store layout**

```
~/.abv0/                                  (ABV0_HOME replaces this root)
  bin/                                    links onto your PATH (ABV0_BIN_DIR)
  store/<name>@<version>@<platform>/      unpacked package, read-only tree
  store/<...>/.abv0-source                gh: installs only: where the package came from
  store/states_wal/                       write-ahead log for crash recovery
  registry/index.json                     the manifest (ABV0_REGISTRY_DIR)
  registry/index.json.sha256              SHA-256 of the manifest abv0 last accepted
  registry/index.abv                      compiled binary index (mmap'ed)
  registry/last-updated-at                newest manifest updated_at accepted
  cache/sha256/<xx>/<sha256>              verified downloads, 0600, LRU-capped (ABV0_CACHE_MAX)
  cas/files/<sha256>[.<mode>]             files shared between installs by hard link
  net-fallback                            hosts the built-in HTTPS client failed on (24 h)
  state/pins                              pinned packages
  apps/                                   app bundles
  locks/                                  per-package and ownership locks
```

**Store folder names.** Each package is stored in `name@version@platform`. `@` is not
allowed in package names or versions, so the split is unambiguous. Earlier versions used
`name-version-platform`, which was ambiguous when a name contained `-`. Packages installed
that way show as not installed; reinstall them once. Their existing bin links are adopted.

**`index.abv` — a real memory-mapped index.** `abv0` compiles `index.json` into a flat
binary file: a header with a content stamp, a sorted fixed-width record array, and a
deduplicated string table. Lookups `mmap` the file and binary-search the records,
slicing strings directly out of the mapping with no parsing and no allocation. The
stamp is checked on load, so editing `index.json` transparently rebuilds the index.
Every offset is bounds-checked against the mapping before use, and a truncated, corrupt
or wrong-version file is rejected rather than dereferenced. On Windows, which has no
`mmap` in the Zig standard library without libc, the same file is read into a heap
buffer and used identically.

*(Before: `index.abv` was a 24-byte header containing no data, written and never read.)*

**Write-ahead log.** Each install appends fixed-width, CRC-32-checked records
(`begin`, `downloaded`, `verified`, `unpacked`, `linked`, `complete`) to an append-only
log. On the next run, an install that stopped before `complete` is detected and the
partial tree is cleaned up before retrying. A record torn by a crash mid-write fails its
CRC and is discarded, so recovery never reads half a record.

*(Before: the "state machine" called `createFile` on every transition, which truncates —
the log only ever held the most recent record, and nothing ever read it.)*

**Bloom filter.** Dependency resolution uses a real bit-array Bloom filter (64 KiB,
7 probes, Kirsch–Mitzenmacher double hashing) as a negative cache for the visited set,
persisted with a CRC and loaded atomically.

*(Before: a text file of `NODE_VISITED:` lines, truncated on every construction, queried
by scanning the whole file for a substring — O(n) per lookup, and it could never retain
state between runs.)*

**SQLite export.** `abv0 sync` writes `registry.sql`, a portable SQL dump with properly
escaped string literals, and materialises `registry.db` with the `sqlite3` CLI when one
is installed. If it is not installed, it says so instead of pretending.

*(Before: `registry.db` was a text file containing SQL statements, named `.db`.)*

---

## Catalog

The package list is generated from upstream projects. `catalog/sources.txt` names each
project, and `tools/build-catalog.zig` reads that project's GitHub releases to write
`packages/index.json`:

- For each of the six platforms it picks one release asset, pins the asset's SHA-256 from
  GitHub's digest or the release's checksum file, and finds the executables inside.
- It is incremental, reuses entries for unchanged versions, keeps the previous entry when a
  source fails, and writes deterministic output. It refuses to write when most sources fail
  or when the catalog would lose more than half its packages.
- A GitHub workflow runs it daily, signs the result with the maintainer's key, and commits
  it only when it changed.
- Software that is not on GitHub releases is listed in `catalog/manual.json`.

See [catalog/README.md](catalog/README.md) for the line format and the commands.

---

## Security

`abv0` treats the manifest and everything it downloads as hostile input. See
[SECURITY.md](SECURITY.md) for each finding, its severity and how it was fixed.

Behaviour you can rely on:

- **Every install is scanned for malware.** Before anything is linked, abv0 reads every
  file of the new package (about 5 ms for small tools) and checks it against rules that
  need several signs together: a dropper must download a file, make it executable in a
  temp folder *and* run it in the background; a stealer must collect several saved
  passwords or wallets *and* send them to a webhook. It also catches reverse shells,
  cryptominers, startup persistence (cron `@reboot`, macOS login items, Windows Run
  keys), `/etc/ld.so.preload` rootkits, and commands hidden in base64, which it decodes
  and scans. Script-only rules never judge compiled programs, which often carry such
  text as data. A match removes the package and fails the install; `--allow-suspicious`
  installs it anyway and `ABV0_NO_SCAN=1` turns the scan off. Weaker signs that ordinary
  tools also contain never block and are listed by `abv0 detect <pkg>`. Tested on about
  175 catalog packages (secret scanners, password managers and backup tools included)
  with no false blocks, and on a set of attack samples, all caught. It is a rule-based
  scan, not an antivirus: code written to evade it can.
- **The manifest is signed.** `update` and the first-run bootstrap download the manifest
  and `<url>.sig`, verify the Ed25519 signature against the public key compiled in from
  `keys/manifest.pub`, and only then use the file. The manifest's `updated_at` may not go
  back in time relative to the last one accepted, so an old signed manifest cannot be
  replayed. `--allow-unsigned-manifest` skips both checks and prints a warning.
- **A manifest on disk is not trusted by its presence.** abv0 records the SHA-256 of the
  manifest it accepted (`registry/index.json.sha256`). A file on disk is used only if its
  hash matches that record. Otherwise its `index.json.sig` is checked if one sits beside it,
  and if not, the manifest is downloaded again. Nothing is deleted first.
- **Checksums are enforced.** A SHA-256 mismatch aborts the install; nothing is
  unpacked and nothing is linked. A package with no pinned hash for your platform is
  refused. `--allow-unverified` opts out per invocation and says so loudly.
- **Archives cannot escape the store.** Every tar/zip member name is validated before
  extraction: `../` components, absolute paths, Windows drive letters, UNC prefixes and
  embedded NUL bytes are rejected. Every existing parent component is checked on disk,
  and a symlink may not walk through a link already present. Extraction stops at 4 GiB
  or 200,000 members, and setuid, setgid and sticky bits are cleared. A zip archive is
  checked entry by entry before the first byte is written. A name that is not a plain
  relative path, or that contains `:` or a backslash, refuses the whole archive. 7z names
  get the same check, and every header and file CRC must match.
- **Commands are owned.** abv0 records which package owns each bin link and app bundle.
  A package cannot take over a name it does not own, and reserved names (`abv0`, `sudo`,
  `ssh`, shells and similar) are refused. `--force` replaces a conflicting link.
- **Manifests are validated on load.** Non-HTTPS URLs, path traversal in `name`,
  `bin_path` or `bin[]`, duplicate and reserved names, and malformed records are dropped
  with the rest of the manifest still usable. A corrupt or truncated `index.json`
  produces an error, not a panic.
- **HTTPS only.** The built-in client and the curl fallback both accept only `https`, for
  the first URL and for every redirect hop. curl runs with `-q` (so `~/.curlrc` is ignored),
  `--fail --proto '=https' --proto-redir '=https'`, bounded timeouts and a 2 GiB download
  cap. URLs containing userinfo are rejected, so a 404 page cannot be saved as a binary
  and a redirect cannot downgrade to plaintext.
- **Tokens stay with their host.** The built-in client sends the GitHub API headers,
  including any token, only to the host of the original request. A redirect to another host
  does not receive them. When curl is used instead, headers go through a private file,
  never the command line.
- **GitHub installs are verified or refused.** A `gh:` install is checked against GitHub's
  digest or the release's checksum file. An asset with neither is refused unless
  `--allow-unverified` is given. A bare name the registry lacks is never searched on GitHub.
- **Upgrades install first.** The new version is installed before older versions are
  removed, so a failed upgrade keeps the working one.

Report a vulnerability by opening an issue, or use `abv0 report --malware <pkg>` for a
suspicious package.

---

## Signing the package list (maintainers)

The manifest is trusted only if its detached Ed25519 signature verifies against
`keys/manifest.pub`, which is compiled into every `abv0` binary. Signing happens offline.

```bash
zig build sign-tool                                      # installs sign-manifest to zig-out/bin
zig-out/bin/sign-manifest keygen <secret-key> keys/manifest.pub
zig-out/bin/sign-manifest sign <secret-key> packages/index.json   # writes packages/index.json.sig
zig-out/bin/sign-manifest verify keys/manifest.pub packages/index.json
```

- Keep the secret key out of git. Only the public key is committed.
- Commit `keys/manifest.pub`, `packages/index.json` and `packages/index.json.sig` together.
  Every change to the manifest needs a new signature.
- `keys/manifest.pub` is the maintainer's key. If it is ever replaced, re-sign the
  manifest and the release checksums with the new secret key, update the
  `ABV0_MANIFEST_KEY` repository secret, and rebuild the binaries.
- Releases also need `release/SHA256SUMS.sig`, a signature over `release/SHA256SUMS`
  made the same way (`sign-manifest sign <secret-key> release/SHA256SUMS`). `abv0
  self-update` refuses a release whose checksums do not verify. The **Release**
  workflow (Actions → Release → Run workflow) does all of this: it rebuilds `release/`,
  regenerates and signs `SHA256SUMS` with the `ABV0_MANIFEST_KEY` secret, and commits it.
- `-Dmanifest-pubkey=<hex>` at build time embeds a different public key instead of
  `keys/manifest.pub`.
- The catalog in `packages/index.json` is rebuilt and signed daily by a GitHub workflow,
  using the `ABV0_MANIFEST_KEY` secret. See [catalog/README.md](catalog/README.md) for how
  the catalog is built and how to set up that secret.

---

## Development

```bash
zig build                       # debug build
zig build test                  # 255 test blocks across src/*.zig and tools/*.zig
zig build check                 # type-check Linux, macOS and Windows targets
zig build release               # stripped ReleaseFast binaries for all 6 targets
zig build sign-tool             # the sign-manifest CLI
zig build catalog-tool          # the build-catalog CLI (catalog/sources.txt -> packages/index.json)
zig build -Doptimize=ReleaseFast
```

The test suite covers path-traversal and tar-slip rejection, symlink escape, hostile
manifests, signature and replay checks, the on-disk manifest hash check, checksum
enforcement, GitHub release parsing and asset choice, digest and checksum-file
verification, zip entry-name rejection, 7z extraction, the built-in client's redirect
rules, index corruption and truncation, WAL torn-record recovery, Bloom filter
false-negative freedom, version comparison, argument parsing and the streaming install.
`src/main.zig` imports every module at comptime, so `zig build test` runs all of them.

Fixtures used only by these tests live in `tests/fixtures/`. They are not registry
packages.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md), including migration notes for this release.

---

## License

See [LICENSE](LICENSE).
