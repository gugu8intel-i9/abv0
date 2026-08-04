# abv0

**A fast, verifying package manager written in Zig. Linux, macOS and Windows.**

`abv0` installs prebuilt release binaries from a signed-by-checksum manifest into a
content-addressed store under `~/.abv0`, then links them onto your `PATH`. There is no
interpreter to boot, no formula DSL to evaluate and no `git` clone in the hot path.

```bash
abv0 install ripgrep jq      # verified, parallel
abv0 run ripgrep -- --help   # run without touching PATH
abv0 shell ripgrep           # ephemeral subshell with just that package
```

---

## Install

**Linux / macOS**

```bash
curl -fsSL https://raw.githubusercontent.com/gugu8intel-i9/abv0/main/install.sh | sh
```

**Windows** (PowerShell)

```powershell
irm https://raw.githubusercontent.com/gugu8intel-i9/abv0/main/install.ps1 | iex
```

The installer downloads over HTTPS only, refuses protocol downgrades on redirect,
verifies the published SHA-256 from `release/SHA256SUMS`, checks the payload is
actually an executable, runs it once, and only then moves it into place. Any failure
leaves nothing installed. Set `ABV0_ALLOW_UNVERIFIED=1` to bypass checksum
verification (not recommended).

**From source** — requires [Zig 0.13.0](https://ziglang.org/):

```bash
git clone https://github.com/gugu8intel-i9/abv0
cd abv0
zig build -Doptimize=ReleaseFast
./zig-out/bin/abv0 --help
```

Add `~/.abv0/bin` to your `PATH` (`abv0 doctor` will tell you if it is missing).

---

## Platform support

| Platform | Status | Linking strategy |
| :--- | :--- | :--- |
| macOS arm64 / x86_64 | supported | APFS `clonefile(2)`, falls back to hard link |
| Linux x86_64 / aarch64 | supported (static musl) | hard link, falls back to symlink |
| Windows x86_64 / arm64 | supported | `CreateHardLinkW`, falls back to copy |

`zig build check` type-checks the whole codebase against all six targets, so a
Windows-only or macOS-only compile error fails on any machine.

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

---

## How it actually works

**Store layout**

```
~/.abv0/
  bin/                     links onto your PATH
  store/<pkg>-<ver>-<platform>/    unpacked package, read-only tree
  store/states_wal/        write-ahead log for crash recovery
  registry/index.json      the manifest
  registry/index.abv       compiled binary index (mmap'ed)
  locks/                   per-package install locks
```

**`index.abv` — a real memory-mapped index.** `abv0` compiles `index.json` into a flat
binary file: a header with a content stamp, a sorted fixed-width record array, and a
deduplicated string table. Lookups `mmap` the file and binary-search the records,
slicing strings directly out of the mapping with no parsing and no allocation. The
stamp (source size + mtime) is checked on load, so editing `index.json` transparently
rebuilds the index. Every offset is bounds-checked against the mapping before use, and
a truncated, corrupt or wrong-version file is rejected rather than dereferenced. On
Windows, which has no `mmap` in the Zig standard library without libc, the same file is
read into a heap buffer and used identically.

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

## Security

`abv0` treats the manifest and everything it downloads as hostile input. See
[SECURITY.md](SECURITY.md) for the full list of vulnerabilities found and fixed in
2.0.0, including three that previous releases claimed to have fixed but had not.

Behaviour you can rely on:

- **Checksums are enforced.** A SHA-256 mismatch aborts the install; nothing is
  unpacked and nothing is linked. A package with no pinned hash for your platform is
  refused. `--allow-unverified` opts out per invocation and says so loudly.
- **Archives cannot escape the store.** Every tar/zip member name is validated before
  extraction: `../` components, absolute paths, Windows drive letters, UNC prefixes and
  embedded NUL bytes are rejected, and symlink targets that resolve outside the
  extraction root are skipped.
- **Manifests are validated on load.** Non-HTTPS URLs, path traversal in `name`,
  `bin_path` or `bin[]`, and malformed records are dropped with the rest of the manifest
  still usable. A corrupt or truncated `index.json` produces an error, not a panic.
- **HTTPS only.** `curl` runs with `--fail --proto '=https' --proto-redir '=https'` and
  bounded timeouts, so a 404 page can never be saved as a binary and a redirect cannot
  downgrade to plaintext.
- **Unverifiable dynamic installs are opt-in.** Installing a package that is not in the
  registry searches GitHub and cannot check a checksum, so it now requires
  `--allow-unverified`.

Report a vulnerability by opening an issue, or use `abv0 report`.

---

## Commands

```
PACKAGES
  install <pkg>...     Install packages (verified, in parallel)
  uninstall <pkg>      Remove a package and its links
  upgrade [pkg]...     Upgrade outdated packages
  outdated             List packages with a newer version available
  list                 List registry packages
  search <query>       Search the registry
  info <pkg>           Show package metadata

EXECUTION
  run <pkg> [-- args]  Run a package executable
  shell <pkg>...       Ephemeral subshell with only those packages

MANIFESTS
  bundle [install]     Install from a Brewfile
  bundle dump          Export installed packages to a Brewfile
  update               Refresh the registry index
  sync                 Recompile the local index and SQL export

MAINTENANCE
  doctor               Diagnose PATH, permissions and links
  fix                  Repair broken links and permissions
  detect <pkg>         Scan an installed package for malware patterns
  benchmark            Measure local store and index performance
  gc                   Remove temporary files and stale sandboxes
  reset                Uninstall everything
  report [--bug]       Open a prefilled GitHub issue

OPTIONS
  --platform <tag>     Target platform (default: x86_64-linux)
  -f, --file <path>    Manifest path for bundle commands
  -j, --jobs <n>       Parallel install workers
  --allow-unverified   Permit installs without a verified checksum
  --micro-split        Parallel ranged download for large assets
  --force              Overwrite output files
  --json               Machine-readable output (list, info, outdated)
  --no-color           Disable colour
  -h, --help           This message
  -V, --version        Version
```

Cross-platform installs work from any host: `abv0 install --platform aarch64-macos jq`
fetches and stores the macOS build without linking it into your `PATH`.

---

## Development

```bash
zig build                       # debug build
zig build test                  # 61 unit tests
zig build check                 # type-check Linux, macOS and Windows targets
zig build release               # stripped ReleaseFast binaries for all 6 targets
zig build -Doptimize=ReleaseFast
```

The test suite covers path-traversal and tar-slip rejection, symlink escape, hostile
manifests, checksum enforcement, index corruption and truncation, WAL torn-record
recovery, Bloom filter false-negative freedom, version comparison and argument parsing.
`src/main.zig` imports every module at comptime, so `zig build test` runs all of them.

---

## Changelog

### v2.0.0 — correctness, security and cross-platform release

The tree did not compile before this release; `zig build` failed on a syntax error in
`src/main.zig`, so none of the previously shipped binaries corresponded to the source.

* **Fixed: the build.** Removed an orphaned function body, added missing imports.
* **Fixed: `abv0 outdated` never reported anything.** Its body was
  `if (try self.isInstalled(...)) {}` — an empty block — so it always printed
  "everything is up to date". It now compares installed versions against the registry
  with numeric-aware version ordering.
* **Fixed: `abv0 run` / `abv0 shell` for most packages.** Both looked for an executable
  named after the *package* (`bin/ripgrep`) instead of the executables the package
  actually provides (`bin/rg`).
* **Fixed: data race in parallel installs.** Every worker thread shared one
  `ArenaAllocator`, which is not thread-safe. Each install now gets its own arena over a
  thread-safe base allocator, and installs are bounded to `min(CPUs, packages, 8)`.
* **Fixed: crashes on malformed input.** Unchecked `.?` unwraps on parsed JSON panicked
  on a truncated manifest or a GitHub rate-limit response.
* **Fixed: concurrent first runs corrupted the registry.** Two `abv0` processes starting
  on a fresh machine both wrote `index.json` in place; one read the other's partial
  write. The manifest is now downloaded to a temporary file, parsed, and renamed into
  place atomically.
* **Fixed: `installDynamic` hardcoded `refs/heads/master`**, so it 404'd on every
  repository that has since renamed its default branch.
* **Security:** strict checksum enforcement, archive path-traversal and symlink-escape
  rejection, manifest validation, HTTPS-only downloads, opt-in dynamic installs,
  `hdiutil attach -readonly`, and removal of the `curl | sh` self-update. Details in
  [SECURITY.md](SECURITY.md).
* **Windows support**, plus Linux aarch64. The old code could not compile for Windows
  at all (`std.posix.getenv` is a compile error there).
* **Implemented the subsystems that were previously fictional**: memory-mapped binary
  index, crash-recoverable WAL, real Bloom filter, genuine SQLite export.
* **Performance:** 6–10× faster startup, single-pass hashing, one directory walk per
  install, buffered stdout, bounded parallelism. Details above.
* **Release binaries rebuilt.** `abv0-darwin-x86_64` was a 0-byte file and
  `abv0-linux-x86_64` was an unstripped debug build. All six artifacts are now stripped
  `ReleaseFast` builds published with `release/SHA256SUMS`.
* **Installer hardened** and an `install.ps1` added for Windows.
* **Documentation:** removed the unreproducible benchmark table and the descriptions of
  subsystems that did not exist.

### Earlier releases

v1.5.0 and earlier claimed fixes for the memory-mapped uninitialized read, the archive
path traversal and several performance features. Those claims did not match the code;
the issues are genuinely fixed in 2.0.0. The historical changelog is preserved in the
git history.

---

## License

See [LICENSE](LICENSE).
