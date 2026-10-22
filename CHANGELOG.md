# Changelog

## Unreleased

### Security

- **Signed manifest.** The registry `index.json` is verified against a detached
  Ed25519 signature (`<url>.sig`) using the public key compiled in from
  `keys/manifest.pub`. A missing or invalid signature is refused. Findings 17 onward in
  [SECURITY.md](SECURITY.md).
- **Replay protection.** The manifest's top-level `updated_at` may not be older than the
  value stored in `<registry dir>/last-updated-at`. An equal value is accepted.
- **Signed self-update.** `abv0 self-update` checks `release/SHA256SUMS.sig` before it
  trusts the checksums for the new binary.
- **No implicit manifest.** `packages/index.json` in the current directory is no longer
  loaded automatically.
- **Symlink-chain escape closed.** Every existing parent component of an archive member,
  and the member itself, is checked on disk before it is written. A symlink target may
  not walk through a link already on disk.
- **Extraction limits.** tar and zip extraction stop at 4 GiB (`max_extract_bytes`) or
  200,000 members (`max_extract_members`). Setuid, setgid and sticky bits are cleared.
- **Command ownership.** Bin links and app bundles are recorded with their owning
  package. A package cannot take over a name it does not own, and reserved names
  (`abv0`, `sudo`, `su`, `ssh`, shells and similar) are refused. `--force` replaces a
  conflicting bin link.
- **Store and uninstall.** Store directories are named `name@version@platform`, so
  package names and versions cannot be confused. Uninstall matches the parsed package
  name exactly. App bundle names must end in `.app` and are never replaced unless abv0
  installed them.
- **Network.** curl runs with `-q` and ignores `~/.curlrc`. Downloads are capped at 2 GiB
  (`max_download_bytes`). URLs containing userinfo are rejected.
- **Index.** Offsets and lengths in the binary index are checked for `u32` overflow and
  fail with `IndexTooLarge`. The index cache is keyed by the SHA-256 of `index.json`,
  not by size and mtime.
- **Registry names.** Duplicate package names and reserved executable names are rejected
  when the manifest is loaded.
- **Terminal and JSON output.** Control bytes from manifest text are printed as `?`.
  All JSON string values use the standard encoder.
- **macOS disk images.** A `.dmg` is attached at a private mount point with
  `-readonly -nobrowse -noverify -noautoopen`, copied only from that mount point, always
  detached, and copy errors are returned rather than ignored.
- **Crash-safe state.** The write-ahead log recovers a torn tail record, fsyncs, persists
  its sequence number across runs and compacts. Publishing a package over an existing
  install moves the old tree aside and deletes it only after the new tree is in place.
- **Upgrade is install-first.** The new version is installed before any older version is
  pruned. Older versions are removed only after the install succeeds.
- **Installers.** The installers write `ABV0_BIN_DIR` into shell profiles with POSIX
  quoting and refuse a value containing a newline. A missing SHA-256 tool is an error
  unless `ABV0_ALLOW_UNVERIFIED=1` is set. Only directories created under the default
  `~/.abv0` are made `0700`. `install.ps1` allows TLS 1.3 where the runtime supports it.
- **Registry contents.** `threat-sample` (a malware-pattern script) and the `git` and
  `wget` entries (mock shell scripts that would shadow the real tools) are removed from
  the public registry. See the migration notes.
- **Zip entry names are checked before extraction.** Every entry name is read from the
  central directory before the first write. A name that is not a plain relative path, or
  that contains `:` or a backslash, refuses the whole archive (`UnsafeArchiveMember`). This
  closes a Windows escape through drive-absolute, drive-relative, UNC and alternate-data-stream
  names. Finding 27 in [SECURITY.md](SECURITY.md).
- **A manifest on disk is verified before it is trusted.** abv0 records the SHA-256 of each
  manifest it accepts in `registry/index.json.sha256`. A file on disk is used only if its
  hash matches. Finding 28.
- **API headers stay with the original host.** The built-in client sends the GitHub API
  headers, including the optional token, only to the host of the original request. A
  redirect to another host does not receive them.
- **Tokens never on a command line.** When a request falls back to curl, its headers,
  including a GitHub token, reach curl through a private 0600 file (`--header @file`), not
  argv. Finding 29.

### Performance

- **Streaming verified install.** For tar, tar.gz, tar.xz, tar.zst and single-binary packages, bytes from curl
  are hashed, decompressed and unpacked in one pass into a private staging directory.
  Nothing is published until the digest matches. Ten rounds installing ripgrep, bat and
  jq: median 346 ms streamed against 404 ms downloading to a file first.
- **Download cache.** A payload whose SHA-256 matched the manifest is kept in
  `<root>/cache/sha256/<xx>/<hex>` (0600, LRU-capped at 2 GiB, `ABV0_CACHE_MAX`). A later
  install of the same payload skips the network, so it also works offline; the cached bytes
  are hashed again on every use and a corrupt entry is dropped and downloaded afresh.
  Installing jq and ripgrep: about 290 ms cold, about 90 ms from the cache.
  `ABV0_NO_CACHE=1` turns it off.
- **File dedupe.** Files of 4 KiB or more in a newly unpacked package are hard linked
  through `<root>/cas/files/<sha256>` (one name per permission mode), so an upgrade or
  reinstall shares every unchanged file with what is already installed. `abv0 gc` and
  `abv0 cleanup` remove shared files nothing else links to. `ABV0_NO_DEDUPE=1` turns it off.
- **Dependency-ordered parallel installs.** `install`, `upgrade` and `bundle install`
  plan with `resolveOrder`, run packages in waves by dependency depth, and skip a
  package whose dependency failed.
- **Per-worker arenas.** Each worker runs jobs in its own page-allocator-backed arena,
  reset per job.
- **Index.** `findByBin` uses a sorted lookup table: 55.5 us to 0.39 us per lookup on
  5,000 packages. The index loads without copying, and `index.json` is read once.
- **Single manifest parse.** `update` and the first-run registry load reuse the parse
  that validates the download.
- **Store scan.** One store scan per operation, and a one-pass scanner.

### New

- **`deps`, `uses`, `leaves`.** `deps <pkg>` lists a package's dependencies in install
  order (`--tree` nests them); `uses <pkg>` lists installed packages that depend on it;
  `leaves` lists installed packages nothing else depends on. All take `--json`.
- **`switch <pkg> <version>` and `rollback <pkg>`.** Make another installed version the
  active one without downloading anything. `upgrade` now keeps the version it replaces
  (older ones are still removed) so `rollback` has somewhere to go; `cleanup` removes it.
  `cleanup` also stops deleting an older version that a bin link, hard link or copy
  still uses.
- **`home <pkg> [--open]`** prints a package's homepage (`gh:owner/repo` gives its
  GitHub page).
- **`search --online <query>`** adds GitHub repository search results (owner/repo, stars,
  description and the `abv0 install gh:owner/repo` line) after the catalog matches.
- **`info`** also shows installed versions (the active one marked), size on disk,
  linked executables and where the package came from (catalog or `gh:`).
- **`migrate [--from-brew-list FILE | --brewfile FILE] [--install]`** maps package names
  from a saved `brew list --formula` or a Brewfile onto the catalog and lists what matched
  and what did not. It reads names only and never runs brew. `--install` installs the
  matches.
- **`upgrade --all`** is the explicit form of `upgrade` with no names. `outdated` marks
  pinned packages (`"pinned"` in `--json`).
- **Commands:** `pin`, `unpin`, `pinned`, `cleanup`, `completions <bash|zsh|fish|pwsh>`,
  `which <bin>` and `self-update [--check]`.
- **`abv0 list --installed`** lists the versions in the store for the current platform.
- **`--dry-run`** for `install`, `upgrade`, `uninstall`, `bundle install` and `cleanup`.
  It prints what would happen and changes nothing. It needs an already-cached registry.
- **Live download progress.** On a terminal, each streaming download shows bytes received
  and speed, redrawn in place. Nothing extra is printed into pipes, files or `--json`.
- **`--color=auto|always|never`.** `--no-color` is the same as `never`.
- **`-q` / `--quiet`** suppresses progress lines. Errors still print.
- **`-v` / `--verbose`** also prints the URL, store path and timing for each package.
- **`abv0 <cmd> --help`** and **`abv0 help <cmd>`** show help for one command.
- **Did-you-mean** for an unknown command, or an unknown package name within edit
  distance 2 or a prefix match.
- **`--json`** on `search`, `install` and `doctor`, in addition to `list`, `info` and
  `outdated`.
- **`--no-stream`** downloads a package fully before unpacking it.
- **`--registry <path>`** loads an explicit manifest. Its `<path>.sig` must verify.
- **`--allow-unsigned-manifest`** skips the signature and replay checks. It prints a
  warning every time. Use it only for local testing.
- **Environment overrides:** `ABV0_HOME`, `ABV0_BIN_DIR`, `ABV0_REGISTRY_DIR` and
  `ABV0_REGISTRY_URL`. Path overrides must be absolute with no NUL bytes or line breaks.
  The registry URL must be https. Invalid values are ignored.
- **Explained errors.** Common failures (missing file, permissions, network, checksum,
  binary conflict) print a sentence and a next step.
- **Exit codes** are documented: 0 success, 1 the operation failed, 2 usage error.
- **CI workflow.** Linux runs unit tests, the all-target compile check, a ReleaseFast
  build and a smoke test that verifies `packages/index.json` against `keys/manifest.pub`.
  macOS and Windows run unit tests.
- **`zig build sign-tool`** installs the `sign-manifest` CLI (`keygen`, `sign`, `verify`).
- **`zig build catalog-tool`** installs the `build-catalog` CLI.
- **GitHub installs.** `abv0 install gh:owner/repo[@tag]` (or `owner/repo`) installs a
  project's own release, with no recipe. The asset is checked against GitHub's sha256
  digest or the release's checksum file. An asset with neither is refused unless
  `--allow-unverified` is given. `list`, `outdated`, `upgrade` and `uninstall` work for these
  installs. `GITHUB_TOKEN` or `GH_TOKEN` is optional.
- **Built-in HTTPS client.** Downloads and API requests use `std.http` with TLS 1.3 and
  reuse connections within a run. curl runs only after a transport failure, and a host that
  fails is remembered for 24 hours. `ABV0_DOWNLOADER=builtin|curl|auto` forces either.
- **7z extraction** in process, for Windows packages: LZMA, LZMA2, BCJ and Copy. PPMd,
  BZip2, Deflate, BCJ2, Delta and AES are refused.
- **Self-building signed catalog.** `tools/build-catalog.zig` turns `catalog/sources.txt`
  into `packages/index.json` from upstream GitHub releases, for six platforms. A daily
  workflow signs the result. See [catalog/README.md](catalog/README.md).
- **Install scripts** `install.sh` and `install.ps1` download `packages/index.json.sig` with
  the index and install it first.
- **Windows launcher shims.** On Windows each installed program is linked as
  `<bin>\<name>.exe` (a copy or hard link of abv0 itself) plus `<name>.shim` naming the real
  executable. Started under the program's name, abv0 runs the target from its own directory,
  so DLLs and data files next to it load. `doctor` reports broken pairs, `fix` rewrites them,
  and `which` shows the target. Linux and macOS keep plain links.

### Changed

- `search` prints `no packages match` and exits 0 when nothing matches.
- `upgrade` exits 1 when every requested name is unknown.
- Argument errors name the option and the bad value. `-j` with a non-number is
  `InvalidNumber`.
- Output is buffered and written to stdout. Colour is used only when stdout is a TTY,
  and `NO_COLOR` is respected.
- Output from code under test goes to stderr in test builds. This fixes a deadlock in
  `zig build test`.
- `abv0 help` lists every command, the new flags and the exit codes.
- An unknown bare name is no longer searched on GitHub. abv0 prints the `gh:owner/repo`
  spelling to use instead.
- Removed the experimental Homebrew-bottle and Scoop backends before release. The
  `bundle` command still reads and writes Brewfile-format files.
- The test suite has 255 `test` blocks across `src/*.zig` and `tools/*.zig`.

### Fixed

- Tarballs whose members start with `./`, as `tar -C dir .` writes them, installed nothing.
  The leading `./` is now dropped before the safety checks.
- On Windows the MSVC build is preferred over the MinGW build when both are published.
- bat 0.24.0 in the catalog: the x86_64-macos checksum did not match the published file, and
  the aarch64-macos entry pointed at the x86_64 build. The checksum is corrected, and the
  aarch64-macos entry is dropped until a native build exists.

## Migration notes

- **Reinstall packages once.** The store directory format changed from
  `name-version-platform` to `name@version@platform`. A package installed by an older
  version shows as not installed. Reinstall it with `abv0 install <pkg>`. Its existing
  bin links are adopted, not refused.
- **Signed manifest.** `update` and the first-run bootstrap refuse a manifest whose
  `<url>.sig` does not verify against `keys/manifest.pub`. `--allow-unsigned-manifest`
  is the escape hatch. It disables the signature and replay checks.
- **`--registry` replaces cwd loading.** abv0 no longer reads `packages/index.json` from
  the current directory. Use `--registry <path>` to load a local manifest, and make sure
  `<path>.sig` exists and verifies.
- **Upgrade order.** `upgrade` installs the new version first and removes older versions
  only after success. A failed upgrade leaves the old version in place.
- **Test fixtures moved.** `packages/git_mock.sh`, `packages/wget_mock.sh`,
  `packages/malware_sample.sh` and `packages/MockApp.app.tar.gz` moved to
  `tests/fixtures/`. They are for abv0's own tests and are not registry packages.
- **Registry entries removed:** `btop`, `ffmpeg`, `git`, `wget`, `threat-sample` and
  `mock-gui`. These names no longer resolve from the registry.
- **`ABV0_ALLOW_UNVERIFIED`** still bypasses the checksum check in `install.sh`.
  If no SHA-256 tool is found, the installer now fails unless that variable is set.
- **The first run re-checks the manifest on disk.** Before this change there is no
  `registry/index.json.sha256`. A manifest already in the registry directory is checked
  against `index.json.sig` when that file is beside it, and is downloaded again otherwise.
- **`--allow-unsigned-manifest` records no hash.** A later run without the flag does not
  trust that manifest. It is checked again, as in the first bullet above.

## 2.0.0

Correctness, security and cross-platform release.

- **Fixed: the build.** Removed an orphaned function body and added missing imports.
- **Fixed: `abv0 outdated` never reported anything.** Its body was an empty block, so it
  always printed "everything is up to date". It now compares installed versions against
  the registry with numeric-aware version ordering.
- **Fixed: `abv0 run` / `abv0 shell` for most packages.** Both looked for an executable
  named after the package instead of the executables the package provides.
- **Fixed: data race in parallel installs.** Every worker thread shared one
  `ArenaAllocator`. Each install now gets its own arena over a thread-safe base
  allocator, and installs are bounded to `min(CPUs, packages, 8)`.
- **Fixed: crashes on malformed input.** Unchecked `.?` unwraps on parsed JSON panicked
  on a truncated manifest or a GitHub rate-limit response.
- **Fixed: concurrent first runs corrupted the registry.** The manifest is now downloaded
  to a temporary file, parsed, and renamed into place atomically.
- **Fixed: `installDynamic` hardcoded `refs/heads/master`.**
- **Security:** strict checksum enforcement, archive path-traversal and symlink-escape
  rejection, manifest validation, HTTPS-only downloads, opt-in dynamic installs,
  `hdiutil attach -readonly`, and removal of the `curl | sh` self-update. See
  [SECURITY.md](SECURITY.md).
- **Windows support**, plus Linux aarch64.
- **Implemented the subsystems that were previously described but missing:** memory-mapped
  binary index, crash-recoverable WAL, Bloom filter, SQLite export.
- **Performance:** faster startup, single-pass hashing, one directory walk per install,
  buffered stdout, bounded parallelism.
- **Release binaries rebuilt.** All six artifacts are stripped `ReleaseFast` builds
  published with `release/SHA256SUMS`.
- **Installer hardened** and `install.ps1` added for Windows.

v1.5.0 and earlier claimed fixes for the memory-mapped uninitialized read, the archive
path traversal and several performance features. Those claims did not match the code.
The history is in git.
