# Changelog

## 2.8.0 (2026-10-28)

### Faster

- **Reinstalls in milliseconds.** `uninstall` keeps the unpacked files in
  `~/.abv0/parked` (for 30 days, or until `abv0 cleanup`), so installing the same version
  again is a rename and a link: no download, no unpack. Uninstalling and reinstalling
  ripgrep, jq and bat went from about 600 ms to 35 ms. `ABV0_NO_PARK=1` turns it off.
- **GitHub answers are remembered.** `install gh:owner/repo` reuses GitHub's release
  answer for an hour (a tagged release for a day; `ABV0_GH_CACHE_MINUTES` changes it), so
  a repeat install needs no network. `upgrade` and `outdated` always ask again.
- **`gh:` installs skip GitHub when they can.** `install gh:owner/repo` with no tag, for
  a project the signed catalog builds, installs the catalog's pinned download: no API
  call, and a signed checksum instead of the release's own. A tag still goes to GitHub.
- The benchmark times abv0 with one install command for all five tools, as it times
  zerobrew and Homebrew. Measured on GitHub's runners, installing five tools cold is
  5.5–7.5× faster than zerobrew, and an uninstall plus reinstall 1.1–4.7× faster.

### New

- **Undo and history.** Every install, uninstall, upgrade, switch and undo is recorded.
  `abv0 history` lists the changes; `abv0 undo` reverses the newest (or `abv0 undo <#>`
  one of them) for every package it touched: switching back to a version still on disk
  with no download, removing what was added, and installing again what was removed.
  Undoing an undo redoes it.
- **Choose when upkeep runs.** `abv0 autoupdate on` takes `--weekly --day mon`,
  `--every 6h`, `--hourly` and `--at 09:30`, on launchd, systemd, cron and Task Scheduler
  alike. `abv0 autoupdate status` shows when it runs.
- **Micro-sharded downloads.** `--micro-shards` (or `ABV0_SHARD_SIZE=on`) cuts a big
  file into pieces that the connections take from a shared queue, so a fast connection
  takes more and one slow connection no longer holds up the end. Pieces start big and
  shrink toward the end; `--micro-shards=4M` sets the smallest. The SHA-256 is still
  computed in order as the pieces land. Off by default: on a fast, clean link the
  default split is as fast.
- **Benchmarks against zerobrew.** The benchmark workflow now times zerobrew next to
  Homebrew, and one 415 MB download with each download mode.
- **Roll abv0 itself back.** `self-update` keeps the abv0 it replaces, and
  `abv0 self-update --rollback` returns to it.

### Fixed

- Hugging Face downloads could save files under the wrong name or fail with "file not
  found" (seen on Windows and macOS): the parallel download threads shared memory that
  is not safe to share. They now use a thread-safe allocator.

## 2.7.0 (2026-10-28)

### New

- **Free books and papers.** `abv0 install book:gutenberg/1342`, `book:standard/<author>/<title>`,
  `book:archive/<identifier>` and `book:arxiv/<id>`, into `~/Books` (or `ABV0_BOOKS_DIR`).
  - `abv0 book search <words>` asks Project Gutenberg, Standard Ebooks, the Internet
    Archive and arXiv at once; `search-gutenberg` (and so on) asks one.
  - `--format epub|pdf|txt|kindle`; EPUB by default for books, PDF for scans and papers.
  - Internet Archive downloads are checked against its SHA-1 and size; borrow-only
    lending-library items are refused. Every file must match its format.
  - `abv0 book list`, `abv0 book dir`, `abv0 uninstall book:...`.
- **Hugging Face models and datasets.** `abv0 install hf:owner/model`,
  `hf:datasets/owner/name`, with an optional `@revision`. Files go into the Hugging Face
  cache in `huggingface_hub`'s layout (blobs, snapshot links, refs), so Python tools find
  them offline.
  - Every file is checked against the Hub's SHA-256 (large files) or git blob id
    (small ones), all from one pinned commit.
  - Pickle files are scanned for dangerous imports, and refused unless
    `--allow-suspicious`.
  - Copies in other weight formats are skipped next to `.safetensors` (`--all-files`
    takes them).
  - `--include` and `--exclude` pick files; a download over 25 GB needs `--include` or
    `--force`; files already cached are reused.
  - `abv0 hf login` plugs in your token: typed hidden (or piped, or `--token`), checked
    with Hugging Face, and saved on this computer only, mode 600, in the file Hugging
    Face's tools share. `abv0 hf whoami` and `abv0 hf logout` too. `HF_TOKEN` also works.
  - `HF_HUB_OFFLINE=1` never contacts Hugging Face and uses only the cache. With no
    network, install falls back to the cached copy.
  - `abv0 hf list | path | search | search-datasets`, and `abv0 uninstall hf:...`.
- **Proprietary software.** `catalog/vendor.txt` lists software published on its maker's
  own site. Each line gives a homepage instead of `owner/repo`, plus `url.<platform>=` for
  each download link (`url.macos=` for a universal Mac build). `{version}` in a link is
  filled in from `version-url=` and `version-after=`.
  - Version: read from the vendor's update feed, else from the final download URL, else
    from the file's Last-Modified date.
  - Links are followed by the builder, https only. A link that lands on a stable,
    versioned file is pinned as that file; one that lands on a signed, expiring URL stays
    the original link.
  - Each file is downloaded once, its SHA-256 pinned and the malware scan run. A platform
    whose link fails is left out.
  - The license defaults to `Proprietary`.
  - First entries: Chrome, VS Code (Mac and Windows), Slack, Discord, Docker Desktop,
    Notion, Postman, Steam, Raycast, Warp, Arc, ChatGPT, Firefox, Signal, Terraform,
    Vault, Packer, Consul, Nomad and the 1Password CLI (`op`).
- **Thousands more packages, found automatically.** `build-catalog discover` searches
  GitHub every week for popular projects (500+ stars, compiled languages, active, at least
  six months old) whose latest release has downloads, and writes them to
  `catalog/auto-sources.txt`. The first search found about 6,200 candidates; the daily
  catalog build adds up to 500 of them per run (about 70% pass all checks). A project
  must ship a program named after it or its owner (one named only after its owner is
  published as `owner-repo`), and keeps its package name from then on. Each one gets the same checks as a
  hand-written source: a pinned SHA-256 per platform, executables found by unpacking, and
  now the malware scan as well. Each is re-checked weekly; projects without a usable
  download are skipped for 30 days (`catalog/auto-rejects.txt`). Hand-written lines
  always win.
- The catalog builder runs abv0's malware scan on every download it unpacks, so a
  package abv0 would refuse at install time never gets into the catalog.
- abv0 reads catalogs up to 64 MB (was 16 MB), enough for tens of thousands of packages.

## 2.6.1 (2026-10-23)

### Security

- `self-update` refuses a published build older than the running one, so old signed
  release files cannot roll users back (SECURITY.md finding 30).
- Every GitHub Actions step is pinned to a commit SHA; the workflows that hold the
  signing key no longer run code a moved tag could change (finding 31).
- `autoupdate on` refuses paths with a control character, `%` or `"` instead of
  writing them into the scheduler's job (finding 32).
- The `brew uninstall` line `migrate` prints holds only plain package names
  (finding 33).

## 2.6.0 (2026-10-23)

### New

- **Move from Homebrew in one command.** `abv0 migrate` with no file reads the Homebrew
  on this machine straight from disk (its Cellar, Caskroom, install receipts and pins),
  in well under a millisecond for a typical install; brew is never run. It takes what
  you installed by hand plus your apps (`--all` adds dependencies), matches them to the
  catalog, and `--install` installs them in parallel, keeps your `brew pin`s and prints
  the `brew uninstall` line for what moved. Already installed matches are skipped.
- **Automatic upkeep.** A catalog older than a day (`ABV0_UPDATE_HOURS`) is refreshed
  before the commands that read it. `abv0 maintain` refreshes, upgrades unpinned
  packages, installs missing dependencies, removes unused ones, cleans up and runs
  self-update. `abv0 autoupdate on [--weekly] | off | status` schedules it with launchd,
  a systemd user timer or cron, or Task Scheduler.
- **Dependencies.** Catalog lines take `deps=`. `upgrade` installs dependencies a new
  version adds, `fix` installs missing ones, and a dependency with no build for the
  platform is skipped with a note instead of failing the install. abv0 records which
  packages it pulled in as dependencies (`state/deps-only`); after an uninstall, those
  nothing needs are removed (`ABV0_AUTO_REMOVE=0` keeps them). Nothing else is ever
  removed automatically.
- **Daily cleanup.** The first package-changing command of the day clears temporary
  files and stale sandboxes (`ABV0_AUTO_CLEAN=0` turns it off).
- **Windows desktop apps.** Portable Windows builds are installed into the store and get
  a Start Menu shortcut (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\abv0`),
  made with the Windows Shell (a plain .lnk file is the fallback); uninstall removes it. The catalog takes
  `win=Name.exe` (or `win="Display=Name*.exe"`) on an app line: the builder picks the
  release's portable Windows .zip, downloads it and checks the program is inside.
  Nineteen existing apps gained Windows builds and fourteen Windows apps were added
  (Notepad++, ShareX, WinMerge, HandBrake, WezTerm, Telegram and others).

## 2.5.0 (2026-10-23)

### Security

- **Install-time malware scan.** Every file of a newly unpacked package is scanned before
  it is linked (src/scan.zig). Rules need several signs in the same file (download +
  chmod in /tmp + background run; four saved-secret paths + a webhook), cover reverse
  shells, miners, droppers, cron/launchd/Run-key persistence, ld.so.preload rootkits and
  encoded execution, decode base64 runs in text files, and apply script-only rules to
  text files only. A strong finding blocks the install (`--allow-suspicious` overrides,
  `ABV0_NO_SCAN=1` disables); `abv0 detect` lists every finding and its file. The old
  single-string patterns (`nicehash`, `nc -e`) matched 8 of 60 ordinary catalog tools.
- **zig checksums fixed.** The three `zig` entries in `catalog/manual.json` carried wrong
  SHA-256 values, so abv0 (correctly) refused to install zig; they now match ziglang.org.
- **Maintainer signing key.** The development key is replaced by the maintainer's key
  (`keys/manifest.pub`). The catalog and `release/SHA256SUMS` are re-signed with it, and
  the release binaries are rebuilt to trust it. Catalogs signed with the old key are
  refused.

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

- **`--registry` manifests use the binary index too.** It is cached per manifest
  path and used only when built from the same bytes. The signature check reads
  `updated_at` with a token scan instead of building a JSON tree. With the full
  373-package catalog, `search`, `info` and `list` take about 5 ms.

- **Progressive parallel downloads.** A download of 8 MiB or more from a server that
  supports byte ranges is fetched over up to 8 connections. The first GET is the probe, with
  no HEAD round trip: once its response head says the body is big and ranges work, the other
  chunks are requested at once on the same final URL while the first connection keeps
  reading chunk 0. Chunks are written into a preallocated file, and the SHA-256 is computed
  in order as they land, so the digest is final with the last byte and the file is not read
  again. A streaming install decodes chunk 0 while later chunks are still arriving. A
  failed chunk is retried twice, resuming where it stopped, on a new connection; a server
  that advertises ranges and ignores them is detected and the download restarts as one
  stream. The curl fallback does the same with one curl process per chunk.
  `ABV0_SPLIT_MIN` and `ABV0_CONNECTIONS` tune it. Idle connections that the server closed
  are retried transparently, and `net.prewarm` can open TLS connections ahead of the first
  request.
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

- **`abv0 browse`**, a full-screen package picker: type to search the catalog (name
  matches first, then descriptions), move with the arrow keys, Space to pick, Enter to
  install. Works in Terminal, iTerm, Linux terminals and Windows Terminal; no library.
  Catalog text is shown with control characters stripped, so a description cannot move
  the cursor or change the screen.

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

- **Full catalog.** `packages/index.json` now carries the 373 packages built from
  `catalog/sources.txt` (signed with the maintainer key).
- **Programs are symlinked on Linux and macOS**, so tools that find their own files
  next to the executable (cmake's `cpack`, `ctest`) work. Windows keeps launchers.
- **Program detection** takes only `bin/` programs when a package has a `bin/`
  directory, skips `share/` and `include/` and build templates, and, when several
  files share a program's name, picks the one beside the main program.

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
