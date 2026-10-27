# Catalog

`packages/index.json` is the registry abv0 installs from. It is generated, not edited by
hand. This directory holds its inputs.

| File | Role |
| :--- | :--- |
| `sources.txt` | One upstream project per line. Each becomes a package built from that project's GitHub releases. |
| `manual.json` | Hand-written entries for software that is not published as GitHub release assets (currently `zig` and `neofetch`). Copied through unchanged. |
| `vendor.txt` | Software published on its maker's own site (most of it proprietary): a homepage and one official download link per platform. The builder follows each link, reads the version, downloads the file once and pins its SHA-256. The header of the file documents the format. |
| `auto-sources.txt` | Written by `build-catalog discover` (every Monday): popular GitHub projects with release downloads, most stars first. Do not edit; a line in `sources.txt` with the same name or repository wins. |
| `auto-rejects.txt` | Discovered repositories that had no usable download, with the day they were tried. Skipped for 30 days, then tried again. Written by the builder. |
| `fixtures/` | Recorded GitHub API responses and assets for offline runs of the builder (ripgrep, fd and fzf). |

## How a project becomes a package

For each line in `sources.txt`, `tools/build-catalog.zig`:

1. asks the GitHub API for the latest release, or the release named by `tag=`;
2. picks one asset for each of the six platforms, with the same scorer that
   `abv0 install gh:owner/repo` uses (`src/ghrelease.zig`);
3. pins each asset's SHA-256 from GitHub's `digest` field, else from a checksums file in
   the same release (`src/ghverify.zig`), else by downloading the asset and hashing it;
4. downloads one asset per changed package, unpacks it with abv0's own extractor, and
   finds the executables inside (`src/bindetect.zig`); a `kind=app` source skips this and
   only reads the `.app` name from a zip;
5. reads the description, license and homepage from the repository record.

The builder is:

- **Incremental.** A package whose version equals the one in `--previous` is reused with
  no download.
- **Tolerant.** A source that fails keeps its previous entry.
- **Deterministic.** Entries are sorted, and `updated_at` does not change when nothing
  did.

Before it replaces the output file, the builder refuses to write when:

- more than half of the attempted sources failed (checked once at least 10 were tried;
  override with `--allow-failures`);
- the catalog would lose more than half of its packages compared with `--previous`
  (checked when the previous catalog had at least 10; override with `--allow-shrink`);
- the registry loader rejects any package in the result. There is no override for this.

## Adding a project

Add one line to `catalog/sources.txt`:

```
name  owner/repo  [key=value ...]
```

| Key | Meaning |
| :--- | :--- |
| `name` | The abv0 package name: letters, digits, `-`, `_`, `.` and `+`. |
| `bin=a,b` | Executables to expose. Replaces detection. The first one is the primary. |
| `asset.<platform>=TEXT` | The release asset whose name is TEXT. An exact name wins; otherwise the shortest name that contains TEXT. |
| `skip=<platform>,...` | Never publish for these platforms. |
| `desc="..."` | Replaces the repository description. |
| `license=SPDX` | Replaces the repository license. |
| `tag=<release tag>` | Pin a release instead of following the latest. |
| `kind=app` | A macOS application (what Homebrew calls a cask). See [GUI apps](#gui-apps). `kind=cli` is the default. |
| `app=Name.app` | The application bundle's name; implies `kind=app`. Required when the Mac asset is a `.dmg`. Quote names with spaces: `app="Brave Browser.app"`. |

The platforms for `asset.` and `skip=` are `x86_64-linux`, `aarch64-linux`,
`x86_64-macos`, `aarch64-macos`, `x86_64-windows` and `aarch64-windows`.

Values with spaces go in double quotes. `#` starts a comment. A line that cannot be
parsed is reported and skipped; it does not stop the run.

Only list projects that publish prebuilt binaries as release assets. A platform the
picker cannot match (no asset, or an archive it does not unpack such as `.bz2`) is left
out of that package. Two existing lines as examples:

```
ripgrep  BurntSushi/ripgrep  bin=rg
fd       sharkdp/fd
```

Names are unique across the file and sorted within each `# ----` section; a test
(`zig build test`) checks both and that every line parses.

### GUI apps

A `kind=app` line is a macOS application bundle, the equivalent of a Homebrew cask:

```
rectangle  rxhanson/Rectangle  app=Rectangle.app
alt-tab    lwouis/alt-tab-macos  kind=app
```

- Only the two Mac platforms are published, and only a `.dmg` or `.zip`. Assets for
  Linux, Windows and iOS, source archives, debug symbols and checksum files are never
  chosen. The asset for each Mac is picked by architecture (`arm64`, `x64`,
  `universal`, or no marker at all).
- `archive_type` is `dmg` or `zip`, `bin` is empty, `bin_path` is empty and
  `app_bundles` holds the bundle name. No executables are detected.
- A `.dmg` cannot be opened off macOS, so its line must say `app=Name.app`. When the
  line gives `app=`, a `.dmg` is preferred over a `.zip` (abv0 unpacks it with the
  system, which keeps permissions and symlinks).
- Without `app=`, a `.zip` is chosen. The builder downloads it once and reads the
  names of the `*.app` directories at its top level. A zip whose app sits one level
  down (`Name-1.0/Name.app`) is refused, because abv0 links `<package>/Name.app`.
- `asset.<platform>=TEXT` still overrides the picker.

A project's Linux and Windows builds are separate CLI-style lines named
`<app>-portable` (an AppImage is a raw executable), so that `abv0 install <app>`
keeps meaning the macOS bundle.

## Running the builder locally

The tools need Zig 0.13.0.

```bash
zig build install catalog-tool sign-tool -Doptimize=ReleaseSafe
```

This installs `abv0`, `build-catalog` and `sign-manifest` into `zig-out/bin`.

Rebuild the catalog from upstream releases. This uses the network. Set `GITHUB_TOKEN` to
raise the GitHub API limit (the workflow does this).

```bash
./zig-out/bin/build-catalog --sources catalog/sources.txt --manual catalog/manual.json \
  --out packages/index.json --previous packages/index.json
```

Refresh only some packages. The rest are taken from `--previous`:

```bash
./zig-out/bin/build-catalog --sources catalog/sources.txt --manual catalog/manual.json \
  --out packages/index.json --previous packages/index.json --only ripgrep,fd
```

The builder's options, from its usage text:

| Option | Meaning |
| :--- | :--- |
| `--sources FILE` | `catalog/sources.txt`: `name owner/repo [key=value ...]` |
| `--out FILE` | The registry to write (`packages/index.json`) |
| `--previous FILE` | Reuse entries whose version is unchanged (no downloads) |
| `--manual FILE` | Hand-written entries copied through (default: `manual.json` beside the sources file, if it exists) |
| `--only a,b` | Refresh only these packages; the rest come from `--previous` |
| `--force` | Ignore `--previous` and rebuild every selected package |
| `--jobs N` | Packages processed in parallel (default 8). The run is network bound, so this is what makes a full build fast; the final line reports the wall-clock time |
| `--summary FILE` | Also write a Markdown report (counts, then every failed source with its reason) for `$GITHUB_STEP_SUMMARY` |
| `--curl` | Use curl instead of `std.http` for all network access |
| `--offline-fixtures DIR` | Read `<owner>__<repo>.release.json` / `.repo.json` and `<owner>__<repo>/<asset>` from DIR instead of the network |
| `--max-download-mb N` | Skip assets larger than this when they must be fetched |
| `--allow-shrink` | Allow the catalog to lose more than half its packages |
| `--allow-failures` | Write the catalog even when most sources failed |
| `--max-wait-min N` | Total minutes the run may wait for the API rate limit to reset (default 20; the workflows pass 50). A longer wait is not taken: API calls stop and every source not yet looked at keeps its previous entry |
| `--etag-cache FILE` | Keep REST ETags (JSON index; bodies in `FILE.bodies/`) and send `If-None-Match`; a `304` costs no quota. The workflows keep it with `actions/cache`, one cache per week |
| `--batch N` | Repositories per GraphQL query (default 40) |
| `--no-graphql` | Use the REST API only (two calls per source) |

### API use and rate limits

With a token, the builder reads the repository record and the release of up to 40 projects
in **one GraphQL query** (`description`, `homepageUrl`, `licenseInfo`, `latestRelease` with
its assets and their `digest`). The full catalog of about 380 sources therefore needs about
10 API requests, not about 760. Without a token (GraphQL needs one), or for a repository
GraphQL could not answer (a release with more than 100 assets, a transient error), it falls
back to the REST API.

Every response's `x-ratelimit-*` and `retry-after` headers are tracked per bucket (REST,
GraphQL). When one is empty the run waits for the reset if that fits in `--max-wait-min`;
otherwise it stops calling the API. Sources it never looked at keep their previous catalog
entry and are reported as **rate limited (carried forward)**, apart from real failures, and the
run still finishes normally. They are checked again on the next run.

`--offline-fixtures catalog/fixtures` builds the committed fixtures without any network
access. Only the projects that have fixtures can be built that way.

## Signing the catalog

The catalog is signed with the same Ed25519 key as the manifest. `keys/manifest.pub` is
the public half, compiled into every abv0 binary.

```bash
./zig-out/bin/sign-manifest sign <secret-key-file> packages/index.json   # writes packages/index.json.sig
./zig-out/bin/sign-manifest verify keys/manifest.pub packages/index.json
```

## The full unsigned build

`.github/workflows/catalog-build.yml` builds the whole catalog and publishes it
without a signature, for review. It runs on manual dispatch (optional input `force`)
and on a push to a `claude/**` branch that changes `catalog/**`,
`tools/build-catalog.zig` or the workflow itself. It needs no secrets:

1. Build `abv0` and `build-catalog`.
2. Choose the previous catalog: `packages/index.json` on the `catalog-unsigned`
   branch if there is one (so unchanged versions are reused with no download), else
   the committed `packages/index.json`.
3. Run `build-catalog --previous <that> --allow-failures --jobs 8 --summary ...` with
   `GITHUB_TOKEN`.
4. Validate: `abv0 --registry <out> --allow-unsigned-manifest list` must load and
   count every package, and `--dry-run install` of 10 random packages that have a
   Linux x86_64 build must name each of them.
5. Write counts, every failed source with its reason, and the run time to the job
   summary.
6. Force-push one orphan commit holding only `packages/index.json` (no `.sig`) to the
   `catalog-unsigned` branch, as `github-actions[bot]`. No other branch is touched,
   and nothing is pushed when the file is byte-identical to the branch's.

Review that file, then sign it with `sign-manifest` and commit it with its `.sig`.

## The daily workflow

`.github/workflows/catalog.yml` runs at 03:17 UTC every day, and on manual dispatch with
the optional inputs `only` (comma-separated package names) and `force`. Its steps:

1. Stop unless the `ABV0_MANIFEST_KEY` secret is set. An unsigned catalog is never
   published.
2. Build `abv0`, `build-catalog` and `sign-manifest`.
3. Run `build-catalog` with `GITHUB_TOKEN`, using `--previous packages/index.json`.
4. Sign `packages/index.json` with the secret.
5. Verify the signature against `keys/manifest.pub`.
6. Load the catalog with `abv0 --registry packages/index.json list`.
7. Commit and push `packages/index.json` and `packages/index.json.sig` only if they changed.

Runs are serialised with the concurrency group `catalog`.

## One-time setup: the signing key

Do this once, before the first release.

1. Generate a key pair:

   ```bash
   zig build sign-tool
   ./zig-out/bin/sign-manifest keygen <secret-key-file> keys/manifest.pub
   ```

   `keygen` writes the secret key (128 hex characters, mode 0600 on Unix) to the first path
   and the public key to the second. It refuses to overwrite either file. Keep the secret file out
   of git; `*.key` is ignored.

2. Commit the new `keys/manifest.pub`.

3. Add the secret. In the repository on GitHub, go to Settings, then Secrets and variables,
   then Actions. Create a repository secret named `ABV0_MANIFEST_KEY` whose value is the
   contents of the secret key file.

4. Re-sign the catalog with the new key, then commit `packages/index.json` and
   `packages/index.json.sig`:

   ```bash
   ./zig-out/bin/sign-manifest sign <secret-key-file> packages/index.json
   ```

5. Rebuild abv0. The public key is compiled in, so binaries built with the old key reject
   the new signatures. `-Dmanifest-pubkey=<hex>` embeds a key at build time instead of the
   file.

The public key committed in this repository is the maintainer's key. Its secret half is
the `ABV0_MANIFEST_KEY` repository secret.
