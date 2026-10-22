# Catalog

`packages/index.json` is the registry abv0 installs from. It is generated, not edited by
hand. This directory holds its inputs.

| File | Role |
| :--- | :--- |
| `sources.txt` | One upstream project per line. Each becomes a package built from that project's GitHub releases. |
| `manual.json` | Hand-written entries for software that is not published as GitHub release assets (currently `zig` and `neofetch`). Copied through unchanged. |
| `fixtures/` | Recorded GitHub API responses and assets for offline runs of the builder (ripgrep, fd and fzf). |

## How a project becomes a package

For each line in `sources.txt`, `tools/build-catalog.zig`:

1. asks the GitHub API for the latest release, or the release named by `tag=`;
2. picks one asset for each of the six platforms, with the same scorer that
   `abv0 install gh:owner/repo` uses (`src/ghrelease.zig`);
3. pins each asset's SHA-256 from GitHub's `digest` field, else from a checksums file in
   the same release (`src/ghverify.zig`), else by downloading the asset and hashing it;
4. downloads one asset per changed package, unpacks it with abv0's own extractor, and
   finds the executables inside (`src/bindetect.zig`);
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
| `--jobs N` | Packages processed in parallel (default 4) |
| `--curl` | Use curl instead of `std.http` for all network access |
| `--offline-fixtures DIR` | Read `<owner>__<repo>.release.json` / `.repo.json` and `<owner>__<repo>/<asset>` from DIR instead of the network |
| `--max-download-mb N` | Skip assets larger than this when they must be fetched |
| `--allow-shrink` | Allow the catalog to lose more than half its packages |
| `--allow-failures` | Write the catalog even when most sources failed |

`--offline-fixtures catalog/fixtures` builds the committed fixtures without any network
access. Only the projects that have fixtures can be built that way.

## Signing the catalog

The catalog is signed with the same Ed25519 key as the manifest. `keys/manifest.pub` is
the public half, compiled into every abv0 binary.

```bash
./zig-out/bin/sign-manifest sign <secret-key-file> packages/index.json   # writes packages/index.json.sig
./zig-out/bin/sign-manifest verify keys/manifest.pub packages/index.json
```

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

The public key committed in this repository is a development placeholder. Replace it with
the maintainer's key before a real release, as described above.
