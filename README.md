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
abv0 install google-chrome slack         # proprietary apps, from their makers' own sites
abv0 install hf:Qwen/Qwen2.5-0.5B-Instruct-GGUF --include "*q4_k_m*"   # AI models
abv0 install book:gutenberg/1342         # free books and papers
abv0 undo                                # take back the last change
abv0 run ripgrep -- --help               # run without touching PATH
abv0 shell ripgrep                       # ephemeral subshell with just that package
abv0 browse                              # pick packages from a searchable list
```

**What it does, in one list:**

| | |
| :--- | :--- |
| Command-line tools | About 1,500 in the signed catalog, plus any GitHub project's release with `gh:owner/repo` |
| Desktop apps | Mac apps into `~/Applications`, Windows portable apps with Start Menu shortcuts |
| Proprietary software | Chrome, VS Code, Slack, Discord, Docker Desktop, Terraform, 1Password CLI and more, from their makers' own links, checksum-pinned |
| AI models and datasets | `hf:owner/model` into the Hugging Face cache, every file verified, pickle files scanned; token login, offline mode |
| Books and papers | Project Gutenberg, Standard Ebooks, the Internet Archive and arXiv, into `~/Books` |
| Undo | `abv0 history`, `abv0 undo`, `abv0 rollback <pkg>`, `abv0 self-update --rollback` |
| Staying current | Catalog refreshes itself; `abv0 autoupdate on` with daily, weekly, every-N-hours or a set time |
| Downloads | Built-in HTTPS client, parallel ranged downloads, micro-shards, streaming unpack, a verified download cache |
| Safety | Signed catalog, SHA-256 on every file, malware scan before anything is linked |

**Staying up to date, automatically.**

- The catalog refreshes itself when it is more than a day old, before `install`,
  `upgrade`, `outdated`, `search`, `info` or `browse` use it (`ABV0_UPDATE_HOURS`
  changes the age, `ABV0_AUTO_UPDATE=0` turns it off).
- `abv0 maintain` does all upkeep in one go: refresh the catalog, upgrade every package
  that is not pinned, install missing dependencies, remove dependencies nothing needs,
  clear temporary files, and update abv0 itself.
- `abv0 autoupdate on` runs `maintain` every night at about 03:17 through the system's
  own scheduler: launchd on macOS, a systemd user timer or cron on Linux, Task Scheduler
  on Windows. Pick another schedule with:
  - `--weekly` (Sundays), or `--weekly --day mon` for another day;
  - `--every 6h` (every N hours, 1-23) or `--hourly`;
  - `--at 09:30` for the time of day.

  `abv0 autoupdate status` shows whether it is on, when it runs and when it last ran;
  `abv0 autoupdate off` removes it.
- Dependencies install with what needs them, `upgrade` adds any a new version needs, and
  `abv0 fix` reinstalls missing ones. When you uninstall something, dependencies that
  nothing else uses go with it. Only packages abv0 itself pulled in as dependencies are
  ever removed this way; anything you installed stays until you remove it.
- Once a day, a command that changes packages also clears temporary files.

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
  maintain                 Refresh, upgrade, fix dependencies and clean up in one go
  autoupdate on|off|status Run maintain daily, --weekly --day mon, --every 6h, --at 09:30
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
  history                  Every change to what is installed, newest first
  undo [<#>]               Undo the last change (or change #), all packages at once
  home [--open] <pkg>      Print (or open) a package's homepage
  pin <pkg>                Hold a package at its installed version
  unpin <pkg>              Let upgrade update it again
  pinned                   List pinned packages
  which <bin>              Show which package owns a command

MODELS, DATASETS AND BOOKS
  install hf:owner/model   A Hugging Face model (hf:datasets/owner/name for a dataset)
  hf login|whoami|logout   Plug in your Hugging Face token (kept on this computer only)
  hf list|path|search      What is in the Hugging Face cache, or on the Hub
  install book:source/id   A free book or paper (gutenberg, standard, archive, arxiv)
  book search|list|dir     Search every book source at once; what you downloaded

EXECUTION
  run <pkg> [-- args]      Run a package executable
  shell <pkg>...           Ephemeral subshell with only those packages

MANIFESTS
  bundle [install|dump]    Install from, or export to, a Brewfile
  migrate [--install]      Move your Homebrew packages and apps to abv0 (reads Homebrew from disk;
                           or --from-brew-list F | --brewfile F)
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
  self-update [--check]    Update abv0 from a signed release (--rollback goes back)
  reset                    Uninstall everything
  report [--bug]           Open a prefilled GitHub issue
  version                  Print the version
  help [command]           This message, or help for one command
```

### Hugging Face models and datasets

```sh
abv0 install hf:HuggingFaceTB/SmolLM2-135M-Instruct      # a model
abv0 install hf:datasets/fka/awesome-chatgpt-prompts     # a dataset
abv0 install hf:bartowski/Llama-3.2-1B-Instruct-GGUF --include "*Q4_K_M*"
abv0 hf search llama 3.2 gguf                             # most downloaded first
abv0 hf list                                              # what is in the cache
abv0 hf path hf:HuggingFaceTB/SmolLM2-135M-Instruct      # where its files are
abv0 uninstall hf:HuggingFaceTB/SmolLM2-135M-Instruct
```

- **Where files go:** the Hugging Face cache, in the same layout as Hugging Face's own
  tools, so transformers, datasets, diffusers and llama.cpp find them without
  downloading again. The cache is `HF_HUB_CACHE`, else `HF_HOME/hub`, else
  `~/.cache/huggingface/hub`.
- **Checks:** every file is checked against the Hub: large files against their
  SHA-256, small ones against their git blob id. The whole download comes from one
  pinned commit.
- **Pickle scan:** PyTorch pickles (`.bin`, `.pt`, `.pkl`, ...) can run code when
  loaded, so they are scanned for imports such as `os.system` or `builtins.eval`, and
  refused if they have one (`--allow-suspicious` keeps them).
- **What gets downloaded:**
  - When a model has `.safetensors` weights, its copies in other formats (PyTorch
    `.bin`, ONNX, TensorFlow, ...) are skipped. That often saves gigabytes, and
    `--all-files` takes them too.
  - `--include` and `--exclude` take patterns such as `"*.gguf"` or `"onnx/*"`.
  - A download over 25 GB needs `--include` or `--force`.
  - Files already in the cache aren't downloaded again.
- **Your token (for gated and private repositories):**
  - `abv0 hf login` asks for it with typing hidden (or pipe it in, or pass
    `--token`), checks it with Hugging Face, and saves it on this computer only, in the
    file Hugging Face's own tools read (`~/.cache/huggingface/token`, readable only by
    you).
  - `abv0 hf whoami` shows the account; `abv0 hf logout` deletes the file.
  - `HF_TOKEN` works too. The token is sent only to huggingface.co.
- **Staying local:** `HF_HUB_OFFLINE=1 abv0 install hf:...` never contacts Hugging
  Face and uses only what is already downloaded. With no network, install falls back to
  the downloaded copy by itself.

### Free books and papers

```sh
abv0 book search pride and prejudice                  # every source at once
abv0 install book:gutenberg/1342                      # Project Gutenberg (EPUB)
abv0 install book:gutenberg/1342 --format txt         # or pdf, txt, kindle
abv0 install book:standard/jane-austen/emma           # Standard Ebooks
abv0 install book:archive/prideprejudice00aust        # Internet Archive (PDF)
abv0 install book:arxiv/1706.03762                    # an arXiv paper
abv0 book list                                        # what you downloaded
abv0 uninstall book:gutenberg/1342
```

- **Sources:** only free, legal ones. Project Gutenberg and Standard Ebooks
  (public-domain books), the Internet Archive (only items anyone may download;
  borrow-only lending-library books are refused) and arXiv (open research papers).
  Sites that share copyrighted books without permission are not supported.
- **Where books go:** `~/Books` (or `ABV0_BOOKS_DIR`), named "Title - Author.epub".
- **Checks:** Internet Archive files are checked against the SHA-1 and size the
  archive lists. Every file must really be the format asked for, so an error page
  or a swapped file is never kept.

### Undo and rollback

```sh
abv0 history              # every change to what is installed, newest first
abv0 undo                 # undo the last change (all packages it touched)
abv0 undo 12              # undo change #12 from the history
abv0 rollback jq          # one package back to its previous version
abv0 switch jq 1.7.1      # one package to any version still on disk
abv0 self-update --rollback   # abv0 itself back to the version before the last update
```

- Every install, uninstall, upgrade, switch and undo is recorded in the history.
- `undo` switches back to the old version when it is still on disk, with no download;
  `upgrade` keeps the version it replaces for this. A removed package is installed
  again (from the download cache when it is there; a GitHub one at the same release).
- An undo is recorded too, so undoing it again redoes the change.

### Moving from Homebrew

```sh
abv0 migrate            # what would move (reads Homebrew from disk, never runs brew)
abv0 migrate --install  # install it all in parallel, keeping your brew pins
```

abv0 finds Homebrew at `HOMEBREW_PREFIX`, else `/opt/homebrew`, `/usr/local` or Linuxbrew.
It takes the formulae you installed yourself plus your apps (`--all` adds the ones
Homebrew pulled in as dependencies). Names not in the catalog stay with Homebrew. At the
end it prints the `brew uninstall ...` line for what moved; abv0 never removes anything
from Homebrew itself. A saved `brew list` or a Brewfile works too:
`abv0 migrate --from-brew-list brew.txt` or `--brewfile Brewfile`.

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
| `--micro-shards[=SIZE]` | Fetch big files as many small pieces (1M each by default) that the connections share; see [Downloads](#downloads) |
| `--include`, `--exclude <glob,...>` | `hf:` installs: only these files, or not these |
| `--all-files` | `hf:` installs: also the copies in other weight formats |
| `--format epub\|pdf\|txt\|kindle` | `book:` installs: the file type |
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
| `ABV0_SHARD_SIZE` | Turn micro-shards on for every download: `on` (1 MiB pieces) or a size such as `512k` or `4M` |
| `ABV0_BOOKS_DIR` | Where books go, replacing `~/Books` |
| `HF_TOKEN`, `HF_HUB_CACHE`, `HF_HOME` | Hugging Face token and cache, as Hugging Face's own tools read them |
| `HF_HUB_OFFLINE` | `1` never contacts Hugging Face; installs come from the cache only |
| `GITHUB_TOKEN`, `GH_TOKEN` | Optional GitHub token for API requests. `GITHUB_TOKEN` is read first. |
| `ABV0_NO_SCAN` | `1` turns off the install-time malware scan |
| `ABV0_AUTO_UPDATE` | `0` stops commands refreshing a stale catalog |
| `ABV0_UPDATE_HOURS` | How old the catalog may get before it is refreshed (default `24`) |
| `ABV0_AUTO_REMOVE` | `0` keeps unused dependencies after an uninstall |
| `ABV0_AUTO_CLEAN` | `0` turns off the daily cleanup of temporary files |
| `ABV0_AUTO_SELF_UPDATE` | `0` stops `maintain` updating abv0 itself |
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

Measured by the [Benchmark workflow](.github/workflows/bench.yml) on GitHub's hosted
runners, on 2026-10-28, with abv0 2.7.0, Homebrew 6.0–7.0 and zerobrew 0.4.2 installing
the same five tools (ripgrep, fd, bat, jq, fzf). Wall time in milliseconds; lower is
better. Hosted runners are shared machines, so read these as rough sizes, not exact
figures. Run it yourself from the Actions tab.

**Installing five tools**

| | Linux x86_64 | macOS arm64 | macOS x86_64 |
| :--- | ---: | ---: | ---: |
| abv0, cold install | **1,022** | **1,277** | **1,363** |
| zerobrew, cold install | 2,626 | 4,510 | failed ¹ |
| Homebrew, cold install | 42,436 | 4,225 | 4,149 |
| abv0, warm reinstall | 567 | 763 | **881** |
| zerobrew, warm reinstall | **62** | **434** | failed ¹ |
| Homebrew, warm reinstall | 44,243 | 2,497 | 5,495 |

¹ zerobrew 0.4.2 could not install fzf's dependency pcre2 on Intel macOS ("unsupported
archive format").

- **Cold installs** (nothing downloaded yet): abv0 is 2.6–3.5× faster than zerobrew
  and 3–42× faster than Homebrew.
- **Warm reinstalls** (everything already downloaded once): zerobrew is faster. It keeps
  every unpacked package in its store and only relinks, where abv0 unpacks again from its
  download cache. abv0 is still 3–78× faster than Homebrew here.

**Everyday commands** (mean of 20–50 runs)

| | abv0 | Homebrew | zerobrew |
| :--- | ---: | ---: | ---: |
| `--version` (Linux / macOS arm64) | **0.4 / 6.6** | 12.3 / 123.5 | 1.8 / 9.9 |
| `search rip` | **15 / 36** | 660 / 817 | no such command |
| `info ripgrep` | **15 / 52** | 517 / 848 | no such command |
| `list --installed` | **0.6 / 7.9** | 10.8 / 55.3 | no such command |

**One big download** (a 415 MB model file from Hugging Face; ms, with MB/s)

| | Linux x86_64 | macOS arm64 | macOS x86_64 |
| :--- | ---: | ---: | ---: |
| abv0, default | 2,093 (198) | 4,347 (96) | 10,645 (39) |
| abv0 `--micro-shards` | 2,354 (176) | **4,341 (96)** | 10,235 (41) |
| abv0 `--micro-shards=4M` | 2,125 (195) | 4,991 (83) | 8,753 (47) |
| abv0 through curl | **1,344 (309)** | 5,544 (75) | **7,405 (56)** |
| plain curl, one connection | 3,646 (114) | 4,366 (95) | 10,754 (39) |

abv0's rows also check the SHA-256 and write the Hugging Face cache; plain curl only saves
the file. Each figure is one run on a shared machine, so differences under about 20% are
noise: the Intel Mac's link was much slower in this run than in an earlier one. The split
download beats a single connection most on Linux (up to 2.7×). On an ordinary home
connection, where one connection is the bottleneck, the gap is larger: in a sandbox test,
abv0 took 3.3–4.0 s for the same file and plain curl 17.5 s.

### Downloads

- A big file is split over several connections (one per 4 MiB, up to 8;
  `ABV0_CONNECTIONS` changes it) and hashed in order as the pieces land, so the file is
  never read twice.
- **Micro-shards** (`--micro-shards`, or `ABV0_SHARD_SIZE=on` for every download) cut the
  file into many pieces that the connections take from a shared queue, so a fast
  connection takes more and one slow connection cannot hold up the end. Pieces start big
  and shrink toward the end. Use it on uneven links (Wi-Fi, a busy mirror, one stalled
  connection). On a clean, fast link the default is as fast or faster, because every
  piece is one more request. `--micro-shards=4M` sets the smallest piece. (A first
  version used equal 1 MB pieces and ran at about 30 MB/s on these runners, because every
  piece waited for the server to answer; the shrinking pieces fixed that.)
- Verified downloads are kept in a cache, so reinstalling or rolling back needs no network.

### Compared with zerobrew

[zerobrew](https://github.com/lucasgelfond/zerobrew) is a fast client for Homebrew's own
packages, written in Rust. Both are much faster than Homebrew; they solve different
problems.

| | abv0 | zerobrew |
| :--- | :--- | :--- |
| Where packages come from | Its own signed catalog built from upstream releases, any GitHub release (`gh:`), vendors' own downloads | Homebrew's formulas and bottles |
| Platforms | Linux, macOS, **Windows** | Linux, macOS |
| Desktop apps | Mac apps, Windows portable apps, proprietary apps | No casks |
| Catalog size | About 1,500 packages | Homebrew's formulas (thousands), with some unsupported |
| Builds from source | No (prebuilt only) | Yes, as a fallback |
| Checks | Signed catalog, SHA-256 on every download, malware scan before linking | Homebrew's bottle checksums |
| Undo | `history`, `undo`, `rollback`, `switch`, `self-update --rollback` | None |
| Scheduled updates | `autoupdate on` (daily, weekly, every N hours, at a time) | None |
| AI models, books | `hf:` models and datasets, `book:` books and papers | No |
| Cold install (5 tools, measured above) | **faster** (2.6–3.5×) | slower |
| Warm reinstall (measured above) | slower | **faster** |

Choose zerobrew if you want Homebrew's exact packages and formulas, faster. Choose abv0 if
you want one tool across Linux, macOS and Windows that verifies everything, can undo, and
also handles apps, models and books.

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
- **Proprietary software** comes from its maker's own download links, listed in
  `catalog/vendor.txt`. Included so far:
  - apps: Chrome, VS Code, Slack, Discord, Docker Desktop, Notion, Postman, Steam,
    Raycast, Warp, Arc and ChatGPT, plus Firefox and Signal (open source, but published
    only on their makers' sites);
  - command-line tools: Terraform, Vault, Packer, Consul, Nomad and the 1Password CLI.

  The builder follows each link, reads the version from the vendor's update feed or the
  file name, downloads the file once, pins its SHA-256 in the signed catalog and runs the
  malware scan. Mac apps must be a `.dmg` or `.zip` (`.pkg` installers such as Zoom's
  are not supported), and Windows needs a portable `.zip` build. A few vendors (Chrome,
  Docker, Steam, Postman) replace the file behind one fixed link. Until the next daily
  build, abv0 then refuses that download, because its checksum no longer matches.
- **Discovered packages.** Every Monday the workflow also searches GitHub for popular
  projects that publish ready-made downloads (`build-catalog discover`). It searches
  compiled languages such as Go, Rust, C, C++ and Zig, and keeps projects that meet all
  of these:
  - at least 500 stars;
  - not a fork, mirror or archive;
  - active in the last two years and at least six months old;
  - the latest release has files to download.

  The list goes to `catalog/auto-sources.txt`, and those projects get the same checks as
  hand-picked ones: one verified download per platform, the executables found inside, and
  the malware scan. A found project also needs at least one program named after it, so
  a repository that ships only helper programs is left out. If its programs carry only
  the owner's name, the package is called `owner-repo`, so `zen-browser/desktop` becomes
  `zen-browser-desktop` rather than `desktop`. Up to 500 new ones are added a day, each is
  re-checked weekly, and a project with no usable download is skipped for 30 days
  (`catalog/auto-rejects.txt`). A line in `sources.txt` always wins over a discovered one.

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
zig build test                  # 450 test blocks across src/*.zig and tools/*.zig
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
