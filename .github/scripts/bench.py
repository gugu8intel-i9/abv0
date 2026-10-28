#!/usr/bin/env python3
"""Time abv0 against Homebrew and zerobrew on this runner and print a table.

Called by .github/workflows/bench.yml once the release binary is built and
the isolated abv0 home is set. Environment:

  ABV0_HOME, ABV0_BIN_DIR   abv0 home and link directory (set by the workflow)
  BREW_BIN                  Homebrew binary, or empty when Homebrew is missing
  ZB_BIN                    zerobrew's `zb`, or empty when it is not installed
  BENCH_BAT                 "bat" to install bat from the signed catalog, or a
                            gh: spec (gh:sharkdp/bat) where the catalog has no
                            build for this platform
  GITHUB_TOKEN              optional; used by the gh: installs
  GITHUB_WORKSPACE          repository root (default: current directory)
  GITHUB_STEP_SUMMARY       optional; the table is appended here

Each figure is a mean wall time of a child process, measured with
time.perf_counter(), so process start-up and exit are included. An abv0
failure exits 1 and fails the job. A Homebrew failure is shown in its cell
and never fails the job.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

CATALOG = ["ripgrep", "jq"]                          # abv0, signed index
GITHUB = ["gh:sharkdp/fd", "gh:junegunn/fzf"]        # abv0, GitHub releases
BREW = ["ripgrep", "fd", "bat", "jq", "fzf"]         # brew formula names
ABV0_NAMES = ["ripgrep", "fd", "bat", "jq", "fzf"]   # abv0 package names
EXECUTABLES = ["rg", "fd", "bat", "jq", "fzf"]       # commands the tools provide

# One big public file, fetched by each downloader into a fresh place.
BIG_REPO = "Qwen/Qwen2.5-0.5B-Instruct-GGUF"
BIG_FILE = "qwen2.5-0.5b-instruct-q2_k.gguf"   # about 415 MB
BIG_URL = "https://huggingface.co/%s/resolve/main/%s" % (BIG_REPO, BIG_FILE)

SEARCH_RUNS = 20
INFO_RUNS = 20
LIST_RUNS = 20
STARTUP_RUNS = 50

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
DONE = re.compile(r"^done (\d+) packages in ([0-9.]+)ms\s*$", re.M)


class Abv0Failure(Exception):
    pass


def run(argv, env):
    """Run argv once. Returns (wall ms, exit code, output without colours)."""
    start = time.perf_counter()
    proc = subprocess.run(argv, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT)
    wall = (time.perf_counter() - start) * 1000.0
    text = ANSI.sub("", proc.stdout.decode("utf-8", "replace"))
    return wall, proc.returncode, text


def tail(text, lines=20):
    return "\n".join(text.rstrip().splitlines()[-lines:])


def mean_ms(label, fn, runs, strict):
    """One untimed warm-up, then the mean of `runs` timed calls.

    fn() returns (wall ms, exit code, output). A non-zero exit raises
    Abv0Failure when strict, otherwise it returns (None, reason).
    """
    def attempt():
        wall, code, text = fn()
        if code != 0:
            if strict:
                raise Abv0Failure("%s exited %d:\n%s" % (label, code, tail(text)))
            return None, "failed (exit %d)" % code
        return wall, None

    _, err = attempt()
    if err:
        return None, err
    total = 0.0
    for _ in range(runs):
        wall, err = attempt()
        if err:
            return None, err
        total += wall
    return total / runs, None


class Bench(object):
    def __init__(self):
        env = os.environ
        workspace = env.get("GITHUB_WORKSPACE") or os.getcwd()
        temp = env.get("RUNNER_TEMP") or tempfile.gettempdir()
        self.abv0 = os.path.join(workspace, "zig-out", "bin", "abv0")
        self.registry = os.path.join(workspace, "packages", "index.json")
        self.home = env.get("ABV0_HOME") or os.path.join(temp, "abv0-home")
        self.bin_dir = env.get("ABV0_BIN_DIR") or os.path.join(temp, "abv0-bin")
        self.abv0_env = dict(env, ABV0_HOME=self.home, ABV0_BIN_DIR=self.bin_dir)

        self.brew = env.get("BREW_BIN", "")
        self.brew_env = dict(
            env,
            HOMEBREW_NO_AUTO_UPDATE="1",
            HOMEBREW_NO_INSTALL_CLEANUP="1",
            HOMEBREW_NO_ANALYTICS="1",
            HOMEBREW_NO_ENV_HINTS="1",
        )

        self.zb = env.get("ZB_BIN", "")
        self.zb_rows = {}   # label -> zerobrew value
        self.downloads = []  # (label, ms or reason, MB/s)
        self.temp = temp

        bat = env.get("BENCH_BAT") or "bat"
        if bat.startswith("gh:"):
            self.catalog = list(CATALOG)
            self.github = [bat] + GITHUB
        else:
            self.catalog = CATALOG + [bat]
            self.github = list(GITHUB)
        self.bat_source = bat

        self.rows = []    # (label, abv0 value, brew value)
        self.done = []    # (phase, command, packages, ms) from abv0's own output
        self.notes = []
        self.error = None

    # -- abv0 -------------------------------------------------------------

    def abv0_cmd(self, *args):
        return [self.abv0, "--registry", self.registry] + list(args)

    def abv0_phase(self, phase, steps):
        """Run abv0 commands back to back. Returns their total wall time."""
        total = 0.0
        for label, args in steps:
            wall, code, text = run(self.abv0_cmd(*args), self.abv0_env)
            if code != 0:
                raise Abv0Failure("%s: %s exited %d:\n%s"
                                  % (phase, label, code, tail(text)))
            total += wall
            for packages, ms in DONE.findall(text):
                self.done.append((phase, label, int(packages), float(ms)))
        return total

    def abv0_cold(self):
        shutil.rmtree(self.home, ignore_errors=True)
        shutil.rmtree(self.bin_dir, ignore_errors=True)
        # One command for all five, as zerobrew and Homebrew are timed.
        return self.abv0_phase("cold", [
            ("install " + " ".join(self.catalog + self.github), ["install"] + self.catalog + self.github),
        ])

    def abv0_warm(self):
        return self.abv0_phase("warm", [
            ("uninstall", ["uninstall"] + ABV0_NAMES),
            ("install " + " ".join(self.catalog + self.github), ["install"] + self.catalog + self.github),
        ])

    def abv0_check_tools(self):
        """The installed commands must run. A failure here is an abv0 failure."""
        for name in EXECUTABLES:
            path = os.path.join(self.bin_dir, name)
            if not os.path.exists(path):
                raise Abv0Failure("%s was not linked into %s" % (name, self.bin_dir))
            _, code, text = run([path, "--version"], self.abv0_env)
            if code != 0:
                raise Abv0Failure("installed %s does not run (exit %d):\n%s"
                                  % (name, code, tail(text)))

    def abv0_mean(self, label, argv, runs):
        value, _ = mean_ms(label, lambda: run(argv, self.abv0_env), runs, strict=True)
        return value

    # -- Homebrew ---------------------------------------------------------

    def brew_run(self, *args):
        return run([self.brew] + list(args), self.brew_env)

    def brew_clear(self):
        """Uninstall the test formulae if the runner preinstalled them.

        Returns the names that are still installed afterwards.
        """
        for name in BREW:
            _, code, _ = self.brew_run("list", "--formula", name)
            if code == 0:
                _, code, text = self.brew_run("uninstall", "--ignore-dependencies", name)
                if code != 0:
                    self.notes.append("could not uninstall preinstalled %s: %s"
                                      % (name, tail(text, 3)))
        leftover = []
        for name in BREW:
            _, code, _ = self.brew_run("list", "--formula", name)
            if code == 0:
                leftover.append(name)
        return leftover

    def brew_clear_downloads(self):
        """Empty brew's bottle download cache so the cold row starts cold."""
        _, code, text = self.brew_run("--cache")
        if code == 0 and text.strip():
            path = text.strip().splitlines()[-1]
            shutil.rmtree(os.path.join(path, "downloads"), ignore_errors=True)

    def brew_cold(self):
        leftover = self.brew_clear()
        if leftover:
            return "failed (still installed: %s)" % ", ".join(leftover)
        self.brew_clear_downloads()
        wall, code, text = self.brew_run("install", *BREW)
        if code != 0:
            self.notes.append("brew install failed (exit %d):\n%s" % (code, tail(text, 8)))
            return "failed (exit %d)" % code
        return wall

    def brew_warm(self):
        wall1, code, text = self.brew_run("uninstall", *BREW)
        if code != 0:
            self.notes.append("brew uninstall failed (exit %d):\n%s" % (code, tail(text, 8)))
            return "failed (exit %d)" % code
        wall2, code, text = self.brew_run("install", *BREW)
        if code != 0:
            self.notes.append("brew reinstall failed (exit %d):\n%s" % (code, tail(text, 8)))
            return "failed (exit %d)" % code
        return wall1 + wall2

    def brew_mean(self, label, argv, runs):
        if not self.brew:
            return "n/a"
        value, err = mean_ms(label, lambda: run(argv, self.brew_env), runs, strict=False)
        if err:
            self.notes.append("%s: %s" % (label, err))
            return err
        return value

    # -- zerobrew ---------------------------------------------------------

    def zb_run(self, *args):
        return run([self.zb] + list(args), dict(os.environ))

    def zb_install(self, label):
        wall, code, text = self.zb_run("install", *BREW)
        if code != 0:
            self.notes.append("zb %s failed (exit %d): %s" % (label, code, tail(text, 4)))
            return "failed (exit %d)" % code
        return wall

    def zb_cold(self):
        if not self.zb:
            return "n/a"
        return self.zb_install("install")

    def zb_warm(self):
        if not self.zb:
            return "n/a"
        wall1, code, text = self.zb_run("uninstall", *BREW)
        if code != 0:
            self.notes.append("zb uninstall failed (exit %d): %s" % (code, tail(text, 4)))
            return "failed (exit %d)" % code
        wall2 = self.zb_install("reinstall")
        return wall1 + wall2 if isinstance(wall2, float) else wall2

    # -- one big download -------------------------------------------------

    def download_row(self, label, argv, env, cleanup):
        shutil.rmtree(cleanup, ignore_errors=True)
        wall, code, text = run(argv, env)
        if code != 0:
            self.notes.append("%s failed (exit %d): %s" % (label, code, tail(text, 4)))
            self.downloads.append((label, "failed (exit %d)" % code, "n/a"))
        else:
            size_mb = 415182688 / 1e6
            self.downloads.append((label, wall, "%.0f" % (size_mb / (wall / 1000.0))))
        print("%-44s %s" % (label, fmt(self.downloads[-1][1])), flush=True)
        shutil.rmtree(cleanup, ignore_errors=True)

    def measure_download(self):
        cache = os.path.join(self.temp, "hf-bench")
        spec = "hf:" + BIG_REPO
        env = dict(self.abv0_env, HF_HUB_CACHE=cache)
        base = [self.abv0, "install", spec, "--include", BIG_FILE, "-q"]
        self.download_row("abv0, default (one chunk per connection)", base, env, cache)
        self.download_row("abv0 --micro-shards (1 MB shards)", base + ["--micro-shards"], env, cache)
        self.download_row("abv0 --micro-shards=4M", base + ["--micro-shards=4M"], env, cache)
        self.download_row("abv0 through curl (ABV0_DOWNLOADER=curl)", base,
                          dict(env, ABV0_DOWNLOADER="curl"), cache)
        out = os.path.join(self.temp, "plain-curl.bin")
        if shutil.which("curl"):
            self.download_row("plain curl (one connection, no checks)",
                              ["curl", "-sSfL", "-o", out, BIG_URL], dict(os.environ), out)

    # -- measurement ------------------------------------------------------

    def add(self, label, abv0_value, brew_value):
        self.rows.append((label, abv0_value, brew_value))
        print("%-44s abv0 %-14s brew %s" % (label, fmt(abv0_value), fmt(brew_value)),
              flush=True)

    def measure(self):
        brew = bool(self.brew)

        print("==> cold install (fresh abv0 home)", flush=True)
        abv0_cold = self.abv0_cold()
        self.abv0_check_tools()
        brew_cold = self.brew_cold() if brew else "n/a"
        self.zb_rows["Cold install: rg, fd, bat, jq, fzf"] = self.zb_cold()
        self.add("Cold install: rg, fd, bat, jq, fzf", abv0_cold, brew_cold)

        print("==> warm reinstall (uninstall + install)", flush=True)
        abv0_warm = self.abv0_warm()
        self.abv0_check_tools()
        brew_warm = self.brew_warm() if brew else "n/a"
        self.zb_rows["Warm reinstall: uninstall + install"] = self.zb_warm()
        self.add("Warm reinstall: uninstall + install", abv0_warm, brew_warm)

        print("==> repeated commands", flush=True)
        self.add("search rip (mean of %d)" % SEARCH_RUNS,
                 self.abv0_mean("abv0 search", self.abv0_cmd("search", "rip"), SEARCH_RUNS),
                 self.brew_mean("brew search", [self.brew, "search", "rip"], SEARCH_RUNS))
        self.add("info ripgrep (mean of %d)" % INFO_RUNS,
                 self.abv0_mean("abv0 info", self.abv0_cmd("info", "ripgrep"), INFO_RUNS),
                 self.brew_mean("brew info", [self.brew, "info", "ripgrep"], INFO_RUNS))
        self.add("list --installed (mean of %d)" % LIST_RUNS,
                 self.abv0_mean("abv0 list --installed",
                                self.abv0_cmd("list", "--installed"), LIST_RUNS),
                 self.brew_mean("brew list", [self.brew, "list", "--formula"], LIST_RUNS))
        self.add("list, registry (mean of %d)" % LIST_RUNS,
                 self.abv0_mean("abv0 list", self.abv0_cmd("list"), LIST_RUNS),
                 "no equivalent")
        self.add("--version startup (mean of %d)" % STARTUP_RUNS,
                 self.abv0_mean("abv0 --version", [self.abv0, "--version"], STARTUP_RUNS),
                 self.brew_mean("brew --version", [self.brew, "--version"], STARTUP_RUNS))
        self.add("help startup (mean of %d)" % STARTUP_RUNS,
                 self.abv0_mean("abv0 help", [self.abv0, "help"], STARTUP_RUNS),
                 self.brew_mean("brew help", [self.brew, "help"], STARTUP_RUNS))
        if self.zb:
            self.zb_rows["--version startup (mean of %d)" % STARTUP_RUNS] = self.zb_mean(
                "zb --version", [self.zb, "--version"], STARTUP_RUNS)

        print("==> one big download", flush=True)
        self.measure_download()

    def zb_mean(self, label, argv, runs):
        value, err = mean_ms(label, lambda: run(argv, dict(os.environ)), runs, strict=False)
        if err:
            self.notes.append("%s: %s" % (label, err))
            return err
        return value

    # -- report -----------------------------------------------------------

    def version_line(self, argv, env):
        _, code, text = run(argv, env)
        lines = [l for l in text.splitlines() if l.strip()]
        if code != 0 or not lines:
            return "unknown"
        return lines[0].strip()

    def report(self):
        runner = "%s %s" % (os.environ.get("RUNNER_OS", platform_name()),
                            os.environ.get("RUNNER_ARCH", ""))
        abv0_ver = self.version_line([self.abv0, "--version"], self.abv0_env) \
            if os.path.exists(self.abv0) else "not built"
        brew_ver = self.version_line([self.brew, "--version"], self.brew_env) \
            if self.brew else "not installed"

        out = []
        out.append("## abv0 vs Homebrew and zerobrew on %s" % runner.strip())
        out.append("")
        if self.error:
            out.append("**abv0 failed before every row was measured:**")
            out.append("")
            out.append("```")
            out.append(self.error.rstrip())
            out.append("```")
            out.append("")
        out.append("Wall time in milliseconds. Speedup is brew / abv0, so above "
                   "1.00× means abv0 was faster. Cold and warm install rows are "
                   "single runs; repeated rows are means with one untimed warm-up.")
        out.append("")
        out.append("| Operation | abv0 (ms) | brew (ms) | vs brew | zerobrew (ms) | vs zerobrew |")
        out.append("|---|---:|---:|---:|---:|---:|")
        for label, abv0_value, brew_value in self.rows:
            zb_value = self.zb_rows.get(label, "n/a" if not self.zb else "no equivalent")
            out.append("| %s | %s | %s | %s | %s | %s |" % (
                label, fmt(abv0_value), fmt(brew_value), speedup(abv0_value, brew_value),
                fmt(zb_value), speedup(abv0_value, zb_value)))
        out.append("")
        if self.downloads:
            out.append("### One big download (%s, about 415 MB)" % BIG_FILE)
            out.append("")
            out.append("abv0 rows verify the SHA-256 and write the Hugging Face cache; "
                       "plain curl only saves the file.")
            out.append("")
            out.append("| Downloader | ms | MB/s |")
            out.append("|---|---:|---:|")
            for label, value, rate in self.downloads:
                out.append("| %s | %s | %s |" % (label, fmt(value), rate))
            out.append("")
        if self.done:
            out.append("### abv0's own `done N packages in X ms` lines")
            out.append("")
            out.append("| Phase | Command | Packages | done (ms) |")
            out.append("|---|---|---:|---:|")
            for phase, label, packages, ms in self.done:
                out.append("| %s | %s | %d | %.2f |" % (phase, label, packages, ms))
            out.append("")
        out.append("### Setup")
        out.append("")
        zb_ver = self.version_line([self.zb, "--version"], dict(os.environ)) \
            if self.zb else "not installed"
        out.append("- abv0: `%s`; Homebrew: `%s`; zerobrew: `%s`" % (abv0_ver, brew_ver, zb_ver))
        out.append("- abv0 reads the signed `packages/index.json` from the checkout; "
                   "the install runs in a fresh `ABV0_HOME` (cold) and is then "
                   "uninstalled and reinstalled (warm).")
        if self.brew:
            out.append("- Homebrew's preinstalled copies of the five formulae are "
                       "uninstalled first, and its bottle download cache is cleared "
                       "before the cold row.")
        if self.bat_source.startswith("gh:"):
            out.append("- bat for abv0 comes from `%s` on this runner: the signed "
                       "catalog has no build for this platform."
                       % self.bat_source)
        if not self.brew:
            out.append("- Homebrew is not installed on this runner; brew cells are n/a.")
        if self.notes:
            out.append("")
            out.append("### Notes")
            out.append("")
            for note in self.notes:
                out.append("- %s" % note.replace("\n", " ").strip())
        text = "\n".join(out) + "\n"

        print()
        print(text)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a") as handle:
                handle.write(text)


def platform_name():
    return sys.platform


def fmt(value):
    if isinstance(value, float):
        return "%.1f" % value
    return str(value)


def speedup(abv0_value, brew_value):
    if isinstance(abv0_value, float) and isinstance(brew_value, float) and abv0_value > 0:
        return "%.2f×" % (brew_value / abv0_value)
    return "n/a"


def main():
    bench = Bench()
    try:
        bench.measure()
    except Abv0Failure as exc:
        bench.error = str(exc)
    bench.report()
    if bench.error:
        print("abv0 failed:\n" + bench.error, file=sys.stderr)
        print("::error::abv0 failed; see the log above")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
