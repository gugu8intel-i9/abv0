//! abv0 command-line interface.

const std = @import("std");
const builtin = @import("builtin");

const registry = @import("registry.zig");
const store = @import("store.zig");
const stream = @import("stream.zig");
const platform = @import("platform.zig");
const safepath = @import("safepath.zig");
const term = @import("term.zig");
const net = @import("net.zig");
const abvindex = @import("abvindex.zig");
const tui = @import("tui.zig");
const auto = @import("auto.zig");
const archive = @import("archive.zig");
const bloom = @import("bloom.zig");
const wal = @import("wal.zig");
const sign = @import("sign.zig");
const cmds_extra = @import("cmds_extra.zig");
const ghrelease = @import("ghrelease.zig");
const ghverify = @import("ghverify.zig");

pub const version = "2.6.0";

const default_registry_url = "https://raw.githubusercontent.com/gugu8intel-i9/abv0/main/packages/index.json";

/// ABV0_REGISTRY_URL points abv0 at a mirror. The manifest is still checked
/// against the compiled-in key, so a mirror can serve it but not alter it.
fn registryUrl() []const u8 {
    return platform.registryUrlOverride() orelse default_registry_url;
}
const issues_url = "https://github.com/gugu8intel-i9/abv0/issues/new";

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

const Args = struct {
    command: ?[]const u8 = null,
    rest: std.ArrayList([]const u8),

    platform_name: ?[]const u8 = null,
    file: ?[]const u8 = null,
    jobs: ?usize = null,
    /// Load this manifest instead of the installed registry (`--registry`).
    registry_path: ?[]const u8 = null,

    json: bool = false,
    force: bool = false,
    micro_split: bool = false,
    no_stream: bool = false,
    allow_unverified: bool = false,
    allow_suspicious: bool = false,
    allow_unsigned_manifest: bool = false,
    /// `--color=auto|always|never`; `--no-color` means `never`.
    color: term.ColorMode = .auto,
    want_help: bool = false,
    want_version: bool = false,
    report_bug: bool = false,
    report_malware: bool = false,
    /// `list --installed`: show what is in the store instead of the registry.
    installed: bool = false,
    check: bool = false,
    /// `--dry-run`: describe what would change and change nothing.
    dry_run: bool = false,
    /// `-q` / `--quiet`: no progress or summary lines. Errors still print.
    quiet: bool = false,
    /// `-v` / `--verbose`: extra detail per package (urls, store paths, timings).
    verbose: bool = false,
    /// `deps --tree`: nested instead of flat.
    tree: bool = false,
    /// `search --online`: also ask GitHub's repository search.
    online: bool = false,
    /// `home --open`: open the page instead of only printing it.
    open: bool = false,
    /// `migrate --install`: install what matched.
    install: bool = false,
    /// `upgrade --all`: every outdated package, said out loud.
    all: bool = false,
    /// `migrate --from-brew-list FILE`: names saved from `brew list --formula`.
    from_brew_list: ?[]const u8 = null,
    /// `migrate --brewfile FILE`: names from a Brewfile's `brew "x"` lines.
    brewfile: ?[]const u8 = null,

    fn deinit(self: *Args) void {
        self.rest.deinit();
    }
};

const ParseError = error{ MissingOptionValue, UnknownOption, InvalidNumber, OutOfMemory };

/// The option a parse error is about, and the value that could not be used.
/// The message names both, so a bad flag is easy to find.
const ArgDiag = struct {
    option: []const u8 = "",
    value: []const u8 = "",
};

fn parseArgs(allocator: std.mem.Allocator, argv: []const []const u8) ParseError!Args {
    var diag = ArgDiag{};
    return parseArgsDiag(allocator, argv, &diag);
}

fn failArg(diag: *ArgDiag, option: []const u8, value: []const u8, err: ParseError) ParseError {
    diag.* = .{ .option = option, .value = value };
    return err;
}

fn parseArgsDiag(allocator: std.mem.Allocator, argv: []const []const u8, diag: *ArgDiag) ParseError!Args {
    var args = Args{ .rest = std.ArrayList([]const u8).init(allocator) };
    errdefer args.deinit();

    var i: usize = 0;
    var after_ddash = false;

    while (i < argv.len) : (i += 1) {
        const arg = argv[i];

        if (after_ddash) {
            try args.rest.append(arg);
            continue;
        }
        if (std.mem.eql(u8, arg, "--")) {
            after_ddash = true;
            continue;
        }

        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            args.want_help = true;
        } else if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-V")) {
            args.want_version = true;
        } else if (std.mem.eql(u8, arg, "--json")) {
            args.json = true;
        } else if (std.mem.eql(u8, arg, "--force")) {
            args.force = true;
        } else if (std.mem.eql(u8, arg, "--micro-split")) {
            args.micro_split = true;
        } else if (std.mem.eql(u8, arg, "--no-stream")) {
            args.no_stream = true;
        } else if (std.mem.eql(u8, arg, "--allow-unverified")) {
            args.allow_unverified = true;
        } else if (std.mem.eql(u8, arg, "--allow-suspicious")) {
            args.allow_suspicious = true;
        } else if (std.mem.eql(u8, arg, "--allow-unsigned-manifest")) {
            args.allow_unsigned_manifest = true;
        } else if (std.mem.eql(u8, arg, "--registry")) {
            i += 1;
            if (i >= argv.len) return failArg(diag, arg, "", error.MissingOptionValue);
            args.registry_path = argv[i];
        } else if (std.mem.eql(u8, arg, "--no-color")) {
            args.color = .never;
        } else if (std.mem.eql(u8, arg, "--color") or std.mem.startsWith(u8, arg, "--color=")) {
            // `--color=when` or `--color when`.
            const value = if (arg.len > "--color".len) arg["--color=".len..] else blk: {
                i += 1;
                if (i >= argv.len) return failArg(diag, arg, "", error.MissingOptionValue);
                break :blk argv[i];
            };
            args.color = std.meta.stringToEnum(term.ColorMode, value) orelse
                return failArg(diag, arg, value, error.UnknownOption);
        } else if (std.mem.eql(u8, arg, "--bug")) {
            args.report_bug = true;
        } else if (std.mem.eql(u8, arg, "--malware")) {
            args.report_malware = true;
        } else if (std.mem.eql(u8, arg, "--installed")) {
            args.installed = true;
        } else if (std.mem.eql(u8, arg, "--check")) {
            args.check = true;
        } else if (std.mem.eql(u8, arg, "--dry-run")) {
            args.dry_run = true;
        } else if (std.mem.eql(u8, arg, "-q") or std.mem.eql(u8, arg, "--quiet")) {
            args.quiet = true;
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--verbose")) {
            args.verbose = true;
        } else if (std.mem.eql(u8, arg, "--tree")) {
            args.tree = true;
        } else if (std.mem.eql(u8, arg, "--online")) {
            args.online = true;
        } else if (std.mem.eql(u8, arg, "--open")) {
            args.open = true;
        } else if (std.mem.eql(u8, arg, "--install")) {
            args.install = true;
        } else if (std.mem.eql(u8, arg, "--all")) {
            args.all = true;
        } else if (std.mem.eql(u8, arg, "--from-brew-list")) {
            i += 1;
            if (i >= argv.len) return failArg(diag, arg, "", error.MissingOptionValue);
            args.from_brew_list = argv[i];
        } else if (std.mem.eql(u8, arg, "--brewfile")) {
            i += 1;
            if (i >= argv.len) return failArg(diag, arg, "", error.MissingOptionValue);
            args.brewfile = argv[i];
        } else if (std.mem.eql(u8, arg, "--platform")) {
            // The original called args_it.next() with no null check, so a
            // trailing `--platform` silently produced a null platform.
            i += 1;
            if (i >= argv.len) return failArg(diag, arg, "", error.MissingOptionValue);
            args.platform_name = argv[i];
        } else if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--file")) {
            i += 1;
            if (i >= argv.len) return failArg(diag, arg, "", error.MissingOptionValue);
            args.file = argv[i];
        } else if (std.mem.eql(u8, arg, "-j") or std.mem.eql(u8, arg, "--jobs")) {
            i += 1;
            if (i >= argv.len) return failArg(diag, arg, "", error.MissingOptionValue);
            args.jobs = std.fmt.parseInt(usize, argv[i], 10) catch
                return failArg(diag, arg, argv[i], error.InvalidNumber);
        } else if (std.mem.eql(u8, arg, "--daily") or std.mem.eql(u8, arg, "--weekly")) {
            // `autoupdate on` reads these from the rest.
            try args.rest.append(arg);
        } else if (arg.len > 1 and arg[0] == '-' and !std.mem.eql(u8, arg, "-")) {
            return failArg(diag, arg, "", error.UnknownOption);
        } else if (args.command == null) {
            args.command = arg;
        } else {
            try args.rest.append(arg);
        }
    }
    return args;
}

/// The one-line message for an argument error, naming the option and value.
fn argErrorMessage(buf: []u8, e: ParseError, diag: ArgDiag) []const u8 {
    return switch (e) {
        error.MissingOptionValue => std.fmt.bufPrint(buf, "option '{}' requires a value", .{safe(diag.option)}) catch "option requires a value",
        error.UnknownOption => std.fmt.bufPrint(buf, "unknown option '{}' (see `abv0 help`)", .{safe(diag.option)}) catch "unknown option",
        error.InvalidNumber => std.fmt.bufPrint(buf, "option '{}' requires a number, got '{}'", .{ safe(diag.option), safe(diag.value) }) catch "option requires a number",
        else => "out of memory",
    };
}

// ---------------------------------------------------------------------------
// Output mode and user-facing messages
// ---------------------------------------------------------------------------

/// How this process talks, set once from the global flags in `run`.
const Output = struct {
    /// `-q`: no progress or summary lines. Errors and results still print.
    quiet: bool = false,
    /// `-v`: extra detail per package.
    verbose: bool = false,
    /// `--dry-run`: describe the change and make none.
    dry_run: bool = false,
    /// `--json`: stdout carries the JSON document and nothing else.
    json: bool = false,
};

var output: Output = .{};

/// A progress or summary line, shown unless `-q` or `--json` is in effect.
fn say(comptime fmt: []const u8, args: anytype) void {
    if (!output.quiet) term.print(fmt, args);
}

/// An extra detail line, shown only with `-v`.
fn detail(comptime fmt: []const u8, args: anytype) void {
    if (output.verbose) term.print(fmt, args);
}

/// A sentence someone can act on for a common failure, with the next step
/// where there is one. Anything not listed falls back to the error's name.
fn explain(err: anyerror) []const u8 {
    return switch (err) {
        error.FileNotFound => "file not found (check the path)",
        error.AccessDenied, error.PermissionDenied => "permission denied (check the file's owner and mode)",
        error.UnknownHostName,
        error.TemporaryNameServerFailure,
        error.NameServerFailure,
        error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.ConnectionTimedOut,
        error.NetworkUnreachable,
        => "network error (check your connection or proxy settings, then retry)",
        net.Error.DownloadFailed => "download failed (check your connection, then retry)",
        net.Error.NoDownloaderAvailable => "no download tool found (install curl and make sure it is on PATH)",
        net.Error.UnsafeUrl => "refused a download URL that is not plain https",
        store.StoreError.ChecksumMismatch => "checksum mismatch: the download does not match the pinned sha256 (retry; if it persists, run `abv0 update`)",
        store.StoreError.SuspiciousPackage => "the malware scan blocked it (use --allow-suspicious to install it anyway)",
        store.StoreError.ChecksumMissing => "no pinned checksum for this package (use --allow-unverified to install it anyway)",
        store.StoreError.BinaryConflict => "an executable with this name already belongs to another package (use --force to replace it)",
        store.StoreError.DownloadLooksLikeErrorPage => "the server sent an error page instead of the package (retry later)",
        store.StoreError.UnpackFailed => "could not unpack the archive (the download may be incomplete; retry)",
        store.StoreError.UnsupportedPlatform => "this package has no build for this platform",
        else => @errorName(err),
    };
}

/// Longest name the suggestion code compares. Longer names are never suggested.
const max_suggest_len = 64;
/// Largest edit distance that still counts as "did you mean".
const max_suggest_distance = 2;

/// Optimal-string-alignment distance: Levenshtein, plus swapping two adjacent
/// bytes as one edit, so `isntall` is one edit away from `install`.
fn editDistance(a: []const u8, b: []const u8) usize {
    if (a.len > max_suggest_len or b.len > max_suggest_len) return max_suggest_len + 1;
    var d: [max_suggest_len + 1][max_suggest_len + 1]usize = undefined;
    for (0..a.len + 1) |i| d[i][0] = i;
    for (0..b.len + 1) |j| d[0][j] = j;
    for (1..a.len + 1) |i| {
        for (1..b.len + 1) |j| {
            const cost: usize = if (a[i - 1] == b[j - 1]) 0 else 1;
            var best = @min(@min(d[i - 1][j] + 1, d[i][j - 1] + 1), d[i - 1][j - 1] + cost);
            if (i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]) {
                best = @min(best, d[i - 2][j - 2] + 1);
            }
            d[i][j] = best;
        }
    }
    return d[a.len][b.len];
}

/// The candidate closest to `name`, when one is within reach: edit distance at
/// most 2, or a candidate that starts with `name` (`ripg` suggests `ripgrep`).
/// Ties go to the earlier candidate, so the order given decides them.
fn closest(name: []const u8, candidates: []const []const u8) ?[]const u8 {
    if (name.len == 0) return null;
    var best: ?[]const u8 = null;
    var best_score: usize = max_suggest_distance + 1;
    for (candidates) |cand| {
        const dist = editDistance(name, cand);
        const prefix = name.len >= 3 and std.mem.startsWith(u8, cand, name);
        const score = if (prefix) @min(dist, max_suggest_distance) else dist;
        if (score <= max_suggest_distance and score < best_score) {
            best = cand;
            best_score = score;
        }
    }
    return best;
}

/// The host part of a URL, for showing where bytes will come from. Returns
/// "?" for anything without a scheme.
fn urlHost(url: []const u8) []const u8 {
    const start = std.mem.indexOf(u8, url, "://") orelse return "?";
    const rest = url[start + 3 ..];
    const end = std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len;
    const host_port = rest[0..end];
    // Drop any user:password@ part; it is never useful to show.
    const host = if (std.mem.lastIndexOfScalar(u8, host_port, '@')) |at| host_port[at + 1 ..] else host_port;
    return if (host.len == 0) "?" else host;
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

const Flag = struct {
    name: []const u8,
    help: []const u8,
};

/// One command as `abv0 <cmd> --help` shows it. `commands` below is the single
/// list of commands: help lookup, `did you mean` and the tests all read it.
const Command = struct {
    name: []const u8,
    /// Arguments after the name, for example `<pkg>...`.
    args: []const u8 = "",
    summary: []const u8,
    flags: []const Flag = &.{},
    example: []const u8,
};

const dry_run_flag = Flag{ .name = "--dry-run", .help = "Show what would change; change nothing" };
const json_flag = Flag{ .name = "--json", .help = "Machine-readable output on stdout" };
const quiet_flag = Flag{ .name = "-q, --quiet", .help = "Suppress progress lines (errors still print)" };
const verbose_flag = Flag{ .name = "-v, --verbose", .help = "Also print urls, store paths and timings" };
const platform_flag = Flag{ .name = "--platform <tag>", .help = "Target platform (default: this machine)" };
const jobs_flag = Flag{ .name = "-j, --jobs <n>", .help = "Parallel workers" };
const file_flag = Flag{ .name = "-f, --file <path>", .help = "Manifest path (default: Brewfile)" };
const unverified_flag = Flag{ .name = "--allow-unverified", .help = "Permit installs without a verified checksum" };
const suspicious_flag = Flag{ .name = "--allow-suspicious", .help = "Install even if the malware scan blocks the package" };
const unsigned_flag = Flag{ .name = "--allow-unsigned-manifest", .help = "Skip signature and replay checks (UNSAFE)" };
const force_flag = Flag{ .name = "--force", .help = "Overwrite files and replace conflicting bin links" };
const installed_flag = Flag{ .name = "--installed", .help = "Show what is installed, not the registry" };
const bug_flag = Flag{ .name = "--bug", .help = "Report a bug (default)" };
const malware_flag = Flag{ .name = "--malware", .help = "Report a suspicious package" };

const commands = [_]Command{
    .{
        .name = "install",
        .args = "<pkg|gh:owner/repo[@tag]>...",
        .summary = "Install packages and their dependencies, verified, in parallel. A gh:owner/repo spec installs that project's own GitHub release (no recipe needed), checked against GitHub's sha256 digest or the release's checksums file.",
        .flags = &.{
            dry_run_flag,    json_flag,                                                                         jobs_flag,  platform_flag,
            unverified_flag, suspicious_flag,                                                                   force_flag, quiet_flag,
            verbose_flag,    .{ .name = "--micro-split", .help = "Parallel ranged download for large assets" },
        },
        .example = "abv0 install jq gh:BurntSushi/ripgrep",
    },
    .{
        .name = "uninstall",
        .args = "<pkg>...",
        .summary = "Remove packages and the links they created.",
        .flags = &.{ dry_run_flag, quiet_flag, verbose_flag },
        .example = "abv0 uninstall jq",
    },
    .{
        .name = "upgrade",
        .args = "[pkg]...",
        .summary = "Upgrade the named packages, or every outdated one when none are named (--all says so explicitly). Pinned packages are skipped unless named. The previous version is kept so `abv0 rollback` can return to it.",
        .flags = &.{
            .{ .name = "--all", .help = "Upgrade every outdated package (the default with no names)" },
            dry_run_flag,
            jobs_flag,
            platform_flag,
            quiet_flag,
            verbose_flag,
        },
        .example = "abv0 upgrade --all",
    },
    .{
        .name = "outdated",
        .summary = "List installed packages that have a newer version in the registry; pinned ones are marked.",
        .flags = &.{ json_flag, platform_flag },
        .example = "abv0 outdated --json",
    },
    .{
        .name = "list",
        .summary = "List registry packages, or with --installed, the versions in the store.",
        .flags = &.{ installed_flag, json_flag, platform_flag },
        .example = "abv0 list --installed",
    },
    .{
        .name = "browse",
        .args = "",
        .summary = "Pick packages from the catalog in a full-screen list and install them. Type to search, arrow keys to move, space to pick, enter to install, esc to quit.",
        .flags = &.{ platform_flag, unverified_flag, suspicious_flag, force_flag },
        .example = "abv0 browse",
    },
    .{
        .name = "search",
        .args = "<query>",
        .summary = "Find registry packages whose name or description contains <query>. With --online, then ask GitHub's repository search and list projects you can install with gh:owner/repo.",
        .flags = &.{ .{ .name = "--online", .help = "Also search GitHub repositories by name (10 results, most stars first)" }, json_flag },
        .example = "abv0 search --online json",
    },
    .{
        .name = "info",
        .args = "<pkg>",
        .summary = "Show a package's catalog entry plus what is installed: versions (active one marked), size on disk, linked executables and where it came from.",
        .flags = &.{ json_flag, platform_flag },
        .example = "abv0 info jq",
    },
    .{
        .name = "deps",
        .args = "<pkg>",
        .summary = "List what a catalog package depends on, dependencies first (the order install uses).",
        .flags = &.{ .{ .name = "--tree", .help = "Show the dependencies as a tree" }, json_flag },
        .example = "abv0 deps --tree ffmpeg",
    },
    .{
        .name = "uses",
        .args = "<pkg>",
        .summary = "List the installed packages that depend on <pkg>.",
        .flags = &.{ json_flag, platform_flag },
        .example = "abv0 uses libfoo",
    },
    .{
        .name = "leaves",
        .summary = "List installed packages that no other installed package depends on.",
        .flags = &.{ json_flag, platform_flag },
        .example = "abv0 leaves",
    },
    .{
        .name = "switch",
        .args = "<pkg> <version>",
        .summary = "Make an installed version the active one: relink its executables to that version's store directory. Needs the version to be in the store (see `abv0 info`).",
        .flags = &.{ json_flag, platform_flag, quiet_flag },
        .example = "abv0 switch jq 1.6",
    },
    .{
        .name = "rollback",
        .args = "<pkg>",
        .summary = "Switch to the version installed just before the active one. `upgrade` keeps that previous version for this; `cleanup` removes it.",
        .flags = &.{ json_flag, platform_flag, quiet_flag },
        .example = "abv0 rollback jq",
    },
    .{
        .name = "home",
        .args = "<pkg>",
        .summary = "Print a package's homepage (for gh:owner/repo, its GitHub page).",
        .flags = &.{ .{ .name = "--open", .help = "Open it in the default browser" }, json_flag },
        .example = "abv0 home --open ripgrep",
    },
    .{
        .name = "migrate",
        .summary = "Move a Homebrew install to abv0. With no file, the Homebrew on this machine is read straight from disk in milliseconds (HOMEBREW_PREFIX, else /opt/homebrew, /usr/local or Linuxbrew); brew is never run. Takes what you installed by hand plus your apps, matches them to the catalog, and with --install installs them in parallel and keeps your brew pins.",
        .flags = &.{
            .{ .name = "--from-brew-list <file>", .help = "Names saved from `brew list --formula`, one per line" },
            .{ .name = "--brewfile <file>", .help = "A Brewfile; its brew \"name\" lines are read" },
            .{ .name = "--install", .help = "Install the matched packages (parallel, verified)" },
            .{ .name = "--all", .help = "Also take formulae Homebrew installed as dependencies" },
            dry_run_flag,
            json_flag,
            jobs_flag,
            platform_flag,
            quiet_flag,
        },
        .example = "abv0 migrate --install",
    },
    .{
        .name = "run",
        .args = "<pkg> [-- args...]",
        .summary = "Run a package's executable, installing the package first if needed.",
        .flags = &.{ platform_flag, unverified_flag },
        .example = "abv0 run ripgrep -- --version",
    },
    .{
        .name = "shell",
        .args = "<pkg>...",
        .summary = "Open a subshell where only the named packages are on PATH.",
        .flags = &.{platform_flag},
        .example = "abv0 shell jq fd",
    },
    .{
        .name = "bundle",
        .args = "[install|dump]",
        .summary = "Install the packages listed in a Brewfile, or write the installed ones to one.",
        .flags = &.{ file_flag, dry_run_flag, jobs_flag, force_flag, quiet_flag, verbose_flag },
        .example = "abv0 bundle install -f Brewfile --dry-run",
    },
    .{
        .name = "update",
        .summary = "Download and verify the registry index.",
        .flags = &.{unsigned_flag},
        .example = "abv0 update",
    },
    .{
        .name = "sync",
        .summary = "Recompile the local index and the SQL export.",
        .example = "abv0 sync",
    },
    .{
        .name = "doctor",
        .summary = "Check PATH, store permissions and links.",
        .flags = &.{ json_flag, platform_flag },
        .example = "abv0 doctor --json",
    },
    .{
        .name = "fix",
        .summary = "Repair broken links and permissions.",
        .example = "abv0 fix",
    },
    .{
        .name = "detect",
        .args = "<pkg>",
        .summary = "Scan every file of an installed package for malware-like patterns (exit 1 if anything is found).",
        .example = "abv0 detect jq",
    },
    .{
        .name = "benchmark",
        .summary = "Measure registry lookups, index load, linking and hashing.",
        .example = "abv0 benchmark",
    },
    .{
        .name = "gc",
        .summary = "Remove temporary files and stale sandboxes.",
        .example = "abv0 gc",
    },
    .{
        .name = "reset",
        .summary = "Uninstall every package and clear the store.",
        .example = "abv0 reset",
    },
    .{
        .name = "report",
        .args = "[subject]",
        .summary = "Open a prefilled GitHub issue for a bug or a suspicious package.",
        .flags = &.{ bug_flag, malware_flag },
        .example = "abv0 report --malware jq",
    },
    .{
        .name = "pin",
        .args = "<pkg>",
        .summary = "Hold a package at its installed version; `upgrade` skips it.",
        .example = "abv0 pin jq",
    },
    .{
        .name = "unpin",
        .args = "<pkg>",
        .summary = "Let `upgrade` update a pinned package again.",
        .example = "abv0 unpin jq",
    },
    .{
        .name = "pinned",
        .summary = "List pinned packages.",
        .example = "abv0 pinned",
    },
    .{
        .name = "cleanup",
        .summary = "Remove old versions (including the previous one `upgrade` keeps for rollback), stale temporary files and the download cache. The active version is always kept.",
        .flags = &.{dry_run_flag},
        .example = "abv0 cleanup --dry-run",
    },
    .{
        .name = "completions",
        .args = "<bash|zsh|fish|pwsh>",
        .summary = "Print a shell completion script.",
        .example = "abv0 completions zsh > ~/.zfunc/_abv0",
    },
    .{
        .name = "which",
        .args = "<bin>",
        .summary = "Show which package owns a command in abv0's bin directory.",
        .example = "abv0 which rg",
    },
    .{
        .name = "maintain",
        .args = "",
        .summary = "Do all upkeep at once: refresh the catalog, upgrade every package that is not pinned, install missing dependencies, remove dependencies nothing needs, clear temporary files and update abv0 itself. This is what `abv0 autoupdate on` schedules.",
        .flags = &.{ quiet_flag, verbose_flag },
        .example = "abv0 maintain",
    },
    .{
        .name = "autoupdate",
        .args = "on [--daily|--weekly] | off | status",
        .summary = "Run `abv0 maintain` automatically through the system scheduler (launchd on macOS, a systemd user timer or cron on Linux, Task Scheduler on Windows), at about 03:17. `status` shows whether it is on and when it last ran.",
        .flags = &.{},
        .example = "abv0 autoupdate on",
    },
    .{
        .name = "self-update",
        .summary = "Update abv0 itself from a signed release.",
        .flags = &.{.{ .name = "--check", .help = "Only report whether an update exists" }},
        .example = "abv0 self-update --check",
    },
    .{
        .name = "version",
        .summary = "Print the version and platform.",
        .example = "abv0 version",
    },
    .{
        .name = "help",
        .args = "[command]",
        .summary = "Show every command and option, or the help for one command.",
        .example = "abv0 help install",
    },
};

const command_names = blk: {
    var names: [commands.len][]const u8 = undefined;
    for (commands, 0..) |cmd, i| names[i] = cmd.name;
    break :blk names;
};

fn findCommand(name: []const u8) ?Command {
    for (commands) |cmd| {
        if (std.mem.eql(u8, cmd.name, name)) return cmd;
    }
    return null;
}

/// An unknown command is a usage error. Name the closest real command when one
/// is near, so a typo costs one retry instead of a search through the help.
fn reportUnknownCommand(name: []const u8) void {
    term.err("{s}error{s}: unknown command '{}'\n", .{ term.red, term.reset, safe(name) });
    if (closest(name, &command_names)) |s| {
        term.err("  did you mean '{s}'?\n", .{s});
    } else {
        term.err("  run `abv0 help` to list the commands\n", .{});
    }
}

fn heading(w: anytype, title: []const u8) !void {
    try w.print("\n{s}{s}{s}\n", .{ term.bold, title, term.reset });
}

fn renderUsage(w: anytype) !void {
    try w.print("{s}{s}abv0{s} {s} - a fast, verifying package manager in Zig\n", .{ term.bold, term.cyan, term.reset, version });
    try heading(w, "USAGE");
    try w.writeAll(
        \\  abv0 <command> [options] [arguments]
        \\  abv0 <command> --help   Help for one command (same as: abv0 help <command>)
        \\
    );
    try heading(w, "PACKAGES");
    try w.writeAll(
        \\  install <pkg>...        Install packages and their dependencies (verified, in parallel)
        \\  install gh:owner/repo   Install any GitHub project's release, verified (no recipe needed)
        \\  uninstall <pkg>...      Remove packages and the links they created
        \\  upgrade [--all|pkg]...  Upgrade outdated packages (keeps the previous version for rollback)
        \\  outdated                List packages with a newer version available (pinned ones marked)
        \\  list [--installed]      List registry packages, or what is installed
        \\  browse                  Pick packages to install from a full-screen list
        \\  search [--online] <q>   Search the registry (and GitHub repositories with --online)
        \\  info <pkg>              Show metadata, installed versions, size and linked bins
        \\  deps [--tree] <pkg>     List what a package depends on
        \\  uses <pkg>              List installed packages that depend on it
        \\  leaves                  List installed packages nothing else depends on
        \\  switch <pkg> <version>  Make an installed version the active one
        \\  rollback <pkg>          Go back to the previously installed version
        \\  home [--open] <pkg>     Print (or open) a package's homepage
        \\  pin <pkg>               Hold a package at its installed version
        \\  unpin <pkg>             Let upgrade update it again
        \\  pinned                  List pinned packages
        \\  which <bin>             Show which package owns a command
        \\
    );
    try heading(w, "EXECUTION");
    try w.writeAll(
        \\  run <pkg> [-- args]     Run a package executable
        \\  shell <pkg>...          Ephemeral subshell with only those packages
        \\
    );
    try heading(w, "MANIFESTS");
    try w.writeAll(
        \\  bundle [install|dump]   Install from, or export to, a Brewfile
        \\  migrate [--install]     Move your Homebrew packages and apps to abv0 (reads Homebrew from disk;
        \\                          or --from-brew-list F | --brewfile F)
        \\  update                  Refresh the registry index
        \\  sync                    Recompile the local index and SQL export
        \\
    );
    try heading(w, "MAINTENANCE");
    try w.writeAll(
        \\  doctor                  Diagnose PATH, permissions and links
        \\  fix                     Repair broken links and permissions
        \\  detect <pkg>            Scan an installed package for malware patterns
        \\  benchmark               Measure local store and index performance
        \\  gc                      Remove temporary files and stale sandboxes
        \\  cleanup                 Remove old versions (including rollback's), keeping the newest
        \\  completions <shell>     Print a bash, zsh, fish or pwsh completion script
        \\  maintain                Refresh, upgrade, fix dependencies and clean up in one go
        \\  autoupdate on|off|status  Run `maintain` daily (or --weekly) via the system scheduler
        \\  self-update [--check]   Update abv0 from a signed release
        \\  reset                   Uninstall everything
        \\  report [--bug]          Open a prefilled GitHub issue
        \\  version                 Print the version
        \\  help [command]          This message, or help for one command
        \\
    );
    try heading(w, "OPTIONS");
    try w.print("  --platform <tag>        Target platform (default: {s})\n", .{platform.defaultPlatformTag()});
    try w.writeAll(
        \\  -f, --file <path>       Manifest path for bundle commands
        \\  -j, --jobs <n>          Parallel install workers
        \\  --registry <path>       Use this manifest (its <path>.sig must verify)
        \\  --allow-unsigned-manifest  Skip signature and replay checks (UNSAFE)
        \\  --allow-unverified      Permit installs without a verified checksum
        \\  --allow-suspicious      Install even if the malware scan blocks the package (ABV0_NO_SCAN=1 skips the scan)
        \\  --micro-split           Parallel ranged download for large assets
        \\  --no-stream             Download fully before unpacking (disable streaming install)
        \\  --force                 Overwrite output files and replace conflicting bin links
        \\  --dry-run               Show what install, upgrade, uninstall, bundle or cleanup would do; change nothing
        \\  --json                  Machine-readable output (list, search, info, outdated, install, doctor, deps, uses, leaves, home, switch, rollback, migrate)
        \\  --installed             With list: show what is installed
        \\  --tree                  With deps: show a tree
        \\  --online                With search: also search GitHub repositories
        \\  --open                  With home: open the page in a browser
        \\  --all                   With upgrade: every outdated package; with migrate: dependencies too
        \\  --from-brew-list <f>    With migrate: names from `brew list --formula` (- for stdin)
        \\  --brewfile <f>          With migrate: names from a Brewfile (- for stdin)
        \\  --install               With migrate: install what matched
        \\  --bug, --malware        With report: file a bug report, or a suspicious-package report
        \\  -q, --quiet             Suppress progress lines (errors still print)
        \\  -v, --verbose           Also print urls, store paths and timings per package
        \\  --color <when>          auto (default), always or never; --no-color means never
        \\  -h, --help              This message, or help for the command before it
        \\  -V, --version           Version
        \\
    );
    try heading(w, "EXIT CODES");
    try w.writeAll(
        \\  0  success
        \\  1  the operation failed (a download, a check, or a package)
        \\  2  usage error (unknown command, option or argument)
        \\
    );
}

fn printUsage() void {
    renderUsage(term.writer()) catch {};
}

/// `abv0 <cmd> --help`: synopsis, one line of description, the relevant flags
/// and one example.
fn renderCommandHelp(w: anytype, cmd: Command) !void {
    try w.print("{s}abv0 {s}{s} - {s}\n", .{ term.bold, cmd.name, term.reset, cmd.summary });
    try heading(w, "USAGE");
    try w.print("  abv0 {s}{s}{s}", .{ cmd.name, if (cmd.args.len > 0) " " else "", cmd.args });
    if (cmd.flags.len > 0) try w.writeAll(" [options]");
    try w.writeAll("\n");
    if (cmd.flags.len > 0) {
        try heading(w, "OPTIONS");
        for (cmd.flags) |flag| try w.print("  {s:<26} {s}\n", .{ flag.name, flag.help });
    }
    try heading(w, "EXAMPLE");
    try w.print("  {s}\n", .{cmd.example});
    try w.writeAll("\nGlobal options and exit codes: abv0 help\n");
}

// ---------------------------------------------------------------------------
// Registry acquisition
// ---------------------------------------------------------------------------

fn registryPaths(a: std.mem.Allocator, st: *const store.Store) ![2][]u8 {
    const json = try std.fs.path.join(a, &.{ st.registry_root, "index.json" });
    const idx = try std.fs.path.join(a, &.{ st.registry_root, "index.abv" });
    return .{ json, idx };
}

/// True when the registry index is already on disk, so a dry run can read it
/// without downloading anything.
fn registryCached(a: std.mem.Allocator, st: *const store.Store) bool {
    const paths = registryPaths(a, st) catch return false;
    defer a.free(paths[0]);
    defer a.free(paths[1]);
    std.fs.cwd().access(paths[0], .{}) catch return false;
    return true;
}

// The manifest is trusted only after its detached signature (`<url>.sig`)
// verifies. The signature check comes before anything else reads the content.
//
// Replay protection: the manifest's top-level `updated_at` must not be older
// than the last one this machine accepted, remembered in
// `<registry dir>/last-updated-at`. Without this an attacker could serve an
// old, correctly signed manifest that still lists a vulnerable version.

const max_manifest_bytes = 16 * 1024 * 1024;
const max_sig_bytes = 4 * 1024;
const stored_updated_at_name = "last-updated-at";

const manifest_error = error{
    ManifestSignatureInvalid,
    ManifestReplay,
    MissingUpdatedAt,
    InvalidUpdatedAt,
};

fn warnUnsignedManifest() void {
    term.err(
        "{s}{s}WARNING{s}: --allow-unsigned-manifest: the registry signature is NOT checked and " ++
            "replay protection is off. Whatever the registry serves will be trusted.\n",
        .{ term.bold, term.red, term.reset },
    );
}

/// Pure replay test. Both values must be in the same fixed ISO-8601 UTC form
/// (validUpdatedAt enforces the character set), so lexical order is time order.
/// Equal is accepted: re-fetching the same manifest is not a replay.
fn isReplay(candidate: []const u8, stored: ?[]const u8) bool {
    const s = stored orelse return false;
    return std.mem.order(u8, candidate, s) == .lt;
}

/// Shape check for `updated_at`: `YYYY-...` made only of the characters an
/// ISO-8601 timestamp uses. Rejecting anything else keeps control bytes out of
/// the terminal and out of the stored file, and keeps the comparison meaningful.
fn validUpdatedAt(s: []const u8) bool {
    if (s.len < 10 or s.len > 64) return false;
    for (s[0..4]) |c| if (!std.ascii.isDigit(c)) return false;
    if (s[4] != '-') return false;
    for (s) |c| switch (c) {
        '0'...'9', 'T', 'Z', ':', '.', '+', '-' => {},
        else => return false,
    };
    return true;
}

/// Top-level `updated_at` of a manifest's bytes. The returned slice aliases
/// `a`'s allocation for the parse, so the caller keeps `a` alive while using it.
fn manifestUpdatedAt(a: std.mem.Allocator, bytes: []const u8) manifest_error![]const u8 {
    // A token scan of the top level: building a full JSON tree of a catalog
    // with hundreds of packages, only to read one field, cost several ms a run.
    const s = topLevelString(a, bytes, "updated_at") catch return error.MissingUpdatedAt;
    if (!validUpdatedAt(s)) return error.InvalidUpdatedAt;
    return s;
}

/// The string value of `key` in the top-level JSON object `bytes`, skipping
/// every other value unparsed and stopping at the first match (the catalog
/// writes `updated_at` before `packages`). Only the part before the match is
/// checked as JSON; callers pass bytes whose signature already verified, and
/// the full parse happens when the registry itself is loaded.
fn topLevelString(a: std.mem.Allocator, bytes: []const u8, key: []const u8) ![]const u8 {
    var sc = std.json.Scanner.initCompleteInput(a, bytes);
    defer sc.deinit();
    if (try sc.next() != .object_begin) return error.NotAnObject;
    while (true) {
        const name = switch (try sc.nextAlloc(a, .alloc_if_needed)) {
            .object_end => return error.MissingField,
            .string, .allocated_string => |n| n,
            else => return error.SyntaxError,
        };
        if (!std.mem.eql(u8, name, key)) {
            try sc.skipValue();
            continue;
        }
        return switch (try sc.nextAlloc(a, .alloc_always)) {
            .allocated_string => |v| v,
            else => error.NotAString,
        };
    }
}

test "topLevelString reads one top-level field" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc =
        \\{"packages":{"x":{"updated_at":"nested"}},"updated_at":"2026-01-02T03:04:05Z","n":[1,{"a":2}]}
    ;
    try std.testing.expectEqualStrings("2026-01-02T03:04:05Z", try topLevelString(a, doc, "updated_at"));
    try std.testing.expectEqualStrings("a\"b", try topLevelString(a, "{\"k\":\"a\\\"b\"}", "k"));
    try std.testing.expectError(error.MissingField, topLevelString(a, "{\"p\":{\"k\":\"v\"}}", "k"));
    try std.testing.expectError(error.NotAString, topLevelString(a, "{\"k\":1}", "k"));
    try std.testing.expect(std.meta.isError(topLevelString(a, "{\"j\":\"v\"", "k")));
    try std.testing.expect(std.meta.isError(topLevelString(a, "[1]", "k")));
}

/// Verify a staged manifest against its staged signature. Returns the
/// manifest's `updated_at`, or null when `--allow-unsigned-manifest` skipped
/// every check. Prints a specific diagnostic for each failure.
/// The returned slice is allocated from `a`; scratch memory for the file
/// contents is released before returning.
fn vetManifest(
    a: std.mem.Allocator,
    manifest_path: []const u8,
    sig_path: []const u8,
    allow_unsigned: bool,
) !?[]const u8 {
    if (allow_unsigned) {
        warnUnsignedManifest();
        return null;
    }

    var scratch = std.heap.ArenaAllocator.init(a);
    defer scratch.deinit();
    const s = scratch.allocator();

    const bytes = std.fs.cwd().readFileAlloc(s, manifest_path, max_manifest_bytes) catch |e| {
        term.err("{s}error{s}: cannot read manifest: {s}\n", .{ term.red, term.reset, explain(e) });
        return e;
    };
    const sig = std.fs.cwd().readFileAlloc(s, sig_path, max_sig_bytes) catch |e| {
        term.err("{s}error{s}: cannot read manifest signature: {s}\n", .{ term.red, term.reset, explain(e) });
        return e;
    };

    sign.verify(bytes, sig) catch |e| {
        term.err(
            "{s}error{s}: manifest signature check failed \xe2\x80\x94 refusing to use it ({s})\n",
            .{ term.red, term.reset, @errorName(e) },
        );
        return error.ManifestSignatureInvalid;
    };

    const updated_at = manifestUpdatedAt(s, bytes) catch |e| {
        term.err("{s}error{s}: signed manifest has no valid updated_at ({s}); refusing it\n", .{ term.red, term.reset, @errorName(e) });
        return e;
    };
    return try a.dupe(u8, updated_at);
}

fn readStoredUpdatedAt(a: std.mem.Allocator, st: *const store.Store) !?[]const u8 {
    const p = try std.fs.path.join(a, &.{ st.registry_root, stored_updated_at_name });
    defer a.free(p);
    const raw = std.fs.cwd().readFileAlloc(a, p, 256) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return e,
    };
    const t = std.mem.trim(u8, raw, " \t\r\n");
    if (!validUpdatedAt(t)) return null;
    return t;
}

/// Refuse a manifest older than the one already accepted.
fn checkReplay(a: std.mem.Allocator, st: *const store.Store, candidate: []const u8) !void {
    const stored = try readStoredUpdatedAt(a, st);
    if (isReplay(candidate, stored)) {
        term.err(
            "{s}error{s}: manifest is older than the one already installed \xe2\x80\x94 possible replay ({s} < {s})\n",
            .{ term.red, term.reset, candidate, stored.? },
        );
        return error.ManifestReplay;
    }
}

/// Record an accepted `updated_at`, atomically. Called after the manifest is
/// in place, so a crash in between leaves the stored value older, never newer.
fn storeUpdatedAt(a: std.mem.Allocator, st: *const store.Store, value: []const u8) !void {
    const p = try std.fs.path.join(a, &.{ st.registry_root, stored_updated_at_name });
    defer a.free(p);
    const tmp = try std.fmt.allocPrint(a, "{s}.{x}.tmp", .{ p, std.crypto.random.int(u32) });
    defer a.free(tmp);
    errdefer std.fs.cwd().deleteFile(tmp) catch {};

    const f = try std.fs.cwd().createFile(tmp, .{ .mode = platform.mode_private });
    {
        defer f.close();
        try f.writeAll(value);
        try f.writeAll("\n");
    }
    try std.fs.cwd().rename(tmp, p);
}

/// Download the manifest and its signature to staging names. Nothing is
/// published here.
fn fetchManifestPair(a: std.mem.Allocator, manifest_tmp: []const u8, sig_tmp: []const u8) !void {
    const url = registryUrl();
    const sig_url = try std.fmt.allocPrint(a, "{s}.sig", .{url});
    defer a.free(sig_url);
    net.download(a, url, manifest_tmp, .{}) catch |e| {
        term.err("{s}error{s}: could not download registry manifest: {s}\n", .{ term.red, term.reset, explain(e) });
        return e;
    };
    net.download(a, sig_url, sig_tmp, .{}) catch |e| {
        term.err("{s}error{s}: could not download manifest signature: {s}\n", .{ term.red, term.reset, explain(e) });
        return e;
    };
}

/// Records the SHA-256 (lowercase hex) of the manifest abv0 last accepted.
/// A manifest that is merely present is not trusted; only one whose bytes match
/// this record is, so a file placed by an installer or by hand is checked first.
const stored_manifest_hash_name = "index.json.sha256";

/// What a manifest already on disk is worth.
const ManifestTrust = enum {
    /// These are the bytes abv0 accepted.
    trusted,
    /// Not accepted yet, but a detached signature sits beside it to check.
    verify_sig,
    /// Not accepted and nothing to check it with: fetch it again.
    refetch,
};

/// Pure decision. `recorded_hash` is what abv0 stored when it last accepted a
/// manifest (null when nothing is stored); `actual_hash` is the SHA-256 hex of
/// the file now. Only an exact match is trusted.
fn trustState(recorded_hash: ?[]const u8, actual_hash: []const u8, has_sig: bool) ManifestTrust {
    if (recorded_hash) |r| {
        if (std.mem.eql(u8, r, actual_hash)) return .trusted;
    }
    return if (has_sig) .verify_sig else .refetch;
}

/// The recorded hash, or null when there is none or it cannot be read. Anything
/// unreadable counts as untrusted.
fn readStoredManifestHash(a: std.mem.Allocator, st: *const store.Store) ?[]const u8 {
    const p = std.fs.path.join(a, &.{ st.registry_root, stored_manifest_hash_name }) catch return null;
    defer a.free(p);
    const raw = std.fs.cwd().readFileAlloc(a, p, 256) catch return null;
    const t = std.mem.trim(u8, raw, " \t\r\n");
    if (t.len != 64) return null;
    for (t) |c| if (!std.ascii.isHex(c)) return null;
    return t;
}

/// Record the hash of the manifest just accepted. Atomic, like storeUpdatedAt.
fn storeManifestHash(a: std.mem.Allocator, st: *const store.Store, hex: []const u8) !void {
    const p = try std.fs.path.join(a, &.{ st.registry_root, stored_manifest_hash_name });
    defer a.free(p);
    const tmp = try std.fmt.allocPrint(a, "{s}.{x}.tmp", .{ p, std.crypto.random.int(u32) });
    defer a.free(tmp);
    errdefer std.fs.cwd().deleteFile(tmp) catch {};

    const f = try std.fs.cwd().createFile(tmp, .{ .mode = platform.mode_private });
    {
        defer f.close();
        try f.writeAll(hex);
        try f.writeAll("\n");
    }
    try std.fs.cwd().rename(tmp, p);
}

/// SHA-256 of the file at `path`, as lowercase hex. Uses the digest the index
/// cache uses (abvindex.Stamp), so both agree on what the bytes are.
fn manifestHex(path: []const u8) ![64]u8 {
    const stamp = try abvindex.Stamp.ofFile(path);
    return std.fmt.bytesToHex(stamp.sha256, .lower);
}

/// Check a manifest already on disk the way a fresh download is checked:
/// signature, replay, then parse. On success its hash is recorded and the parsed
/// registry is returned. On any failure the caller fetches the manifest again.
fn acceptOnDisk(base: std.mem.Allocator, st: *const store.Store, json_path: []const u8, sig_path: []const u8) !registry.Registry {
    var scratch = std.heap.ArenaAllocator.init(base);
    defer scratch.deinit();
    const a = scratch.allocator();

    const updated_at = try vetManifest(a, json_path, sig_path, false);
    if (updated_at) |u| try checkReplay(a, st, u);

    var fresh = try registry.loadFromJsonFile(base, json_path, null);
    errdefer fresh.deinit();

    // Hash the bytes that were just verified. updated_at is stored before the
    // hash: a crash in between leaves no hash, which costs one more check.
    const hex = try manifestHex(json_path);
    if (updated_at) |u| try storeUpdatedAt(a, st, u);
    try storeManifestHash(a, st, &hex);
    return fresh;
}

/// Materialise the registry manifest, atomically, if it is not present yet.
///
/// The manifest is always downloaded: a file in the current directory is never
/// used. Download to unique temporary names, verify, validate, and rename into
/// place, so a reader sees either no file or a complete, verified one.
///
/// Returns the registry it parsed while validating, so the caller does not parse
/// the same bytes again. Returns null when the manifest already on disk is
/// trusted as it is.
fn ensureRegistryFile(base: std.mem.Allocator, st: *const store.Store, json_path: []const u8, allow_unsigned: bool) !?registry.Registry {
    // Scratch for paths and the verified manifest. The caller's allocator is
    // long-lived (it is the GPA in `main`), so nothing is left in it.
    var scratch = std.heap.ArenaAllocator.init(base);
    defer scratch.deinit();
    const a = scratch.allocator();

    // A manifest already on disk is trusted only if abv0 accepted these exact
    // bytes. Otherwise its signature (if an installer left one) is checked, or
    // the manifest is fetched again.
    const json_sig = try std.fmt.allocPrint(a, "{s}.sig", .{json_path});
    if (std.fs.cwd().access(json_path, .{})) |_| {
        const hex = try manifestHex(json_path);
        const has_sig = if (std.fs.cwd().access(json_sig, .{})) |_| true else |_| false;
        switch (trustState(readStoredManifestHash(a, st), &hex, has_sig)) {
            .trusted => return null,
            .verify_sig => if (acceptOnDisk(base, st, json_path, json_sig)) |fresh| return fresh else |_| {},
            .refetch => {},
        }
        if (allow_unsigned) {
            warnUnsignedManifest();
            return null;
        }
        say("registry index on disk is not verified; fetching it again\n", .{});
    } else |_| {}

    const tag = std.crypto.random.int(u64);
    const tmp_path = try std.fmt.allocPrint(a, "{s}.{x}.tmp", .{ json_path, tag });
    defer a.free(tmp_path);
    const sig_path = try std.fmt.allocPrint(a, "{s}.sig", .{tmp_path});
    defer a.free(sig_path);
    defer std.fs.cwd().deleteFile(tmp_path) catch {};
    defer std.fs.cwd().deleteFile(sig_path) catch {};

    say("fetching registry index...\n", .{});
    try fetchManifestPair(a, tmp_path, sig_path);

    const updated_at = try vetManifest(a, tmp_path, sig_path, allow_unsigned);
    if (updated_at) |u| try checkReplay(a, st, u);

    // Never publish something the parser would reject: a corrupt download must
    // not become the registry every later command reads. The parse is kept
    // (not freed) because it is the registry the caller wants. It lives in
    // `base`, not the scratch arena, so it outlives this function.
    var fresh = try registry.loadFromJsonFile(base, tmp_path, null);
    errdefer fresh.deinit();

    try std.fs.cwd().rename(tmp_path, json_path);
    // Unsigned fetches (--allow-unsigned-manifest) record nothing: they were
    // never accepted, so a later run must not trust them without the flag.
    if (updated_at) |u| {
        try storeUpdatedAt(a, st, u);
        const hex = try manifestHex(json_path);
        try storeManifestHash(a, st, &hex);
    }
    return fresh;
}

fn loadRegistry(a: std.mem.Allocator, st: *const store.Store, allow_unsigned: bool) !registry.Registry {
    const paths = try registryPaths(a, st);
    defer a.free(paths[0]);
    defer a.free(paths[1]);

    const fresh = ensureRegistryFile(a, st, paths[0], allow_unsigned) catch |e| {
        term.err("{s}error{s}: no package registry available: {s}\n", .{ term.red, term.reset, explain(e) });
        return e;
    };
    if (fresh) |parsed| {
        // Just downloaded and already parsed: build the index from that
        // registry rather than parsing the same file again.
        var reg = parsed;
        const stamp = try abvindex.Stamp.ofFile(paths[0]);
        abvindex.build(a, &reg, paths[1], stamp) catch {};
        return reg;
    }

    return abvindex.loadCached(a, paths[0], paths[1]) catch |e| {
        term.err("{s}error{s}: could not load registry: {s}\n", .{ term.red, term.reset, explain(e) });
        return e;
    };
}

/// `--registry <path>`: an explicit local manifest. It is signature-checked
/// against `<path>.sig` like any other. It does not touch the installed
/// registry or its replay state. Its binary index lives in a file of its own
/// (named after the manifest's path), and like the installed one is used only
/// when it was built from exactly these bytes.
fn loadExplicitRegistry(base: std.mem.Allocator, st: *const store.Store, path: []const u8, allow_unsigned: bool) !registry.Registry {
    var scratch = std.heap.ArenaAllocator.init(base);
    defer scratch.deinit();
    const a = scratch.allocator();

    const sig_path = try std.fmt.allocPrint(a, "{s}.sig", .{path});

    _ = vetManifest(a, path, sig_path, allow_unsigned) catch |e| {
        term.err("{s}error{s}: registry '{s}' was not loaded: {s}\n", .{ term.red, term.reset, path, explain(e) });
        return e;
    };
    // The loaded registry outlives the scratch arena, so it uses `base`.
    if (explicitIndexPath(a, st, path)) |idx| {
        if (abvindex.loadCached(base, path, idx)) |reg| return reg else |_| {}
    } else |_| {}
    return registry.loadFromJsonFile(base, path, null) catch |e| {
        term.err("{s}error{s}: could not load registry '{s}': {s}\n", .{ term.red, term.reset, path, explain(e) });
        return e;
    };
}

/// `<registry dir>/explicit-<hash of the manifest's real path>.abv`, with the
/// directory created. Distinct from `index.abv`, and one per manifest so two
/// checkouts do not keep rebuilding each other's index.
fn explicitIndexPath(a: std.mem.Allocator, st: *const store.Store, path: []const u8) ![]u8 {
    const real = try std.fs.cwd().realpathAlloc(a, path);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(real, &digest, .{});
    const hex = std.fmt.bytesToHex(digest[0..8], .lower);
    try std.fs.cwd().makePath(st.registry_root);
    const name = try std.fmt.allocPrint(a, "explicit-{s}.abv", .{&hex});
    return std.fs.path.join(a, &.{ st.registry_root, name });
}

// ---------------------------------------------------------------------------
// Dependency-ordered parallel install
// ---------------------------------------------------------------------------

/// Wave number for each package. `pkgs` must list every dependency before its
/// dependents, as `registry.resolveOrder` returns them. A package's wave is one
/// more than the highest wave of its dependencies that are in `pkgs`, so it runs
/// after everything it depends on, and packages in one wave are independent.
/// Dependencies outside `pkgs` are not waited for.
fn levelize(a: std.mem.Allocator, pkgs: []const registry.Package) ![]usize {
    var index = std.StringHashMap(usize).init(a);
    defer index.deinit();
    for (pkgs, 0..) |pkg, i| try index.put(pkg.name, i);

    const levels = try a.alloc(usize, pkgs.len);
    errdefer a.free(levels);
    @memset(levels, 0);

    for (pkgs, 0..) |pkg, i| {
        for (pkg.deps) |dep| {
            const j = index.get(dep) orelse continue;
            if (j >= i) return error.NotDependencyOrdered;
            levels[i] = @max(levels[i], levels[j] + 1);
        }
    }
    return levels;
}

/// What to install, dependencies first: `names[i]` runs in wave `levels[i]`.
const Plan = struct {
    names: []const []const u8,
    levels: []const usize,
};

/// Plan the installation of `roots` and what they depend on. Names the registry
/// does not know go last, in a wave of their own. If the registry graph cannot
/// be ordered (a cycle, or an unknown dependency), everything goes in one wave.
fn planInstall(a: std.mem.Allocator, reg: *const registry.Registry, roots: []const []const u8) !Plan {
    var known = std.ArrayList([]const u8).init(a);
    defer known.deinit();
    var unknown = std.ArrayList([]const u8).init(a);
    defer unknown.deinit();
    var seen = std.StringHashMap(void).init(a);
    defer seen.deinit();

    for (roots) |root| {
        if (store.Store.resolveRequest(reg, root)) |pkg| {
            if (try seen.fetchPut(pkg.name, {}) == null) try known.append(pkg.name);
        } else {
            if (try seen.fetchPut(root, {}) == null) try unknown.append(root);
        }
    }

    var names = std.ArrayList([]const u8).init(a);
    errdefer names.deinit();
    var levels = std.ArrayList(usize).init(a);
    errdefer levels.deinit();

    if (known.items.len > 0) {
        if (registry.resolveOrder(a, reg, known.items)) |ordered| {
            defer a.free(ordered);
            const wave = try levelize(a, ordered);
            defer a.free(wave);
            for (ordered, wave) |pkg, lv| {
                try names.append(pkg.name);
                try levels.append(lv);
            }
        } else |err| switch (err) {
            error.OutOfMemory => return err,
            else => {
                term.err("{s}warning{s}: no dependency order ({s}); installing without one\n", .{ term.yellow, term.reset, @errorName(err) });
                for (known.items) |name| {
                    try names.append(name);
                    try levels.append(0);
                }
            },
        }
    }

    const after_known: usize = if (levels.items.len == 0) 0 else std.mem.max(usize, levels.items) + 1;
    for (unknown.items) |name| {
        try names.append(name);
        try levels.append(after_known);
    }

    return .{ .names = try names.toOwnedSlice(), .levels = try levels.toOwnedSlice() };
}

fn reportInstallError(name: []const u8, e: anyerror) void {
    if (!store.alreadyDiagnosed(e)) {
        term.err("{s}error{s}: {}: {s}\n", .{ term.red, term.reset, safe(name), explain(e) });
    }
}

/// `-v`: where one package landed and how long it took. Runs on the worker that
/// installed it, and only reads.
fn reportVerbose(a: std.mem.Allocator, st: *const store.Store, pkg: registry.Package, platform_name: []const u8, started: i128) void {
    if (!output.verbose) return;
    const elapsed_ns: u64 = @intCast(std.time.nanoTimestamp() - started);
    if (pkg.platform(platform_name)) |info| detail("  {}  url    {}\n", .{ safe(pkg.name), safe(info.url) });
    if (st.pkgStorePath(a, pkg, platform_name)) |p| {
        detail("  {}  store  {s}\n", .{ safe(pkg.name), p });
    } else |_| {}
    detail("  {}  took   {d:.2}ms\n", .{ safe(pkg.name), ms(elapsed_ns) });
}

/// One install pool shared by every wave of one command.
const Batch = struct {
    st: *store.Store,
    reg: *const registry.Registry,
    names: []const []const u8,
    /// Indices into `names` that make up the wave being run.
    slots: []const usize,
    /// `ok[i]` is set once `names[i]` is installed. Each index is written by
    /// exactly one worker, and the main thread reads it after the join.
    ok: []bool,
    platform_name: []const u8,
    opts: store.InstallOptions,
    next: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

    fn worker(self: *Batch) void {
        // Per-worker arena for each job's temporary memory. It is backed by
        // page_allocator, so it never takes the shared thread-safe allocator's
        // lock. Each job's allocations are released by reset when it finishes.
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();

        while (true) {
            const slot = self.next.fetchAdd(1, .monotonic);
            if (slot >= self.slots.len) return;
            const i = self.slots[slot];
            self.ok[i] = self.installOne(arena.allocator(), self.names[i]);
            _ = arena.reset(.retain_capacity);
        }
    }

    fn installOne(self: *Batch, scratch: std.mem.Allocator, name: []const u8) bool {
        const started = std.time.nanoTimestamp();
        if (store.Store.resolveRequest(self.reg, name)) |pkg| {
            self.st.install(pkg, self.platform_name, self.opts) catch |e| {
                reportInstallError(name, e);
                return false;
            };
            reportVerbose(scratch, self.st, pkg, self.platform_name, started);
            return true;
        }
        const pkg = self.st.installDynamic(scratch, name, self.platform_name, self.opts) catch |e| {
            reportInstallError(name, e);
            return false;
        };
        reportVerbose(scratch, self.st, pkg, self.platform_name, started);
        return true;
    }
};

/// Run one wave on a pool of at most `min(requested or CPUs, wave size, 8)`
/// threads. Returns once every package in the wave has finished.
fn runWave(batch: *Batch, requested_jobs: ?usize) void {
    const cpus = std.Thread.getCpuCount() catch 2;
    // The original spawned one OS thread per package with no bound, so a
    // 50-entry Brewfile created 50 threads all contending for bandwidth.
    const jobs = @max(1, @min(requested_jobs orelse cpus, @min(batch.slots.len, 8)));

    var threads: [8]std.Thread = undefined;
    var spawned: usize = 0;
    // Join whatever started, even if a later spawn failed.
    defer for (threads[0..spawned]) |t| t.join();
    while (spawned < jobs) : (spawned += 1) {
        threads[spawned] = std.Thread.spawn(.{}, Batch.worker, .{batch}) catch break;
    }
    // If no thread could be started, the calling thread does the work itself.
    if (spawned == 0) batch.worker();
}

/// The first dependency of `names[i]` that sits in an earlier wave and did not
/// install. A package is never started while one of its dependencies is missing.
fn failedDependency(
    reg: *const registry.Registry,
    names: []const []const u8,
    levels: []const usize,
    ok: []const bool,
    i: usize,
) ?[]const u8 {
    const pkg = store.Store.resolveRequest(reg, names[i]) orelse return null;
    for (pkg.deps) |dep| {
        for (names, levels, ok) |name, lv, done| {
            if (lv < levels[i] and !done and std.mem.eql(u8, name, dep)) return dep;
        }
    }
    return null;
}

/// Install `names` one wave at a time. Every package in a wave runs on the pool
/// before the next wave starts, so nothing begins before its dependencies have
/// finished. A package whose dependency failed is skipped. Sets `ok[i]` for each
/// name that is installed, and returns how many names were not.
fn installWaves(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: *const registry.Registry,
    names: []const []const u8,
    levels: []const usize,
    ok: []bool,
    platform_name: []const u8,
    opts: store.InstallOptions,
    requested_jobs: ?usize,
) !usize {
    std.debug.assert(levels.len == names.len and ok.len == names.len);
    @memset(ok, false);
    if (names.len == 0) return 0;

    const last_wave = std.mem.max(usize, levels);
    for (0..last_wave + 1) |wave_no| {
        var slots = std.ArrayList(usize).init(a);
        defer slots.deinit();

        for (levels, 0..) |lv, i| {
            if (lv != wave_no) continue;
            if (failedDependency(reg, names, levels, ok, i)) |dep| {
                term.err("{s}skipped{s} {}: dependency {} did not install\n", .{ term.yellow, term.reset, safe(names[i]), safe(dep) });
                continue;
            }
            try slots.append(i);
        }
        if (slots.items.len == 0) continue;

        var batch = Batch{
            .st = st,
            .reg = reg,
            .names = names,
            .slots = slots.items,
            .ok = ok,
            .platform_name = platform_name,
            .opts = opts,
        };
        runWave(&batch, requested_jobs);
    }

    var failures: usize = 0;
    for (ok) |done| {
        if (!done) failures += 1;
    }
    return failures;
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

/// Terminal-safe text and JSON strings live in cmds_extra.zig so the extra
/// commands print manifest text the same way.
const Safe = cmds_extra.Safe;
const safe = cmds_extra.safe;
const writeJsonString = cmds_extra.writeJsonString;

fn writePackageJson(w: anytype, pkg: registry.Package) !void {
    try w.writeAll("{");
    try writePackageJsonFields(w, pkg);
    try w.writeAll("}");
}

/// The members of a package's JSON object, without the braces, so `info` can
/// add its own members after them.
fn writePackageJsonFields(w: anytype, pkg: registry.Package) !void {
    try w.writeAll("\"name\":");
    try writeJsonString(w, pkg.name);
    try w.writeAll(",\"version\":");
    try writeJsonString(w, pkg.version);
    try w.writeAll(",\"description\":");
    try writeJsonString(w, pkg.description);
    try w.writeAll(",\"homepage\":");
    try writeJsonString(w, pkg.homepage);
    try w.writeAll(",\"license\":");
    try writeJsonString(w, pkg.license);
    try w.writeAll(",\"bin\":[");
    for (pkg.bin, 0..) |b, i| {
        if (i > 0) try w.writeAll(",");
        try writeJsonString(w, b);
    }
    try w.writeAll("],\"platforms\":{");
    for (pkg.platforms, 0..) |p, i| {
        if (i > 0) try w.writeAll(",");
        try writeJsonString(w, p.name);
        try w.writeAll(":{\"archive_type\":");
        try writeJsonString(w, p.archive_type);
        try w.writeAll(",\"sha256\":");
        try writeJsonString(w, p.sha256);
        try w.writeAll(",\"bin_path\":");
        try writeJsonString(w, p.bin_path);
        try w.writeAll(",\"url\":");
        try writeJsonString(w, p.url);
        try w.writeAll("}");
    }
    try w.writeAll("}");
}

fn writeOutdatedJson(w: anytype, name: []const u8, installed: []const u8, available: []const u8, pinned: bool) !void {
    try w.writeAll("{\"name\":");
    try writeJsonString(w, name);
    try w.writeAll(",\"installed\":");
    try writeJsonString(w, installed);
    try w.writeAll(",\"available\":");
    try writeJsonString(w, available);
    try w.print(",\"pinned\":{s}}}", .{if (pinned) "true" else "false"});
}

/// The registry name closest to `name`, for a name the registry does not have.
fn suggestPackage(a: std.mem.Allocator, reg: *const registry.Registry, name: []const u8) ?[]const u8 {
    const names = a.alloc([]const u8, reg.packages.len) catch return null;
    defer a.free(names);
    for (reg.packages, names) |pkg, *slot| slot.* = pkg.name;
    // The result points at registry memory, so it outlives `names`.
    return closest(name, names);
}

/// Under an error about an unknown package, the closest registry name.
fn hintPackage(a: std.mem.Allocator, reg: *const registry.Registry, name: []const u8) void {
    if (suggestPackage(a, reg, name)) |s| term.err("  did you mean '{}'?\n", .{safe(s)});
}

/// Before a name the registry lacks goes to a GitHub search, say which registry
/// name it may have been meant to be. Silent when nothing is close.
fn noteUnknownName(a: std.mem.Allocator, reg: *const registry.Registry, name: []const u8) void {
    if (store.Store.resolveRequest(reg, name) != null) return;
    // A GitHub spec is not a misspelt registry name.
    if (ghverify.looksLikeSpec(name)) return;
    if (suggestPackage(a, reg, name)) |s| {
        term.err("{s}note{s}: '{}' is not in the registry; did you mean '{}'?\n", .{ term.yellow, term.reset, safe(name), safe(s) });
    }
}

fn supportsDryRun(cmd: []const u8) bool {
    const names = [_][]const u8{ "install", "upgrade", "uninstall", "bundle", "cleanup", "migrate" };
    for (names) |n| {
        if (std.mem.eql(u8, n, cmd)) return true;
    }
    return false;
}

/// What an install or upgrade of `names` would do, one line per package in
/// install order. It reads the registry and the store and writes nothing.
fn writeDryRunPlan(
    w: anytype,
    a: std.mem.Allocator,
    st: *const store.Store,
    reg: *const registry.Registry,
    names: []const []const u8,
    platform_name: []const u8,
    verb: []const u8,
) !void {
    if (output.json) {
        try w.writeAll("[");
        for (names, 0..) |name, i| {
            if (i > 0) try w.writeAll(",");
            const pkg = store.Store.resolveRequest(reg, name);
            const status: []const u8 = if (pkg == null)
                "unknown"
            else if (st.isInstalled(pkg.?, platform_name))
                "cached"
            else
                "would_install";
            try w.writeAll("{\"name\":");
            try writeJsonString(w, name);
            try w.writeAll(",\"version\":");
            if (pkg) |p| {
                try writeJsonString(w, p.version);
            } else {
                try w.writeAll("null");
            }
            try w.print(",\"status\":\"{s}\"}}", .{status});
        }
        try w.writeAll("]\n");
        return;
    }

    for (names) |name| {
        const pkg = store.Store.resolveRequest(reg, name) orelse {
            if (ghverify.looksLikeSpec(name)) {
                try w.print("  {s}{s:<8}{s} {} from its GitHub release (needs a sha256 digest or checksums file)\n", .{ term.green, verb, term.reset, safe(name) });
            } else {
                try w.print("  {s}unknown{s}   {} is not in the catalog; try gh:<owner>/{}\n", .{ term.yellow, term.reset, safe(name), safe(name) });
            }
            continue;
        };
        const info = pkg.platform(platform_name) orelse {
            try w.print("  {s}blocked{s}   {} {} has no build for {s}\n", .{ term.red, term.reset, safe(pkg.name), safe(pkg.version), platform_name });
            continue;
        };
        if (st.isInstalled(pkg, platform_name)) {
            try w.print("  {s}{s:<8}{s} {} {} (already installed)\n", .{ term.dim, "cached", term.reset, safe(pkg.name), safe(pkg.version) });
        } else {
            try w.print("  {s}{s:<8}{s} {} {} from {}\n", .{ term.green, verb, term.reset, safe(pkg.name), safe(pkg.version), safe(urlHost(info.url)) });
        }
        if (output.verbose) {
            try w.print("           url   {}\n", .{safe(info.url)});
            if (st.pkgStorePath(a, pkg, platform_name)) |p| {
                try w.print("           store {s}\n", .{p});
            } else |_| {}
        }
    }
    try w.print("\ndry run: {d} packages, nothing was changed\n", .{names.len});
}

/// `install --json`: one entry per planned package, with how it ended.
fn writeInstallJson(w: anytype, reg: *const registry.Registry, names: []const []const u8, levels: []const usize, ok: []const bool) !void {
    try writeInstallJsonArray(w, reg, names, levels, ok);
    try w.writeAll("\n");
}

fn writeInstallJsonArray(w: anytype, reg: *const registry.Registry, names: []const []const u8, levels: []const usize, ok: []const bool) !void {
    try w.writeAll("[");
    for (names, 0..) |name, i| {
        if (i > 0) try w.writeAll(",");
        const status: []const u8 = if (ok[i])
            "installed"
        else if (failedDependency(reg, names, levels, ok, i) != null)
            "skipped"
        else
            "failed";
        try w.writeAll("{\"name\":");
        try writeJsonString(w, name);
        try w.writeAll(",\"version\":");
        if (store.Store.resolveRequest(reg, name)) |pkg| {
            try writeJsonString(w, pkg.version);
        } else {
            try w.writeAll("null");
        }
        try w.print(",\"status\":\"{s}\"}}", .{status});
    }
    try w.writeAll("]");
}

const InstalledRow = struct {
    name: []const u8,
    version: []const u8,
};

fn lessThanInstalled(_: void, x: InstalledRow, y: InstalledRow) bool {
    const by_name = std.mem.order(u8, x.name, y.name);
    if (by_name != .eq) return by_name == .lt;
    return registry.compareVersions(x.version, y.version) == .lt;
}

/// `list --installed`: the versions in the store for `platform_name`, read from
/// the store's directory names. No registry is needed, so packages the registry
/// has dropped still show.
fn writeInstalled(w: anytype, a: std.mem.Allocator, st: *const store.Store, platform_name: []const u8, json: bool) !u8 {
    var rows = std.ArrayList(InstalledRow).init(a);
    defer rows.deinit();

    if (std.fs.cwd().openDir(st.store_root, .{ .iterate = true })) |opened| {
        var dir = opened;
        defer dir.close();
        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .directory) continue;
            const parsed = store.Store.parseStoreDirName(entry.name) orelse continue;
            if (!std.mem.eql(u8, parsed.platform, platform_name)) continue;
            // The iterator reuses `entry.name`, so the kept strings are copied.
            try rows.append(.{ .name = try a.dupe(u8, parsed.name), .version = try a.dupe(u8, parsed.version) });
        }
    } else |_| {}
    std.mem.sort(InstalledRow, rows.items, {}, lessThanInstalled);

    if (json) {
        try w.writeAll("[");
        for (rows.items, 0..) |row, i| {
            if (i > 0) try w.writeAll(",");
            try w.writeAll("{\"name\":");
            try writeJsonString(w, row.name);
            try w.writeAll(",\"version\":");
            try writeJsonString(w, row.version);
            try w.writeAll("}");
        }
        try w.writeAll("]\n");
        return 0;
    }
    if (rows.items.len == 0) {
        try w.print("no packages installed for {s}\n", .{platform_name});
        return 0;
    }
    for (rows.items) |row| {
        try w.print("{s}{:<24}{s} {}\n", .{ term.bold, safe(row.name), term.reset, safe(row.version) });
    }
    try w.print("\n{d} installed\n", .{rows.items.len});
    return 0;
}

/// `doctor --json`: the checks `Store.doctor` makes, as one JSON document. The
/// text form prints as it goes, so it cannot be reused; the checks are the same.
fn cmdDoctorJson(a: std.mem.Allocator, st: *const store.Store, reg: *const registry.Registry, platform_name: []const u8) !u8 {
    var path_ok = false;
    if (platform.envOwned(a, "PATH")) |env_path| {
        defer a.free(env_path);
        path_ok = std.mem.indexOf(u8, env_path, st.bin_root) != null;
    }
    const store_writable = if (std.fs.cwd().access(st.store_root, .{ .mode = .read_write })) |_| true else |_| false;

    const w = term.writer();
    try w.writeAll("{\"path\":{\"ok\":");
    try w.writeAll(if (path_ok) "true" else "false");
    try w.writeAll(",\"bin_root\":");
    try writeJsonString(w, st.bin_root);
    try w.writeAll("},\"store\":{\"ok\":");
    try w.writeAll(if (store_writable) "true" else "false");
    try w.writeAll(",\"root\":");
    try writeJsonString(w, st.store_root);
    try w.writeAll("},\"broken_links\":[");

    var broken: usize = 0;
    for (reg.packages) |pkg| {
        if (!st.isInstalled(pkg, platform_name)) continue;
        for (pkg.bin) |bin_name| {
            // Same check as `doctor`: on Windows this also catches a launcher
            // shim whose target is gone.
            if (store.Store.binHealth(a, st.bin_root, bin_name, builtin.os.tag) != .ok) {
                if (broken > 0) try w.writeAll(",");
                try w.writeAll("{\"package\":");
                try writeJsonString(w, pkg.name);
                try w.writeAll(",\"bin\":");
                try writeJsonString(w, bin_name);
                try w.writeAll("}");
                broken += 1;
            }
        }
    }

    const warnings: usize = (if (path_ok) @as(usize, 0) else 1) + (if (store_writable) @as(usize, 0) else 1);
    try w.print("],\"warnings\":{d}}}\n", .{warnings});
    return if (warnings + broken == 0) 0 else 1;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main() u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    // Started as a shim (e.g. `rg.exe` hard-linked to abv0)? Run the target.
    // Free for plain `abv0`: one basename comparison, no filesystem access.
    if (@import("shim.zig").maybeRun(gpa.allocator())) |code| return code;

    // Install workers allocate concurrently. The original handed them a plain
    // ArenaAllocator, which is not thread-safe.
    var thread_safe = std.heap.ThreadSafeAllocator{ .child_allocator = gpa.allocator() };
    const base = thread_safe.allocator();

    var arena_state = std.heap.ArenaAllocator.init(base);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const code = run(base, a) catch |e| {
        // Only fall back to the bare error name when nothing more useful has
        // already been printed, so failures are reported exactly once.
        if (!term.anythingReported()) {
            term.err("{s}error{s}: {s}\n", .{ term.red, term.reset, explain(e) });
        }
        term.flush();
        return 1;
    };
    term.flush();
    return code;
}

/// Commands that can download packages. Only these pay for loading the CA store.
fn installsPackages(cmd: []const u8) bool {
    const names = [_][]const u8{ "install", "upgrade", "bundle", "run", "shell", "browse", "maintain", "fix" };
    for (names) |name| {
        if (std.mem.eql(u8, cmd, name)) return true;
    }
    return false;
}

fn run(base: std.mem.Allocator, a: std.mem.Allocator) !u8 {
    const argv = try std.process.argsAlloc(a);
    const rest_argv = if (argv.len > 1) argv[1..] else &[_][]const u8{};

    var diag = ArgDiag{};
    var args = parseArgsDiag(a, rest_argv, &diag) catch |e| {
        term.init(.auto);
        if (e == error.OutOfMemory) return e;
        var buf: [512]u8 = undefined;
        term.err("{s}error{s}: {s}\n", .{ term.red, term.reset, argErrorMessage(&buf, e, diag) });
        return 2;
    };
    defer args.deinit();

    term.init(args.color);
    term.progress_enabled = !args.quiet and !args.json and term.stdoutIsTty();

    if (args.want_version) {
        term.print("abv0 {s} ({s})\n", .{ version, platform.defaultPlatformTag() });
        return 0;
    }
    // Help must not touch the filesystem at all. `abv0 <cmd> --help` gets that
    // command's page; anything else gets the overview.
    if (args.want_help) {
        if (args.command) |name| {
            if (findCommand(name)) |spec| {
                try renderCommandHelp(term.writer(), spec);
                return 0;
            }
        }
        printUsage();
        return 0;
    }
    const cmd = args.command orelse {
        printUsage();
        return 0;
    };
    if (std.mem.eql(u8, cmd, "help")) {
        if (args.rest.items.len == 0) {
            printUsage();
            return 0;
        }
        const topic = args.rest.items[0];
        if (findCommand(topic)) |spec| {
            try renderCommandHelp(term.writer(), spec);
            return 0;
        }
        reportUnknownCommand(topic);
        return 2;
    }
    // `abv0 version` is as natural as `abv0 --version`; accept both.
    if (std.mem.eql(u8, cmd, "version")) {
        term.print("abv0 {s} ({s})\n", .{ version, platform.defaultPlatformTag() });
        return 0;
    }
    // A typo is a usage error. Catch it before the store or the registry is touched.
    if (findCommand(cmd) == null and !std.mem.eql(u8, cmd, "hybrid-sync")) {
        reportUnknownCommand(cmd);
        return 2;
    }

    const platform_name = args.platform_name orelse platform.defaultPlatformTag();
    if (!platform.isKnownPlatformTag(platform_name)) {
        term.err("{s}error{s}: unknown platform '{s}'\n", .{ term.red, term.reset, platform_name });
        return 2;
    }

    // --json keeps stdout to the document alone, so it implies quiet. Verbose
    // lines are free text, so they are dropped under --json as well.
    output = .{
        .quiet = args.quiet or args.json,
        .verbose = args.verbose and !args.json,
        .dry_run = args.dry_run,
        .json = args.json,
    };
    if (output.dry_run and !supportsDryRun(cmd)) {
        term.err("{s}error{s}: --dry-run applies to install, upgrade, uninstall, bundle install, cleanup and migrate --install\n", .{ term.red, term.reset });
        return 2;
    }

    var opts = store.InstallOptions{
        .micro_split = args.micro_split,
        .no_stream = args.no_stream,
        .allow_unverified = args.allow_unverified,
        .allow_suspicious = args.allow_suspicious,
        .force = args.force,
        .quiet = output.quiet,
    };

    // One streaming session for the whole run, shared by every worker. If it
    // cannot be built, installs download to a file first.
    var session: ?stream.Session = null;
    defer if (session) |*s| s.deinit();
    if (!args.no_stream and (installsPackages(cmd) or (args.install and std.mem.eql(u8, cmd, "migrate")))) {
        if (stream.Session.init(base)) |s| {
            session = s;
            opts.session = &session.?;
        } else |_| {}
    }

    var timer = try std.time.Timer.start();

    var st = try store.Store.init(base);
    defer st.deinit();

    // Once a day, a command that changes packages also clears temporary files
    // and stale sandboxes (ABV0_AUTO_CLEAN=0 turns this off).
    if (changesPackages(cmd) and !output.dry_run and auto.enabled("ABV0_AUTO_CLEAN") and auto.dueDaily(a, st.root, "gc")) {
        _ = st.gc(a) catch 0;
        auto.markDone(a, st.root, "gc");
    }

    // ---- commands that need no registry ----
    if (std.mem.eql(u8, cmd, "autoupdate")) return cmdAutoupdate(a, &st, args.rest.items);
    if (std.mem.eql(u8, cmd, "gc")) {
        const n = try st.gc(a);
        say("reclaimed {d} items in {d:.2}ms\n", .{ n, ms(timer.read()) });
        return 0;
    }
    if (std.mem.eql(u8, cmd, "update")) {
        return cmdUpdate(a, &st, args.allow_unsigned_manifest);
    }
    if (std.mem.eql(u8, cmd, "report")) {
        return cmdReport(a, &args, platform_name);
    }
    if (std.mem.eql(u8, cmd, "pinned")) return cmds_extra.cmdPinned(a, &st, null, args.rest.items);
    if (std.mem.eql(u8, cmd, "unpin")) return cmds_extra.cmdUnpin(a, &st, null, args.rest.items);
    if (std.mem.eql(u8, cmd, "completions")) return cmds_extra.cmdCompletions(a, &st, null, args.rest.items);
    if (std.mem.eql(u8, cmd, "which")) return cmds_extra.cmdWhich(a, &st, null, args.rest.items);
    if (std.mem.eql(u8, cmd, "cleanup")) {
        const extra: []const []const u8 = if (output.dry_run) &.{"--dry-run"} else &.{};
        return cmds_extra.cmdCleanup(a, &st, null, if (args.rest.items.len > 0) args.rest.items else extra);
    }
    if (std.mem.eql(u8, cmd, "self-update")) {
        const extra: []const []const u8 = if (args.check) &.{"--check"} else &.{};
        return cmds_extra.cmdSelfUpdate(a, &st, null, if (args.rest.items.len > 0) args.rest.items else extra);
    }
    if (std.mem.eql(u8, cmd, "list") and args.installed) {
        return writeInstalled(term.writer(), a, &st, platform_name, args.json);
    }

    // A dry run reads the registry but must not download it, so it needs one already cached.
    if (output.dry_run and args.registry_path == null and !registryCached(a, &st)) {
        term.err("{s}error{s}: no registry cached yet; run `abv0 update` first (--dry-run does not download)\n", .{ term.red, term.reset });
        return 1;
    }

    // Open TLS connections to GitHub while the registry loads, so the first
    // download reuses a ready connection. Returns at once; failures are ignored.
    if (installsPackages(cmd) and !output.dry_run) net.prewarmGithub(args.rest.items.len);

    if (args.registry_path == null and !output.dry_run and refreshesCatalog(cmd)) {
        autoRefresh(a, &st, args.allow_unsigned_manifest, std.mem.eql(u8, cmd, "maintain"));
    }

    var reg = if (args.registry_path) |p|
        try loadExplicitRegistry(base, &st, p, args.allow_unsigned_manifest)
    else
        try loadRegistry(base, &st, args.allow_unsigned_manifest);
    defer reg.deinit();

    if (std.mem.eql(u8, cmd, "maintain")) return cmdMaintain(a, &st, &reg, &args, platform_name, opts);

    if (std.mem.eql(u8, cmd, "pin")) return cmds_extra.cmdPin(a, &st, &reg, args.rest.items);
    if (std.mem.eql(u8, cmd, "list")) return cmdList(&reg, args.json);
    if (std.mem.eql(u8, cmd, "search")) return cmdSearch(a, &reg, args.rest.items, args.json, args.online);
    if (std.mem.eql(u8, cmd, "info")) return cmdInfo(a, &st, &reg, args.rest.items, args.json, platform_name);
    if (std.mem.eql(u8, cmd, "deps")) return cmdDeps(a, &reg, &args);
    if (std.mem.eql(u8, cmd, "uses")) return cmdUses(a, &st, &reg, &args, platform_name);
    if (std.mem.eql(u8, cmd, "leaves")) return cmdLeaves(a, &st, &reg, &args, platform_name);
    if (std.mem.eql(u8, cmd, "switch")) return cmdSwitch(a, &st, &reg, &args, platform_name, opts);
    if (std.mem.eql(u8, cmd, "rollback")) return cmdSwitch(a, &st, &reg, &args, platform_name, opts);
    if (std.mem.eql(u8, cmd, "home")) return cmdHome(a, &st, &reg, &args, platform_name);
    if (std.mem.eql(u8, cmd, "migrate")) return cmdMigrate(a, &st, &reg, &args, platform_name, opts, &timer);
    if (std.mem.eql(u8, cmd, "install")) return cmdInstall(a, &st, &reg, &args, platform_name, opts, &timer);
    if (std.mem.eql(u8, cmd, "browse")) return cmdBrowse(a, &st, &reg, &args, platform_name, opts, &timer);
    if (std.mem.eql(u8, cmd, "uninstall")) return cmdUninstall(a, &st, &reg, args.rest.items, platform_name);
    if (std.mem.eql(u8, cmd, "outdated")) return cmdOutdated(a, &st, &reg, platform_name, args.json);
    if (std.mem.eql(u8, cmd, "upgrade")) return cmdUpgrade(a, &st, &reg, args.rest.items, args.all, platform_name, opts, args.jobs);
    if (std.mem.eql(u8, cmd, "run")) return cmdRun(a, &st, &reg, args.rest.items, platform_name, opts);
    if (std.mem.eql(u8, cmd, "shell")) return cmdShell(a, &st, &reg, args.rest.items, platform_name, opts);
    if (std.mem.eql(u8, cmd, "bundle")) return cmdBundle(a, &st, &reg, &args, platform_name, opts);
    if (std.mem.eql(u8, cmd, "doctor")) {
        if (args.json) return cmdDoctorJson(a, &st, &reg, platform_name);
        const h = try st.doctor(a, &reg, platform_name);
        term.print("\n{d} warnings, {d} broken links ({d:.2}ms)\n", .{ h.warnings, h.broken_links, ms(timer.read()) });
        return if (h.warnings + h.broken_links == 0) 0 else 1;
    }
    if (std.mem.eql(u8, cmd, "fix")) {
        const n = try st.fix(a, &reg, platform_name);
        const deps = try installMissingDeps(a, &st, &reg, platform_name, opts, args.jobs);
        say("repaired {d} packages and installed {d} missing dependencies in {d:.2}ms\n", .{ n, deps.installed, ms(timer.read()) });
        return if (deps.failed == 0) 0 else 1;
    }
    if (std.mem.eql(u8, cmd, "detect")) return cmdDetect(a, &st, &reg, args.rest.items, platform_name);
    if (std.mem.eql(u8, cmd, "reset")) {
        const n = try st.resetAll(a, &reg, platform_name);
        say("uninstalled {d} packages; store reset\n", .{n});
        return 0;
    }
    if (std.mem.eql(u8, cmd, "sync") or std.mem.eql(u8, cmd, "hybrid-sync")) {
        try st.exportRegistry(a, &reg);
        say("\nsynchronised in {d:.2}ms\n", .{ms(timer.read())});
        return 0;
    }
    if (std.mem.eql(u8, cmd, "benchmark")) return cmdBenchmark(a, &st, &reg, platform_name);

    reportUnknownCommand(cmd);
    return 2;
}

fn ms(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / 1_000_000.0;
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

fn cmdList(reg: *const registry.Registry, json: bool) !u8 {
    if (json) {
        const w = term.writer();
        try w.writeAll("[");
        for (reg.packages, 0..) |pkg, i| {
            if (i > 0) try w.writeAll(",");
            try writePackageJson(w, pkg);
        }
        try w.writeAll("]\n");
        return 0;
    }
    for (reg.packages) |pkg| {
        term.print("{s}{}{s} {s}{}{s}\n    {}\n", .{
            term.bold, safe(pkg.name), term.reset, term.dim, safe(pkg.version), term.reset, safe(pkg.description),
        });
    }
    term.print("\n{d} packages\n", .{reg.count()});
    return 0;
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    return std.ascii.indexOfIgnoreCase(haystack, needle) != null;
}

fn cmdSearch(a: std.mem.Allocator, reg: *const registry.Registry, rest: []const []const u8, json: bool, online: bool) !u8 {
    if (rest.len == 0) {
        term.err("usage: abv0 search [--online] <query>\n", .{});
        return 2;
    }
    const q = try std.mem.join(a, " ", rest);
    defer a.free(q);
    if (q.len > cmds_extra.max_query_len) {
        term.err("{s}error{s}: the query is longer than {d} bytes\n", .{ term.red, term.reset, cmds_extra.max_query_len });
        return 2;
    }
    const w = term.writer();
    if (json and online) try w.writeAll("{\"catalog\":");
    if (json) try w.writeAll("[");
    var found: usize = 0;
    for (reg.packages) |pkg| {
        if (!containsIgnoreCase(pkg.name, q) and !containsIgnoreCase(pkg.description, q)) continue;
        if (json) {
            if (found > 0) try w.writeAll(",");
            try writePackageJson(w, pkg);
        } else {
            term.print("{s}{}{s} {s}{}{s}\n    {}\n", .{
                term.bold, safe(pkg.name), term.reset, term.dim, safe(pkg.version), term.reset, safe(pkg.description),
            });
        }
        found += 1;
    }
    if (json) {
        try w.writeAll("]");
        if (!online) try w.writeAll("\n");
    } else if (found == 0) {
        // No match is an answer, not a failure.
        term.print("no packages match '{}'\n", .{safe(q)});
    }
    if (!online) return 0;
    return searchOnline(a, w, q, json);
}

/// Why a GitHub search failed, in a sentence with a next step.
fn searchFailure(e: anyerror, message: ?[]const u8) []const u8 {
    if (message) |m| return m;
    return switch (e) {
        net.Error.DownloadFailed => "GitHub did not answer (no network, or the search rate limit is used up: 10 a minute without a token; set GITHUB_TOKEN to raise it)",
        else => explain(e),
    };
}

/// `search --online`: the GitHub half. The catalog results are already out.
fn searchOnline(a: std.mem.Allocator, w: anytype, q: []const u8, json: bool) !u8 {
    var message: ?[]const u8 = null;
    var failure: ?[]const u8 = null;
    const repos: []const cmds_extra.Repo = cmds_extra.searchGithub(a, q, &message) catch |e| blk: {
        failure = searchFailure(e, message);
        break :blk &.{};
    };

    if (json) {
        try w.writeAll(",\"online\":");
        try writeRepoJson(w, repos);
        if (failure) |f| {
            try w.writeAll(",\"online_error\":");
            try writeJsonString(w, f);
        }
        try w.writeAll("}\n");
        return if (failure == null) 0 else 1;
    }
    if (failure) |f| {
        term.err("{s}error{s}: GitHub search failed: {}\n", .{ term.red, term.reset, safe(f) });
        return 1;
    }
    if (repos.len == 0) {
        term.print("\nno GitHub repositories match '{}'\n", .{safe(q)});
        return 0;
    }
    term.print("\n{s}GitHub repositories{s} matching '{}' (most stars first; abv0 has not vetted them):\n", .{ term.bold, term.reset, safe(q) });
    for (repos) |r| {
        term.print("{s}{}{s} {s}{d} stars{s}\n", .{ term.bold, safe(r.full_name), term.reset, term.dim, r.stars, term.reset });
        if (r.description.len > 0) term.print("    {}\n", .{safe(r.description)});
        term.print("    abv0 install gh:{}\n", .{safe(r.full_name)});
    }
    return 0;
}

fn writeRepoJson(w: anytype, repos: []const cmds_extra.Repo) !void {
    try w.writeAll("[");
    for (repos, 0..) |r, i| {
        if (i > 0) try w.writeAll(",");
        try w.writeAll("{\"repo\":");
        try writeJsonString(w, r.full_name);
        try w.print(",\"stars\":{d},\"description\":", .{r.stars});
        try writeJsonString(w, r.description);
        try w.writeAll(",\"install\":");
        var spec_buf: [320]u8 = undefined;
        try writeJsonString(w, try std.fmt.bufPrint(&spec_buf, "gh:{s}", .{r.full_name}));
        try w.writeAll("}");
    }
    try w.writeAll("]");
}

/// What `info` prints about the store side of a package: where it came from,
/// which versions are there, how big, and which executables are linked.
fn printInstalledInfo(data: cmds_extra.InfoData, source: []const u8) void {
    term.print("  source: {}\n", .{safe(source)});
    if (data.rows.len == 0) {
        term.print("  installed: no\n", .{});
        return;
    }
    term.print("  installed:\n", .{});
    var i = data.rows.len;
    while (i > 0) {
        i -= 1;
        const r = data.rows[i];
        var buf: [32]u8 = undefined;
        term.print("    {:<14} {s:<7} {s}\n", .{ safe(r.version), if (r.active) "active" else "", term.formatBytes(&buf, r.bytes) });
    }
    var total_buf: [32]u8 = undefined;
    term.print("  size on disk: {s}\n", .{term.formatBytes(&total_buf, data.total_bytes)});
    if (data.bins.len > 0) {
        term.print("  linked:", .{});
        for (data.bins) |b| term.print(" {}", .{safe(b)});
        term.print("\n", .{});
    }
}

fn writeInstalledInfoJson(w: anytype, data: cmds_extra.InfoData, source: []const u8) !void {
    try w.writeAll(",\"source\":");
    try writeJsonString(w, source);
    try w.writeAll(",\"installed\":[");
    for (data.rows, 0..) |r, i| {
        if (i > 0) try w.writeAll(",");
        try w.writeAll("{\"version\":");
        try writeJsonString(w, r.version);
        try w.print(",\"active\":{s},\"bytes\":{d}}}", .{ if (r.active) "true" else "false", r.bytes });
    }
    try w.print("],\"size_bytes\":{d},\"linked_bins\":[", .{data.total_bytes});
    for (data.bins, 0..) |b, i| {
        if (i > 0) try w.writeAll(",");
        try writeJsonString(w, b);
    }
    // The catalog does not publish download sizes.
    try w.writeAll("],\"download_size\":null");
}

fn cmdInfo(
    a: std.mem.Allocator,
    st: *const store.Store,
    reg: *const registry.Registry,
    rest: []const []const u8,
    json: bool,
    platform_name: []const u8,
) !u8 {
    if (rest.len == 0) {
        term.err("usage: abv0 info <pkg>\n", .{});
        return 2;
    }
    const catalog = store.Store.resolveRequest(reg, rest[0]);
    // A package installed from GitHub is not in the catalog; the store knows it.
    const gh = findGithubInstall(a, st, if (catalog) |p| p.name else rest[0], platform_name);
    if (catalog == null and gh == null) {
        term.err("{s}error{s}: '{}' not found\n", .{ term.red, term.reset, safe(rest[0]) });
        hintPackage(a, reg, rest[0]);
        return 1;
    }
    const name = if (gh) |g| g.name else catalog.?.name;
    const data = try cmds_extra.gatherInfo(a, st, name, platform_name);
    var source_buf: [320]u8 = undefined;
    const source: []const u8 = if (gh) |g|
        (std.fmt.bufPrint(&source_buf, "gh:{s}/{s}@{s}", .{ g.owner, g.repo, g.tag }) catch "github")
    else
        "catalog";

    if (json) {
        const w = term.writer();
        try w.writeAll("{");
        if (catalog) |pkg| {
            try writePackageJsonFields(w, pkg);
        } else {
            try w.writeAll("\"name\":");
            try writeJsonString(w, gh.?.name);
            try w.writeAll(",\"version\":");
            try writeJsonString(w, gh.?.version);
        }
        try writeInstalledInfoJson(w, data, source);
        try w.writeAll("}\n");
        return 0;
    }

    const pkg = catalog orelse {
        const g = gh.?;
        term.print("{s}{}{s} {}\n", .{ term.bold, safe(g.name), term.reset, safe(g.version) });
        term.print("  GitHub release of {}/{}\n", .{ safe(g.owner), safe(g.repo) });
        term.print("  https://github.com/{}/{}\n", .{ safe(g.owner), safe(g.repo) });
        printInstalledInfo(data, source);
        return 0;
    };

    term.print("{s}{}{s} {}\n", .{ term.bold, safe(pkg.name), term.reset, safe(pkg.version) });
    if (pkg.description.len > 0) term.print("  {}\n", .{safe(pkg.description)});
    if (pkg.homepage.len > 0) term.print("  {}\n", .{safe(pkg.homepage)});
    term.print("  license: {}\n", .{safe(pkg.license)});
    if (pkg.bin.len > 0) {
        term.print("  binaries:", .{});
        for (pkg.bin) |b| term.print(" {}", .{safe(b)});
        term.print("\n", .{});
    }
    if (pkg.deps.len > 0) {
        term.print("  depends on:", .{});
        for (pkg.deps) |d| term.print(" {}", .{safe(d)});
        term.print("\n", .{});
    }
    printInstalledInfo(data, source);
    term.print("\n  platforms:\n", .{});
    for (pkg.platforms) |p| {
        const pinned = p.checksumIsPinned();
        const colour = if (pinned) term.green else term.yellow;
        const state = if (pinned) "verified" else "UNVERIFIED";
        term.print("    {:<16} {:<8} {s}{s}{s}\n", .{ safe(p.name), safe(p.archive_type), colour, state, term.reset });
        term.print("      {}\n", .{safe(p.url)});
        term.print("      sha256 {}\n", .{safe(if (p.sha256.len > 0) p.sha256 else "(none)")});
    }
    return 0;
}

/// `deps <pkg>`: what a catalog package depends on. Flat (install order) or a tree.
fn cmdDeps(a: std.mem.Allocator, reg: *const registry.Registry, args: *Args) !u8 {
    const rest = args.rest.items;
    if (rest.len != 1) {
        term.err("usage: abv0 deps [--tree] <pkg>\n", .{});
        return 2;
    }
    const pkg = store.Store.resolveRequest(reg, rest[0]) orelse {
        term.err("{s}error{s}: '{}' not found\n", .{ term.red, term.reset, safe(rest[0]) });
        hintPackage(a, reg, rest[0]);
        return 1;
    };
    const w = term.writer();
    if (args.tree) {
        if (args.json) {
            try cmds_extra.writeDepsTreeJson(w, a, reg, pkg);
        } else {
            try cmds_extra.writeDepsTree(w, a, reg, pkg);
        }
        return 0;
    }
    const deps = cmds_extra.collectDeps(a, reg, pkg.name) catch |e| {
        term.err("{s}error{s}: cannot follow the dependencies of {}: {s}\n", .{ term.red, term.reset, safe(pkg.name), @errorName(e) });
        return 1;
    };
    if (args.json) {
        try cmds_extra.writeDepsFlatJson(w, pkg.name, deps);
        return 0;
    }
    for (deps) |d| term.print("{}\n", .{safe(d)});
    return 0;
}

fn writeInstalledListJson(w: anytype, list: []const cmds_extra.InstalledPkg) !void {
    try w.writeAll("[");
    for (list, 0..) |p, i| {
        if (i > 0) try w.writeAll(",");
        try w.writeAll("{\"name\":");
        try writeJsonString(w, p.name);
        try w.writeAll(",\"version\":");
        try writeJsonString(w, p.version);
        try w.writeAll("}");
    }
    try w.writeAll("]\n");
}

/// `uses <pkg>`: installed packages that depend on it.
fn cmdUses(
    a: std.mem.Allocator,
    st: *const store.Store,
    reg: *const registry.Registry,
    args: *Args,
    platform_name: []const u8,
) !u8 {
    const rest = args.rest.items;
    if (rest.len != 1) {
        term.err("usage: abv0 uses <pkg>\n", .{});
        return 2;
    }
    const target: []const u8 = if (store.Store.resolveRequest(reg, rest[0])) |p| p.name else if (findGithubInstall(a, st, rest[0], platform_name)) |g| g.name else {
        term.err("{s}error{s}: '{}' not found\n", .{ term.red, term.reset, safe(rest[0]) });
        hintPackage(a, reg, rest[0]);
        return 1;
    };
    const installed = try cmds_extra.installedPackages(a, st, platform_name);
    const users = try cmds_extra.dependentsOf(a, reg, installed, target);
    if (args.json) {
        try writeInstalledListJson(term.writer(), users);
        return 0;
    }
    for (users) |p| term.print("{}\n", .{safe(p.name)});
    return 0;
}

/// `leaves`: installed packages nothing else installed depends on.
fn cmdLeaves(
    a: std.mem.Allocator,
    st: *const store.Store,
    reg: *const registry.Registry,
    args: *Args,
    platform_name: []const u8,
) !u8 {
    if (args.rest.items.len != 0) {
        term.err("usage: abv0 leaves\n", .{});
        return 2;
    }
    const installed = try cmds_extra.installedPackages(a, st, platform_name);
    const leaves = try cmds_extra.leavesOf(a, reg, installed);
    if (args.json) {
        try writeInstalledListJson(term.writer(), leaves);
        return 0;
    }
    for (leaves) |p| term.print("{}\n", .{safe(p.name)});
    return 0;
}

/// `switch <pkg> <version>` and `rollback <pkg>`: relink an installed version.
/// Nothing is downloaded; the version has to be in the store already.
fn cmdSwitch(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: *const registry.Registry,
    args: *Args,
    platform_name: []const u8,
    opts: store.InstallOptions,
) !u8 {
    const rollback = std.mem.eql(u8, args.command orelse "", "rollback");
    const rest = args.rest.items;
    if (rollback and rest.len != 1) {
        term.err("usage: abv0 rollback <pkg>\n", .{});
        return 2;
    }
    if (!rollback and rest.len != 2) {
        term.err("usage: abv0 switch <pkg> <version>\n", .{});
        return 2;
    }

    const catalog = store.Store.resolveRequest(reg, rest[0]);
    const gh = findGithubInstall(a, st, if (catalog) |p| p.name else rest[0], platform_name);
    if (catalog == null and gh == null) {
        term.err("{s}error{s}: '{}' not found\n", .{ term.red, term.reset, safe(rest[0]) });
        hintPackage(a, reg, rest[0]);
        return 1;
    }
    const name = if (gh) |g| g.name else catalog.?.name;

    const rows = try cmds_extra.listVersions(a, st, name, platform_name);
    if (rows.len == 0) {
        term.err("{s}error{s}: '{}' is not installed\n", .{ term.red, term.reset, safe(name) });
        return 1;
    }
    const from = cmds_extra.activeIndex(rows);

    const to: usize = blk: {
        if (rollback) {
            break :blk cmds_extra.previousIndex(rows) orelse {
                term.err("{s}error{s}: no earlier version of {} is installed to roll back to\n", .{ term.red, term.reset, safe(name) });
                term.err("  `abv0 upgrade` keeps the version it replaces; `abv0 cleanup` removes it\n", .{});
                return 1;
            };
        }
        break :blk cmds_extra.findVersion(rows, rest[1]) orelse {
            term.err("{s}error{s}: {} {} is not installed\n", .{ term.red, term.reset, safe(name), safe(rest[1]) });
            term.err("  installed versions:", .{});
            for (rows) |r| term.err(" {}", .{safe(r.version)});
            term.err("\n", .{});
            return 1;
        };
    };
    const target_version = rows[to].version;

    if (from != null and from.? == to) {
        if (args.json) {
            try writeSwitchJson(term.writer(), name, target_version, target_version);
        } else {
            say("{} is already at {}\n", .{ safe(name), safe(target_version) });
        }
        return 0;
    }

    if (gh) |g| {
        _ = st.relinkGithub(a, g.name, target_version, platform_name, opts) catch |e| {
            reportInstallError(name, e);
            return 1;
        };
    } else {
        // The store directory exists, so install only relinks it.
        var pkg = catalog.?;
        pkg.version = target_version;
        st.install(pkg, platform_name, opts) catch |e| {
            reportInstallError(name, e);
            return 1;
        };
    }

    const from_version: ?[]const u8 = if (from) |i| rows[i].version else null;
    if (args.json) {
        try writeSwitchJson(term.writer(), name, from_version, target_version);
        return 0;
    }
    say("{s}switched{s} {} {s}{}{s} -> {}\n", .{ term.green, term.reset, safe(name), term.dim, safe(from_version orelse "(unknown)"), term.reset, safe(target_version) });
    // `pin` only knows catalog names, so the hint is for those.
    if (gh == null and to + 1 < rows.len and !cmds_extra.isPinned(st, a, name)) {
        say("  `abv0 upgrade` would replace it; `abv0 pin {}` holds it here\n", .{safe(name)});
    }
    return 0;
}

fn writeSwitchJson(w: anytype, name: []const u8, from: ?[]const u8, to: []const u8) !void {
    try w.writeAll("{\"package\":");
    try writeJsonString(w, name);
    try w.writeAll(",\"from\":");
    if (from) |f| try writeJsonString(w, f) else try w.writeAll("null");
    try w.writeAll(",\"to\":");
    try writeJsonString(w, to);
    try w.writeAll("}\n");
}

/// `home <pkg>`: print (and with --open, open) a package's homepage.
fn cmdHome(
    a: std.mem.Allocator,
    st: *const store.Store,
    reg: *const registry.Registry,
    args: *Args,
    platform_name: []const u8,
) !u8 {
    const rest = args.rest.items;
    if (rest.len != 1) {
        term.err("usage: abv0 home [--open] <pkg>\n", .{});
        return 2;
    }
    var name = rest[0];
    var url: []const u8 = "";
    if (store.Store.resolveRequest(reg, rest[0])) |pkg| {
        name = pkg.name;
        url = pkg.homepage;
        if (url.len == 0) {
            term.err("{s}error{s}: {} lists no homepage\n", .{ term.red, term.reset, safe(pkg.name) });
            return 1;
        }
    } else if (ghrelease.parseSpec(rest[0])) |spec| {
        // gh:owner/repo, or owner/repo.
        url = try std.fmt.allocPrint(a, "https://github.com/{s}/{s}", .{ spec.owner, spec.repo });
    } else if (findGithubInstall(a, st, rest[0], platform_name)) |g| {
        url = try std.fmt.allocPrint(a, "https://github.com/{s}/{s}", .{ g.owner, g.repo });
    } else {
        term.err("{s}error{s}: '{}' not found\n", .{ term.red, term.reset, safe(rest[0]) });
        hintPackage(a, reg, rest[0]);
        return 1;
    }

    if (args.json) {
        const w = term.writer();
        try w.writeAll("{\"name\":");
        try writeJsonString(w, name);
        try w.writeAll(",\"homepage\":");
        try writeJsonString(w, url);
        try w.writeAll("}\n");
    } else {
        term.print("{}\n", .{safe(url)});
    }
    if (args.open) {
        if (!std.mem.startsWith(u8, url, "https://")) {
            term.err("{s}error{s}: not opening {}: only https pages are opened\n", .{ term.red, term.reset, safe(url) });
            return 1;
        }
        term.flush();
        platform.openBrowser(a, url);
    }
    return 0;
}

const max_names_bytes = 1024 * 1024;

fn readNamesInput(a: std.mem.Allocator, path: []const u8) ![]u8 {
    if (std.mem.eql(u8, path, "-")) return std.io.getStdIn().reader().readAllAlloc(a, max_names_bytes);
    return std.fs.cwd().readFileAlloc(a, path, max_names_bytes);
}

/// One name to move over from Homebrew.
const BrewWanted = struct { name: []const u8, cask: bool = false, pinned: bool = false };

/// `migrate`: move a Homebrew install over to abv0. With no file given, the
/// Homebrew on this machine is read from disk (its Cellar, Caskroom, install
/// receipts and pins), which takes milliseconds; brew is never run. Only what
/// was installed by hand is taken (`--all` adds the dependencies), each name
/// is matched to the catalog, and `--install` installs the matches in
/// parallel and carries over `brew pin`s.
fn cmdMigrate(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: *const registry.Registry,
    args: *Args,
    platform_name: []const u8,
    opts: store.InstallOptions,
    timer: *std.time.Timer,
) !u8 {
    if (args.rest.items.len != 0) {
        term.err("usage: abv0 migrate [--all] [--from-brew-list <file> | --brewfile <file>] [--install]\n", .{});
        return 2;
    }

    var wanted = std.ArrayList(BrewWanted).init(a);
    var seen = std.StringHashMap(void).init(a);
    var deps_skipped: usize = 0;
    const from_disk = args.from_brew_list == null and args.brewfile == null;

    if (from_disk) {
        var scan_timer = try std.time.Timer.start();
        const prefixes = try cmds_extra.brewPrefixes(a, envOwned(a, "HOMEBREW_PREFIX"), envOwned(a, "HOME"));
        var found = std.ArrayList([]const u8).init(a);
        var formulae: usize = 0;
        var casks: usize = 0;
        for (prefixes) |prefix| {
            const items = (try cmds_extra.scanBrew(a, prefix)) orelse continue;
            try found.append(prefix);
            for (items) |it| {
                if (it.kind == .cask) casks += 1 else formulae += 1;
                if (!it.requested and !args.all) {
                    deps_skipped += 1;
                    continue;
                }
                if (try seen.fetchPut(it.name, {}) == null) {
                    try wanted.append(.{ .name = it.name, .cask = it.kind == .cask, .pinned = it.pinned });
                }
            }
        }
        if (found.items.len == 0) {
            term.err("{s}error{s}: no Homebrew found (looked in", .{ term.red, term.reset });
            for (prefixes) |p| term.err(" {}", .{safe(p)});
            term.err(")\n  set HOMEBREW_PREFIX, or give a list: brew list --formula > brew.txt; abv0 migrate --from-brew-list brew.txt\n", .{});
            return 1;
        }
        if (!args.json) {
            term.print("Homebrew at", .{});
            for (found.items) |p| term.print(" {}", .{safe(p)});
            term.print(": {d} formulae, {d} apps, read in {d:.2}ms", .{ formulae, casks, ms(scan_timer.read()) });
            if (deps_skipped > 0) term.print(" ({d} dependencies left out; --all takes them too)", .{deps_skipped});
            term.print("\n", .{});
        }
    } else {
        const inputs = [_]struct { path: ?[]const u8, source: cmds_extra.NameSource }{
            .{ .path = args.from_brew_list, .source = .list },
            .{ .path = args.brewfile, .source = .brewfile },
        };
        for (inputs) |in| {
            const path = in.path orelse continue;
            const text = readNamesInput(a, path) catch |e| {
                term.err("{s}error{s}: cannot read {}: {s}\n", .{ term.red, term.reset, safe(path), explain(e) });
                return 1;
            };
            for (try cmds_extra.parseNames(a, text, in.source)) |n| {
                if (try seen.fetchPut(n, {}) == null) try wanted.append(.{ .name = n });
            }
        }
    }

    var matched = std.ArrayList(cmds_extra.Match).init(a);
    var unmatched = std.ArrayList([]const u8).init(a);
    var no_build = std.ArrayList([]const u8).init(a);
    // Two Homebrew names can land on one catalog package; install it once.
    var installs = std.ArrayList([]const u8).init(a);
    var to_pin = std.ArrayList([]const u8).init(a);
    var already: usize = 0;
    var picked = std.StringHashMap(void).init(a);
    for (wanted.items) |w| {
        const found = if (w.cask) cmds_extra.matchCask(reg, w.name) else cmds_extra.matchName(reg, w.name);
        const m = found orelse {
            try unmatched.append(w.name);
            continue;
        };
        if (m.pkg.platform(platform_name) == null) {
            try no_build.append(w.name);
            continue;
        }
        try matched.append(m);
        if (w.pinned and !auto.contains(to_pin.items, m.pkg.name)) try to_pin.append(m.pkg.name);
        if (try picked.fetchPut(m.pkg.name, {}) != null) continue;
        if (st.isInstalled(m.pkg, platform_name)) {
            already += 1;
            continue;
        }
        try installs.append(m.pkg.name);
    }

    const w = term.writer();
    if (!args.json) {
        term.print("{d} to move: {s}{d} in the catalog{s}, {d} not", .{ wanted.items.len, term.green, matched.items.len, term.reset, unmatched.items.len });
        if (no_build.items.len > 0) term.print(", {d} without a build for {s}", .{ no_build.items.len, platform_name });
        if (already > 0) term.print(", {d} already installed", .{already});
        term.print("\n", .{});
        if (matched.items.len > 0 and !output.quiet) {
            term.print("\n{s}in the catalog{s}\n", .{ term.bold, term.reset });
            for (matched.items) |m| {
                term.print("  {:<24} -> {}", .{ safe(m.wanted), safe(m.pkg.name) });
                if (m.via != .exact) term.print(" {s}({s}){s}", .{ term.dim, m.via.label(), term.reset });
                term.print("\n", .{});
            }
        }
        if (no_build.items.len > 0 and !output.quiet) {
            term.print("\n{s}no build for {s}{s}\n", .{ term.bold, platform_name, term.reset });
            for (no_build.items) |n| term.print("  {}\n", .{safe(n)});
        }
        if (unmatched.items.len > 0 and !output.quiet) {
            term.print("\n{s}not in the catalog{s} (they stay with Homebrew)\n", .{ term.bold, term.reset });
            for (unmatched.items) |n| term.print("  {:<24} {s}abv0 search --online {}{s}\n", .{ safe(n), term.dim, safe(n), term.reset });
            term.print("  a project's own GitHub release installs with: abv0 install gh:<owner>/<repo>\n", .{});
        }
    }

    var failures: usize = 0;
    var names: []const []const u8 = &.{};
    var levels: []const usize = &.{};
    var ok: []bool = try a.alloc(bool, 0);
    const do_install = args.install and installs.items.len > 0;
    if (do_install) {
        const plan = try planInstall(a, reg, installs.items);
        if (output.dry_run) {
            if (args.json) {
                try writeMigrateJson(w, matched.items, unmatched.items);
                try w.writeAll(",\"install\":");
            }
            try writeDryRunPlan(w, a, st, reg, plan.names, platform_name, "install");
            if (args.json) try w.writeAll("}\n");
            return 0;
        }
        if (!args.json) term.print("\n", .{});
        const kept = try dropUnavailableDeps(a, reg, plan, installs.items, platform_name);
        names = kept.names;
        levels = kept.levels;
        const before = try installedFlags(a, st, reg, names, platform_name);
        ok = try a.alloc(bool, names.len);
        failures = try installWaves(a, st, reg, names, levels, ok, platform_name, opts, args.jobs);
        try recordInstall(a, st, names, ok, before, installs.items);
    }

    // `brew pin`s carry over once the package is here.
    var pinned: usize = 0;
    if (args.install and to_pin.items.len > 0 and !output.dry_run) {
        var here = std.ArrayList([]const u8).init(a);
        for (to_pin.items) |n| {
            const p = reg.get(n) orelse continue;
            if (st.isInstalled(p, platform_name)) try here.append(n);
        }
        pinned = cmds_extra.addPins(a, st, here.items) catch 0;
    }

    if (args.json) {
        try writeMigrateJson(w, matched.items, unmatched.items);
        try w.writeAll(",\"no_build\":[");
        for (no_build.items, 0..) |n, i| {
            if (i > 0) try w.writeAll(",");
            try writeJsonString(w, n);
        }
        try w.writeAll("]");
        if (do_install) {
            try w.writeAll(",\"install\":");
            try writeInstallJsonArray(w, reg, names, levels, ok);
        }
        try w.writeAll("}\n");
        return if (failures == 0) 0 else 1;
    }
    if (do_install) {
        const elapsed = ms(timer.read());
        if (failures == 0) {
            say("\n{s}done{s} {d} packages in {d:.2}ms\n", .{ term.green, term.reset, names.len, elapsed });
        } else {
            term.print("\n{s}{d} of {d} packages failed{s} ({d:.2}ms)\n", .{ term.red, failures, names.len, term.reset, elapsed });
        }
        if (pinned > 0) term.print("pinned {d} (as in Homebrew)\n", .{pinned});
        if (from_disk and failures == 0) try printBrewRemoval(a, matched.items, wanted.items);
    } else if (!args.install and installs.items.len > 0) {
        term.print("\nrun again with --install to install the {d} catalog packages\n", .{installs.items.len});
    } else if (args.install and matched.items.len > 0) {
        term.print("\nnothing to install: the catalog matches are already here\n", .{});
        if (pinned > 0) term.print("pinned {d} (as in Homebrew)\n", .{pinned});
    }
    return if (failures == 0) 0 else 1;
}

/// After a move: the command that removes the moved packages from Homebrew.
/// abv0 never runs it; the links Homebrew puts first on PATH would otherwise
/// keep winning.
fn printBrewRemoval(a: std.mem.Allocator, matched: []const cmds_extra.Match, wanted: []const BrewWanted) !void {
    var formulae = std.ArrayList(u8).init(a);
    var casks = std.ArrayList(u8).init(a);
    for (matched) |m| {
        var is_cask = false;
        for (wanted) |x| {
            if (std.mem.eql(u8, x.name, m.wanted)) is_cask = x.cask;
        }
        const list = if (is_cask) &casks else &formulae;
        try list.append(' ');
        try list.appendSlice(m.wanted);
    }
    if (formulae.items.len == 0 and casks.items.len == 0) return;
    term.print("\nHomebrew still has its copies. When you are happy, remove them with:\n", .{});
    if (formulae.items.len > 0) term.print("  brew uninstall{}\n", .{safe(formulae.items)});
    if (casks.items.len > 0) term.print("  brew uninstall --cask{}\n", .{safe(casks.items)});
}

/// The `matched` and `unmatched` members of the `migrate --json` document,
/// opened with `{` and left open so the caller can add `install`.
fn writeMigrateJson(w: anytype, matched: []const cmds_extra.Match, unmatched: []const []const u8) !void {
    try w.writeAll("{\"matched\":[");
    for (matched, 0..) |m, i| {
        if (i > 0) try w.writeAll(",");
        try w.writeAll("{\"name\":");
        try writeJsonString(w, m.wanted);
        try w.writeAll(",\"package\":");
        try writeJsonString(w, m.pkg.name);
        try w.writeAll(",\"via\":");
        try writeJsonString(w, @tagName(m.via));
        try w.writeAll("}");
    }
    try w.writeAll("],\"unmatched\":[");
    for (unmatched, 0..) |n, i| {
        if (i > 0) try w.writeAll(",");
        try writeJsonString(w, n);
    }
    try w.writeAll("]");
}

/// `abv0 browse`: pick packages in a full-screen list, then install them as
/// `abv0 install` would.
fn cmdBrowse(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: *const registry.Registry,
    args: *Args,
    platform_name: []const u8,
    opts: store.InstallOptions,
    timer: *std.time.Timer,
) !u8 {
    const Installed = struct {
        st: *store.Store,
        platform_name: []const u8,
        pub fn check(self: @This(), p: registry.Package) bool {
            return self.st.isInstalled(p, self.platform_name);
        }
    };
    term.flush();
    const picked = tui.browse(a, reg, platform_name, Installed{ .st = st, .platform_name = platform_name }, term.green.len > 0) catch |e| switch (e) {
        error.NotATerminal => {
            term.err("{s}error{s}: browse needs an interactive terminal; use `abv0 search` and `abv0 install` in scripts\n", .{ term.red, term.reset });
            return 2;
        },
        else => return e,
    } orelse return 0;
    if (picked.len == 0) return 0;
    args.rest.clearRetainingCapacity();
    try args.rest.appendSlice(picked);
    // Reset the clock so the summary times the install, not the browsing.
    timer.reset();
    return cmdInstall(a, st, reg, args, platform_name, opts, timer);
}

fn cmdInstall(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: *const registry.Registry,
    args: *Args,
    platform_name: []const u8,
    opts: store.InstallOptions,
    timer: *std.time.Timer,
) !u8 {
    if (args.rest.items.len == 0) {
        term.err("usage: abv0 install <pkg|gh:owner/repo[@tag]>...\n", .{});
        return 2;
    }
    for (args.rest.items) |name| noteUnknownName(a, reg, name);

    // Dependencies come along, and always install before what needs them.
    const plan = try planInstall(a, reg, args.rest.items);
    defer a.free(plan.names);
    defer a.free(plan.levels);

    if (output.dry_run) {
        try writeDryRunPlan(term.writer(), a, st, reg, plan.names, platform_name, "install");
        // A real install of an unknown name fails, so its dry run does too.
        for (args.rest.items) |name| {
            const is_spec = std.mem.startsWith(u8, name, "gh:") or std.mem.indexOfScalar(u8, name, '/') != null;
            if (!is_spec and store.Store.resolveRequest(reg, name) == null) return 1;
        }
        return 0;
    }

    const requested = try requestedNames(a, reg, args.rest.items);
    defer a.free(requested);
    const kept = try dropUnavailableDeps(a, reg, plan, requested, platform_name);
    defer a.free(kept.names);
    defer a.free(kept.levels);
    const before = try installedFlags(a, st, reg, kept.names, platform_name);
    defer a.free(before);

    const ok = try a.alloc(bool, kept.names.len);
    defer a.free(ok);
    const failures = try installWaves(a, st, reg, kept.names, kept.levels, ok, platform_name, opts, args.jobs);
    try recordInstall(a, st, kept.names, ok, before, requested);
    const plan_names = kept.names;

    if (output.json) {
        try writeInstallJson(term.writer(), reg, kept.names, kept.levels, ok);
        return if (failures == 0) 0 else 1;
    }

    const elapsed = ms(timer.read());
    if (failures == 0) {
        say("\n{s}done{s} {d} packages in {d:.2}ms\n", .{ term.green, term.reset, plan_names.len, elapsed });
        return 0;
    }
    term.print("\n{s}{d} of {d} packages failed{s} ({d:.2}ms)\n", .{ term.red, failures, plan_names.len, term.reset, elapsed });
    return 1;
}

/// The installed GitHub package a command line names: `gh:owner/repo[@tag]` or
/// `owner/repo` (the owner must match), or just the repository name.
fn findGithubInstall(a: std.mem.Allocator, st: *const store.Store, name: []const u8, platform_name: []const u8) ?store.Store.GhEntry {
    const spec: ?ghrelease.Spec = if (ghverify.looksLikeSpec(name)) (ghrelease.parseSpec(name) orelse return null) else null;
    const repo = if (spec) |sp| sp.repo else name;
    const entries = st.githubInstalled(a, platform_name) catch return null;
    for (entries) |e| {
        if (!std.mem.eql(u8, e.name, repo)) continue;
        if (spec) |sp| {
            if (!std.ascii.eqlIgnoreCase(sp.owner, e.owner)) continue;
        }
        return e;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Dependencies, auto-update and upkeep
// ---------------------------------------------------------------------------

/// Commands that install, upgrade or remove packages.
fn changesPackages(cmd: []const u8) bool {
    const names = [_][]const u8{ "install", "upgrade", "uninstall", "browse", "maintain", "bundle", "migrate", "fix" };
    for (names) |n| {
        if (std.mem.eql(u8, cmd, n)) return true;
    }
    return false;
}

/// Commands that read the catalog and should not work from a stale one.
fn refreshesCatalog(cmd: []const u8) bool {
    const names = [_][]const u8{ "install", "upgrade", "outdated", "browse", "search", "info", "maintain", "bundle", "migrate", "fix" };
    for (names) |n| {
        if (std.mem.eql(u8, cmd, n)) return true;
    }
    return false;
}

/// Refresh the installed catalog when it is older than ABV0_UPDATE_HOURS
/// (default 24; `ABV0_AUTO_UPDATE=0` turns this off). `always` refreshes
/// unless it was done in the last hour. A failed refresh is reported and the
/// copy on disk is used.
fn autoRefresh(a: std.mem.Allocator, st: *store.Store, allow_unsigned: bool, always: bool) void {
    const limit: i64 = if (always) 3600 else (auto.refreshAfterSeconds() orelse return);
    const paths = registryPaths(a, st) catch return;
    defer a.free(paths[0]);
    defer a.free(paths[1]);
    // No catalog yet: loading it fetches one anyway.
    const age = auto.ageSeconds(paths[0]) orelse return;
    if (age < limit) return;
    const hours = @divTrunc(age, 3600);
    if (hours >= 48) {
        say("{s}catalog{s}  {d} days old; refreshing\n", .{ term.dim, term.reset, @divTrunc(hours, 24) });
    } else {
        say("{s}catalog{s}  {d} hours old; refreshing\n", .{ term.dim, term.reset, hours });
    }
    const was_quiet = output.quiet;
    output.quiet = true;
    const code = cmdUpdate(a, st, allow_unsigned) catch 1;
    output.quiet = was_quiet;
    if (code != 0) {
        term.err("{s}warning{s}: could not refresh the catalog; using the copy on disk\n", .{ term.yellow, term.reset });
        // Do not try again on every command while offline.
        if (std.fs.cwd().openFile(paths[0], .{ .mode = .read_write })) |f| {
            defer f.close();
            const now = std.time.nanoTimestamp();
            f.updateTimes(now, now) catch {};
        } else |_| {}
    }
}

/// The registry names a command line asked for (gh: specs and unknown names
/// are left out). Owned by `a`.
fn requestedNames(a: std.mem.Allocator, reg: *const registry.Registry, rest: []const []const u8) ![]const []const u8 {
    var out = std.ArrayList([]const u8).init(a);
    for (rest) |name| {
        if (store.Store.resolveRequest(reg, name)) |p| try out.append(p.name);
    }
    return out.toOwnedSlice();
}

/// `plan` without the dependencies that have no build for this platform: each
/// is named once, and what needs it is installed anyway. Requested packages
/// always stay, so their own error is reported as before.
fn dropUnavailableDeps(a: std.mem.Allocator, reg: *const registry.Registry, plan: Plan, requested: []const []const u8, platform_name: []const u8) !struct { names: []const []const u8, levels: []const usize } {
    var names = std.ArrayList([]const u8).init(a);
    errdefer names.deinit();
    var levels = std.ArrayList(usize).init(a);
    errdefer levels.deinit();
    for (plan.names, plan.levels) |name, lv| {
        if (!auto.contains(requested, name)) {
            if (store.Store.resolveRequest(reg, name)) |p| {
                if (p.platform(platform_name) == null) {
                    term.err("{s}note{s}: dependency {s} has no build for {s}; skipping it\n", .{ term.yellow, term.reset, p.name, platform_name });
                    continue;
                }
            }
        }
        try names.append(name);
        try levels.append(lv);
    }
    return .{ .names = try names.toOwnedSlice(), .levels = try levels.toOwnedSlice() };
}

/// Which of `names` are installed right now.
fn installedFlags(a: std.mem.Allocator, st: *const store.Store, reg: *const registry.Registry, names: []const []const u8, platform_name: []const u8) ![]bool {
    const out = try a.alloc(bool, names.len);
    for (names, 0..) |n, i| {
        out[i] = if (store.Store.resolveRequest(reg, n)) |p| st.isInstalled(p, platform_name) else true;
    }
    return out;
}

/// After an install: the requested packages are the user's; the others that
/// were installed by this run (not before it) are dependencies.
fn recordInstall(a: std.mem.Allocator, st: *const store.Store, names: []const []const u8, ok: []const bool, before: []const bool, requested: []const []const u8) !void {
    var pulled = std.ArrayList([]const u8).init(a);
    defer pulled.deinit();
    for (names, ok, before) |n, done, was| {
        if (done and !was and !auto.contains(requested, n)) try pulled.append(n);
    }
    auto.noteInstall(a, st.root, requested, pulled.items) catch {};
}

/// Names of the packages installed for `platform_name`. Owned by `a`.
fn installedNames(a: std.mem.Allocator, st: *const store.Store, platform_name: []const u8) ![]const []const u8 {
    var out = std.ArrayList([]const u8).init(a);
    var dir = std.fs.cwd().openDir(st.store_root, .{ .iterate = true }) catch return out.toOwnedSlice();
    defer dir.close();
    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .directory) continue;
        const parsed = store.Store.parseStoreDirName(entry.name) orelse continue;
        if (!std.mem.eql(u8, parsed.platform, platform_name)) continue;
        if (auto.contains(out.items, parsed.name)) continue;
        try out.append(try a.dupe(u8, parsed.name));
    }
    return out.toOwnedSlice();
}

/// Uninstall dependencies nothing installed needs any more. Only packages abv0
/// recorded as pulled in are candidates (ABV0_AUTO_REMOVE=0 turns this off).
fn removeUnusedDeps(a: std.mem.Allocator, st: *store.Store, reg: *const registry.Registry, platform_name: []const u8) !usize {
    if (!auto.enabled("ABV0_AUTO_REMOVE")) return 0;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const aa = arena.allocator();
    var removed: usize = 0;
    // Removing one can free another, so repeat until nothing changes.
    var rounds: usize = 0;
    while (rounds < 16) : (rounds += 1) {
        const installed = try installedNames(aa, st, platform_name);
        const deps_only = try auto.readNames(aa, st.root, auto.deps_only_file);
        const gone = try auto.orphans(aa, reg, installed, deps_only);
        if (gone.len == 0) break;
        for (gone) |name| {
            const pkg = reg.get(name) orelse registry.Package{ .name = name, .version = "" };
            if (st.uninstall(aa, pkg) catch false) {
                say("  {s}removed{s}  {s} (no longer needed)\n", .{ term.dim, term.reset, name });
                removed += 1;
            }
        }
        try auto.forget(aa, st.root, gone);
    }
    return removed;
}

/// Install every dependency of an installed package that is itself missing.
fn installMissingDeps(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: *const registry.Registry,
    platform_name: []const u8,
    opts: store.InstallOptions,
    jobs: ?usize,
) !struct { installed: usize, failed: usize } {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const aa = arena.allocator();
    const installed = try installedNames(aa, st, platform_name);
    var missing = std.ArrayList([]const u8).init(aa);
    for (installed) |n| {
        const pkg = reg.get(n) orelse continue;
        for (pkg.deps) |d| {
            const dep = reg.get(d) orelse continue;
            if (dep.platform(platform_name) == null or st.isInstalled(dep, platform_name)) continue;
            if (!auto.contains(missing.items, d)) try missing.append(d);
        }
    }
    if (missing.items.len == 0) return .{ .installed = 0, .failed = 0 };
    for (missing.items) |d| say("  {s}missing{s}  dependency {s}\n", .{ term.yellow, term.reset, d });
    const plan = try planInstall(aa, reg, missing.items);
    const kept = try dropUnavailableDeps(aa, reg, plan, missing.items, platform_name);
    const before = try installedFlags(aa, st, reg, kept.names, platform_name);
    const ok = try aa.alloc(bool, kept.names.len);
    const failures = try installWaves(aa, st, reg, kept.names, kept.levels, ok, platform_name, opts, jobs);
    try recordInstall(aa, st, kept.names, ok, before, &.{});
    var n: usize = 0;
    for (ok) |done| {
        if (done) n += 1;
    }
    return .{ .installed = n, .failed = failures };
}

/// `abv0 maintain`: what the scheduled job runs, and what anyone can run by
/// hand. Refresh the catalog (done before the registry is loaded), upgrade
/// every package that is not pinned, install missing dependencies, remove
/// unused ones, clear temporary files, then update abv0 itself.
fn cmdMaintain(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: *const registry.Registry,
    args: *Args,
    platform_name: []const u8,
    opts: store.InstallOptions,
) !u8 {
    var bad: u8 = 0;
    say("{s}maintain{s} {s}\n", .{ term.bold, term.reset, platform_name });
    if (try cmdUpgrade(a, st, reg, &.{}, true, platform_name, opts, args.jobs) != 0) bad = 1;
    const deps = try installMissingDeps(a, st, reg, platform_name, opts, args.jobs);
    if (deps.failed != 0) bad = 1;
    _ = try removeUnusedDeps(a, st, reg, platform_name);
    const cleared = st.gc(a) catch 0;
    auto.markDone(a, st.root, "gc");
    if (cleared > 0) say("  {s}cleaned{s}  {d} temporary items\n", .{ term.dim, term.reset, cleared });
    if (auto.enabled("ABV0_AUTO_SELF_UPDATE")) {
        if ((cmds_extra.cmdSelfUpdate(a, st, null, &.{}) catch 1) != 0) bad = 1;
    }
    auto.markDone(a, st.root, "maintain");
    return bad;
}

/// Run a system tool, discarding its output. Its exit code, or null when it
/// could not be started.
fn runTool(a: std.mem.Allocator, argv: []const []const u8) ?u8 {
    const r = std.process.Child.run(.{ .allocator = a, .argv = argv, .max_output_bytes = 1 << 20 }) catch return null;
    a.free(r.stdout);
    a.free(r.stderr);
    return switch (r.term) {
        .Exited => |c| c,
        else => 255,
    };
}

/// Like runTool, returning stdout (owned by `a`) when the tool succeeded.
fn toolOutput(a: std.mem.Allocator, argv: []const []const u8) ?[]u8 {
    const r = std.process.Child.run(.{ .allocator = a, .argv = argv, .max_output_bytes = 1 << 20 }) catch return null;
    a.free(r.stderr);
    switch (r.term) {
        .Exited => |c| if (c == 0) return r.stdout,
        else => {},
    }
    a.free(r.stdout);
    return null;
}

fn envOwned(a: std.mem.Allocator, name: []const u8) ?[]u8 {
    return std.process.getEnvVarOwned(a, name) catch null;
}

/// `abv0 autoupdate on [--weekly] | off | status`: a scheduled `abv0 maintain`
/// through the system's own scheduler (launchd, systemd or cron, Task
/// Scheduler).
fn cmdAutoupdate(base: std.mem.Allocator, st: *store.Store, rest: []const []const u8) !u8 {
    var arena = std.heap.ArenaAllocator.init(base);
    defer arena.deinit();
    const a = arena.allocator();
    const sub = if (rest.len > 0) rest[0] else "status";
    var interval: auto.Interval = .daily;
    for (rest[@min(rest.len, 1)..]) |opt| {
        if (std.mem.eql(u8, opt, "--weekly")) interval = .weekly else if (std.mem.eql(u8, opt, "--daily")) interval = .daily else {
            term.err("usage: abv0 autoupdate on [--daily|--weekly] | off | status\n", .{});
            return 2;
        }
    }
    const logs = try std.fs.path.join(a, &.{ st.root, "logs" });
    const log = try std.fs.path.join(a, &.{ logs, "maintain.log" });
    const env = auto.JobEnv{ .home = envOwned(a, "ABV0_HOME"), .bin_dir = envOwned(a, "ABV0_BIN_DIR") };

    if (std.mem.eql(u8, sub, "on")) {
        const exe = try std.fs.selfExePathAlloc(a);
        try std.fs.cwd().makePath(logs);
        const how = scheduleOn(a, st, exe, log, interval, env) catch |e| {
            const why: []const u8 = switch (e) {
                error.CrontabFailed => "no scheduler found: this needs a systemd user session or cron (the crontab command)",
                error.LaunchctlFailed => "launchctl refused the job",
                error.SchtasksFailed => "Task Scheduler refused the job",
                else => @errorName(e),
            };
            term.err("{s}error{s}: could not schedule abv0 maintain: {s}\n", .{ term.red, term.reset, why });
            return 1;
        };
        say("{s}on{s}  abv0 maintain runs {s} at about 03:17 ({s})\n", .{ term.green, term.reset, @tagName(interval), how });
        say("     it refreshes the catalog, upgrades unpinned packages, installs missing\n     dependencies, removes unused ones, cleans up and updates abv0\n", .{});
        say("     log: {s}\n", .{log});
        return 0;
    }
    if (std.mem.eql(u8, sub, "off")) {
        scheduleOff(a, st);
        say("{s}off{s}  automatic upkeep is disabled\n", .{ term.yellow, term.reset });
        return 0;
    }
    if (std.mem.eql(u8, sub, "status")) {
        const state = scheduleStatus(a, st);
        say("scheduled:   {s}\n", .{state});
        const last = try std.fs.path.join(a, &.{ st.root, "state", "last-maintain" });
        if (auto.ageSeconds(last)) |age| {
            say("last run:    {d} hours ago\n", .{@divTrunc(age, 3600)});
        } else say("last run:    never\n", .{});
        if (auto.refreshAfterSeconds()) |sec| {
            say("catalog:     refreshed when older than {d} hours (ABV0_UPDATE_HOURS)\n", .{@divTrunc(sec, 3600)});
        } else say("catalog:     automatic refresh off (ABV0_AUTO_UPDATE=0)\n", .{});
        say("log:         {s}\n", .{log});
        return 0;
    }
    term.err("usage: abv0 autoupdate on [--daily|--weekly] | off | status\n", .{});
    return 2;
}

/// The user's id, for launchd's `gui/<uid>` domain (macOS only).
fn currentUid() u32 {
    const c = struct {
        extern "c" fn getuid() c_uint;
    };
    return @intCast(c.getuid());
}

fn launchdPlistPath(a: std.mem.Allocator, st: *const store.Store) ![]u8 {
    return std.fs.path.join(a, &.{ st.home, "Library", "LaunchAgents", auto.job_label ++ ".plist" });
}

fn systemdDir(a: std.mem.Allocator, st: *const store.Store) ![]u8 {
    if (envOwned(a, "XDG_CONFIG_HOME")) |x| {
        if (std.fs.path.isAbsolute(x)) return std.fs.path.join(a, &.{ x, "systemd", "user" });
    }
    return std.fs.path.join(a, &.{ st.home, ".config", "systemd", "user" });
}

fn hasUserSystemd(a: std.mem.Allocator) bool {
    return (runTool(a, &.{ "systemctl", "--user", "show-environment" }) orelse 1) == 0;
}

fn scheduleOn(a: std.mem.Allocator, st: *const store.Store, exe: []const u8, log: []const u8, interval: auto.Interval, env: auto.JobEnv) anyerror![]const u8 {
    switch (builtin.os.tag) {
        .macos => {
            const plist = try launchdPlistPath(a, st);
            try std.fs.cwd().makePath(std.fs.path.dirname(plist).?);
            try std.fs.cwd().writeFile(.{ .sub_path = plist, .data = try auto.launchdPlist(a, exe, log, interval, env) });
            const domain = try std.fmt.allocPrint(a, "gui/{d}", .{currentUid()});
            const target = try std.fmt.allocPrint(a, "{s}/{s}", .{ domain, auto.job_label });
            _ = runTool(a, &.{ "launchctl", "bootout", target });
            if ((runTool(a, &.{ "launchctl", "bootstrap", domain, plist }) orelse 1) != 0) {
                if ((runTool(a, &.{ "launchctl", "load", "-w", plist }) orelse 1) != 0) return error.LaunchctlFailed;
            }
            return "launchd";
        },
        .windows => {
            const tr = try auto.schtasksCommand(a, exe, log, env);
            var argv = std.ArrayList([]const u8).init(a);
            try argv.appendSlice(&.{ "schtasks", "/Create", "/F", "/TN", auto.job_name, "/ST", "03:17", "/TR", tr });
            if (interval == .daily) try argv.appendSlice(&.{ "/SC", "DAILY" }) else try argv.appendSlice(&.{ "/SC", "WEEKLY", "/D", "SUN" });
            if ((runTool(a, argv.items) orelse 1) != 0) return error.SchtasksFailed;
            return "Task Scheduler";
        },
        else => {
            if (hasUserSystemd(a)) {
                const dir = try systemdDir(a, st);
                try std.fs.cwd().makePath(dir);
                const units = try auto.systemdUnits(a, exe, interval, env);
                try std.fs.cwd().writeFile(.{ .sub_path = try std.fs.path.join(a, &.{ dir, auto.job_name ++ ".service" }), .data = units.service });
                try std.fs.cwd().writeFile(.{ .sub_path = try std.fs.path.join(a, &.{ dir, auto.job_name ++ ".timer" }), .data = units.timer });
                _ = runTool(a, &.{ "systemctl", "--user", "daemon-reload" });
                if ((runTool(a, &.{ "systemctl", "--user", "enable", "--now", auto.job_name ++ ".timer" }) orelse 1) == 0) return "systemd user timer";
            }
            // No user systemd: the user's crontab.
            const current = toolOutput(a, &.{ "crontab", "-l" }) orelse "";
            const text = try auto.editCrontab(a, current, try auto.cronLine(a, exe, log, interval, env));
            const tmp = try std.fs.path.join(a, &.{ st.root, "state", "crontab.tmp" });
            try std.fs.cwd().makePath(std.fs.path.dirname(tmp).?);
            try std.fs.cwd().writeFile(.{ .sub_path = tmp, .data = text });
            defer std.fs.cwd().deleteFile(tmp) catch {};
            if ((runTool(a, &.{ "crontab", tmp }) orelse 1) != 0) return error.CrontabFailed;
            return "cron";
        },
    }
}

fn scheduleOff(a: std.mem.Allocator, st: *const store.Store) void {
    switch (builtin.os.tag) {
        .macos => {
            const plist = launchdPlistPath(a, st) catch return;
            const target = std.fmt.allocPrint(a, "gui/{d}/{s}", .{ currentUid(), auto.job_label }) catch return;
            if ((runTool(a, &.{ "launchctl", "bootout", target }) orelse 1) != 0) _ = runTool(a, &.{ "launchctl", "unload", "-w", plist });
            std.fs.cwd().deleteFile(plist) catch {};
        },
        .windows => _ = runTool(a, &.{ "schtasks", "/Delete", "/F", "/TN", auto.job_name }),
        else => {
            if (hasUserSystemd(a)) _ = runTool(a, &.{ "systemctl", "--user", "disable", "--now", auto.job_name ++ ".timer" });
            if (systemdDir(a, st)) |dir| {
                for ([_][]const u8{ ".service", ".timer" }) |ext| {
                    const f = std.fmt.allocPrint(a, "{s}{s}", .{ auto.job_name, ext }) catch continue;
                    std.fs.cwd().deleteFile(std.fs.path.join(a, &.{ dir, f }) catch continue) catch {};
                }
            } else |_| {}
            if (toolOutput(a, &.{ "crontab", "-l" })) |current| {
                if (std.mem.indexOf(u8, current, auto.cron_marker) != null) {
                    const text = auto.editCrontab(a, current, null) catch return;
                    const tmp = std.fs.path.join(a, &.{ st.root, "state", "crontab.tmp" }) catch return;
                    std.fs.cwd().writeFile(.{ .sub_path = tmp, .data = text }) catch return;
                    defer std.fs.cwd().deleteFile(tmp) catch {};
                    _ = runTool(a, &.{ "crontab", tmp });
                }
            }
        },
    }
}

fn scheduleStatus(a: std.mem.Allocator, st: *const store.Store) []const u8 {
    switch (builtin.os.tag) {
        .macos => {
            const plist = launchdPlistPath(a, st) catch return "unknown";
            if (!platform.pathExists(plist)) return "no (run `abv0 autoupdate on`)";
            const target = std.fmt.allocPrint(a, "gui/{d}/{s}", .{ currentUid(), auto.job_label }) catch return "unknown";
            return if ((runTool(a, &.{ "launchctl", "print", target }) orelse 1) == 0) "yes (launchd)" else "set up but not loaded (run `abv0 autoupdate on`)";
        },
        .windows => return if ((runTool(a, &.{ "schtasks", "/Query", "/TN", auto.job_name }) orelse 1) == 0) "yes (Task Scheduler)" else "no (run `abv0 autoupdate on`)",
        else => {
            if (hasUserSystemd(a) and (runTool(a, &.{ "systemctl", "--user", "is-enabled", "--quiet", auto.job_name ++ ".timer" }) orelse 1) == 0) return "yes (systemd user timer)";
            if (toolOutput(a, &.{ "crontab", "-l" })) |c| {
                if (std.mem.indexOf(u8, c, auto.cron_marker) != null) return "yes (cron)";
            }
            return "no (run `abv0 autoupdate on`)";
        },
    }
}

fn cmdUninstall(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: *const registry.Registry,
    rest: []const []const u8,
    platform_name: []const u8,
) !u8 {
    if (rest.len == 0) {
        term.err("usage: abv0 uninstall <pkg>\n", .{});
        return 2;
    }
    var failed: u8 = 0;
    for (rest) |name| {
        // A package installed from GitHub is not in the registry; its store
        // directory says where it came from.
        const gh_plats = [_]registry.PlatformInfo{.{ .name = platform_name }};
        const pkg = store.Store.resolveRequest(reg, name) orelse blk: {
            if (findGithubInstall(a, st, name, platform_name)) |e| {
                break :blk registry.Package{ .name = e.name, .version = e.version, .platforms = &gh_plats };
            }
            term.err("{s}error{s}: '{}' not found in registry\n", .{ term.red, term.reset, safe(name) });
            hintPackage(a, reg, name);
            failed = 1;
            continue;
        };
        if (output.dry_run) {
            if (st.isInstalled(pkg, platform_name)) {
                term.print("would remove {}\n", .{safe(pkg.name)});
            } else {
                term.print("{} is not installed; nothing to remove\n", .{safe(pkg.name)});
            }
            continue;
        }
        if (try st.uninstall(a, pkg)) {
            say("removed {}\n", .{safe(pkg.name)});
        } else {
            say("{} was not installed\n", .{safe(pkg.name)});
        }
        auto.forget(a, st.root, &.{pkg.name}) catch {};
    }
    if (output.dry_run) {
        term.print("\ndry run: nothing was changed\n", .{});
        return failed;
    }
    _ = try removeUnusedDeps(a, st, reg, platform_name);
    return failed;
}

fn cmdOutdated(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: *const registry.Registry,
    platform_name: []const u8,
    json: bool,
) !u8 {
    const list = try st.getOutdated(a, reg, platform_name);
    defer a.free(list);
    // One API call per package installed from GitHub.
    const gh_list = try st.getOutdatedGithub(a, platform_name);
    defer a.free(gh_list);

    if (json) {
        const w = term.writer();
        try w.writeAll("[");
        for (list, 0..) |e, i| {
            if (i > 0) try w.writeAll(",");
            try writeOutdatedJson(w, e.pkg.name, e.installed, e.pkg.version, cmds_extra.isPinned(st, a, e.pkg.name));
        }
        for (gh_list, 0..) |g, i| {
            if (i > 0 or list.len > 0) try w.writeAll(",");
            try writeOutdatedJson(w, g.entry.name, g.entry.tag, g.latest_tag, cmds_extra.isPinned(st, a, g.entry.name));
        }
        try w.writeAll("]\n");
        return 0;
    }

    if (list.len == 0 and gh_list.len == 0) {
        term.print("everything is up to date\n", .{});
        return 0;
    }
    var pinned: usize = 0;
    for (list) |e| {
        term.print("{s}{}{s}  {} {s}->{s} {s}{}{s}", .{
            term.bold,         safe(e.pkg.name),    term.reset,
            safe(e.installed), term.dim,            term.reset,
            term.green,        safe(e.pkg.version), term.reset,
        });
        if (cmds_extra.isPinned(st, a, e.pkg.name)) {
            pinned += 1;
            term.print(" {s}(pinned){s}", .{ term.yellow, term.reset });
        }
        term.print("\n", .{});
    }
    for (gh_list) |g| {
        term.print("{s}{}{s}  {} {s}->{s} {s}{}{s} {s}(gh:{}/{}){s}", .{
            term.bold,         safe(g.entry.name),  term.reset,
            safe(g.entry.tag), term.dim,            term.reset,
            term.green,        safe(g.latest_tag),  term.reset,
            term.dim,          safe(g.entry.owner), safe(g.entry.repo),
            term.reset,
        });
        if (cmds_extra.isPinned(st, a, g.entry.name)) {
            pinned += 1;
            term.print(" {s}(pinned){s}", .{ term.yellow, term.reset });
        }
        term.print("\n", .{});
    }
    term.print("\n{d} outdated", .{list.len + gh_list.len});
    if (pinned > 0) term.print(" ({d} pinned: `abv0 upgrade` skips them)", .{pinned});
    term.print("; run `abv0 upgrade`\n", .{});
    return 0;
}

fn cmdUpgrade(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: *const registry.Registry,
    rest: []const []const u8,
    all: bool,
    platform_name: []const u8,
    opts: store.InstallOptions,
    jobs: ?usize,
) !u8 {
    if (all and rest.len > 0) {
        term.err("usage: abv0 upgrade [--all | <pkg>...]  (--all takes no package names)\n", .{});
        return 2;
    }
    var targets = std.ArrayList(registry.Package).init(a);
    defer targets.deinit();
    // Packages installed from GitHub: re-resolved against the project's releases.
    const GhTarget = struct { spec: []const u8, name: []const u8, from: []const u8 };
    var gh_targets = std.ArrayList(GhTarget).init(a);
    defer gh_targets.deinit();

    if (rest.len == 0) {
        const list = try st.getOutdated(a, reg, platform_name);
        defer a.free(list);
        for (list) |e| {
            // `upgrade` with no names respects pins; naming a package overrides it.
            if (cmds_extra.isPinned(st, a, e.pkg.name)) {
                say("  {s}pinned{s}   {} stays at {}\n", .{ term.dim, term.reset, safe(e.pkg.name), safe(e.installed) });
                continue;
            }
            try targets.append(e.pkg);
        }
        const gh_list = try st.getOutdatedGithub(a, platform_name);
        defer a.free(gh_list);
        for (gh_list) |g| {
            if (cmds_extra.isPinned(st, a, g.entry.name)) {
                say("  {s}pinned{s}   {} stays at {}\n", .{ term.dim, term.reset, safe(g.entry.name), safe(g.entry.tag) });
                continue;
            }
            try gh_targets.append(.{
                .spec = try std.fmt.allocPrint(a, "gh:{s}/{s}@{s}", .{ g.entry.owner, g.entry.repo, g.latest_tag }),
                .name = g.entry.name,
                .from = g.entry.tag,
            });
        }
    } else {
        var unknown: usize = 0;
        for (rest) |name| {
            if (store.Store.resolveRequest(reg, name)) |p| {
                try targets.append(p);
            } else if (findGithubInstall(a, st, name, platform_name)) |e| {
                // Latest release of the project it was installed from, unless
                // the command line pins a tag.
                const spec = if (ghverify.looksLikeSpec(name)) name else try std.fmt.allocPrint(a, "gh:{s}/{s}", .{ e.owner, e.repo });
                try gh_targets.append(.{ .spec = spec, .name = e.name, .from = e.tag });
            } else if (ghverify.looksLikeSpec(name)) {
                try gh_targets.append(.{ .spec = name, .name = name, .from = "" });
            } else {
                unknown += 1;
                term.err("{s}warning{s}: '{}' not in registry\n", .{ term.yellow, term.reset, safe(name) });
                hintPackage(a, reg, name);
            }
        }
        // Asking only for names that do not exist is a failed request.
        if (unknown == rest.len) return 1;
    }

    if (targets.items.len == 0 and gh_targets.items.len == 0) {
        say("nothing to upgrade\n", .{});
        return 0;
    }

    // Only the requested packages are upgraded, so their dependencies are
    // dropped from the plan. What remains keeps dependency order among itself.
    var roots = std.ArrayList([]const u8).init(a);
    defer roots.deinit();
    var wanted = std.StringHashMap(void).init(a);
    defer wanted.deinit();
    for (targets.items) |pkg| {
        try roots.append(pkg.name);
        try wanted.put(pkg.name, {});
    }

    const plan = try planInstall(a, reg, roots.items);
    defer a.free(plan.names);
    defer a.free(plan.levels);
    var names = std.ArrayList([]const u8).init(a);
    defer names.deinit();
    var levels = std.ArrayList(usize).init(a);
    defer levels.deinit();
    // Dependencies already installed are left alone; one a new version needs
    // and that is missing is installed with it (if it exists for this system).
    var new_deps = std.ArrayList([]const u8).init(a);
    defer new_deps.deinit();
    for (plan.names, plan.levels) |name, lv| {
        if (!wanted.contains(name)) {
            const dep = store.Store.resolveRequest(reg, name) orelse continue;
            if (st.isInstalled(dep, platform_name) or dep.platform(platform_name) == null) continue;
            try new_deps.append(name);
        }
        try names.append(name);
        try levels.append(lv);
    }

    if (output.dry_run) {
        for (gh_targets.items) |t| {
            term.print("  {s}{s:<8}{s} {} {s}->{s} {} {s}(GitHub){s}\n", .{
                term.green, "upgrade", term.reset, safe(t.name), term.dim, term.reset, safe(t.spec), term.dim, term.reset,
            });
        }
        if (names.items.len > 0) {
            try writeDryRunPlan(term.writer(), a, st, reg, names.items, platform_name, "upgrade");
        } else {
            term.print("\ndry run: nothing was changed\n", .{});
        }
        return 0;
    }

    // Install the new version first; each version has its own store
    // directory, so the old one stays usable until the new one is in place.
    // Only a successful install lets the older versions go, so a failed
    // download leaves the package exactly as it was. The version right
    // before the new one stays, so `abv0 rollback` has somewhere to go.
    const ok = try a.alloc(bool, names.items.len);
    defer a.free(ok);
    const failures = try installWaves(a, st, reg, names.items, levels.items, ok, platform_name, opts, jobs);
    {
        var pulled = std.ArrayList([]const u8).init(a);
        defer pulled.deinit();
        for (names.items, ok) |name, done| {
            if (done and auto.contains(new_deps.items, name)) try pulled.append(name);
        }
        auto.noteInstall(a, st.root, &.{}, pulled.items) catch {};
    }

    for (names.items, ok) |name, done| {
        if (!done) continue;
        const pkg = store.Store.resolveRequest(reg, name) orelse continue;
        _ = try cmds_extra.pruneKeepingPrevious(a, st, pkg.name, pkg.version, platform_name);
    }

    var gh_failures: usize = 0;
    for (gh_targets.items) |t| {
        const pkg = st.installDynamic(a, t.spec, platform_name, opts) catch |e| {
            reportInstallError(t.spec, e);
            gh_failures += 1;
            continue;
        };
        _ = try cmds_extra.pruneKeepingPrevious(a, st, pkg.name, pkg.version, platform_name);
    }
    return if (failures + gh_failures == 0) 0 else 1;
}

fn cmdRun(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: *const registry.Registry,
    rest: []const []const u8,
    platform_name: []const u8,
    opts: store.InstallOptions,
) !u8 {
    if (rest.len == 0) {
        term.err("usage: abv0 run <pkg> [-- args...]\n", .{});
        return 2;
    }
    noteUnknownName(a, reg, rest[0]);
    return st.runPackage(a, reg, rest[0], rest[1..], platform_name, opts);
}

fn cmdShell(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: *const registry.Registry,
    rest: []const []const u8,
    platform_name: []const u8,
    opts: store.InstallOptions,
) !u8 {
    if (rest.len == 0) {
        term.err("usage: abv0 shell <pkg>...\n", .{});
        return 2;
    }
    for (rest) |name| noteUnknownName(a, reg, name);
    return st.spawnShell(a, reg, rest, platform_name, opts);
}

fn cmdBundle(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: *const registry.Registry,
    args: *Args,
    platform_name: []const u8,
    opts: store.InstallOptions,
) !u8 {
    const sub = if (args.rest.items.len > 0) args.rest.items[0] else "install";
    const path = args.file orelse "Brewfile";

    if (std.mem.eql(u8, sub, "install")) {
        const requested = try store.Store.bundleInstall(a, reg, path);
        if (requested.len == 0) {
            term.print("no installable entries in {s}\n", .{path});
            return 0;
        }
        const plan = try planInstall(a, reg, requested);
        defer a.free(plan.names);
        defer a.free(plan.levels);

        if (output.dry_run) {
            try writeDryRunPlan(term.writer(), a, st, reg, plan.names, platform_name, "install");
            return 0;
        }

        say("installing {d} packages from {s}\n\n", .{ plan.names.len, path });
        const ok = try a.alloc(bool, plan.names.len);
        defer a.free(ok);
        // A package that fails is reported and the rest still run, as before.
        _ = try installWaves(a, st, reg, plan.names, plan.levels, ok, platform_name, opts, args.jobs);
        return 0;
    }
    if (std.mem.eql(u8, sub, "dump")) {
        if (output.dry_run) {
            term.err("{s}error{s}: --dry-run does not apply to bundle dump\n", .{ term.red, term.reset });
            return 2;
        }
        try st.bundleDump(a, reg, path, args.force, platform_name);
        return 0;
    }
    term.err("usage: abv0 bundle [install|dump] [-f <path>]\n", .{});
    return 2;
}

fn cmdDetect(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: *const registry.Registry,
    rest: []const []const u8,
    platform_name: []const u8,
) !u8 {
    if (rest.len == 0) {
        term.err("usage: abv0 detect <pkg>\n", .{});
        return 2;
    }
    const pkg = store.Store.resolveRequest(reg, rest[0]) orelse {
        term.err("{s}error{s}: '{}' not found\n", .{ term.red, term.reset, safe(rest[0]) });
        hintPackage(a, reg, rest[0]);
        return 1;
    };
    if (!st.isInstalled(pkg, platform_name)) {
        term.err("{s}error{s}: '{s}' is not installed\n", .{ term.red, term.reset, pkg.name });
        return 1;
    }

    const pkg_dir = try st.pkgStorePath(a, pkg, platform_name);
    defer a.free(pkg_dir);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const result = try @import("scan.zig").scanTree(arena.allocator(), pkg_dir);

    term.print("scanned {d} files ({d} KiB) in {s}\n\n", .{ result.files, result.bytes / 1024, pkg_dir });
    printScan(result);
    return if (result.findings.len == 0) 0 else 1;
}

/// The findings of a package scan, one line each.
fn printScan(result: @import("scan.zig").Result) void {
    if (result.findings.len == 0) {
        term.print("{s}clean{s}\n", .{ term.green, term.reset });
        return;
    }
    if (result.blocked) {
        term.print("{s}suspicious{s}  an install would be blocked\n", .{ term.red, term.reset });
    } else {
        term.print("{s}notes{s}  nothing that blocks an install\n", .{ term.yellow, term.reset });
    }
    for (result.findings) |f| {
        const mark = if (f.strong) "!" else "-";
        term.print("  {s} {s} ({}{s})\n", .{ mark, f.reason, safe(f.file), if (f.hidden) ", hidden in base64" else "" });
    }
}

fn cmdUpdate(a: std.mem.Allocator, st: *store.Store, allow_unsigned: bool) !u8 {
    // The original `update` ran:
    //     sh -c "curl -sL https://.../install.sh | sh"
    // i.e. it downloaded and executed an arbitrary remote script every time.
    // `update` now refreshes the registry index and nothing else.
    const paths = try registryPaths(a, st);
    defer a.free(paths[0]);
    defer a.free(paths[1]);

    const tag = std.crypto.random.int(u32);
    const tmp = try std.fmt.allocPrint(a, "{s}.{x}.tmp", .{ paths[0], tag });
    defer a.free(tmp);
    const tmp_sig = try std.fmt.allocPrint(a, "{s}.sig", .{tmp});
    defer a.free(tmp_sig);
    defer std.fs.cwd().deleteFile(tmp) catch {};
    defer std.fs.cwd().deleteFile(tmp_sig) catch {};

    say("fetching {s}\n", .{registryUrl()});
    fetchManifestPair(a, tmp, tmp_sig) catch return 1;

    // Nothing below may touch the working registry until the signature and
    // the replay check both pass.
    const updated_at = vetManifest(a, tmp, tmp_sig, allow_unsigned) catch return 1;
    if (updated_at) |u| checkReplay(a, st, u) catch return 1;

    // Validate before replacing the working registry. This one parse is also
    // the registry the index is built from, so the file is parsed only once.
    var reg = registry.loadFromJsonFile(a, tmp, null) catch |e| {
        term.err("{s}error{s}: downloaded registry is invalid ({s}); keeping the existing one\n", .{ term.red, term.reset, explain(e) });
        return 1;
    };
    defer reg.deinit();
    const n = reg.count();

    try std.fs.cwd().rename(tmp, paths[0]);
    if (updated_at) |u| {
        try storeUpdatedAt(a, st, u);
        const hex = try manifestHex(paths[0]);
        try storeManifestHash(a, st, &hex);
    }

    const stamp = try abvindex.Stamp.ofFile(paths[0]);
    abvindex.build(a, &reg, paths[1], stamp) catch {};

    say("{s}updated{s} {d} packages\n", .{ term.green, term.reset, n });
    return 0;
}

fn cmdReport(a: std.mem.Allocator, args: *Args, platform_name: []const u8) !u8 {
    const subject = if (args.rest.items.len > 0) args.rest.items[0] else "unspecified";

    const title = if (args.report_malware)
        try std.fmt.allocPrint(a, "[security] suspicious behaviour in '{s}'", .{subject})
    else if (args.report_bug)
        try std.fmt.allocPrint(a, "[bug] {s}", .{subject})
    else
        try std.fmt.allocPrint(a, "[report] {s}", .{subject});
    defer a.free(title);

    const body = try std.fmt.allocPrint(a,
        \\### abv0 report
        \\
        \\- abv0 version: {s}
        \\- platform: {s}
        \\- subject: {s}
        \\
        \\#### What happened
        \\
        \\
    , .{ version, platform_name, subject });
    defer a.free(body);

    const enc_title = try net.urlEncode(a, title);
    defer a.free(enc_title);
    const enc_body = try net.urlEncode(a, body);
    defer a.free(enc_body);

    const url = try std.fmt.allocPrint(a, "{s}?title={s}&body={s}", .{ issues_url, enc_title, enc_body });
    defer a.free(url);

    term.print("opening:\n{s}\n", .{url});
    term.flush();
    platform.openBrowser(a, url);
    return 0;
}

fn cmdBenchmark(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: *const registry.Registry,
    platform_name: []const u8,
) !u8 {
    _ = platform_name;
    term.print("{s}abv0 benchmark{s}  ({d} packages)\n\n", .{ term.bold, term.reset, reg.count() });

    var t = try std.time.Timer.start();

    // 1. Registry lookups.
    const lookups: usize = 100_000;
    var hits: usize = 0;
    var i: usize = 0;
    while (i < lookups) : (i += 1) {
        const name = reg.packages[i % reg.packages.len].name;
        if (reg.get(name) != null) hits += 1;
    }
    const lookup_ns = t.lap();

    // 2. Binary index build + mmap load.
    const paths = try registryPaths(a, st);
    defer a.free(paths[0]);
    defer a.free(paths[1]);

    const stamp = abvindex.Stamp.ofFile(paths[0]) catch abvindex.Stamp{ .size = 0, .mtime_ns = 0 };
    try abvindex.build(a, reg, paths[1], stamp);
    const build_ns = t.lap();

    var loaded = try abvindex.load(a, paths[1], stamp);
    loaded.deinit();
    const load_ns = t.lap();

    // 3. Link throughput.
    const scratch = try std.fs.path.join(a, &.{ st.store_root, "bench.tmp" });
    defer a.free(scratch);
    try platform.makeSecureDir(scratch);
    defer std.fs.cwd().deleteTree(scratch) catch {};

    const src = try std.fs.path.join(a, &.{ scratch, "src" });
    defer a.free(src);
    {
        const f = try std.fs.cwd().createFile(src, .{ .mode = platform.mode_exec });
        defer f.close();
        try f.writeAll("benchmark payload\n");
    }

    const links: usize = 500;
    var kind: platform.LinkKind = .copied;
    i = 0;
    _ = t.lap();
    while (i < links) : (i += 1) {
        const dst = try std.fmt.allocPrint(a, "{s}/dst.{d}", .{ scratch, i });
        defer a.free(dst);
        kind = try platform.fastLink(src, dst);
    }
    const link_ns = t.lap();

    // 4. Hashing throughput.
    const blob = try std.fs.path.join(a, &.{ scratch, "blob" });
    defer a.free(blob);
    const blob_size = 8 * 1024 * 1024;
    {
        const f = try std.fs.cwd().createFile(blob, .{});
        defer f.close();
        const chunk = try a.alloc(u8, 64 * 1024);
        defer a.free(chunk);
        @memset(chunk, 0xAB);
        var written: usize = 0;
        while (written < blob_size) : (written += chunk.len) try f.writeAll(chunk);
    }
    _ = t.lap();
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    {
        const f = try std.fs.cwd().openFile(blob, .{});
        defer f.close();
        var buf: [64 * 1024]u8 = undefined;
        while (true) {
            const n = try f.read(&buf);
            if (n == 0) break;
            hasher.update(buf[0..n]);
        }
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    const hash_ns = t.lap();

    term.print("  registry lookup     {d:>10} ops  {d:>8.3} ms  {d:>9.1} ns/op\n", .{ lookups, ms(lookup_ns), @as(f64, @floatFromInt(lookup_ns)) / @as(f64, @floatFromInt(lookups)) });
    term.print("  index build         {d:>10} pkgs {d:>8.3} ms\n", .{ reg.count(), ms(build_ns) });
    term.print("  index mmap load     {d:>10} pkgs {d:>8.3} ms\n", .{ reg.count(), ms(load_ns) });
    term.print("  fastLink ({s:<10}) {d:>8} ops  {d:>8.3} ms  {d:>9.1} us/op\n", .{ kind.label(), links, ms(link_ns), ms(link_ns) * 1000.0 / @as(f64, @floatFromInt(links)) });
    term.print("  sha256              {d:>10} MiB  {d:>8.3} ms  {d:>9.1} MiB/s\n", .{ blob_size / (1024 * 1024), ms(hash_ns), @as(f64, @floatFromInt(blob_size)) / (1024.0 * 1024.0) / (ms(hash_ns) / 1000.0) });

    return 0;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parseArgs handles commands, flags and separators" {
    var a = try parseArgs(testing.allocator, &.{ "install", "jq", "ripgrep", "--platform", "x86_64-linux" });
    defer a.deinit();
    try testing.expectEqualStrings("install", a.command.?);
    try testing.expectEqual(@as(usize, 2), a.rest.items.len);
    try testing.expectEqualStrings("x86_64-linux", a.platform_name.?);
}

test "parseArgs errors on a missing option value instead of silently continuing" {
    try testing.expectError(error.MissingOptionValue, parseArgs(testing.allocator, &.{ "install", "jq", "--platform" }));
    try testing.expectError(error.MissingOptionValue, parseArgs(testing.allocator, &.{ "bundle", "-f" }));
}

test "parseArgs passes --weekly through to autoupdate" {
    var args = try parseArgs(testing.allocator, &.{ "autoupdate", "on", "--weekly" });
    defer args.deinit();
    try testing.expectEqualStrings("autoupdate", args.command.?);
    try testing.expectEqual(@as(usize, 2), args.rest.items.len);
    try testing.expectEqualStrings("--weekly", args.rest.items[1]);
}

test "parseArgs rejects unknown options" {
    try testing.expectError(error.UnknownOption, parseArgs(testing.allocator, &.{ "install", "--definitely-not-a-flag" }));
}

test "parseArgs passes everything after -- through untouched" {
    var a = try parseArgs(testing.allocator, &.{ "run", "jq", "--", "-n", "1+1" });
    defer a.deinit();
    try testing.expectEqualStrings("run", a.command.?);
    try testing.expectEqual(@as(usize, 3), a.rest.items.len);
    try testing.expectEqualStrings("jq", a.rest.items[0]);
    // `-n` must reach jq, not be parsed by abv0.
    try testing.expectEqualStrings("-n", a.rest.items[1]);
}

test "parseArgs recognises help and version early" {
    var h = try parseArgs(testing.allocator, &.{"--help"});
    defer h.deinit();
    try testing.expect(h.want_help);

    var v = try parseArgs(testing.allocator, &.{"-V"});
    defer v.deinit();
    try testing.expect(v.want_version);
}

test "writePackageJson escapes strings" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();

    try writePackageJson(buf.writer(), .{
        .name = "x",
        .version = "1.0",
        .description = "has \"quotes\" and \\ backslash",
        .bin = &.{"x"},
    });

    // Must remain parseable.
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, buf.items, .{});
    defer parsed.deinit();
    try testing.expectEqualStrings("x", parsed.value.object.get("name").?.string);
    try testing.expectEqualStrings("has \"quotes\" and \\ backslash", parsed.value.object.get("description").?.string);
}

test "JSON output escapes quotes, newlines and ESC in every string field" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();

    const nasty = "q\"uote\\ new\nline\x1b[2J";
    try writePackageJson(buf.writer(), .{
        .name = nasty,
        .version = nasty,
        .description = nasty,
        .homepage = nasty,
        .license = nasty,
        .bin = &.{nasty},
        .platforms = &.{.{
            .name = nasty,
            .url = nasty,
            .sha256 = nasty,
            .archive_type = nasty,
            .bin_path = nasty,
        }},
    });

    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, buf.items, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try testing.expectEqualStrings(nasty, obj.get("name").?.string);
    try testing.expectEqualStrings(nasty, obj.get("version").?.string);
    try testing.expectEqualStrings(nasty, obj.get("description").?.string);
    try testing.expectEqualStrings(nasty, obj.get("homepage").?.string);
    try testing.expectEqualStrings(nasty, obj.get("license").?.string);
    try testing.expectEqualStrings(nasty, obj.get("bin").?.array.items[0].string);
    const plat = obj.get("platforms").?.object.get(nasty).?.object;
    try testing.expectEqualStrings(nasty, plat.get("archive_type").?.string);
    try testing.expectEqualStrings(nasty, plat.get("sha256").?.string);
    try testing.expectEqualStrings(nasty, plat.get("bin_path").?.string);
    try testing.expectEqualStrings(nasty, plat.get("url").?.string);
}

test "outdated JSON escapes its fields" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try writeOutdatedJson(buf.writer(), "a\"b", "1\n", "2\x1b", true);

    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, buf.items, .{});
    defer parsed.deinit();
    try testing.expectEqualStrings("a\"b", parsed.value.object.get("name").?.string);
    try testing.expectEqualStrings("1\n", parsed.value.object.get("installed").?.string);
    try testing.expectEqualStrings("2\x1b", parsed.value.object.get("available").?.string);
    try testing.expect(parsed.value.object.get("pinned").?.bool);
}

test "terminal output replaces every control byte with '?'" {
    const out = try std.fmt.allocPrint(testing.allocator, "{}", .{safe("a\x1b[31mb\n\t\x7fc")});
    defer testing.allocator.free(out);
    try testing.expectEqualStrings("a?[31mb???c", out);
    // Printable text, including multi-byte UTF-8, passes through untouched.
    const plain = try std.fmt.allocPrint(testing.allocator, "{}", .{safe("jq 1.7 \xc3\xa9")});
    defer testing.allocator.free(plain);
    try testing.expectEqualStrings("jq 1.7 \xc3\xa9", plain);
}

test "terminal output keeps width padding" {
    const out = try std.fmt.allocPrint(testing.allocator, "[{:<6}]", .{safe("ab\x1b")});
    defer testing.allocator.free(out);
    try testing.expectEqualStrings("[ab?   ]", out);
}

test "replay check refuses older manifests and accepts equal or newer" {
    const old = "2026-06-18T00:00:00Z";
    const new = "2026-06-19T00:00:00Z";
    try testing.expect(isReplay(old, new));
    try testing.expect(!isReplay(new, old));
    try testing.expect(!isReplay(old, old));
    try testing.expect(!isReplay(old, null));
}

test "updated_at must look like an ISO-8601 timestamp" {
    try testing.expect(validUpdatedAt("2026-06-18T00:00:00Z"));
    try testing.expect(validUpdatedAt("2026-06-18T10:20:30.5+02:00"));
    try testing.expect(!validUpdatedAt("2026-06-18\n"));
    try testing.expect(!validUpdatedAt("yesterday"));
    try testing.expect(!validUpdatedAt("2026-06-18T00:00:00Z\x1b[2J"));
}

test "a manifest on disk is trusted only when its hash is the recorded one" {
    const h = "a" ** 64;
    try testing.expectEqual(ManifestTrust.trusted, trustState(h, h, false));
    try testing.expectEqual(ManifestTrust.trusted, trustState(h, h, true));
    // Nothing recorded, signature beside it: verify once, then it gets recorded.
    try testing.expectEqual(ManifestTrust.verify_sig, trustState(null, h, true));
    // Nothing recorded and no signature: fetch it again.
    try testing.expectEqual(ManifestTrust.refetch, trustState(null, h, false));
}

test "a tampered manifest is not trusted even with the old hash recorded" {
    const old = "a" ** 64;
    const tampered = "b" ** 64;
    try testing.expectEqual(ManifestTrust.verify_sig, trustState(old, tampered, true));
    try testing.expectEqual(ManifestTrust.refetch, trustState(old, tampered, false));
}

test "manifestHex is the SHA-256 of the file's bytes" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "m.json", .data = "abc" });
    const p = try tmp.dir.realpathAlloc(testing.allocator, "m.json");
    defer testing.allocator.free(p);
    const hex = try manifestHex(p);
    try testing.expectEqualStrings("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", &hex);
}

test "manifestUpdatedAt reads the top-level field only" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const ok = try manifestUpdatedAt(a, "{\"packages\":{\"x\":{\"updated_at\":\"1999-01-01\"}},\"updated_at\":\"2026-06-18T00:00:00Z\"}");
    try testing.expectEqualStrings("2026-06-18T00:00:00Z", ok);
    try testing.expectError(error.MissingUpdatedAt, manifestUpdatedAt(a, "{\"packages\":{}}"));
    try testing.expectError(error.MissingUpdatedAt, manifestUpdatedAt(a, "[1,2]"));
    try testing.expectError(error.InvalidUpdatedAt, manifestUpdatedAt(a, "{\"updated_at\":\"bad\\nvalue\"}"));
}

test "levelize puts a dependency chain in successive waves and independent packages in the first" {
    // a <- b <- c, and d is independent: waves are [a, d], [b], [c].
    const pkgs = [_]registry.Package{
        .{ .name = "a" },
        .{ .name = "b", .deps = &.{"a"} },
        .{ .name = "c", .deps = &.{"b"} },
        .{ .name = "d" },
    };
    const levels = try levelize(testing.allocator, &pkgs);
    defer testing.allocator.free(levels);
    try testing.expectEqualSlices(usize, &.{ 0, 1, 2, 0 }, levels);
}

test "levelize waits for the deepest of several dependencies" {
    // c needs a and b; d needs c; e needs only a.
    const pkgs = [_]registry.Package{
        .{ .name = "a" },
        .{ .name = "b" },
        .{ .name = "c", .deps = &.{ "a", "b" } },
        .{ .name = "d", .deps = &.{"c"} },
        .{ .name = "e", .deps = &.{"a"} },
    };
    const levels = try levelize(testing.allocator, &pkgs);
    defer testing.allocator.free(levels);
    try testing.expectEqualSlices(usize, &.{ 0, 0, 1, 2, 1 }, levels);
}

test "levelize ignores dependencies outside the list" {
    const pkgs = [_]registry.Package{
        .{ .name = "app", .deps = &.{"not-in-this-plan"} },
    };
    const levels = try levelize(testing.allocator, &pkgs);
    defer testing.allocator.free(levels);
    try testing.expectEqualSlices(usize, &.{0}, levels);
}

test "levelize refuses a list where a dependency comes after its dependent" {
    const pkgs = [_]registry.Package{
        .{ .name = "b", .deps = &.{"a"} },
        .{ .name = "a" },
    };
    try testing.expectError(error.NotDependencyOrdered, levelize(testing.allocator, &pkgs));
}

test "global flags parse, including the short forms" {
    var a = try parseArgs(testing.allocator, &.{ "install", "jq", "-q", "--dry-run", "-v", "--installed" });
    defer a.deinit();
    try testing.expect(a.quiet and a.dry_run and a.verbose and a.installed);
    try testing.expectEqualStrings("install", a.command.?);
}

test "-j with a non-number is an InvalidNumber error that names -j and the value" {
    var diag = ArgDiag{};
    try testing.expectError(error.InvalidNumber, parseArgsDiag(testing.allocator, &.{ "install", "jq", "-j", "abc" }, &diag));
    try testing.expectEqualStrings("-j", diag.option);
    try testing.expectEqualStrings("abc", diag.value);

    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings(
        "option '-j' requires a number, got 'abc'",
        argErrorMessage(&buf, error.InvalidNumber, diag),
    );
}

test "an unknown option is reported by name" {
    var diag = ArgDiag{};
    try testing.expectError(error.UnknownOption, parseArgsDiag(testing.allocator, &.{ "install", "--foo" }, &diag));
    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings(
        "unknown option '--foo' (see `abv0 help`)",
        argErrorMessage(&buf, error.UnknownOption, diag),
    );
    try testing.expectEqualStrings(
        "option '--platform' requires a value",
        argErrorMessage(&buf, error.MissingOptionValue, .{ .option = "--platform" }),
    );
}

test "editDistance counts an adjacent swap as one edit" {
    try testing.expectEqual(@as(usize, 1), editDistance("ab", "ba"));
    try testing.expectEqual(@as(usize, 3), editDistance("kitten", "sitting"));
    try testing.expectEqual(@as(usize, 0), editDistance("jq", "jq"));
}

test "closest suggests a near name, a transposition or a prefix, and nothing far off" {
    const names = [_][]const u8{ "install", "info", "list", "uninstall" };
    try testing.expectEqualStrings("install", closest("instal", &names).?);
    try testing.expectEqualStrings("install", closest("isntall", &names).?);
    try testing.expectEqualStrings("list", closest("lsit", &names).?);
    try testing.expectEqualStrings("uninstall", closest("uninstal", &names).?);
    try testing.expect(closest("zzzzzz", &names) == null);
    try testing.expect(closest("", &names) == null);

    const pkgs = [_][]const u8{ "jq", "ripgrep" };
    try testing.expectEqualStrings("ripgrep", closest("ripg", &pkgs).?);
    try testing.expect(closest("zzz", &pkgs) == null);
}

test "an unknown command is matched against the command table" {
    try testing.expectEqualStrings("install", closest("instal", &command_names).?);
    try testing.expect(findCommand("instal") == null);
}

test "explain turns common failures into a sentence with a next step" {
    try testing.expect(std.mem.indexOf(u8, explain(error.FileNotFound), "file not found") != null);
    try testing.expect(std.mem.indexOf(u8, explain(store.StoreError.ChecksumMismatch), "checksum mismatch") != null);
    try testing.expectEqualStrings("SomethingOdd", explain(error.SomethingOdd));
}

test "urlHost names the host an artifact comes from" {
    try testing.expectEqualStrings("github.com", urlHost("https://github.com/x/y/releases/a.tar.gz"));
    try testing.expectEqualStrings("h.example:8443", urlHost("https://user@h.example:8443/a"));
    try testing.expectEqualStrings("?", urlHost("not a url"));
}

test "top-level help lists every command" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try renderUsage(buf.writer());
    for (commands) |cmd| {
        const line = try std.fmt.allocPrint(testing.allocator, "\n  {s}", .{cmd.name});
        defer testing.allocator.free(line);
        try testing.expect(std.mem.indexOf(u8, buf.items, line) != null);
    }
}

test "every command has per-command help with usage, options and an example" {
    for (commands) |cmd| {
        var buf = std.ArrayList(u8).init(testing.allocator);
        defer buf.deinit();
        try renderCommandHelp(buf.writer(), cmd);
        try testing.expect(std.mem.indexOf(u8, buf.items, "USAGE") != null);
        try testing.expect(std.mem.indexOf(u8, buf.items, "EXAMPLE") != null);
        try testing.expect(std.mem.indexOf(u8, buf.items, cmd.example) != null);
        try testing.expect(findCommand(cmd.name) != null);
    }
}

/// A Store whose only live field is `store_root`. The read-only helpers the
/// tests call use no other path, so the remaining fields are left undefined.
fn storeAt(store_root: []u8) store.Store {
    var st: store.Store = undefined;
    st.store_root = store_root;
    return st;
}

test "dry run describes an install and touches neither the store nor the registry" {
    output = .{ .dry_run = true };
    defer output = .{};

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // jq is already in the store; fzf is not.
    try tmp.dir.makePath("store/jq@1.0@x86_64-linux");
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    const store_root = try std.fs.path.join(testing.allocator, &.{ root, "store" });
    defer testing.allocator.free(store_root);
    var st = storeAt(store_root);

    var packages = [_]registry.Package{
        .{ .name = "fzf", .version = "0.5", .platforms = &.{.{ .name = "x86_64-linux", .url = "https://releases.example.org/fzf.tar.gz", .archive_type = "tar.gz", .sha256 = "SKIP" }} },
        .{ .name = "jq", .version = "1.0", .platforms = &.{.{ .name = "x86_64-linux", .url = "https://example.com/jq.tar.gz", .archive_type = "tar.gz", .sha256 = "SKIP" }} },
    };
    var reg = registry.Registry{ .allocator = testing.allocator, .packages = &packages };

    const wanted = [_][]const u8{ "fzf", "jq" };
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try writeDryRunPlan(buf.writer(), testing.allocator, &st, &reg, &wanted, "x86_64-linux", "install");

    try testing.expect(std.mem.indexOf(u8, buf.items, "from releases.example.org") != null);
    try testing.expect(std.mem.indexOf(u8, buf.items, "already installed") != null);
    try testing.expect(std.mem.indexOf(u8, buf.items, "dry run: 2 packages, nothing was changed") != null);

    // Nothing was created: fzf is still absent.
    try testing.expectError(error.FileNotFound, tmp.dir.access("store/fzf@0.5@x86_64-linux", .{}));
}

test "list --installed reads the store directory names for one platform, in version order" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("store/jq@1.10@x86_64-linux");
    try tmp.dir.makePath("store/jq@1.9@x86_64-linux");
    try tmp.dir.makePath("store/jq@1.9@aarch64-linux");
    try tmp.dir.makePath("store/jq@1.9@x86_64-linux.tmp");
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    const store_root = try std.fs.path.join(testing.allocator, &.{ root, "store" });
    defer testing.allocator.free(store_root);
    var st = storeAt(store_root);

    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    _ = try writeInstalled(buf.writer(), arena.allocator(), &st, "x86_64-linux", true);
    try testing.expectEqualStrings(
        "[{\"name\":\"jq\",\"version\":\"1.9\"},{\"name\":\"jq\",\"version\":\"1.10\"}]\n",
        buf.items,
    );
}

test "new flags parse: --tree, --online, --open, --install, --all and the migrate sources" {
    var a = try parseArgs(testing.allocator, &.{ "migrate", "--from-brew-list", "-", "--brewfile", "Brewfile", "--install", "--tree", "--online", "--open", "--all" });
    defer a.deinit();
    try testing.expectEqualStrings("migrate", a.command.?);
    try testing.expectEqualStrings("-", a.from_brew_list.?);
    try testing.expectEqualStrings("Brewfile", a.brewfile.?);
    try testing.expect(a.install and a.tree and a.online and a.open and a.all);
    try testing.expectEqual(@as(usize, 0), a.rest.items.len);

    try testing.expectError(error.MissingOptionValue, parseArgs(testing.allocator, &.{ "migrate", "--brewfile" }));
    try testing.expectError(error.MissingOptionValue, parseArgs(testing.allocator, &.{ "migrate", "--from-brew-list" }));
}

test "every new command has a table entry that says what it does" {
    for ([_][]const u8{ "deps", "uses", "leaves", "switch", "rollback", "home", "migrate" }) |name| {
        const cmd = findCommand(name) orelse return error.TestUnexpectedResult;
        try testing.expect(cmd.summary.len > 20);
    }
    // The flags that gate behaviour are documented where they apply.
    const search = findCommand("search").?;
    try testing.expectEqualStrings("--online", search.flags[0].name);
    const upgrade = findCommand("upgrade").?;
    try testing.expectEqualStrings("--all", upgrade.flags[0].name);
    try testing.expect(findCommand("migrate").?.flags.len >= 4);
}

test "search --online JSON lists repo, stars, description and the install spec" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    const repos = [_]cmds_extra.Repo{
        .{ .full_name = "BurntSushi/ripgrep", .stars = 48000, .description = "fast \"grep\"\n" },
        .{ .full_name = "a/b", .stars = 0, .description = "" },
    };
    try writeRepoJson(buf.writer(), &repos);
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, buf.items, .{});
    defer parsed.deinit();
    const items = parsed.value.array.items;
    try testing.expectEqual(@as(usize, 2), items.len);
    try testing.expectEqualStrings("BurntSushi/ripgrep", items[0].object.get("repo").?.string);
    try testing.expectEqual(@as(i64, 48000), items[0].object.get("stars").?.integer);
    try testing.expectEqualStrings("fast \"grep\"\n", items[0].object.get("description").?.string);
    try testing.expectEqualStrings("gh:BurntSushi/ripgrep", items[0].object.get("install").?.string);
}

test "online search text uses the same safe printer as the catalog" {
    // The description reaches the terminal only through `safe`.
    const out = try std.fmt.allocPrint(testing.allocator, "{}", .{safe("evil \x1b]0;pwned\x07 repo")});
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOfScalar(u8, out, 0x1b) == null);
    try testing.expect(std.mem.indexOfScalar(u8, out, 0x07) == null);
}

test "migrate JSON lists what matched, how, and what did not" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    const pkg = registry.Package{ .name = "ripgrep", .version = "14" };
    const matched = [_]cmds_extra.Match{.{ .wanted = "rg", .pkg = pkg, .via = .bin }};
    const unmatched = [_][]const u8{ "wget", "we\"ird" };
    try writeMigrateJson(buf.writer(), &matched, &unmatched);
    try buf.appendSlice("}");
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, buf.items, .{});
    defer parsed.deinit();
    const m = parsed.value.object.get("matched").?.array.items[0].object;
    try testing.expectEqualStrings("rg", m.get("name").?.string);
    try testing.expectEqualStrings("ripgrep", m.get("package").?.string);
    try testing.expectEqualStrings("bin", m.get("via").?.string);
    const u = parsed.value.object.get("unmatched").?.array.items;
    try testing.expectEqual(@as(usize, 2), u.len);
    try testing.expectEqualStrings("we\"ird", u[1].string);
}

test "switch JSON names the package and both versions, null when the old one is unknown" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try writeSwitchJson(buf.writer(), "jq", "1.7.1", "1.6");
    try writeSwitchJson(buf.writer(), "jq", null, "1.6");
    var lines = std.mem.splitScalar(u8, std.mem.trimRight(u8, buf.items, "\n"), '\n');
    const first = try std.json.parseFromSlice(std.json.Value, testing.allocator, lines.next().?, .{});
    defer first.deinit();
    try testing.expectEqualStrings("1.7.1", first.value.object.get("from").?.string);
    try testing.expectEqualStrings("1.6", first.value.object.get("to").?.string);
    const second = try std.json.parseFromSlice(std.json.Value, testing.allocator, lines.next().?, .{});
    defer second.deinit();
    try testing.expect(second.value.object.get("from").? == .null);
}

test "info JSON appends installed versions, size, bins and source after the package fields" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    const w = buf.writer();
    const pkg = registry.Package{ .name = "jq", .version = "1.7.1", .bin = &.{"jq"} };
    var rows = [_]cmds_extra.VersionRow{
        .{ .version = "1.6", .dir_name = "jq@1.6@x", .bytes = 100 },
        .{ .version = "1.7.1", .dir_name = "jq@1.7.1@x", .active = true, .bytes = 250 },
    };
    const data = cmds_extra.InfoData{ .rows = &rows, .bins = &.{"jq"}, .total_bytes = 350 };
    try w.writeAll("{");
    try writePackageJsonFields(w, pkg);
    try writeInstalledInfoJson(w, data, "catalog");
    try w.writeAll("}");

    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, buf.items, .{});
    defer parsed.deinit();
    const o = parsed.value.object;
    try testing.expectEqualStrings("jq", o.get("name").?.string);
    try testing.expectEqualStrings("catalog", o.get("source").?.string);
    try testing.expectEqual(@as(i64, 350), o.get("size_bytes").?.integer);
    try testing.expect(o.get("installed").?.array.items[1].object.get("active").?.bool);
    try testing.expectEqualStrings("jq", o.get("linked_bins").?.array.items[0].string);
    try testing.expect(o.get("download_size").? == .null);
}

test "migrate and the other new commands accept --dry-run only where it means something" {
    try testing.expect(supportsDryRun("migrate"));
    try testing.expect(!supportsDryRun("switch"));
    try testing.expect(!supportsDryRun("deps"));
}

comptime {
    // Ensure every module's tests are discovered by `zig build test`.
    _ = @import("safepath.zig");
    _ = @import("term.zig");
    _ = @import("platform.zig");
    _ = @import("bloom.zig");
    _ = @import("wal.zig");
    _ = @import("archive.zig");
    _ = @import("sevenzip.zig");
    _ = @import("registry.zig");
    _ = @import("abvindex.zig");
    _ = @import("scan.zig");
    _ = @import("tui.zig");
    _ = @import("winapp.zig");
    _ = @import("auto.zig");
    _ = @import("net.zig");
    _ = @import("store.zig");
    _ = @import("cmds_extra.zig");
    _ = @import("stream.zig");
    _ = @import("http.zig");
    _ = @import("ghrelease.zig");
    _ = @import("ghverify.zig");
    _ = @import("bindetect.zig");
    _ = @import("shim.zig");
}
