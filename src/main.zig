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
const archive = @import("archive.zig");
const bloom = @import("bloom.zig");
const wal = @import("wal.zig");
const sign = @import("sign.zig");
const cmds_extra = @import("cmds_extra.zig");

pub const version = "2.0.0";

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
const unsigned_flag = Flag{ .name = "--allow-unsigned-manifest", .help = "Skip signature and replay checks (UNSAFE)" };
const force_flag = Flag{ .name = "--force", .help = "Overwrite files and replace conflicting bin links" };
const installed_flag = Flag{ .name = "--installed", .help = "Show what is installed, not the registry" };
const bug_flag = Flag{ .name = "--bug", .help = "Report a bug (default)" };
const malware_flag = Flag{ .name = "--malware", .help = "Report a suspicious package" };

const commands = [_]Command{
    .{
        .name = "install",
        .args = "<pkg>...",
        .summary = "Install packages and their dependencies, verified, in parallel.",
        .flags = &.{
            dry_run_flag,                                                                      json_flag,  jobs_flag,  platform_flag,
            unverified_flag,                                                                   force_flag, quiet_flag, verbose_flag,
            .{ .name = "--micro-split", .help = "Parallel ranged download for large assets" },
        },
        .example = "abv0 install jq ripgrep",
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
        .summary = "Upgrade the named packages, or every outdated one when none are named.",
        .flags = &.{ dry_run_flag, jobs_flag, platform_flag, quiet_flag, verbose_flag },
        .example = "abv0 upgrade ripgrep",
    },
    .{
        .name = "outdated",
        .summary = "List installed packages that have a newer version in the registry.",
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
        .name = "search",
        .args = "<query>",
        .summary = "Find registry packages whose name or description contains <query>.",
        .flags = &.{json_flag},
        .example = "abv0 search json --json",
    },
    .{
        .name = "info",
        .args = "<pkg>",
        .summary = "Show a package's versions, platforms, URLs and checksums.",
        .flags = &.{json_flag},
        .example = "abv0 info jq",
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
        .summary = "Scan an installed package's executable for malware-like patterns (exit 1 if suspicious).",
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
        .summary = "Remove old versions and stale temporary files, keeping the newest install.",
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
        \\  uninstall <pkg>...      Remove packages and the links they created
        \\  upgrade [pkg]...        Upgrade outdated packages
        \\  outdated                List packages with a newer version available
        \\  list [--installed]      List registry packages, or what is installed
        \\  search <query>          Search the registry
        \\  info <pkg>              Show package metadata
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
        \\  cleanup                 Remove old versions, keeping the newest
        \\  completions <shell>     Print a bash, zsh, fish or pwsh completion script
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
        \\  --micro-split           Parallel ranged download for large assets
        \\  --no-stream             Download fully before unpacking (disable streaming install)
        \\  --force                 Overwrite output files and replace conflicting bin links
        \\  --dry-run               Show what install, upgrade, uninstall, bundle or cleanup would do; change nothing
        \\  --json                  Machine-readable output (list, search, info, outdated, install, doctor)
        \\  --installed             With list: show what is installed
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
    const root = std.json.parseFromSliceLeaky(std.json.Value, a, bytes, .{}) catch return error.MissingUpdatedAt;
    const obj = switch (root) {
        .object => |o| o,
        else => return error.MissingUpdatedAt,
    };
    const v = obj.get("updated_at") orelse return error.MissingUpdatedAt;
    const s = switch (v) {
        .string => |str| str,
        else => return error.MissingUpdatedAt,
    };
    if (!validUpdatedAt(s)) return error.InvalidUpdatedAt;
    return s;
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
/// registry or its replay state, and it skips the binary index cache so it
/// cannot be confused with the installed one.
fn loadExplicitRegistry(base: std.mem.Allocator, path: []const u8, allow_unsigned: bool) !registry.Registry {
    var scratch = std.heap.ArenaAllocator.init(base);
    defer scratch.deinit();
    const a = scratch.allocator();

    const sig_path = try std.fmt.allocPrint(a, "{s}.sig", .{path});

    _ = vetManifest(a, path, sig_path, allow_unsigned) catch |e| {
        term.err("{s}error{s}: registry '{s}' was not loaded: {s}\n", .{ term.red, term.reset, path, explain(e) });
        return e;
    };
    // The loaded registry outlives the scratch arena, so it uses `base`.
    return registry.loadFromJsonFile(base, path, null) catch |e| {
        term.err("{s}error{s}: could not load registry '{s}': {s}\n", .{ term.red, term.reset, path, explain(e) });
        return e;
    };
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

/// Terminal-safe view of manifest text. Manifest strings come from a remote
/// index and may carry escape sequences that move the cursor, rewrite earlier
/// lines or retitle the window. Every control byte (0x00-0x1f, which includes
/// ESC and tab/newline, and 0x7f) prints as '?'. Use with `{}`. Pads on the
/// right when a width is given, like `{s:<16}`.
const Safe = struct {
    text: []const u8,

    pub fn format(
        self: Safe,
        comptime fmt_str: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt_str;
        for (self.text) |c| try writer.writeByte(if (c < 0x20 or c == 0x7f) '?' else c);
        if (options.width) |w| {
            if (w > self.text.len) try writer.writeByteNTimes(' ', w - self.text.len);
        }
    }
};

fn safe(text: []const u8) Safe {
    return .{ .text = text };
}

/// Every JSON string value goes through the standard encoder, so quotes,
/// backslashes and control bytes can never break out of the document.
fn writeJsonString(w: anytype, s: []const u8) !void {
    try std.json.encodeJsonString(s, .{}, w);
}

fn writePackageJson(w: anytype, pkg: registry.Package) !void {
    try w.writeAll("{\"name\":");
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
    try w.writeAll("}}");
}

fn writeOutdatedJson(w: anytype, name: []const u8, installed: []const u8, available: []const u8) !void {
    try w.writeAll("{\"name\":");
    try writeJsonString(w, name);
    try w.writeAll(",\"installed\":");
    try writeJsonString(w, installed);
    try w.writeAll(",\"available\":");
    try writeJsonString(w, available);
    try w.writeAll("}");
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
    if (suggestPackage(a, reg, name)) |s| {
        term.err("{s}note{s}: '{}' is not in the registry; did you mean '{}'?\n", .{ term.yellow, term.reset, safe(name), safe(s) });
    }
}

fn supportsDryRun(cmd: []const u8) bool {
    const names = [_][]const u8{ "install", "upgrade", "uninstall", "bundle", "cleanup" };
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
            try w.print("  {s}unknown{s}   {} is not in the registry; it would be fetched from GitHub\n", .{ term.yellow, term.reset, safe(name) });
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
    try w.writeAll("]\n");
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
            const dst_name = try std.fmt.allocPrint(a, "{s}{s}", .{ bin_name, platform.exe_suffix });
            defer a.free(dst_name);
            const p = try std.fs.path.join(a, &.{ st.bin_root, dst_name });
            defer a.free(p);
            std.fs.cwd().access(p, .{}) catch {
                if (broken > 0) try w.writeAll(",");
                try w.writeAll("{\"package\":");
                try writeJsonString(w, pkg.name);
                try w.writeAll(",\"bin\":");
                try writeJsonString(w, bin_name);
                try w.writeAll("}");
                broken += 1;
            };
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
    const names = [_][]const u8{ "install", "upgrade", "bundle", "run", "shell" };
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
        term.err("{s}error{s}: --dry-run applies to install, upgrade, uninstall and bundle install\n", .{ term.red, term.reset });
        return 2;
    }

    var opts = store.InstallOptions{
        .micro_split = args.micro_split,
        .no_stream = args.no_stream,
        .allow_unverified = args.allow_unverified,
        .force = args.force,
        .quiet = output.quiet,
    };

    // One streaming session for the whole run, shared by every worker. If it
    // cannot be built, installs download to a file first.
    var session: ?stream.Session = null;
    defer if (session) |*s| s.deinit();
    if (!args.no_stream and installsPackages(cmd)) {
        if (stream.Session.init(base)) |s| {
            session = s;
            opts.session = &session.?;
        } else |_| {}
    }

    var timer = try std.time.Timer.start();

    var st = try store.Store.init(base);
    defer st.deinit();

    // ---- commands that need no registry ----
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

    var reg = if (args.registry_path) |p|
        try loadExplicitRegistry(base, p, args.allow_unsigned_manifest)
    else
        try loadRegistry(base, &st, args.allow_unsigned_manifest);
    defer reg.deinit();

    if (std.mem.eql(u8, cmd, "pin")) return cmds_extra.cmdPin(a, &st, &reg, args.rest.items);
    if (std.mem.eql(u8, cmd, "list")) return cmdList(&reg, args.json);
    if (std.mem.eql(u8, cmd, "search")) return cmdSearch(&reg, args.rest.items, args.json);
    if (std.mem.eql(u8, cmd, "info")) return cmdInfo(a, &reg, args.rest.items, args.json);
    if (std.mem.eql(u8, cmd, "install")) return cmdInstall(a, &st, &reg, &args, platform_name, opts, &timer);
    if (std.mem.eql(u8, cmd, "uninstall")) return cmdUninstall(a, &st, &reg, args.rest.items, platform_name);
    if (std.mem.eql(u8, cmd, "outdated")) return cmdOutdated(a, &st, &reg, platform_name, args.json);
    if (std.mem.eql(u8, cmd, "upgrade")) return cmdUpgrade(a, &st, &reg, args.rest.items, platform_name, opts, args.jobs);
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
        say("repaired {d} packages in {d:.2}ms\n", .{ n, ms(timer.read()) });
        return 0;
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

fn cmdSearch(reg: *const registry.Registry, rest: []const []const u8, json: bool) !u8 {
    if (rest.len == 0) {
        term.err("usage: abv0 search <query>\n", .{});
        return 2;
    }
    const q = rest[0];
    const w = term.writer();
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
        try w.writeAll("]\n");
    } else if (found == 0) {
        // No match is an answer, not a failure.
        term.print("no packages match '{}'\n", .{safe(q)});
    }
    return 0;
}

fn cmdInfo(a: std.mem.Allocator, reg: *const registry.Registry, rest: []const []const u8, json: bool) !u8 {
    if (rest.len == 0) {
        term.err("usage: abv0 info <pkg>\n", .{});
        return 2;
    }
    const pkg = store.Store.resolveRequest(reg, rest[0]) orelse {
        term.err("{s}error{s}: '{}' not found\n", .{ term.red, term.reset, safe(rest[0]) });
        hintPackage(a, reg, rest[0]);
        return 1;
    };
    if (json) {
        const w = term.writer();
        try writePackageJson(w, pkg);
        try w.writeAll("\n");
        return 0;
    }

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
        term.err("usage: abv0 install <pkg>...\n", .{});
        return 2;
    }
    for (args.rest.items) |name| noteUnknownName(a, reg, name);

    // Dependencies come along, and always install before what needs them.
    const plan = try planInstall(a, reg, args.rest.items);
    defer a.free(plan.names);
    defer a.free(plan.levels);

    if (output.dry_run) {
        try writeDryRunPlan(term.writer(), a, st, reg, plan.names, platform_name, "install");
        return 0;
    }

    const ok = try a.alloc(bool, plan.names.len);
    defer a.free(ok);
    const failures = try installWaves(a, st, reg, plan.names, plan.levels, ok, platform_name, opts, args.jobs);

    if (output.json) {
        try writeInstallJson(term.writer(), reg, plan.names, plan.levels, ok);
        return if (failures == 0) 0 else 1;
    }

    const elapsed = ms(timer.read());
    if (failures == 0) {
        say("\n{s}done{s} {d} packages in {d:.2}ms\n", .{ term.green, term.reset, plan.names.len, elapsed });
        return 0;
    }
    term.print("\n{s}{d} of {d} packages failed{s} ({d:.2}ms)\n", .{ term.red, failures, plan.names.len, term.reset, elapsed });
    return 1;
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
        const pkg = store.Store.resolveRequest(reg, name) orelse {
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
    }
    if (output.dry_run) term.print("\ndry run: nothing was changed\n", .{});
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

    if (json) {
        const w = term.writer();
        try w.writeAll("[");
        for (list, 0..) |e, i| {
            if (i > 0) try w.writeAll(",");
            try writeOutdatedJson(w, e.pkg.name, e.installed, e.pkg.version);
        }
        try w.writeAll("]\n");
        return 0;
    }

    if (list.len == 0) {
        term.print("everything is up to date\n", .{});
        return 0;
    }
    for (list) |e| {
        term.print("{s}{}{s}  {} {s}->{s} {s}{}{s}\n", .{
            term.bold,         safe(e.pkg.name),    term.reset,
            safe(e.installed), term.dim,            term.reset,
            term.green,        safe(e.pkg.version), term.reset,
        });
    }
    term.print("\n{d} outdated; run `abv0 upgrade`\n", .{list.len});
    return 0;
}

fn cmdUpgrade(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: *const registry.Registry,
    rest: []const []const u8,
    platform_name: []const u8,
    opts: store.InstallOptions,
    jobs: ?usize,
) !u8 {
    var targets = std.ArrayList(registry.Package).init(a);
    defer targets.deinit();

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
    } else {
        var unknown: usize = 0;
        for (rest) |name| {
            if (store.Store.resolveRequest(reg, name)) |p| {
                try targets.append(p);
            } else {
                unknown += 1;
                term.err("{s}warning{s}: '{}' not in registry\n", .{ term.yellow, term.reset, safe(name) });
                hintPackage(a, reg, name);
            }
        }
        // Asking only for names that do not exist is a failed request.
        if (unknown == rest.len) return 1;
    }

    if (targets.items.len == 0) {
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
    for (plan.names, plan.levels) |name, lv| {
        if (!wanted.contains(name)) continue;
        try names.append(name);
        try levels.append(lv);
    }

    if (output.dry_run) {
        try writeDryRunPlan(term.writer(), a, st, reg, names.items, platform_name, "upgrade");
        return 0;
    }

    // Install the new version first; each version has its own store
    // directory, so the old one stays usable until the new one is in place.
    // Only a successful install lets the older versions go, so a failed
    // download leaves the package exactly as it was.
    const ok = try a.alloc(bool, names.items.len);
    defer a.free(ok);
    const failures = try installWaves(a, st, reg, names.items, levels.items, ok, platform_name, opts, jobs);

    for (names.items, ok) |name, done| {
        if (!done) continue;
        const pkg = store.Store.resolveRequest(reg, name) orelse continue;
        _ = try st.pruneOtherVersions(a, pkg.name, pkg.version, platform_name);
    }
    return if (failures == 0) 0 else 1;
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

    const bin = try st.resolveBinary(a, pkg, platform_name);
    defer a.free(bin);

    var threat = try store.Store.scanFile(a, bin);
    defer threat.deinit();

    term.print("scanned {s}\n\n", .{bin});
    if (threat.score == 0) {
        term.print("{s}clean{s}  threat score 0/100\n", .{ term.green, term.reset });
        return 0;
    }
    term.print("{s}suspicious{s}  threat score {d}/100\n", .{ term.red, term.reset, threat.score });
    for (threat.reasons.items) |r| term.print("  - {s}\n", .{r});
    return 1;
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
    try writeOutdatedJson(buf.writer(), "a\"b", "1\n", "2\x1b");

    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, buf.items, .{});
    defer parsed.deinit();
    try testing.expectEqualStrings("a\"b", parsed.value.object.get("name").?.string);
    try testing.expectEqualStrings("1\n", parsed.value.object.get("installed").?.string);
    try testing.expectEqualStrings("2\x1b", parsed.value.object.get("available").?.string);
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

comptime {
    // Ensure every module's tests are discovered by `zig build test`.
    _ = @import("safepath.zig");
    _ = @import("term.zig");
    _ = @import("platform.zig");
    _ = @import("bloom.zig");
    _ = @import("wal.zig");
    _ = @import("archive.zig");
    _ = @import("registry.zig");
    _ = @import("abvindex.zig");
    _ = @import("net.zig");
    _ = @import("store.zig");
    _ = @import("cmds_extra.zig");
    _ = @import("stream.zig");
    _ = @import("ghrelease.zig");
    _ = @import("shim.zig");
}
