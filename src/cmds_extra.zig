//! Extra commands: pin, unpin, pinned, cleanup, completions, which, self-update.
//!
//! Every command shares one signature so main.zig can dispatch them the same way:
//!
//!     pub fn cmdX(a: std.mem.Allocator, st: *store.Store, reg: ?*const registry.Registry, args: []const []const u8) !u8
//!
//!   * `a`    scratch allocator. Commands allocate through a local arena, so any
//!            allocator works; an arena is still the cheapest choice.
//!   * `st`   the store (paths and bin ownership).
//!   * `reg`  the loaded registry, or null when it is not available. Only `pin`
//!            uses it (to refuse unknown names); pass null to skip that check.
//!   * `args` the words after the command name, without the command itself.
//!
//! Return value is the process exit code: 0 success, 1 runtime failure,
//! 2 usage error (wrong arguments).
//!
//! Also exported for main.zig: `isPinned(st, a, name) bool`, so upgrade and
//! outdated can skip pinned packages.

const std = @import("std");
const builtin = @import("builtin");

const registry = @import("registry.zig");
const store = @import("store.zig");
const platform = @import("platform.zig");
const safepath = @import("safepath.zig");
const term = @import("term.zig");
const net = @import("net.zig");
const sign = @import("sign.zig");
const shim = @import("shim.zig");

const testing = std.testing;

const release_base_url = "https://raw.githubusercontent.com/gugu8intel-i9/abv0/main/release";
const sums_max_bytes = 64 * 1024;
const sig_max_bytes = 1024;
const day_ns: i128 = 24 * std.time.ns_per_hour;

// ---------------------------------------------------------------------------
// Pins
// ---------------------------------------------------------------------------

fn pinsPath(a: std.mem.Allocator, st: *const store.Store) ![]u8 {
    return std.fs.path.join(a, &.{ st.root, "state", "pins" });
}

/// Pinned names in file order. Strings are allocated from `a`.
fn readPins(a: std.mem.Allocator, st: *const store.Store) ![][]const u8 {
    var out = std.ArrayList([]const u8).init(a);
    errdefer out.deinit();

    const path = try pinsPath(a, st);
    const data = std.fs.cwd().readFileAlloc(a, path, 1024 * 1024) catch |e| switch (e) {
        error.FileNotFound => return out.toOwnedSlice(),
        else => return e,
    };

    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        try out.append(try a.dupe(u8, line));
    }
    return out.toOwnedSlice();
}

fn containsName(names: []const []const u8, name: []const u8) bool {
    for (names) |n| {
        if (std.mem.eql(u8, n, name)) return true;
    }
    return false;
}

/// Replace the pin file atomically: write a temp file next to it, then rename.
fn writePins(a: std.mem.Allocator, st: *const store.Store, names: []const []const u8) !void {
    const state_dir = try std.fs.path.join(a, &.{ st.root, "state" });
    try platform.makeSecureDir(state_dir);

    const path = try pinsPath(a, st);
    const tmp = try std.fmt.allocPrint(a, "{s}.{x}.tmp", .{ path, std.crypto.random.int(u64) });

    writePinsFile(tmp, names) catch |e| {
        std.fs.cwd().deleteFile(tmp) catch {};
        return e;
    };
    std.fs.cwd().rename(tmp, path) catch |e| {
        std.fs.cwd().deleteFile(tmp) catch {};
        return e;
    };
}

fn writePinsFile(path: []const u8, names: []const []const u8) !void {
    const file = try std.fs.cwd().createFile(path, .{ .mode = platform.mode_private });
    defer file.close();
    for (names) |n| {
        try file.writeAll(n);
        try file.writeAll("\n");
    }
    try file.sync();
}

/// True when `name` is pinned. Any read failure counts as not pinned.
pub fn isPinned(st: *const store.Store, a: std.mem.Allocator, name: []const u8) bool {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const names = readPins(arena.allocator(), st) catch return false;
    return containsName(names, name);
}

pub fn cmdPin(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: ?*const registry.Registry,
    args: []const []const u8,
) !u8 {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const aa = arena.allocator();

    if (args.len != 1) {
        term.err("usage: abv0 pin <package>\n", .{});
        return 2;
    }
    const name = args[0];
    if (!safepath.isValidId(name)) {
        term.err("{s}error{s}: '{s}' is not a valid package name\n", .{ term.red, term.reset, name });
        return 2;
    }
    if (reg) |r| {
        if (r.get(name) == null) {
            term.err("{s}error{s}: unknown package '{s}'\n", .{ term.red, term.reset, name });
            return 1;
        }
    }

    const current = try readPins(aa, st);
    if (containsName(current, name)) {
        term.print("{s} is already pinned\n", .{name});
        return 0;
    }
    var next = std.ArrayList([]const u8).init(aa);
    try next.appendSlice(current);
    try next.append(name);
    writePins(aa, st, next.items) catch |e| {
        term.err("{s}error{s}: cannot write pins ({s})\n", .{ term.red, term.reset, @errorName(e) });
        return 1;
    };
    term.print("pinned {s}\n", .{name});
    return 0;
}

pub fn cmdUnpin(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: ?*const registry.Registry,
    args: []const []const u8,
) !u8 {
    _ = reg;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const aa = arena.allocator();

    if (args.len != 1) {
        term.err("usage: abv0 unpin <package>\n", .{});
        return 2;
    }
    const name = args[0];
    const current = try readPins(aa, st);
    if (!containsName(current, name)) {
        term.err("{s}error{s}: '{s}' is not pinned\n", .{ term.red, term.reset, name });
        return 1;
    }

    var next = std.ArrayList([]const u8).init(aa);
    for (current) |n| {
        if (!std.mem.eql(u8, n, name)) try next.append(n);
    }
    writePins(aa, st, next.items) catch |e| {
        term.err("{s}error{s}: cannot write pins ({s})\n", .{ term.red, term.reset, @errorName(e) });
        return 1;
    };
    term.print("unpinned {s}\n", .{name});
    return 0;
}

pub fn cmdPinned(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: ?*const registry.Registry,
    args: []const []const u8,
) !u8 {
    _ = reg;
    if (args.len != 0) {
        term.err("usage: abv0 pinned\n", .{});
        return 2;
    }
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();

    const names = try readPins(arena.allocator(), st);
    if (names.len == 0) {
        term.print("no pinned packages\n", .{});
        return 0;
    }
    for (names) |n| term.print("{s}\n", .{n});
    return 0;
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

const Victim = struct {
    label: []const u8,
    path: []const u8,
    bytes: u64,
};

const StoreDir = struct {
    dir_name: []const u8,
    name: []const u8,
    platform: []const u8,
    version: []const u8,
};

/// Total size of the regular files under `path` (or the file itself).
fn treeSize(a: std.mem.Allocator, path: []const u8) u64 {
    var dir = std.fs.cwd().openDir(path, .{ .iterate = true }) catch {
        const info = std.fs.cwd().statFile(path) catch return 0;
        return info.size;
    };
    defer dir.close();

    var walker = dir.walk(a) catch return 0;
    defer walker.deinit();

    var total: u64 = 0;
    while (walker.next() catch null) |entry| {
        if (entry.kind != .file) continue;
        const info = entry.dir.statFile(entry.basename) catch continue;
        total += info.size;
    }
    return total;
}

/// True when `path` has not been modified for longer than `ns`.
fn olderThan(path: []const u8, ns: i128) bool {
    const info = std.fs.cwd().statFile(path) catch return false;
    return std.time.nanoTimestamp() - info.mtime > ns;
}

/// Absolute targets of every symlink in the bin directory. A store directory
/// that a bin link still points at is kept, or the link would dangle.
fn linkTargets(a: std.mem.Allocator, st: *const store.Store) ![][]const u8 {
    // On Windows bins are launcher shims; their .shim files name the targets.
    if (platform.is_windows) return st.binShimTargets(a);
    var out = std.ArrayList([]const u8).init(a);

    var dir = std.fs.cwd().openDir(st.bin_root, .{ .iterate = true }) catch return out.toOwnedSlice();
    defer dir.close();

    var buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    var it = dir.iterate();
    while (try it.next()) |entry| {
        const target = dir.readLink(entry.name, &buf) catch continue;
        if (std.fs.path.isAbsolute(target)) {
            try out.append(try a.dupe(u8, target));
        } else {
            try out.append(try std.fs.path.join(a, &.{ st.bin_root, target }));
        }
    }
    return out.toOwnedSlice();
}

fn isLinkedInto(dir_path: []const u8, targets: []const []const u8) bool {
    for (targets) |t| {
        if (!std.mem.startsWith(u8, t, dir_path)) continue;
        if (t.len == dir_path.len or t[dir_path.len] == std.fs.path.sep) return true;
    }
    return false;
}

/// Old versions: for each package and platform, every store directory whose
/// version is not the newest one installed.
fn collectOldVersions(a: std.mem.Allocator, st: *const store.Store, plan: *std.ArrayList(Victim)) !void {
    var dir = std.fs.cwd().openDir(st.store_root, .{ .iterate = true }) catch return;
    defer dir.close();

    var dirs = std.ArrayList(StoreDir).init(a);
    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .directory) continue;
        const parsed = store.Store.parseStoreDirName(entry.name) orelse continue;
        try dirs.append(.{
            .dir_name = try a.dupe(u8, entry.name),
            .name = try a.dupe(u8, parsed.name),
            .platform = try a.dupe(u8, parsed.platform),
            .version = try a.dupe(u8, parsed.version),
        });
    }
    if (dirs.items.len == 0) return;

    const targets = try linkTargets(a, st);

    for (dirs.items) |d| {
        var newer_exists = false;
        for (dirs.items) |other| {
            if (!std.mem.eql(u8, other.name, d.name) or !std.mem.eql(u8, other.platform, d.platform)) continue;
            if (registry.compareVersions(other.version, d.version) == .gt) {
                newer_exists = true;
                break;
            }
        }
        if (!newer_exists) continue;

        const path = try std.fs.path.join(a, &.{ st.store_root, d.dir_name });
        if (isLinkedInto(path, targets)) {
            term.print("kept {s} {s}: a bin link still points at it\n", .{ d.name, d.version });
            continue;
        }
        try plan.append(.{
            .label = try std.fmt.allocPrint(a, "old version {s} {s}", .{ d.name, d.version }),
            .path = path,
            .bytes = treeSize(a, path),
        });
    }
}

/// `*.tmp` entries in the store that have not been touched for 24 hours.
fn collectStaleTmp(a: std.mem.Allocator, st: *const store.Store, plan: *std.ArrayList(Victim)) !void {
    var dir = std.fs.cwd().openDir(st.store_root, .{ .iterate = true }) catch return;
    defer dir.close();

    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (!std.mem.endsWith(u8, entry.name, ".tmp")) continue;
        const path = try std.fs.path.join(a, &.{ st.store_root, entry.name });
        if (!olderThan(path, day_ns)) continue;
        try plan.append(.{
            .label = try std.fmt.allocPrint(a, "stale temp {s}", .{entry.name}),
            .path = path,
            .bytes = treeSize(a, path),
        });
    }
}

fn formatBytes(buf: []u8, n: u64) []const u8 {
    const units = [_][]const u8{ "B", "KiB", "MiB", "GiB", "TiB" };
    if (n < 1024) return std.fmt.bufPrint(buf, "{d} B", .{n}) catch "?";
    var v: f64 = @floatFromInt(n);
    var u: usize = 0;
    while (v >= 1024 and u < units.len - 1) : (u += 1) v /= 1024;
    return std.fmt.bufPrint(buf, "{d:.1} {s}", .{ v, units[u] }) catch "?";
}

pub fn cmdCleanup(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: ?*const registry.Registry,
    args: []const []const u8,
) !u8 {
    _ = reg;
    var dry_run = false;
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--dry-run")) {
            dry_run = true;
        } else {
            term.err("usage: abv0 cleanup [--dry-run]\n", .{});
            return 2;
        }
    }

    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const aa = arena.allocator();

    var plan = std.ArrayList(Victim).init(aa);
    try collectOldVersions(aa, st, &plan);
    try collectStaleTmp(aa, st, &plan);

    const cache_path = try std.fs.path.join(aa, &.{ st.root, "cache" });
    if (platform.pathExists(cache_path)) {
        try plan.append(.{ .label = "download cache", .path = cache_path, .bytes = treeSize(aa, cache_path) });
    }

    if (plan.items.len == 0) {
        term.print("nothing to clean\n", .{});
        return 0;
    }

    var failed = false;
    var reclaimed: u64 = 0;
    var total: u64 = 0;
    var size_buf: [32]u8 = undefined;
    for (plan.items) |v| {
        total += v.bytes;
        const size = formatBytes(&size_buf, v.bytes);
        if (dry_run) {
            term.print("would remove {s}: {s} ({s})\n", .{ v.label, v.path, size });
            continue;
        }
        std.fs.cwd().deleteTree(v.path) catch |e| {
            term.err("{s}error{s}: cannot remove {s}: {s}\n", .{ term.red, term.reset, v.path, @errorName(e) });
            failed = true;
            continue;
        };
        reclaimed += v.bytes;
        term.print("removed {s}: {s} ({s})\n", .{ v.label, v.path, size });
    }

    if (dry_run) {
        term.print("would reclaim {s}\n", .{formatBytes(&size_buf, total)});
    } else {
        term.print("reclaimed {s}\n", .{formatBytes(&size_buf, reclaimed)});
    }
    return if (failed) 1 else 0;
}

// ---------------------------------------------------------------------------
// Shell completions
// ---------------------------------------------------------------------------

const commands_list = "help version list search info install uninstall outdated upgrade run shell bundle doctor fix detect reset sync update gc report benchmark pin unpin pinned cleanup completions which self-update";

/// Commands whose argument is a package name.
const name_commands_space = "info install uninstall upgrade run shell pin unpin";

/// The same list with `|` separators, for shell case patterns.
const name_commands_pipe = "info|install|uninstall|upgrade|run|shell|pin|unpin";

/// Package names come from `abv0 list`. Name lines are the only lines that
/// start at column 0 and have exactly two fields (name and version). The
/// description lines are indented, and the summary is "N packages".
const bash_script =
    \\# abv0 bash completion. Load with: source <(abv0 completions bash)
    \\_abv0_pkgs() {
    \\  abv0 list 2>/dev/null | awk 'NF == 2 && $2 != "packages" && !/^[[:space:]]/ { print $1 }'
    \\}
    \\_abv0() {
    \\  local cur prev
    \\  cur="${COMP_WORDS[COMP_CWORD]}"
    \\  prev="${COMP_WORDS[COMP_CWORD-1]}"
    \\  if [ "$COMP_CWORD" -eq 1 ]; then
    \\    COMPREPLY=( $(compgen -W "
++ commands_list ++
    \\" -- "$cur") )
    \\    return 0
    \\  fi
    \\  case "$prev" in
    \\
++ name_commands_pipe ++
    \\)
    \\      COMPREPLY=( $(compgen -W "$(_abv0_pkgs)" -- "$cur") ) ;;
    \\    completions)
    \\      COMPREPLY=( $(compgen -W "bash zsh fish pwsh" -- "$cur") ) ;;
    \\    *)
    \\      COMPREPLY=( $(compgen -f -- "$cur") ) ;;
    \\  esac
    \\}
    \\complete -F _abv0 abv0
    \\
;

const zsh_script =
    \\# abv0 zsh completion. Load with: source <(abv0 completions zsh) after compinit
    \\_abv0_pkgs() {
    \\  local -a pkgs
    \\  pkgs=( ${(f)"$(abv0 list 2>/dev/null | awk 'NF == 2 && $2 != "packages" && !/^[[:space:]]/ { print $1 }')"} )
    \\  compadd -- $pkgs
    \\}
    \\_abv0() {
    \\  local -a cmds
    \\  if (( CURRENT == 2 )); then
    \\    cmds=(
++ commands_list ++
    \\ )
    \\    compadd -- $cmds
    \\    return
    \\  fi
    \\  case $words[2] in
    \\
++ name_commands_pipe ++
    \\)
    \\      _abv0_pkgs ;;
    \\    completions)
    \\      compadd -- bash zsh fish pwsh ;;
    \\    *)
    \\      _files ;;
    \\  esac
    \\}
    \\(( $+functions[compdef] )) && compdef _abv0 abv0
    \\
;

const fish_script =
    \\# abv0 fish completion. Load with: abv0 completions fish | source
    \\function __abv0_pkgs
    \\    abv0 list 2>/dev/null | awk 'NF == 2 && $2 != "packages" && !/^[[:space:]]/ { print $1 }'
    \\end
    \\complete -c abv0 -f
    \\complete -c abv0 -n __fish_use_subcommand -a "
++ commands_list ++
    \\"
    \\complete -c abv0 -n "__fish_seen_subcommand_from
++ name_commands_space ++
    \\" -a "(__abv0_pkgs)"
    \\complete -c abv0 -n "__fish_seen_subcommand_from completions" -a "bash zsh fish pwsh"
    \\
;

const pwsh_script =
    \\# abv0 PowerShell completion. Load with: abv0 completions pwsh | Out-String | Invoke-Expression
    \\Register-ArgumentCompleter -Native -CommandName abv0 -ScriptBlock {
    \\    param($wordToComplete, $commandAst, $cursorPosition)
    \\    $elements = @($commandAst.CommandElements)
    \\    $pos = if ($wordToComplete -eq '') { $elements.Count } else { $elements.Count - 1 }
    \\    $cands = @()
    \\    if ($pos -le 1) {
    \\        $cands = '
++ commands_list ++
    \\'.Split(' ')
    \\    } elseif ($pos -ge 2) {
    \\        $sub = $elements[1].ToString()
    \\        if ($sub -in '
++ name_commands_space ++
    \\'.Split(' ')) {
    \\            $cands = @(abv0 list 2>$null | Where-Object { $_ -match '^\S+\s+\S+$' -and $_ -notmatch '^\d+ packages$' } | ForEach-Object { ($_ -split '\s+')[0] })
    \\        } elseif ($sub -eq 'completions') {
    \\            $cands = @('bash', 'zsh', 'fish', 'pwsh')
    \\        }
    \\    }
    \\    $cands | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
    \\        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    \\    }
    \\}
    \\
;

/// The completion script for `shell`, or null for an unknown shell.
pub fn completionScript(shell: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, shell, "bash")) return bash_script;
    if (std.mem.eql(u8, shell, "zsh")) return zsh_script;
    if (std.mem.eql(u8, shell, "fish")) return fish_script;
    if (std.mem.eql(u8, shell, "pwsh")) return pwsh_script;
    return null;
}

pub fn cmdCompletions(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: ?*const registry.Registry,
    args: []const []const u8,
) !u8 {
    _ = a;
    _ = st;
    _ = reg;
    if (args.len != 1) {
        term.err("usage: abv0 completions <bash|zsh|fish|pwsh>\n", .{});
        return 2;
    }
    const script = completionScript(args[0]) orelse {
        term.err("{s}error{s}: unknown shell '{s}' (bash, zsh, fish, pwsh)\n", .{ term.red, term.reset, args[0] });
        return 2;
    };
    term.writeAll(script);
    return 0;
}

// ---------------------------------------------------------------------------
// which
// ---------------------------------------------------------------------------

pub fn cmdWhich(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: ?*const registry.Registry,
    args: []const []const u8,
) !u8 {
    _ = reg;
    if (args.len != 1) {
        term.err("usage: abv0 which <bin>\n", .{});
        return 2;
    }
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const aa = arena.allocator();

    const bin = args[0];
    const owner = try st.binOwnerOf(aa, bin) orelse {
        term.err("{s}error{s}: '{s}' is not managed by abv0\n", .{ term.red, term.reset, bin });
        return 1;
    };

    const file_name = try std.fmt.allocPrint(aa, "{s}{s}", .{ bin, platform.exe_suffix });
    const link_path = try std.fs.path.join(aa, &.{ st.bin_root, file_name });

    term.print("{s}link{s}     {s}\n", .{ term.dim, term.reset, link_path });

    // A launcher shim (Windows): `<bin>.shim` names the real executable.
    const shim_path = try std.fmt.allocPrint(aa, "{s}{c}{s}{s}", .{ st.bin_root, std.fs.path.sep, bin, shim.shim_suffix });
    if (shim.readShimFile(aa, shim_path)) |s| {
        term.print("{s}store{s}    {s}\n", .{ term.dim, term.reset, s.path });
        if (!platform.pathExists(s.path)) {
            term.print("{s}warning{s}  the shim target is missing; run `abv0 fix`\n", .{ term.yellow, term.reset });
        }
        term.print("{s}package{s}  {s}\n", .{ term.dim, term.reset, owner });
        return 0;
    } else |_| {}

    var buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    if (std.fs.cwd().readLink(link_path, &buf)) |target| {
        const abs = if (std.fs.path.isAbsolute(target))
            try aa.dupe(u8, target)
        else
            try std.fs.path.join(aa, &.{ st.bin_root, target });
        term.print("{s}store{s}    {s}\n", .{ term.dim, term.reset, abs });
        if (!platform.pathExists(abs)) {
            term.print("{s}warning{s}  the store path is missing; run `abv0 fix`\n", .{ term.yellow, term.reset });
        }
    } else |_| {
        term.print("{s}store{s}    (not a symlink: copy or hard link)\n", .{ term.dim, term.reset });
    }
    term.print("{s}package{s}  {s}\n", .{ term.dim, term.reset, owner });
    return 0;
}

// ---------------------------------------------------------------------------
// self-update
// ---------------------------------------------------------------------------

/// Release asset name for a target, as listed in release/SHA256SUMS and built
/// by the build.zig release step. Null when no release is published for it.
pub fn assetName(os: std.Target.Os.Tag, arch: std.Target.Cpu.Arch) ?[]const u8 {
    return switch (os) {
        .linux => switch (arch) {
            .x86_64 => "abv0-linux-x86_64",
            .aarch64 => "abv0-linux-aarch64",
            else => null,
        },
        .macos => switch (arch) {
            .x86_64 => "abv0-darwin-x86_64",
            .aarch64 => "abv0-darwin-arm64",
            else => null,
        },
        .windows => switch (arch) {
            .x86_64 => "abv0-windows-x86_64.exe",
            .aarch64 => "abv0-windows-aarch64.exe",
            else => null,
        },
        else => null,
    };
}

/// Look up `asset` in SHA256SUMS text. Lines have the `sha256sum` form
/// `<64 hex>  <name>`, and binary mode `<64 hex> *<name>` is accepted too.
/// Returns the hex digits (as written in the file), or null when the asset is
/// not listed or its digest is malformed.
pub fn findChecksum(sums: []const u8, asset: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, sums, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        const sep = std.mem.indexOfAny(u8, line, " \t") orelse continue;
        const hex = line[0..sep];
        const name = std.mem.trimLeft(u8, line[sep..], " \t*");
        if (!std.mem.eql(u8, name, asset)) continue;

        if (hex.len != 64) return null;
        for (hex) |c| {
            if (!std.ascii.isHex(c)) return null;
        }
        return hex;
    }
    return null;
}

/// Lowercase hex SHA-256 of the file at `path`.
fn sha256File(path: []const u8) ![64]u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [64 * 1024]u8 = undefined;
    while (true) {
        const n = try file.read(&buf);
        if (n == 0) break;
        hasher.update(buf[0..n]);
    }
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    hasher.final(&digest);
    return std.fmt.bytesToHex(digest, .lower);
}

pub fn cmdSelfUpdate(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: ?*const registry.Registry,
    args: []const []const u8,
) !u8 {
    _ = st;
    _ = reg;
    var check_only = false;
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--check")) {
            check_only = true;
        } else {
            term.err("usage: abv0 self-update [--check]\n", .{});
            return 2;
        }
    }

    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const aa = arena.allocator();

    const asset = assetName(builtin.os.tag, builtin.cpu.arch) orelse {
        term.err("{s}error{s}: no abv0 release is published for this platform\n", .{ term.red, term.reset });
        return 1;
    };

    // 1. Fetch the checksum list and its signature, then verify the signature
    //    before any digest in the list is trusted.
    const sums_url = release_base_url ++ "/SHA256SUMS";
    const sums = net.fetchToString(aa, sums_url, sums_max_bytes, .{}) catch |e| {
        term.err("{s}error{s}: cannot fetch SHA256SUMS ({s})\n", .{ term.red, term.reset, @errorName(e) });
        return 1;
    };
    const sig = net.fetchToString(aa, sums_url ++ ".sig", sig_max_bytes, .{}) catch |e| {
        term.err("{s}error{s}: cannot fetch SHA256SUMS.sig ({s})\n", .{ term.red, term.reset, @errorName(e) });
        return 1;
    };
    sign.verify(sums, sig) catch |e| {
        term.err("{s}error{s}: SHA256SUMS signature check failed ({s}); not updating\n", .{ term.red, term.reset, @errorName(e) });
        return 1;
    };

    const expected = findChecksum(sums, asset) orelse {
        term.err("{s}error{s}: SHA256SUMS has no valid entry for {s}\n", .{ term.red, term.reset, asset });
        return 1;
    };

    // 2. Compare against the running binary.
    const exe_path = std.fs.selfExePathAlloc(aa) catch |e| {
        term.err("{s}error{s}: cannot locate the running binary ({s})\n", .{ term.red, term.reset, @errorName(e) });
        return 1;
    };
    const current = sha256File(exe_path) catch |e| {
        term.err("{s}error{s}: cannot hash {s} ({s})\n", .{ term.red, term.reset, exe_path, @errorName(e) });
        return 1;
    };
    if (std.ascii.eqlIgnoreCase(&current, expected)) {
        term.print("already up to date\n", .{});
        return 0;
    }
    if (check_only) {
        term.print("update available: {s} (current build differs from the published {s})\n", .{ asset, asset });
        return 0;
    }

    // 3. Download next to the running binary, so the final rename stays on one
    //    filesystem and is atomic.
    const exe_dir = std.fs.path.dirname(exe_path) orelse {
        term.err("{s}error{s}: cannot find the directory of {s}\n", .{ term.red, term.reset, exe_path });
        return 1;
    };
    var rand_buf: [8]u8 = undefined;
    std.crypto.random.bytes(&rand_buf);
    const tmp_name = try std.fmt.allocPrint(aa, "abv0-update-{s}.tmp", .{std.fmt.bytesToHex(rand_buf, .lower)});
    const tmp_path = try std.fs.path.join(aa, &.{ exe_dir, tmp_name });

    const asset_url = try std.fmt.allocPrint(aa, "{s}/{s}", .{ release_base_url, asset });
    term.print("downloading {s}\n", .{asset_url});
    net.download(aa, asset_url, tmp_path, .{}) catch |e| {
        std.fs.cwd().deleteFile(tmp_path) catch {};
        term.err("{s}error{s}: download failed ({s}); the current binary is unchanged\n", .{ term.red, term.reset, @errorName(e) });
        return 1;
    };

    // 4. Verify, make executable, and sanity-check that it runs.
    const got = sha256File(tmp_path) catch |e| {
        std.fs.cwd().deleteFile(tmp_path) catch {};
        term.err("{s}error{s}: cannot hash the download ({s})\n", .{ term.red, term.reset, @errorName(e) });
        return 1;
    };
    if (!std.ascii.eqlIgnoreCase(&got, expected)) {
        std.fs.cwd().deleteFile(tmp_path) catch {};
        term.err("{s}error{s}: download does not match SHA256SUMS; the current binary is unchanged\n", .{ term.red, term.reset });
        return 1;
    }
    platform.chmodPath(tmp_path, platform.mode_bin);

    const sanity = std.process.Child.run(.{
        .allocator = aa,
        .argv = &.{ tmp_path, "--version" },
        .max_output_bytes = 64 * 1024,
    }) catch |e| {
        std.fs.cwd().deleteFile(tmp_path) catch {};
        term.err("{s}error{s}: the new binary does not run ({s}); the current binary is unchanged\n", .{ term.red, term.reset, @errorName(e) });
        return 1;
    };
    if (sanity.term != .Exited or sanity.term.Exited != 0) {
        std.fs.cwd().deleteFile(tmp_path) catch {};
        term.err("{s}error{s}: the new binary failed `--version`; the current binary is unchanged\n", .{ term.red, term.reset });
        return 1;
    }

    // 5. Swap it in. Unix can rename over a running executable. Windows cannot,
    //    so the running one is moved aside first and put back on failure.
    if (platform.is_windows) {
        const old_path = try std.fmt.allocPrint(aa, "{s}.old", .{exe_path});
        std.fs.cwd().deleteFile(old_path) catch {};
        std.fs.cwd().rename(exe_path, old_path) catch |e| {
            std.fs.cwd().deleteFile(tmp_path) catch {};
            term.err("{s}error{s}: cannot move the running binary aside ({s})\n", .{ term.red, term.reset, @errorName(e) });
            return 1;
        };
        std.fs.cwd().rename(tmp_path, exe_path) catch |e| {
            std.fs.cwd().rename(old_path, exe_path) catch {};
            std.fs.cwd().deleteFile(tmp_path) catch {};
            term.err("{s}error{s}: cannot install the new binary ({s}); restored the old one\n", .{ term.red, term.reset, @errorName(e) });
            return 1;
        };
    } else {
        std.fs.cwd().rename(tmp_path, exe_path) catch |e| {
            std.fs.cwd().deleteFile(tmp_path) catch {};
            term.err("{s}error{s}: cannot replace {s} ({s})\n", .{ term.red, term.reset, exe_path, @errorName(e) });
            return 1;
        };
    }

    term.print("{s}updated{s} to {s} (sha256 {s})\n", .{ term.green, term.reset, asset, expected });
    return 0;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn testStore(a: std.mem.Allocator, root: []u8) !store.Store {
    return .{
        .allocator = a,
        .home = root,
        .root = root,
        .store_root = try std.fs.path.join(a, &.{ root, "store" }),
        .bin_root = try std.fs.path.join(a, &.{ root, "bin" }),
        .shells_root = try std.fs.path.join(a, &.{ root, "shells" }),
        .apps_root = try std.fs.path.join(a, &.{ root, "apps" }),
        .registry_root = try std.fs.path.join(a, &.{ root, "registry" }),
        .locks_root = try std.fs.path.join(a, &.{ root, "locks" }),
    };
}

test "every command and helper compiles for this target" {
    // `check` only analyses what main.zig references, so reference everything here.
    std.testing.refAllDeclsRecursive(@This());
}

test "pins add, remove and list round trip" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();
    var st = try testStore(aa, root);

    try testing.expect(!isPinned(&st, aa, "ripgrep"));

    try testing.expectEqual(@as(u8, 0), try cmdPin(aa, &st, null, &.{"ripgrep"}));
    try testing.expectEqual(@as(u8, 0), try cmdPin(aa, &st, null, &.{"jq"}));
    // Pinning twice is harmless and leaves a single line.
    try testing.expectEqual(@as(u8, 0), try cmdPin(aa, &st, null, &.{"ripgrep"}));
    try testing.expect(isPinned(&st, aa, "ripgrep"));
    try testing.expect(isPinned(&st, aa, "jq"));
    try testing.expect(!isPinned(&st, aa, "fd"));

    const listed = try readPins(aa, &st);
    try testing.expectEqual(@as(usize, 2), listed.len);
    try testing.expectEqualStrings("ripgrep", listed[0]);
    try testing.expectEqualStrings("jq", listed[1]);

    try testing.expectEqual(@as(u8, 0), try cmdUnpin(aa, &st, null, &.{"ripgrep"}));
    try testing.expect(!isPinned(&st, aa, "ripgrep"));
    try testing.expect(isPinned(&st, aa, "jq"));
    try testing.expectEqual(@as(u8, 1), try cmdUnpin(aa, &st, null, &.{"ripgrep"}));

    try testing.expectEqual(@as(u8, 0), try cmdUnpin(aa, &st, null, &.{"jq"}));
    try testing.expectEqual(@as(usize, 0), (try readPins(aa, &st)).len);
    try testing.expectEqual(@as(u8, 0), try cmdPinned(aa, &st, null, &.{}));
}

test "pin rejects invalid names and usage errors" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();
    var st = try testStore(aa, root);

    try testing.expectEqual(@as(u8, 2), try cmdPin(aa, &st, null, &.{}));
    try testing.expectEqual(@as(u8, 2), try cmdPin(aa, &st, null, &.{"../evil"}));
    try testing.expectEqual(@as(u8, 2), try cmdUnpin(aa, &st, null, &.{}));
    try testing.expectEqual(@as(u8, 1), try cmdUnpin(aa, &st, null, &.{"never-pinned"}));
}

test "completions output for each shell is non-empty and lists install" {
    for ([_][]const u8{ "bash", "zsh", "fish", "pwsh" }) |shell| {
        const script = completionScript(shell) orelse return error.TestUnexpectedResult;
        try testing.expect(script.len > 0);
        try testing.expect(std.mem.indexOf(u8, script, "install") != null);
        try testing.expect(std.mem.indexOf(u8, script, "self-update") != null);
    }
    try testing.expect(completionScript("tcsh") == null);
}

test "asset name for each of the six release targets" {
    try testing.expectEqualStrings("abv0-linux-x86_64", assetName(.linux, .x86_64).?);
    try testing.expectEqualStrings("abv0-linux-aarch64", assetName(.linux, .aarch64).?);
    try testing.expectEqualStrings("abv0-darwin-x86_64", assetName(.macos, .x86_64).?);
    try testing.expectEqualStrings("abv0-darwin-arm64", assetName(.macos, .aarch64).?);
    try testing.expectEqualStrings("abv0-windows-x86_64.exe", assetName(.windows, .x86_64).?);
    try testing.expectEqualStrings("abv0-windows-aarch64.exe", assetName(.windows, .aarch64).?);
    try testing.expect(assetName(.linux, .riscv64) == null);
    try testing.expect(assetName(.freebsd, .x86_64) == null);
}

test "SHA256SUMS line parser" {
    const h1 = "ab" ** 32;
    const h2 = "cd" ** 32;
    const sums = "ad20fb96f737fc34b61f3be524618853294c153842861604ac6ae7d3fd7a762c  abv0-darwin-arm64\n" ++
        h1 ++ "  abv0-linux-x86_64\r\n" ++
        h2 ++ " *abv0-windows-x86_64.exe\n" ++
        "abcd  abv0-linux-aarch64\n";

    try testing.expectEqualStrings(h1, findChecksum(sums, "abv0-linux-x86_64").?);
    try testing.expectEqualStrings(h2, findChecksum(sums, "abv0-windows-x86_64.exe").?);
    try testing.expectEqualStrings("ad20fb96f737fc34b61f3be524618853294c153842861604ac6ae7d3fd7a762c", findChecksum(sums, "abv0-darwin-arm64").?);
    // A short or non-hex digest is refused, not passed through.
    try testing.expect(findChecksum(sums, "abv0-linux-aarch64") == null);
    // Names are matched exactly, not by prefix.
    try testing.expect(findChecksum(sums, "abv0-linux") == null);
    try testing.expect(findChecksum(sums, "abv0-darwin-x86_64") == null);
}
