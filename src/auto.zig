//! Automatic upkeep: catalog refresh, dependency bookkeeping, daily cleanup and
//! the scheduled `abv0 maintain` job.
//!
//! State lives in `<abv0 home>/state`:
//!   deps-only       packages abv0 installed only because something needed them;
//!                   the only packages auto-removal may ever take
//!   last-<task>     when a once-a-day task last ran (a decimal Unix time)
//!
//! Nothing here removes a package that is not in `deps-only`, so anything the
//! user installed, by any command, stays until they uninstall it.

const std = @import("std");
const builtin = @import("builtin");
const registry = @import("registry.zig");

// ---------------------------------------------------------------------------
// Name lists in the state directory
// ---------------------------------------------------------------------------

fn statePath(a: std.mem.Allocator, root: []const u8, name: []const u8) ![]u8 {
    return std.fs.path.join(a, &.{ root, "state", name });
}

/// Names in `<root>/state/<file>`, one per line. A missing file is empty.
pub fn readNames(a: std.mem.Allocator, root: []const u8, file: []const u8) ![][]const u8 {
    var out = std.ArrayList([]const u8).init(a);
    errdefer out.deinit();
    const path = try statePath(a, root, file);
    defer a.free(path);
    const data = std.fs.cwd().readFileAlloc(a, path, 1 << 20) catch |e| switch (e) {
        error.FileNotFound => return out.toOwnedSlice(),
        else => return e,
    };
    defer a.free(data);
    var it = std.mem.splitScalar(u8, data, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or contains(out.items, line)) continue;
        try out.append(try a.dupe(u8, line));
    }
    return out.toOwnedSlice();
}

/// Replace `<root>/state/<file>` with `names`, through a temporary file.
pub fn writeNames(a: std.mem.Allocator, root: []const u8, file: []const u8, names: []const []const u8) !void {
    const dir = try std.fs.path.join(a, &.{ root, "state" });
    defer a.free(dir);
    try std.fs.cwd().makePath(dir);
    const path = try statePath(a, root, file);
    defer a.free(path);
    const tmp = try std.fmt.allocPrint(a, "{s}.{x}.tmp", .{ path, std.crypto.random.int(u64) });
    defer a.free(tmp);
    {
        const f = try std.fs.cwd().createFile(tmp, .{});
        defer f.close();
        var bw = std.io.bufferedWriter(f.writer());
        for (names) |n| {
            try bw.writer().writeAll(n);
            try bw.writer().writeByte('\n');
        }
        try bw.flush();
    }
    std.fs.cwd().rename(tmp, path) catch |e| {
        std.fs.cwd().deleteFile(tmp) catch {};
        return e;
    };
}

fn sameNames(x: []const []const u8, y: []const []const u8) bool {
    if (x.len != y.len) return false;
    for (x, y) |p, q| {
        if (!std.mem.eql(u8, p, q)) return false;
    }
    return true;
}

pub fn contains(names: []const []const u8, name: []const u8) bool {
    for (names) |n| {
        if (std.mem.eql(u8, n, name)) return true;
    }
    return false;
}

pub const deps_only_file = "deps-only";

/// Record an install: `requested` (what the user named) are theirs from now on
/// and leave the dependency list; `pulled_in` (installed only because something
/// needed them, and not installed before) join it.
pub fn noteInstall(a: std.mem.Allocator, root: []const u8, requested: []const []const u8, pulled_in: []const []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const aa = arena.allocator();
    const cur = try readNames(aa, root, deps_only_file);
    var next = std.ArrayList([]const u8).init(aa);
    for (cur) |n| {
        if (!contains(requested, n)) try next.append(n);
    }
    for (pulled_in) |n| {
        if (!contains(requested, n) and !contains(next.items, n)) try next.append(n);
    }
    if (sameNames(cur, next.items)) return;
    try writeNames(aa, root, deps_only_file, next.items);
}

/// Drop `names` from the dependency list (they were uninstalled).
pub fn forget(a: std.mem.Allocator, root: []const u8, names: []const []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const aa = arena.allocator();
    const cur = try readNames(aa, root, deps_only_file);
    var next = std.ArrayList([]const u8).init(aa);
    for (cur) |n| {
        if (!contains(names, n)) try next.append(n);
    }
    if (next.items.len != cur.len) try writeNames(aa, root, deps_only_file, next.items);
}

/// Packages that can go: on the dependency list, still installed, and not
/// needed (directly or through other dependencies) by any installed package
/// that is not itself going. Owned by `a`.
pub fn orphans(
    a: std.mem.Allocator,
    reg: *const registry.Registry,
    installed: []const []const u8,
    deps_only: []const []const u8,
) ![][]const u8 {
    // Everything reachable from a package the user keeps is needed.
    var needed = std.StringHashMap(void).init(a);
    defer needed.deinit();
    var stack = std.ArrayList([]const u8).init(a);
    defer stack.deinit();
    for (installed) |n| {
        if (!contains(deps_only, n)) try stack.append(n);
    }
    while (stack.popOrNull()) |n| {
        if ((try needed.fetchPut(n, {})) != null) continue;
        const pkg = reg.get(n) orelse continue;
        for (pkg.deps) |d| try stack.append(d);
    }
    var out = std.ArrayList([]const u8).init(a);
    for (deps_only) |n| {
        if (contains(installed, n) and !needed.contains(n)) try out.append(n);
    }
    return out.toOwnedSlice();
}

// ---------------------------------------------------------------------------
// Settings from the environment
// ---------------------------------------------------------------------------

fn envValue(buf: []u8, name: []const u8) ?[]const u8 {
    var fba = std.heap.FixedBufferAllocator.init(buf);
    const v = std.process.getEnvVarOwned(fba.allocator(), name) catch return null;
    return std.mem.trim(u8, v, " \t\r\n");
}

fn isOff(v: []const u8) bool {
    for ([_][]const u8{ "0", "false", "no", "off" }) |o| {
        if (std.ascii.eqlIgnoreCase(v, o)) return true;
    }
    return false;
}

/// True unless `name` is set to 0/false/no/off.
pub fn enabled(name: []const u8) bool {
    var buf: [64]u8 = undefined;
    const v = envValue(&buf, name) orelse return true;
    return v.len == 0 or !isOff(v);
}

/// How old (in seconds) the catalog may get before a command refreshes it:
/// `ABV0_UPDATE_HOURS` (default 24), or null when auto-refresh is off
/// (`ABV0_AUTO_UPDATE=0` or `ABV0_UPDATE_HOURS=0`).
pub fn refreshAfterSeconds() ?i64 {
    if (!enabled("ABV0_AUTO_UPDATE")) return null;
    var buf: [64]u8 = undefined;
    const v = envValue(&buf, "ABV0_UPDATE_HOURS") orelse return 24 * 3600;
    const hours = std.fmt.parseFloat(f64, v) catch return 24 * 3600;
    if (!(hours > 0)) return null;
    return @intFromFloat(@min(hours, 24 * 365) * 3600);
}

/// Seconds since `path` was last written, or null when it cannot be read.
pub fn ageSeconds(path: []const u8) ?i64 {
    const st = std.fs.cwd().statFile(path) catch return null;
    const now = std.time.nanoTimestamp();
    return @intCast(@divTrunc(@max(now - st.mtime, 0), std.time.ns_per_s));
}

/// True when the once-a-day task `task` has not run in the last 24 hours.
pub fn dueDaily(a: std.mem.Allocator, root: []const u8, task: []const u8) bool {
    const name = std.fmt.allocPrint(a, "last-{s}", .{task}) catch return false;
    defer a.free(name);
    const path = statePath(a, root, name) catch return false;
    defer a.free(path);
    const age = ageSeconds(path) orelse return true;
    return age >= 24 * 3600;
}

/// Mark the once-a-day task `task` as done now.
pub fn markDone(a: std.mem.Allocator, root: []const u8, task: []const u8) void {
    const name = std.fmt.allocPrint(a, "last-{s}", .{task}) catch return;
    defer a.free(name);
    const dir = std.fs.path.join(a, &.{ root, "state" }) catch return;
    defer a.free(dir);
    std.fs.cwd().makePath(dir) catch return;
    const path = statePath(a, root, name) catch return;
    defer a.free(path);
    var buf: [32]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, "{d}\n", .{std.time.timestamp()}) catch return;
    std.fs.cwd().writeFile(.{ .sub_path = path, .data = text }) catch {};
}

// ---------------------------------------------------------------------------
// The scheduled job
// ---------------------------------------------------------------------------

pub const Interval = enum { daily, weekly };

pub const job_label = "dev.abv0.maintain";
pub const job_name = "abv0-maintain";

/// Environment the job must see to find the same abv0 home.
pub const JobEnv = struct {
    home: ?[]const u8 = null,
    bin_dir: ?[]const u8 = null,
};

fn xmlEscape(w: anytype, s: []const u8) !void {
    for (s) |c| switch (c) {
        '&' => try w.writeAll("&amp;"),
        '<' => try w.writeAll("&lt;"),
        '>' => try w.writeAll("&gt;"),
        '"' => try w.writeAll("&quot;"),
        else => try w.writeByte(c),
    };
}

/// The launchd agent (macOS) that runs `exe maintain --quiet` at 03:17, every
/// day or on Sundays, logging to `log`.
pub fn launchdPlist(a: std.mem.Allocator, exe: []const u8, log: []const u8, interval: Interval, env: JobEnv) ![]u8 {
    var out = std.ArrayList(u8).init(a);
    const w = out.writer();
    try w.writeAll(
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        \\<plist version="1.0">
        \\<dict>
        \\  <key>Label</key><string>
    );
    try w.writeAll(job_label);
    try w.writeAll("</string>\n  <key>ProgramArguments</key>\n  <array>\n    <string>");
    try xmlEscape(w, exe);
    try w.writeAll("</string>\n    <string>maintain</string>\n    <string>--quiet</string>\n  </array>\n");
    try w.writeAll("  <key>StartCalendarInterval</key>\n  <dict>\n");
    if (interval == .weekly) try w.writeAll("    <key>Weekday</key><integer>0</integer>\n");
    try w.writeAll("    <key>Hour</key><integer>3</integer>\n    <key>Minute</key><integer>17</integer>\n  </dict>\n");
    if (env.home != null or env.bin_dir != null) {
        try w.writeAll("  <key>EnvironmentVariables</key>\n  <dict>\n");
        if (env.home) |h| {
            try w.writeAll("    <key>ABV0_HOME</key><string>");
            try xmlEscape(w, h);
            try w.writeAll("</string>\n");
        }
        if (env.bin_dir) |b| {
            try w.writeAll("    <key>ABV0_BIN_DIR</key><string>");
            try xmlEscape(w, b);
            try w.writeAll("</string>\n");
        }
        try w.writeAll("  </dict>\n");
    }
    for ([_][]const u8{ "StandardOutPath", "StandardErrorPath" }) |k| {
        try w.print("  <key>{s}</key><string>", .{k});
        try xmlEscape(w, log);
        try w.writeAll("</string>\n");
    }
    try w.writeAll("  <key>ProcessType</key><string>Background</string>\n</dict>\n</plist>\n");
    return out.toOwnedSlice();
}

/// systemd quoting for one word of ExecStart/Environment: always quoted, with
/// backslash, quote, and the specifier `%` escaped.
fn systemdQuote(w: anytype, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |c| switch (c) {
        '"', '\\' => {
            try w.writeByte('\\');
            try w.writeByte(c);
        },
        '%' => try w.writeAll("%%"),
        else => try w.writeByte(c),
    };
    try w.writeByte('"');
}

/// The systemd user service and timer (Linux).
pub fn systemdUnits(a: std.mem.Allocator, exe: []const u8, interval: Interval, env: JobEnv) !struct { service: []u8, timer: []u8 } {
    var svc = std.ArrayList(u8).init(a);
    errdefer svc.deinit();
    const w = svc.writer();
    try w.writeAll("[Unit]\nDescription=abv0: refresh the catalog, upgrade packages and clean up\n\n[Service]\nType=oneshot\n");
    if (env.home) |h| {
        try w.writeAll("Environment=");
        try systemdQuote(w, try std.fmt.allocPrint(a, "ABV0_HOME={s}", .{h}));
        try w.writeByte('\n');
    }
    if (env.bin_dir) |b| {
        try w.writeAll("Environment=");
        try systemdQuote(w, try std.fmt.allocPrint(a, "ABV0_BIN_DIR={s}", .{b}));
        try w.writeByte('\n');
    }
    try w.writeAll("ExecStart=");
    try systemdQuote(w, exe);
    try w.writeAll(" maintain --quiet\nNice=10\n");

    const timer = try std.fmt.allocPrint(a,
        \\[Unit]
        \\Description=Run abv0 maintain {s}
        \\
        \\[Timer]
        \\OnCalendar={s}
        \\RandomizedDelaySec=1h
        \\Persistent=true
        \\
        \\[Install]
        \\WantedBy=timers.target
        \\
    , .{ @tagName(interval), if (interval == .daily) "*-*-* 03:17:00" else "Sun *-*-* 03:17:00" });
    return .{ .service = try svc.toOwnedSlice(), .timer = timer };
}

/// Single-quote for a POSIX shell.
fn shQuote(w: anytype, s: []const u8) !void {
    try w.writeByte('\'');
    for (s) |c| {
        if (c == '\'') try w.writeAll("'\\''") else try w.writeByte(c);
    }
    try w.writeByte('\'');
}

pub const cron_marker = "# abv0-maintain";

/// The crontab line (Linux without systemd): `exe maintain --quiet >> log`.
pub fn cronLine(a: std.mem.Allocator, exe: []const u8, log: []const u8, interval: Interval, env: JobEnv) ![]u8 {
    var out = std.ArrayList(u8).init(a);
    const w = out.writer();
    try w.writeAll(if (interval == .daily) "17 3 * * * " else "17 3 * * 0 ");
    if (env.home) |h| {
        try w.writeAll("ABV0_HOME=");
        try shQuote(w, h);
        try w.writeByte(' ');
    }
    if (env.bin_dir) |b| {
        try w.writeAll("ABV0_BIN_DIR=");
        try shQuote(w, b);
        try w.writeByte(' ');
    }
    try shQuote(w, exe);
    try w.writeAll(" maintain --quiet >> ");
    try shQuote(w, log);
    try w.writeAll(" 2>&1 " ++ cron_marker);
    return out.toOwnedSlice();
}

/// `crontab` text with abv0's line replaced (or removed when `line` is null).
pub fn editCrontab(a: std.mem.Allocator, current: []const u8, line: ?[]const u8) ![]u8 {
    var out = std.ArrayList(u8).init(a);
    var it = std.mem.splitScalar(u8, current, '\n');
    while (it.next()) |l| {
        if (l.len == 0 or std.mem.endsWith(u8, std.mem.trimRight(u8, l, " \r"), cron_marker)) continue;
        try out.appendSlice(l);
        try out.append('\n');
    }
    if (line) |l| {
        try out.appendSlice(l);
        try out.append('\n');
    }
    return out.toOwnedSlice();
}

/// The command line Task Scheduler runs (Windows), as one /TR string. With a
/// custom home, `cmd /c set …&&` carries it, since a task has no environment
/// option.
pub fn schtasksCommand(a: std.mem.Allocator, exe: []const u8, log: []const u8, env: JobEnv) ![]u8 {
    var out = std.ArrayList(u8).init(a);
    const w = out.writer();
    try w.writeAll("cmd /c ");
    if (env.home) |h| try w.print("set \"ABV0_HOME={s}\"&& ", .{h});
    if (env.bin_dir) |b| try w.print("set \"ABV0_BIN_DIR={s}\"&& ", .{b});
    try w.print("\"{s}\" maintain --quiet >> \"{s}\" 2>&1", .{ exe, log });
    return out.toOwnedSlice();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "noteInstall and forget keep only what was pulled in as a dependency" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try noteInstall(testing.allocator, root, &.{"yt-dlp"}, &.{"ffmpeg"});
    try testing.expectEqualSlices(u8, "ffmpeg", (try readNames(a, root, deps_only_file))[0]);
    // Asking for ffmpeg by name makes it the user's.
    try noteInstall(testing.allocator, root, &.{"ffmpeg"}, &.{});
    try testing.expectEqual(@as(usize, 0), (try readNames(a, root, deps_only_file)).len);
    try noteInstall(testing.allocator, root, &.{"a"}, &.{ "b", "c" });
    try forget(testing.allocator, root, &.{"b"});
    const left = try readNames(a, root, deps_only_file);
    try testing.expectEqual(@as(usize, 1), left.len);
    try testing.expectEqualStrings("c", left[0]);
}

test "orphans are unneeded dependencies only" {
    const pkgs = [_]registry.Package{
        // Sorted by name, as a loaded registry is.
        .{ .name = "app", .version = "1", .deps = &.{"lib"} },
        .{ .name = "base", .version = "1" },
        .{ .name = "lib", .version = "1", .deps = &.{"base"} },
        .{ .name = "mine", .version = "1" },
        .{ .name = "old", .version = "1" },
    };
    var reg = registry.Registry{ .allocator = testing.allocator, .packages = @constCast(&pkgs) };
    const a = testing.allocator;

    // app keeps lib and base; old is an unneeded dependency; mine is the user's.
    const o1 = try orphans(a, &reg, &.{ "app", "lib", "base", "old", "mine" }, &.{ "lib", "base", "old" });
    defer a.free(o1);
    try testing.expectEqual(@as(usize, 1), o1.len);
    try testing.expectEqualStrings("old", o1[0]);

    // With app gone, its whole chain goes; mine never does.
    const o2 = try orphans(a, &reg, &.{ "lib", "base", "mine" }, &.{ "lib", "base" });
    defer a.free(o2);
    try testing.expectEqual(@as(usize, 2), o2.len);
}

test "job definitions carry the command, schedule and home" {
    const a = testing.allocator;
    const env = JobEnv{ .home = "/Users/me/my abv0", .bin_dir = null };

    const plist = try launchdPlist(a, "/Users/me/.abv0/bin/abv0", "/Users/me/.abv0/logs/maintain.log", .weekly, env);
    defer a.free(plist);
    try testing.expect(std.mem.indexOf(u8, plist, "<string>maintain</string>") != null);
    try testing.expect(std.mem.indexOf(u8, plist, "<key>Weekday</key><integer>0</integer>") != null);
    try testing.expect(std.mem.indexOf(u8, plist, "<string>/Users/me/my abv0</string>") != null);

    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const units = try systemdUnits(arena.allocator(), "/home/me/.abv0/bin/abv0", .daily, .{ .home = "/home/me/100% \"x\"" });
    try testing.expect(std.mem.indexOf(u8, units.service, "ExecStart=\"/home/me/.abv0/bin/abv0\" maintain --quiet") != null);
    try testing.expect(std.mem.indexOf(u8, units.service, "100%% \\\"x\\\"") != null);
    try testing.expect(std.mem.indexOf(u8, units.timer, "OnCalendar=*-*-* 03:17:00") != null);

    const line = try cronLine(a, "/opt/it's/abv0", "/tmp/m.log", .daily, .{});
    defer a.free(line);
    try testing.expectEqualStrings("17 3 * * * '/opt/it'\\''s/abv0' maintain --quiet >> '/tmp/m.log' 2>&1 # abv0-maintain", line);
    const edited = try editCrontab(a, "0 1 * * * backup\n17 3 * * * old # abv0-maintain\n", line);
    defer a.free(edited);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, edited, cron_marker));
    try testing.expect(std.mem.startsWith(u8, edited, "0 1 * * * backup\n"));
    const removed = try editCrontab(a, edited, null);
    defer a.free(removed);
    try testing.expectEqualStrings("0 1 * * * backup\n", removed);

    const tr = try schtasksCommand(a, "C:\\Users\\me\\.abv0\\bin\\abv0.exe", "C:\\Users\\me\\.abv0\\logs\\maintain.log", .{ .home = "D:\\abv0" });
    defer a.free(tr);
    try testing.expectEqualStrings("cmd /c set \"ABV0_HOME=D:\\abv0\"&& \"C:\\Users\\me\\.abv0\\bin\\abv0.exe\" maintain --quiet >> \"C:\\Users\\me\\.abv0\\logs\\maintain.log\" 2>&1", tr);
}

test "refresh interval follows the environment default" {
    // The test environment does not set these, so the default applies.
    try testing.expectEqual(@as(?i64, 24 * 3600), refreshAfterSeconds());
    try testing.expect(enabled("ABV0_SURELY_UNSET_FLAG"));
}
