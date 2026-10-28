//! A record of every change to what is installed, so it can be undone.
//!
//! Before a command that can change packages runs, the store is read once
//! (which packages, which version is active, where a GitHub install came
//! from). Afterwards it is read again, and if anything differs the change is
//! appended to `<abv0 home>/history.jsonl`: one JSON object per line with the
//! command and, per package, the version before and after (none = not
//! installed). `abv0 history` lists it; `abv0 undo [id]` reverses one entry.

const std = @import("std");
const store = @import("store.zig");
const cmds_extra = @import("cmds_extra.zig");
const safepath = @import("safepath.zig");
const term = @import("term.zig");

const Allocator = std.mem.Allocator;

pub const file_name = "history.jsonl";
/// Entries kept; older ones are dropped when a new one is written.
pub const max_entries = 200;

/// One installed package and its active version.
pub const Item = struct {
    name: []const u8,
    version: []const u8,
    /// `gh:owner/repo@tag` for a GitHub install, so it can be fetched again.
    gh: ?[]const u8 = null,
};

pub const Change = struct {
    name: []const u8,
    /// Null: the package was not installed before.
    from: ?[]const u8,
    /// Null: the package is not installed after.
    to: ?[]const u8,
    from_gh: ?[]const u8 = null,
    to_gh: ?[]const u8 = null,
};

pub const Entry = struct {
    id: u64,
    time: i64,
    command: []const u8,
    changes: []const Change,
};

/// What is installed for `platform_name`: one row per package, with the
/// version the bin links use. Reads the store only.
pub fn snapshot(a: Allocator, st: *const store.Store, platform_name: []const u8) ![]Item {
    var versions = std.StringArrayHashMap(std.ArrayList([]const u8)).init(a);
    var dir = std.fs.cwd().openDir(st.store_root, .{ .iterate = true }) catch return &.{};
    defer dir.close();
    var it = dir.iterate();
    while (try it.next()) |e| {
        if (e.kind != .directory) continue;
        const parsed = store.Store.parseStoreDirName(e.name) orelse continue;
        if (!std.mem.eql(u8, parsed.platform, platform_name)) continue;
        const gop = try versions.getOrPut(try a.dupe(u8, parsed.name));
        if (!gop.found_existing) gop.value_ptr.* = std.ArrayList([]const u8).init(a);
        try gop.value_ptr.append(try a.dupe(u8, parsed.version));
    }

    var out = std.ArrayList(Item).init(a);
    var vit = versions.iterator();
    while (vit.next()) |kv| {
        const name = kv.key_ptr.*;
        var active: []const u8 = kv.value_ptr.items[0];
        // Several versions: ask which one the links point at.
        if (kv.value_ptr.items.len > 1) {
            const rows = try cmds_extra.listVersions(a, st, name, platform_name);
            if (cmds_extra.activeIndex(rows)) |i| active = rows[i].version else if (rows.len != 0) active = rows[rows.len - 1].version;
        }
        const dir_name = try std.fmt.allocPrint(a, "{s}@{s}@{s}", .{ name, active, platform_name });
        const path = try std.fs.path.join(a, &.{ st.store_root, dir_name });
        var gh: ?[]const u8 = null;
        if (store.Store.readSource(a, path)) |spec| {
            if (spec.tag) |tag| gh = try std.fmt.allocPrint(a, "gh:{s}/{s}@{s}", .{ spec.owner, spec.repo, tag });
        }
        try out.append(.{ .name = name, .version = active, .gh = gh });
    }
    std.mem.sort(Item, out.items, {}, struct {
        fn lt(_: void, x: Item, y: Item) bool {
            return std.mem.order(u8, x.name, y.name) == .lt;
        }
    }.lt);
    return out.toOwnedSlice();
}

fn find(items: []const Item, name: []const u8) ?Item {
    for (items) |i| if (std.mem.eql(u8, i.name, name)) return i;
    return null;
}

/// Packages added, removed or switched between two snapshots, by name.
pub fn diff(a: Allocator, before: []const Item, after: []const Item) ![]Change {
    var out = std.ArrayList(Change).init(a);
    for (before) |b| {
        if (find(after, b.name)) |x| {
            if (!std.mem.eql(u8, b.version, x.version)) try out.append(.{ .name = b.name, .from = b.version, .to = x.version, .from_gh = b.gh, .to_gh = x.gh });
        } else {
            try out.append(.{ .name = b.name, .from = b.version, .to = null, .from_gh = b.gh });
        }
    }
    for (after) |x| {
        if (find(before, x.name) == null) try out.append(.{ .name = x.name, .from = null, .to = x.version, .to_gh = x.gh });
    }
    std.mem.sort(Change, out.items, {}, struct {
        fn lt(_: void, x: Change, y: Change) bool {
            return std.mem.order(u8, x.name, y.name) == .lt;
        }
    }.lt);
    return out.toOwnedSlice();
}

fn historyPath(a: Allocator, st: *const store.Store) ![]u8 {
    return std.fs.path.join(a, &.{ st.root, file_name });
}

fn validChange(c: Change) bool {
    if (!safepath.isValidId(c.name)) return false;
    if (c.from == null and c.to == null) return false;
    for ([_]?[]const u8{ c.from, c.to }) |v| if (v) |s| if (s.len == 0 or s.len > 128) return false;
    for ([_]?[]const u8{ c.from_gh, c.to_gh }) |g| if (g) |s| if (!std.mem.startsWith(u8, s, "gh:")) return false;
    return true;
}

/// Entries oldest first. A line that does not parse (a torn write, a hand
/// edit) is skipped rather than failing the whole history.
pub fn parse(a: Allocator, text: []const u8) ![]Entry {
    var out = std.ArrayList(Entry).init(a);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.trim(u8, line, " \r\t").len == 0) continue;
        const e = std.json.parseFromSliceLeaky(Entry, a, line, .{ .ignore_unknown_fields = true }) catch continue;
        var ok = e.changes.len != 0;
        for (e.changes) |c| ok = ok and validChange(c);
        if (ok) try out.append(e);
    }
    return out.toOwnedSlice();
}

pub fn load(a: Allocator, st: *const store.Store) ![]Entry {
    const text = std.fs.cwd().readFileAlloc(a, try historyPath(a, st), 32 * 1024 * 1024) catch return &.{};
    return parse(a, text);
}

/// Append an entry for `changes` (nothing when there are none), keeping the
/// newest `max_entries`. Returns the new entry's id, or null.
pub fn record(a: Allocator, st: *const store.Store, command: []const u8, changes: []const Change) !?u64 {
    if (changes.len == 0) return null;
    const old = try load(a, st);
    const id: u64 = if (old.len == 0) 1 else old[old.len - 1].id + 1;
    const keep = if (old.len >= max_entries) old[old.len - max_entries + 1 ..] else old;

    var buf = std.ArrayList(u8).init(a);
    for (keep) |e| {
        try std.json.stringify(e, .{}, buf.writer());
        try buf.append('\n');
    }
    const cmd = if (command.len > 300) command[0..300] else command;
    try std.json.stringify(Entry{ .id = id, .time = std.time.timestamp(), .command = cmd, .changes = changes }, .{}, buf.writer());
    try buf.append('\n');

    const path = try historyPath(a, st);
    const tmp = try std.fmt.allocPrint(a, "{s}.{x}.tmp", .{ path, std.crypto.random.int(u32) });
    try std.fs.cwd().writeFile(.{ .sub_path = tmp, .data = buf.items });
    std.fs.cwd().rename(tmp, path) catch |e| {
        std.fs.cwd().deleteFile(tmp) catch {};
        return e;
    };
    return id;
}

/// "jq 1.6 → 1.7", "ripgrep (new) 14.1", "fd 9.0 (removed)".
pub fn describe(w: anytype, c: Change) !void {
    try w.print("{}", .{cmds_extra.safe(c.name)});
    if (c.from) |f| {
        if (c.to) |t| {
            try w.print(" {} -> {}", .{ cmds_extra.safe(f), cmds_extra.safe(t) });
        } else try w.print(" {} removed", .{cmds_extra.safe(f)});
    } else if (c.to) |t| try w.print(" {} added", .{cmds_extra.safe(t)});
}

fn printTime(w: anytype, t: i64) !void {
    const es = std.time.epoch.EpochSeconds{ .secs = @intCast(@max(t, 0)) };
    const day = es.getEpochDay().calculateYearDay();
    const md = day.calculateMonthDay();
    const ds = es.getDaySeconds();
    try w.print("{d}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2} UTC", .{ day.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour() });
}

/// `abv0 history [--all]`: newest first.
pub fn cmdHistory(base: Allocator, st: *const store.Store, all: bool) !u8 {
    var arena = std.heap.ArenaAllocator.init(base);
    defer arena.deinit();
    const a = arena.allocator();
    const entries = try load(a, st);
    if (entries.len == 0) {
        term.print("no changes recorded yet\n", .{});
        return 0;
    }
    const w = term.writer();
    const shown = if (all) entries.len else @min(entries.len, 20);
    var i = entries.len;
    while (i > entries.len - shown) {
        i -= 1;
        const e = entries[i];
        try w.print("{s}#{d}{s}  ", .{ term.bold, e.id, term.reset });
        try printTime(w, e.time);
        try w.print("  {s}abv0 {}{s}\n", .{ term.dim, cmds_extra.safe(e.command), term.reset });
        for (e.changes) |c| {
            try w.writeAll("    ");
            try describe(w, c);
            try w.writeAll("\n");
        }
    }
    if (shown < entries.len) try w.print("({d} older; --all shows them)\n", .{entries.len - shown});
    try w.print("undo the newest with `abv0 undo`, or one entry with `abv0 undo <#>`\n", .{});
    return 0;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "diff finds added, removed and switched packages" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const before = [_]Item{ .{ .name = "fd", .version = "9.0" }, .{ .name = "jq", .version = "1.6" }, .{ .name = "rg", .version = "14" } };
    const after = [_]Item{ .{ .name = "jq", .version = "1.7" }, .{ .name = "rg", .version = "14" }, .{ .name = "bat", .version = "0.24", .gh = "gh:sharkdp/bat@v0.24.0" } };
    const d = try diff(arena.allocator(), &before, &after);
    try testing.expectEqual(@as(usize, 3), d.len);
    try testing.expectEqualStrings("bat", d[0].name);
    try testing.expect(d[0].from == null);
    try testing.expectEqualStrings("gh:sharkdp/bat@v0.24.0", d[0].to_gh.?);
    try testing.expectEqualStrings("fd", d[1].name);
    try testing.expect(d[1].to == null);
    try testing.expectEqualStrings("1.6", d[2].from.?);
    try testing.expectEqualStrings("1.7", d[2].to.?);
    try testing.expectEqual(@as(usize, 0), (try diff(arena.allocator(), &before, &before)).len);
}

test "parse keeps good entries and skips torn or unsafe ones" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const text =
        \\{"id":1,"time":1700000000,"command":"install jq","changes":[{"name":"jq","from":null,"to":"1.7"}]}
        \\{"id":2,"time":17000
        \\{"id":3,"time":1700000100,"command":"x","changes":[{"name":"../evil","from":null,"to":"1"}]}
        \\{"id":4,"time":1700000200,"command":"x","changes":[{"name":"bat","from":null,"to":"1","to_gh":"https://x"}]}
        \\{"id":5,"time":1700000300,"command":"upgrade","changes":[{"name":"jq","from":"1.7","to":"1.8","extra":true}]}
        \\
    ;
    const e = try parse(arena.allocator(), text);
    try testing.expectEqual(@as(usize, 2), e.len);
    try testing.expectEqual(@as(u64, 1), e[0].id);
    try testing.expectEqual(@as(u64, 5), e[1].id);
}

test "describe says what changed" {
    var buf: [128]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try describe(fbs.writer(), .{ .name = "jq", .from = "1.6", .to = "1.7" });
    try testing.expectEqualStrings("jq 1.6 -> 1.7", fbs.getWritten());
    fbs.reset();
    try describe(fbs.writer(), .{ .name = "fd", .from = "9.0", .to = null });
    try testing.expectEqualStrings("fd 9.0 removed", fbs.getWritten());
    fbs.reset();
    try describe(fbs.writer(), .{ .name = "rg", .from = null, .to = "14" });
    try testing.expectEqualStrings("rg 14 added", fbs.getWritten());
}
