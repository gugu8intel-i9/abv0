//! `index.abv` - a compiled, memory-mapped, zero-copy registry index.
//!
//! The README has advertised a "Zero-Copy Memory-Mapped Flat Custom Index"
//! since v0.9.5. What actually existed was a 24-byte header written to a file
//! that nothing ever read, plus a `ColumnarRegistry` that was never called from
//! anywhere in the program.
//!
//! This is the real thing. `index.json` is compiled once into a flat binary
//! layout; subsequent runs `mmap` it and slice strings directly out of the
//! mapping, so steady-state startup performs no JSON parsing and no string
//! copying. Lookups are a binary search over a sorted record array.
//!
//! Every offset read out of the file is bounds-checked against the mapping
//! before use. This is the general fix for the class of bug that made
//! `ColumnarRegistry.projectNamesAndVersions` leak uninitialised heap memory:
//! it allocated an attacker-controlled `u16` length and ignored short reads.

const std = @import("std");
const registry = @import("registry.zig");
const platform = @import("platform.zig");
const safepath = @import("safepath.zig");

pub const magic = "ABV0IDX\x00";
pub const format_version: u32 = 1;

pub const header_size = 64;
pub const record_size = 72; // 18 x u32
pub const list_entry_size = 8; // 2 x u32
pub const plat_entry_size = 40; // 10 x u32

pub const Error = error{
    BadMagic,
    UnsupportedFormatVersion,
    CorruptIndex,
    StaleIndex,
};

/// Identity of the source manifest, used to decide whether the cache is fresh.
pub const Stamp = struct {
    size: u64,
    mtime_ns: i64,

    pub fn ofFile(path: []const u8) !Stamp {
        const st = try std.fs.cwd().statFile(path);
        return .{ .size = st.size, .mtime_ns = @truncate(st.mtime) };
    }

    pub fn eql(a: Stamp, b: Stamp) bool {
        return a.size == b.size and a.mtime_ns == b.mtime_ns;
    }
};

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

const StringTable = struct {
    bytes: std.ArrayList(u8),
    dedup: std.StringHashMap(u32),

    fn init(allocator: std.mem.Allocator) StringTable {
        return .{
            .bytes = std.ArrayList(u8).init(allocator),
            .dedup = std.StringHashMap(u32).init(allocator),
        };
    }

    fn deinit(self: *StringTable) void {
        self.bytes.deinit();
        self.dedup.deinit();
    }

    /// Returns (offset, length). Identical strings share storage.
    fn put(self: *StringTable, s: []const u8) ![2]u32 {
        if (s.len == 0) return .{ 0, 0 };
        if (self.dedup.get(s)) |off| return .{ off, @intCast(s.len) };

        const off: u32 = @intCast(self.bytes.items.len);
        try self.bytes.appendSlice(s);
        try self.dedup.put(s, off);
        return .{ off, @intCast(s.len) };
    }
};

/// Compile `reg` into a binary index at `out_path`. Written to a temporary
/// file and renamed, so a concurrent reader never observes a partial index.
pub fn build(
    allocator: std.mem.Allocator,
    reg: *const registry.Registry,
    out_path: []const u8,
    stamp: Stamp,
) !void {
    var strings = StringTable.init(allocator);
    defer strings.deinit();

    var records = std.ArrayList(u8).init(allocator);
    defer records.deinit();
    var lists = std.ArrayList(u8).init(allocator);
    defer lists.deinit();
    var plats = std.ArrayList(u8).init(allocator);
    defer plats.deinit();

    // Packages must already be sorted for binary search to be valid.
    for (reg.packages) |pkg| {
        const name = try strings.put(pkg.name);
        const version = try strings.put(pkg.version);
        const desc = try strings.put(pkg.description);
        const home = try strings.put(pkg.homepage);
        const lic = try strings.put(pkg.license);

        const bin_first: u32 = @intCast(lists.items.len / list_entry_size);
        for (pkg.bin) |b| {
            const e = try strings.put(b);
            try appendU32(&lists, e[0]);
            try appendU32(&lists, e[1]);
        }
        const app_first: u32 = @intCast(lists.items.len / list_entry_size);
        for (pkg.app_bundles) |a| {
            const e = try strings.put(a);
            try appendU32(&lists, e[0]);
            try appendU32(&lists, e[1]);
        }
        const dep_first: u32 = @intCast(lists.items.len / list_entry_size);
        for (pkg.deps) |d| {
            const e = try strings.put(d);
            try appendU32(&lists, e[0]);
            try appendU32(&lists, e[1]);
        }

        const plat_first: u32 = @intCast(plats.items.len / plat_entry_size);
        for (pkg.platforms) |p| {
            inline for (.{ p.name, p.url, p.sha256, p.archive_type, p.bin_path }) |field| {
                const e = try strings.put(field);
                try appendU32(&plats, e[0]);
                try appendU32(&plats, e[1]);
            }
        }

        inline for (.{ name, version, desc, home, lic }) |pair| {
            try appendU32(&records, pair[0]);
            try appendU32(&records, pair[1]);
        }
        try appendU32(&records, bin_first);
        try appendU32(&records, @intCast(pkg.bin.len));
        try appendU32(&records, app_first);
        try appendU32(&records, @intCast(pkg.app_bundles.len));
        try appendU32(&records, dep_first);
        try appendU32(&records, @intCast(pkg.deps.len));
        try appendU32(&records, plat_first);
        try appendU32(&records, @intCast(pkg.platforms.len));
    }

    const rec_off: u32 = header_size;
    const list_off: u32 = rec_off + @as(u32, @intCast(records.items.len));
    const plat_off: u32 = list_off + @as(u32, @intCast(lists.items.len));
    const str_off: u32 = plat_off + @as(u32, @intCast(plats.items.len));

    var header: [header_size]u8 = [_]u8{0} ** header_size;
    @memcpy(header[0..8], magic);
    std.mem.writeInt(u32, header[8..12], format_version, .little);
    std.mem.writeInt(u32, header[12..16], @intCast(reg.packages.len), .little);
    std.mem.writeInt(u64, header[16..24], stamp.size, .little);
    std.mem.writeInt(i64, header[24..32], stamp.mtime_ns, .little);
    std.mem.writeInt(u32, header[32..36], rec_off, .little);
    std.mem.writeInt(u32, header[36..40], @intCast(records.items.len), .little);
    std.mem.writeInt(u32, header[40..44], list_off, .little);
    std.mem.writeInt(u32, header[44..48], @intCast(lists.items.len / list_entry_size), .little);
    std.mem.writeInt(u32, header[48..52], plat_off, .little);
    std.mem.writeInt(u32, header[52..56], @intCast(plats.items.len / plat_entry_size), .little);
    std.mem.writeInt(u32, header[56..60], str_off, .little);
    std.mem.writeInt(u32, header[60..64], @intCast(strings.bytes.items.len), .little);

    if (std.fs.path.dirname(out_path)) |d| std.fs.cwd().makePath(d) catch {};

    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.{x}.tmp", .{ out_path, std.crypto.random.int(u32) });
    defer allocator.free(tmp_path);

    {
        const file = try std.fs.cwd().createFile(tmp_path, .{ .mode = platform.mode_private });
        defer file.close();
        var bw = std.io.bufferedWriter(file.writer());
        const w = bw.writer();
        try w.writeAll(&header);
        try w.writeAll(records.items);
        try w.writeAll(lists.items);
        try w.writeAll(plats.items);
        try w.writeAll(strings.bytes.items);
        try bw.flush();
    }
    errdefer std.fs.cwd().deleteFile(tmp_path) catch {};
    try std.fs.cwd().rename(tmp_path, out_path);
}

fn appendU32(list: *std.ArrayList(u8), v: u32) !void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, v, .little);
    try list.appendSlice(&buf);
}

// ---------------------------------------------------------------------------
// Load
// ---------------------------------------------------------------------------

const View = struct {
    bytes: []const u8,
    str_off: u32,
    str_len: u32,

    /// Bounds-checked string slice. Every string in the index goes through
    /// here, so a malformed offset yields CorruptIndex rather than reading
    /// out of bounds.
    fn str(self: View, off: u32, len: u32) ![]const u8 {
        if (len == 0) return "";
        const start = @as(u64, self.str_off) + off;
        const end = start + len;
        if (end > self.bytes.len) return Error.CorruptIndex;
        if (off + len > self.str_len) return Error.CorruptIndex;
        return self.bytes[@intCast(start)..@intCast(end)];
    }

    fn u32At(self: View, off: u64) !u32 {
        if (off + 4 > self.bytes.len) return Error.CorruptIndex;
        return std.mem.readInt(u32, self.bytes[@intCast(off)..][0..4], .little);
    }
};

/// Load a compiled index, verifying it matches `expected` (the current
/// `index.json`). Returns `StaleIndex` when the source has changed.
pub fn load(
    allocator: std.mem.Allocator,
    index_path: []const u8,
    expected: ?Stamp,
) !registry.Registry {
    var mapped = try platform.MappedFile.open(allocator, index_path);
    errdefer mapped.deinit();

    const bytes = mapped.bytes;
    if (bytes.len < header_size) return Error.CorruptIndex;
    if (!std.mem.eql(u8, bytes[0..8], magic)) return Error.BadMagic;

    const ver = std.mem.readInt(u32, bytes[8..12], .little);
    if (ver != format_version) return Error.UnsupportedFormatVersion;

    const pkg_count = std.mem.readInt(u32, bytes[12..16], .little);
    const src_size = std.mem.readInt(u64, bytes[16..24], .little);
    const src_mtime = std.mem.readInt(i64, bytes[24..32], .little);

    if (expected) |e| {
        if (!Stamp.eql(e, .{ .size = src_size, .mtime_ns = src_mtime })) return Error.StaleIndex;
    }

    const rec_off = std.mem.readInt(u32, bytes[32..36], .little);
    const rec_len = std.mem.readInt(u32, bytes[36..40], .little);
    const list_off = std.mem.readInt(u32, bytes[40..44], .little);
    const list_count = std.mem.readInt(u32, bytes[44..48], .little);
    const plat_off = std.mem.readInt(u32, bytes[48..52], .little);
    const plat_count = std.mem.readInt(u32, bytes[52..56], .little);
    const str_off = std.mem.readInt(u32, bytes[56..60], .little);
    const str_len = std.mem.readInt(u32, bytes[60..64], .little);

    // Structural validation before trusting any of it.
    if (@as(u64, pkg_count) * record_size != rec_len) return Error.CorruptIndex;
    if (@as(u64, rec_off) + rec_len > bytes.len) return Error.CorruptIndex;
    if (@as(u64, list_off) + @as(u64, list_count) * list_entry_size > bytes.len) return Error.CorruptIndex;
    if (@as(u64, plat_off) + @as(u64, plat_count) * plat_entry_size > bytes.len) return Error.CorruptIndex;
    if (@as(u64, str_off) + str_len > bytes.len) return Error.CorruptIndex;

    const view = View{ .bytes = bytes, .str_off = str_off, .str_len = str_len };

    const arena = try allocator.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(allocator);
    errdefer {
        arena.deinit();
        allocator.destroy(arena);
    }
    const aa = arena.allocator();

    const packages = try aa.alloc(registry.Package, pkg_count);

    var i: u32 = 0;
    while (i < pkg_count) : (i += 1) {
        const base = @as(u64, rec_off) + @as(u64, i) * record_size;

        var f: [18]u32 = undefined;
        for (&f, 0..) |*slot, j| {
            slot.* = try view.u32At(base + j * 4);
        }

        const bin_first = f[10];
        const bin_count = f[11];
        const app_first = f[12];
        const app_count = f[13];
        const dep_first = f[14];
        const dep_count = f[15];
        const plat_first = f[16];
        const pcount = f[17];

        if (@as(u64, bin_first) + bin_count > list_count) return Error.CorruptIndex;
        if (@as(u64, app_first) + app_count > list_count) return Error.CorruptIndex;
        if (@as(u64, dep_first) + dep_count > list_count) return Error.CorruptIndex;
        if (@as(u64, plat_first) + pcount > plat_count) return Error.CorruptIndex;

        packages[i] = .{
            .name = try view.str(f[0], f[1]),
            .version = try view.str(f[2], f[3]),
            .description = try view.str(f[4], f[5]),
            .homepage = try view.str(f[6], f[7]),
            .license = try view.str(f[8], f[9]),
            .bin = try readList(aa, view, list_off, bin_first, bin_count),
            .app_bundles = try readList(aa, view, list_off, app_first, app_count),
            .deps = try readList(aa, view, list_off, dep_first, dep_count),
            .platforms = try readPlatforms(aa, view, plat_off, plat_first, pcount),
        };
    }

    // A tampered index could present unsorted records, breaking binary search.
    var k: usize = 1;
    while (k < packages.len) : (k += 1) {
        if (std.mem.order(u8, packages[k - 1].name, packages[k].name) != .lt) return Error.CorruptIndex;
    }

    return registry.Registry{
        .allocator = allocator,
        .arena = arena,
        .mapped = mapped,
        .packages = packages,
    };
}

fn readList(
    allocator: std.mem.Allocator,
    view: View,
    list_off: u32,
    first: u32,
    count: u32,
) ![]const []const u8 {
    if (count == 0) return &.{};
    const out = try allocator.alloc([]const u8, count);
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const base = @as(u64, list_off) + @as(u64, first + i) * list_entry_size;
        const off = try view.u32At(base);
        const len = try view.u32At(base + 4);
        out[i] = try view.str(off, len);
    }
    return out;
}

fn readPlatforms(
    allocator: std.mem.Allocator,
    view: View,
    plat_off: u32,
    first: u32,
    count: u32,
) ![]const registry.PlatformInfo {
    if (count == 0) return &.{};
    const out = try allocator.alloc(registry.PlatformInfo, count);
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const base = @as(u64, plat_off) + @as(u64, first + i) * plat_entry_size;
        var f: [10]u32 = undefined;
        for (&f, 0..) |*slot, j| {
            slot.* = try view.u32At(base + j * 4);
        }
        out[i] = .{
            .name = try view.str(f[0], f[1]),
            .url = try view.str(f[2], f[3]),
            .sha256 = try view.str(f[4], f[5]),
            .archive_type = try view.str(f[6], f[7]),
            .bin_path = try view.str(f[8], f[9]),
        };
    }
    return out;
}

/// Load the registry the fast way when possible, otherwise parse JSON and
/// refresh the cache. This is the function the CLI actually calls.
pub fn loadCached(
    allocator: std.mem.Allocator,
    json_path: []const u8,
    index_path: []const u8,
) !registry.Registry {
    const stamp = try Stamp.ofFile(json_path);

    if (load(allocator, index_path, stamp)) |reg| {
        return reg;
    } else |_| {
        // Any problem at all (missing, stale, corrupt, wrong version) falls
        // back to the authoritative JSON.
    }

    var reg = try registry.loadFromJsonFile(allocator, json_path, null);
    errdefer reg.deinit();

    // Best-effort cache refresh; failing to write it must not break the command.
    build(allocator, &reg, index_path, stamp) catch {};
    return reg;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const sample_manifest =
    \\{"packages":{
    \\ "jq":{"name":"jq","version":"1.7.1","description":"json processor","homepage":"https://jqlang.org",
    \\   "license":"MIT","bin":["jq"],"deps":[],
    \\   "platforms":{"x86_64-linux":{"url":"https://example.com/jq","sha256":"SKIP",
    \\   "archive_type":"raw","bin_path":"jq"}}},
    \\ "ripgrep":{"name":"ripgrep","version":"14.1.0","description":"fast grep","homepage":"",
    \\   "license":"MIT","bin":["rg"],"deps":["jq"],
    \\   "platforms":{"x86_64-linux":{"url":"https://example.com/rg.tar.gz","sha256":"SKIP",
    \\   "archive_type":"tar.gz","bin_path":"rg"},
    \\   "aarch64-macos":{"url":"https://example.com/rg-mac.tar.gz","sha256":"SKIP",
    \\   "archive_type":"tar.gz","bin_path":"rg"}}}
    \\}}
;

fn setupSample(tmp: *std.testing.TmpDir, allocator: std.mem.Allocator) ![2][]u8 {
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const json_path = try std.fs.path.join(allocator, &.{ root, "index.json" });
    const idx_path = try std.fs.path.join(allocator, &.{ root, "index.abv" });
    const f = try std.fs.cwd().createFile(json_path, .{});
    defer f.close();
    try f.writeAll(sample_manifest);
    return .{ json_path, idx_path };
}

test "index round-trips every field" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const paths = try setupSample(&tmp, testing.allocator);
    defer testing.allocator.free(paths[0]);
    defer testing.allocator.free(paths[1]);

    var src = try registry.loadFromJsonFile(testing.allocator, paths[0], null);
    defer src.deinit();

    const stamp = try Stamp.ofFile(paths[0]);
    try build(testing.allocator, &src, paths[1], stamp);

    var loaded = try load(testing.allocator, paths[1], stamp);
    defer loaded.deinit();

    try testing.expectEqual(src.count(), loaded.count());

    const rg = loaded.get("ripgrep").?;
    try testing.expectEqualStrings("ripgrep", rg.name);
    try testing.expectEqualStrings("14.1.0", rg.version);
    try testing.expectEqualStrings("fast grep", rg.description);
    try testing.expectEqualStrings("MIT", rg.license);
    try testing.expectEqual(@as(usize, 1), rg.bin.len);
    try testing.expectEqualStrings("rg", rg.bin[0]);
    try testing.expectEqual(@as(usize, 1), rg.deps.len);
    try testing.expectEqualStrings("jq", rg.deps[0]);
    try testing.expectEqual(@as(usize, 2), rg.platforms.len);

    const linux = rg.platform("x86_64-linux").?;
    try testing.expectEqualStrings("https://example.com/rg.tar.gz", linux.url);
    try testing.expectEqualStrings("tar.gz", linux.archive_type);
    try testing.expectEqualStrings("rg", linux.bin_path);

    try testing.expectEqualStrings("json processor", loaded.get("jq").?.description);
    try testing.expect(loaded.get("absent") == null);
}

test "stale index is detected when the manifest changes" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const paths = try setupSample(&tmp, testing.allocator);
    defer testing.allocator.free(paths[0]);
    defer testing.allocator.free(paths[1]);

    var src = try registry.loadFromJsonFile(testing.allocator, paths[0], null);
    defer src.deinit();
    const stamp = try Stamp.ofFile(paths[0]);
    try build(testing.allocator, &src, paths[1], stamp);

    // Rewrite the manifest with different content and a different size.
    {
        const f = try std.fs.cwd().createFile(paths[0], .{});
        defer f.close();
        try f.writeAll(sample_manifest ++ "\n\n");
    }

    const new_stamp = try Stamp.ofFile(paths[0]);
    try testing.expectError(Error.StaleIndex, load(testing.allocator, paths[1], new_stamp));
}

test "loadCached builds the index then reuses it" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const paths = try setupSample(&tmp, testing.allocator);
    defer testing.allocator.free(paths[0]);
    defer testing.allocator.free(paths[1]);

    try testing.expectError(error.FileNotFound, std.fs.cwd().access(paths[1], .{}));

    {
        var r1 = try loadCached(testing.allocator, paths[0], paths[1]);
        defer r1.deinit();
        try testing.expectEqual(@as(usize, 2), r1.count());
    }

    // The cache now exists...
    try std.fs.cwd().access(paths[1], .{});

    {
        var r2 = try loadCached(testing.allocator, paths[0], paths[1]);
        defer r2.deinit();
        // ...and serves identical data, this time straight from the mapping.
        try testing.expect(r2.mapped != null);
        try testing.expectEqualStrings("14.1.0", r2.get("ripgrep").?.version);
    }
}

test "truncated index is rejected" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const paths = try setupSample(&tmp, testing.allocator);
    defer testing.allocator.free(paths[0]);
    defer testing.allocator.free(paths[1]);

    var src = try registry.loadFromJsonFile(testing.allocator, paths[0], null);
    defer src.deinit();
    const stamp = try Stamp.ofFile(paths[0]);
    try build(testing.allocator, &src, paths[1], stamp);

    const full = try std.fs.cwd().readFileAlloc(testing.allocator, paths[1], 1 << 20);
    defer testing.allocator.free(full);

    {
        const f = try std.fs.cwd().createFile(paths[1], .{});
        defer f.close();
        try f.writeAll(full[0 .. full.len / 2]);
    }
    try testing.expectError(Error.CorruptIndex, load(testing.allocator, paths[1], stamp));
}

test "out-of-range string offsets are rejected, not read out of bounds" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const paths = try setupSample(&tmp, testing.allocator);
    defer testing.allocator.free(paths[0]);
    defer testing.allocator.free(paths[1]);

    var src = try registry.loadFromJsonFile(testing.allocator, paths[0], null);
    defer src.deinit();
    const stamp = try Stamp.ofFile(paths[0]);
    try build(testing.allocator, &src, paths[1], stamp);

    const full = try std.fs.cwd().readFileAlloc(testing.allocator, paths[1], 1 << 20);
    defer testing.allocator.free(full);

    // Point the first package's name at a wildly out-of-range offset, the
    // exact shape of the ColumnarRegistry heap-disclosure bug.
    const rec_off = std.mem.readInt(u32, full[32..36], .little);
    std.mem.writeInt(u32, full[rec_off..][0..4], 0xFFFF_0000, .little);
    std.mem.writeInt(u32, full[rec_off + 4 ..][0..4], 0x1000, .little);

    {
        const f = try std.fs.cwd().createFile(paths[1], .{});
        defer f.close();
        try f.writeAll(full);
    }
    try testing.expectError(Error.CorruptIndex, load(testing.allocator, paths[1], stamp));
}

test "bad magic and wrong version are rejected" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    const p = try std.fs.path.join(testing.allocator, &.{ root, "junk.abv" });
    defer testing.allocator.free(p);

    {
        const f = try std.fs.cwd().createFile(p, .{});
        defer f.close();
        try f.writeAll(&[_]u8{0xAA} ** 128);
    }
    try testing.expectError(Error.BadMagic, load(testing.allocator, p, null));

    {
        var buf = [_]u8{0} ** 128;
        @memcpy(buf[0..8], magic);
        std.mem.writeInt(u32, buf[8..12], 999, .little);
        const f = try std.fs.cwd().createFile(p, .{});
        defer f.close();
        try f.writeAll(&buf);
    }
    try testing.expectError(Error.UnsupportedFormatVersion, load(testing.allocator, p, null));
}

test "string table deduplicates repeated values" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    var st = StringTable.init(testing.allocator);
    defer st.deinit();

    const a = try st.put("x86_64-linux");
    const b = try st.put("x86_64-linux");
    try testing.expectEqual(a[0], b[0]);
    try testing.expectEqual(@as(usize, "x86_64-linux".len), st.bytes.items.len);
}
