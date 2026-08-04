//! A real Bloom filter.
//!
//! The previous `DependencyBloomFilter` was a text file of `NODE_VISITED: <hex>`
//! lines that was (a) truncated by `createFile` on every construction, so it
//! could never retain state, and (b) queried with a linear substring scan over
//! the whole file, so it was O(n) per lookup rather than O(1).
//!
//! This is an actual bit-array filter with k independent probes derived by
//! Kirsch-Mitzenmacher double hashing (h_i = h1 + i*h2), which is standard and
//! avoids computing k separate hashes.

const std = @import("std");
const platform = @import("platform.zig");

pub fn Bloom(comptime bit_count: usize, comptime probes: u8) type {
    comptime std.debug.assert(bit_count % 8 == 0);
    comptime std.debug.assert(probes > 0);

    return struct {
        const Self = @This();
        pub const byte_count = bit_count / 8;

        bits: [byte_count]u8 = [_]u8{0} ** byte_count,

        pub fn init() Self {
            return .{};
        }

        pub fn reset(self: *Self) void {
            @memset(&self.bits, 0);
        }

        fn probeIndex(key: []const u8, i: u8) usize {
            const h1 = std.hash.Wyhash.hash(0x9E3779B97F4A7C15, key);
            const h2 = std.hash.Wyhash.hash(0xC2B2AE3D27D4EB4F, key) | 1; // odd
            const combined = h1 +% (@as(u64, i) *% h2);
            return @intCast(combined % bit_count);
        }

        pub fn insert(self: *Self, key: []const u8) void {
            var i: u8 = 0;
            while (i < probes) : (i += 1) {
                const bit = probeIndex(key, i);
                self.bits[bit / 8] |= @as(u8, 1) << @intCast(bit % 8);
            }
        }

        /// False positives are possible; false negatives are not.
        pub fn mightContain(self: *const Self, key: []const u8) bool {
            var i: u8 = 0;
            while (i < probes) : (i += 1) {
                const bit = probeIndex(key, i);
                if (self.bits[bit / 8] & (@as(u8, 1) << @intCast(bit % 8)) == 0) return false;
            }
            return true;
        }

        /// Insert and report whether the key was probably already present.
        pub fn testAndSet(self: *Self, key: []const u8) bool {
            const seen = self.mightContain(key);
            self.insert(key);
            return seen;
        }

        pub fn popCount(self: *const Self) usize {
            var n: usize = 0;
            for (self.bits) |b| n += @popCount(b);
            return n;
        }

        // -- persistence -----------------------------------------------------
        // Raw bits with a header, written atomically. Reads are bounded and use
        // readAll, so a truncated or hostile file yields an error rather than
        // uninitialised memory.

        const magic = "ABV0BLM1";

        pub fn saveToFile(self: *const Self, path: []const u8) !void {
            if (std.fs.path.dirname(path)) |d| std.fs.cwd().makePath(d) catch {};

            var tmp_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
            const tmp_path = try std.fmt.bufPrint(&tmp_buf, "{s}.tmp", .{path});

            {
                const file = try std.fs.cwd().createFile(tmp_path, .{ .mode = platform.mode_private });
                defer file.close();
                var w = file.writer();
                try w.writeAll(magic);
                try w.writeInt(u64, bit_count, .little);
                try w.writeByte(probes);
                try w.writeAll(&self.bits);
            }
            try std.fs.cwd().rename(tmp_path, path);
        }

        pub fn loadFromFile(path: []const u8) !Self {
            const file = try std.fs.cwd().openFile(path, .{});
            defer file.close();

            var header: [magic.len + 8 + 1]u8 = undefined;
            const got = try file.readAll(&header);
            if (got != header.len) return error.CorruptFilter;
            if (!std.mem.eql(u8, header[0..magic.len], magic)) return error.CorruptFilter;

            const stored_bits = std.mem.readInt(u64, header[magic.len..][0..8], .little);
            const stored_probes = header[magic.len + 8];
            if (stored_bits != bit_count or stored_probes != probes) return error.FilterShapeMismatch;

            var self = Self.init();
            const n = try file.readAll(&self.bits);
            if (n != byte_count) return error.CorruptFilter;
            return self;
        }
    };
}

/// 64 KiB of bits with 7 probes: ~1% false positives at 50k entries, which is
/// far more registry than abv0 will plausibly hold.
pub const Default = Bloom(64 * 1024 * 8, 7);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "no false negatives" {
    var f = Default.init();
    const keys = [_][]const u8{ "jq", "ripgrep", "bat", "ffmpeg", "zig", "btop" };
    for (keys) |k| f.insert(k);
    for (keys) |k| try std.testing.expect(f.mightContain(k));
}

test "empty filter contains nothing" {
    var f = Default.init();
    try std.testing.expect(!f.mightContain("jq"));
    try std.testing.expectEqual(@as(usize, 0), f.popCount());
}

test "testAndSet reports prior membership" {
    var f = Default.init();
    try std.testing.expect(!f.testAndSet("node-a"));
    try std.testing.expect(f.testAndSet("node-a"));
}

test "false positive rate stays within budget" {
    var f = Bloom(1 << 16, 7).init();
    var buf: [32]u8 = undefined;

    var i: usize = 0;
    while (i < 2000) : (i += 1) {
        const k = try std.fmt.bufPrint(&buf, "present-{d}", .{i});
        f.insert(k);
    }

    var false_positives: usize = 0;
    i = 0;
    while (i < 10_000) : (i += 1) {
        const k = try std.fmt.bufPrint(&buf, "absent-{d}", .{i});
        if (f.mightContain(k)) false_positives += 1;
    }
    // Theoretical rate here is well under 1%; allow generous headroom.
    try std.testing.expect(false_positives < 500);
}

test "persistence round-trips and survives reload" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(dir_path);
    const p = try std.fs.path.join(std.testing.allocator, &.{ dir_path, "bloom.bitset" });
    defer std.testing.allocator.free(p);

    var f = Default.init();
    f.insert("alpha");
    f.insert("beta");
    try f.saveToFile(p);

    // The old implementation truncated on open, losing everything here.
    const g = try Default.loadFromFile(p);
    try std.testing.expect(g.mightContain("alpha"));
    try std.testing.expect(g.mightContain("beta"));
    try std.testing.expectEqual(f.popCount(), g.popCount());
}

test "corrupt filter file is rejected, not misread" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(dir_path);
    const p = try std.fs.path.join(std.testing.allocator, &.{ dir_path, "bad.bitset" });
    defer std.testing.allocator.free(p);

    {
        const file = try std.fs.cwd().createFile(p, .{});
        defer file.close();
        try file.writeAll("NOT-A-FILTER");
    }
    try std.testing.expectError(error.CorruptFilter, Default.loadFromFile(p));
}
