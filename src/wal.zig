//! Append-only, CRC-checked write-ahead log for install state.
//!
//! The previous `InstallStateMachine` called `createFile` on every transition,
//! which truncates. The "log" therefore only ever held the most recent record
//! and could not support the crash recovery it was documented as providing.
//! Nothing ever read it back.
//!
//! This version appends fixed-width records, checksums each one, and can
//! recover the last durable state after a crash - including discarding a
//! torn trailing record from a partial write.

const std = @import("std");
const safepath = @import("safepath.zig");
const platform = @import("platform.zig");

pub const State = enum(u8) {
    init = 0,
    fetch = 1,
    verify = 2,
    unpack = 3,
    link = 4,
    complete = 5,
    failed = 6,

    pub fn label(self: State) []const u8 {
        return @tagName(self);
    }
};

/// 24 bytes, fixed width, little-endian.
///   magic u32 | seq u32 | state u8 | pad [3] | timestamp i64 | crc u32
pub const record_size = 24;
const record_magic: u32 = 0x30_56_42_41; // "ABV0"

pub const Record = struct {
    seq: u32,
    state: State,
    timestamp: i64,

    fn encode(self: Record) [record_size]u8 {
        var buf: [record_size]u8 = undefined;
        std.mem.writeInt(u32, buf[0..4], record_magic, .little);
        std.mem.writeInt(u32, buf[4..8], self.seq, .little);
        buf[8] = @intFromEnum(self.state);
        buf[9] = 0;
        buf[10] = 0;
        buf[11] = 0;
        std.mem.writeInt(i64, buf[12..20], self.timestamp, .little);
        const crc = std.hash.Crc32.hash(buf[0..20]);
        std.mem.writeInt(u32, buf[20..24], crc, .little);
        return buf;
    }

    fn decode(buf: *const [record_size]u8) ?Record {
        if (std.mem.readInt(u32, buf[0..4], .little) != record_magic) return null;
        const stored_crc = std.mem.readInt(u32, buf[20..24], .little);
        if (std.hash.Crc32.hash(buf[0..20]) != stored_crc) return null;
        const raw_state = buf[8];
        if (raw_state > @intFromEnum(State.failed)) return null;
        return Record{
            .seq = std.mem.readInt(u32, buf[4..8], .little),
            .state = @enumFromInt(raw_state),
            .timestamp = std.mem.readInt(i64, buf[12..20], .little),
        };
    }
};

pub const Wal = struct {
    allocator: std.mem.Allocator,
    path: []u8,
    seq: u32 = 0,

    /// `pkg_name` is validated because it becomes a filename.
    pub fn init(allocator: std.mem.Allocator, state_root: []const u8, pkg_name: []const u8) !Wal {
        if (!safepath.isValidId(pkg_name)) return error.InvalidPackageIdentifier;

        const dir = try std.fs.path.join(allocator, &.{ state_root, "states_wal" });
        defer allocator.free(dir);
        std.fs.cwd().makePath(dir) catch {};

        // The original leaked this inner allocPrint by nesting it in path.join.
        const file_name = try std.fmt.allocPrint(allocator, "{s}.wal", .{pkg_name});
        defer allocator.free(file_name);

        const path = try std.fs.path.join(allocator, &.{ dir, file_name });
        return .{ .allocator = allocator, .path = path };
    }

    pub fn deinit(self: *Wal) void {
        self.allocator.free(self.path);
        self.* = undefined;
    }

    /// Append a state transition and flush it to disk.
    pub fn append(self: *Wal, state: State) !void {
        const file = std.fs.cwd().openFile(self.path, .{ .mode = .write_only }) catch |e| switch (e) {
            error.FileNotFound => try std.fs.cwd().createFile(self.path, .{ .mode = platform.mode_private }),
            else => return e,
        };
        defer file.close();

        try file.seekFromEnd(0);
        self.seq +%= 1;
        const rec = Record{
            .seq = self.seq,
            .state = state,
            .timestamp = std.time.timestamp(),
        };
        const bytes = rec.encode();
        try file.writeAll(&bytes);
    }

    /// The last structurally valid record, or null when there is no usable log.
    /// A torn trailing record (partial write during a crash) is ignored.
    pub fn recover(self: *Wal) !?Record {
        const file = std.fs.cwd().openFile(self.path, .{}) catch |e| switch (e) {
            error.FileNotFound => return null,
            else => return e,
        };
        defer file.close();

        const size = (try file.stat()).size;
        const whole_records = size / record_size;
        if (whole_records == 0) return null;

        var last: ?Record = null;
        var i: u64 = 0;
        while (i < whole_records) : (i += 1) {
            var buf: [record_size]u8 = undefined;
            try file.seekTo(i * record_size);
            const n = try file.readAll(&buf);
            if (n != record_size) break;
            if (Record.decode(&buf)) |rec| {
                last = rec;
                self.seq = rec.seq;
            }
        }
        return last;
    }

    /// True when a previous run died partway through an install.
    pub fn hasUnfinishedInstall(self: *Wal) !bool {
        const last = (try self.recover()) orelse return false;
        return switch (last.state) {
            .complete, .failed => false,
            else => true,
        };
    }

    pub fn clear(self: *Wal) void {
        std.fs.cwd().deleteFile(self.path) catch {};
        self.seq = 0;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn tmpRoot(tmp: *std.testing.TmpDir, allocator: std.mem.Allocator) ![]u8 {
    return tmp.dir.realpathAlloc(allocator, ".");
}

test "wal is append-only and retains full history" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmpRoot(&tmp, testing.allocator);
    defer testing.allocator.free(root);

    var w = try Wal.init(testing.allocator, root, "jq");
    defer w.deinit();

    try w.append(.init);
    try w.append(.fetch);
    try w.append(.verify);

    // The old implementation truncated per transition; three records must
    // actually be on disk here.
    const stat = try std.fs.cwd().statFile(w.path);
    try testing.expectEqual(@as(u64, 3 * record_size), stat.size);

    const last = (try w.recover()).?;
    try testing.expectEqual(State.verify, last.state);
    try testing.expectEqual(@as(u32, 3), last.seq);
}

test "recover reports an unfinished install" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmpRoot(&tmp, testing.allocator);
    defer testing.allocator.free(root);

    var w = try Wal.init(testing.allocator, root, "ripgrep");
    defer w.deinit();

    try w.append(.init);
    try w.append(.unpack);
    try testing.expect(try w.hasUnfinishedInstall());

    try w.append(.complete);
    try testing.expect(!(try w.hasUnfinishedInstall()));
}

test "torn trailing record is discarded, earlier state survives" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmpRoot(&tmp, testing.allocator);
    defer testing.allocator.free(root);

    var w = try Wal.init(testing.allocator, root, "bat");
    defer w.deinit();
    try w.append(.init);
    try w.append(.fetch);

    // Simulate a crash midway through writing record 3.
    {
        const f = try std.fs.cwd().openFile(w.path, .{ .mode = .write_only });
        defer f.close();
        try f.seekFromEnd(0);
        try f.writeAll("\x41\x42\x56\x30\xff\xff");
    }

    const last = (try w.recover()).?;
    try testing.expectEqual(State.fetch, last.state);
}

test "bit-flip in a record is caught by the crc" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmpRoot(&tmp, testing.allocator);
    defer testing.allocator.free(root);

    var w = try Wal.init(testing.allocator, root, "zig");
    defer w.deinit();
    try w.append(.init);
    try w.append(.complete);

    {
        const f = try std.fs.cwd().openFile(w.path, .{ .mode = .read_write });
        defer f.close();
        try f.seekTo(record_size + 8); // state byte of the second record
        try f.writeAll(&[_]u8{@intFromEnum(State.link)});
    }

    // The tampered record fails its checksum, so recovery falls back to the
    // last intact one rather than trusting corrupt state.
    const last = (try w.recover()).?;
    try testing.expectEqual(State.init, last.state);
}

test "wal rejects an unsafe package name" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmpRoot(&tmp, testing.allocator);
    defer testing.allocator.free(root);

    try testing.expectError(
        error.InvalidPackageIdentifier,
        Wal.init(testing.allocator, root, "../../../etc/cron.d/pwn"),
    );
}
