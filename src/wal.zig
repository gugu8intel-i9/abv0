//! Append-only, CRC-checked write-ahead log for install state.
//!
//! The previous `InstallStateMachine` called `createFile` on every transition,
//! which truncates. The "log" therefore only ever held the most recent record
//! and could not support the crash recovery it was documented as providing.
//! Nothing ever read it back.
//!
//! This version appends fixed-width records, checksums each one, and can
//! recover the last durable state after a crash - including discarding a
//! torn trailing record from a partial write. Opening a log scans it once,
//! truncates any torn tail, and restores the sequence counter, so appends
//! always land on a record boundary and sequence numbers keep increasing
//! across process restarts.

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

const state_count = @typeInfo(State).Enum.fields.len;

/// Compaction runs after an append once the log grows past either bound.
const compact_max_records: u32 = 10_000;
const compact_max_bytes: u64 = 1 << 20;

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

/// What one front-to-back pass over the log found.
const Scan = struct {
    /// Last valid record in the file.
    last: ?Record = null,
    /// Byte offset just past the last valid record.
    end: u64 = 0,
    /// Number of valid records.
    count: u32 = 0,
    /// Newest valid record of each state, used by compaction.
    latest: [state_count]?Record = [_]?Record{null} ** state_count,
};

pub const Wal = struct {
    allocator: std.mem.Allocator,
    path: []u8,
    /// Open handle, kept for the life of this Wal. Null only after a failed
    /// compaction or `clear`; `openFile` reopens it on demand.
    file: ?std.fs.File = null,
    /// Sequence number of the last record written or recovered.
    seq: u32 = 0,
    /// Offset where the next record goes (end of the valid log).
    end: u64 = 0,
    /// Valid records currently in the log.
    count: u32 = 0,

    /// `pkg_name` is validated because it becomes a filename. Opening the log
    /// truncates any torn tail and restores the sequence counter.
    pub fn init(allocator: std.mem.Allocator, state_root: []const u8, pkg_name: []const u8) !Wal {
        if (!safepath.isValidId(pkg_name)) return error.InvalidPackageIdentifier;

        const dir = try std.fs.path.join(allocator, &.{ state_root, "states_wal" });
        defer allocator.free(dir);
        std.fs.cwd().makePath(dir) catch {};

        // The original leaked this inner allocPrint by nesting it in path.join.
        const file_name = try std.fmt.allocPrint(allocator, "{s}.wal", .{pkg_name});
        defer allocator.free(file_name);

        const path = try std.fs.path.join(allocator, &.{ dir, file_name });
        var w = Wal{ .allocator = allocator, .path = path };
        errdefer w.deinit();

        const file = try w.openFile();
        const s = try scanFile(file);
        const size = try file.getEndPos();
        if (s.end != size) {
            // A crash left bytes after the last valid record. Appending after
            // them would misalign every later record, so cut them off first.
            try file.setEndPos(s.end);
            try file.sync();
        }
        w.end = s.end;
        w.count = s.count;
        w.seq = if (s.last) |rec| rec.seq else 0;
        return w;
    }

    pub fn deinit(self: *Wal) void {
        self.close();
        self.allocator.free(self.path);
        self.* = undefined;
    }

    /// Append a state transition and flush it to disk before returning.
    pub fn append(self: *Wal, state: State) !void {
        const file = try self.openFile();

        const seq = self.seq +% 1;
        const rec = Record{
            .seq = seq,
            .state = state,
            .timestamp = std.time.timestamp(),
        };
        try file.seekTo(self.end);
        try file.writeAll(&rec.encode());
        try file.sync();

        self.seq = seq;
        self.end += record_size;
        self.count += 1;

        if (self.count > compact_max_records or self.end > compact_max_bytes) {
            // The record above is already durable, so a failed housekeeping
            // pass must not turn this append into an error. The next append
            // retries because the bounds are still exceeded.
            self.compact() catch {};
        }
    }

    /// The last structurally valid record, or null when there is no usable log.
    /// A torn trailing record (partial write during a crash) is ignored.
    pub fn recover(self: *Wal) !?Record {
        const s = try scanFile(try self.openFile());
        return s.last;
    }

    /// True when a previous run died partway through an install.
    pub fn hasUnfinishedInstall(self: *Wal) !bool {
        const last = (try self.recover()) orelse return false;
        return switch (last.state) {
            .complete, .failed => false,
            else => true,
        };
    }

    /// Rewrite the log keeping only the newest record of each state, in seq
    /// order. The new log is written to a temp file, synced, and renamed over
    /// the old one, so a crash leaves either the old or the new log in place.
    /// The newest record overall is always kept, so the recovered state and
    /// the sequence counter are unchanged.
    pub fn compact(self: *Wal) !void {
        const s = try scanFile(try self.openFile());

        var kept: [state_count]Record = undefined;
        var n: usize = 0;
        for (s.latest) |maybe| {
            if (maybe) |rec| {
                kept[n] = rec;
                n += 1;
            }
        }
        std.mem.sort(Record, kept[0..n], {}, lessBySeq);

        const tmp_path = try std.fmt.allocPrint(self.allocator, "{s}.tmp", .{self.path});
        defer self.allocator.free(tmp_path);

        writeRecords(tmp_path, kept[0..n]) catch |e| {
            std.fs.cwd().deleteFile(tmp_path) catch {};
            return e;
        };

        // Windows will not replace a file that is still open.
        self.close();
        std.fs.cwd().rename(tmp_path, self.path) catch |e| {
            std.fs.cwd().deleteFile(tmp_path) catch {};
            return e;
        };

        self.end = @as(u64, n) * record_size;
        self.count = @intCast(n);
    }

    pub fn clear(self: *Wal) void {
        self.close();
        std.fs.cwd().deleteFile(self.path) catch {};
        self.seq = 0;
        self.end = 0;
        self.count = 0;
    }

    fn openFile(self: *Wal) !std.fs.File {
        if (self.file) |f| return f;
        const f = try std.fs.cwd().createFile(self.path, .{
            .read = true,
            .truncate = false,
            .mode = platform.mode_private,
        });
        self.file = f;
        return f;
    }

    fn close(self: *Wal) void {
        if (self.file) |f| f.close();
        self.file = null;
    }
};

/// One buffered pass over the whole log. Records are fixed width, so the
/// offset advances by `record_size` whether or not a record decodes; invalid
/// records are skipped and only the bytes after the last valid one are cut.
fn scanFile(file: std.fs.File) !Scan {
    try file.seekTo(0);
    var br = std.io.bufferedReader(file.reader());
    const reader = br.reader();

    var out = Scan{};
    var offset: u64 = 0;
    var buf: [record_size]u8 = undefined;
    while (true) {
        const n = try reader.readAll(&buf);
        if (n != record_size) break;
        offset += record_size;
        const rec = Record.decode(&buf) orelse continue;
        out.last = rec;
        out.end = offset;
        out.count += 1;
        out.latest[@intFromEnum(rec.state)] = rec;
    }
    return out;
}

fn writeRecords(path: []const u8, recs: []const Record) !void {
    const f = try std.fs.cwd().createFile(path, .{
        .truncate = true,
        .mode = platform.mode_private,
    });
    defer f.close();
    for (recs) |rec| try f.writeAll(&rec.encode());
    try f.sync();
}

fn lessBySeq(_: void, a: Record, b: Record) bool {
    return a.seq < b.seq;
}

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

test "reopen truncates a torn tail, appends stay readable, seq continues" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmpRoot(&tmp, testing.allocator);
    defer testing.allocator.free(root);

    var w = try Wal.init(testing.allocator, root, "fd");
    try w.append(.init);
    try w.append(.fetch);
    try w.append(.verify);

    // Garbage after the last full record, as a crash mid-write would leave.
    {
        const f = try std.fs.cwd().openFile(w.path, .{ .mode = .write_only });
        defer f.close();
        try f.seekFromEnd(0);
        try f.writeAll("\x41\x42\x56\x30\xff\xff\x01");
    }
    w.deinit();

    var reopened = try Wal.init(testing.allocator, root, "fd");
    defer reopened.deinit();

    const stat = try std.fs.cwd().statFile(reopened.path);
    try testing.expectEqual(@as(u64, 3 * record_size), stat.size);

    const last = (try reopened.recover()).?;
    try testing.expectEqual(State.verify, last.state);
    try testing.expectEqual(@as(u32, 3), last.seq);

    try reopened.append(.complete);
    const after = (try reopened.recover()).?;
    try testing.expectEqual(State.complete, after.state);
    try testing.expectEqual(@as(u32, 4), after.seq);
    try testing.expectEqual(@as(u64, 4 * record_size), (try std.fs.cwd().statFile(reopened.path)).size);
}

test "compaction keeps only the newest record of each state" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmpRoot(&tmp, testing.allocator);
    defer testing.allocator.free(root);

    var w = try Wal.init(testing.allocator, root, "rg");
    defer w.deinit();
    try w.append(.init); // seq 1
    try w.append(.fetch); // seq 2
    try w.append(.fetch); // seq 3
    try w.append(.fetch); // seq 4
    try w.append(.verify); // seq 5

    try w.compact();

    // init (seq 1), newest fetch (seq 4), verify (seq 5).
    const stat = try std.fs.cwd().statFile(w.path);
    try testing.expectEqual(@as(u64, 3 * record_size), stat.size);

    const last = (try w.recover()).?;
    try testing.expectEqual(State.verify, last.state);
    try testing.expectEqual(@as(u32, 5), last.seq);

    // Sequence numbers keep counting from the compacted log.
    try w.append(.complete);
    try testing.expectEqual(@as(u32, 6), w.seq);
    try testing.expect(!(try w.hasUnfinishedInstall()));
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
