//! Streaming verified install.
//!
//! The curl path downloads the whole package, hashes it, and only then reads
//! it again to unpack, so install time is download time plus unpack time.
//! Here the bytes are hashed, decompressed and unpacked in one pass as they
//! arrive, into the private staging directory. Nothing is published until the
//! caller has compared the digest with the manifest. A mismatch leaves the
//! staging directory to be deleted, so unverified bytes never reach the store.
//!
//! The transport is curl writing to a pipe, with the same hardened arguments
//! as every other download (https only, no curlrc, size cap, timeouts). That
//! keeps proxies, system CA stores and TLS versions working exactly as they do
//! for the plain download path, so streaming never costs a failed attempt.

const std = @import("std");
const builtin = @import("builtin");
const archive = @import("archive.zig");
const net = @import("net.zig");
const platform = @import("platform.zig");
const safepath = @import("safepath.zig");

const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Read-ahead between the network and the decoder. Same size as archive.zig.
const buffer_size = 64 * 1024;

pub const Result = struct {
    digest: [32]u8,
    bytes: u64,
};

/// Wraps a reader and feeds every byte it hands out into SHA-256.
///
/// Leading bytes can be peeked before the consumer starts. They are read and
/// hashed once, then replayed to the next reads without being hashed again, so
/// a sniff costs no second pass.
pub fn HashingReader(comptime R: type) type {
    return struct {
        const Self = @This();

        pub const Error = R.Error || error{DownloadTooLarge};

        inner: R,
        hasher: Sha256 = Sha256.init(.{}),
        /// Bytes pulled from `inner`. Replayed bytes are not counted again.
        bytes: u64 = 0,
        limit: u64,
        head_buf: [archive.head_len]u8 = undefined,
        head_len: usize = 0,
        head_pos: usize = 0,

        pub fn init(inner: R, limit: u64) Self {
            return .{ .inner = inner, .limit = limit };
        }

        /// Pull up to `archive.head_len` leading bytes and keep them for `read`.
        /// Shorter than that only at end of stream.
        pub fn peekHead(self: *Self) Error![]const u8 {
            while (self.head_len < archive.head_len) {
                const n = try self.pull(self.head_buf[self.head_len..]);
                if (n == 0) break;
                self.head_len += n;
            }
            return self.head_buf[0..self.head_len];
        }

        pub fn read(self: *Self, buf: []u8) Error!usize {
            if (self.head_pos < self.head_len) {
                const take = @min(buf.len, self.head_len - self.head_pos);
                @memcpy(buf[0..take], self.head_buf[self.head_pos..][0..take]);
                self.head_pos += take;
                return take;
            }
            return self.pull(buf);
        }

        /// Final digest. Consumes the hasher, so call it once, after the last read.
        pub fn final(self: *Self) [32]u8 {
            var out: [32]u8 = undefined;
            self.hasher.final(&out);
            return out;
        }

        fn pull(self: *Self, buf: []u8) Error!usize {
            const n = try self.inner.read(buf);
            if (n == 0) return 0;
            // Checked before hashing, so an oversized response is refused
            // without the digest ever covering bytes we will not keep.
            if (n > self.limit - self.bytes) return error.DownloadTooLarge;
            self.bytes += n;
            self.hasher.update(buf[0..n]);
            return n;
        }
    };
}

/// Shared state for one abv0 run. All install workers use the same session.
pub const Session = struct {
    /// Set by the first failed stream. Such a failure is almost always the
    /// environment (no curl, no pipes), so every later package would fail the
    /// same way. The rest of the run then downloads to a file first.
    stream_failed: bool = false,

    pub fn streamingEnabled(self: *const Session) bool {
        return !@atomicLoad(bool, &self.stream_failed, .acquire);
    }

    pub fn disableStreaming(self: *Session) void {
        @atomicStore(bool, &self.stream_failed, true, .release);
    }

    pub fn init(allocator: Allocator) !Session {
        _ = allocator;
        return .{};
    }

    pub fn deinit(self: *Session) void {
        _ = self;
    }
};

/// Download `url` and unpack it into `dest` in one pass. The caller checks the
/// digest before publishing `dest`.
///
/// Every failure returns an error and leaves cleanup to the caller. The caller
/// then falls back to downloading to a file, so these errors are never fatal
/// on their own.
pub fn streamInstall(
    session: *Session,
    a: Allocator,
    url: []const u8,
    declared: archive.Kind,
    raw_name: []const u8,
    dest: std.fs.Dir,
) !Result {
    _ = session;
    // Decided before any connection is made. These formats need a seekable
    // file (zip's central directory, a disk image), so they cannot stream.
    switch (declared) {
        .zip, .dmg => return error.NotStreamable,
        else => {},
    }
    if (!net.isSafeUrl(url)) return error.UnsafeUrl;

    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // No --output: curl writes the body to its stdout, which is our pipe.
    const argv = try net.buildCurlArgv(arena, url, null, .{}, &.{});

    var child = std.process.Child.init(argv, arena);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    // Not piped: nothing drains it while we read stdout, so a chatty curl
    // could block on a full stderr pipe.
    child.stderr_behavior = .Ignore;
    try child.spawn();

    const result = unpackStream(a, child.stdout.?.reader(), declared, raw_name, dest) catch |e| {
        // Stop the transfer; its bytes are no longer wanted.
        _ = child.kill() catch {};
        return e;
    };

    // A transfer cut short ends the stream early. The digest would not match
    // either, but this reports the real cause.
    const term = try child.wait();
    switch (term) {
        .Exited => |code| if (code != 0) return error.DownloadFailed,
        else => return error.DownloadFailed,
    }
    return result;
}

/// Everything after the transfer starts: hash, sniff, decode and unpack `reader`.
/// Split out so the tests can drive it with an in-memory payload.
pub fn unpackStream(
    a: Allocator,
    reader: anytype,
    declared: archive.Kind,
    raw_name: []const u8,
    dest: std.fs.Dir,
) !Result {
    var hashing = HashingReader(@TypeOf(reader)).init(reader, net.max_download_bytes);

    // Peeking is free: these bytes are replayed, not read twice.
    const head = try hashing.peekHead();
    if (archive.looksLikeErrorPageBytes(head)) return error.DownloadLooksLikeErrorPage;

    // Same rule as the curl path: the bytes beat the manifest, except for raw
    // and dmg, which keep what was declared.
    const kind = if (declared == .raw or declared == .dmg)
        declared
    else
        archive.sniffBytes(head) orelse declared;
    switch (kind) {
        .zip, .dmg => return error.NotStreamable,
        else => {},
    }

    // The hasher is the buffered reader's unbuffered source, so it can be read
    // back out for the digest afterwards.
    var buffered = std.io.bufferedReaderSize(buffer_size, hashing);
    const src = buffered.reader();
    const opts: archive.Options = .{ .raw_name = raw_name };

    var scratch: [buffer_size]u8 = undefined;
    switch (kind) {
        .raw => {
            if (!safepath.isSafeRelPath(raw_name)) return error.UnsafePath;
            if (std.fs.path.dirname(raw_name)) |d| dest.makePath(d) catch {};
            const out = try dest.createFile(raw_name, .{ .mode = platform.mode_bin });
            defer out.close();
            while (true) {
                const n = try src.read(&scratch);
                if (n == 0) break;
                try out.writeAll(scratch[0..n]);
            }
        },
        .tar => try archive.pipeTar(a, src, dest, opts),
        .tar_gz => {
            var dec = std.compress.gzip.decompressor(src);
            try archive.pipeTar(a, dec.reader(), dest, opts);
        },
        .tar_xz => {
            var dec = try std.compress.xz.decompress(a, src);
            defer dec.deinit();
            try archive.pipeTar(a, dec.reader(), dest, opts);
        },
        .tar_zst => {
            const window = try a.alloc(u8, 1 << 23);
            defer a.free(window);
            var dec = std.compress.zstd.decompressor(src, .{ .window_buffer = window });
            try archive.pipeTar(a, dec.reader(), dest, opts);
        },
        .zip, .dmg => unreachable,
    }

    // The extractor stops at the archive's end marker, but the response may
    // still hold padding or a trailer. Those bytes must pass through the hash
    // too, or the digest would not cover the whole download.
    while (try src.read(&scratch) != 0) {}

    return .{
        .digest = buffered.unbuffered_reader.final(),
        .bytes = buffered.unbuffered_reader.bytes,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn digestOf(data: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    Sha256.hash(data, &out, .{});
    return out;
}

/// Drain `reader` through `hr` into a buffer and return what came out.
fn drainAll(a: Allocator, hr: anytype) ![]u8 {
    var out = std.ArrayList(u8).init(a);
    errdefer out.deinit();
    var buf: [1000]u8 = undefined; // odd size, so reads straddle the peek
    while (true) {
        const n = try hr.read(&buf);
        if (n == 0) break;
        try out.appendSlice(buf[0..n]);
    }
    return out.toOwnedSlice();
}

test "HashingReader digest equals SHA-256 of everything it hands out" {
    const data = try testing.allocator.alloc(u8, 300 * 1024 + 17);
    defer testing.allocator.free(data);
    for (data, 0..) |*b, i| b.* = @truncate(i *% 131 +% (i >> 8));

    var fbs = std.io.fixedBufferStream(data);
    var hr = HashingReader(@TypeOf(fbs.reader())).init(fbs.reader(), net.max_download_bytes);
    const got = try drainAll(testing.allocator, &hr);
    defer testing.allocator.free(got);

    try testing.expectEqualSlices(u8, data, got);
    try testing.expectEqual(@as(u64, data.len), hr.bytes);
    const digest = hr.final();
    try testing.expectEqualSlices(u8, &digestOf(data), &digest);
}

test "HashingReader replays peeked bytes without hashing them twice" {
    const data = "0123456789" ** 100; // 1000 bytes, more than the peek
    var fbs = std.io.fixedBufferStream(@as([]const u8, data));
    var hr = HashingReader(@TypeOf(fbs.reader())).init(fbs.reader(), net.max_download_bytes);

    const head = try hr.peekHead();
    try testing.expectEqual(archive.head_len, head.len);
    try testing.expectEqualSlices(u8, data[0..archive.head_len], head);

    const got = try drainAll(testing.allocator, &hr);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, data, got);
    try testing.expectEqual(@as(u64, data.len), hr.bytes);
    const digest = hr.final();
    try testing.expectEqualSlices(u8, &digestOf(data), &digest);
}

test "HashingReader refuses a payload past its size cap" {
    const data = "x" ** 100;
    var fbs = std.io.fixedBufferStream(@as([]const u8, data));
    var hr = HashingReader(@TypeOf(fbs.reader())).init(fbs.reader(), 10);
    try testing.expectError(error.DownloadTooLarge, drainAll(testing.allocator, &hr));
}

test "one failed stream turns streaming off for the rest of the session" {
    var session = try Session.init(testing.allocator);
    defer session.deinit();
    try testing.expect(session.streamingEnabled());
    session.disableStreaming();
    try testing.expect(!session.streamingEnabled());
}

test "streamInstall refuses zip and dmg before touching the network" {
    var session = try Session.init(testing.allocator);
    defer session.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // The host is unroutable on purpose: a request would hang or fail
    // differently, so NotStreamable proves nothing was attempted.
    try testing.expectError(
        error.NotStreamable,
        streamInstall(&session, testing.allocator, "https://192.0.2.1/x.zip", .zip, "x", tmp.dir),
    );
    try testing.expectError(
        error.NotStreamable,
        streamInstall(&session, testing.allocator, "https://192.0.2.1/x.dmg", .dmg, "x", tmp.dir),
    );
}

/// A one-member ustar archive, written in the same shape archive.zig's tests use.
fn tarOneFile(a: Allocator, name: []const u8, content: []const u8) ![]u8 {
    var list = std.ArrayList(u8).init(a);
    errdefer list.deinit();
    const w = list.writer();

    var header = [_]u8{0} ** 512;
    @memcpy(header[0..name.len], name);
    _ = try std.fmt.bufPrint(header[100..108], "{o:0>7}\x00", .{@as(u32, 0o755)});
    _ = try std.fmt.bufPrint(header[108..116], "0000000\x00", .{});
    _ = try std.fmt.bufPrint(header[116..124], "0000000\x00", .{});
    _ = try std.fmt.bufPrint(header[124..136], "{o:0>11} ", .{content.len});
    _ = try std.fmt.bufPrint(header[136..148], "{o:0>11} ", .{@as(u64, 0)});
    header[156] = '0';
    @memcpy(header[257..262], "ustar");
    header[263] = '0';
    header[264] = '0';
    @memset(header[148..156], ' ');
    var sum: u32 = 0;
    for (header) |b| sum += b;
    _ = try std.fmt.bufPrint(header[148..156], "{o:0>6}\x00 ", .{sum});

    try w.writeAll(&header);
    try w.writeAll(content);
    try w.writeByteNTimes(0, (512 - (content.len % 512)) % 512);
    try w.writeByteNTimes(0, 1024); // end-of-archive
    return list.toOwnedSlice();
}

test "a tar.gz streamed through unpackStream extracts the file and hashes every byte" {
    const content = "#!/bin/sh\necho streamed\n";
    const tar_bytes = try tarOneFile(testing.allocator, "pkg-1.0/bin/tool", content);
    defer testing.allocator.free(tar_bytes);

    var gz = std.ArrayList(u8).init(testing.allocator);
    defer gz.deinit();
    {
        var comp = try std.compress.gzip.compressor(gz.writer(), .{});
        try comp.writer().writeAll(tar_bytes);
        try comp.finish();
    }
    // Bytes after the gzip member are still part of the download, so the digest must cover them.
    try gz.appendNTimes(0, 4096);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var fbs = std.io.fixedBufferStream(@as([]const u8, gz.items));
    const res = try unpackStream(testing.allocator, fbs.reader(), .tar_gz, "tool", tmp.dir);

    try testing.expectEqualSlices(u8, &digestOf(gz.items), &res.digest);
    try testing.expectEqual(@as(u64, gz.items.len), res.bytes);

    const extracted = try tmp.dir.readFileAlloc(testing.allocator, "pkg-1.0/bin/tool", 1024);
    defer testing.allocator.free(extracted);
    try testing.expectEqualStrings(content, extracted);
}

test "unpackStream refuses an HTML error page before decoding anything" {
    const page = "<!DOCTYPE html><html><body>404: Not Found</body></html>";
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var fbs = std.io.fixedBufferStream(@as([]const u8, page));
    try testing.expectError(
        error.DownloadLooksLikeErrorPage,
        unpackStream(testing.allocator, fbs.reader(), .tar_gz, "tool", tmp.dir),
    );
}

test "unpackStream trusts the bytes over the manifest and refuses a zip in disguise" {
    const zip_head = "PK\x03\x04" ++ "\x00" ** 300;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var fbs = std.io.fixedBufferStream(@as([]const u8, zip_head));
    try testing.expectError(
        error.NotStreamable,
        unpackStream(testing.allocator, fbs.reader(), .tar_gz, "tool", tmp.dir),
    );
}

test "unpackStream keeps a raw payload whole and executable" {
    const data = "\x7fELF-not-really" ** 100;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var fbs = std.io.fixedBufferStream(@as([]const u8, data));
    const res = try unpackStream(testing.allocator, fbs.reader(), .raw, "rg", tmp.dir);
    try testing.expectEqualSlices(u8, &digestOf(data), &res.digest);

    const got = try tmp.dir.readFileAlloc(testing.allocator, "rg", 1 << 20);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, data, got);
}
