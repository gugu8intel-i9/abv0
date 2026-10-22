//! In-process, sandboxed archive extraction.
//!
//! Previously extraction shelled out to `tar`, `unzip` and `hdiutil`. That was
//! slow (a fork+exec per install), unavailable on Windows (`unzip` does not
//! ship there), and unsafe: nothing validated member paths, so a malicious
//! tarball could write outside the store via `../` members or via a symlink
//! pointing out of the extraction root.
//!
//! Every member name is now checked with `safepath` before it touches the
//! filesystem, and symlink targets are resolved against the extraction root.

const std = @import("std");
const builtin = @import("builtin");
const safepath = @import("safepath.zig");
const platform = @import("platform.zig");
const sevenzip = @import("sevenzip.zig");
pub const inflate = @import("inflate.zig");

pub const Kind = enum {
    tar,
    tar_gz,
    tar_xz,
    tar_zst,
    zip,
    raw,
    dmg,
    sevenz,

    pub fn fromString(s: []const u8) ?Kind {
        const table = .{
            .{ "tar", Kind.tar },
            .{ "tar.gz", Kind.tar_gz },
            .{ "tgz", Kind.tar_gz },
            .{ "tar.xz", Kind.tar_xz },
            .{ "txz", Kind.tar_xz },
            .{ "tar.zst", Kind.tar_zst },
            .{ "zip", Kind.zip },
            .{ "raw", Kind.raw },
            .{ "dmg", Kind.dmg },
            .{ "7z", Kind.sevenz },
        };
        inline for (table) |pair| {
            if (std.mem.eql(u8, s, pair[0])) return pair[1];
        }
        return null;
    }

    pub fn fromFilename(name: []const u8) ?Kind {
        const table = .{
            .{ ".tar.gz", Kind.tar_gz },
            .{ ".tgz", Kind.tar_gz },
            .{ ".tar.xz", Kind.tar_xz },
            .{ ".txz", Kind.tar_xz },
            .{ ".tar.zst", Kind.tar_zst },
            .{ ".tar", Kind.tar },
            .{ ".zip", Kind.zip },
            .{ ".dmg", Kind.dmg },
            .{ ".7z", Kind.sevenz },
        };
        inline for (table) |pair| {
            if (std.mem.endsWith(u8, name, pair[0])) return pair[1];
        }
        return null;
    }
};

/// Leading payload bytes that the sniff and error-page checks need. The tar
/// magic sits at offset 257, so sniffing needs 262 of them.
pub const head_len = 512;

/// The error-page check looks at this many leading bytes and no further.
const error_page_probe_len = 256;

const error_page_markers = [_][]const u8{ "<!DOCTYPE", "<!doctype", "<html", "<HTML", "404: Not Found", "Not Found" };

/// What the bytes on disk actually are, regardless of what the manifest claims.
///
/// This catches the common failure where a CDN returns an HTML error page and
/// the package manager cheerfully installs it as an executable.
pub fn sniff(path: []const u8) ?Kind {
    const file = std.fs.cwd().openFile(path, .{}) catch return null;
    defer file.close();

    var head: [head_len]u8 = undefined;
    const n = file.readAll(&head) catch return null;
    return sniffBytes(head[0..n]);
}

/// `sniff` on the leading bytes of a payload that is already in memory.
pub fn sniffBytes(buf: []const u8) ?Kind {
    const n = buf.len;
    if (n >= 2 and buf[0] == 0x1f and buf[1] == 0x8b) return .tar_gz;
    if (n >= 6 and std.mem.eql(u8, buf[0..6], &.{ 0xFD, '7', 'z', 'X', 'Z', 0x00 })) return .tar_xz;
    if (n >= 4 and std.mem.eql(u8, buf[0..4], &.{ 0x28, 0xB5, 0x2F, 0xFD })) return .tar_zst;
    if (n >= 4 and std.mem.eql(u8, buf[0..4], &.{ 'P', 'K', 0x03, 0x04 })) return .zip;
    if (n >= sevenzip.magic.len and std.mem.eql(u8, buf[0..sevenzip.magic.len], &sevenzip.magic)) return .sevenz;
    if (n >= 262 and std.mem.eql(u8, buf[257..262], "ustar")) return .tar;
    return null;
}

/// True when the payload is obviously an HTML/text error page rather than a
/// binary or archive.
pub fn looksLikeErrorPage(path: []const u8) bool {
    const file = std.fs.cwd().openFile(path, .{}) catch return false;
    defer file.close();

    var head: [head_len]u8 = undefined;
    const n = file.readAll(&head) catch return false;
    return looksLikeErrorPageBytes(head[0..n]);
}

/// `looksLikeErrorPage` on the leading bytes of a payload already in memory.
/// Only the first `error_page_probe_len` bytes are examined.
pub fn looksLikeErrorPageBytes(head: []const u8) bool {
    if (head.len == 0) return true; // a zero-byte "binary" is never valid

    const buf = head[0..@min(head.len, error_page_probe_len)];
    for (error_page_markers) |m| {
        if (std.mem.indexOf(u8, buf, m) != null) return true;
    }
    return false;
}

/// Upper bounds on what one archive may expand to. A few kilobytes of gzip can
/// claim terabytes of output, so extraction stops once either limit is passed.
pub const max_extract_bytes: u64 = 4 * 1024 * 1024 * 1024;
pub const max_extract_members: usize = 200_000;

pub const Options = struct {
    /// Destination name for `raw` payloads (a bare executable, not an archive).
    raw_name: []const u8 = "payload",
    /// Directory levels to strip from member paths.
    strip_components: u32 = 0,
    /// Total member bytes allowed before extraction is refused.
    max_bytes: u64 = max_extract_bytes,
    /// Member count allowed before extraction is refused.
    max_members: usize = max_extract_members,
};

/// Extract `archive_path` into `dest_dir_path`.
pub fn extract(
    allocator: std.mem.Allocator,
    kind: Kind,
    archive_path: []const u8,
    dest_dir_path: []const u8,
    options: Options,
) !void {
    var dest = try std.fs.cwd().openDir(dest_dir_path, .{});
    defer dest.close();

    switch (kind) {
        .raw => {
            if (!safepath.isSafeRelPath(options.raw_name)) return error.UnsafePath;
            if (std.fs.path.dirname(options.raw_name)) |d| dest.makePath(d) catch {};
            const dst = try std.fs.path.join(allocator, &.{ dest_dir_path, options.raw_name });
            defer allocator.free(dst);
            try std.fs.cwd().rename(archive_path, dst);
            platform.setExecutable(dst);
        },
        .zip => {
            const file = try std.fs.cwd().openFile(archive_path, .{});
            defer file.close();
            try extractZip(allocator, file, dest, options);
        },
        .tar, .tar_gz, .tar_xz, .tar_zst => try extractTar(allocator, kind, archive_path, dest, options),
        .dmg => try extractDmg(allocator, archive_path, dest_dir_path),
        .sevenz => {
            // 7z finds its streams by offset, so it needs the file itself.
            const file = try std.fs.cwd().openFile(archive_path, .{});
            defer file.close();
            try sevenzip.extract(allocator, file, dest, options);
        },
    }
}

fn extractTar(
    allocator: std.mem.Allocator,
    kind: Kind,
    archive_path: []const u8,
    dest: std.fs.Dir,
    options: Options,
) !void {
    const file = try std.fs.cwd().openFile(archive_path, .{});
    defer file.close();

    var buffered = std.io.bufferedReaderSize(read_buf_len, file.reader());
    const src = buffered.reader();

    switch (kind) {
        .tar => try pipeTar(allocator, src, dest, options),
        .tar_gz => {
            // The decoder buffers its own input; a second buffer would only add a copy.
            var dec = try inflate.gzip(allocator, file.reader());
            defer dec.deinit();
            try pipeTar(allocator, dec.reader(), dest, options);
        },
        .tar_xz => {
            var dec = try std.compress.xz.decompress(allocator, src);
            defer dec.deinit();
            try pipeTar(allocator, dec.reader(), dest, options);
        },
        .tar_zst => {
            const window = try allocator.alloc(u8, 1 << 23);
            defer allocator.free(window);
            var dec = std.compress.zstd.decompressor(src, .{ .window_buffer = window });
            try pipeTar(allocator, dec.reader(), dest, options);
        },
        else => unreachable,
    }
}

const ZipStream = @TypeOf(@as(std.fs.File, undefined).seekableStream());
const ZipIterator = std.zip.Iterator(ZipStream);

/// One central-directory record that passed validation. `name` lives in the
/// extraction's arena.
const ZipJob = struct {
    entry: ZipIterator.Entry,
    name: []const u8,
    /// Mode for a regular file: one of two fixed values, never setuid/setgid.
    mode: std.fs.File.Mode,
    /// The entry is a Unix symlink; its content is the link target.
    is_link: bool,

    fn isDir(self: ZipJob) bool {
        return self.name[self.name.len - 1] == '/';
    }
};

/// Below this much uncompressed data a thread pool costs more than it saves.
const zip_parallel_min_bytes: u64 = 512 * 1024;
const zip_max_workers = 8;

/// A symlink target longer than this is refused (PATH_MAX is 4096 on Linux).
const zip_max_link_len = 4096;

/// Test hook: lets unit tests force the threaded path on small archives.
var zip_parallel_min_bytes_override: ?u64 = null;

const s_ifmt: u32 = 0o170000;
const s_iflnk: u32 = 0o120000;
const zip_host_unix: u16 = 3;

/// Read the whole central directory first, because std.zip has no limits of its
/// own and cannot skip a member. Refuse the archive, before anything is written,
/// when it is over the limits or when ANY name is not a plain relative path.
///
/// std.zip only rejects a leading '/' and `..` components. A name such as
/// `C:/Users/x/Startup/x.cmd` passes that check. On Windows, `Dir.createFile`
/// treats a drive-absolute path as absolute and ignores the directory handle,
/// so the file would land outside the store.
fn collectZipJobs(
    arena: std.mem.Allocator,
    file: std.fs.File,
    options: Options,
    total_uncompressed: *u64,
) ![]ZipJob {
    var iter = try ZipIterator.init(file.seekableStream());

    const hdr_len = @sizeOf(std.zip.CentralDirectoryFileHeader);
    var jobs = std.ArrayList(ZipJob).init(arena);
    var rec_buf: [hdr_len + std.fs.MAX_PATH_BYTES]u8 = undefined;
    var total: u64 = 0;
    while (try iter.next()) |entry| {
        if (jobs.items.len >= options.max_members) return error.ArchiveTooManyMembers;
        total +|= entry.uncompressed_size;
        if (total > options.max_bytes) return error.ArchiveTooLarge;

        // Read the record from the same offset that std.zip.extract uses: the
        // fixed header (for the Unix mode) and the name behind it.
        if (entry.filename_len > rec_buf.len - hdr_len) return error.UnsafeArchiveMember;
        const rec = rec_buf[0 .. hdr_len + entry.filename_len];
        if ((try file.preadAll(rec, entry.header_zip_offset)) != rec.len) return error.ZipTruncated;
        const name = rec[hdr_len..];

        // Backslashes are rejected too. std.zip would refuse them by default,
        // but this makes the whole archive fail the same way.
        if (!safepath.isSafeRelPath(name) or hasColon(name) or
            std.mem.indexOfScalar(u8, name, '\\') != null)
        {
            return error.UnsafeArchiveMember;
        }

        // Unix permissions live in the high half of the external attributes,
        // but only when the archive says a Unix system wrote it.
        const version_made_by = std.mem.readInt(u16, rec[4..6], .little);
        const external_attrs = std.mem.readInt(u32, rec[38..42], .little);
        const unix_mode: u32 = if ((version_made_by >> 8) == zip_host_unix) external_attrs >> 16 else 0;
        const is_dir = name[name.len - 1] == '/';
        const is_link = !is_dir and (unix_mode & s_ifmt) == s_iflnk;
        // Only the owner-exec bit decides; setuid, setgid, sticky and the
        // write bits are never carried over.
        const mode: std.fs.File.Mode = if (std.fs.has_executable_bit and (unix_mode & 0o111) != 0)
            platform.mode_bin
        else
            platform.mode_public;

        try jobs.append(.{
            .entry = entry,
            .name = try arena.dupe(u8, name),
            .mode = mode,
            .is_link = is_link,
        });
    }
    total_uncompressed.* = total;
    return jobs.items;
}

/// Reads a byte range of the archive with `pread`, so any number of threads can
/// share one file handle without fighting over its offset.
const PreadRange = struct {
    file: std.fs.File,
    pos: u64,
    end: u64,

    const Error = std.fs.File.PReadError;
    const Reader = std.io.GenericReader(*PreadRange, Error, read);

    fn read(self: *PreadRange, buf: []u8) Error!usize {
        if (self.pos >= self.end) return 0;
        const want: usize = @intCast(@min(@as(u64, buf.len), self.end - self.pos));
        const n = try self.file.pread(buf[0..want], self.pos);
        self.pos += n;
        return n;
    }

    fn reader(self: *PreadRange) Reader {
        return .{ .context = self };
    }
};

/// Per-thread buffers, allocated up front on the caller's thread because the
/// caller's allocator need not be thread-safe.
const ZipInflater = inflate.Raw(PreadRange.Reader);

const ZipScratch = struct {
    in: []u8,
    out: []u8,
    inflater: *ZipInflater,
};

/// Batches decoded chunks into large writes on a file.
const FileSink = struct {
    file: std.fs.File,
    buf: []u8,
    fill: usize = 0,

    fn put(self: *FileSink, chunk: []const u8) !void {
        if (chunk.len >= self.buf.len) {
            try self.flush();
            return self.file.writeAll(chunk);
        }
        if (self.fill + chunk.len > self.buf.len) try self.flush();
        @memcpy(self.buf[self.fill..][0..chunk.len], chunk);
        self.fill += chunk.len;
    }

    fn flush(self: *FileSink) !void {
        if (self.fill > 0) try self.file.writeAll(self.buf[0..self.fill]);
        self.fill = 0;
    }
};

/// Collects a small entry (a symlink target) in memory.
const MemSink = struct {
    buf: []u8,
    len: usize = 0,

    fn put(self: *MemSink, chunk: []const u8) !void {
        if (self.len + chunk.len > self.buf.len) return error.UnsafeArchiveMember;
        @memcpy(self.buf[self.len..][0..chunk.len], chunk);
        self.len += chunk.len;
    }
};

fn readLocalHeader(file: std.fs.File, offset: u64) !std.zip.LocalFileHeader {
    var bytes: [@sizeOf(std.zip.LocalFileHeader)]u8 = undefined;
    const n = try file.preadAll(&bytes, offset);
    if (n != bytes.len) return error.ZipBadFileOffset;
    var h: std.zip.LocalFileHeader = undefined;
    @memcpy(std.mem.asBytes(&h), &bytes);
    if (builtin.cpu.arch.endian() != .little) std.mem.byteSwapAllFields(std.zip.LocalFileHeader, &h);
    return h;
}

/// Decode one entry into `sink`. The consistency checks are the ones
/// std.zip.extract makes between the central and the local header, and the
/// size and CRC checks are the ones `std.zip.decompress` and `std.zip.extract`
/// make, so a corrupt member fails exactly as it did before.
fn decodeZipEntry(file: std.fs.File, entry: ZipIterator.Entry, scratch: ZipScratch, sink: anytype) !void {
    const local = try readLocalHeader(file, entry.file_offset);
    if (!std.mem.eql(u8, &local.signature, &std.zip.local_file_header_sig)) return error.ZipBadFileOffset;
    if (local.version_needed_to_extract != entry.version_needed_to_extract) return error.ZipMismatchVersionNeeded;
    if (local.last_modification_time != entry.last_modification_time) return error.ZipMismatchModTime;
    if (local.last_modification_date != entry.last_modification_date) return error.ZipMismatchModDate;
    if (@as(u16, @bitCast(local.flags)) != @as(u16, @bitCast(entry.flags))) return error.ZipMismatchFlags;
    if (local.crc32 != 0 and local.crc32 != entry.crc32) return error.ZipMismatchCrc32;
    if (local.compressed_size != 0 and local.compressed_size != entry.compressed_size) return error.ZipMismatchCompLen;
    if (local.uncompressed_size != 0 and local.uncompressed_size != entry.uncompressed_size) return error.ZipMismatchUncompLen;
    if (local.filename_len != entry.filename_len) return error.ZipMismatchFilenameLen;

    const data_offset = entry.file_offset + @sizeOf(std.zip.LocalFileHeader) +
        @as(u64, local.filename_len) + @as(u64, local.extra_len);

    var range: PreadRange = .{ .file = file, .pos = data_offset, .end = data_offset + entry.compressed_size };
    var crc = inflate.Crc32.init();
    var total: u64 = 0;
    const in_buf = scratch.in;

    switch (entry.compression_method) {
        .store => {
            while (true) {
                const n = try range.reader().read(in_buf);
                if (n == 0) break;
                try sink.put(in_buf[0..n]);
                crc.update(in_buf[0..n]);
                total += n;
            }
        },
        .deflate => {
            const inf = scratch.inflater;
            inf.reset(range.reader());
            while (try inf.nextChunk()) |chunk| {
                crc.update(chunk);
                total += chunk.len;
                if (total > entry.uncompressed_size) return error.ZipUncompressSizeTooSmall;
                try sink.put(chunk);
            }
            if (inf.unreadBytes() != 0) return error.ZipDeflateTruncated;
        },
        _ => return error.UnsupportedCompressionMethod,
    }
    if (total != entry.uncompressed_size) return error.ZipUncompressSizeMismatch;
    if (range.pos != range.end) return error.ZipDecompressTruncated;
    if (crc.final() != entry.crc32) return error.ZipCrcMismatch;
}

fn extractZipFile(file: std.fs.File, dest: std.fs.Dir, job: ZipJob, scratch: ZipScratch) !void {
    // `exclusive` also means an existing entry, link or not, is never opened.
    const out = try dest.createFile(job.name, .{ .exclusive = true, .mode = job.mode });
    defer out.close();
    var sink: FileSink = .{ .file = out, .buf = scratch.out };
    try decodeZipEntry(file, job.entry, scratch, &sink);
    try sink.flush();
}

/// Create a symlink entry. Runs after every file is written, on one thread, with
/// the same checks the tar path makes: the target text must stay inside the
/// root, must not walk through a link already on disk, and the link's own
/// parent directories have been proven to be real directories. A link that
/// fails any check is skipped, like a tar member would be.
fn extractZipLink(
    allocator: std.mem.Allocator,
    file: std.fs.File,
    dest: std.fs.Dir,
    dirs: *DirCache,
    job: ZipJob,
    scratch: ZipScratch,
) !void {
    if (job.entry.uncompressed_size == 0 or job.entry.uncompressed_size > zip_max_link_len) return;
    var target_buf: [zip_max_link_len]u8 = undefined;
    var sink: MemSink = .{ .buf = &target_buf };
    try decodeZipEntry(file, job.entry, scratch, &sink);
    const target = target_buf[0..sink.len];

    const name = job.name;
    const link_dir = std.fs.path.dirname(name) orelse "";
    if (!safepath.symlinkStaysInside(link_dir, target)) return;
    if (try targetCrossesSymlink(allocator, dest, dirs, link_dir, target)) return;
    if (link_dir.len > 0 and !dirs.ensure(dest, link_dir)) return;
    dest.symLink(target, name, .{}) catch return;
    dirs.remove(name);
}

const ZipWork = struct {
    file: std.fs.File,
    dest: std.fs.Dir,
    jobs: []const ZipJob,
    /// Indices into `jobs` of the file entries, largest first so the long
    /// pole starts early.
    order: []const u32,
    next: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    failed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    mutex: std.Thread.Mutex = .{},
    err: ?anyerror = null,

    fn fail(self: *ZipWork, e: anyerror) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.err == null) self.err = e;
        self.failed.store(true, .release);
    }

    fn run(self: *ZipWork, scratch: ZipScratch) void {
        while (!self.failed.load(.acquire)) {
            const i = self.next.fetchAdd(1, .monotonic);
            if (i >= self.order.len) return;
            extractZipFile(self.file, self.dest, self.jobs[self.order[i]], scratch) catch |e| {
                self.fail(e);
                return;
            };
        }
    }
};

fn zipSizeDesc(jobs: []const ZipJob, a: u32, b: u32) bool {
    return jobs[a].entry.uncompressed_size > jobs[b].entry.uncompressed_size;
}

/// Extract a zip. Names are validated up front; directories are created (and
/// checked for links) by this thread; the file entries are independent, each
/// its own deflate stream, so they are decoded by a small pool of threads.
/// Symlink entries are created last, one at a time.
fn extractZip(allocator: std.mem.Allocator, file: std.fs.File, dest: std.fs.Dir, options: Options) !void {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var total: u64 = 0;
    const jobs = try collectZipJobs(arena, file, options, &total);

    // Directories first, so the workers never create one concurrently.
    var dirs = DirCache.init(allocator);
    defer dirs.deinit();
    var order = std.ArrayList(u32).init(arena);
    var links = std.ArrayList(u32).init(arena);
    for (jobs, 0..) |job, i| {
        if (job.isDir()) {
            // std.zip refuses a directory entry that claims content.
            if (job.entry.uncompressed_size != 0) return error.ZipBadDirectorySize;
            if (!dirs.ensure(dest, job.name)) return error.UnsafeArchiveMember;
        } else {
            if (std.fs.path.dirname(job.name)) |d| {
                if (!dirs.ensure(dest, d)) return error.UnsafeArchiveMember;
            }
            const list = if (job.is_link) &links else &order;
            try list.append(@intCast(i));
        }
    }
    std.mem.sort(u32, order.items, jobs, zipSizeDesc);

    const min_bytes = zip_parallel_min_bytes_override orelse zip_parallel_min_bytes;
    const cpus = std.Thread.getCpuCount() catch 1;
    var workers: usize = @min(@min(cpus, zip_max_workers), @max(order.items.len, 1));
    if (total < min_bytes or builtin.single_threaded) workers = 1;

    // One set of buffers per worker, allocated here: `allocator` need not be
    // safe to call from several threads.
    const bufs = try allocator.alloc(u8, workers * 2 * copy_buf_len);
    defer allocator.free(bufs);
    var inflaters: [zip_max_workers]ZipInflater = undefined;
    var made: usize = 0;
    defer for (inflaters[0..made]) |*inf| inf.deinit();
    var scratches: [zip_max_workers]ZipScratch = undefined;
    for (0..workers) |w| {
        inflaters[w] = try ZipInflater.initSized(allocator, .{ .context = undefined }, 512 * 1024);
        made += 1;
        scratches[w] = .{
            .in = bufs[w * 2 * copy_buf_len ..][0..copy_buf_len],
            .out = bufs[w * 2 * copy_buf_len + copy_buf_len ..][0..copy_buf_len],
            .inflater = &inflaters[w],
        };
    }

    var work: ZipWork = .{ .file = file, .dest = dest, .jobs = jobs, .order = order.items };

    var threads: [zip_max_workers]std.Thread = undefined;
    var spawned: usize = 0;
    // Worker 0 is this thread. A failed spawn just means fewer helpers.
    while (spawned + 1 < workers) : (spawned += 1) {
        threads[spawned] = std.Thread.spawn(.{}, ZipWork.run, .{ &work, scratches[spawned + 1] }) catch break;
    }
    work.run(scratches[0]);
    for (threads[0..spawned]) |t| t.join();

    if (work.err) |e| return e;

    for (links.items) |i| try extractZipLink(allocator, file, dest, &dirs, jobs[i], scratches[0]);
}

/// True when a member name contains a ':'. On Windows that is a drive prefix
/// (`C:x`) or an NTFS alternate data stream (`a.exe:evil`). `isSafeRelPath`
/// only looks at the second byte, so it does not catch these.
fn hasColon(name: []const u8) bool {
    return std.mem.indexOfScalar(u8, name, ':') != null;
}

/// Drop leading `./` components (and the bare `.` root entry).
pub fn stripDotPrefix(path: []const u8) []const u8 {
    var p = path;
    while (std.mem.startsWith(u8, p, "./")) {
        p = p[2..];
        while (p.len > 0 and p[0] == '/') p = p[1..];
    }
    if (std.mem.eql(u8, p, ".")) return p[1..];
    return p;
}

pub fn stripComponents(path: []const u8, count: u32) []const u8 {
    var i: usize = 0;
    var c = count;
    while (c > 0) : (c -= 1) {
        if (std.mem.indexOfScalarPos(u8, path, i, '/')) |pos| {
            i = pos + 1;
        } else {
            return path[path.len..];
        }
    }
    return path[i..];
}

/// Size of the read buffer in front of every decompressor. The std default is
/// 4 KiB, which turns a 40 MB download into ten thousand `read` calls.
pub const read_buf_len = 256 * 1024;

/// File content is copied through one buffer of this size, so a member of up to
/// 256 KiB costs one `read` and one `write`. std.tar copies 4 KiB at a time.
const copy_buf_len = 256 * 1024;

/// Path separators that matter for the host's filesystem calls. A backslash is
/// an ordinary file-name character everywhere except Windows.
const path_seps: []const u8 = if (builtin.os.tag == .windows) "/\\" else "/";

/// Directories that this extraction has already proven to be real (non-link)
/// directories under the root: either it created them, or it found them on disk
/// and `isLinkOnDisk` said no. A member whose parent is in the set needs no
/// further per-component link checks, so each directory is checked once rather
/// than once per member below it.
///
/// Only positive facts are cached. Nothing is removed from disk during
/// extraction, and a symlink member cannot be created over an existing entry,
/// so a cached directory cannot turn into a link behind our back. The set is
/// still told about every link it creates, as a second line of defence.
const DirCache = struct {
    arena: std.heap.ArenaAllocator,
    set: std.StringHashMapUnmanaged(void) = .{},
    key_bytes: usize = 0,

    /// The cache is an optimisation, so it stops growing rather than letting a
    /// hostile archive with huge directory names spend our memory.
    const max_entries = 32 * 1024;
    const max_key_bytes = 8 * 1024 * 1024;

    fn init(allocator: std.mem.Allocator) DirCache {
        return .{ .arena = std.heap.ArenaAllocator.init(allocator) };
    }

    fn deinit(self: *DirCache) void {
        self.set.deinit(self.arena.child_allocator);
        self.arena.deinit();
    }

    fn has(self: *const DirCache, path: []const u8) bool {
        return self.set.contains(path);
    }

    fn add(self: *DirCache, path: []const u8) void {
        if (self.set.count() >= max_entries or self.key_bytes + path.len > max_key_bytes) return;
        if (self.set.contains(path)) return;
        const key = self.arena.allocator().dupe(u8, path) catch return;
        self.set.put(self.arena.child_allocator, key, {}) catch return;
        self.key_bytes += key.len;
    }

    fn remove(self: *DirCache, path: []const u8) void {
        _ = self.set.remove(path);
    }

    /// Make `dir` (a relative path, possibly with a trailing separator) exist as
    /// a chain of real directories under `dest`. False when some component is a
    /// symlink already on disk, or when a component cannot be created.
    fn ensure(self: *DirCache, dest: std.fs.Dir, dir: []const u8) bool {
        var d = dir;
        while (d.len > 0 and std.mem.indexOfScalar(u8, path_seps, d[d.len - 1]) != null) d = d[0 .. d.len - 1];
        if (d.len == 0) return true;
        if (self.has(d)) return true;

        var start: usize = 0;
        while (true) {
            const sep = std.mem.indexOfAnyPos(u8, d, start, path_seps) orelse d.len;
            if (sep > start) {
                const prefix = d[0..sep];
                if (!self.has(prefix)) {
                    // mkdir first: success proves we made a fresh directory, so
                    // the link check is needed only when the name already exists.
                    dest.makeDir(prefix) catch |e| switch (e) {
                        error.PathAlreadyExists => if (isLinkOnDisk(dest, prefix)) return false,
                        else => return false,
                    };
                    self.add(prefix);
                }
            }
            if (sep >= d.len) return true;
            start = sep + 1;
        }
    }
};

/// Create `name` under `dest` for writing without ever following a symlink in
/// the final component. POSIX `O_NOFOLLOW` fails with ELOOP on a link, which
/// replaces a separate `readlink` and closes the check-then-create race.
fn createNoFollow(dest: std.fs.Dir, name: []const u8, mode: std.fs.File.Mode) !std.fs.File {
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        if (isLinkOnDisk(dest, name)) return error.SymLinkLoop;
        return dest.createFile(name, .{ .mode = mode });
    }
    const fd = try std.posix.openat(dest.fd, name, .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .TRUNC = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, mode);
    return .{ .handle = fd };
}

/// Copy the rest of the current tar member into `out` through `buf`.
fn copyMember(entry: anytype, out: std.fs.File, buf: []u8) !void {
    while (entry.unread_bytes.* > 0) {
        const n: usize = @intCast(@min(@as(u64, buf.len), entry.unread_bytes.*));
        try entry.parent_reader.readNoEof(buf[0..n]);
        entry.unread_bytes.* -= n;
        try out.writeAll(buf[0..n]);
    }
}

/// The safety-critical loop. `std.tar.pipeToFileSystem` is deliberately not
/// used because it performs no containment check on member names.
pub fn pipeTar(
    allocator: std.mem.Allocator,
    reader: anytype,
    dest: std.fs.Dir,
    options: Options,
) !void {
    var file_name_buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    var link_name_buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;

    var it = std.tar.iterator(reader, .{
        .file_name_buffer = &file_name_buffer,
        .link_name_buffer = &link_name_buffer,
    });

    var dirs = DirCache.init(allocator);
    defer dirs.deinit();
    const copy_buf = try allocator.alloc(u8, copy_buf_len);
    defer allocator.free(copy_buf);

    var members: usize = 0;
    var total_bytes: u64 = 0;

    while (try it.next()) |entry| {
        // Counted before any filtering, so skipped members cannot hide cost.
        members += 1;
        if (members > options.max_members) return error.ArchiveTooManyMembers;
        total_bytes +|= entry.size;
        if (total_bytes > options.max_bytes) return error.ArchiveTooLarge;

        // `tar -C dir .` writes every member as `./x`. The prefix names the
        // root itself, so it is dropped before the safety checks see the name.
        const name = stripComponents(stripDotPrefix(entry.name), options.strip_components);
        if (name.len == 0) continue;

        // Refuse anything that could land outside the extraction root.
        if (!safepath.isSafeRelPath(name)) continue;
        // On Windows a colon is a drive prefix or an alternate data stream.
        if (platform.is_windows and hasColon(name)) continue;

        // Creating files and directories follows links. An earlier member may
        // have put a link on disk (`a/l -> ..`), so a later name can route
        // through it. Every parent directory is proven to be a real directory
        // (once, then remembered); the last component is created with
        // O_NOFOLLOW, or checked, so it cannot be a link either.
        switch (entry.kind) {
            .directory => {
                _ = dirs.ensure(dest, name);
            },
            .file => {
                if (std.fs.path.dirname(name)) |d| {
                    if (!dirs.ensure(dest, d)) continue;
                }
                // Only the permission bits matter here. setuid, setgid and
                // sticky are dropped, and the mode is one of two fixed values.
                const perm = entry.mode & 0o777;
                const mode: std.fs.File.Mode = if (std.fs.has_executable_bit and (perm & 0o100) != 0)
                    platform.mode_bin
                else
                    platform.mode_public;
                const out = createNoFollow(dest, name, mode) catch continue;
                defer out.close();
                try copyMember(entry, out, copy_buf);
            },
            .sym_link => {
                const link_dir = std.fs.path.dirname(name) orelse "";
                // A member name can be safe while its symlink target escapes.
                if (!safepath.symlinkStaysInside(link_dir, entry.link_name)) continue;
                // The target text can also run through a link already on disk.
                if (try targetCrossesSymlink(allocator, dest, &dirs, link_dir, entry.link_name)) continue;
                if (link_dir.len > 0 and !dirs.ensure(dest, link_dir)) continue;
                // Unprivileged Windows accounts cannot create symlinks; skip.
                dest.symLink(entry.link_name, name, .{}) catch continue;
                // `name` is a link from now on, whatever the set believed.
                dirs.remove(name);
            },
        }
    }
}

/// True when `rel` names a symbolic link on disk under `dest`.
pub fn isLinkOnDisk(dest: std.fs.Dir, rel: []const u8) bool {
    if (builtin.os.tag == .windows) return isReparsePointWindows(dest, rel);
    var buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    _ = dest.readLink(rel, &buf) catch return false;
    return true;
}

/// Windows has no cheap "is this a link" call through std: readLink on an
/// ordinary file fails with STATUS_NOT_A_REPARSE_POINT, which std reports as
/// an unexpected error and, in debug builds, a stack trace per check. Open
/// the entry itself (not its target) and read its attributes instead. Any
/// reparse point counts: symlinks and junctions both redirect writes.
fn isReparsePointWindows(dest: std.fs.Dir, rel: []const u8) bool {
    const w = std.os.windows;
    const path = w.sliceToPrefixedFileW(dest.fd, rel) catch return false;
    const handle = w.OpenFile(path.span(), .{
        .access_mask = w.FILE_READ_ATTRIBUTES | w.SYNCHRONIZE,
        .dir = dest.fd,
        .creation = w.FILE_OPEN,
        .filter = .any,
        .follow_symlinks = false,
    }) catch return false;
    defer w.CloseHandle(handle);

    var io: w.IO_STATUS_BLOCK = undefined;
    var info: w.FILE_BASIC_INFORMATION = undefined;
    const rc = w.ntdll.NtQueryInformationFile(handle, &io, &info, @sizeOf(w.FILE_BASIC_INFORMATION), .FileBasicInformation);
    if (rc != .SUCCESS) return false;
    return info.FileAttributes & w.FILE_ATTRIBUTE_REPARSE_POINT != 0;
}

/// `safepath.symlinkStaysInside` reads only the link text. A target such as
/// `a/l/..` also depends on what `a/l` is on disk. Every component the target
/// walks through before its last one must therefore not be a link already.
/// The last component may be one, since that is an ordinary link chain.
fn targetCrossesSymlink(
    allocator: std.mem.Allocator,
    dest: std.fs.Dir,
    dirs: *const DirCache,
    link_dir: []const u8,
    target: []const u8,
) !bool {
    // Where the walk currently is, relative to `dest`.
    var here = std.ArrayList([]const u8).init(allocator);
    defer here.deinit();
    var dir_it = std.mem.tokenizeAny(u8, link_dir, "/\\");
    while (dir_it.next()) |c| try here.append(c);

    var steps = std.ArrayList([]const u8).init(allocator);
    defer steps.deinit();
    var tgt_it = std.mem.tokenizeAny(u8, target, "/\\");
    while (tgt_it.next()) |c| {
        if (std.mem.eql(u8, c, ".")) continue;
        try steps.append(c);
    }

    for (steps.items, 0..) |c, i| {
        if (std.mem.eql(u8, c, "..")) {
            // safepath has already ensured the walk never leaves the root.
            if (here.items.len > 0) _ = here.pop();
            continue;
        }
        try here.append(c);
        if (i + 1 < steps.items.len) {
            const joined = try std.mem.join(allocator, "/", here.items);
            defer allocator.free(joined);
            // A directory this extraction already proved real needs no probe.
            if (dirs.has(joined)) continue;
            if (isLinkOnDisk(dest, joined)) return true;
        }
    }
    return false;
}

fn extractDmg(allocator: std.mem.Allocator, archive_path: []const u8, dest_dir_path: []const u8) !void {
    if (!platform.is_macos) return error.DmgUnsupportedOnThisPlatform;

    // Attach at a mount point we create, so the only volume we read from or
    // detach is the one this image produced. Scanning /Volumes could reach an
    // unrelated disk.
    const mount_name = try std.fmt.allocPrint(allocator, ".abv0-dmg-{x}", .{std.crypto.random.int(u64)});
    defer allocator.free(mount_name);
    const mount_point = try std.fs.path.join(allocator, &.{ dest_dir_path, mount_name });
    defer allocator.free(mount_point);

    try std.fs.cwd().makePath(mount_point);
    // Runs last, after the detach below.
    defer std.fs.cwd().deleteDir(mount_point) catch {};

    const attach = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "hdiutil", "attach", "-readonly", "-nobrowse", "-noverify", "-noautoopen", "-quiet", "-mountpoint", mount_point, archive_path },
    });
    defer {
        allocator.free(attach.stdout);
        allocator.free(attach.stderr);
    }
    if (attach.term != .Exited or attach.term.Exited != 0) return error.DmgMountFailed;

    // The image is attached from here on, so detach on every path out.
    defer detachDmg(allocator, mount_point);

    var mounted = std.fs.cwd().openDir(mount_point, .{ .iterate = true }) catch return error.DmgMountFailed;
    defer mounted.close();

    var entries = mounted.iterate();
    while (try entries.next()) |entry| {
        if (!std.mem.endsWith(u8, entry.name, ".app")) continue;

        const src_app = try std.fs.path.join(allocator, &.{ mount_point, entry.name });
        defer allocator.free(src_app);
        const dst_app = try std.fs.path.join(allocator, &.{ dest_dir_path, entry.name });
        defer allocator.free(dst_app);

        try platform.copyTree(src_app, dst_app);
        return;
    }
    return error.DmgNoApplicationFound;
}

/// Detach our own mount point. A failure here is not fatal, because the copy
/// is already finished, but the mount is left for the user to eject.
fn detachDmg(allocator: std.mem.Allocator, mount_point: []const u8) void {
    const detach = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "hdiutil", "detach", "-quiet", mount_point },
    }) catch return;
    allocator.free(detach.stdout);
    allocator.free(detach.stderr);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "Kind parsing" {
    try testing.expectEqual(Kind.tar_gz, Kind.fromString("tar.gz").?);
    try testing.expectEqual(Kind.zip, Kind.fromString("zip").?);
    try testing.expectEqual(Kind.raw, Kind.fromString("raw").?);
    try testing.expect(Kind.fromString("rar") == null);
    try testing.expectEqual(Kind.tar_xz, Kind.fromFilename("tool-v1.2.3-x86_64.tar.xz").?);
    try testing.expectEqual(Kind.zip, Kind.fromFilename("tool.zip").?);
    try testing.expectEqual(Kind.sevenz, Kind.fromString("7z").?);
    try testing.expectEqual(Kind.sevenz, Kind.fromFilename("node-v22-win-x64.7z").?);
    try testing.expectEqual(Kind.sevenz, sniffBytes("7z\xBC\xAF\x27\x1C\x00\x04").?);
}

test "stripComponents" {
    try testing.expectEqualStrings("bin/jq", stripComponents("jq-1.7/bin/jq", 1));
    try testing.expectEqualStrings("jq", stripComponents("jq-1.7/bin/jq", 2));
    try testing.expectEqualStrings("jq-1.7/bin/jq", stripComponents("jq-1.7/bin/jq", 0));
    try testing.expectEqualStrings("", stripComponents("jq", 3));
}

fn writeTarEntry(w: anytype, name: []const u8, content: []const u8, kind: u8, link: []const u8) !void {
    try writeTarEntryMode(w, name, content, kind, link, 0o644);
}

fn writeTarEntryMode(w: anytype, name: []const u8, content: []const u8, kind: u8, link: []const u8, mode: u32) !void {
    var header = [_]u8{0} ** 512;
    @memcpy(header[0..name.len], name);
    _ = try std.fmt.bufPrint(header[100..108], "{o:0>7}\x00", .{mode});
    _ = try std.fmt.bufPrint(header[108..116], "0000000\x00", .{});
    _ = try std.fmt.bufPrint(header[116..124], "0000000\x00", .{});
    _ = try std.fmt.bufPrint(header[124..136], "{o:0>11} ", .{content.len});
    _ = try std.fmt.bufPrint(header[136..148], "{o:0>11} ", .{@as(u64, 0)});
    header[156] = kind;
    if (link.len > 0) @memcpy(header[157..][0..link.len], link);
    @memcpy(header[257..262], "ustar");
    header[263] = '0';
    header[264] = '0';

    // Checksum: sum of all bytes with the checksum field treated as spaces.
    @memset(header[148..156], ' ');
    var sum: u32 = 0;
    for (header) |b| sum += b;
    _ = try std.fmt.bufPrint(header[148..156], "{o:0>6}\x00 ", .{sum});

    try w.writeAll(&header);
    if (content.len > 0) {
        try w.writeAll(content);
        const pad = (512 - (content.len % 512)) % 512;
        try w.writeByteNTimes(0, pad);
    }
}

fn buildTar(list: *std.ArrayList(u8), entries: anytype) !void {
    const w = list.writer();
    inline for (entries) |e| {
        try writeTarEntry(w, e[0], e[1], e[2], e[3]);
    }
    try w.writeByteNTimes(0, 1024); // end-of-archive
}

test "tar extraction writes safe members" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try buildTar(&buf, .{
        .{ "bin/tool", "#!/bin/sh\necho hi\n", '0', "" },
        .{ "README", "docs", '0', "" },
    });

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var stream = std.io.fixedBufferStream(buf.items);
    try pipeTar(testing.allocator, stream.reader(), tmp.dir, .{});

    const content = try tmp.dir.readFileAlloc(testing.allocator, "bin/tool", 128);
    defer testing.allocator.free(content);
    try testing.expectEqualStrings("#!/bin/sh\necho hi\n", content);
}

test "tar extraction refuses ../ members (tar slip)" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try buildTar(&buf, .{
        .{ "../../escaped.txt", "pwned", '0', "" },
        .{ "safe.txt", "ok", '0', "" },
    });

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var stream = std.io.fixedBufferStream(buf.items);
    try pipeTar(testing.allocator, stream.reader(), tmp.dir, .{});

    // The safe member landed...
    const ok = try tmp.dir.readFileAlloc(testing.allocator, "safe.txt", 16);
    defer testing.allocator.free(ok);
    try testing.expectEqualStrings("ok", ok);

    // ...and the escaping member did not, anywhere.
    try testing.expectError(error.FileNotFound, tmp.dir.access("../../escaped.txt", .{}));
    try testing.expectError(error.FileNotFound, tmp.dir.access("escaped.txt", .{}));
}

test "tar extraction refuses absolute member paths" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try buildTar(&buf, .{.{ "/tmp/abv0-should-not-exist", "pwned", '0', "" }});

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var stream = std.io.fixedBufferStream(buf.items);
    try pipeTar(testing.allocator, stream.reader(), tmp.dir, .{});

    try testing.expectError(error.FileNotFound, std.fs.cwd().access("/tmp/abv0-should-not-exist", .{}));
}

test "tar extraction refuses symlinks that escape the root" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try buildTar(&buf, .{
        .{ "escape", "", '2', "../../../../etc/passwd" },
        .{ "inside", "", '2', "real" },
        .{ "real", "content", '0', "" },
    });

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var stream = std.io.fixedBufferStream(buf.items);
    try pipeTar(testing.allocator, stream.reader(), tmp.dir, .{});

    try testing.expectError(error.FileNotFound, tmp.dir.access("escape", .{}));
    if (!platform.is_windows) {
        try tmp.dir.access("inside", .{});
    }
}

test "tar extraction refuses to write through a symlink chain" {
    if (platform.is_windows) return error.SkipZigTest;

    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    // Each name passes on its own. Together, `p/...` lands in the directory
    // above the root, because `a/l/..` resolves through the earlier `a/l`.
    try buildTar(&buf, .{
        .{ "a/l", "", '2', ".." },
        .{ "p", "", '2', "a/l/.." },
        .{ "p/abv0-escape-probe", "pwned", '0', "" },
    });

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var stream = std.io.fixedBufferStream(buf.items);
    try pipeTar(testing.allocator, stream.reader(), tmp.dir, .{});

    // The escape target is the parent of the extraction root.
    try testing.expectError(error.FileNotFound, tmp.parent_dir.access("abv0-escape-probe", .{}));
    // The chain's second link was never created.
    var link_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    try testing.expectError(error.NotLink, tmp.dir.readLink("p", &link_buf));
}

test "tar extraction refuses members that route through an earlier symlink" {
    if (platform.is_windows) return error.SkipZigTest;

    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try buildTar(&buf, .{
        .{ "a/l", "", '2', ".." },
        .{ "a/l/abv0-escape-probe", "pwned", '0', "" },
        .{ "a/l/sub/file", "pwned", '0', "" },
    });

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var stream = std.io.fixedBufferStream(buf.items);
    try pipeTar(testing.allocator, stream.reader(), tmp.dir, .{});

    // Neither write goes through the link, so nothing lands at the root.
    try testing.expectError(error.FileNotFound, tmp.dir.access("abv0-escape-probe", .{}));
    try testing.expectError(error.FileNotFound, tmp.dir.access("sub/file", .{}));
}

test "tar extraction strips setuid, setgid and sticky bits" {
    if (platform.is_windows) return error.SkipZigTest;

    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    const w = buf.writer();
    try writeTarEntryMode(w, "bin/suid", "#!/bin/sh\n", '0', "", 0o4755);
    try writeTarEntryMode(w, "bin/sgid", "#!/bin/sh\n", '0', "", 0o2755);
    try writeTarEntryMode(w, "bin/sticky", "#!/bin/sh\n", '0', "", 0o1755);
    try w.writeByteNTimes(0, 1024);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var stream = std.io.fixedBufferStream(buf.items);
    try pipeTar(testing.allocator, stream.reader(), tmp.dir, .{});

    for ([_][]const u8{ "bin/suid", "bin/sgid", "bin/sticky" }) |name| {
        const st = try tmp.dir.statFile(name);
        try testing.expectEqual(@as(std.fs.File.Mode, 0), st.mode & 0o7000);
        try testing.expectEqual(@as(std.fs.File.Mode, 0o755), st.mode & 0o777);
    }
}

test "tar extraction stops at the member and byte caps" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try buildTar(&buf, .{
        .{ "a", "1", '0', "" },
        .{ "b", "2", '0', "" },
        .{ "c", "3", '0', "" },
    });

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var stream = std.io.fixedBufferStream(buf.items);
    try testing.expectError(
        error.ArchiveTooManyMembers,
        pipeTar(testing.allocator, stream.reader(), tmp.dir, .{ .max_members = 2 }),
    );

    stream.reset();
    try testing.expectError(
        error.ArchiveTooLarge,
        pipeTar(testing.allocator, stream.reader(), tmp.dir, .{ .max_bytes = 2 }),
    );

    // Under the limits the same archive extracts normally.
    stream.reset();
    try pipeTar(testing.allocator, stream.reader(), tmp.dir, .{ .max_members = 3, .max_bytes = 3 });
    try tmp.dir.access("c", .{});
}

test "sniff identifies formats and rejects an HTML error page" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);

    const html = try std.fs.path.join(testing.allocator, &.{ root, "err.bin" });
    defer testing.allocator.free(html);
    {
        const f = try std.fs.cwd().createFile(html, .{});
        defer f.close();
        try f.writeAll("<!DOCTYPE html><html><body>404: Not Found</body></html>");
    }
    try testing.expect(looksLikeErrorPage(html));
    try testing.expect(sniff(html) == null);

    const gz = try std.fs.path.join(testing.allocator, &.{ root, "a.gz" });
    defer testing.allocator.free(gz);
    {
        const f = try std.fs.cwd().createFile(gz, .{});
        defer f.close();
        try f.writeAll(&.{ 0x1f, 0x8b, 0x08, 0x00 });
    }
    try testing.expectEqual(Kind.tar_gz, sniff(gz).?);

    const empty = try std.fs.path.join(testing.allocator, &.{ root, "empty.bin" });
    defer testing.allocator.free(empty);
    (try std.fs.cwd().createFile(empty, .{})).close();
    // A zero-byte download is exactly the shipped abv0-darwin-x86_64 bug.
    try testing.expect(looksLikeErrorPage(empty));
}

test "byte-slice checks agree with the path checks and probe 256 bytes" {
    const html = "<!DOCTYPE html><html><body>404: Not Found</body></html>";
    try testing.expect(looksLikeErrorPageBytes(html));
    try testing.expect(sniffBytes(html) == null);
    try testing.expect(looksLikeErrorPageBytes(""));

    // A marker that starts past the probe window is not looked at.
    var late = [_]u8{'x'} ** 300;
    @memcpy(late[260..][0..6], "<html>");
    try testing.expect(!looksLikeErrorPageBytes(&late));
    @memcpy(late[200..][0..6], "<html>");
    try testing.expect(looksLikeErrorPageBytes(&late));

    try testing.expectEqual(Kind.tar_gz, sniffBytes(&.{ 0x1f, 0x8b, 0x08 }).?);
}

const ZipMember = struct {
    name: []const u8,
    data: []const u8,
    unix_mode: u32 = 0,
    deflate: bool = false,
};

/// Appends a zip with one stored (or, with `deflate`, compressed) record per member, followed
/// by the central directory and end record. Only the fields std.zip reads
/// are meaningful. Times are zero, which matches on both sides.
fn buildZip(list: *std.ArrayList(u8), members: []const ZipMember) !void {
    var cd = std.ArrayList(u8).init(testing.allocator);
    defer cd.deinit();
    const w = list.writer();
    const cdw = cd.writer();

    for (members) |m| {
        const offset: u32 = @intCast(list.items.len);
        const crc = std.hash.Crc32.hash(m.data);
        const size: u32 = @intCast(m.data.len);
        const name_len: u16 = @intCast(m.name.len);
        var packed_data = std.ArrayList(u8).init(testing.allocator);
        defer packed_data.deinit();
        if (m.deflate) {
            var src = std.io.fixedBufferStream(m.data);
            try std.compress.flate.compress(src.reader(), packed_data.writer(), .{});
        }
        const stored: []const u8 = if (m.deflate) packed_data.items else m.data;
        const csize: u32 = @intCast(stored.len);
        const method: u16 = if (m.deflate) 8 else 0;

        try w.writeAll(&std.zip.local_file_header_sig);
        try w.writeInt(u16, 20, .little); // version needed
        try w.writeInt(u16, 0, .little); // flags
        try w.writeInt(u16, method, .little);
        try w.writeInt(u32, 0, .little); // time and date
        try w.writeInt(u32, crc, .little);
        try w.writeInt(u32, csize, .little);
        try w.writeInt(u32, size, .little);
        try w.writeInt(u16, name_len, .little);
        try w.writeInt(u16, 0, .little); // extra length
        try w.writeAll(m.name);
        try w.writeAll(stored);

        try cdw.writeAll(&std.zip.central_file_header_sig);
        // Host byte 3 = Unix, which makes the external attributes carry a mode.
        try cdw.writeInt(u16, if (m.unix_mode != 0) (3 << 8) | 20 else 20, .little); // version made by
        try cdw.writeInt(u16, 20, .little); // version needed
        try cdw.writeInt(u16, 0, .little); // flags
        try cdw.writeInt(u16, method, .little);
        try cdw.writeInt(u32, 0, .little); // time and date
        try cdw.writeInt(u32, crc, .little);
        try cdw.writeInt(u32, csize, .little);
        try cdw.writeInt(u32, size, .little);
        try cdw.writeInt(u16, name_len, .little);
        try cdw.writeInt(u16, 0, .little); // extra length
        try cdw.writeInt(u16, 0, .little); // comment length
        try cdw.writeInt(u16, 0, .little); // disk number
        try cdw.writeInt(u16, 0, .little); // internal attributes
        try cdw.writeInt(u32, m.unix_mode << 16, .little); // external attributes
        try cdw.writeInt(u32, offset, .little);
        try cdw.writeAll(m.name);
    }

    const cd_offset: u32 = @intCast(list.items.len);
    try w.writeAll(cd.items);
    try w.writeAll(&std.zip.end_record_sig);
    try w.writeInt(u16, 0, .little); // disk number
    try w.writeInt(u16, 0, .little); // central directory disk
    try w.writeInt(u16, @intCast(members.len), .little);
    try w.writeInt(u16, @intCast(members.len), .little);
    try w.writeInt(u32, @intCast(cd.items.len), .little);
    try w.writeInt(u32, cd_offset, .little);
    try w.writeInt(u16, 0, .little); // comment length
}

/// Writes `members` as `in.zip` in a fresh temporary directory with an empty
/// `out` directory beside it. Returns both as absolute paths the caller frees.
fn zipFixture(
    tmp: *testing.TmpDir,
    members: []const ZipMember,
) !struct { archive: []u8, out: []u8 } {
    var list = std.ArrayList(u8).init(testing.allocator);
    defer list.deinit();
    try buildZip(&list, members);
    try tmp.dir.writeFile(.{ .sub_path = "in.zip", .data = list.items });
    try tmp.dir.makeDir("out");

    const archive = try tmp.dir.realpathAlloc(testing.allocator, "in.zip");
    errdefer testing.allocator.free(archive);
    const out = try tmp.dir.realpathAlloc(testing.allocator, "out");
    return .{ .archive = archive, .out = out };
}

test "zip extraction extracts plain members" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const paths = try zipFixture(&tmp, &.{
        .{ .name = "ok/a.txt", .data = "hello" },
        .{ .name = "top.txt", .data = "world" },
    });
    defer testing.allocator.free(paths.archive);
    defer testing.allocator.free(paths.out);

    try extract(testing.allocator, .zip, paths.archive, paths.out, .{});

    var out = try tmp.dir.openDir("out", .{});
    defer out.close();
    const a = try out.readFileAlloc(testing.allocator, "ok/a.txt", 64);
    defer testing.allocator.free(a);
    try testing.expectEqualStrings("hello", a);
    const top = try out.readFileAlloc(testing.allocator, "top.txt", 64);
    defer testing.allocator.free(top);
    try testing.expectEqualStrings("world", top);
}

test "zip extraction refuses unsafe member names and writes nothing" {
    const bad_names = [_][]const u8{
        "C:/x.txt", // drive-absolute: Windows ignores the directory handle
        "C:x.txt", // drive-relative
        "//srv/share/x", // UNC
        "/abs.txt",
        "../up.txt",
        "a.txt:stream", // NTFS alternate data stream
        "dir\\x.txt", // backslash separator
        "a//b.txt", // empty component
    };
    for (bad_names) |name| {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        const paths = try zipFixture(&tmp, &.{.{ .name = name, .data = "pwned" }});
        defer testing.allocator.free(paths.archive);
        defer testing.allocator.free(paths.out);

        try testing.expectError(
            error.UnsafeArchiveMember,
            extract(testing.allocator, .zip, paths.archive, paths.out, .{}),
        );

        var out = try tmp.dir.openDir("out", .{ .iterate = true });
        defer out.close();
        var it = out.iterate();
        try testing.expect((try it.next()) == null);
    }
}

test "zip extraction rejects the whole archive when one member is unsafe" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // The safe member comes first, so it would be written before the bad one
    // was reached. The archive must be refused before that happens.
    const paths = try zipFixture(&tmp, &.{
        .{ .name = "ok/a.txt", .data = "hello" },
        .{ .name = "C:/Users/x/Startup/x.cmd", .data = "pwned" },
    });
    defer testing.allocator.free(paths.archive);
    defer testing.allocator.free(paths.out);

    try testing.expectError(
        error.UnsafeArchiveMember,
        extract(testing.allocator, .zip, paths.archive, paths.out, .{}),
    );

    var out = try tmp.dir.openDir("out", .{ .iterate = true });
    defer out.close();
    var it = out.iterate();
    try testing.expect((try it.next()) == null);
}

test "zip extraction restores the exec bit and nothing else" {
    if (platform.is_windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const paths = try zipFixture(&tmp, &.{
        .{ .name = "bin/tool", .data = "#!/bin/sh\n", .unix_mode = 0o100755 },
        // setuid + setgid + sticky + world-writable: only "executable" survives.
        .{ .name = "bin/suid", .data = "x", .unix_mode = 0o107777 },
        .{ .name = "doc/readme", .data = "docs", .unix_mode = 0o100644 },
        // Written by a non-Unix host: no mode information at all.
        .{ .name = "plain", .data = "p" },
    });
    defer testing.allocator.free(paths.archive);
    defer testing.allocator.free(paths.out);

    try extract(testing.allocator, .zip, paths.archive, paths.out, .{});

    var out = try tmp.dir.openDir("out", .{});
    defer out.close();
    const want = [_]struct { name: []const u8, mode: std.fs.File.Mode }{
        .{ .name = "bin/tool", .mode = 0o755 },
        .{ .name = "bin/suid", .mode = 0o755 },
        .{ .name = "doc/readme", .mode = 0o644 },
        .{ .name = "plain", .mode = 0o644 },
    };
    for (want) |w| {
        const st = try out.statFile(w.name);
        try testing.expectEqual(@as(std.fs.File.Mode, 0), st.mode & 0o7000);
        try testing.expectEqual(w.mode, st.mode & 0o777);
    }
}

test "zip extraction creates safe symlinks and skips escaping ones" {
    if (platform.is_windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const lnk: u32 = 0o120777;
    const paths = try zipFixture(&tmp, &.{
        .{ .name = "App.app/Versions/A/Lib", .data = "lib" },
        .{ .name = "App.app/Versions/Current", .data = "A", .unix_mode = lnk },
        .{ .name = "App.app/Lib", .data = "Versions/A/Lib", .unix_mode = lnk },
        // Walks through the `Current` link: refused, exactly as a tar member is.
        .{ .name = "App.app/Via", .data = "Versions/Current/Lib", .unix_mode = lnk },
        // Escapes by text.
        .{ .name = "esc", .data = "../../etc/passwd", .unix_mode = lnk },
        .{ .name = "abs", .data = "/etc/passwd", .unix_mode = lnk },
        // `a/l/..` only escapes because `a/l` is itself a link to `..`.
        .{ .name = "a/l", .data = "..", .unix_mode = lnk },
        .{ .name = "p", .data = "a/l/..", .unix_mode = lnk },
    });
    defer testing.allocator.free(paths.archive);
    defer testing.allocator.free(paths.out);

    try extract(testing.allocator, .zip, paths.archive, paths.out, .{});

    var out = try tmp.dir.openDir("out", .{});
    defer out.close();
    var buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    try testing.expectEqualStrings("A", try out.readLink("App.app/Versions/Current", &buf));
    try testing.expectEqualStrings("Versions/A/Lib", try out.readLink("App.app/Lib", &buf));
    try testing.expectError(error.FileNotFound, out.readLink("App.app/Via", &buf));
    // Reads through the chain.
    const via = try out.readFileAlloc(testing.allocator, "App.app/Lib", 16);
    defer testing.allocator.free(via);
    try testing.expectEqualStrings("lib", via);

    try testing.expectError(error.FileNotFound, out.readLink("esc", &buf));
    try testing.expectError(error.FileNotFound, out.readLink("abs", &buf));
    // `a/l -> ..` stays inside the root, but the second link crosses it.
    try testing.expectEqualStrings("..", try out.readLink("a/l", &buf));
    try testing.expectError(error.FileNotFound, out.readLink("p", &buf));
}

test "zip extraction decodes deflate entries on several threads" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // Compressible, distinct per entry, and big enough that the threaded path
    // is worth taking.
    var members: [24]ZipMember = undefined;
    var names: [24][16]u8 = undefined;
    var datas: [24][]u8 = undefined;
    for (&members, 0..) |*m, i| {
        const name = try std.fmt.bufPrint(&names[i], "d{d}/f{d}.txt", .{ i % 5, i });
        datas[i] = try testing.allocator.alloc(u8, 20_000 + i * 1000);
        for (datas[i], 0..) |*b, j| b.* = @intCast('a' + (j * (i + 1) / 7) % 23);
        m.* = .{ .name = name, .data = datas[i], .deflate = i % 3 != 0 };
    }
    defer for (datas) |d| testing.allocator.free(d);

    const paths = try zipFixture(&tmp, &members);
    defer testing.allocator.free(paths.archive);
    defer testing.allocator.free(paths.out);

    zip_parallel_min_bytes_override = 1;
    defer zip_parallel_min_bytes_override = null;
    try extract(testing.allocator, .zip, paths.archive, paths.out, .{});

    var out = try tmp.dir.openDir("out", .{});
    defer out.close();
    for (members, 0..) |m, i| {
        const got = try out.readFileAlloc(testing.allocator, m.name, 1 << 20);
        defer testing.allocator.free(got);
        try testing.expectEqualSlices(u8, datas[i], got);
    }
}

test "zip extraction reports a CRC mismatch and a bad member" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const paths = try zipFixture(&tmp, &.{
        .{ .name = "a.txt", .data = "hello hello hello hello", .deflate = true },
    });
    defer testing.allocator.free(paths.archive);
    defer testing.allocator.free(paths.out);

    // Flip a byte of the deflated payload: either the stream or the CRC breaks.
    var f = try std.fs.cwd().openFile(paths.archive, .{ .mode = .read_write });
    defer f.close();
    const payload_at = @sizeOf(std.zip.LocalFileHeader) + "a.txt".len + 2;
    var b: [1]u8 = undefined;
    _ = try f.preadAll(&b, payload_at);
    b[0] ^= 0x55;
    try f.pwriteAll(&b, payload_at);

    try testing.expect(std.meta.isError(extract(testing.allocator, .zip, paths.archive, paths.out, .{})));
}

test "members written by `tar -C dir .` keep their names" {
    try testing.expectEqualStrings("tool", stripDotPrefix("./tool"));
    try testing.expectEqualStrings("bin/tool", stripDotPrefix("././bin/tool"));
    try testing.expectEqualStrings("", stripDotPrefix("./"));
    try testing.expectEqualStrings("", stripDotPrefix("."));
    try testing.expectEqualStrings("../x", stripDotPrefix("./../x"));

    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try buildTar(&buf, .{
        .{ "./", "", '5', "" },
        .{ "./tool", "#!/bin/sh\n", '0', "" },
        .{ "./../escape", "x", '0', "" },
    });
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var stream = std.io.fixedBufferStream(buf.items);
    try pipeTar(testing.allocator, stream.reader(), tmp.dir, .{});
    try tmp.dir.access("tool", .{});
    try testing.expectError(error.FileNotFound, tmp.parent_dir.access("escape", .{}));
}
