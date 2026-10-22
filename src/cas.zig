//! Content-addressed storage: a download cache and file-level dedupe.
//!
//! Two independent pieces share this file because both are keyed by SHA-256
//! and both live under the abv0 root.
//!
//! Download cache  `<root>/cache/sha256/<first2>/<hex>`
//!   A payload is kept only after its digest matched the manifest, so the file
//!   name is also its checksum. A later install of the same payload skips the
//!   network entirely (which makes installs work offline). Every use re-checks
//!   the bytes: files up to 64 MiB are hashed again, larger ones are trusted
//!   through a `<hex>.ok` sidecar that records size and mtime at verification
//!   time and is only believed while both still match. A corrupt entry is
//!   deleted and reported as a miss, so the caller downloads it again.
//!   Files are 0600 in 0700 directories. The cache is capped (default 2 GiB,
//!   `ABV0_CACHE_MAX`); inserting evicts the least recently used entries, with
//!   the file's mtime as the use stamp. `ABV0_NO_CACHE=1` turns it off.
//!
//! File dedupe  `<root>/cas/files/<hex>[.<mode>]`
//!   When an unpacked tree is about to be published, each regular file of
//!   4 KiB or more is hashed. If an identical file (same bytes, same permission
//!   bits) is already in `cas/files`, the new file is replaced by a hard link
//!   to it; otherwise it is hard linked into `cas/files` for the next install
//!   to find. An upgrade therefore reuses unchanged files, and a reinstall
//!   shares everything with what it replaced. Symlinks are never followed or
//!   deduped, and files with different permission bits never share a name.
//!   `gc` removes `cas/files` entries whose link count is 1, i.e. nothing but
//!   the CAS holds them. `ABV0_NO_DEDUPE=1` turns it off.
//!
//! Streaming tee (the interface `stream.zig` calls)
//!   A streaming install never has the payload as a file. `Sink` collects the
//!   bytes as they arrive so the payload can be cached once the digest checks
//!   out. The stream path only has to call `teeWrite(bytes)` for every chunk
//!   it reads from the network; `tee` is a thread-local, so it is a no-op
//!   unless the installing thread set it. The sink hashes what it receives and
//!   `Sink.promote` refuses unless that hash is the expected digest, so a
//!   missed or reordered chunk can never produce a bad cache entry.
//!
//! Everything here is best effort: a cache or dedupe failure never fails an
//! install, it only costs the speed-up.

const std = @import("std");
const builtin = @import("builtin");
const platform = @import("platform.zig");
const archive = @import("archive.zig");

const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const is_windows = builtin.os.tag == .windows;

/// Files smaller than this are not worth a hash and a directory entry.
pub const min_dedupe_size: u64 = 4096;
pub const default_cache_max: u64 = 2 * 1024 * 1024 * 1024;
/// Cached files above this size are trusted through their `.ok` sidecar
/// instead of being hashed on every use.
pub const trust_sidecar_over: u64 = 64 * 1024 * 1024;
/// `pruneCache` drops entries that have not been used for this long.
pub const stale_after_ns: i128 = 30 * 24 * std.time.ns_per_hour;
const tmp_stale_ns: i128 = std.time.ns_per_hour;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

pub const Config = struct {
    /// Keep and reuse verified downloads.
    cache: bool = true,
    /// Share identical files between installed trees.
    dedupe: bool = true,
    max_bytes: u64 = default_cache_max,

    pub fn fromEnv() Config {
        var c = Config{};
        if (envFlag("ABV0_NO_CACHE")) c.cache = false;
        if (envFlag("ABV0_NO_DEDUPE")) c.dedupe = false;
        var buf: [64]u8 = undefined;
        if (envText(&buf, "ABV0_CACHE_MAX")) |t| {
            if (parseSize(t)) |n| c.max_bytes = n;
        }
        if (c.max_bytes == 0) c.cache = false;
        return c;
    }

    /// The configuration in force: the test override if one is set, otherwise
    /// the environment.
    pub fn current() Config {
        return config_override orelse fromEnv();
    }
};

/// Test seam. Unit tests cannot set environment variables, so they set this.
pub var config_override: ?Config = null;

fn envText(buf: []u8, name: []const u8) ?[]const u8 {
    var fba = std.heap.FixedBufferAllocator.init(buf);
    const v = std.process.getEnvVarOwned(fba.allocator(), name) catch return null;
    return std.mem.trim(u8, v, " \t\r\n");
}

/// Set means on: anything but empty, `0`, `false`, `no` or `off`.
fn envFlag(name: []const u8) bool {
    var buf: [32]u8 = undefined;
    const v = envText(&buf, name) orelse return false;
    if (v.len == 0) return false;
    for ([_][]const u8{ "0", "false", "no", "off" }) |off| {
        if (std.ascii.eqlIgnoreCase(v, off)) return false;
    }
    return true;
}

/// `2G`, `512MiB`, `1048576`, `64k`. Powers of 1024. Null when malformed.
pub fn parseSize(text: []const u8) ?u64 {
    const t = std.mem.trim(u8, text, " \t");
    var i: usize = 0;
    while (i < t.len and std.ascii.isDigit(t[i])) i += 1;
    if (i == 0) return null;
    const n = std.fmt.parseInt(u64, t[0..i], 10) catch return null;
    var rest = std.mem.trim(u8, t[i..], " ");
    if (rest.len == 0) return n;
    var shift: u6 = 0;
    switch (std.ascii.toLower(rest[0])) {
        'k' => shift = 10,
        'm' => shift = 20,
        'g' => shift = 30,
        't' => shift = 40,
        'b' => {},
        else => return null,
    }
    rest = rest[1..];
    if (rest.len > 0 and std.ascii.toLower(rest[0]) == 'i') rest = rest[1..];
    if (rest.len > 0 and std.ascii.toLower(rest[0]) == 'b') rest = rest[1..];
    if (rest.len != 0) return null;
    return std.math.mul(u64, n, @as(u64, 1) << shift) catch null;
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

pub fn isHex64(s: []const u8) bool {
    if (s.len != 64) return false;
    for (s) |c| {
        if (!std.ascii.isHex(c)) return false;
    }
    return true;
}

fn hexOf(digest: *const [32]u8) [64]u8 {
    var out: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&out, "{s}", .{std.fmt.fmtSliceHexLower(digest)}) catch unreachable;
    return out;
}

fn entryDirPath(a: Allocator, root: []const u8, hex: []const u8) ![]u8 {
    return std.fs.path.join(a, &.{ root, "cache", "sha256", hex[0..2] });
}

fn entryPath(a: Allocator, root: []const u8, hex: []const u8) ![]u8 {
    return std.fs.path.join(a, &.{ root, "cache", "sha256", hex[0..2], hex });
}

fn ensureCacheDirs(a: Allocator, root: []const u8, hex: []const u8) !void {
    const cache = try std.fs.path.join(a, &.{ root, "cache" });
    defer a.free(cache);
    try platform.ensureSecureDir(cache);
    const sha = try std.fs.path.join(a, &.{ cache, "sha256" });
    defer a.free(sha);
    try platform.ensureSecureDir(sha);
    const sub = try entryDirPath(a, root, hex);
    defer a.free(sub);
    try platform.ensureSecureDir(sub);
}

fn tmpDirPath(a: Allocator, root: []const u8) ![]u8 {
    return std.fs.path.join(a, &.{ root, "cache", "tmp" });
}

/// Hard link `src` as `dst`. Never copies and never makes a symlink, unlike
/// `platform.fastLink`: callers need to know the two names are one file.
pub fn hardLink(src: []const u8, dst: []const u8) !void {
    if (comptime is_windows) {
        if (src.len >= 4096 or dst.len >= 4096) return error.NameTooLong;
        var src_w: [4096]u16 = undefined;
        var dst_w: [4096]u16 = undefined;
        const sl = try std.unicode.utf8ToUtf16Le(&src_w, src);
        src_w[sl] = 0;
        const dl = try std.unicode.utf8ToUtf16Le(&dst_w, dst);
        dst_w[dl] = 0;
        const src_z: [*:0]const u16 = @ptrCast(&src_w);
        const dst_z: [*:0]const u16 = @ptrCast(&dst_w);
        if (CreateHardLinkW(dst_z, src_z, null) == 0) return error.LinkFailed;
        return;
    }
    try std.posix.link(src, dst, 0);
}

extern "kernel32" fn CreateHardLinkW(
    lpFileName: [*:0]const u16,
    lpExistingFileName: [*:0]const u16,
    lpSecurityAttributes: ?*anyopaque,
) callconv(std.os.windows.WINAPI) std.os.windows.BOOL;

/// Number of names (directory entries) the file has.
pub fn linkCount(file: std.fs.File) !u64 {
    if (comptime is_windows) {
        const w = std.os.windows;
        var io: w.IO_STATUS_BLOCK = undefined;
        var info: w.FILE_STANDARD_INFORMATION = undefined;
        const rc = w.ntdll.NtQueryInformationFile(file.handle, &io, &info, @sizeOf(w.FILE_STANDARD_INFORMATION), .FileStandardInformation);
        if (rc != .SUCCESS) return error.Unexpected;
        return info.NumberOfLinks;
    }
    const st = try std.posix.fstat(file.handle);
    return @intCast(st.nlink);
}

fn permBits(mode: anytype) u32 {
    return @intCast(mode);
}

// ---------------------------------------------------------------------------
// Download cache: lookup
// ---------------------------------------------------------------------------

pub const Hit = struct {
    /// Allocated from the allocator given to `lookup`.
    path: []const u8,
    size: u64,
    digest: [32]u8,
    /// The first `archive.head_len` bytes, which the sniff checks need.
    head: [archive.head_len]u8,
    head_len: usize,
};

/// Find a verified payload with SHA-256 `hex`. A hit has been re-checked
/// against `hex` (hashed, or matched to its sidecar for a very large file) and
/// marked as just used. A cached file that fails the check is deleted.
pub fn lookup(a: Allocator, root: []const u8, hex_in: []const u8) ?Hit {
    if (!isHex64(hex_in)) return null;
    var hex: [64]u8 = undefined;
    _ = std.ascii.lowerString(&hex, hex_in);

    const path = entryPath(a, root, &hex) catch return null;
    var keep = false;
    defer if (!keep) a.free(path);

    var read_write = true;
    const file = std.fs.cwd().openFile(path, .{ .mode = .read_write }) catch |e| blk: {
        if (e == error.FileNotFound) return null;
        read_write = false;
        break :blk std.fs.cwd().openFile(path, .{}) catch return null;
    };
    defer file.close();

    const st = file.stat() catch return null;
    if (st.kind != .file) return null;

    var want: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&want, &hex) catch return null;

    var hit = Hit{ .path = path, .size = st.size, .digest = want, .head = undefined, .head_len = 0 };

    const large = st.size > trust_sidecar_over;
    if (large and sidecarMatches(a, path, st.size, st.mtime)) {
        hit.head_len = file.readAll(&hit.head) catch return null;
    } else {
        var h = Sha256.init(.{});
        var buf: [64 * 1024]u8 = undefined;
        while (true) {
            const n = file.read(&buf) catch return null;
            if (n == 0) break;
            if (hit.head_len < hit.head.len) {
                const take = @min(hit.head.len - hit.head_len, n);
                @memcpy(hit.head[hit.head_len..][0..take], buf[0..take]);
                hit.head_len += take;
            }
            h.update(buf[0..n]);
        }
        const got = h.finalResult();
        if (!std.mem.eql(u8, &got, &want)) {
            removeEntryPath(path);
            return null;
        }
    }

    // Mark as used. A large file's sidecar records the mtime, so it is
    // rewritten with the new one.
    if (read_write) {
        const now: i128 = std.time.nanoTimestamp();
        if (file.updateTimes(now, now)) |_| {
            if (large) {
                if (file.stat()) |st2| writeSidecar(a, path, st2.size, st2.mtime) else |_| {}
            }
        } else |_| {}
    }
    keep = true;
    return hit;
}

fn sidecarPath(a: Allocator, path: []const u8) ![]u8 {
    return std.fmt.allocPrint(a, "{s}.ok", .{path});
}

fn sidecarMatches(a: Allocator, path: []const u8, size: u64, mtime: i128) bool {
    const sp = sidecarPath(a, path) catch return false;
    defer a.free(sp);
    var buf: [128]u8 = undefined;
    const f = std.fs.cwd().openFile(sp, .{}) catch return false;
    defer f.close();
    const n = f.readAll(&buf) catch return false;
    var it = std.mem.tokenizeAny(u8, buf[0..n], " \n");
    const s = std.fmt.parseInt(u64, it.next() orelse return false, 10) catch return false;
    const m = std.fmt.parseInt(i128, it.next() orelse return false, 10) catch return false;
    return s == size and m == mtime;
}

fn writeSidecar(a: Allocator, path: []const u8, size: u64, mtime: i128) void {
    const sp = sidecarPath(a, path) catch return;
    defer a.free(sp);
    const f = std.fs.cwd().createFile(sp, .{ .mode = platform.mode_private }) catch return;
    defer f.close();
    var buf: [96]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, "{d} {d}\n", .{ size, mtime }) catch return;
    f.writeAll(text) catch {};
}

fn removeEntryPath(path: []const u8) void {
    std.fs.cwd().deleteFile(path) catch {};
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const sp = std.fmt.bufPrint(&buf, "{s}.ok", .{path}) catch return;
    std.fs.cwd().deleteFile(sp) catch {};
}

/// Put a cache hit where the unpacker expects the payload. Archives are only
/// read, so a hard link will do. A `raw` payload is the program itself: the
/// unpacker renames it and makes it executable, which must not touch the
/// cache's inode, so it gets a private copy. That copy is 0755, the mode a
/// streamed raw payload is written with, so the installed file has the same
/// permission bits (and the same dedupe name) whichever way it arrived.
pub fn materialize(src: []const u8, dst: []const u8, raw: bool) !void {
    if (!raw) {
        if (hardLink(src, dst)) |_| return else |_| {}
    }
    const mode = if (raw) platform.mode_bin else platform.mode_private;
    try std.fs.cwd().copyFile(src, std.fs.cwd(), dst, .{ .override_mode = mode });
}

// ---------------------------------------------------------------------------
// Download cache: insert
// ---------------------------------------------------------------------------

/// Keep the verified payload at `src` as cache entry `hex`. The caller has
/// already checked that the file's digest is `hex`. `copy` makes a private copy
/// instead of a hard link (needed when `src` is about to be renamed and
/// chmodded, as for `raw` payloads). Payloads larger than the cache are
/// skipped.
pub fn insertFile(a: Allocator, root: []const u8, cfg: Config, hex_in: []const u8, src: []const u8, copy: bool) !void {
    if (!cfg.cache or !isHex64(hex_in)) return;
    var hex: [64]u8 = undefined;
    _ = std.ascii.lowerString(&hex, hex_in);

    const st = try std.fs.cwd().statFile(src);
    if (st.kind != .file or st.size > cfg.max_bytes) return;

    try ensureCacheDirs(a, root, &hex);
    const dst = try entryPath(a, root, &hex);
    defer a.free(dst);

    if (std.fs.cwd().statFile(dst)) |existing| {
        if (existing.size == st.size) return;
        removeEntryPath(dst);
    } else |_| {}

    if (!copy) {
        if (hardLink(src, dst)) |_| {
            try finishEntry(a, root, cfg, &hex, dst, st.size);
            return;
        } else |e| {
            if (e == error.PathAlreadyExists) return;
        }
    }

    const tmp_dir = try tmpDirPath(a, root);
    defer a.free(tmp_dir);
    try platform.ensureSecureDir(tmp_dir);
    const tmp = try std.fmt.allocPrint(a, "{s}/{x}.part", .{ tmp_dir, std.crypto.random.int(u64) });
    defer a.free(tmp);
    errdefer std.fs.cwd().deleteFile(tmp) catch {};
    try std.fs.cwd().copyFile(src, std.fs.cwd(), tmp, .{ .override_mode = platform.mode_private });
    try commit(a, root, cfg, &hex, tmp, st.size);
}

/// Rename a finished temp file into the cache as entry `hex`.
fn commit(a: Allocator, root: []const u8, cfg: Config, hex: *const [64]u8, tmp: []const u8, size: u64) !void {
    try ensureCacheDirs(a, root, hex);
    const dst = try entryPath(a, root, hex);
    defer a.free(dst);
    try std.fs.cwd().rename(tmp, dst);
    try finishEntry(a, root, cfg, hex, dst, size);
}

/// Permissions, sidecar and eviction for a new entry at `dst`.
fn finishEntry(a: Allocator, root: []const u8, cfg: Config, hex: *const [64]u8, dst: []const u8, size: u64) !void {
    platform.chmodPath(dst, 0o600);
    if (size > trust_sidecar_over) {
        // The sidecar says the bytes were checked, so they must be on disk.
        if (std.fs.cwd().openFile(dst, .{ .mode = .read_write })) |f| {
            defer f.close();
            f.sync() catch {};
        } else |_| {}
        const st = try std.fs.cwd().statFile(dst);
        writeSidecar(a, dst, st.size, st.mtime);
    }
    _ = evict(a, root, cfg.max_bytes, hex);
}

/// Collects the bytes of a streaming download so they can be cached once the
/// digest is known. See the file header for how `stream.zig` feeds it.
pub const Sink = struct {
    a: Allocator,
    root: []const u8,
    cfg: Config,
    file: ?std.fs.File,
    path: []u8,
    hasher: Sha256,
    bytes: u64 = 0,
    failed: bool = false,

    pub fn open(a: Allocator, root: []const u8, cfg: Config) !Sink {
        const dir = try tmpDirPath(a, root);
        defer a.free(dir);
        try platform.ensureSecureDir(dir);
        const path = try std.fmt.allocPrint(a, "{s}/{x}.part", .{ dir, std.crypto.random.int(u64) });
        errdefer a.free(path);
        const f = try std.fs.cwd().createFile(path, .{ .mode = platform.mode_private });
        return .{ .a = a, .root = root, .cfg = cfg, .file = f, .path = path, .hasher = Sha256.init(.{}) };
    }

    /// Append `bytes`. Failures (disk full, over the cache cap) only stop the
    /// sink; they never reach the download.
    pub fn write(self: *Sink, bytes: []const u8) void {
        if (self.failed) return;
        const f = self.file orelse return;
        if (bytes.len > self.cfg.max_bytes -| self.bytes) return self.fail();
        f.writeAll(bytes) catch return self.fail();
        self.hasher.update(bytes);
        self.bytes += bytes.len;
    }

    fn fail(self: *Sink) void {
        self.failed = true;
        self.release();
    }

    fn release(self: *Sink) void {
        if (self.file) |f| f.close();
        self.file = null;
        std.fs.cwd().deleteFile(self.path) catch {};
    }

    /// Cache what was collected as entry `hex`, but only if it hashes to
    /// `hex`. The sink is spent afterwards either way.
    pub fn promote(self: *Sink, hex_in: []const u8) !void {
        if (!isHex64(hex_in)) return error.BadDigest;
        var hex: [64]u8 = undefined;
        _ = std.ascii.lowerString(&hex, hex_in);
        defer self.release();
        const f = self.file orelse return error.SinkFailed;
        if (self.failed or self.bytes == 0) return error.SinkFailed;
        const got = hexOf(&self.hasher.finalResult());
        if (!std.mem.eql(u8, &got, &hex)) return error.HashMismatch;
        f.close();
        self.file = null;
        try commit(self.a, self.root, self.cfg, &hex, self.path, self.bytes);
    }

    pub fn deinit(self: *Sink) void {
        self.release();
        self.a.free(self.path);
        self.* = undefined;
    }
};

/// The sink the current thread is streaming into, if any. Set by the installer
/// around a streaming download; read by `teeWrite`.
pub threadlocal var tee: ?*Sink = null;

/// Called by the stream path with every chunk it reads from the network.
pub fn teeWrite(bytes: []const u8) void {
    if (tee) |s| s.write(bytes);
}

// ---------------------------------------------------------------------------
// Download cache: eviction, stats, prune
// ---------------------------------------------------------------------------

pub const Prune = struct {
    files: u64 = 0,
    bytes: u64 = 0,
};

const CacheEntry = struct {
    hex: [64]u8,
    size: u64,
    mtime: i128,

    fn older(_: void, x: CacheEntry, y: CacheEntry) bool {
        return x.mtime < y.mtime;
    }
};

fn scanCache(aa: Allocator, root: []const u8) !std.ArrayList(CacheEntry) {
    var list = std.ArrayList(CacheEntry).init(aa);
    const base = try std.fs.path.join(aa, &.{ root, "cache", "sha256" });
    var top = std.fs.cwd().openDir(base, .{ .iterate = true }) catch return list;
    defer top.close();
    var it = top.iterate();
    while (try it.next()) |sub| {
        if (sub.kind != .directory or sub.name.len != 2) continue;
        var d = top.openDir(sub.name, .{ .iterate = true }) catch continue;
        defer d.close();
        var it2 = d.iterate();
        while (try it2.next()) |e| {
            if (e.kind != .file or !isHex64(e.name)) continue;
            const st = d.statFile(e.name) catch continue;
            var ce = CacheEntry{ .hex = undefined, .size = st.size, .mtime = st.mtime };
            @memcpy(&ce.hex, e.name[0..64]);
            try list.append(ce);
        }
    }
    return list;
}

fn removeEntry(aa: Allocator, root: []const u8, hex: *const [64]u8) void {
    const p = entryPath(aa, root, hex) catch return;
    removeEntryPath(p);
}

/// Delete least recently used entries until the cache fits in `max_bytes`.
/// `keep` (the entry just inserted) is never chosen.
pub fn evict(a: Allocator, root: []const u8, max_bytes: u64, keep: ?*const [64]u8) Prune {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const aa = arena.allocator();
    var out = Prune{};

    const list = scanCache(aa, root) catch return out;
    var total: u64 = 0;
    for (list.items) |e| total += e.size;
    if (total <= max_bytes) return out;

    std.mem.sort(CacheEntry, list.items, {}, CacheEntry.older);
    for (list.items) |e| {
        if (total <= max_bytes) break;
        if (keep) |k| {
            if (std.mem.eql(u8, &e.hex, k)) continue;
        }
        removeEntry(aa, root, &e.hex);
        total -= e.size;
        out.files += 1;
        out.bytes += e.size;
    }
    return out;
}

pub const Stats = struct {
    entries: u64 = 0,
    bytes: u64 = 0,
    max_bytes: u64 = default_cache_max,
    enabled: bool = true,
};

pub fn cacheStats(a: Allocator, root: []const u8) Stats {
    const cfg = Config.current();
    var s = Stats{ .max_bytes = cfg.max_bytes, .enabled = cfg.cache };
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const list = scanCache(arena.allocator(), root) catch return s;
    for (list.items) |e| {
        s.entries += 1;
        s.bytes += e.size;
    }
    return s;
}

/// What `cleanup` removes from the download cache: entries unused for 30 days,
/// then the least recently used until it fits the cap, and abandoned partial
/// downloads. `dry_run` only counts.
pub fn pruneCache(a: Allocator, root: []const u8, cfg: Config, dry_run: bool) Prune {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const aa = arena.allocator();
    var out = Prune{};

    if (scanCache(aa, root)) |found| {
        const list = found;
        const now = std.time.nanoTimestamp();
        std.mem.sort(CacheEntry, list.items, {}, CacheEntry.older);
        var total: u64 = 0;
        for (list.items) |e| total += e.size;
        for (list.items) |e| {
            const stale = now - e.mtime > stale_after_ns;
            if (!stale and total <= cfg.max_bytes) break;
            if (!dry_run) removeEntry(aa, root, &e.hex);
            total -= e.size;
            out.files += 1;
            out.bytes += e.size;
        }
    } else |_| {}

    const tmp_dir = tmpDirPath(aa, root) catch return out;
    var dir = std.fs.cwd().openDir(tmp_dir, .{ .iterate = true }) catch return out;
    defer dir.close();
    const now = std.time.nanoTimestamp();
    var it = dir.iterate();
    while (it.next() catch null) |e| {
        if (e.kind != .file) continue;
        const st = dir.statFile(e.name) catch continue;
        if (now - st.mtime <= tmp_stale_ns) continue;
        if (!dry_run) dir.deleteFile(e.name) catch continue;
        out.files += 1;
        out.bytes += st.size;
    }
    return out;
}

// ---------------------------------------------------------------------------
// File dedupe
// ---------------------------------------------------------------------------

pub const DedupeStats = struct {
    /// Files replaced by a link to an identical one already in the CAS.
    shared: u64 = 0,
    /// Bytes those links saved.
    bytes: u64 = 0,
    /// Files newly offered to the CAS.
    added: u64 = 0,
};

/// File name in `cas/files`: the digest, plus the permission bits unless they
/// are the common 0644 (and always plain on Windows, which has none).
fn casName(buf: *[72]u8, hex: *const [64]u8, mode: u32) []const u8 {
    if (is_windows or mode == 0o644) return hex;
    return std.fmt.bufPrint(buf, "{s}.{o:0>3}", .{ hex, mode }) catch hex;
}

fn casDirPath(a: Allocator, root: []const u8) ![]u8 {
    return std.fs.path.join(a, &.{ root, "cas", "files" });
}

/// Share the identical files of an unpacked tree through `cas/files`. Call
/// right before the tree is published. Each file is replaced atomically, so a
/// crash leaves a complete tree either way.
pub fn dedupeTree(a: Allocator, root: []const u8, tree: []const u8) !DedupeStats {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const aa = arena.allocator();
    var scratch_state = std.heap.ArenaAllocator.init(a);
    defer scratch_state.deinit();
    const scratch = scratch_state.allocator();

    const cas_root = try std.fs.path.join(aa, &.{ root, "cas" });
    try platform.ensureSecureDir(cas_root);
    const cas_dir = try casDirPath(aa, root);
    try platform.ensureSecureDir(cas_dir);

    // Collect first: the loop below renames files in the directories the walk
    // is still reading.
    var paths = std.ArrayList([]const u8).init(aa);
    {
        var dir = try std.fs.cwd().openDir(tree, .{ .iterate = true });
        defer dir.close();
        var walker = try dir.walk(aa);
        defer walker.deinit();
        while (try walker.next()) |entry| {
            if (entry.kind != .file) continue;
            try paths.append(try aa.dupe(u8, entry.path));
        }
    }

    var stats = DedupeStats{};
    var buf: [64 * 1024]u8 = undefined;
    for (paths.items) |rel| {
        _ = scratch_state.reset(.retain_capacity);
        const file_path = std.fs.path.join(scratch, &.{ tree, rel }) catch continue;

        const f = std.fs.cwd().openFile(file_path, .{}) catch continue;
        defer f.close();
        const st = f.stat() catch continue;
        if (st.kind != .file or st.size < min_dedupe_size) continue;
        const mode = permBits(st.mode);
        if (mode & 0o7000 != 0) continue;
        const perm = mode & 0o777;

        var h = Sha256.init(.{});
        var seen: u64 = 0;
        while (true) {
            const n = f.read(&buf) catch break;
            if (n == 0) break;
            h.update(buf[0..n]);
            seen += n;
        }
        if (seen != st.size) continue;
        const hex = hexOf(&h.finalResult());

        var name_buf: [72]u8 = undefined;
        const name = casName(&name_buf, &hex, perm);
        const cas_path = std.fs.path.join(scratch, &.{ cas_dir, name }) catch continue;

        if (std.fs.cwd().statFile(cas_path)) |have| {
            if (have.kind == .file and have.size == st.size) {
                const staged = std.fmt.allocPrint(scratch, "{s}.abv0dd", .{file_path}) catch continue;
                hardLink(cas_path, staged) catch continue;
                std.fs.cwd().rename(staged, file_path) catch {
                    std.fs.cwd().deleteFile(staged) catch {};
                    continue;
                };
                stats.shared += 1;
                stats.bytes += st.size;
                continue;
            }
            // Same name, other size: a damaged entry. Replace it.
            std.fs.cwd().deleteFile(cas_path) catch continue;
        } else |_| {}

        if (hardLink(file_path, cas_path)) |_| {
            stats.added += 1;
        } else |_| {}
    }
    return stats;
}

pub const CasStats = struct {
    files: u64 = 0,
    bytes: u64 = 0,
    /// Entries only the CAS holds: `pruneCas` removes them.
    orphans: u64 = 0,
    orphan_bytes: u64 = 0,
};

fn forEachCas(a: Allocator, root: []const u8, ctx: anytype, comptime visit: fn (@TypeOf(ctx), std.fs.Dir, []const u8, u64, u64) void) void {
    const cas_dir = casDirPath(a, root) catch return;
    defer a.free(cas_dir);
    var dir = std.fs.cwd().openDir(cas_dir, .{ .iterate = true }) catch return;
    defer dir.close();
    var it = dir.iterate();
    while (it.next() catch null) |e| {
        if (e.kind != .file) continue;
        const f = dir.openFile(e.name, .{}) catch continue;
        defer f.close();
        const st = f.stat() catch continue;
        const links = linkCount(f) catch continue;
        visit(ctx, dir, e.name, st.size, links);
    }
}

pub fn casStats(a: Allocator, root: []const u8) CasStats {
    var s = CasStats{};
    const V = struct {
        fn visit(out: *CasStats, _: std.fs.Dir, _: []const u8, size: u64, links: u64) void {
            out.files += 1;
            out.bytes += size;
            if (links <= 1) {
                out.orphans += 1;
                out.orphan_bytes += size;
            }
        }
    };
    forEachCas(a, root, &s, V.visit);
    return s;
}

/// Remove `cas/files` entries that nothing else links to. `dry_run` only
/// counts them.
pub fn pruneCas(a: Allocator, root: []const u8, dry_run: bool) Prune {
    var out = Prune{};
    const Ctx = struct { out: *Prune, dry: bool };
    const V = struct {
        fn visit(c: Ctx, dir: std.fs.Dir, name: []const u8, size: u64, links: u64) void {
            if (links > 1) return;
            if (!c.dry) dir.deleteFile(name) catch return;
            c.out.files += 1;
            c.out.bytes += size;
        }
    };
    forEachCas(a, root, Ctx{ .out = &out, .dry = dry_run }, V.visit);
    return out;
}

// ---------------------------------------------------------------------------
// Making a deduped file executable
// ---------------------------------------------------------------------------

/// Like `platform.setExecutable`, but a file shared through the CAS is copied
/// first. Its CAS name encodes its permission bits, so changing them in place
/// would change every other install that shares it.
pub fn setExecutable(path: []const u8) void {
    if (comptime is_windows) return platform.setExecutable(path);
    const file = std.fs.cwd().openFile(path, .{}) catch return;
    defer file.close();
    const st = std.posix.fstat(file.handle) catch return;
    const mode: u32 = @intCast(st.mode);
    if (mode & 0o100 != 0) return;
    if (st.nlink > 1) {
        var tmp_buf: [std.fs.max_path_bytes]u8 = undefined;
        const tmp = std.fmt.bufPrint(&tmp_buf, "{s}.{x}.abv0x", .{ path, std.crypto.random.int(u64) }) catch return;
        std.fs.cwd().copyFile(path, std.fs.cwd(), tmp, .{ .override_mode = @intCast((mode | 0o100) & 0o7777) }) catch return;
        std.fs.cwd().rename(tmp, path) catch {
            std.fs.cwd().deleteFile(tmp) catch {};
        };
        return;
    }
    std.posix.fchmod(file.handle, @intCast(mode | 0o100)) catch {};
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn sha256Hex(data: []const u8) [64]u8 {
    var d: [32]u8 = undefined;
    Sha256.hash(data, &d, .{});
    return hexOf(&d);
}

fn tmpRoot(tmp: *testing.TmpDir) ![]u8 {
    return tmp.dir.realpathAlloc(testing.allocator, ".");
}

fn writeAt(dir: std.fs.Dir, path: []const u8, data: []const u8, posix_mode: u32) !void {
    // Windows has no mode bits (File.Mode is u0 there).
    const mode: std.fs.File.Mode = if (builtin.os.tag == .windows) 0 else @intCast(posix_mode);
    if (std.fs.path.dirname(path)) |d| try dir.makePath(d);
    try dir.writeFile(.{ .sub_path = path, .data = data, .flags = .{ .mode = mode } });
    // The creation mode is filtered by the umask; the tests need exact bits.
    if (builtin.os.tag == .windows) return;
    const f = try dir.openFile(path, .{});
    defer f.close();
    try f.chmod(mode);
}

fn inodeOf(dir: std.fs.Dir, path: []const u8) !std.fs.File.INode {
    return (try dir.statFile(path)).inode;
}

test "parseSize reads plain and suffixed byte counts" {
    try testing.expectEqual(@as(?u64, 1048576), parseSize("1048576"));
    try testing.expectEqual(@as(?u64, 2 * 1024 * 1024 * 1024), parseSize("2G"));
    try testing.expectEqual(@as(?u64, 512 * 1024 * 1024), parseSize("512MiB"));
    try testing.expectEqual(@as(?u64, 64 * 1024), parseSize("64k"));
    try testing.expectEqual(@as(?u64, 0), parseSize("0"));
    try testing.expect(parseSize("") == null);
    try testing.expect(parseSize("lots") == null);
    try testing.expect(parseSize("12x") == null);
    try testing.expect(parseSize("99999999999T") == null);
}

test "a verified payload is found again and a bad hash is not" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = try tmpRoot(&tmp);
    defer testing.allocator.free(root);
    const a = testing.allocator;

    try writeAt(tmp.dir, "stage/payload", "hello payload", 0o644);
    const hex = sha256Hex("hello payload");
    const src = try std.fs.path.join(a, &.{ root, "stage", "payload" });
    defer a.free(src);
    try insertFile(a, root, .{}, &hex, src, false);

    const hit = lookup(a, root, &hex) orelse return error.TestExpectedHit;
    defer a.free(hit.path);
    try testing.expectEqual(@as(u64, 13), hit.size);
    try testing.expectEqualStrings("hello payload", hit.head[0..hit.head_len]);

    // 0600 file, 0700 directories.
    const rel = try std.fmt.allocPrint(a, "cache/sha256/{s}/{s}", .{ hex[0..2], hex });
    defer a.free(rel);
    const st = try tmp.dir.statFile(rel);
    if (builtin.os.tag != .windows) try testing.expectEqual(@as(u32, 0o600), @as(u32, @intCast(st.mode)) & 0o777);
    const dst = try tmp.dir.statFile("cache");
    if (builtin.os.tag != .windows) try testing.expectEqual(@as(u32, 0o700), @as(u32, @intCast(dst.mode)) & 0o777);

    const other = sha256Hex("something else");
    try testing.expect(lookup(a, root, &other) == null);
    try testing.expect(lookup(a, root, "not a digest") == null);
}

test "a corrupt cache entry is detected, removed and reported as a miss" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = try tmpRoot(&tmp);
    defer testing.allocator.free(root);
    const a = testing.allocator;

    try writeAt(tmp.dir, "stage/payload", "good bytes here", 0o644);
    const hex = sha256Hex("good bytes here");
    const src = try std.fs.path.join(a, &.{ root, "stage", "payload" });
    defer a.free(src);
    // A copy, not a link, so damaging the cache leaves the staged file alone.
    try insertFile(a, root, .{}, &hex, src, true);

    const rel = try std.fmt.allocPrint(a, "cache/sha256/{s}/{s}", .{ hex[0..2], hex });
    defer a.free(rel);
    {
        const f = try tmp.dir.openFile(rel, .{ .mode = .read_write });
        defer f.close();
        try f.writeAll("bad");
    }
    try testing.expect(lookup(a, root, &hex) == null);
    try testing.expectError(error.FileNotFound, tmp.dir.access(rel, .{}));
}

test "inserting beyond the cap evicts the least recently used entry" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = try tmpRoot(&tmp);
    defer testing.allocator.free(root);
    const a = testing.allocator;
    const cfg = Config{ .max_bytes = 25 };

    const blobs = [_][]const u8{ "aaaaaaaaaa", "bbbbbbbbbb", "cccccccccc" };
    var hexes: [3][64]u8 = undefined;
    for (blobs, 0..) |b, i| {
        hexes[i] = sha256Hex(b);
        try writeAt(tmp.dir, "stage/p", b, 0o644);
        const src = try std.fs.path.join(a, &.{ root, "stage", "p" });
        defer a.free(src);
        try insertFile(a, root, cfg, &hexes[i], src, true);
        // Make the order unambiguous even on coarse timestamps.
        const rel = try std.fmt.allocPrint(a, "cache/sha256/{s}/{s}", .{ hexes[i][0..2], hexes[i] });
        defer a.free(rel);
        if (tmp.dir.openFile(rel, .{ .mode = .read_write })) |f| {
            defer f.close();
            const t: i128 = (@as(i128, @intCast(i)) + 1) * 10 * std.time.ns_per_s;
            try f.updateTimes(t, t);
        } else |_| {}
        if (i == 1) {
            // Use the first entry again: it is now newer than the second.
            const hit = lookup(a, root, &hexes[0]) orelse return error.TestExpectedHit;
            a.free(hit.path);
        }
    }
    // 30 bytes were offered into a 25 byte cache: exactly one entry is gone,
    // and it is the one nobody used since insertion (the second).
    try testing.expect(lookup(a, root, &hexes[1]) == null);
    const keep0 = lookup(a, root, &hexes[0]) orelse return error.TestExpectedHit;
    a.free(keep0.path);
    const keep2 = lookup(a, root, &hexes[2]) orelse return error.TestExpectedHit;
    a.free(keep2.path);

    const stats = cacheStats(a, root);
    try testing.expectEqual(@as(u64, 2), stats.entries);
    try testing.expectEqual(@as(u64, 20), stats.bytes);
}

test "a payload larger than the whole cache is not kept" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = try tmpRoot(&tmp);
    defer testing.allocator.free(root);
    const a = testing.allocator;

    try writeAt(tmp.dir, "stage/p", "0123456789", 0o644);
    const src = try std.fs.path.join(a, &.{ root, "stage", "p" });
    defer a.free(src);
    const hex = sha256Hex("0123456789");
    try insertFile(a, root, .{ .max_bytes = 5 }, &hex, src, false);
    try testing.expect(lookup(a, root, &hex) == null);
}

test "disabled configuration keeps nothing" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = try tmpRoot(&tmp);
    defer testing.allocator.free(root);
    const a = testing.allocator;

    try writeAt(tmp.dir, "stage/p", "payload", 0o644);
    const src = try std.fs.path.join(a, &.{ root, "stage", "p" });
    defer a.free(src);
    const hex = sha256Hex("payload");
    try insertFile(a, root, .{ .cache = false }, &hex, src, false);
    try testing.expectEqual(@as(u64, 0), cacheStats(a, root).entries);
    try testing.expectError(error.FileNotFound, tmp.dir.access("cache", .{}));
}

test "a sink promotes only the bytes that hash to the expected digest" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = try tmpRoot(&tmp);
    defer testing.allocator.free(root);
    const a = testing.allocator;

    const hex = sha256Hex("streamed payload");
    {
        var sink = try Sink.open(a, root, .{});
        defer sink.deinit();
        tee = &sink;
        defer tee = null;
        teeWrite("streamed ");
        teeWrite("payload");
        try sink.promote(&hex);
    }
    const hit = lookup(a, root, &hex) orelse return error.TestExpectedHit;
    a.free(hit.path);

    // A chunk the stream path never passed on: the hash gives it away.
    const hex2 = sha256Hex("whole thing");
    {
        var sink = try Sink.open(a, root, .{});
        defer sink.deinit();
        sink.write("whole ");
        try testing.expectError(error.HashMismatch, sink.promote(&hex2));
    }
    try testing.expect(lookup(a, root, &hex2) == null);

    // Nothing is left behind in the temp directory.
    var dir = try tmp.dir.openDir("cache/tmp", .{ .iterate = true });
    defer dir.close();
    var it = dir.iterate();
    try testing.expect((try it.next()) == null);
}

test "pruneCache drops entries that fit the cap only when stale, and counts a dry run" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = try tmpRoot(&tmp);
    defer testing.allocator.free(root);
    const a = testing.allocator;

    const old = sha256Hex("old payload");
    const fresh = sha256Hex("fresh payload");
    for ([_][]const u8{ "old payload", "fresh payload" }) |b| {
        try writeAt(tmp.dir, "stage/p", b, 0o644);
        const src = try std.fs.path.join(a, &.{ root, "stage", "p" });
        defer a.free(src);
        const hex = sha256Hex(b);
        try insertFile(a, root, .{}, &hex, src, true);
    }
    {
        const rel = try std.fmt.allocPrint(a, "cache/sha256/{s}/{s}", .{ old[0..2], old });
        defer a.free(rel);
        const f = try tmp.dir.openFile(rel, .{ .mode = .read_write });
        defer f.close();
        const t: i128 = std.time.nanoTimestamp() - 40 * 24 * std.time.ns_per_hour;
        try f.updateTimes(t, t);
    }

    const dry = pruneCache(a, root, .{}, true);
    try testing.expectEqual(@as(u64, 1), dry.files);
    try testing.expectEqual(@as(u64, 11), dry.bytes);
    try testing.expectEqual(@as(u64, 2), cacheStats(a, root).entries);

    const real = pruneCache(a, root, .{}, false);
    try testing.expectEqual(@as(u64, 1), real.files);
    try testing.expectEqual(@as(u64, 1), cacheStats(a, root).entries);
    const hit = lookup(a, root, &fresh) orelse return error.TestExpectedHit;
    a.free(hit.path);
}

test "dedupe links identical files across two versions and keeps modes distinct" {
    // POSIX mode bits; Windows has none.
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = try tmpRoot(&tmp);
    defer testing.allocator.free(root);
    const a = testing.allocator;

    const doc = "d" ** 6000;
    const prog = "p" ** 5000;
    const small = "tiny";

    // Version 1.
    try writeAt(tmp.dir, "v1/share/doc.txt", doc, 0o644);
    try writeAt(tmp.dir, "v1/bin/tool", prog, 0o755);
    try writeAt(tmp.dir, "v1/bin/tool-copy", prog, 0o644);
    try writeAt(tmp.dir, "v1/small", small, 0o644);
    const v1 = try std.fs.path.join(a, &.{ root, "v1" });
    defer a.free(v1);
    const s1 = try dedupeTree(a, root, v1);
    try testing.expectEqual(@as(u64, 0), s1.shared);
    try testing.expectEqual(@as(u64, 3), s1.added);

    // Version 2: the doc and the program are unchanged, one file is new.
    try writeAt(tmp.dir, "v2/share/doc.txt", doc, 0o644);
    try writeAt(tmp.dir, "v2/bin/tool", prog, 0o755);
    try writeAt(tmp.dir, "v2/bin/tool-copy", prog, 0o644);
    try writeAt(tmp.dir, "v2/share/new.txt", "n" ** 4096, 0o644);
    try writeAt(tmp.dir, "v2/small", small, 0o644);
    const v2 = try std.fs.path.join(a, &.{ root, "v2" });
    defer a.free(v2);
    const s2 = try dedupeTree(a, root, v2);
    try testing.expectEqual(@as(u64, 3), s2.shared);
    try testing.expectEqual(@as(u64, 1), s2.added);
    try testing.expectEqual(@as(u64, 6000 + 5000 + 5000), s2.bytes);

    // Same bytes and mode: one inode.
    try testing.expectEqual(try inodeOf(tmp.dir, "v1/share/doc.txt"), try inodeOf(tmp.dir, "v2/share/doc.txt"));
    try testing.expectEqual(try inodeOf(tmp.dir, "v1/bin/tool"), try inodeOf(tmp.dir, "v2/bin/tool"));
    // Same bytes, different mode: never shared.
    try testing.expect(try inodeOf(tmp.dir, "v1/bin/tool") != try inodeOf(tmp.dir, "v1/bin/tool-copy"));
    // Modes survive, and below the size threshold nothing is linked.
    try testing.expectEqual(@as(u32, 0o755), @as(u32, @intCast((try tmp.dir.statFile("v2/bin/tool")).mode)) & 0o777);
    try testing.expectEqual(@as(u32, 0o644), @as(u32, @intCast((try tmp.dir.statFile("v2/bin/tool-copy")).mode)) & 0o777);
    try testing.expect(try inodeOf(tmp.dir, "v1/small") != try inodeOf(tmp.dir, "v2/small"));
    // Contents are untouched.
    const got = try tmp.dir.readFileAlloc(a, "v2/bin/tool", 1 << 20);
    defer a.free(got);
    try testing.expectEqualStrings(prog, got);
    // No staging leftovers.
    try testing.expectError(error.FileNotFound, tmp.dir.access("v2/bin/tool.abv0dd", .{}));
}

test "dedupe leaves symlinks alone" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = try tmpRoot(&tmp);
    defer testing.allocator.free(root);
    const a = testing.allocator;

    try writeAt(tmp.dir, "t/real", "r" ** 5000, 0o644);
    try tmp.dir.symLink("real", "t/alias", .{});
    const t = try std.fs.path.join(a, &.{ root, "t" });
    defer a.free(t);
    const s = try dedupeTree(a, root, t);
    try testing.expectEqual(@as(u64, 1), s.added);

    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("real", try tmp.dir.readLink("t/alias", &buf));
}

test "gc of the CAS removes only files nothing else links to" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = try tmpRoot(&tmp);
    defer testing.allocator.free(root);
    const a = testing.allocator;

    try writeAt(tmp.dir, "keep/f", "k" ** 5000, 0o644);
    try writeAt(tmp.dir, "drop/f", "x" ** 5000, 0o644);
    const keep = try std.fs.path.join(a, &.{ root, "keep" });
    defer a.free(keep);
    const drop = try std.fs.path.join(a, &.{ root, "drop" });
    defer a.free(drop);
    _ = try dedupeTree(a, root, keep);
    _ = try dedupeTree(a, root, drop);
    try testing.expectEqual(@as(u64, 2), casStats(a, root).files);
    try testing.expectEqual(@as(u64, 0), casStats(a, root).orphans);

    // Uninstalling a package deletes its tree; the CAS keeps its file.
    try tmp.dir.deleteTree("drop");
    const stats = casStats(a, root);
    try testing.expectEqual(@as(u64, 1), stats.orphans);
    try testing.expectEqual(@as(u64, 5000), stats.orphan_bytes);

    const dry = pruneCas(a, root, true);
    try testing.expectEqual(@as(u64, 1), dry.files);
    try testing.expectEqual(@as(u64, 2), casStats(a, root).files);

    const real = pruneCas(a, root, false);
    try testing.expectEqual(@as(u64, 1), real.files);
    try testing.expectEqual(@as(u64, 5000), real.bytes);
    try testing.expectEqual(@as(u64, 1), casStats(a, root).files);
    // The surviving tree is intact.
    const kept = try tmp.dir.readFileAlloc(a, "keep/f", 1 << 20);
    defer a.free(kept);
    try testing.expectEqual(@as(usize, 5000), kept.len);
}

test "making a shared file executable copies it first" {
    // POSIX mode bits; Windows has none.
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = try tmpRoot(&tmp);
    defer testing.allocator.free(root);
    const a = testing.allocator;

    try writeAt(tmp.dir, "a/data", "z" ** 5000, 0o644);
    try writeAt(tmp.dir, "b/data", "z" ** 5000, 0o644);
    const pa = try std.fs.path.join(a, &.{ root, "a" });
    defer a.free(pa);
    const pb = try std.fs.path.join(a, &.{ root, "b" });
    defer a.free(pb);
    _ = try dedupeTree(a, root, pa);
    _ = try dedupeTree(a, root, pb);
    try testing.expectEqual(try inodeOf(tmp.dir, "a/data"), try inodeOf(tmp.dir, "b/data"));

    const target = try std.fs.path.join(a, &.{ root, "a", "data" });
    defer a.free(target);
    setExecutable(target);
    try testing.expect(@as(u32, @intCast((try tmp.dir.statFile("a/data")).mode)) & 0o100 != 0);
    try testing.expectEqual(@as(u32, 0o644), @as(u32, @intCast((try tmp.dir.statFile("b/data")).mode)) & 0o777);
    try testing.expect(try inodeOf(tmp.dir, "a/data") != try inodeOf(tmp.dir, "b/data"));
}
