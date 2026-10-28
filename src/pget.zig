//! Progressive parallel download.
//!
//! One GET starts at byte 0. When its response head arrives and says the body
//! is big (`ABV0_SPLIT_MIN`, default 8 MiB) and that byte ranges work, the
//! other chunks are requested at once, each on its own connection, for the same
//! post-redirect URL. The first connection keeps reading chunk 0 only. There is
//! no HEAD round trip: the first GET is the probe.
//!
//! Chunks are written with positional writes into one preallocated file. The
//! SHA-256 is computed in order as the bytes become contiguous: chunk 0 is
//! hashed while it streams, and every later chunk is hashed as soon as the
//! chunks before it are, so the digest is final when the last byte lands and
//! the file is never read in a pass of its own. The same in-order cursor makes
//! the file readable while it is still being filled, so a consumer (the
//! streaming unpacker) can decode chunk 0 while chunks 5 to 7 are in flight.
//!
//! Micro-shards (`--micro-shards`, `ABV0_SHARD_SIZE`): instead of one chunk
//! per connection, the body is cut into many small shards (1 MiB by default)
//! that the connections take from a shared queue. A fast connection takes more
//! shards and a slow one fewer, so one slow connection no longer holds up the
//! end of the download. Each shard is one ranged request on a kept-alive
//! connection; the in-order hash works the same.
//!
//! Transport is the built-in client (`http.zig`) or, when that cannot talk to
//! the server, one `curl` process per chunk that pipes its body here. Both go
//! through the same engine; only `open(start, end)` differs.
//!
//! Safety rules are the ones every other download follows: https only on
//! every redirect hop (`http.resolveRedirect`), the size cap, no
//! Accept-Encoding, request headers only for the original host, headers to curl
//! only through a private file. A ranged answer must be a 206 for exactly the
//! span asked for, or the chunk fails instead of writing the wrong bytes.

const std = @import("std");
const builtin = @import("builtin");
const archive = @import("archive.zig");
const http = @import("http.zig");
const net = @import("net.zig");
const platform = @import("platform.zig");

const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Thread = std.Thread;
const page = std.heap.page_allocator;

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/// Bodies at least this big are split (ABV0_SPLIT_MIN).
pub const default_split_min: u64 = 8 << 20;
/// Auto mode gives each connection at least this much to fetch.
pub const default_chunk_target: u64 = 4 << 20;
/// Connections used at most (ABV0_CONNECTIONS raises or lowers it).
pub const default_max_conns: u32 = 8;
pub const hard_max_conns: u32 = 16;
/// When ABV0_CONNECTIONS is set, chunks may be as small as this.
pub const forced_min_chunk: u64 = 256 << 10;
/// Most shards one download is cut into; bigger bodies get bigger shards.
pub const max_shards: u32 = 1024;
/// Shard size when micro-shards are on and no size is given.
pub const default_shard_size: u64 = 1 << 20;
/// Smallest shard: below this the per-request cost outweighs the gain.
pub const min_shard_size: u64 = 64 << 10;
/// Set from `--micro-shards[=SIZE]`; wins over `ABV0_SHARD_SIZE`.
pub var shard_override: ?u64 = null;
/// Retries of one chunk, each on a fresh connection.
pub const max_chunk_retries: u32 = 2;
/// Bytes of the payload kept for the error-page check and the type sniff.
pub const head_keep = archive.head_len;

pub const Config = struct {
    split_min: u64 = default_split_min,
    max_conns: u32 = default_max_conns,
    /// ABV0_CONNECTIONS was given: use that many whatever the size, down to
    /// `forced_min_chunk` per connection.
    forced: bool = false,
    /// Micro-shards: the size of each shard, or null for one chunk per connection.
    shard_size: ?u64 = null,
};

/// `ABV0_SHARD_SIZE` / `--micro-shards=SIZE`: "on"/"1" means the default
/// size, "off"/"0" means none, else a size (at least `min_shard_size`).
pub fn parseShardSize(text: ?[]const u8) ?u64 {
    const t = std.mem.trim(u8, text orelse return null, " \t");
    if (t.len == 0 or std.ascii.eqlIgnoreCase(t, "on") or std.mem.eql(u8, t, "1") or std.ascii.eqlIgnoreCase(t, "true")) return default_shard_size;
    if (std.ascii.eqlIgnoreCase(t, "off") or std.mem.eql(u8, t, "0") or std.ascii.eqlIgnoreCase(t, "false")) return null;
    const v = parseSize(t) orelse return null;
    return @max(v, min_shard_size);
}

/// `8M`, `8MiB`, `512k`, `1048576`. Null when it is not a size.
pub fn parseSize(text: ?[]const u8) ?u64 {
    const t = std.mem.trim(u8, text orelse return null, " \t");
    var i: usize = 0;
    while (i < t.len and std.ascii.isDigit(t[i])) i += 1;
    if (i == 0) return null;
    const n = std.fmt.parseInt(u64, t[0..i], 10) catch return null;
    const suffix = std.mem.trim(u8, t[i..], " ");
    const mult: u64 = if (suffix.len == 0 or std.ascii.eqlIgnoreCase(suffix, "b"))
        1
    else if (std.ascii.eqlIgnoreCase(suffix, "k") or std.ascii.eqlIgnoreCase(suffix, "kb") or std.ascii.eqlIgnoreCase(suffix, "kib"))
        1 << 10
    else if (std.ascii.eqlIgnoreCase(suffix, "m") or std.ascii.eqlIgnoreCase(suffix, "mb") or std.ascii.eqlIgnoreCase(suffix, "mib"))
        1 << 20
    else if (std.ascii.eqlIgnoreCase(suffix, "g") or std.ascii.eqlIgnoreCase(suffix, "gb") or std.ascii.eqlIgnoreCase(suffix, "gib"))
        1 << 30
    else
        return null;
    return std.math.mul(u64, n, mult) catch null;
}

/// A connection count, 1 to `hard_max_conns`. Larger values are clamped, zero
/// and text that is not a number are null (ignored).
pub fn parseConns(text: ?[]const u8) ?u32 {
    const t = std.mem.trim(u8, text orelse return null, " \t");
    const n = std.fmt.parseInt(u32, t, 10) catch return null;
    if (n == 0) return null;
    return @min(n, hard_max_conns);
}

pub fn configFrom(split_text: ?[]const u8, conns_text: ?[]const u8) Config {
    var cfg: Config = .{ .shard_size = shard_override };
    if (parseSize(split_text)) |v| cfg.split_min = v;
    if (parseConns(conns_text)) |v| {
        cfg.max_conns = v;
        cfg.forced = true;
    }
    return cfg;
}

pub fn configFromEnv() Config {
    // Windows widens the variable name to UTF-16 in this buffer, so it is not tight.
    var b1: [256]u8 = undefined;
    var b2: [256]u8 = undefined;
    var f1 = std.heap.FixedBufferAllocator.init(&b1);
    var f2 = std.heap.FixedBufferAllocator.init(&b2);
    const split = std.process.getEnvVarOwned(f1.allocator(), "ABV0_SPLIT_MIN") catch null;
    const conns = std.process.getEnvVarOwned(f2.allocator(), "ABV0_CONNECTIONS") catch null;
    var cfg = configFrom(split, conns);
    if (shard_override == null) {
        var b3: [256]u8 = undefined;
        var f3 = std.heap.FixedBufferAllocator.init(&b3);
        cfg.shard_size = parseShardSize(std.process.getEnvVarOwned(f3.allocator(), "ABV0_SHARD_SIZE") catch null);
    }
    return cfg;
}

/// How many connections a body of `total` bytes gets: 1 below the threshold,
/// otherwise `min(max_conns, total / chunk target)`, never below 1.
pub fn connectionsFor(cfg: Config, total: u64) u32 {
    if (total < cfg.split_min) return 1;
    // With shards, a connection is worth opening once there are two shards for it.
    const per = if (cfg.forced) forced_min_chunk else if (cfg.shard_size) |sz| sz * 2 else default_chunk_target;
    const by_size = total / per;
    return @intCast(@max(1, @min(@as(u64, cfg.max_conns), by_size)));
}

/// `connectionsFor`, given what the response head said. A body of unknown
/// length cannot be split. A server that says `Accept-Ranges: none` is not
/// asked. One that says nothing is probed, but only when the caller can start
/// over if the probe fails (a download to a file, not a stream being decoded).
pub fn connectionsToUse(cfg: Config, total: ?u64, ranges: http.AcceptRanges, can_restart: bool) u32 {
    const t = total orelse return 1;
    switch (ranges) {
        .no => return 1,
        .unknown => if (!can_restart) return 1,
        .yes => {},
    }
    return connectionsFor(cfg, t);
}

// ---------------------------------------------------------------------------
// Chunk plan
// ---------------------------------------------------------------------------

/// Bytes `start..end` (end exclusive).
pub const Chunk = struct {
    start: u64,
    end: u64,

    pub fn len(self: Chunk) u64 {
        return self.end - self.start;
    }
};

pub const Plan = struct {
    n: u32,
    items: [max_shards]Chunk,

    pub fn slice(self: *const Plan) []const Chunk {
        return self.items[0..self.n];
    }
};

/// Split `total` bytes into `n` chunks. Every chunk but the last has
/// `total / n` bytes; the last takes the remainder. `n` is clamped to
/// 1..hard_max_conns and to `total` (no empty chunks) unless total is 0.
pub fn planChunks(total: u64, n_wanted: u32) Plan {
    var n: u32 = std.math.clamp(n_wanted, 1, hard_max_conns);
    if (total > 0 and n > total) n = @intCast(total);
    var plan: Plan = .{ .n = n, .items = undefined };
    const size = total / n;
    for (0..n) |i| {
        const start = size * i;
        plan.items[i] = .{ .start = start, .end = if (i == n - 1) total else start + size };
    }
    return plan;
}

/// Cut `total` bytes into shards of `shard_size` (the last one shorter). When
/// that would make more than `max_shards`, the shards grow to fit.
pub fn planShards(total: u64, shard_size: u64) Plan {
    var size = @max(shard_size, 1);
    if (total > 0 and (total + size - 1) / size > max_shards) size = (total + max_shards - 1) / max_shards;
    var plan: Plan = .{ .n = 0, .items = undefined };
    var start: u64 = 0;
    while (start < total) : (start += size) {
        plan.items[plan.n] = .{ .start = start, .end = @min(total, start + size) };
        plan.n += 1;
    }
    if (plan.n == 0) {
        plan.items[0] = .{ .start = 0, .end = 0 };
        plan.n = 1;
    }
    return plan;
}

// ---------------------------------------------------------------------------
// Digest of what has been received
// ---------------------------------------------------------------------------

/// SHA-256 of a payload plus its leading bytes, which the error-page check and
/// the type sniff read.
pub const Digester = struct {
    hasher: Sha256 = Sha256.init(.{}),
    head_buf: [head_keep]u8 = undefined,
    head_len: usize = 0,
    bytes: u64 = 0,

    pub fn update(self: *Digester, data: []const u8) void {
        self.hasher.update(data);
        if (self.head_len < head_keep) {
            const take = @min(head_keep - self.head_len, data.len);
            @memcpy(self.head_buf[self.head_len..][0..take], data[0..take]);
            self.head_len += take;
        }
        self.bytes += data.len;
    }

    pub fn fetched(self: *Digester, connections: u32) Fetched {
        var out: Fetched = .{
            .digest = undefined,
            .bytes = self.bytes,
            .head = self.head_buf,
            .head_len = self.head_len,
            .connections = connections,
        };
        self.hasher.final(&out.digest);
        return out;
    }
};

/// What a finished download yields.
pub const Fetched = struct {
    digest: [32]u8,
    bytes: u64,
    head: [head_keep]u8,
    head_len: usize,
    /// Connections that carried the body (1 for a single stream).
    connections: u32 = 1,

    pub fn headBytes(self: *const Fetched) []const u8 {
        return self.head[0..self.head_len];
    }
};

// ---------------------------------------------------------------------------
// Assembly: the preallocated file and the in-order hash cursor
// ---------------------------------------------------------------------------

/// Receives chunk bytes in any order and keeps a SHA-256 over the file in
/// order. A byte is hashed once, when everything before it has been.
pub const Assembly = struct {
    file: std.fs.File,
    chunks: []const Chunk,
    total: u64,

    /// Guards `filled`, `readable` and `failed`.
    state: Thread.Mutex = .{},
    ready: Thread.Condition = .{},
    /// Contiguous bytes received at the start of each chunk.
    filled: [max_shards]u64 = [_]u64{0} ** max_shards,
    /// Bytes hashed so far, which is also how much of the file may be read.
    readable: u64 = 0,
    failed: ?anyerror = null,
    cancelled: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    /// Guards the digest state below. Only one thread hashes at a time.
    hash_lock: Thread.Mutex = .{},
    dirty: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    digest: Digester = .{},
    /// Chunk the hash cursor is in.
    cursor: usize = 0,

    pub fn init(file: std.fs.File, chunks: []const Chunk, total: u64) Assembly {
        return .{ .file = file, .chunks = chunks, .total = total };
    }

    pub fn isCancelled(self: *const Assembly) bool {
        return self.cancelled.load(.acquire);
    }

    /// Record the first failure and wake every waiter. Workers notice the
    /// flag between reads and stop.
    pub fn fail(self: *Assembly, err: anyerror) void {
        self.state.lock();
        defer self.state.unlock();
        if (self.failed == null) self.failed = err;
        self.cancelled.store(true, .release);
        self.ready.broadcast();
    }

    pub fn failure(self: *Assembly) ?anyerror {
        self.state.lock();
        defer self.state.unlock();
        return self.failed;
    }

    /// Write `data`, which belongs at absolute offset `abs` inside chunk `idx`.
    /// The bytes of one chunk must arrive in order; chunks may arrive in any
    /// order. When they are exactly the next bytes to hash they are hashed from
    /// memory, otherwise the hash cursor reads them back from the file later.
    pub fn put(self: *Assembly, idx: usize, abs: u64, data: []const u8) !void {
        if (data.len == 0) return;
        self.file.pwriteAll(data, abs) catch return error.WriteFailed;

        if (self.hash_lock.tryLock()) {
            const direct = self.cursor == idx and abs == self.digest.bytes;
            if (direct) self.digest.update(data);
            self.bump(idx, data.len);
            const drained = self.drainLocked();
            self.hash_lock.unlock();
            try drained;
            // Another thread may have found the lock busy while we held it.
            return self.kick();
        }
        self.bump(idx, data.len);
        return self.kick();
    }

    fn bump(self: *Assembly, idx: usize, n: usize) void {
        self.state.lock();
        defer self.state.unlock();
        self.filled[idx] += n;
    }

    /// Hash whatever has become contiguous. The flag closes the window where a
    /// thread finds the lock busy just as its holder finishes looking: the
    /// holder clears the flag before it looks and checks it again after.
    fn kick(self: *Assembly) !void {
        self.dirty.store(true, .seq_cst);
        while (self.dirty.load(.seq_cst)) {
            if (!self.hash_lock.tryLock()) return;
            self.dirty.store(false, .seq_cst);
            const r = self.drainLocked();
            self.hash_lock.unlock();
            try r;
        }
    }

    /// Caller holds `hash_lock`. Hash every contiguous byte not yet hashed,
    /// reading it back from the file, and step the cursor over finished chunks.
    fn drainLocked(self: *Assembly) !void {
        var buf: [64 * 1024]u8 = undefined;
        while (self.cursor < self.chunks.len) {
            const c = self.chunks[self.cursor];
            self.state.lock();
            const have_end = c.start + self.filled[self.cursor];
            self.state.unlock();

            const hashed = self.digest.bytes;
            if (have_end > hashed) {
                const take: usize = @intCast(@min(have_end - hashed, buf.len));
                const got = self.file.preadAll(buf[0..take], hashed) catch return error.ReadFailed;
                if (got != take) return error.ReadFailed;
                self.digest.update(buf[0..take]);
                continue;
            }
            if (hashed == c.end) {
                self.cursor += 1;
                continue;
            }
            break;
        }
        self.publish();
    }

    fn publish(self: *Assembly) void {
        self.state.lock();
        defer self.state.unlock();
        if (self.digest.bytes != self.readable) {
            self.readable = self.digest.bytes;
            self.ready.broadcast();
        }
    }

    pub fn isComplete(self: *Assembly) bool {
        self.state.lock();
        defer self.state.unlock();
        return self.readable == self.total;
    }

    /// Bytes in order from the start that may be read (hashed so far).
    pub fn readableBytes(self: *Assembly) u64 {
        self.state.lock();
        defer self.state.unlock();
        return self.readable;
    }

    /// Block until the byte at `pos` is readable or the download is over.
    /// Returns how many bytes starting at `pos` are readable; zero means the
    /// end of the payload. A failed download returns its error at once.
    pub fn waitReadable(self: *Assembly, pos: u64) !u64 {
        self.state.lock();
        defer self.state.unlock();
        while (true) {
            if (self.failed) |e| return e;
            if (self.readable > pos) return self.readable - pos;
            if (self.readable >= self.total) return 0;
            self.ready.wait(&self.state);
        }
    }

    /// Read in-order payload bytes at `pos`, waiting for them to arrive.
    pub fn readAt(self: *Assembly, pos: u64, out: []u8) !usize {
        if (out.len == 0) return 0;
        const avail = try self.waitReadable(pos);
        if (avail == 0) return 0;
        const take: usize = @intCast(@min(avail, out.len));
        const got = self.file.preadAll(out[0..take], pos) catch return error.ReadFailed;
        if (got != take) return error.ReadFailed;
        return take;
    }

    /// The digest, once every byte has landed and been hashed.
    pub fn finalDigest(self: *Assembly, connections: u32) !Fetched {
        if (self.failure()) |e| return e;
        if (!self.isComplete()) return error.Incomplete;
        self.hash_lock.lock();
        defer self.hash_lock.unlock();
        return self.digest.fetched(connections);
    }
};

// ---------------------------------------------------------------------------
// Chunk driver: retries, resume, cancellation
// ---------------------------------------------------------------------------

/// True when another try at the chunk may help. Our own refusals and local
/// disk errors do not get better by asking again.
pub fn chunkRetryable(err: anyerror) bool {
    return switch (err) {
        error.RangeNotHonoured,
        error.WriteFailed,
        error.ReadFailed,
        error.OutOfMemory,
        error.DownloadTooLarge,
        error.UnsafeUrl,
        error.UnsafeRedirect,
        error.BadRedirect,
        error.TooManyRedirects,
        error.Canceled,
        error.NoSpaceLeft,
        error.DiskQuota,
        error.CurlMissing,
        => false,
        error.HttpStatus => http.isTransientStatus(http.last_http_status),
        else => true,
    };
}

/// Failures of one chunk so far, against the retry budget. Pure bookkeeping,
/// so the policy can be tested without a network.
pub const RetryBudget = struct {
    failures: u32 = 0,
    max: u32 = max_chunk_retries,

    /// Record a failure. True when the chunk should be tried again.
    pub fn onFailure(self: *RetryBudget, err: anyerror) bool {
        self.failures += 1;
        return chunkRetryable(err) and self.failures <= self.max;
    }
};

fn retryPause(comptime Src: type, failures: u32) void {
    const ms: u64 = if (@hasDecl(Src, "retry_delay_ms")) Src.retry_delay_ms else 150;
    if (ms == 0) return;
    std.time.sleep(ms * failures * std.time.ns_per_ms);
}

/// Fetch chunk `idx` into `sink`. `initial` is an already open body for the
/// chunk's first byte (the unranged GET, for chunk 0). After a failure the
/// chunk is requested again from the first byte it still lacks, on a fresh
/// connection, at most `max_chunk_retries` times.
///
/// `hook` has `register(body)` and `clear()`, called around each body's use, so
/// the engine can interrupt a read that is stuck when the download is abandoned.
pub fn driveChunk(
    comptime Src: type,
    sink: *Assembly,
    src: *Src,
    idx: usize,
    initial: ?Src.Body,
    buf: []u8,
    hook: anytype,
) !void {
    const c = sink.chunks[idx];
    var pos = c.start;
    var first = initial;
    // An open body that is never used (the download was cancelled first) still
    // has a connection to give back.
    defer if (first) |b| b.close();
    var budget: RetryBudget = .{};
    while (pos < c.end) {
        if (sink.isCancelled()) return error.Canceled;

        const body = if (first) |b| blk: {
            first = null;
            break :blk b;
        } else src.open(pos, c.end - 1) catch |e| {
            if (!sink.isCancelled() and budget.onFailure(e)) {
                retryPause(Src, budget.failures);
                continue;
            }
            return e;
        };

        hook.register(body);
        const result = pump(sink, idx, body, &pos, c.end, buf);
        hook.clear();
        body.close();
        result catch |e| {
            if (!sink.isCancelled() and budget.onFailure(e)) {
                retryPause(Src, budget.failures);
                continue;
            }
            return e;
        };
    }
}

fn pump(sink: *Assembly, idx: usize, body: anytype, pos: *u64, end: u64, buf: []u8) !void {
    while (pos.* < end) {
        if (sink.isCancelled()) return error.Canceled;
        const want: usize = @intCast(@min(@as(u64, buf.len), end - pos.*));
        const n = try body.read(buf[0..want]);
        if (n == 0) return error.UnexpectedEof;
        try sink.put(idx, pos.*, buf[0..n]);
        pos.* += n;
    }
}

// ---------------------------------------------------------------------------
// Engine: workers over one transport
// ---------------------------------------------------------------------------

const io_buf_len = 128 * 1024;

/// Runs the chunks of one download. `Src` supplies `Body` (a type with
/// `read([]u8) !usize` and `close()`) and `open(start, end_inclusive) !Body`.
pub fn Engine(comptime Src: type) type {
    return struct {
        const Self = @This();
        pub const Body = Src.Body;

        src: Src,
        sink: Assembly,
        plan: Plan,
        initial: ?Body,
        initial_taken: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        /// Workers (connections); with micro-shards, fewer than `plan.n`.
        conns: u32,
        next: std.atomic.Value(u32) = std.atomic.Value(u32).init(1),
        running: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
        threads: [hard_max_conns]?Thread = [_]?Thread{null} ** hard_max_conns,
        /// The body each worker is reading, so `fail` can unstick it.
        active_mu: Thread.Mutex = .{},
        active: [hard_max_conns]?Body = [_]?Body{null} ** hard_max_conns,

        const Hook = struct {
            eng: *Self,
            slot: usize,
            pub fn register(h: Hook, b: Body) void {
                h.eng.active_mu.lock();
                defer h.eng.active_mu.unlock();
                h.eng.active[h.slot] = b;
            }
            pub fn clear(h: Hook) void {
                h.eng.active_mu.lock();
                defer h.eng.active_mu.unlock();
                h.eng.active[h.slot] = null;
            }
        };

        /// The engine is pinned in memory: the sink points into `plan`.
        /// `n` connections; with `shard_size`, they share many small shards.
        pub fn create(src: Src, file: std.fs.File, total: u64, n: u32, initial: ?Body, shard_size: ?u64) !*Self {
            const self = try page.create(Self);
            const plan = if (shard_size) |sz| planShards(total, sz) else planChunks(total, n);
            self.* = .{
                .src = src,
                .sink = undefined,
                .plan = plan,
                .conns = @max(1, @min(std.math.clamp(n, 1, hard_max_conns), plan.n)),
                .initial = initial,
            };
            self.sink = Assembly.init(file, self.plan.slice(), total);
            return self;
        }

        pub fn connections(self: *const Self) u32 {
            return self.conns;
        }

        /// Close what was never used and free the engine. Workers are joined.
        pub fn destroy(self: *Self) void {
            self.join();
            if (self.initial) |b| {
                if (!self.initial_taken.load(.acquire)) b.close();
            }
            page.destroy(self);
        }

        fn spawnOne(self: *Self, slot: usize, first: bool) bool {
            _ = self.running.fetchAdd(1, .acq_rel);
            self.threads[slot] = Thread.spawn(.{}, worker, .{ self, slot, first }) catch {
                _ = self.running.fetchSub(1, .acq_rel);
                return false;
            };
            return true;
        }

        /// Start every worker, chunk 0's included, and return. The caller
        /// reads the in-order bytes through the sink while they run.
        pub fn startAll(self: *Self) void {
            if (!self.spawnOne(0, true)) {
                self.fail(error.ThreadQuotaExceeded);
                return;
            }
            self.spawnExtras();
        }

        fn spawnExtras(self: *Self) void {
            var i: usize = 1;
            while (i < self.conns) : (i += 1) {
                if (!self.spawnOne(i, false)) break;
            }
        }

        /// Run the whole download, chunk 0 on the calling thread.
        pub fn runInline(self: *Self) !void {
            self.spawnExtras();
            _ = self.running.fetchAdd(1, .acq_rel);
            worker(self, 0, true);
            self.join();
            if (self.sink.failure()) |e| return e;
        }

        pub fn join(self: *Self) void {
            for (&self.threads) |*t| {
                if (t.*) |th| {
                    th.join();
                    t.* = null;
                }
            }
        }

        /// Stop the workers and wake a reader that is waiting.
        pub fn abort(self: *Self) void {
            self.fail(error.Canceled);
        }

        /// Record a failure, then cut every connection that is mid-read so the
        /// other workers stop now instead of when their read times out.
        fn fail(self: *Self, err: anyerror) void {
            self.sink.fail(err);
            if (!@hasDecl(Src, "interrupt")) return;
            self.active_mu.lock();
            defer self.active_mu.unlock();
            for (self.active) |maybe| {
                if (maybe) |b| Src.interrupt(b);
            }
        }

        fn worker(self: *Self, slot: usize, first: bool) void {
            defer {
                // The last worker out turns a silent shortfall into an error,
                // so a reader never waits for bytes nobody is fetching.
                if (self.running.fetchSub(1, .acq_rel) == 1) {
                    if (self.sink.failure() == null and !self.sink.isComplete()) self.fail(error.Incomplete);
                }
            }
            const buf = page.alloc(u8, io_buf_len) catch {
                self.fail(error.OutOfMemory);
                return;
            };
            defer page.free(buf);
            const hook: Hook = .{ .eng = self, .slot = slot };

            if (first) {
                const body = self.initial;
                self.initial_taken.store(true, .release);
                driveChunk(Src, &self.sink, &self.src, 0, body, buf, hook) catch |e| {
                    self.fail(e);
                    return;
                };
            }
            while (!self.sink.isCancelled()) {
                const idx = self.next.fetchAdd(1, .monotonic);
                if (idx >= self.plan.n) break;
                driveChunk(Src, &self.sink, &self.src, idx, null, buf, hook) catch |e| {
                    self.fail(e);
                    return;
                };
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Built-in client transport
// ---------------------------------------------------------------------------

pub const BuiltinSource = struct {
    client: *http.Client,
    /// Final URL after the first request's redirects. Owned (page allocator).
    url: []u8,
    /// Limits for ranged requests; headers are empty when the final host is
    /// not the host the caller named.
    lim: http.Limits,

    pub const Body = *http.Stream;

    pub fn open(self: *BuiltinSource, start: u64, end: u64) anyerror!Body {
        var lim = self.lim;
        lim.range = .{ .start = start, .end = end };
        return self.client.open(page, self.url, lim);
    }

    /// Cut the connection under a read that is stuck. The reader gets an error.
    pub fn interrupt(body: Body) void {
        if (!body.have_req) return;
        if (body.req.connection) |conn| std.posix.shutdown(conn.stream.handle, .both) catch {};
    }
};

// ---------------------------------------------------------------------------
// curl transport
// ---------------------------------------------------------------------------

/// What `--include` shows of one response.
pub const Head = struct {
    status: u16 = 0,
    content_length: ?u64 = null,
    accept_ranges: http.AcceptRanges = .unknown,
    content_range: ?http.ContentRange = null,
    location: ?[]const u8 = null,
    interim: bool = false,
};

pub const HeadScan = union(enum) {
    need_more,
    bad,
    /// The final response head: `len` bytes of `bytes` hold it and every
    /// earlier head (redirects, a proxy's CONNECT answer).
    done: struct { head: Head, len: usize },
};

/// Find the final response head in curl's `--include` output. Redirect
/// answers and a proxy's `200 Connection Established` come first and are
/// skipped.
pub fn scanHead(bytes: []const u8) HeadScan {
    var pos: usize = 0;
    while (true) {
        const end = std.mem.indexOfPos(u8, bytes, pos, "\r\n\r\n") orelse return .need_more;
        const head = parseHeadBlock(bytes[pos..end]) orelse return .bad;
        pos = end + 4;
        if (head.interim) continue;
        return .{ .done = .{ .head = head, .len = pos } };
    }
}

fn parseHeadBlock(block: []const u8) ?Head {
    var lines = std.mem.splitScalar(u8, block, '\n');
    const status_line = std.mem.trim(u8, lines.next() orelse return null, "\r ");
    if (!std.ascii.startsWithIgnoreCase(status_line, "HTTP/")) return null;
    var parts = std.mem.tokenizeScalar(u8, status_line, ' ');
    _ = parts.next() orelse return null;
    const code_text = parts.next() orelse return null;
    const code = std.fmt.parseInt(u16, code_text, 10) catch return null;
    const reason = std.mem.trim(u8, parts.rest(), " ");

    var head: Head = .{ .status = code };
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, "\r ");
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = line[0..colon];
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            head.content_length = std.fmt.parseInt(u64, value, 10) catch null;
        } else if (std.ascii.eqlIgnoreCase(name, "accept-ranges")) {
            if (std.ascii.eqlIgnoreCase(value, "bytes")) head.accept_ranges = .yes;
            if (std.ascii.eqlIgnoreCase(value, "none")) head.accept_ranges = .no;
        } else if (std.ascii.eqlIgnoreCase(name, "content-range")) {
            head.content_range = http.parseContentRange(value);
        } else if (std.ascii.eqlIgnoreCase(name, "location")) {
            head.location = value;
        }
    }
    head.interim = code < 200 or (code >= 300 and code < 400 and head.location != null) or
        std.ascii.eqlIgnoreCase(reason, "Connection established");
    return head;
}

/// Where the redirect chain in curl's `--include` output ended, starting from
/// `url`. Every hop is resolved with `http.resolveRedirect`, so each one has
/// passed `net.isSafeUrl`. Result is owned by `a`.
pub fn effectiveUrl(a: Allocator, url: []const u8, head_bytes: []const u8) ![]u8 {
    var cur = try a.dupe(u8, url);
    errdefer a.free(cur);
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, head_bytes, pos, "\r\n\r\n")) |end| {
        const head = parseHeadBlock(head_bytes[pos..end]) orelse break;
        pos = end + 4;
        if (head.status >= 300 and head.status < 400) {
            if (head.location) |loc| {
                const next = try http.resolveRedirect(a, cur, loc);
                a.free(cur);
                cur = next;
            }
        }
    }
    return cur;
}

const max_head_bytes = 128 * 1024;

/// Exit code of the curl that most recently ended before sending a response,
/// on this thread.
threadlocal var last_curl_exit: u8 = 0;

/// The failures curl's own --retry treats as transient: it could not resolve
/// the host (5, 6) or the operation timed out (28). Others (a refused
/// protocol, a size over the cap, a certificate problem) will not improve.
pub fn curlExitIsTransient(code: u8) bool {
    return code == 5 or code == 6 or code == 28;
}

/// A running curl whose stdout is the response body. The head has been read
/// and removed; bytes that came with it are replayed first.
pub const CurlBody = struct {
    child: std.process.Child,
    arena: std.heap.ArenaAllocator,
    pending: []const u8 = &.{},
    pending_pos: usize = 0,
    head: Head = .{},
    /// Where the redirects ended (arena-owned); the request URL if none.
    final_url: []const u8 = "",
    /// Body bytes handed out so far.
    got: u64 = 0,
    reaped: bool = false,

    pub fn read(self: *CurlBody, buf: []u8) anyerror!usize {
        if (self.pending_pos < self.pending.len) {
            const take = @min(buf.len, self.pending.len - self.pending_pos);
            @memcpy(buf[0..take], self.pending[self.pending_pos..][0..take]);
            self.pending_pos += take;
            self.got += take;
            return take;
        }
        const out = self.child.stdout orelse return 0;
        const n = out.read(buf) catch return error.ConnectionResetByPeer;
        self.got += n;
        return n;
    }

    /// Wait for curl to exit and say whether it succeeded.
    pub fn finish(self: *CurlBody) !void {
        if (self.reaped) return;
        self.reaped = true;
        const t = self.child.wait() catch return error.DownloadFailed;
        switch (t) {
            .Exited => |code| if (code != 0) return error.DownloadFailed,
            else => return error.DownloadFailed,
        }
        if (self.head.content_length) |cl| {
            if (self.got != cl) return error.DownloadFailed;
        }
    }

    /// Stop curl if it still runs and free everything.
    pub fn close(self: *CurlBody) void {
        if (!self.reaped) {
            self.reaped = true;
            _ = self.child.kill() catch {};
        }
        var arena = self.arena;
        page.destroy(self);
        arena.deinit();
    }
};

/// Start curl with `extra` arguments and read its response head.
/// `error.CurlMissing` when there is no curl, `error.HttpStatus` (with
/// `http.last_http_status` set) for an error answer.
fn spawnCurl(url: []const u8, opts: net.Options, extra: []const []const u8) anyerror!*CurlBody {
    const self = try page.create(CurlBody);
    self.* = .{ .child = undefined, .arena = std.heap.ArenaAllocator.init(page) };
    errdefer {
        var arena = self.arena;
        page.destroy(self);
        arena.deinit();
    }
    const a = self.arena.allocator();

    last_curl_exit = 0;
    var o = opts;
    o.retries = 0; // a retry would append the body again to a pipe
    var all = std.ArrayList([]const u8).init(a);
    try all.append("--include");
    try all.appendSlice(extra);
    const argv = try net.buildCurlArgv(a, url, null, o, all.items);

    self.child = std.process.Child.init(argv, a);
    self.child.stdin_behavior = .Ignore;
    self.child.stdout_behavior = .Pipe;
    self.child.stderr_behavior = .Ignore;
    self.child.spawn() catch |e| switch (e) {
        error.FileNotFound => return error.CurlMissing,
        else => return error.DownloadFailed,
    };
    self.reaped = false;
    errdefer {
        _ = self.child.kill() catch {};
        self.reaped = true;
    }

    // Read until the final head is in.
    var raw = std.ArrayList(u8).init(a);
    var chunk: [16 * 1024]u8 = undefined;
    const out = self.child.stdout.?;
    while (true) {
        switch (scanHead(raw.items)) {
            .done => |d| {
                self.head = d.head;
                self.final_url = try effectiveUrl(a, url, raw.items[0..d.len]);
                self.pending = raw.items[d.len..];
                // `head.location` slices `raw`, which stays alive in the arena.
                break;
            },
            .bad => return error.DownloadFailed,
            .need_more => {},
        }
        if (raw.items.len > max_head_bytes) return error.DownloadFailed;
        const n = out.read(&chunk) catch return error.DownloadFailed;
        if (n == 0) {
            // curl ended before a response. Its exit code says whether
            // another try could help (see `curlExitIsTransient`).
            self.reaped = true;
            last_curl_exit = if (self.child.wait()) |t| switch (t) {
                .Exited => |c| c,
                else => 255,
            } else |_| 255;
            return error.DownloadFailed;
        }
        try raw.appendSlice(chunk[0..n]);
    }

    if (self.head.status >= 300) {
        http.last_http_status = self.head.status;
        return error.HttpStatus;
    }
    return self;
}

/// Stop a curl process without waiting for it (the reader sees the pipe end).
fn interruptCurl(c: *CurlBody) void {
    if (c.reaped) return;
    if (builtin.os.tag == .windows) {
        std.os.windows.TerminateProcess(c.child.id, 1) catch {};
    } else {
        std.posix.kill(c.child.id, std.posix.SIG.TERM) catch {};
    }
}

pub const CurlSource = struct {
    /// URL for ranged requests: the final one when it is known.
    url: []u8,
    opts: net.Options,

    pub const Body = *CurlBody;

    pub const interrupt = interruptCurl;

    pub fn open(self: *CurlSource, start: u64, end: u64) anyerror!Body {
        var rb: [48]u8 = undefined;
        const range = std.fmt.bufPrint(&rb, "{d}-{d}", .{ start, end }) catch unreachable;
        const body = try spawnCurl(self.url, self.opts, &.{ "--range", range });
        errdefer body.close();
        const cr = body.head.content_range orelse return error.RangeNotHonoured;
        if (body.head.status != 206 or cr.start != start or cr.end != end) return error.RangeNotHonoured;
        return body;
    }
};

// ---------------------------------------------------------------------------
// Transfer: the whole download, from the first GET to the digest
// ---------------------------------------------------------------------------

/// Where the bytes go.
pub const Dest = union(enum) {
    /// A named file, which exists only if the download succeeded.
    file: []const u8,
    /// A private temporary file that is deleted when the transfer is.
    scratch,
};

pub const Mode = enum {
    /// `complete` drives the transfer to the end and returns the digest.
    download,
    /// The caller reads the payload in order with `read`, then `finish`.
    consume,
};

pub const BeginOptions = struct {
    opts: net.Options = .{},
    dest: Dest,
    mode: Mode,
    /// False to force one stream (after a ranged probe failed).
    allow_split: bool = true,
    /// Skip the built-in client (it already failed on this transfer).
    use_curl: bool = false,
};

const BEngine = Engine(BuiltinSource);
const CEngine = Engine(CurlSource);

const Impl = union(enum) {
    b_single: *http.Stream,
    c_single: *CurlBody,
    b_par: *BEngine,
    c_par: *CEngine,
};

pub const Transfer = struct {
    mode: Mode,
    impl: Impl,
    begin_opts: BeginOptions,
    url: []const u8, // as given by the caller; owned
    /// File being written: the destination, or the scratch file.
    path: ?[]u8 = null,
    file: ?std.fs.File = null,
    scratch: bool = false,
    header_file: ?[]u8 = null,
    host_key: [128]u8 = undefined,
    host_len: usize = 0,
    /// Consumer position.
    pos: u64 = 0,
    done: bool = false,

    pub const Reader = std.io.Reader(*Transfer, anyerror, read);

    pub fn reader(self: *Transfer) Reader {
        return .{ .context = self };
    }

    /// True when the built-in client carries this transfer, false for curl.
    pub fn isBuiltin(self: *const Transfer) bool {
        return switch (self.impl) {
            .b_single, .b_par => true,
            .c_single, .c_par => false,
        };
    }

    /// Connections carrying the body (1 for a single stream).
    pub fn connections(self: *const Transfer) u32 {
        return switch (self.impl) {
            .b_par => |e| e.connections(),
            .c_par => |e| e.connections(),
            else => 1,
        };
    }

    /// A server that promised ranges and broke the promise is not asked again.
    fn noted(self: *Transfer, err: anyerror) anyerror {
        if (err == error.RangeNotHonoured) rememberNoRange(self.hostKey());
        return err;
    }

    /// In-order payload bytes (consume mode).
    pub fn read(self: *Transfer, buf: []u8) anyerror!usize {
        switch (self.impl) {
            .b_single => |s| return s.read(buf),
            .c_single => |c| return c.read(buf),
            .b_par => |e| {
                const n = e.sink.readAt(self.pos, buf) catch |err| return self.noted(err);
                self.pos += n;
                return n;
            },
            .c_par => |e| {
                const n = e.sink.readAt(self.pos, buf) catch |err| return self.noted(err);
                self.pos += n;
                return n;
            },
        }
    }

    /// Consume mode, after `read` returned 0: check the transfer really ended
    /// well. For a split download this returns the digest computed in order
    /// over the file; a single stream has none (the caller hashed what it read).
    pub fn finish(self: *Transfer) !?Fetched {
        switch (self.impl) {
            .b_single => return null,
            .c_single => |c| {
                try c.finish();
                return null;
            },
            .b_par => |e| {
                e.join();
                const f = try e.sink.finalDigest(e.connections());
                self.done = true;
                return f;
            },
            .c_par => |e| {
                e.join();
                const f = try e.sink.finalDigest(e.connections());
                self.done = true;
                return f;
            },
        }
    }

    /// Download mode: run to the end and return the digest of the file.
    pub fn complete(self: *Transfer) !Fetched {
        const f = self.completeInner() catch |e| return self.noted(e);
        self.done = true;
        return f;
    }

    fn completeInner(self: *Transfer) !Fetched {
        switch (self.impl) {
            .b_par => |e| {
                try e.runInline();
                return e.sink.finalDigest(e.connections());
            },
            .c_par => |e| {
                try e.runInline();
                return e.sink.finalDigest(e.connections());
            },
            .b_single => |s| return self.drainToFile(s, null),
            .c_single => |c| return self.drainToFile(c, c),
        }
    }

    fn drainToFile(self: *Transfer, body: anytype, curl: ?*CurlBody) !Fetched {
        const path = self.path orelse return error.WriteFailed;
        const file = std.fs.cwd().createFile(path, .{}) catch return error.WriteFailed;
        defer file.close();
        var d: Digester = .{};
        const buf = try page.alloc(u8, io_buf_len);
        defer page.free(buf);
        while (true) {
            const n = try body.read(buf);
            if (n == 0) break;
            file.writeAll(buf[0..n]) catch return error.WriteFailed;
            d.update(buf[0..n]);
        }
        if (curl) |c| try c.finish();
        return d.fetched(1);
    }

    /// Release everything. A transfer that did not finish leaves no file
    /// behind (a scratch file is always removed).
    pub fn deinit(self: *Transfer) void {
        switch (self.impl) {
            .b_single => |s| s.close(),
            .c_single => |c| c.close(),
            .b_par => |e| {
                e.abort();
                e.destroy();
            },
            .c_par => |e| {
                e.abort();
                e.destroy();
            },
        }
        if (self.file) |f| f.close();
        if (self.path) |p| {
            if (self.scratch or !self.done) std.fs.cwd().deleteFile(p) catch {};
            page.free(p);
        }
        net.removeHeaderFile(self.header_file);
        if (self.header_file) |h| page.free(h);
        page.free(self.url);
        page.destroy(self);
    }

    /// The host the range-support memory is keyed by.
    fn hostKey(self: *const Transfer) []const u8 {
        return self.host_key[0..self.host_len];
    }
};

// Hosts whose servers promised ranges and then ignored them.
var no_range_mutex: Thread.Mutex = .{};
var no_range_hosts: [16]u64 = [_]u64{0} ** 16;
var no_range_next: usize = 0;

fn hostHash(host: []const u8) u64 {
    var buf: [256]u8 = undefined;
    const n = @min(host.len, buf.len);
    for (host[0..n], 0..) |c, i| buf[i] = std.ascii.toLower(c);
    return std.hash.Wyhash.hash(0x61627630, buf[0..n]) | 1;
}

pub fn rememberNoRange(host: []const u8) void {
    const h = hostHash(host);
    no_range_mutex.lock();
    defer no_range_mutex.unlock();
    for (no_range_hosts) |v| if (v == h) return;
    no_range_hosts[no_range_next % no_range_hosts.len] = h;
    no_range_next += 1;
}

pub fn knownNoRange(host: []const u8) bool {
    const h = hostHash(host);
    no_range_mutex.lock();
    defer no_range_mutex.unlock();
    for (no_range_hosts) |v| if (v == h) return true;
    return false;
}

/// Start a download of `url`. The first request is made here and its head
/// read; for a big body that supports ranges the other chunks start at once
/// (consume mode: all workers run in the background; download mode: they start
/// when `complete` is called). Policy answers (HTTP status, an unsafe
/// redirect) are returned as errors; a transport failure of the built-in
/// client falls back to curl.
pub fn begin(url: []const u8, bo: BeginOptions) !*Transfer {
    if (!net.isSafeUrl(url)) return error.UnsafeUrl;
    if (!net.validHeaders(bo.opts.headers)) return error.UnsafeHeader;
    if (!bo.use_curl) {
        if (try beginBuiltin(url, bo)) |t| return t;
    }
    return beginCurl(url, bo);
}

fn newTransfer(url: []const u8, bo: BeginOptions, impl: Impl, final_host: []const u8) !*Transfer {
    const t = try page.create(Transfer);
    errdefer page.destroy(t);
    const owned = try page.dupe(u8, url);
    errdefer page.free(owned);
    const path: ?[]u8 = switch (bo.dest) {
        .file => |p| try page.dupe(u8, p),
        .scratch => null,
    };
    t.* = .{ .mode = bo.mode, .impl = impl, .begin_opts = bo, .url = owned, .path = path };
    const n = @min(final_host.len, t.host_key.len);
    @memcpy(t.host_key[0..n], final_host[0..n]);
    t.host_len = n;
    return t;
}

/// Create the file the chunks are written into, sized up front so a full disk
/// shows at once. On failure nothing is left open and the caller streams
/// instead (which meets the same disk problem, if it is one, and reports it).
fn openTarget(t: *Transfer, total: u64) bool {
    var scratch_path: ?[]u8 = null;
    const file: std.fs.File = switch (t.begin_opts.dest) {
        .file => |p| std.fs.cwd().createFile(p, .{ .read = true }) catch return false,
        .scratch => blk: {
            const dir = net.privateTmpDir(page) catch return false;
            defer page.free(dir);
            var rand: [8]u8 = undefined;
            std.crypto.random.bytes(&rand);
            const name = std.fmt.allocPrint(page, "abv0-dl-{s}", .{std.fmt.fmtSliceHexLower(&rand)}) catch return false;
            defer page.free(name);
            const p = std.fs.path.join(page, &.{ dir, name }) catch return false;
            const f = std.fs.cwd().createFile(p, .{ .read = true, .exclusive = true, .mode = platform.mode_private }) catch {
                page.free(p);
                return false;
            };
            scratch_path = p;
            break :blk f;
        },
    };
    file.setEndPos(total) catch {
        file.close();
        switch (t.begin_opts.dest) {
            .file => |p| std.fs.cwd().deleteFile(p) catch {},
            .scratch => if (scratch_path) |p| {
                std.fs.cwd().deleteFile(p) catch {};
                page.free(p);
            },
        }
        return false;
    };
    t.file = file;
    if (scratch_path) |p| {
        t.path = p;
        t.scratch = true;
    }
    return true;
}

fn beginBuiltin(url: []const u8, bo: BeginOptions) !?*Transfer {
    const host = http.hostOf(url) orelse return null;
    if (net.chooseRoute(host) == .curl) return null;

    const client = http.shared() catch |e| {
        try net.builtinFailed(host, e);
        return null;
    };

    var attempt: u32 = 0;
    const s: *http.Stream = while (true) : (attempt += 1) {
        if (client.open(page, url, net.limitsFor(bo.opts))) |st| {
            net.reportBuiltinSuccess();
            break st;
        } else |e| {
            if (net.retryable(e, attempt, bo.opts)) {
                net.retryDelay(attempt);
                continue;
            }
            try net.builtinFailed(host, e);
            return null;
        }
    };

    const final_host = http.hostOf(s.finalUrl()) orelse host;
    var n: u32 = 1;
    if (bo.allow_split and !knownNoRange(final_host)) {
        n = connectionsToUse(configFromEnv(), s.content_length, s.accept_ranges, bo.mode == .download);
    }

    // From here the transfer owns the stream.
    const t = newTransfer(url, bo, .{ .b_single = s }, final_host) catch |e| {
        s.close();
        return e;
    };
    errdefer t.deinit();
    if (n < 2) return t;

    const total = s.content_length.?;
    if (!openTarget(t, total)) return t;

    // Ranged requests go to the final URL, with the caller's headers only if
    // that is still the host they were meant for.
    var lim = net.limitsFor(bo.opts);
    if (!std.ascii.eqlIgnoreCase(final_host, host)) lim.headers = &.{};
    const final_url = try page.dupe(u8, s.finalUrl());
    errdefer page.free(final_url);

    const eng = try BEngine.create(.{ .client = client, .url = final_url, .lim = lim }, t.file.?, total, n, s, configFromEnv().shard_size);
    t.impl = .{ .b_par = eng };
    if (bo.mode == .consume) eng.startAll();
    return t;
}

fn beginCurl(url: []const u8, bo: BeginOptions) !*Transfer {
    const dir: ?[]const u8 = switch (bo.dest) {
        .file => |p| std.fs.path.dirname(p) orelse ".",
        .scratch => null,
    };
    var arena_state = std.heap.ArenaAllocator.init(page);
    defer arena_state.deinit();
    const header_file: ?[]u8 = blk: {
        const h = try net.writeHeaderFile(arena_state.allocator(), dir, bo.opts.headers);
        break :blk if (h) |p| try page.dupe(u8, p) else null;
    };
    const t = beginCurlWith(url, bo, header_file) catch |e| {
        if (header_file) |h| {
            net.removeHeaderFile(h);
            page.free(h);
        }
        return e;
    };
    t.header_file = header_file;
    return t;
}

fn beginCurlWith(url: []const u8, bo: BeginOptions, header_file: ?[]u8) !*Transfer {
    var co = bo.opts;
    co.header_file = header_file;

    var attempt: u32 = 0;
    const body: *CurlBody = while (true) : (attempt += 1) {
        if (spawnCurl(url, co, &.{})) |b| break b else |e| {
            const transient = (e == error.HttpStatus and http.isTransientStatus(http.last_http_status)) or
                (e == error.DownloadFailed and curlExitIsTransient(last_curl_exit));
            if (transient and attempt < bo.opts.retries) {
                net.retryDelay(attempt);
                continue;
            }
            if (e == error.HttpStatus) return error.DownloadFailed;
            return e;
        }
    };

    const first_host = http.hostOf(url) orelse "";
    const final_host = http.hostOf(body.final_url) orelse first_host;
    http.checkDeclaredLength(body.head.content_length, net.max_download_bytes) catch |e| {
        body.close();
        return e;
    };
    var n: u32 = 1;
    if (bo.allow_split and !knownNoRange(final_host)) {
        n = connectionsToUse(configFromEnv(), body.head.content_length, body.head.accept_ranges, bo.mode == .download);
    }

    const t = newTransfer(url, bo, .{ .c_single = body }, final_host) catch |e| {
        body.close();
        return e;
    };
    errdefer t.deinit();
    if (n < 2) return t;

    const total = body.head.content_length.?;
    if (!openTarget(t, total)) return t;

    var src_opts = co;
    if (!std.ascii.eqlIgnoreCase(final_host, first_host)) {
        src_opts.headers = &.{};
        src_opts.header_file = null;
    }
    const final_url = try page.dupe(u8, body.final_url);
    errdefer page.free(final_url);
    // A curl process per shard costs more than it gains: one chunk per connection.
    const eng = try CEngine.create(.{ .url = final_url, .opts = src_opts }, t.file.?, total, n, body, null);
    t.impl = .{ .c_par = eng };
    if (bo.mode == .consume) eng.startAll();
    return t;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn sha(data: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    Sha256.hash(data, &out, .{});
    return out;
}

fn patterned(a: Allocator, n: usize) ![]u8 {
    const data = try a.alloc(u8, n);
    var prng = std.Random.DefaultPrng.init(0x5eed);
    prng.random().bytes(data);
    return data;
}

test "parseSize reads plain bytes and K/M/G suffixes" {
    try testing.expectEqual(@as(?u64, 1048576), parseSize("1048576"));
    try testing.expectEqual(@as(?u64, 8 << 20), parseSize("8M"));
    try testing.expectEqual(@as(?u64, 8 << 20), parseSize("8MiB"));
    try testing.expectEqual(@as(?u64, 8 << 20), parseSize(" 8 mb "));
    try testing.expectEqual(@as(?u64, 512 << 10), parseSize("512k"));
    try testing.expectEqual(@as(?u64, 2 << 30), parseSize("2G"));
    try testing.expectEqual(@as(?u64, 0), parseSize("0"));
    try testing.expectEqual(@as(?u64, null), parseSize(null));
    try testing.expectEqual(@as(?u64, null), parseSize(""));
    try testing.expectEqual(@as(?u64, null), parseSize("abc"));
    try testing.expectEqual(@as(?u64, null), parseSize("-5"));
    try testing.expectEqual(@as(?u64, null), parseSize("8X"));
    try testing.expectEqual(@as(?u64, null), parseSize("99999999999999999999G")); // overflow
}

test "parseConns clamps to 16 and ignores zero and junk" {
    try testing.expectEqual(@as(?u32, 4), parseConns("4"));
    try testing.expectEqual(@as(?u32, 8), parseConns(" 8 "));
    try testing.expectEqual(@as(?u32, 16), parseConns("100"));
    try testing.expectEqual(@as(?u32, 1), parseConns("1"));
    try testing.expectEqual(@as(?u32, null), parseConns("0"));
    try testing.expectEqual(@as(?u32, null), parseConns("many"));
    try testing.expectEqual(@as(?u32, null), parseConns(null));
}

test "configFrom: defaults, split threshold and forced connection count" {
    const d = configFrom(null, null);
    try testing.expectEqual(default_split_min, d.split_min);
    try testing.expectEqual(default_max_conns, d.max_conns);
    try testing.expect(!d.forced);

    const c = configFrom("1M", "4");
    try testing.expectEqual(@as(u64, 1 << 20), c.split_min);
    try testing.expectEqual(@as(u32, 4), c.max_conns);
    try testing.expect(c.forced);

    // Junk leaves the defaults alone.
    const j = configFrom("lots", "0");
    try testing.expectEqual(default_split_min, j.split_min);
    try testing.expect(!j.forced);
}

test "connectionsFor: threshold, 4 MiB per connection, cap of 8" {
    const cfg = configFrom(null, null);
    try testing.expectEqual(@as(u32, 1), connectionsFor(cfg, 0));
    try testing.expectEqual(@as(u32, 1), connectionsFor(cfg, (8 << 20) - 1)); // below the threshold
    try testing.expectEqual(@as(u32, 2), connectionsFor(cfg, 8 << 20));
    try testing.expectEqual(@as(u32, 2), connectionsFor(cfg, 11_995_741)); // ~11.4 MiB
    try testing.expectEqual(@as(u32, 5), connectionsFor(cfg, 20 << 20));
    try testing.expectEqual(@as(u32, 8), connectionsFor(cfg, 47_082_308)); // the zig tarball
    try testing.expectEqual(@as(u32, 8), connectionsFor(cfg, 1 << 30));

    // A forced count is honoured down to 256 KiB per connection.
    const f = configFrom(null, "4");
    try testing.expectEqual(@as(u32, 4), connectionsFor(f, 11_995_741));
    try testing.expectEqual(@as(u32, 1), connectionsFor(f, 4 << 20)); // still below the threshold
    const one = configFrom(null, "1");
    try testing.expectEqual(@as(u32, 1), connectionsFor(one, 1 << 30));
    const small = configFrom("1M", "8");
    try testing.expectEqual(@as(u32, 4), connectionsFor(small, 1 << 20)); // 1 MiB / 256 KiB
}

test "connectionsToUse needs a known length and range support" {
    const cfg = configFrom(null, null);
    try testing.expectEqual(@as(u32, 8), connectionsToUse(cfg, 64 << 20, .yes, false));
    try testing.expectEqual(@as(u32, 1), connectionsToUse(cfg, null, .yes, true)); // chunked body
    try testing.expectEqual(@as(u32, 1), connectionsToUse(cfg, 64 << 20, .no, true));
    // Silent servers are probed only when a failed probe can be redone.
    try testing.expectEqual(@as(u32, 8), connectionsToUse(cfg, 64 << 20, .unknown, true));
    try testing.expectEqual(@as(u32, 1), connectionsToUse(cfg, 64 << 20, .unknown, false));
}

test "planChunks: sizes, boundaries and the remainder in the last chunk" {
    const p = planChunks(100, 8);
    try testing.expectEqual(@as(u32, 8), p.n);
    for (p.slice()[0..7], 0..) |c, i| {
        try testing.expectEqual(@as(u64, 12), c.len());
        try testing.expectEqual(@as(u64, 12 * i), c.start);
    }
    try testing.expectEqual(@as(u64, 84), p.items[7].start);
    try testing.expectEqual(@as(u64, 100), p.items[7].end);
    try testing.expectEqual(@as(u64, 16), p.items[7].len());

    // Exact division: all equal.
    const q = planChunks(8 << 20, 4);
    for (q.slice()) |c| try testing.expectEqual(@as(u64, 2 << 20), c.len());

    // Chunks tile the range exactly, for many sizes and counts.
    var total: u64 = 1;
    while (total < 5_000_000) : (total = total * 3 + 7) {
        var n: u32 = 1;
        while (n <= 20) : (n += 1) {
            const plan = planChunks(total, n);
            try testing.expect(plan.n >= 1 and plan.n <= hard_max_conns);
            var at: u64 = 0;
            for (plan.slice()) |c| {
                try testing.expectEqual(at, c.start);
                try testing.expect(c.end > c.start);
                at = c.end;
            }
            try testing.expectEqual(total, at);
        }
    }
}

test "planChunks edge cases: more chunks than bytes, one chunk, empty body" {
    const tiny = planChunks(3, 8);
    try testing.expectEqual(@as(u32, 3), tiny.n);
    try testing.expectEqual(@as(u64, 1), tiny.items[0].len());
    try testing.expectEqual(@as(u64, 3), tiny.items[2].end);

    const one = planChunks(1000, 1);
    try testing.expectEqual(@as(u32, 1), one.n);
    try testing.expectEqual(@as(u64, 1000), one.items[0].end);

    const empty = planChunks(0, 4);
    try testing.expectEqual(@as(u32, 4), empty.n); // empty chunks are harmless
    try testing.expectEqual(@as(u64, 0), empty.items[3].end);

    try testing.expectEqual(@as(u32, hard_max_conns), planChunks(1 << 30, 99).n);
}

/// Write `data` into a new file in `tmp` through an Assembly, handing the
/// chunks over in `order`, each in `piece`-byte slices. Returns the digest.
fn assembleInOrder(tmp: *testing.TmpDir, data: []const u8, n: u32, order: []const usize, piece: usize) !Fetched {
    const file = try tmp.dir.createFile("out", .{ .read = true });
    defer file.close();
    try file.setEndPos(data.len);
    const plan = planChunks(data.len, n);
    var sink = Assembly.init(file, plan.slice(), data.len);
    var last_readable: u64 = 0;
    for (order) |idx| {
        const c = plan.items[idx];
        var at = c.start;
        while (at < c.end) {
            const take = @min(piece, c.end - at);
            try sink.put(idx, at, data[at..][0..take]);
            at += take;
            // The readable prefix only ever grows.
            const r = sink.readableBytes();
            try testing.expect(r >= last_readable);
            last_readable = r;
        }
    }
    try testing.expect(sink.isComplete());
    const f = try sink.finalDigest(n);

    // The file holds exactly the payload.
    const back = try tmp.dir.readFileAlloc(testing.allocator, "out", data.len + 1);
    defer testing.allocator.free(back);
    try testing.expectEqualSlices(u8, data, back);
    return f;
}

test "digest is final when the last chunk lands, whatever the arrival order" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const data = try patterned(testing.allocator, 1_000_003);
    defer testing.allocator.free(data);
    const want = sha(data);

    const orders = [_][]const usize{
        &.{ 0, 1, 2, 3, 4 },
        &.{ 4, 3, 2, 1, 0 },
        &.{ 2, 4, 0, 3, 1 },
        &.{ 1, 2, 3, 4, 0 }, // chunk 0 last: nothing can be hashed until it lands
        &.{ 0, 4, 3, 2, 1 },
    };
    for (orders) |order| {
        const f = try assembleInOrder(&tmp, data, 5, order, 7919);
        try testing.expectEqualSlices(u8, &want, &f.digest);
        try testing.expectEqual(@as(u64, data.len), f.bytes);
        try testing.expectEqualSlices(u8, data[0..head_keep], f.headBytes());
    }
}

test "digest with one chunk, tiny pieces and a payload smaller than the head" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const data = try patterned(testing.allocator, 300);
    defer testing.allocator.free(data);
    const f = try assembleInOrder(&tmp, data, 1, &.{0}, 1);
    try testing.expectEqualSlices(u8, &sha(data), &f.digest);
    try testing.expectEqual(@as(usize, 300), f.head_len);
}

test "chunk 0 is readable while later chunks are still missing" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const data = try patterned(testing.allocator, 4000);
    defer testing.allocator.free(data);

    const file = try tmp.dir.createFile("out", .{ .read = true });
    defer file.close();
    try file.setEndPos(data.len);
    const plan = planChunks(data.len, 4);
    var sink = Assembly.init(file, plan.slice(), data.len);

    // Chunks 2 and 3 arrive first: nothing is readable.
    try sink.put(3, 3000, data[3000..4000]);
    try sink.put(2, 2000, data[2000..3000]);
    try testing.expectEqual(@as(u64, 0), sink.readableBytes());

    // Half of chunk 0 is readable at once.
    try sink.put(0, 0, data[0..500]);
    try testing.expectEqual(@as(u64, 500), sink.readableBytes());
    var out: [4000]u8 = undefined;
    const n = try sink.readAt(0, &out);
    try testing.expectEqual(@as(usize, 500), n);
    try testing.expectEqualSlices(u8, data[0..500], out[0..n]);

    // Finishing chunk 0 does not release chunk 2 until chunk 1 is in.
    try sink.put(0, 500, data[500..1000]);
    try testing.expectEqual(@as(u64, 1000), sink.readableBytes());
    try sink.put(1, 1000, data[1000..2000]);
    try testing.expectEqual(@as(u64, 4000), sink.readableBytes());
    try testing.expectEqual(@as(usize, 0), try sink.readAt(4000, &out)); // end of payload
    const f = try sink.finalDigest(4);
    try testing.expectEqualSlices(u8, &sha(data), &f.digest);
}

test "a failed download wakes its reader with the error" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile("out", .{ .read = true });
    defer file.close();
    const plan = planChunks(100, 2);
    var sink = Assembly.init(file, plan.slice(), 100);
    sink.fail(error.ConnectionResetByPeer);
    try testing.expectError(error.ConnectionResetByPeer, sink.waitReadable(0));
    try testing.expectError(error.ConnectionResetByPeer, sink.finalDigest(2));
    // The first error is kept.
    sink.fail(error.Canceled);
    try testing.expectEqual(@as(?anyerror, error.ConnectionResetByPeer), sink.failure());
    try testing.expect(sink.isCancelled());
}

test "digest is correct when threads deliver pieces concurrently" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const data = try patterned(testing.allocator, 3_000_017);
    defer testing.allocator.free(data);

    const file = try tmp.dir.createFile("out", .{ .read = true });
    defer file.close();
    try file.setEndPos(data.len);
    const plan = planChunks(data.len, 8);
    var sink = Assembly.init(file, plan.slice(), data.len);

    const Ctx = struct {
        sink: *Assembly,
        data: []const u8,
        idx: usize,
        fn run(self: @This()) void {
            const c = self.sink.chunks[self.idx];
            var at = c.start;
            while (at < c.end) {
                const take = @min(@as(u64, 4093), c.end - at);
                self.sink.put(self.idx, at, self.data[at..][0..take]) catch |e| {
                    self.sink.fail(e);
                    return;
                };
                at += take;
            }
        }
    };
    var threads: [8]Thread = undefined;
    for (0..8) |i| threads[i] = try Thread.spawn(.{}, Ctx.run, .{Ctx{ .sink = &sink, .data = data, .idx = i }});
    for (threads) |t| t.join();

    try testing.expect(sink.failure() == null);
    const f = try sink.finalDigest(8);
    try testing.expectEqualSlices(u8, &sha(data), &f.digest);
}

test "retry budget: two retries for a retryable error, none for our own refusals" {
    var b: RetryBudget = .{};
    try testing.expect(b.onFailure(error.ConnectionResetByPeer)); // 1st failure -> retry 1
    try testing.expect(b.onFailure(error.EndOfStream)); // 2nd failure -> retry 2
    try testing.expect(!b.onFailure(error.EndOfStream)); // 3rd failure: out of retries
    try testing.expectEqual(@as(u32, 3), b.failures);

    var c: RetryBudget = .{};
    try testing.expect(!c.onFailure(error.RangeNotHonoured));
    var d: RetryBudget = .{};
    try testing.expect(!d.onFailure(error.WriteFailed));
    var e: RetryBudget = .{};
    try testing.expect(!e.onFailure(error.DownloadTooLarge));
    var f: RetryBudget = .{};
    try testing.expect(!f.onFailure(error.Canceled));

    http.last_http_status = 503;
    var g: RetryBudget = .{};
    try testing.expect(g.onFailure(error.HttpStatus));
    http.last_http_status = 404;
    var h: RetryBudget = .{};
    try testing.expect(!h.onFailure(error.HttpStatus));
}

/// A transport that serves `data` from memory, for testing the engine.
const FakeSource = struct {
    data: []const u8,
    /// Number of opens, and how many of them should break mid-body.
    opens: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    breaks_left: std.atomic.Value(i32) = std.atomic.Value(i32).init(0),
    /// Every open fails outright while this is above zero.
    refusals_left: std.atomic.Value(i32) = std.atomic.Value(i32).init(0),

    pub const retry_delay_ms = 0;
    pub const Body = *FakeBody;

    const FakeBody = struct {
        bytes: []const u8,
        pos: usize = 0,
        break_at: ?usize = null,
        closed: bool = false,
        pub fn read(self: *FakeBody, buf: []u8) anyerror!usize {
            if (self.break_at) |b| if (self.pos >= b) return error.ConnectionResetByPeer;
            var limit = self.bytes.len - self.pos;
            if (self.break_at) |b| limit = @min(limit, b - self.pos);
            const n = @min(buf.len, @min(limit, 10_000));
            @memcpy(buf[0..n], self.bytes[self.pos..][0..n]);
            self.pos += n;
            return n;
        }
        pub fn close(self: *FakeBody) void {
            self.closed = true;
            testing.allocator.destroy(self);
        }
    };

    pub fn open(self: *FakeSource, start: u64, end: u64) anyerror!Body {
        _ = self.opens.fetchAdd(1, .monotonic);
        if (self.refusals_left.fetchSub(1, .acq_rel) > 0) return error.ConnectionRefused;
        const b = try testing.allocator.create(FakeBody);
        b.* = .{ .bytes = self.data[start .. end + 1] };
        if (end - start > 100 and self.breaks_left.fetchSub(1, .acq_rel) > 0) {
            b.break_at = @intCast((end - start + 1) / 2);
        }
        return b;
    }
};

fn runFake(tmp: *testing.TmpDir, src: FakeSource, n: u32, with_initial: bool) !struct { result: anyerror!void, fetched: ?Fetched, opens: u32 } {
    const file = try tmp.dir.createFile("out", .{ .read = true });
    defer file.close();
    const total = src.data.len;
    try file.setEndPos(total);

    const E = Engine(FakeSource);
    var eng = try E.create(src, file, total, n, null, null);
    defer eng.destroy();
    if (with_initial) {
        // Chunk 0 arrives on an already open body that covers the whole payload.
        const b = try testing.allocator.create(FakeSource.FakeBody);
        b.* = .{ .bytes = src.data };
        eng.initial = b;
    }
    const r = eng.runInline();
    const f: ?Fetched = if (r) |_| (eng.sink.finalDigest(n) catch null) else |_| null;
    return .{ .result = r, .fetched = f, .opens = eng.src.opens.load(.acquire) };
}

test "planShards cuts small shards and grows them past max_shards" {
    const p = planShards(10 << 20, 1 << 20);
    try testing.expectEqual(@as(u32, 10), p.n);
    try testing.expectEqual(@as(u64, 1 << 20), p.items[0].len());
    const odd = planShards((3 << 20) + 5, 1 << 20);
    try testing.expectEqual(@as(u32, 4), odd.n);
    try testing.expectEqual(@as(u64, 5), odd.items[3].len());
    const big = planShards(4 << 30, 1 << 20);
    try testing.expect(big.n <= max_shards);
    try testing.expectEqual(@as(u64, 4 << 30), big.items[big.n - 1].end);
    for (big.slice()[1..], 1..) |c, i| try testing.expectEqual(big.items[i - 1].end, c.start);
    try testing.expectEqual(@as(u32, 1), planShards(0, 1 << 20).n);
}

test "parseShardSize: on, off and sizes" {
    try testing.expectEqual(@as(?u64, default_shard_size), parseShardSize("on"));
    try testing.expectEqual(@as(?u64, default_shard_size), parseShardSize("1"));
    try testing.expectEqual(@as(?u64, null), parseShardSize("off"));
    try testing.expectEqual(@as(?u64, 2 << 20), parseShardSize("2M"));
    try testing.expectEqual(@as(?u64, min_shard_size), parseShardSize("1k"));
    try testing.expectEqual(@as(?u64, null), parseShardSize(null));
}

test "micro-shards: few connections share many shards, digest matches" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const data = try patterned(testing.allocator, 3_000_017);
    defer testing.allocator.free(data);
    const file = try tmp.dir.createFile("out", .{ .read = true });
    defer file.close();
    try file.setEndPos(data.len);

    const E = Engine(FakeSource);
    var eng = try E.create(.{ .data = data }, file, data.len, 4, null, 100 << 10);
    defer eng.destroy();
    try testing.expectEqual(@as(u32, 4), eng.connections());
    try testing.expectEqual(@as(u32, 30), eng.plan.n);
    try eng.runInline();
    const f = try eng.sink.finalDigest(4);
    try testing.expectEqualSlices(u8, &sha(data), &f.digest);
    // Every shard but the first was its own ranged request.
    try testing.expectEqual(@as(u32, 30), eng.src.opens.load(.acquire));
}

test "engine fetches every chunk in parallel and the digest matches" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const data = try patterned(testing.allocator, 2_000_001);
    defer testing.allocator.free(data);

    const r = try runFake(&tmp, .{ .data = data }, 6, true);
    try r.result;
    try testing.expectEqualSlices(u8, &sha(data), &r.fetched.?.digest);
    // Chunk 0 used the body it was handed; the other five opened one each.
    try testing.expectEqual(@as(u32, 5), r.opens);

    const back = try tmp.dir.readFileAlloc(testing.allocator, "out", data.len + 1);
    defer testing.allocator.free(back);
    try testing.expectEqualSlices(u8, data, back);
}

test "a chunk that breaks mid-body is resumed on a fresh connection" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const data = try patterned(testing.allocator, 800_000);
    defer testing.allocator.free(data);

    var src: FakeSource = .{ .data = data };
    src.breaks_left.store(2, .release);
    const r = try runFake(&tmp, src, 4, false);
    try r.result;
    try testing.expectEqualSlices(u8, &sha(data), &r.fetched.?.digest);
    // 4 chunks + 2 resumes.
    try testing.expectEqual(@as(u32, 6), r.opens);
}

test "a chunk that cannot connect is retried twice, then the download fails" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const data = try patterned(testing.allocator, 100_000);
    defer testing.allocator.free(data);

    // Two refusals: every chunk still ends up fetched.
    var ok_src: FakeSource = .{ .data = data };
    ok_src.refusals_left.store(2, .release);
    const ok = try runFake(&tmp, ok_src, 1, false);
    try ok.result;
    try testing.expectEqualSlices(u8, &sha(data), &ok.fetched.?.digest);
    try testing.expectEqual(@as(u32, 3), ok.opens);

    // Endless refusals: one chunk, three attempts (the first try and two retries).
    var bad_src: FakeSource = .{ .data = data };
    bad_src.refusals_left.store(1000, .release);
    const bad = try runFake(&tmp, bad_src, 1, false);
    try testing.expectError(error.ConnectionRefused, bad.result);
    try testing.expectEqual(@as(u32, 3), bad.opens);
    try testing.expect(bad.fetched == null);
}

test "one hard chunk failure fails the download and stops the other workers" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const data = try patterned(testing.allocator, 400_000);
    defer testing.allocator.free(data);

    var src: FakeSource = .{ .data = data };
    src.refusals_left.store(1000, .release);
    const r = try runFake(&tmp, src, 4, true);
    try testing.expectError(error.ConnectionRefused, r.result);
    try testing.expect(r.fetched == null);
}

test "startAll lets a consumer read the file in order while workers fetch" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const data = try patterned(testing.allocator, 1_500_000);
    defer testing.allocator.free(data);

    const file = try tmp.dir.createFile("out", .{ .read = true });
    defer file.close();
    try file.setEndPos(data.len);

    const E = Engine(FakeSource);
    const b = try testing.allocator.create(FakeSource.FakeBody);
    b.* = .{ .bytes = data };
    const eng = try E.create(.{ .data = data }, file, data.len, 5, b, null);
    defer eng.destroy();
    eng.startAll();

    var got = std.ArrayList(u8).init(testing.allocator);
    defer got.deinit();
    var buf: [9000]u8 = undefined;
    var pos: u64 = 0;
    while (true) {
        const n = try eng.sink.readAt(pos, &buf);
        if (n == 0) break;
        try got.appendSlice(buf[0..n]);
        pos += n;
    }
    try testing.expectEqualSlices(u8, data, got.items);
    eng.join();
    const f = try eng.sink.finalDigest(5);
    try testing.expectEqualSlices(u8, &sha(data), &f.digest);
}

test "scanHead skips a proxy's CONNECT answer and redirect heads" {
    const raw =
        "HTTP/1.1 200 Connection Established\r\n\r\n" ++
        "HTTP/1.1 302 Found\r\nLocation: https://cdn.test/a/b?x=1\r\nContent-Length: 0\r\n\r\n" ++
        "HTTP/1.1 200 Connection Established\r\n\r\n" ++
        "HTTP/1.1 200 OK\r\nContent-Length: 11995741\r\nAccept-Ranges: bytes\r\n\r\nBODY";
    switch (scanHead(raw)) {
        .done => |d| {
            try testing.expectEqual(@as(u16, 200), d.head.status);
            try testing.expectEqual(@as(?u64, 11995741), d.head.content_length);
            try testing.expectEqual(http.AcceptRanges.yes, d.head.accept_ranges);
            try testing.expectEqualStrings("BODY", raw[d.len..]);
            const url = try effectiveUrl(testing.allocator, "https://github.com/o/r/x.tgz", raw[0..d.len]);
            defer testing.allocator.free(url);
            try testing.expectEqualStrings("https://cdn.test/a/b?x=1", url);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "scanHead needs the whole head, understands 206 and HTTP/2 heads" {
    try testing.expect(scanHead("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n") == .need_more);
    try testing.expect(scanHead("") == .need_more);
    try testing.expect(scanHead("not http\r\n\r\n") == .bad);

    const h2 = "HTTP/2 206 \r\ncontent-range: bytes 100-199/1000\r\ncontent-length: 100\r\n\r\n";
    switch (scanHead(h2)) {
        .done => |d| {
            try testing.expectEqual(@as(u16, 206), d.head.status);
            try testing.expectEqual(@as(u64, 100), d.head.content_range.?.start);
            try testing.expectEqual(@as(u64, 199), d.head.content_range.?.end);
            try testing.expectEqual(@as(?u64, 1000), d.head.content_range.?.total);
        },
        else => return error.TestUnexpectedResult,
    }

    // An error answer is a final head too; the caller refuses it.
    switch (scanHead("HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\n")) {
        .done => |d| try testing.expectEqual(@as(u16, 404), d.head.status),
        else => return error.TestUnexpectedResult,
    }
}

test "effectiveUrl refuses a redirect to plain http" {
    const raw = "HTTP/1.1 302 Found\r\nLocation: http://evil.test/x\r\n\r\nHTTP/1.1 200 OK\r\n\r\n";
    try testing.expectError(error.UnsafeRedirect, effectiveUrl(testing.allocator, "https://a.test/x", raw));
}

test "a response bigger than the size cap is refused before any byte is kept" {
    // Both transports apply http.checkDeclaredLength to the head, with the
    // same cap curl is given as --max-filesize.
    try testing.expectEqual(net.max_download_bytes, (http.Limits{}).max_bytes);
    switch (scanHead("HTTP/1.1 200 OK\r\nContent-Length: 2147483649\r\nAccept-Ranges: bytes\r\n\r\n")) {
        .done => |d| {
            try testing.expectError(error.DownloadTooLarge, http.checkDeclaredLength(d.head.content_length, net.max_download_bytes));
        },
        else => return error.TestUnexpectedResult,
    }
    // At the cap exactly, the plan still splits it as usual.
    try http.checkDeclaredLength(net.max_download_bytes, net.max_download_bytes);
    try testing.expectEqual(@as(u32, 8), connectionsFor(configFrom(null, null), net.max_download_bytes));
}

test "range memory is per host and case-insensitive" {
    try testing.expect(!knownNoRange("norange.example"));
    rememberNoRange("NoRange.Example");
    try testing.expect(knownNoRange("norange.example"));
    try testing.expect(!knownNoRange("other.example"));
}

/// A transport whose bodies block until interrupted, to prove that one hard
/// failure frees the workers that are stuck mid-read.
const HangSource = struct {
    pub const retry_delay_ms = 0;
    pub const Body = *HangBody;

    const HangBody = struct {
        stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        pub fn read(self: *HangBody, buf: []u8) anyerror!usize {
            _ = buf;
            while (!self.stop.load(.acquire)) std.time.sleep(std.time.ns_per_ms);
            return error.ConnectionResetByPeer;
        }
        pub fn close(self: *HangBody) void {
            testing.allocator.destroy(self);
        }
    };

    pub fn open(self: *HangSource, start: u64, end: u64) anyerror!Body {
        _ = self;
        _ = end;
        if (start == 0) return error.ConnectionRefused; // chunk 0 fails for good
        return try testing.allocator.create(HangBody);
    }

    pub fn interrupt(body: Body) void {
        body.stop.store(true, .release);
    }
};

test "a hard failure interrupts the workers that are stuck in a read" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile("out", .{ .read = true });
    defer file.close();
    try file.setEndPos(1_000_000);

    const E = Engine(HangSource);
    const eng = try E.create(.{}, file, 1_000_000, 4, null, null);
    defer eng.destroy();
    // Chunk 0 is refused three times; chunks 1 to 3 hang until cut.
    try testing.expectError(error.ConnectionRefused, eng.runInline());
    try testing.expectEqual(@as(?anyerror, error.ConnectionRefused), eng.sink.failure());
}
