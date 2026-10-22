//! The pieces of the catalog builder's GitHub access that need no network and
//! are therefore unit-testable on their own:
//!
//!   * rate-limit bookkeeping and the decision "wait, stop or carry on"
//!     (`decide`, `decideLimited`, `Limiter`),
//!   * the GraphQL batch query (`buildQuery`) and its response parser
//!     (`parseResponse`), which turns a reply into the same REST-shaped JSON
//!     that `ghrelease.parseRelease` and `parseRepoInfo` already read, so the
//!     rest of the builder does not know which API a record came from,
//!   * the ETag cache for conditional REST requests (`EtagCache`).
//!
//! Nothing here opens a socket; `build-catalog.zig` owns the transports.

const std = @import("std");
const deps = @import("catalog_deps");

const ghrelease = deps.ghrelease;
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

// ---------------------------------------------------------------------------
// Response headers
// ---------------------------------------------------------------------------

/// What the rate-limit headers of one response said.
pub const RateInfo = struct {
    /// `x-ratelimit-remaining`
    remaining: ?i64 = null,
    /// `x-ratelimit-reset`, seconds since the epoch
    reset: ?i64 = null,
    /// `retry-after`, in seconds (the secondary-limit signal)
    retry_after: ?i64 = null,
    /// `etag`, only when it is safe to send back in `If-None-Match`
    etag: ?[]const u8 = null,
};

/// An ETag we are willing to echo in a request header: printable ASCII, no
/// control characters (so no header injection), a sane length.
pub fn isSafeEtag(s: []const u8) bool {
    if (s.len == 0 or s.len > 200) return false;
    for (s) |c| {
        if (c < 0x21 or c > 0x7e) return false;
    }
    return true;
}

/// Folds one response header into `info`. Unknown headers are ignored. `a`
/// owns the copy of the ETag (header memory is reused by the HTTP client).
pub fn noteHeader(a: Allocator, info: *RateInfo, name: []const u8, value: []const u8) void {
    const v = std.mem.trim(u8, value, " \t\r\n");
    if (std.ascii.eqlIgnoreCase(name, "x-ratelimit-remaining")) {
        info.remaining = std.fmt.parseInt(i64, v, 10) catch null;
    } else if (std.ascii.eqlIgnoreCase(name, "x-ratelimit-reset")) {
        info.reset = std.fmt.parseInt(i64, v, 10) catch null;
    } else if (std.ascii.eqlIgnoreCase(name, "retry-after")) {
        // The HTTP-date form is not used by GitHub; it parses to null here
        // and the caller falls back to its default pause.
        info.retry_after = std.fmt.parseInt(i64, v, 10) catch null;
    } else if (std.ascii.eqlIgnoreCase(name, "etag")) {
        if (isSafeEtag(v)) info.etag = a.dupe(u8, v) catch null;
    }
}

/// Reads the header block curl wrote with `-D`. Only the last response counts
/// (a redirect or `100 Continue` comes first).
pub fn infoFromHeaderDump(a: Allocator, dump: []const u8) RateInfo {
    var info = RateInfo{};
    var start: usize = 0;
    // The last block: after the final blank line that is followed by "HTTP/".
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, dump, pos, "HTTP/")) |i| {
        if (i == 0 or dump[i - 1] == '\n') start = i;
        pos = i + 5;
    }
    var lines = std.mem.splitScalar(u8, dump[start..], '\n');
    _ = lines.next(); // status line
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, "\r ");
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        noteHeader(a, &info, line[0..colon], line[colon + 1 ..]);
    }
    return info;
}

// ---------------------------------------------------------------------------
// Rate-limit decisions (pure)
// ---------------------------------------------------------------------------

pub const Decision = union(enum) {
    /// Not limited (or the window has already rolled over): go ahead.
    proceed,
    /// Pause this many seconds, then go ahead.
    wait: u64,
    /// The pause would exceed the budget: make no more calls.
    stop,
};

/// Seconds added to a computed wait so the request lands after the reset, not on it.
pub const wait_slack_s: i64 = 2;
/// The pause GitHub asks for when a secondary limit names none.
pub const default_secondary_wait_s: i64 = 60;

/// What to do given the primary-limit headers of the latest response.
///
///   * `remaining` unknown or above zero: proceed.
///   * exhausted, and `reset` already passed: proceed (a new window began).
///   * exhausted, and the wait until `reset` (plus slack) is within
///     `max_wait_s`: wait that long.
///   * otherwise: stop.
///
/// `reset` unknown while exhausted is treated as a default pause. `now` and
/// `reset` are seconds since the epoch.
pub fn decide(remaining: ?i64, reset: ?i64, now: i64, max_wait_s: u64) Decision {
    const rem = remaining orelse return .proceed;
    if (rem > 0) return .proceed;
    const wait_s: i64 = if (reset) |r| blk: {
        if (r <= now) return .proceed;
        break :blk r - now + wait_slack_s;
    } else default_secondary_wait_s;
    return fitsBudget(wait_s, max_wait_s);
}

fn fitsBudget(wait_s: i64, max_wait_s: u64) Decision {
    const w: u64 = if (wait_s < 0) 0 else @intCast(wait_s);
    if (w > max_wait_s) return .stop;
    return .{ .wait = w };
}

/// What to do about a response whose status was 403 or 429. Returns null when
/// it is not a rate limit at all (a plain "forbidden"), so the caller reports
/// the error as usual.
///
///   * `retry-after` present: a secondary limit; pause that long.
///   * `x-ratelimit-remaining: 0`: the primary limit; `decide`.
///   * the body talks about a rate limit but no header says for how long:
///     the default one minute.
pub fn decideLimited(status: u16, body: []const u8, info: RateInfo, now: i64, max_wait_s: u64) ?Decision {
    if (status != 403 and status != 429) return null;
    if (info.retry_after) |ra| return fitsBudget(ra + wait_slack_s, max_wait_s);
    if (info.remaining) |rem| {
        if (rem <= 0) return decide(rem, info.reset, now, max_wait_s);
    }
    if (status == 429 or std.ascii.indexOfIgnoreCase(body, "rate limit") != null) {
        return fitsBudget(default_secondary_wait_s, max_wait_s);
    }
    return null;
}

// ---------------------------------------------------------------------------
// Clock, wait budget and the shared limiter
// ---------------------------------------------------------------------------

/// Time and sleeping, replaceable in tests so they never wait.
pub const Clock = struct {
    ctx: ?*anyopaque = null,
    nowFn: *const fn (ctx: ?*anyopaque) i64 = realNow,
    sleepFn: *const fn (ctx: ?*anyopaque, secs: u64) void = realSleep,

    pub fn now(self: *const Clock) i64 {
        return self.nowFn(self.ctx);
    }

    pub fn sleep(self: *const Clock, secs: u64) void {
        self.sleepFn(self.ctx, secs);
    }
};

fn realNow(_: ?*anyopaque) i64 {
    return std.time.timestamp();
}

/// Sleeps in slices of five minutes and says so, so a long pause does not look
/// like a hung job.
fn realSleep(_: ?*anyopaque, secs: u64) void {
    var left = secs;
    while (left > 0) {
        const slice: u64 = @min(left, 300);
        std.time.sleep(slice * std.time.ns_per_s);
        left -= slice;
        if (left > 0) std.debug.print("  still waiting for the rate limit: {d} s to go\n", .{left});
    }
}

/// Total seconds the whole run may spend waiting for rate limits.
pub const Budget = struct {
    mutex: std.Thread.Mutex = .{},
    left_s: u64,

    fn left(self: *Budget) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.left_s;
    }

    fn take(self: *Budget, secs: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.left_s -|= secs;
    }
};

pub const Retry = enum { retry, not_limited };

/// Tracks one GitHub rate-limit bucket (REST "core", or GraphQL) across all
/// worker threads: remembers the last remaining/reset pair, makes callers wait
/// when the bucket is empty and the reset is near enough, and latches "stopped"
/// when it is not, after which every call fails fast with `error.RateLimited`.
pub const Limiter = struct {
    name: []const u8,
    budget: ?*Budget = null,
    mutex: std.Thread.Mutex = .{},
    remaining: ?i64 = null,
    reset: ?i64 = null,
    /// Epoch second until which a wait is already in progress.
    blocked_until: i64 = 0,
    stopped: bool = false,
    waits: usize = 0,
    waited_s: u64 = 0,
    quiet: bool = false,

    pub fn isStopped(self: *Limiter) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.stopped;
    }

    fn budgetLeft(self: *Limiter) u64 {
        return if (self.budget) |b| b.left() else 0;
    }

    /// Records the headers of a response.
    pub fn observe(self: *Limiter, info: RateInfo, now: i64) void {
        const rem = info.remaining orelse return;
        self.mutex.lock();
        defer self.mutex.unlock();
        if (info.reset) |r| {
            if (r < now) return; // a window that is already over
            if (self.reset == null or r > self.reset.?) {
                self.reset = r;
                self.remaining = rem;
            } else if (r == self.reset.?) {
                self.remaining = if (self.remaining) |x| @min(x, rem) else rem;
            }
        } else {
            self.remaining = rem;
        }
    }

    /// Call before every request. Returns after any needed wait, or fails
    /// with `error.RateLimited` when the bucket is empty for too long.
    pub fn gate(self: *Limiter, clock: *const Clock) error{RateLimited}!void {
        while (true) {
            self.mutex.lock();
            if (self.stopped) {
                self.mutex.unlock();
                return error.RateLimited;
            }
            const now = clock.now();
            var sleep_for: u64 = 0;
            if (self.blocked_until > now) {
                sleep_for = @intCast(self.blocked_until - now);
            } else if (self.remaining) |rem| {
                if (rem <= 0) {
                    switch (decide(rem, self.reset, now, self.budgetLeft())) {
                        .proceed => {
                            self.remaining = null;
                            self.reset = null;
                        },
                        .wait => |w| sleep_for = self.startWait(w, now),
                        .stop => {
                            self.stopLocked(self.reset, now);
                            self.mutex.unlock();
                            return error.RateLimited;
                        },
                    }
                }
            }
            self.mutex.unlock();
            if (sleep_for == 0) return;
            self.sleepAndRelease(clock, sleep_for);
        }
    }

    /// Call when a response had status 403 or 429. `.retry` means the caller
    /// waited (or the window had rolled over) and should send the request again;
    /// `.not_limited` means this was an ordinary error; `error.RateLimited`
    /// means no further calls will be made.
    pub fn limited(self: *Limiter, status: u16, body: []const u8, info: RateInfo, clock: *const Clock) error{RateLimited}!Retry {
        self.mutex.lock();
        if (self.stopped) {
            self.mutex.unlock();
            return error.RateLimited;
        }
        const now = clock.now();
        const d = decideLimited(status, body, info, now, self.budgetLeft()) orelse {
            self.mutex.unlock();
            return .not_limited;
        };
        var sleep_for: u64 = 0;
        if (self.blocked_until > now) {
            // Another thread is already waiting out this limit: join it.
            sleep_for = @intCast(self.blocked_until - now);
        } else switch (d) {
            .proceed => {},
            .wait => |w| sleep_for = self.startWait(w, now),
            .stop => {
                self.stopLocked(info.reset, now);
                self.mutex.unlock();
                return error.RateLimited;
            },
        }
        self.mutex.unlock();
        if (sleep_for != 0) self.sleepAndRelease(clock, sleep_for);
        return .retry;
    }

    fn sleepAndRelease(self: *Limiter, clock: *const Clock, secs: u64) void {
        clock.sleep(secs);
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.blocked_until <= clock.now()) {
            // The window is over: forget the old counters.
            self.remaining = null;
            self.reset = null;
        }
    }

    /// Caller holds the mutex. Charges the budget and announces the pause.
    fn startWait(self: *Limiter, secs: u64, now: i64) u64 {
        if (self.budget) |b| b.take(secs);
        self.blocked_until = now + @as(i64, @intCast(@min(secs, std.math.maxInt(i32))));
        self.waits += 1;
        self.waited_s += secs;
        if (!self.quiet) std.debug.print("rate limit reached ({s}): waiting {d} s for the window to reset\n", .{ self.name, secs });
        return secs;
    }

    /// Caller holds the mutex.
    fn stopLocked(self: *Limiter, reset: ?i64, now: i64) void {
        if (self.stopped) return;
        self.stopped = true;
        if (self.quiet) return;
        const left = self.budgetLeft();
        if (reset) |r| {
            std.debug.print("rate limit reached ({s}): the window resets in {d} s, more than the {d} s still allowed to wait; making no more {s} calls, unfetched sources keep their previous entries\n", .{ self.name, @max(r - now, 0), left, self.name });
        } else {
            std.debug.print("rate limit reached ({s}): no reset time given and {d} s of waiting left; making no more {s} calls, unfetched sources keep their previous entries\n", .{ self.name, left, self.name });
        }
    }
};

// ---------------------------------------------------------------------------
// GraphQL batch queries
// ---------------------------------------------------------------------------

/// One repository to look up in a batch.
pub const RepoRequest = struct {
    owner: []const u8,
    repo: []const u8,
    /// Ask for `latestRelease`.
    want_latest: bool = true,
    /// Pinned release tags to fetch with `release(tagName:)`.
    tags: []const []const u8 = &.{},
};

pub const QueryError = error{ InvalidName, InvalidTag, EmptyBatch, OutOfMemory };

/// Checks owner, repo and tags with the same rules `ghrelease.parseSpec` applies
/// to what a user types, so nothing but `[A-Za-z0-9._-]` names and
/// `[A-Za-z0-9._+/-]` tags can reach a query. The result must round-trip to the
/// very same strings (which also rejects a `gh:` prefix or an `@` smuggled
/// into a name).
pub fn validateRequest(a: Allocator, r: RepoRequest) QueryError!void {
    const probe = try std.fmt.allocPrint(a, "{s}/{s}", .{ r.owner, r.repo });
    defer a.free(probe);
    const spec = ghrelease.parseSpec(probe) orelse return error.InvalidName;
    if (spec.tag != null) return error.InvalidName;
    if (!std.mem.eql(u8, spec.owner, r.owner) or !std.mem.eql(u8, spec.repo, r.repo)) return error.InvalidName;
    for (r.tags) |t| {
        const tp = try std.fmt.allocPrint(a, "{s}/{s}@{s}", .{ r.owner, r.repo, t });
        defer a.free(tp);
        const ts = ghrelease.parseSpec(tp) orelse return error.InvalidTag;
        if (ts.tag == null or !std.mem.eql(u8, ts.tag.?, t)) return error.InvalidTag;
    }
}

/// A GraphQL string literal. The validated inputs cannot contain any of these
/// characters; the escaping is a second line of defence, not the first.
fn writeGqlString(w: anytype, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            0...8, 11, 12, 14...0x1f, 0x7f => try w.print("\\u{x:0>4}", .{c}),
            else => try w.writeByte(c),
        }
    }
    try w.writeByte('"');
}

/// Alias of the i-th repository in the response's `data`.
pub fn repoAlias(buf: *[24]u8, i: usize) []const u8 {
    return std.fmt.bufPrint(buf, "r{d}", .{i}) catch unreachable;
}

/// The GraphQL document that looks up every repository in `reqs`: one aliased
/// `repository(owner:, name:)` each, with the repository record, `latestRelease`
/// and the pinned `release(tagName:)`s. `with_digest` adds the asset `digest`
/// field, which older GraphQL schemas lack.
pub fn buildQuery(a: Allocator, reqs: []const RepoRequest, with_digest: bool) QueryError![]u8 {
    if (reqs.len == 0) return error.EmptyBatch;
    for (reqs) |r| try validateRequest(a, r);

    var out = std.ArrayList(u8).init(a);
    errdefer out.deinit();
    const w = out.writer();
    try w.writeAll("fragment P on Repository{description homepageUrl url licenseInfo{spdxId}}");
    try w.writeAll("fragment R on Release{tagName releaseAssets(first:100){pageInfo{hasNextPage} nodes{name downloadUrl size");
    if (with_digest) try w.writeAll(" digest");
    try w.writeAll("}}}query{");
    for (reqs, 0..) |r, i| {
        try w.print("r{d}:repository(owner:", .{i});
        try writeGqlString(w, r.owner);
        try w.writeAll(",name:");
        try writeGqlString(w, r.repo);
        try w.writeAll("){...P");
        if (r.want_latest) try w.writeAll(" latestRelease{...R}");
        for (r.tags, 0..) |t, j| {
            try w.print(" t{d}:release(tagName:", .{j});
            try writeGqlString(w, t);
            try w.writeAll("){...R}");
        }
        try w.writeAll("}");
    }
    try w.writeAll("}");
    return out.toOwnedSlice();
}

/// The POST body `{"query":"..."}`.
pub fn buildRequestBody(a: Allocator, query: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(a);
    errdefer out.deinit();
    try out.appendSlice("{\"query\":");
    try std.json.encodeJsonString(query, .{}, out.writer());
    try out.append('}');
    return out.toOwnedSlice();
}

pub const Rel = union(enum) {
    /// No such release (a null `latestRelease`, or no such tag).
    absent,
    /// More assets than one page holds; the REST API must be asked instead.
    truncated,
    /// REST-shaped JSON for `ghrelease.parseRelease`.
    json: []const u8,
};

pub const State = enum { ok, not_found, failed };

/// The outcome for one repository of a batch.
pub const Looked = struct {
    state: State = .failed,
    message: []const u8 = "",
    /// REST-shaped JSON for `parseRepoInfo`.
    repo_json: []const u8 = "",
    latest: Rel = .absent,
    /// One entry per requested tag, in order.
    tags: []const Rel = &.{},
};

pub const BatchErrorKind = enum {
    /// The schema has no `digest` on ReleaseAsset: ask again without it.
    digest_unsupported,
    /// The GraphQL rate limit (it can arrive as HTTP 200 with an error).
    rate_limited,
    /// Too much for one query: split the batch.
    too_big,
    other,
};

pub const BatchError = struct { kind: BatchErrorKind, message: []const u8 };

pub const Parsed = union(enum) {
    repos: []Looked,
    batch_error: BatchError,
};

const max_message_len = 200;

/// Printable, single-line, bounded: safe to put in a log or a table cell.
fn cleanMessage(a: Allocator, s: []const u8) ![]const u8 {
    var out = std.ArrayList(u8).init(a);
    errdefer out.deinit();
    for (s) |c| {
        if (out.items.len >= max_message_len) break;
        try out.append(if (c < 0x20 or c == 0x7f) ' ' else c);
    }
    return out.toOwnedSlice();
}

fn objGet(v: std.json.Value, key: []const u8) ?std.json.Value {
    return switch (v) {
        .object => |o| o.get(key),
        else => null,
    };
}

fn strOf(v: ?std.json.Value) ?[]const u8 {
    const x = v orelse return null;
    return switch (x) {
        .string => |s| s,
        else => null,
    };
}

const RestAsset = struct {
    name: []const u8,
    browser_download_url: []const u8,
    size: i64,
    digest: ?[]const u8,
};

const RestRelease = struct {
    tag_name: []const u8,
    assets: []const RestAsset,
};

const RestRepo = struct {
    full_name: []const u8,
    html_url: []const u8,
    description: ?[]const u8,
    homepage: ?[]const u8,
    license: ?struct { spdx_id: []const u8 },
};

/// Maps a GraphQL `Release` object to the REST release JSON.
fn releaseToRest(a: Allocator, node: std.json.Value) !Rel {
    const tag = strOf(objGet(node, "tagName")) orelse return error.MalformedResponse;
    const assets_conn = objGet(node, "releaseAssets") orelse return error.MalformedResponse;
    if (objGet(assets_conn, "pageInfo")) |pi| {
        if (objGet(pi, "hasNextPage")) |hn| {
            if (hn == .bool and hn.bool) return .truncated;
        }
    }
    const nodes = switch (objGet(assets_conn, "nodes") orelse return error.MalformedResponse) {
        .array => |arr| arr.items,
        else => return error.MalformedResponse,
    };
    var list = std.ArrayList(RestAsset).init(a);
    for (nodes) |n| {
        // A null node (an asset the token cannot see) is skipped.
        if (n != .object) continue;
        const size: i64 = switch (objGet(n, "size") orelse return error.MalformedResponse) {
            .integer => |i| i,
            else => return error.MalformedResponse,
        };
        try list.append(.{
            .name = strOf(objGet(n, "name")) orelse return error.MalformedResponse,
            .browser_download_url = strOf(objGet(n, "downloadUrl")) orelse return error.MalformedResponse,
            .size = size,
            .digest = strOf(objGet(n, "digest")),
        });
    }
    const json = try std.json.stringifyAlloc(a, RestRelease{ .tag_name = tag, .assets = list.items }, .{});
    return .{ .json = json };
}

fn repoToRest(a: Allocator, node: std.json.Value, req: RepoRequest) ![]const u8 {
    const full = try std.fmt.allocPrint(a, "{s}/{s}", .{ req.owner, req.repo });
    const url = strOf(objGet(node, "url")) orelse try std.fmt.allocPrint(a, "https://github.com/{s}", .{full});
    var spdx: ?[]const u8 = null;
    if (objGet(node, "licenseInfo")) |li| spdx = strOf(objGet(li, "spdxId"));
    return std.json.stringifyAlloc(a, RestRepo{
        .full_name = full,
        .html_url = url,
        .description = strOf(objGet(node, "description")),
        .homepage = strOf(objGet(node, "homepageUrl")),
        .license = if (spdx) |s| .{ .spdx_id = s } else null,
    }, .{});
}

fn errorMentions(msg: []const u8, needle: []const u8) bool {
    return std.ascii.indexOfIgnoreCase(msg, needle) != null;
}

/// Reads a GraphQL reply for `reqs` (the batch sent with `buildQuery`).
///
/// A reply with no `data`, or a rate-limit error, is a batch error. Otherwise
/// every repository gets its own outcome: a null `repository` with an `errors`
/// entry whose `path` starts at its alias is `not_found` (or `failed` for other
/// error types) with that message, and the rest of the batch is unaffected.
pub fn parseResponse(a: Allocator, body: []const u8, reqs: []const RepoRequest) !Parsed {
    const root = std.json.parseFromSliceLeaky(std.json.Value, a, body, .{}) catch
        return .{ .batch_error = .{ .kind = .other, .message = "unreadable GraphQL response" } };
    if (root != .object) return .{ .batch_error = .{ .kind = .other, .message = "unexpected GraphQL response" } };

    const errors: []const std.json.Value = if (root.object.get("errors")) |e| switch (e) {
        .array => |arr| arr.items,
        else => &.{},
    } else &.{};

    // Whole-batch problems first.
    var first_msg: []const u8 = "";
    for (errors) |e| {
        const msg = strOf(objGet(e, "message")) orelse "";
        const typ = strOf(objGet(e, "type")) orelse "";
        if (first_msg.len == 0) first_msg = msg;
        if (std.mem.eql(u8, typ, "RATE_LIMITED") or errorMentions(msg, "rate limit")) {
            return .{ .batch_error = .{ .kind = .rate_limited, .message = try cleanMessage(a, msg) } };
        }
    }
    const data_val = root.object.get("data");
    const have_data = data_val != null and data_val.? == .object;
    if (!have_data) {
        for (errors) |e| {
            const msg = strOf(objGet(e, "message")) orelse "";
            const typ = strOf(objGet(e, "type")) orelse "";
            if (errorMentions(msg, "digest") and (errorMentions(msg, "doesn't exist") or errorMentions(msg, "undefined"))) {
                return .{ .batch_error = .{ .kind = .digest_unsupported, .message = try cleanMessage(a, msg) } };
            }
            if (std.mem.eql(u8, typ, "MAX_NODE_LIMIT_EXCEEDED") or std.mem.eql(u8, typ, "RESOURCE_LIMITS_EXCEEDED") or
                errorMentions(msg, "node limit") or errorMentions(msg, "timeout") or errorMentions(msg, "timed out"))
            {
                return .{ .batch_error = .{ .kind = .too_big, .message = try cleanMessage(a, msg) } };
            }
        }
        return .{ .batch_error = .{ .kind = .other, .message = try cleanMessage(a, if (first_msg.len != 0) first_msg else "no data in GraphQL response") } };
    }
    const data = data_val.?.object;

    const out = try a.alloc(Looked, reqs.len);
    for (reqs, out, 0..) |req, *o, i| {
        var buf: [24]u8 = undefined;
        const alias = repoAlias(&buf, i);
        const node = data.get(alias) orelse .null;
        if (node != .object) {
            // The repository itself is missing: find the error filed under its alias.
            var msg: []const u8 = "repository not found";
            var state: State = .not_found;
            for (errors) |e| {
                const path = objGet(e, "path") orelse continue;
                if (path != .array or path.array.items.len == 0) continue;
                if (strOf(path.array.items[0]) == null or !std.mem.eql(u8, strOf(path.array.items[0]).?, alias)) continue;
                msg = strOf(objGet(e, "message")) orelse msg;
                const typ = strOf(objGet(e, "type")) orelse "";
                if (!std.mem.eql(u8, typ, "NOT_FOUND")) state = .failed;
                break;
            }
            o.* = .{ .state = state, .message = try cleanMessage(a, msg) };
            continue;
        }

        var looked = Looked{ .state = .ok };
        looked.repo_json = repoToRest(a, node, req) catch {
            o.* = .{ .state = .failed, .message = "unreadable repository data" };
            continue;
        };
        if (req.want_latest) {
            looked.latest = if (objGet(node, "latestRelease")) |lr| switch (lr) {
                .object => releaseToRest(a, lr) catch {
                    o.* = .{ .state = .failed, .message = "unreadable release data" };
                    continue;
                },
                else => .absent,
            } else .absent;
        }
        const tags = try a.alloc(Rel, req.tags.len);
        var bad = false;
        for (tags, 0..) |*t, j| {
            var tb: [24]u8 = undefined;
            const ta = std.fmt.bufPrint(&tb, "t{d}", .{j}) catch unreachable;
            t.* = if (objGet(node, ta)) |tn| switch (tn) {
                .object => releaseToRest(a, tn) catch {
                    bad = true;
                    break;
                },
                else => .absent,
            } else .absent;
        }
        if (bad) {
            o.* = .{ .state = .failed, .message = "unreadable release data" };
            continue;
        }
        looked.tags = tags;
        o.* = looked;
    }
    return .{ .repos = out };
}

// ---------------------------------------------------------------------------
// ETag cache
// ---------------------------------------------------------------------------

/// Conditional-request cache for REST GETs: `{url: {etag, body_sha256}}` in one
/// JSON file, the response bodies in `<file>.bodies/<sha256>`. A body is only
/// served after its hash is checked, so a damaged or tampered cache simply
/// misses. Entries not used during a run are dropped when the file is saved,
/// which bounds its size.
pub const EtagCache = struct {
    pub const Item = struct { etag: []const u8, sha: [64]u8 };

    arena: Allocator,
    path: []const u8,
    dir: []const u8,
    mutex: std.Thread.Mutex = .{},
    map: std.StringHashMap(Item),
    touched: std.StringHashMap(void),

    /// Loads `path` if it exists and is readable; anything else is an empty cache.
    pub fn load(arena: Allocator, path: []const u8) !EtagCache {
        var c = EtagCache{
            .arena = arena,
            .path = path,
            .dir = try std.fmt.allocPrint(arena, "{s}.bodies", .{path}),
            .map = std.StringHashMap(Item).init(arena),
            .touched = std.StringHashMap(void).init(arena),
        };
        const bytes = std.fs.cwd().readFileAlloc(arena, path, 16 * 1024 * 1024) catch return c;
        const root = std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{}) catch return c;
        if (root != .object) return c;
        var it = root.object.iterator();
        while (it.next()) |kv| {
            const etag = strOf(objGet(kv.value_ptr.*, "etag")) orelse continue;
            const sha = strOf(objGet(kv.value_ptr.*, "body_sha256")) orelse continue;
            if (!isSafeEtag(etag) or sha.len != 64) continue;
            var ok = true;
            for (sha) |ch| {
                if (!(ch >= '0' and ch <= '9') and !(ch >= 'a' and ch <= 'f')) ok = false;
            }
            if (!ok) continue;
            var item = Item{ .etag = etag, .sha = undefined };
            @memcpy(&item.sha, sha);
            try c.map.put(kv.key_ptr.*, item);
        }
        return c;
    }

    pub fn lookup(self: *EtagCache, url: []const u8) ?Item {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.map.get(url);
    }

    /// The cached body, or null when it is missing or does not match its hash.
    pub fn readBody(self: *EtagCache, a: Allocator, item: Item) ?[]u8 {
        const p = std.fs.path.join(a, &.{ self.dir, &item.sha }) catch return null;
        const body = std.fs.cwd().readFileAlloc(a, p, 64 * 1024 * 1024) catch return null;
        var d: [32]u8 = undefined;
        Sha256.hash(body, &d, .{});
        const hex = std.fmt.bytesToHex(d, .lower);
        if (!std.mem.eql(u8, &hex, &item.sha)) return null;
        return body;
    }

    /// Marks the entry as still wanted (a 304 confirmed it).
    pub fn touch(self: *EtagCache, url: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.map.getKey(url)) |k| self.touched.put(k, {}) catch {};
    }

    /// Remembers `body` under `url` with the ETag the server sent.
    pub fn store(self: *EtagCache, url: []const u8, etag: []const u8, body: []const u8) !void {
        if (!isSafeEtag(etag)) return;
        // The arena is not thread safe and the file work is small: one lock.
        self.mutex.lock();
        defer self.mutex.unlock();
        var d: [32]u8 = undefined;
        Sha256.hash(body, &d, .{});
        const hex = std.fmt.bytesToHex(d, .lower);

        try std.fs.cwd().makePath(self.dir);
        const final = try std.fs.path.join(self.arena, &.{ self.dir, &hex });
        const exists = if (std.fs.cwd().access(final, .{})) true else |_| false;
        if (!exists) {
            const tmp = try std.fmt.allocPrint(self.arena, "{s}.{x}.tmp", .{ final, std.crypto.random.int(u32) });
            try std.fs.cwd().writeFile(.{ .sub_path = tmp, .data = body });
            std.fs.cwd().rename(tmp, final) catch |e| {
                std.fs.cwd().deleteFile(tmp) catch {};
                return e;
            };
        }

        const key = try self.arena.dupe(u8, url);
        const item = Item{ .etag = try self.arena.dupe(u8, etag), .sha = hex };
        try self.map.put(key, item);
        try self.touched.put(key, {});
    }

    /// Writes the entries used in this run and removes body files nothing
    /// refers to any more.
    pub fn save(self: *EtagCache) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var out = std.ArrayList(u8).init(self.arena);
        const w = out.writer();
        try w.writeAll("{");
        var keep = std.StringHashMap(void).init(self.arena);
        var first = true;
        var it = self.map.iterator();
        while (it.next()) |kv| {
            if (!self.touched.contains(kv.key_ptr.*)) continue;
            if (!first) try w.writeAll(",");
            first = false;
            try w.writeAll("\n  ");
            try std.json.encodeJsonString(kv.key_ptr.*, .{}, w);
            try w.writeAll(": {\"etag\": ");
            try std.json.encodeJsonString(kv.value_ptr.etag, .{}, w);
            try w.print(", \"body_sha256\": \"{s}\"}}", .{kv.value_ptr.sha});
            try keep.put(try self.arena.dupe(u8, &kv.value_ptr.sha), {});
        }
        try w.writeAll(if (first) "}\n" else "\n}\n");

        if (std.fs.path.dirname(self.path)) |d| try std.fs.cwd().makePath(d);
        const tmp = try std.fmt.allocPrint(self.arena, "{s}.tmp", .{self.path});
        try std.fs.cwd().writeFile(.{ .sub_path = tmp, .data = out.items });
        try std.fs.cwd().rename(tmp, self.path);

        // Prune bodies no entry refers to.
        var dir = std.fs.cwd().openDir(self.dir, .{ .iterate = true }) catch return;
        defer dir.close();
        var di = dir.iterate();
        while (di.next() catch null) |entry| {
            if (entry.kind != .file) continue;
            if (keep.contains(entry.name)) continue;
            dir.deleteFile(entry.name) catch {};
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "decide: proceed, wait or stop from remaining/reset/now/max_wait" {
    const now: i64 = 1_000_000;
    // Plenty left, or no information: go.
    try testing.expectEqual(Decision.proceed, decide(null, null, now, 0));
    try testing.expectEqual(Decision.proceed, decide(5, now + 3000, now, 0));
    // Exhausted, reset in 100 s, 20 minutes allowed: wait 100 s plus slack.
    try testing.expectEqual(Decision{ .wait = 100 + wait_slack_s }, decide(0, now + 100, now, 20 * 60));
    // Exhausted, reset in an hour, 20 minutes allowed: stop.
    try testing.expectEqual(Decision.stop, decide(0, now + 3600, now, 20 * 60));
    // The same hour fits a budget that is large enough, to the second.
    try testing.expectEqual(Decision{ .wait = 3600 + wait_slack_s }, decide(0, now + 3600, now, 3600 + wait_slack_s));
    try testing.expectEqual(Decision.stop, decide(0, now + 3600, now, 3600 + wait_slack_s - 1));
    // The window has already rolled over.
    try testing.expectEqual(Decision.proceed, decide(0, now - 1, now, 0));
    try testing.expectEqual(Decision.proceed, decide(0, now, now, 0));
    // Exhausted with no reset time: the default pause, if it fits.
    try testing.expectEqual(Decision{ .wait = 60 }, decide(0, null, now, 600));
    try testing.expectEqual(Decision.stop, decide(0, null, now, 30));
    // A negative count is exhausted too.
    try testing.expectEqual(Decision{ .wait = 12 }, decide(-1, now + 10, now, 600));
}

test "decideLimited: primary, secondary and ordinary 403" {
    const now: i64 = 5000;
    // Primary limit: 403, remaining 0, reset in 60 s.
    const primary = RateInfo{ .remaining = 0, .reset = now + 60 };
    try testing.expectEqual(Decision{ .wait = 62 }, decideLimited(403, "API rate limit exceeded", primary, now, 1200).?);
    try testing.expectEqual(Decision.stop, decideLimited(403, "", primary, now, 10).?);
    // Secondary limit: retry-after wins over everything else.
    const secondary = RateInfo{ .retry_after = 30, .remaining = 4000, .reset = now + 9999 };
    try testing.expectEqual(Decision{ .wait = 32 }, decideLimited(403, "You have exceeded a secondary rate limit", secondary, now, 1200).?);
    try testing.expectEqual(Decision.stop, decideLimited(429, "", .{ .retry_after = 4000 }, now, 1200).?);
    // A 429 or a body that names a rate limit, with no header: one minute.
    try testing.expectEqual(Decision{ .wait = 60 }, decideLimited(429, "", .{}, now, 1200).?);
    try testing.expectEqual(Decision{ .wait = 60 }, decideLimited(403, "Secondary Rate Limit hit", .{ .remaining = 100 }, now, 1200).?);
    // A plain forbidden is not a limit; nor is any other status.
    try testing.expect(decideLimited(403, "Resource not accessible by integration", .{ .remaining = 100 }, now, 1200) == null);
    try testing.expect(decideLimited(500, "rate limit", primary, now, 1200) == null);
    try testing.expect(decideLimited(200, "", primary, now, 1200) == null);
}

test "headers: parsed from a dump and from single fields" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const dump = "HTTP/2 301\r\nlocation: https://x\r\n\r\nHTTP/2 403\r\nX-RateLimit-Remaining: 0\r\nx-ratelimit-reset: 1700000000\r\nRetry-After: 45\r\nETag: W/\"abc\"\r\n\r\n";
    const info = infoFromHeaderDump(a, dump);
    try testing.expectEqual(@as(i64, 0), info.remaining.?);
    try testing.expectEqual(@as(i64, 1700000000), info.reset.?);
    try testing.expectEqual(@as(i64, 45), info.retry_after.?);
    try testing.expectEqualStrings("W/\"abc\"", info.etag.?);

    var odd = RateInfo{};
    noteHeader(a, &odd, "retry-after", "Wed, 21 Oct 2026 07:28:00 GMT");
    try testing.expect(odd.retry_after == null);
    noteHeader(a, &odd, "etag", "bad\r\nInjected: 1");
    try testing.expect(odd.etag == null);
}

const SleepLog = struct { now: i64, slept: u64 = 0, calls: usize = 0 };

fn testClockNowLog(ctx: ?*anyopaque) i64 {
    const s: *SleepLog = @ptrCast(@alignCast(ctx.?));
    return s.now;
}

fn testClockSleep(ctx: ?*anyopaque, secs: u64) void {
    const s: *SleepLog = @ptrCast(@alignCast(ctx.?));
    s.now += @intCast(secs);
    s.slept += secs;
    s.calls += 1;
}

test "limiter: waits within the budget, then stops for good" {
    var log = SleepLog{ .now = 10_000 };
    const clock = Clock{ .ctx = &log, .nowFn = testClockNowLog, .sleepFn = testClockSleep };
    var budget = Budget{ .left_s = 600 };
    var lim = Limiter{ .name = "rest", .budget = &budget, .quiet = true };

    // Plenty left: no wait.
    lim.observe(.{ .remaining = 900, .reset = log.now + 100 }, log.now);
    try lim.gate(&clock);
    try testing.expectEqual(@as(usize, 0), log.calls);

    // Exhausted (same window, fewer left), reset in 100 s: the next call
    // waits 102 s on the (fake) clock.
    lim.observe(.{ .remaining = 0, .reset = log.now + 100 }, log.now);
    try lim.gate(&clock);
    try testing.expectEqual(@as(u64, 102), log.slept);
    try testing.expectEqual(@as(u64, 498), budget.left_s);

    // A 403 + headers after the wait: wait again if it fits...
    const r1 = try lim.limited(403, "API rate limit exceeded", .{ .remaining = 0, .reset = log.now + 300 }, &clock);
    try testing.expectEqual(Retry.retry, r1);
    try testing.expectEqual(@as(u64, 102 + 302), log.slept);
    try testing.expectEqual(@as(u64, 196), budget.left_s);

    // ...and stop when the reset is further away than the budget left.
    try testing.expectError(error.RateLimited, lim.limited(403, "API rate limit exceeded", .{ .remaining = 0, .reset = log.now + 3600 }, &clock));
    try testing.expect(lim.isStopped());
    const slept = log.slept;
    try testing.expectError(error.RateLimited, lim.gate(&clock));
    try testing.expectEqual(slept, log.slept);

    // An ordinary 403 is not a limit.
    var lim2 = Limiter{ .name = "rest", .budget = &budget, .quiet = true };
    try testing.expectEqual(Retry.not_limited, try lim2.limited(403, "Resource not accessible", .{ .remaining = 50 }, &clock));
}

test "limiter: stale in-flight responses from an old window are ignored" {
    var log = SleepLog{ .now = 100 };
    const clock = Clock{ .ctx = &log, .nowFn = testClockNowLog, .sleepFn = testClockSleep };
    var budget = Budget{ .left_s = 600 };
    var lim = Limiter{ .name = "graphql", .budget = &budget, .quiet = true };
    lim.observe(.{ .remaining = 0, .reset = 90 }, log.now); // reset already passed
    try lim.gate(&clock);
    try testing.expectEqual(@as(usize, 0), log.calls);
}

test "query: aliases, fragments, escaping and validation" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const reqs = [_]RepoRequest{
        .{ .owner = "BurntSushi", .repo = "ripgrep" },
        .{ .owner = "acme", .repo = "widget.rs", .want_latest = false, .tags = &.{ "v1.2.3", "release/2+x" } },
    };
    const q = try buildQuery(a, &reqs, true);
    try testing.expect(std.mem.indexOf(u8, q, "r0:repository(owner:\"BurntSushi\",name:\"ripgrep\"){...P latestRelease{...R}}") != null);
    try testing.expect(std.mem.indexOf(u8, q, "r1:repository(owner:\"acme\",name:\"widget.rs\"){...P t0:release(tagName:\"v1.2.3\"){...R} t1:release(tagName:\"release/2+x\"){...R}}") != null);
    try testing.expect(std.mem.indexOf(u8, q, "name downloadUrl size digest}") != null);
    try testing.expect(std.mem.indexOf(u8, q, "licenseInfo{spdxId}") != null);
    const q2 = try buildQuery(a, &reqs, false);
    try testing.expect(std.mem.indexOf(u8, q2, "digest") == null);

    const body = try buildRequestBody(a, q);
    try testing.expect(std.mem.startsWith(u8, body, "{\"query\":\"fragment P"));
    try testing.expect(std.mem.indexOf(u8, body, "owner:\\\"BurntSushi\\\"") != null);
    const back = try std.json.parseFromSliceLeaky(std.json.Value, a, body, .{});
    try testing.expectEqualStrings(q, back.object.get("query").?.string);

    // Nothing that is not a valid owner/repo/tag reaches a query.
    const evil = [_]RepoRequest{
        .{ .owner = "a\"b", .repo = "x" },
        .{ .owner = "a", .repo = "x\") { id } #" },
        .{ .owner = "a", .repo = "x\\" },
        .{ .owner = "gh:a", .repo = "x" },
        .{ .owner = "a", .repo = "x@v1" },
        .{ .owner = "a/b", .repo = "x" },
        .{ .owner = "-a", .repo = "x" },
        .{ .owner = "..", .repo = "x" },
        .{ .owner = "", .repo = "x" },
        .{ .owner = "a", .repo = "x\n" },
    };
    for (evil) |r| try testing.expectError(error.InvalidName, buildQuery(a, &.{r}, true));
    const bad_tags = [_][]const u8{ "v1\"", "v1 2", "a..b", "", "v\\1" };
    for (bad_tags) |t| {
        try testing.expectError(error.InvalidTag, buildQuery(a, &.{.{ .owner = "a", .repo = "b", .tags = &.{t} }}, true));
    }
    try testing.expectError(error.EmptyBatch, buildQuery(a, &.{}, true));

    // The escaper itself, in case a validator ever lets something through.
    var buf = std.ArrayList(u8).init(a);
    try writeGqlString(buf.writer(), "a\"b\\c\nd\x01");
    try testing.expectEqualStrings("\"a\\\"b\\\\c\\nd\\u0001\"", buf.items);
}

const sample_ok =
    \\{"data":{
    \\ "r0":{"description":"Fast  grep","homepageUrl":"","url":"https://github.com/acme/rg","licenseInfo":{"spdxId":"MIT"},
    \\   "latestRelease":{"tagName":"v1.0.0","releaseAssets":{"pageInfo":{"hasNextPage":false},"nodes":[
    \\     {"name":"rg-linux-amd64","downloadUrl":"https://github.com/acme/rg/releases/download/v1.0.0/rg-linux-amd64","size":123,"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
    \\     {"name":"rg-darwin-arm64","downloadUrl":"https://github.com/acme/rg/releases/download/v1.0.0/rg-darwin-arm64","size":456,"digest":null},
    \\     null]}}},
    \\ "r1":null,
    \\ "r2":{"description":null,"homepageUrl":"https://wid.example","url":"https://github.com/acme/widget","licenseInfo":null,"latestRelease":null,
    \\   "t0":{"tagName":"v0.9","releaseAssets":{"pageInfo":{"hasNextPage":false},"nodes":[]}},
    \\   "t1":null},
    \\ "r3":{"description":"big","homepageUrl":null,"url":"https://github.com/acme/big","licenseInfo":{"spdxId":"NOASSERTION"},
    \\   "latestRelease":{"tagName":"v9","releaseAssets":{"pageInfo":{"hasNextPage":true},"nodes":[]}}}
    \\},
    \\"errors":[{"type":"NOT_FOUND","path":["r1"],"locations":[{"line":1,"column":1}],"message":"Could not resolve to a Repository with the name 'acme/gone'."}]}
;

test "response: ok, missing repo, null latestRelease, missing tag, truncated assets" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const reqs = [_]RepoRequest{
        .{ .owner = "acme", .repo = "rg" },
        .{ .owner = "acme", .repo = "gone" },
        .{ .owner = "acme", .repo = "widget", .want_latest = true, .tags = &.{ "v0.9", "v0.8" } },
        .{ .owner = "acme", .repo = "big" },
    };
    const parsed = try parseResponse(a, sample_ok, &reqs);
    const r = parsed.repos;
    try testing.expectEqual(@as(usize, 4), r.len);

    // r0: the release becomes the REST shape parseRelease reads.
    try testing.expect(r[0].state == .ok);
    const rel = try ghrelease.parseRelease(a, r[0].latest.json);
    try testing.expectEqualStrings("v1.0.0", rel.tag);
    try testing.expectEqual(@as(usize, 2), rel.assets.len); // the null node is skipped
    try testing.expectEqualStrings("rg-linux-amd64", rel.assets[0].name);
    try testing.expectEqual(@as(u64, 123), rel.assets[0].size);
    try testing.expectEqualStrings("a" ** 64, &rel.assets[0].sha256.?);
    try testing.expect(rel.assets[1].sha256 == null);
    try testing.expectEqualStrings("https://github.com/acme/rg/releases/download/v1.0.0/rg-darwin-arm64", rel.assets[1].url);
    try testing.expect(std.mem.indexOf(u8, r[0].repo_json, "\"spdx_id\":\"MIT\"") != null);

    // r1: a missing repository fails alone, with the API's message.
    try testing.expect(r[1].state == .not_found);
    try testing.expect(std.mem.indexOf(u8, r[1].message, "acme/gone") != null);

    // r2: no latest release; one pinned tag found, one not.
    try testing.expect(r[2].state == .ok);
    try testing.expect(r[2].latest == .absent);
    try testing.expect(r[2].tags[0] == .json);
    try testing.expect(r[2].tags[1] == .absent);
    try testing.expect(std.mem.indexOf(u8, r[2].repo_json, "\"license\":null") != null);
    try testing.expect(std.mem.indexOf(u8, r[2].repo_json, "\"homepage\":\"https://wid.example\"") != null);

    // r3: too many assets for one page: the REST API must be asked.
    try testing.expect(r[3].state == .ok);
    try testing.expect(r[3].latest == .truncated);
}

test "response: batch-level errors" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const reqs = [_]RepoRequest{.{ .owner = "a", .repo = "b" }};

    const digest = try parseResponse(a,
        \\{"errors":[{"path":["fragment R","releaseAssets","nodes","digest"],"extensions":{"code":"undefinedField"},"message":"Field 'digest' doesn't exist on type 'ReleaseAsset'"}]}
    , &reqs);
    try testing.expect(digest.batch_error.kind == .digest_unsupported);

    const limited = try parseResponse(a,
        \\{"errors":[{"type":"RATE_LIMITED","message":"API rate limit exceeded for user ID 1."}]}
    , &reqs);
    try testing.expect(limited.batch_error.kind == .rate_limited);

    const big = try parseResponse(a,
        \\{"errors":[{"type":"MAX_NODE_LIMIT_EXCEEDED","message":"Query exceeds the node limit"}]}
    , &reqs);
    try testing.expect(big.batch_error.kind == .too_big);

    const other = try parseResponse(a, "{\"errors\":[{\"message\":\"Bad credentials\"}]}", &reqs);
    try testing.expect(other.batch_error.kind == .other);
    try testing.expectEqualStrings("Bad credentials", other.batch_error.message);

    const junk = try parseResponse(a, "<html>502</html>", &reqs);
    try testing.expect(junk.batch_error.kind == .other);

    // A non-NOT_FOUND error under an alias marks only that repo as failed.
    const failed = try parseResponse(a,
        \\{"data":{"r0":null},"errors":[{"type":"FORBIDDEN","path":["r0"],"message":"Resource not accessible\nby integration"}]}
    , &reqs);
    try testing.expect(failed.repos[0].state == .failed);
    try testing.expectEqualStrings("Resource not accessible by integration", failed.repos[0].message);

    // data present but no error filed for a null repository: not found.
    const quiet = try parseResponse(a, "{\"data\":{\"r0\":null}}", &reqs);
    try testing.expect(quiet.repos[0].state == .not_found);
}

test "etag cache: store, reload, verify, prune" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(a, ".");
    const path = try std.fs.path.join(a, &.{ root, "sub", "etag.json" });

    var c1 = try EtagCache.load(a, path);
    try testing.expect(c1.lookup("https://api.github.com/x") == null);
    try c1.store("https://api.github.com/x", "\"v1\"", "{\"tag_name\":\"v1\"}");
    try c1.store("https://api.github.com/y", "W/\"v2\"", "{\"tag_name\":\"v2\"}");
    try c1.save();

    var c2 = try EtagCache.load(a, path);
    const item = c2.lookup("https://api.github.com/x").?;
    try testing.expectEqualStrings("\"v1\"", item.etag);
    try testing.expectEqualStrings("{\"tag_name\":\"v1\"}", c2.readBody(a, item).?);

    // Only entries used in a run survive its save: y was not touched.
    c2.touch("https://api.github.com/x");
    try c2.save();
    var c3 = try EtagCache.load(a, path);
    try testing.expect(c3.lookup("https://api.github.com/x") != null);
    try testing.expect(c3.lookup("https://api.github.com/y") == null);
    const y_item = c2.lookup("https://api.github.com/y").?;
    const y_body = try std.fs.path.join(a, &.{ c3.dir, &y_item.sha });
    try testing.expectError(error.FileNotFound, std.fs.cwd().access(y_body, .{}));

    // A body whose bytes changed is not served.
    const x_item = c3.lookup("https://api.github.com/x").?;
    const x_path = try std.fs.path.join(a, &.{ c3.dir, &x_item.sha });
    try std.fs.cwd().writeFile(.{ .sub_path = x_path, .data = "tampered" });
    try testing.expect(c3.readBody(a, x_item) == null);

    // A damaged index is an empty cache, not an error.
    try std.fs.cwd().writeFile(.{ .sub_path = path, .data = "{not json" });
    var c4 = try EtagCache.load(a, path);
    try testing.expectEqual(@as(u32, 0), c4.map.count());
}
