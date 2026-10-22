//! Built-in HTTPS client.
//!
//! abv0 used to start a `curl` process for every download. That costs a fork,
//! a fresh TCP and TLS handshake per file, and gives the progress display
//! nothing to hook into. This module speaks HTTPS itself with Zig's own
//! `std.http` and `std.crypto.tls`, so one client serves a whole run: TLS
//! connections to a host are kept alive and reused by every download and every
//! install worker.
//!
//! The built-in client is the fast path, not the only one. Some networks break
//! std's TLS (an egress proxy that resets its ClientHello, interception that
//! needs a library std does not have, a SOCKS proxy). Such failures are
//! reported as *transport* errors by `isTransportError`, and `net.zig` then
//! retries the same request with curl. Everything that curl would answer the
//! same way (an HTTP 404, a redirect to plain http, a body over the size cap)
//! is a *policy* error and is returned as it is.
//!
//! Security rules match the curl argv in `net.zig`:
//!   * https only, for the first URL and for every redirect hop;
//!   * redirects are followed here, not by std, so each hop passes
//!     `net.isSafeUrl` (no userinfo, no control characters) before any
//!     connection is opened;
//!   * at most `Limits.max_redirects` hops;
//!   * the body is capped at `net.max_download_bytes`;
//!   * no `Accept-Encoding`, so the bytes received are the bytes the manifest
//!     hashes. A server that compresses anyway is treated as a transport
//!     problem, so curl fetches the exact bytes.

const std = @import("std");
const builtin = @import("builtin");
const net = @import("net.zig");

const Allocator = std.mem.Allocator;

/// Sent on every request. GitHub's API refuses a request without a User-Agent.
pub const user_agent = "abv0/" ++ @import("main.zig").version;

/// Per-request limits. The defaults mirror the curl argv in `net.zig`.
pub const Limits = struct {
    /// Redirect hops followed before giving up (curl: --max-redirs 5).
    max_redirects: u32 = 5,
    /// A read that makes no progress for this long fails (SO_RCVTIMEO).
    recv_timeout_s: u32 = 60,
    /// Total time allowed for the request, checked between reads. std offers
    /// no non-blocking connect, so a stuck connect or handshake is bounded
    /// only by the operating system; once the connection is up, this holds.
    max_time_s: u32 = 600,
    /// Largest body accepted (curl: --max-filesize).
    max_bytes: u64 = net.max_download_bytes,
};

/// Failures that are the client's own judgement, not the network's. They are
/// what curl would report too, so `net.zig` does not retry them with curl.
pub const PolicyError = error{
    /// The final status was not 2xx. `last_http_status` holds the code.
    HttpStatus,
    TooManyRedirects,
    /// A redirect target that is not plain https, or carries userinfo.
    UnsafeRedirect,
    /// A redirect without a usable Location header.
    BadRedirect,
    UnsafeUrl,
    DownloadTooLarge,
    /// The caller's sink refused the bytes (disk full, closed file).
    WriteFailed,
    OutOfMemory,
};

/// Status code of the most recent `HttpStatus` failure on this thread, so the
/// caller can retry a transient 5xx and print the code.
pub threadlocal var last_http_status: u16 = 0;

/// True when `err` means the built-in client could not talk to the server, so
/// curl may do better. Anything not on the policy list counts as transport:
/// an unknown error is more likely a std limitation than a real answer, and
/// curl then gives the authoritative result.
pub fn isTransportError(err: anyerror) bool {
    return switch (err) {
        error.HttpStatus,
        error.TooManyRedirects,
        error.UnsafeRedirect,
        error.BadRedirect,
        error.UnsafeUrl,
        error.DownloadTooLarge,
        error.WriteFailed,
        error.OutOfMemory,
        => false,
        else => true,
    };
}

/// A status worth another try, the same set curl's --retry treats as transient.
pub fn isTransientStatus(code: u16) bool {
    return switch (code) {
        408, 429, 500, 502, 503, 504 => true,
        else => false,
    };
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

/// Host part of an https URL, as a slice of `url`. Null when it does not parse.
pub fn hostOf(url: []const u8) ?[]const u8 {
    const uri = std.Uri.parse(url) catch return null;
    const host = uri.host orelse return null;
    const raw = switch (host) {
        .raw => |s| s,
        .percent_encoded => |s| s,
    };
    if (raw.len == 0) return null;
    return raw;
}

/// Resolve a `Location` header against the URL it came from. The result is
/// owned by `a` and has passed `net.isSafeUrl`, so a hostile server cannot
/// steer the download to plain http, to another scheme, or to a URL with
/// userinfo. Every shape RFC 3986 allows for a reference is handled: absolute,
/// scheme-relative (`//host/x`), absolute-path, query-only and relative-path.
pub fn resolveRedirect(a: Allocator, base: []const u8, location: []const u8) ![]u8 {
    if (location.len == 0) return error.BadRedirect;
    // A line break here would split the request that the next hop sends.
    if (std.mem.indexOfAny(u8, location, "\r\n\x00") != null) return error.UnsafeRedirect;

    const scheme_end = "https://".len;
    if (base.len < scheme_end) return error.BadRedirect;
    const authority_end = std.mem.indexOfAnyPos(u8, base, scheme_end, "/?#") orelse base.len;
    const origin = base[0..authority_end];

    const next: []u8 = blk: {
        if (hasScheme(location)) {
            // Only the scheme name is case-insensitive.
            if (std.ascii.startsWithIgnoreCase(location, "https://")) {
                break :blk try std.fmt.allocPrint(a, "https://{s}", .{location[scheme_end..]});
            }
            // Any other scheme fails isSafeUrl below; keep it verbatim.
            break :blk try a.dupe(u8, location);
        }
        if (std.mem.startsWith(u8, location, "//")) {
            break :blk try std.fmt.allocPrint(a, "https:{s}", .{location});
        }
        if (location[0] == '/') {
            const path = try normalizePath(a, location);
            defer a.free(path);
            break :blk try std.fmt.allocPrint(a, "{s}{s}", .{ origin, path });
        }
        if (location[0] == '?') {
            const path_end = std.mem.indexOfAnyPos(u8, base, authority_end, "?#") orelse base.len;
            break :blk try std.fmt.allocPrint(a, "{s}{s}", .{ base[0..path_end], location });
        }
        if (location[0] == '#') {
            const frag = std.mem.indexOfScalarPos(u8, base, authority_end, '#') orelse base.len;
            break :blk try std.fmt.allocPrint(a, "{s}{s}", .{ base[0..frag], location });
        }

        // Relative path: replace the base path's last segment.
        const path_end = std.mem.indexOfAnyPos(u8, base, authority_end, "?#") orelse base.len;
        const base_path = base[authority_end..path_end];
        const dir_end = if (std.mem.lastIndexOfScalar(u8, base_path, '/')) |i| i + 1 else 0;
        const joined = try std.fmt.allocPrint(a, "/{s}{s}", .{
            std.mem.trimLeft(u8, base_path[0..dir_end], "/"),
            location,
        });
        defer a.free(joined);
        const path = try normalizePath(a, joined);
        defer a.free(path);
        break :blk try std.fmt.allocPrint(a, "{s}{s}", .{ origin, path });
    };
    errdefer a.free(next);

    if (!net.isSafeUrl(next)) return error.UnsafeRedirect;
    return next;
}

/// `scheme:` prefix (RFC 3986 section 3.1) before any '/', '?' or '#'.
fn hasScheme(s: []const u8) bool {
    if (s.len == 0 or !std.ascii.isAlphabetic(s[0])) return false;
    for (s[1..]) |c| {
        if (c == ':') return true;
        if (!(std.ascii.isAlphanumeric(c) or c == '+' or c == '-' or c == '.')) return false;
    }
    return false;
}

/// Remove `.` and `..` segments from the path part of `path_and_rest`, leaving
/// any query or fragment untouched. Result is owned by `a`. A `..` that would
/// climb above the root is dropped, as RFC 3986 section 5.2.4 specifies.
fn normalizePath(a: Allocator, path_and_rest: []const u8) ![]u8 {
    const cut = std.mem.indexOfAny(u8, path_and_rest, "?#") orelse path_and_rest.len;
    const path = path_and_rest[0..cut];
    const rest = path_and_rest[cut..];

    var out = std.ArrayList(u8).init(a);
    errdefer out.deinit();
    var it = std.mem.splitScalar(u8, path, '/');
    _ = it.next(); // the empty segment before the leading '/'
    while (it.next()) |seg| {
        if (std.mem.eql(u8, seg, ".")) continue;
        if (std.mem.eql(u8, seg, "..")) {
            if (std.mem.lastIndexOfScalar(u8, out.items, '/')) |i| out.shrinkRetainingCapacity(i);
            continue;
        }
        try out.append('/');
        try out.appendSlice(seg);
    }
    // `/a/..` normalises to `/`, and a trailing `/.` keeps its slash.
    if (out.items.len == 0 or std.mem.endsWith(u8, path, "/") or
        std.mem.endsWith(u8, path, "/.") or std.mem.endsWith(u8, path, "/.."))
    {
        if (out.items.len == 0 or out.items[out.items.len - 1] != '/') try out.append('/');
    }
    try out.appendSlice(rest);
    return out.toOwnedSlice();
}

// ---------------------------------------------------------------------------
// NO_PROXY
// ---------------------------------------------------------------------------

/// std.http has no NO_PROXY support, so the rule is applied here. Same grammar
/// curl uses: comma-separated entries; `*` matches everything; `example.com`
/// and `.example.com` and `*.example.com` match the domain and its
/// subdomains; an IPv4 address or `a.b.c.d/len` CIDR matches that address
/// range; a trailing `:port` on an entry is ignored.
pub fn noProxyMatches(list: []const u8, host: []const u8) bool {
    const h = std.mem.trim(u8, host, "[]");
    var it = std.mem.tokenizeAny(u8, list, ", \t");
    while (it.next()) |raw| {
        var entry = raw;
        if (std.mem.eql(u8, entry, "*")) return true;

        // `host:port` (not an IPv6 literal, which has several colons).
        if (std.mem.indexOfScalar(u8, entry, ':')) |c| {
            if (std.mem.indexOfScalarPos(u8, entry, c + 1, ':') == null) entry = entry[0..c];
        }
        if (entry.len == 0) continue;

        if (std.mem.indexOfScalar(u8, entry, '/')) |slash| {
            if (cidrContains(entry[0..slash], entry[slash + 1 ..], h)) return true;
            continue;
        }

        entry = std.mem.trimLeft(u8, entry, "*");
        entry = std.mem.trimLeft(u8, entry, ".");
        if (entry.len == 0) continue;
        if (std.ascii.eqlIgnoreCase(entry, h)) return true;
        // Subdomain: the host ends with ".entry".
        if (h.len > entry.len and h[h.len - entry.len - 1] == '.' and
            std.ascii.eqlIgnoreCase(h[h.len - entry.len ..], entry)) return true;
    }
    return false;
}

fn parseIp4(s: []const u8) ?u32 {
    var it = std.mem.splitScalar(u8, s, '.');
    var out: u32 = 0;
    var n: u32 = 0;
    while (it.next()) |part| : (n += 1) {
        if (n == 4) return null;
        const v = std.fmt.parseInt(u8, part, 10) catch return null;
        out = (out << 8) | v;
    }
    if (n != 4) return null;
    return out;
}

/// IPv4 CIDR test. Other address families never match a CIDR entry.
fn cidrContains(net_addr: []const u8, len_text: []const u8, host: []const u8) bool {
    const base = parseIp4(net_addr) orelse return false;
    const addr = parseIp4(host) orelse return false;
    const len = std.fmt.parseInt(u6, len_text, 10) catch return false;
    if (len > 32) return false;
    if (len == 0) return true;
    const shift: u5 = @intCast(32 - len);
    return (base >> shift) == (addr >> shift);
}

// ---------------------------------------------------------------------------
// Sockets
// ---------------------------------------------------------------------------

/// Bound a stalled read or write. std.http exposes no timeout, so this sets
/// SO_RCVTIMEO and SO_SNDTIMEO on the socket. POSIX takes a `timeval`; Windows
/// takes a DWORD of milliseconds. A timed-out read surfaces as a read failure,
/// which `isTransportError` counts as transport.
pub fn setSocketTimeouts(handle: std.posix.socket_t, seconds: u32) void {
    if (seconds == 0) return;
    if (builtin.os.tag == .windows) {
        const ws2 = std.os.windows.ws2_32;
        const ms: u32 = std.math.mul(u32, seconds, 1000) catch std.math.maxInt(u32);
        const bytes: [*]const u8 = @ptrCast(&ms);
        _ = ws2.setsockopt(handle, ws2.SOL.SOCKET, ws2.SO.RCVTIMEO, bytes, @sizeOf(u32));
        _ = ws2.setsockopt(handle, ws2.SOL.SOCKET, ws2.SO.SNDTIMEO, bytes, @sizeOf(u32));
        return;
    }
    const tv = std.posix.timeval{ .tv_sec = @intCast(seconds), .tv_usec = 0 };
    inline for (.{ std.posix.SO.RCVTIMEO, std.posix.SO.SNDTIMEO }) |opt| {
        std.posix.setsockopt(handle, std.posix.SOL.SOCKET, opt, std.mem.asBytes(&tv)) catch {};
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// One HTTPS client for a whole run. Safe to use from several threads: std's
/// connection pool is mutex-protected, and the lazily built direct client is
/// guarded here.
pub const Client = struct {
    allocator: Allocator,
    /// Owns the proxy settings and the NO_PROXY text. Must outlive `http`.
    arena: std.heap.ArenaAllocator,
    /// The client every request uses, through the proxy when one is set.
    http: std.http.Client,
    /// A second client without a proxy, for hosts NO_PROXY exempts. Built on
    /// first use; std ties the proxy to the client, so it cannot be a flag.
    direct: ?std.http.Client = null,
    direct_mutex: std.Thread.Mutex = .{},
    no_proxy: []const u8 = "",
    has_proxy: bool = false,

    /// Heap-allocated because std's pool hands out pointers into the client.
    pub fn create(allocator: Allocator) !*Client {
        const self = try allocator.create(Client);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .arena = std.heap.ArenaAllocator.init(allocator),
            .http = .{ .allocator = allocator },
        };
        errdefer self.arena.deinit();
        errdefer self.http.deinit();

        loadCaBundle(&self.http);

        // HTTPS_PROXY, https_proxy and ALL_PROXY, as curl reads them.
        try self.http.initDefaultProxies(self.arena.allocator());
        // A proxy std cannot use (socks5://...) is left unset by
        // initDefaultProxies, which would silently connect directly and bypass
        // what the user asked for. Refuse instead, so curl handles it.
        if (self.http.https_proxy == null and envProxyConfigured())
            return error.UnsupportedProxy;
        self.has_proxy = self.http.https_proxy != null;

        for ([_][]const u8{ "no_proxy", "NO_PROXY" }) |name| {
            const v = std.process.getEnvVarOwned(self.arena.allocator(), name) catch continue;
            if (v.len > 0) {
                self.no_proxy = v;
                break;
            }
        }
        return self;
    }

    pub fn destroy(self: *Client) void {
        const allocator = self.allocator;
        if (self.direct) |*d| d.deinit();
        self.http.deinit();
        self.arena.deinit();
        allocator.destroy(self);
    }

    /// The std client to use for `host`: direct when NO_PROXY exempts it.
    fn clientFor(self: *Client, host: []const u8) *std.http.Client {
        if (!self.has_proxy or !noProxyMatches(self.no_proxy, host)) return &self.http;

        self.direct_mutex.lock();
        defer self.direct_mutex.unlock();
        if (self.direct == null) {
            var d: std.http.Client = .{ .allocator = self.allocator };
            loadCaBundle(&d);
            self.direct = d;
        }
        return &self.direct.?;
    }

    /// Open a GET and read the response head. The body is read through
    /// `Stream.read`. Caller must `Stream.close` the result.
    pub fn open(self: *Client, a: Allocator, url: []const u8, lim: Limits) !*Stream {
        if (!net.isSafeUrl(url)) return error.UnsafeUrl;

        const s = try a.create(Stream);
        errdefer a.destroy(s);
        s.* = .{
            .a = a,
            .lim = lim,
            .deadline_ns = deadlineFrom(lim.max_time_s),
            .target = try a.dupe(u8, url),
            .req = undefined,
            .header_buf = undefined,
        };
        errdefer a.free(s.target);
        errdefer if (s.have_req) s.req.deinit();

        try self.follow(s);
        return s;
    }

    /// Send the request and follow redirects by hand. On return `s.req` holds
    /// a 2xx response whose body is unread.
    fn follow(self: *Client, s: *Stream) !void {
        var hops: u32 = 0;
        while (true) : (hops += 1) {
            if (hops > s.lim.max_redirects) return error.TooManyRedirects;
            const uri = std.Uri.parse(s.target) catch return error.UnsafeUrl;
            const host = hostOf(s.target) orelse return error.UnsafeUrl;

            s.req = try self.clientFor(host).open(.GET, uri, .{
                .server_header_buffer = &s.header_buf,
                // Redirects are followed below so every hop is checked.
                .redirect_behavior = .unhandled,
                .headers = .{
                    // The curl path does not ask for a compressed body.
                    // Asking for one would make the hash cover other bytes.
                    .accept_encoding = .omit,
                    .user_agent = .{ .override = user_agent },
                },
            });
            s.have_req = true;

            if (s.req.connection) |conn| setSocketTimeouts(conn.stream.handle, s.lim.recv_timeout_s);
            if (nowNs() > s.deadline_ns) return error.Timeout;

            try s.req.send();
            try s.req.finish();
            try s.req.wait();

            const status = s.req.response.status;
            if (status.class() == .redirect) {
                const location = s.req.response.location orelse return error.BadRedirect;
                // Copy before deinit: the header lives in `s.header_buf`.
                const next = try resolveRedirect(s.a, s.target, location);
                s.a.free(s.target);
                s.target = next;
                s.req.deinit();
                s.have_req = false;
                continue;
            }
            if (status.class() != .success) {
                last_http_status = @intFromEnum(status);
                return error.HttpStatus;
            }
            if (s.req.response.transfer_compression != .identity) return error.UnexpectedEncoding;
            s.status = @intFromEnum(status);
            s.content_length = s.req.response.content_length;
            if (s.content_length) |cl| {
                if (cl > s.lim.max_bytes) return error.DownloadTooLarge;
            }
            return;
        }
    }

    /// Stream a GET response into `sink`, anything with `writeAll([]const u8)`.
    pub fn get(self: *Client, a: Allocator, url: []const u8, sink: anytype, lim: Limits) !Response {
        const s = try self.open(a, url, lim);
        defer s.close();

        var buf: [32 * 1024]u8 = undefined;
        while (true) {
            const n = try s.read(&buf);
            if (n == 0) break;
            sink.writeAll(buf[0..n]) catch return error.WriteFailed;
        }
        return .{ .status = s.status, .bytes = s.bytes };
    }
};

pub const Response = struct {
    status: u16,
    bytes: u64,
};

/// An open response body. Read it with `read` or `reader`, then `close`.
pub const Stream = struct {
    a: Allocator,
    lim: Limits,
    deadline_ns: i128,
    /// Current request URL, owned by `a`.
    target: []u8,
    req: std.http.Client.Request,
    have_req: bool = false,
    header_buf: [16 * 1024]u8,
    status: u16 = 0,
    content_length: ?u64 = null,
    bytes: u64 = 0,

    pub const ReadError = std.http.Client.Request.ReadError || error{ Timeout, DownloadTooLarge, TruncatedBody };
    pub const Reader = std.io.Reader(*Stream, ReadError, read);

    pub fn reader(self: *Stream) Reader {
        return .{ .context = self };
    }

    pub fn read(self: *Stream, buf: []u8) ReadError!usize {
        if (nowNs() > self.deadline_ns) return error.Timeout;
        const n = try self.req.read(buf);
        if (n == 0) {
            // A connection cut short ends the body early without an error
            // from std when the length was never declared to match.
            if (self.content_length) |cl| if (self.bytes != cl) return error.TruncatedBody;
            return 0;
        }
        // Checked before the bytes are handed on, so an oversized response is
        // refused without the caller ever seeing the excess.
        if (n > self.lim.max_bytes -| self.bytes) return error.DownloadTooLarge;
        self.bytes += n;
        return n;
    }

    /// Release the request. A body that was not read to the end closes its
    /// connection; a finished one returns to the pool for reuse.
    pub fn close(self: *Stream) void {
        const a = self.a;
        if (self.have_req) self.req.deinit();
        a.free(self.target);
        a.destroy(self);
    }
};

fn nowNs() i128 {
    return std.time.nanoTimestamp();
}

fn deadlineFrom(seconds: u32) i128 {
    return nowNs() + @as(i128, seconds) * std.time.ns_per_s;
}

fn envProxyConfigured() bool {
    var buf: [512]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    for ([_][]const u8{ "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY" }) |name| {
        fba.reset();
        // A value too long for the buffer is certainly not empty.
        const v = std.process.getEnvVarOwned(fba.allocator(), name) catch |e| switch (e) {
            error.EnvironmentVariableNotFound => continue,
            else => return true,
        };
        if (v.len > 0) return true;
    }
    return false;
}

/// Load the system CA store, plus the file named by SSL_CERT_FILE or
/// CURL_CA_BUNDLE. Those are the variables curl reads, and a sandbox proxy
/// re-signs TLS with its own CA that only those files carry. Without them every
/// proxied download would fail verification and fall back to curl.
///
/// Done once per std client, before any request. Clearing
/// `next_https_rescan_certs` stops std.http from replacing the bundle on the
/// first connection.
fn loadCaBundle(client: *std.http.Client) void {
    client.ca_bundle_mutex.lock();
    defer client.ca_bundle_mutex.unlock();

    client.ca_bundle.rescan(client.allocator) catch {};
    for ([_][]const u8{ "SSL_CERT_FILE", "CURL_CA_BUNDLE" }) |name| {
        const path = std.process.getEnvVarOwned(client.allocator, name) catch continue;
        defer client.allocator.free(path);
        // Relative paths are ignored rather than resolved against the cwd.
        if (!std.fs.path.isAbsolute(path)) continue;
        client.ca_bundle.addCertsFromFilePathAbsolute(client.allocator, path) catch {};
    }
    @atomicStore(bool, &client.next_https_rescan_certs, false, .release);
}

// ---------------------------------------------------------------------------
// Process-wide client
// ---------------------------------------------------------------------------

var shared_mutex: std.Thread.Mutex = .{};
var shared_client: ?*Client = null;
var shared_error: ?anyerror = null;

/// The client every download in this run shares. Built on first use, so a run
/// that never downloads (or one that goes straight to curl) pays nothing for
/// the CA bundle. A failure to build it is remembered, so it is not retried.
///
/// Backed by `page_allocator`, which is thread-safe: std's pool allocates from
/// whichever worker thread opens the connection. The client lives until the
/// process exits.
pub fn shared() !*Client {
    shared_mutex.lock();
    defer shared_mutex.unlock();
    if (shared_client) |c| return c;
    if (shared_error) |e| return e;
    shared_client = Client.create(std.heap.page_allocator) catch |e| {
        shared_error = e;
        return e;
    };
    return shared_client.?;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn expectResolved(base: []const u8, location: []const u8, want: []const u8) !void {
    const got = try resolveRedirect(testing.allocator, base, location);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(want, got);
}

test "resolveRedirect follows absolute https URLs" {
    try expectResolved(
        "https://github.com/o/r/releases/download/v1/x.tgz",
        "https://objects.githubusercontent.com/asset?X-Amz-Expires=300",
        "https://objects.githubusercontent.com/asset?X-Amz-Expires=300",
    );
    // Scheme names are case-insensitive.
    try expectResolved("https://a.test/x", "HTTPS://b.test/y", "https://b.test/y");
}

test "resolveRedirect refuses a downgrade or another scheme" {
    const base = "https://github.com/a/b";
    try testing.expectError(error.UnsafeRedirect, resolveRedirect(testing.allocator, base, "http://github.com/a/b"));
    try testing.expectError(error.UnsafeRedirect, resolveRedirect(testing.allocator, base, "file:///etc/passwd"));
    try testing.expectError(error.UnsafeRedirect, resolveRedirect(testing.allocator, base, "ftp://x.test/y"));
    try testing.expectError(error.UnsafeRedirect, resolveRedirect(testing.allocator, base, "javascript:alert(1)"));
}

test "resolveRedirect rejects userinfo and header injection" {
    const base = "https://github.com/a/b";
    try testing.expectError(error.UnsafeRedirect, resolveRedirect(testing.allocator, base, "https://github.com@evil.test/x"));
    try testing.expectError(error.UnsafeRedirect, resolveRedirect(testing.allocator, base, "https://user:pw@cdn.test/x"));
    try testing.expectError(error.UnsafeRedirect, resolveRedirect(testing.allocator, base, "//user@cdn.test/x"));
    try testing.expectError(error.UnsafeRedirect, resolveRedirect(testing.allocator, base, "/x\r\nHost: evil.test"));
    try testing.expectError(error.UnsafeRedirect, resolveRedirect(testing.allocator, base, "https://cdn.test/a b"));
    try testing.expectError(error.BadRedirect, resolveRedirect(testing.allocator, base, ""));
}

test "resolveRedirect keeps relative references on the same host" {
    const base = "https://cdn.test/dir/sub/file.tgz?token=1#frag";
    try expectResolved(base, "/abs/path?x=1", "https://cdn.test/abs/path?x=1");
    try expectResolved(base, "other.tgz", "https://cdn.test/dir/sub/other.tgz");
    try expectResolved(base, "../up.tgz", "https://cdn.test/dir/up.tgz");
    try expectResolved(base, "../../../../top.tgz", "https://cdn.test/top.tgz");
    try expectResolved(base, "./same.tgz?a=b", "https://cdn.test/dir/sub/same.tgz?a=b");
    try expectResolved(base, "?only=query", "https://cdn.test/dir/sub/file.tgz?only=query");
    try expectResolved(base, "//other.test/z", "https://other.test/z");
    // A base with no path at all.
    try expectResolved("https://cdn.test", "x/y", "https://cdn.test/x/y");
    try expectResolved("https://cdn.test?q=1", "/x", "https://cdn.test/x");
}

test "hostOf extracts the host" {
    try testing.expectEqualStrings("github.com", hostOf("https://github.com/a/b").?);
    try testing.expectEqualStrings("cdn.test", hostOf("https://cdn.test:8443/x?y=z").?);
    try testing.expect(hostOf("not a url") == null);
}

test "NO_PROXY matches hosts, domains, wildcards and CIDR ranges" {
    const list = "localhost, 127.0.0.1,.internal.corp,*.svc.cluster.local,pypi.org,10.0.0.0/8,192.168.1.0/24";
    try testing.expect(noProxyMatches(list, "localhost"));
    try testing.expect(noProxyMatches(list, "127.0.0.1"));
    try testing.expect(noProxyMatches(list, "build.internal.corp"));
    try testing.expect(noProxyMatches(list, "INTERNAL.corp"));
    try testing.expect(noProxyMatches(list, "a.b.svc.cluster.local"));
    try testing.expect(noProxyMatches(list, "pypi.org"));
    try testing.expect(noProxyMatches(list, "files.pypi.org")); // subdomain of a bare domain
    try testing.expect(noProxyMatches(list, "10.20.30.40"));
    try testing.expect(noProxyMatches(list, "192.168.1.77"));

    try testing.expect(!noProxyMatches(list, "github.com"));
    try testing.expect(!noProxyMatches(list, "notpypi.org")); // suffix without a dot boundary
    try testing.expect(!noProxyMatches(list, "evilinternal.corp"));
    try testing.expect(!noProxyMatches(list, "192.168.2.1"));
    try testing.expect(!noProxyMatches(list, "11.0.0.1"));
    try testing.expect(!noProxyMatches("", "github.com"));
}

test "NO_PROXY star, ports and bracketed addresses" {
    try testing.expect(noProxyMatches("*", "anything.test"));
    try testing.expect(noProxyMatches("example.com:8080", "example.com"));
    try testing.expect(noProxyMatches("::1", "[::1]"));
    try testing.expect(!noProxyMatches("127.0.0.0/33", "127.0.0.1")); // bad prefix length
    try testing.expect(noProxyMatches("0.0.0.0/0", "8.8.8.8"));
}

test "isTransportError separates network failures from answers" {
    // The network (or std's TLS) failed: curl may do better.
    try testing.expect(isTransportError(error.ConnectionResetByPeer));
    try testing.expect(isTransportError(error.TlsAlert));
    try testing.expect(isTransportError(error.TlsFailure));
    try testing.expect(isTransportError(error.CertificateBundleLoadFailure));
    try testing.expect(isTransportError(error.UnsupportedProxy));
    try testing.expect(isTransportError(error.ConnectionTimedOut));
    try testing.expect(isTransportError(error.UnknownHostName));
    try testing.expect(isTransportError(error.Timeout));
    try testing.expect(isTransportError(error.TruncatedBody));
    try testing.expect(isTransportError(error.UnexpectedEncoding));
    try testing.expect(isTransportError(error.EndOfStream));

    // A real answer, or our own refusal: curl would say the same.
    try testing.expect(!isTransportError(error.HttpStatus));
    try testing.expect(!isTransportError(error.TooManyRedirects));
    try testing.expect(!isTransportError(error.UnsafeRedirect));
    try testing.expect(!isTransportError(error.BadRedirect));
    try testing.expect(!isTransportError(error.UnsafeUrl));
    try testing.expect(!isTransportError(error.DownloadTooLarge));
    try testing.expect(!isTransportError(error.WriteFailed));
}

test "isTransientStatus matches curl's retry set" {
    for ([_]u16{ 408, 429, 500, 502, 503, 504 }) |c| try testing.expect(isTransientStatus(c));
    for ([_]u16{ 200, 301, 400, 401, 403, 404, 501 }) |c| try testing.expect(!isTransientStatus(c));
}
