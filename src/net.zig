//! Network fetching.
//!
//! Security notes on what changed:
//!   * `curl` was invoked as `curl -s -L <url> -o <file>` with no `--fail`.
//!     curl exits 0 on an HTTP 404, so the error page was written to disk and
//!     then installed and executed as the package binary. `--fail` is now set.
//!   * No protocol restriction existed, so a manifest URL (or a redirect) could
//!     use `file://`, `scp://` or plaintext `http://`. Now pinned to https for
//!     both the initial request and every redirect.
//!   * No timeouts, so a hung server hung the installer forever.
//!   * URLs interpolated from user input were never validated; a package name
//!     could inject extra query parameters into the GitHub API request.
//!   * Request headers (the GitHub token in `Authorization`) were passed to
//!     curl as `--header <value>`, so any local user could read them from `ps`.
//!     They now go through a private 0600 file, passed as `--header @<path>`.
//!
//! Who does the downloading:
//!   * `http.zig` is the built-in HTTPS client (std.http + std.crypto.tls). It
//!     is tried first: no process to spawn, and TLS connections are reused
//!     across every download in a run.
//!   * curl, with the hardened argv below, is the backup. A *transport*
//!     failure of the built-in client (TLS handshake, connection reset, proxy
//!     error, timeout) falls back to it automatically. An HTTP 404 or a
//!     redirect-policy violation does not, since curl would get the same
//!     answer.
//!   * A host the built-in client failed on is remembered for 24 hours in
//!     `<abv0 home>/net-fallback`, so later runs go straight to curl instead
//!     of paying the failed attempt again.
//!   * `ABV0_DOWNLOADER=builtin|curl|auto` forces either one (default auto).
//!   * `pget.zig` runs the transfer on either of them. A body of
//!     `ABV0_SPLIT_MIN` (8 MiB) or more from a server that supports byte ranges
//!     is fetched over several connections and hashed in order as it lands;
//!     `downloadHashed` returns that digest.

const std = @import("std");
const builtin = @import("builtin");
const platform = @import("platform.zig");
const http = @import("http.zig");
const pget = @import("pget.zig");

pub const Options = struct {
    connect_timeout_s: u32 = 20,
    max_time_s: u32 = 600,
    retries: u32 = 2,
    user_agent: []const u8 = http.user_agent,
    /// Extra request headers, each a complete `Name: value` line.
    headers: []const []const u8 = &.{},
    /// Path of the private file that holds `headers` (see `writeHeaderFile`).
    /// Set internally before curl runs; `buildCurlArgv` requires it whenever
    /// `headers` is non-empty.
    header_file: ?[]const u8 = null,
};

pub const Error = error{
    UnsafeUrl,
    UnsafeHeader,
    HeaderFileMissing,
    NoPrivateDir,
    DownloadFailed,
    NoDownloaderAvailable,
};

/// Reject anything that is not a plain https URL. Also rejects control
/// characters and whitespace, which are the usual argument-injection vectors
/// when a URL is passed to another program.
pub fn isSafeUrl(url: []const u8) bool {
    if (url.len < "https://x".len or url.len > 2048) return false;
    if (!std.mem.startsWith(u8, url, "https://")) return false;

    for (url) |c| {
        if (c <= 0x20 or c == 0x7f) return false; // control chars, space
        if (c == '"' or c == '\'' or c == '\\' or c == '`') return false;
    }

    // A leading '-' after the scheme cannot happen, but guard the whole string
    // being parsed as an option by any downstream tool.
    if (url[0] == '-') return false;

    // Reject userinfo (`https://user:pass@host`, or `https://host@evil.com`
    // where the browser and the user see different hosts). Only the authority
    // part is checked, so an '@' in the path or query is still allowed.
    const host_start = "https://".len;
    if (host_start >= url.len) return false;
    if (url[host_start] == '/') return false;

    var authority_end = host_start;
    while (authority_end < url.len and url[authority_end] != '/' and
        url[authority_end] != '?' and url[authority_end] != '#') : (authority_end += 1)
    {}
    if (std.mem.indexOfScalar(u8, url[host_start..authority_end], '@') != null) return false;
    return true;
}

/// Largest response curl will accept. Enforced by curl itself via
/// `--max-filesize`, so a hostile or runaway server cannot fill the disk.
pub const max_download_bytes: u64 = 2 * 1024 * 1024 * 1024;

/// Percent-encode a value for safe inclusion in a query string.
pub fn urlEncode(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    for (s) |c| {
        switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '_', '.', '~' => try out.append(c),
            else => try out.writer().print("%{X:0>2}", .{c}),
        }
    }
    return out.toOwnedSlice();
}

/// Reject a header that would break the header file: CR or LF would start a
/// new line in it, and NUL would cut the line short. Each header is one line.
pub fn validHeaders(headers: []const []const u8) bool {
    for (headers) |h| {
        if (std.mem.indexOfAny(u8, h, "\r\n\x00") != null) return false;
    }
    return true;
}

/// `<abv0 home>`, found the way `Store.init` finds it: `ABV0_HOME`, else
/// `~/.abv0`. Caller frees the result.
fn stateRoot(allocator: std.mem.Allocator) ?[]u8 {
    return platform.homeOverride(allocator) orelse blk: {
        const home = platform.homeDir(allocator) catch return null;
        defer allocator.free(home);
        break :blk std.fs.path.join(allocator, &.{ home, ".abv0" }) catch return null;
    };
}

/// `<abv0 home>/tmp`, created 0700 when missing. Private scratch space for
/// requests that have no download destination beside them.
pub fn privateTmpDir(allocator: std.mem.Allocator) ![]u8 {
    const root = stateRoot(allocator) orelse return Error.NoPrivateDir;
    defer allocator.free(root);
    const tmp = try std.fs.path.join(allocator, &.{ root, "tmp" });
    errdefer allocator.free(tmp);
    try platform.ensureSecureDir(tmp);
    return tmp;
}

/// Write `headers`, one per line, to a new private file (mode 0600, created
/// exclusively) in `dir`, or in `<abv0 home>/tmp` when `dir` is null. Returns
/// its path, or null when there are no headers. Remove it with
/// `removeHeaderFile` once curl has exited, whatever curl did.
pub fn writeHeaderFile(allocator: std.mem.Allocator, dir: ?[]const u8, headers: []const []const u8) !?[]u8 {
    if (headers.len == 0) return null;
    if (!validHeaders(headers)) return Error.UnsafeHeader;

    const owned_dir: ?[]u8 = if (dir == null) try privateTmpDir(allocator) else null;
    defer if (owned_dir) |d| allocator.free(d);
    const dir_path = dir orelse owned_dir.?;

    var rand: [8]u8 = undefined;
    std.crypto.random.bytes(&rand);
    const name = try std.fmt.allocPrint(allocator, "abv0-headers-{s}", .{std.fmt.fmtSliceHexLower(&rand)});
    defer allocator.free(name);
    const path = try std.fs.path.join(allocator, &.{ dir_path, name });
    errdefer allocator.free(path);

    // Exclusive: a file that already exists is never ours to write or remove.
    const file = try std.fs.cwd().createFile(path, .{ .exclusive = true, .mode = platform.mode_private });
    var written = false;
    defer {
        file.close();
        if (!written) removeHeaderFile(path);
    }
    for (headers) |h| {
        try file.writeAll(h);
        try file.writeAll("\n");
    }
    written = true;
    return path;
}

/// Delete a file made by `writeHeaderFile`. Best effort; null is a no-op.
pub fn removeHeaderFile(path: ?[]const u8) void {
    const p = path orelse return;
    std.fs.cwd().deleteFile(p) catch {};
}

/// Build the curl argv. Pure (no spawning) so it can be unit tested.
/// `-q` must stay first: it stops curl from reading ~/.curlrc or
/// $CURL_HOME, which could otherwise add proxies, headers or `--insecure`.
pub fn buildCurlArgv(
    allocator: std.mem.Allocator,
    url: []const u8,
    dest: ?[]const u8,
    opts: Options,
    extra: []const []const u8,
) ![][]const u8 {
    var args = std.ArrayList([]const u8).init(allocator);
    errdefer args.deinit();

    const connect = try std.fmt.allocPrint(allocator, "{d}", .{opts.connect_timeout_s});
    const maxtime = try std.fmt.allocPrint(allocator, "{d}", .{opts.max_time_s});
    const retries = try std.fmt.allocPrint(allocator, "{d}", .{opts.retries});
    const maxsize = try std.fmt.allocPrint(allocator, "{d}", .{max_download_bytes});

    try args.appendSlice(&.{
        "curl",
        "-q", // must be first: ignore ~/.curlrc
        "--fail", // non-zero exit on HTTP >= 400
        "--silent",
        "--show-error",
        "--location", // follow redirects...
        "--max-redirs",
        "5",
        "--proto",       "=https", // ...but only ever over https
        "--proto-redir", "=https",
        "--tlsv1.2", // no TLS 1.0/1.1
        "--max-filesize",
        maxsize,
        "--connect-timeout",
        connect,
        "--max-time",
        maxtime,
        "--retry",
        retries,
        "--user-agent",
        opts.user_agent,
    });
    try args.appendSlice(extra);
    if (opts.headers.len > 0) {
        // Header values stay out of argv, where `ps` shows them to every user.
        // curl reads them from the private file instead.
        const path = opts.header_file orelse return Error.HeaderFileMissing;
        const arg = try std.fmt.allocPrint(allocator, "@{s}", .{path});
        try args.appendSlice(&.{ "--header", arg });
    }
    if (dest) |d| try args.appendSlice(&.{ "--output", d });
    try args.append(url);
    return args.toOwnedSlice();
}

/// What a finished download yields: the SHA-256 of the file and its first bytes.
pub const Fetched = pget.Fetched;

/// Download `url` to `dest_path`. Returns an error on any HTTP failure.
pub fn download(
    allocator: std.mem.Allocator,
    url: []const u8,
    dest_path: []const u8,
    opts: Options,
) !void {
    _ = try downloadHashed(allocator, url, dest_path, opts);
}

/// `download`, and the digest of what was written, computed while the bytes
/// arrived. A big body that supports byte ranges is fetched over several
/// connections at once and hashed in order as the chunks land (see
/// `pget.zig`), so the digest costs no pass over the file. Nothing is left at
/// `dest_path` unless the download succeeded.
pub fn downloadHashed(
    allocator: std.mem.Allocator,
    url: []const u8,
    dest_path: []const u8,
    opts: Options,
) !Fetched {
    if (!isSafeUrl(url)) return Error.UnsafeUrl;
    if (!validHeaders(opts.headers)) return Error.UnsafeHeader;

    var allow_split = true;
    var use_curl = false;
    while (true) {
        const t = pget.begin(url, .{
            .opts = opts,
            .dest = .{ .file = dest_path },
            .mode = .download,
            .allow_split = allow_split,
            .use_curl = use_curl,
        }) catch |e| switch (e) {
            // No curl: Windows has PowerShell as a last resort.
            error.CurlMissing => {
                var arena_state = std.heap.ArenaAllocator.init(allocator);
                defer arena_state.deinit();
                try downloadFallback(arena_state.allocator(), url, dest_path, opts);
                return hashFile(dest_path);
            },
            else => return curlError(e),
        };
        defer t.deinit();

        if (t.complete()) |fetched| return fetched else |e| {
            // A server that promised byte ranges and broke the promise:
            // start over with one stream (and do not ask that host again).
            if (e == error.RangeNotHonoured and allow_split) {
                allow_split = false;
                continue;
            }
            if (t.isBuiltin()) {
                // A policy answer, or the caller forced the built-in client.
                if (!http.isTransportError(e) or downloaderMode() == .builtin) return e;
                // The network broke the built-in client mid-transfer: remember
                // that and redo the download with curl.
                reportBuiltinFailure(http.hostOf(url) orelse "", e);
                use_curl = true;
                continue;
            }
            return curlError(e);
        }
    }
}

/// What a failed curl transfer reports: the policy answers as they are, every
/// other failure as `DownloadFailed`.
fn curlError(e: anyerror) anyerror {
    return switch (e) {
        error.UnsafeUrl,
        error.UnsafeHeader,
        error.DownloadTooLarge,
        error.WriteFailed,
        error.OutOfMemory,
        error.NoDownloaderAvailable,
        error.HeaderFileMissing,
        error.NoPrivateDir,
        error.UnsafeRedirect,
        error.TooManyRedirects,
        error.BadRedirect,
        error.HttpStatus,
        => e,
        else => Error.DownloadFailed,
    };
}

/// SHA-256 and leading bytes of a file, for the rare path that downloads
/// without the in-order digest.
fn hashFile(path: []const u8) !Fetched {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    var d: pget.Digester = .{};
    var buf: [64 * 1024]u8 = undefined;
    while (true) {
        const n = try file.read(&buf);
        if (n == 0) break;
        d.update(buf[0..n]);
    }
    return d.fetched(1);
}

/// Windows ships curl.exe since Windows 10 1803, but fall back to PowerShell
/// if it is missing.
fn downloadFallback(
    allocator: std.mem.Allocator,
    url: []const u8,
    dest_path: []const u8,
    opts: Options,
) !void {
    if (!platform.is_windows) return Error.NoDownloaderAvailable;

    // Any failure removes the partial file. The script checks that the final
    // URL after redirects is still https; Invoke-WebRequest cannot be told to
    // refuse a plain-http hop, so that case is caught after the fact and the
    // bytes are discarded.
    errdefer std.fs.cwd().deleteFile(dest_path) catch {};

    const script = try std.fmt.allocPrint(
        allocator,
        \\$ProgressPreference='SilentlyContinue';
        \\try {{
        \\  $r = Invoke-WebRequest -UseBasicParsing -ErrorAction Stop -MaximumRedirection 5 -TimeoutSec {d} -Uri $env:ABV0_URL -OutFile $env:ABV0_DEST -PassThru;
        \\  $final = $r.BaseResponse.ResponseUri;
        \\  if ($null -eq $final) {{ $final = $r.BaseResponse.RequestMessage.RequestUri }};
        \\  if ($null -eq $final -or $final.Scheme -ne 'https') {{ throw 'redirected to a non-https URL' }};
        \\}} catch {{
        \\  Remove-Item -LiteralPath $env:ABV0_DEST -Force -ErrorAction SilentlyContinue;
        \\  exit 1;
        \\}}
    ,
        .{opts.max_time_s},
    );

    var env = try std.process.getEnvMap(allocator);
    defer env.deinit();
    try env.put("ABV0_URL", url);
    try env.put("ABV0_DEST", dest_path);

    var child = std.process.Child.init(
        &.{ "powershell", "-NoProfile", "-NonInteractive", "-Command", script },
        allocator,
    );
    child.env_map = &env;
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;

    const term = child.spawnAndWait() catch return Error.NoDownloaderAvailable;
    if (term != .Exited or term.Exited != 0) return Error.DownloadFailed;
}

/// Fetch a small resource (an API response) into memory.
pub fn fetchToString(
    allocator: std.mem.Allocator,
    url: []const u8,
    max_bytes: usize,
    opts: Options,
) ![]u8 {
    if (!isSafeUrl(url)) return Error.UnsafeUrl;
    if (!validHeaders(opts.headers)) return Error.UnsafeHeader;
    if (try fetchBuiltin(allocator, url, max_bytes, opts)) |body| return body;

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const header_file = try writeHeaderFile(arena, null, opts.headers);
    defer removeHeaderFile(header_file);
    var curl_opts = opts;
    curl_opts.header_file = header_file;

    const argv = try buildCurlArgv(arena, url, null, curl_opts, &.{});

    const res = std.process.Child.run(.{
        .allocator = arena,
        .argv = argv,
        .max_output_bytes = max_bytes,
    }) catch return Error.DownloadFailed;

    if (res.term != .Exited or res.term.Exited != 0) return Error.DownloadFailed;
    return allocator.dupe(u8, res.stdout);
}

// ---------------------------------------------------------------------------
// Built-in client first, curl as the backup
// ---------------------------------------------------------------------------

/// Which downloader `ABV0_DOWNLOADER` selects.
pub const Downloader = enum { auto, builtin, curl };

/// Parse an `ABV0_DOWNLOADER` value. Unset, empty or unrecognised means auto,
/// so a typo never disables downloading.
pub fn parseDownloader(value: ?[]const u8) Downloader {
    const v = value orelse return .auto;
    if (std.ascii.eqlIgnoreCase(v, "builtin")) return .builtin;
    if (std.ascii.eqlIgnoreCase(v, "curl")) return .curl;
    return .auto;
}

pub fn downloaderMode() Downloader {
    var buf: [32]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const v = std.process.getEnvVarOwned(fba.allocator(), "ABV0_DOWNLOADER") catch return .auto;
    return parseDownloader(v);
}

pub const Route = enum { builtin, curl };

/// The decision, separated from the state it reads so it can be tested.
/// A forced mode wins; in auto mode curl is chosen once the built-in client
/// has failed for this host before, or for the run as a whole.
pub fn decideRoute(mode: Downloader, run_tripped: bool, host_remembered: bool) Route {
    return switch (mode) {
        .curl => .curl,
        .builtin => .builtin,
        .auto => if (run_tripped or host_remembered) .curl else .builtin,
    };
}

/// How long a transport failure is remembered.
pub const fallback_ttl_s: i64 = 24 * 60 * 60;
/// Entry that stands for every host (see `reportBuiltinFailure`).
const any_host = "*";

/// Hosts the built-in client could not talk to, persisted so that the next run
/// skips the attempt instead of paying its failure again. A failed TLS
/// handshake through a broken proxy costs seconds; curl on the same network
/// works at once.
///
/// File format, one host per line, tab separated:
///     <host> <unix time> <reason>
/// Lines starting with '#' are ignored, as are malformed and expired lines, so
/// a damaged or hand-edited file can only cost a retry of the built-in client.
pub const FallbackMemory = struct {
    pub const file_name = "net-fallback";
    pub const max_entries = 32;
    const max_file_bytes = 16 * 1024;

    pub const Entry = struct {
        host: []u8,
        reason: []u8,
        time: i64,
    };

    allocator: std.mem.Allocator,
    entries: std.ArrayListUnmanaged(Entry) = .{},

    pub fn init(allocator: std.mem.Allocator) FallbackMemory {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *FallbackMemory) void {
        for (self.entries.items) |e| self.freeEntry(e);
        self.entries.deinit(self.allocator);
    }

    fn freeEntry(self: *FallbackMemory, e: Entry) void {
        self.allocator.free(e.host);
        self.allocator.free(e.reason);
    }

    /// An entry still in force at `now`. One dated in the far future is a
    /// clock that was wrong when it was written, so it expires too.
    fn live(time: i64, now: i64) bool {
        return time <= now + fallback_ttl_s and now - time < fallback_ttl_s;
    }

    pub fn shouldSkip(self: *const FallbackMemory, host: []const u8, now: i64) bool {
        for (self.entries.items) |e| {
            if (!live(e.time, now)) continue;
            if (std.mem.eql(u8, e.host, any_host) or std.ascii.eqlIgnoreCase(e.host, host)) return true;
        }
        return false;
    }

    /// Merge `text` (file contents) into the memory. The newer entry wins per host.
    pub fn parse(self: *FallbackMemory, text: []const u8, now: i64) !void {
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, raw, "\r ");
            if (line.len == 0 or line[0] == '#') continue;
            var f = std.mem.splitScalar(u8, line, '\t');
            const host = f.next() orelse continue;
            const time = std.fmt.parseInt(i64, f.next() orelse continue, 10) catch continue;
            const reason = f.next() orelse "unknown";
            if (!validField(host) or !validField(reason)) continue;
            if (!live(time, now)) continue;
            try self.put(host, reason, time);
        }
    }

    /// No whitespace or control bytes, so a field can never break the format.
    fn validField(s: []const u8) bool {
        if (s.len == 0 or s.len > 253) return false;
        for (s) |c| if (c <= 0x20 or c == 0x7f) return false;
        return true;
    }

    fn put(self: *FallbackMemory, host: []const u8, reason: []const u8, time: i64) !void {
        for (self.entries.items) |*e| {
            if (!std.ascii.eqlIgnoreCase(e.host, host)) continue;
            if (time < e.time) return; // keep the newer one
            const new_reason = try self.allocator.dupe(u8, reason);
            self.allocator.free(e.reason);
            e.reason = new_reason;
            e.time = time;
            return;
        }
        // Full: drop the oldest to make room.
        if (self.entries.items.len >= max_entries) {
            var oldest: usize = 0;
            for (self.entries.items, 0..) |e, i| {
                if (e.time < self.entries.items[oldest].time) oldest = i;
            }
            self.freeEntry(self.entries.swapRemove(oldest));
        }
        const h = try self.allocator.dupe(u8, host);
        errdefer self.allocator.free(h);
        const r = try self.allocator.dupe(u8, reason);
        errdefer self.allocator.free(r);
        try self.entries.append(self.allocator, .{ .host = h, .reason = r, .time = time });
    }

    /// Serialise the live entries.
    pub fn format(self: *const FallbackMemory, w: anytype, now: i64) !void {
        try w.writeAll("# abv0: hosts where the built-in HTTPS client failed; curl is used for them until the entry expires.\n");
        try w.writeAll("# host<TAB>unix time<TAB>reason. Delete this file to try the built-in client again.\n");
        for (self.entries.items) |e| {
            if (!live(e.time, now)) continue;
            try w.print("{s}\t{d}\t{s}\n", .{ e.host, e.time, e.reason });
        }
    }

    /// Read the file in `dir` into the memory. Best effort: a missing or
    /// unreadable file just means nothing is remembered.
    pub fn load(self: *FallbackMemory, dir: std.fs.Dir, now: i64) void {
        const text = dir.readFileAlloc(self.allocator, file_name, max_file_bytes) catch return;
        defer self.allocator.free(text);
        self.parse(text, now) catch {};
    }

    /// Remember `host` and write the file. The file is replaced atomically
    /// (written to a temporary name, then renamed), so a run that starts while
    /// another is writing sees the old file or the new one, never half of it.
    /// What other runs wrote since this one loaded is merged first. The entry
    /// stays in memory even when the write fails.
    pub fn record(self: *FallbackMemory, dir: ?std.fs.Dir, host: []const u8, reason: []const u8, now: i64) void {
        if (!validField(host)) return;
        if (dir) |d| self.load(d, now);
        self.put(host, if (validField(reason)) reason else "error", now) catch return;
        const d = dir orelse return;

        var af = d.atomicFile(file_name, .{ .mode = platform.mode_private }) catch return;
        defer af.deinit();
        self.format(af.file.writer(), now) catch return;
        af.finish() catch {};
    }
};

var route_mutex: std.Thread.Mutex = .{};
var route_memory: ?FallbackMemory = null;
var route_dir: ?std.fs.Dir = null;
/// Built-in attempts this run that failed at the transport level, and that
/// worked. Atomics: read outside the mutex on the hot path.
var run_failures: u32 = 0;
var run_successes: u32 = 0;

/// Failures with no success in between that make the whole run use curl. The
/// cause in that case is the network path (a proxy, interception), not one
/// host, and every further host would pay the same failed attempt.
const breaker_threshold = 2;

fn runTripped() bool {
    return @atomicLoad(u32, &run_failures, .acquire) >= breaker_threshold and
        @atomicLoad(u32, &run_successes, .acquire) == 0;
}

/// The abv0 home as a directory handle. The download functions take no store,
/// so they find it through `stateRoot`.
fn openStateDir() ?std.fs.Dir {
    const a = std.heap.page_allocator;
    const root = stateRoot(a) orelse return null;
    defer a.free(root);
    return std.fs.cwd().openDir(root, .{}) catch null;
}

/// Caller holds `route_mutex`.
fn memoryLocked() *FallbackMemory {
    if (route_memory == null) {
        route_memory = FallbackMemory.init(std.heap.page_allocator);
        route_dir = openStateDir();
        if (route_dir) |d| route_memory.?.load(d, std.time.timestamp());
    }
    return &route_memory.?;
}

/// Which downloader to use for a request to `host`.
pub fn chooseRoute(host: []const u8) Route {
    const mode = downloaderMode();
    if (mode != .auto) return decideRoute(mode, false, false);
    if (runTripped()) return .curl;

    route_mutex.lock();
    defer route_mutex.unlock();
    return decideRoute(mode, false, memoryLocked().shouldSkip(host, std.time.timestamp()));
}

/// The built-in client failed at the transport level for `host` and the
/// request is about to be retried with curl. Remembers the host on disk.
pub fn reportBuiltinFailure(host: []const u8, err: anyerror) void {
    if (downloaderMode() != .auto) return;
    _ = @atomicRmw(u32, &run_failures, .Add, 1, .acq_rel);

    route_mutex.lock();
    defer route_mutex.unlock();
    const mem = memoryLocked();
    const now = std.time.timestamp();
    mem.record(route_dir, host, @errorName(err), now);
    // Enough failures without a success: remember the whole network path.
    if (runTripped()) mem.record(route_dir, any_host, @errorName(err), now);
}

/// The built-in client completed a request. Without this the breaker could
/// trip on two failures that were host-specific.
pub fn reportBuiltinSuccess() void {
    _ = @atomicRmw(u32, &run_successes, .Add, 1, .acq_rel);
}

/// Hosts a GitHub release download talks to: the site, then the CDNs it
/// redirects to.
pub const github_hosts = [_][]const u8{
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
};

/// Open TLS connections to `hosts` in the background and leave them idle in the
/// shared client's pool, so the first request to each reuses a connection that
/// is already up instead of paying for the handshake. Returns at once. Hosts
/// the route says should go through curl are skipped, as is everything when
/// the downloader is forced to curl. A failure is ignored: the real request
/// will meet it and handle it.
pub fn prewarm(hosts: []const []const u8) void {
    if (downloaderMode() == .curl) return;
    for (hosts) |h| {
        if (h.len == 0 or chooseRoute(h) == .curl) continue;
        const owned = std.heap.page_allocator.dupe(u8, h) catch return;
        const t = std.Thread.spawn(.{}, prewarmOne, .{owned}) catch {
            std.heap.page_allocator.free(owned);
            continue;
        };
        t.detach();
    }
}

/// `prewarm` for the hosts a GitHub release download uses.
pub fn prewarmGithub() void {
    prewarm(&github_hosts);
}

fn prewarmOne(host: []u8) void {
    defer std.heap.page_allocator.free(host);
    const client = http.shared() catch return;
    client.warm(host);
}

pub fn retryDelay(attempt: u32) void {
    // curl's --retry waits 1 s, then doubles.
    std.time.sleep(@as(u64, std.time.ns_per_s) << @intCast(@min(attempt, 4)));
}

/// True when an HTTP error should be tried again, as curl's --retry does.
pub fn retryable(err: anyerror, attempt: u32, opts: Options) bool {
    return err == error.HttpStatus and http.isTransientStatus(http.last_http_status) and attempt < opts.retries;
}

pub fn limitsFor(opts: Options) http.Limits {
    return .{ .max_time_s = opts.max_time_s, .headers = opts.headers };
}

/// Outcome of a built-in attempt that failed: return the error, or hand over
/// to curl by returning normally.
pub fn builtinFailed(host: []const u8, err: anyerror) anyerror!void {
    // A policy answer, or the caller forced the built-in client and wants the
    // raw error: curl would not help.
    if (!http.isTransportError(err) or downloaderMode() == .builtin) return err;
    reportBuiltinFailure(host, err);
}

/// Try the built-in client for a response held in memory. Returns the body, null
/// when the caller should use curl, and an error for a final answer.
fn fetchBuiltin(allocator: std.mem.Allocator, url: []const u8, max_bytes: usize, opts: Options) !?[]u8 {
    const host = http.hostOf(url) orelse return null;
    if (chooseRoute(host) == .curl) return null;

    const client = http.shared() catch |e| {
        try builtinFailed(host, e);
        return null;
    };

    var attempt: u32 = 0;
    while (true) : (attempt += 1) {
        var body = std.ArrayList(u8).init(allocator);
        var lim = limitsFor(opts);
        lim.max_bytes = max_bytes;
        if (client.get(allocator, url, body.writer(), lim)) |_| {
            reportBuiltinSuccess();
            return try body.toOwnedSlice();
        } else |e| {
            body.deinit();
            if (retryable(e, attempt, opts)) {
                retryDelay(attempt);
                continue;
            }
            try builtinFailed(host, e);
            return null;
        }
    }
}

/// Remote size via a HEAD request, plus whether ranges are supported.
pub const RemoteInfo = struct {
    content_length: ?u64 = null,
    accepts_ranges: bool = false,
};

pub fn head(allocator: std.mem.Allocator, url: []const u8, opts: Options) !RemoteInfo {
    if (!isSafeUrl(url)) return Error.UnsafeUrl;
    if (!validHeaders(opts.headers)) return Error.UnsafeHeader;

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const header_file = try writeHeaderFile(arena, null, opts.headers);
    defer removeHeaderFile(header_file);
    var curl_opts = opts;
    curl_opts.header_file = header_file;

    const argv = try buildCurlArgv(arena, url, null, curl_opts, &.{ "--head", "--request", "GET" });
    const res = std.process.Child.run(.{
        .allocator = arena,
        .argv = argv,
        .max_output_bytes = 128 * 1024,
    }) catch return Error.DownloadFailed;

    if (res.term != .Exited or res.term.Exited != 0) return Error.DownloadFailed;
    return parseHeaders(res.stdout);
}

pub fn parseHeaders(raw: []const u8) RemoteInfo {
    var info = RemoteInfo{};
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, "\r\t ");
        if (line.len == 0) continue;

        if (std.ascii.startsWithIgnoreCase(line, "content-length:")) {
            const val = std.mem.trim(u8, line["content-length:".len..], " \t");
            // Later headers win (a redirect chain reports several).
            info.content_length = std.fmt.parseInt(u64, val, 10) catch info.content_length;
        } else if (std.ascii.startsWithIgnoreCase(line, "accept-ranges:")) {
            const val = std.mem.trim(u8, line["accept-ranges:".len..], " \t");
            if (std.ascii.eqlIgnoreCase(val, "bytes")) info.accepts_ranges = true;
        }
    }
    return info;
}

/// One byte-range slice of a parallel download.
pub const ChunkJob = struct {
    allocator: std.mem.Allocator,
    url: []const u8,
    start: u64,
    end: u64,
    dest: []const u8,
    opts: Options,
    ok: bool = false,

    pub fn run(self: *ChunkJob) void {
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const range = std.fmt.allocPrint(arena, "{d}-{d}", .{ self.start, self.end }) catch return;
        const header_file = writeHeaderFile(arena, std.fs.path.dirname(self.dest) orelse ".", self.opts.headers) catch return;
        defer removeHeaderFile(header_file);
        var curl_opts = self.opts;
        curl_opts.header_file = header_file;
        const argv = buildCurlArgv(arena, self.url, self.dest, curl_opts, &.{ "--range", range }) catch return;

        const res = std.process.Child.run(.{
            .allocator = arena,
            .argv = argv,
            .max_output_bytes = 16 * 1024,
        }) catch return;

        self.ok = (res.term == .Exited and res.term.Exited == 0);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test {
    _ = pget;
}

test "isSafeUrl accepts https and rejects everything else" {
    try testing.expect(isSafeUrl("https://github.com/a/b/releases/download/v1/x.tar.gz"));
    try testing.expect(isSafeUrl("https://api.github.com/repos/o/r/releases/latest"));

    try testing.expect(!isSafeUrl("http://example.com/x")); // downgrade
    try testing.expect(!isSafeUrl("file:///etc/passwd")); // local file read
    try testing.expect(!isSafeUrl("ftp://example.com/x"));
    try testing.expect(!isSafeUrl("https://example.com/x\nHeader: y")); // header injection
    try testing.expect(!isSafeUrl("https://example.com/ x")); // arg splitting
    try testing.expect(!isSafeUrl("https://example.com/\"x\""));
    try testing.expect(!isSafeUrl("https:///etc"));
    try testing.expect(!isSafeUrl(""));
    try testing.expect(!isSafeUrl("https://"));
}

test "urlEncode escapes query-breaking characters" {
    const a = testing.allocator;

    const q = try urlEncode(a, "ripgrep&per_page=1");
    defer a.free(q);
    // Without this, a package name could inject GitHub API parameters.
    try testing.expectEqualStrings("ripgrep%26per_page%3D1", q);

    const s = try urlEncode(a, "hello world\n");
    defer a.free(s);
    try testing.expectEqualStrings("hello%20world%0A", s);

    const plain = try urlEncode(a, "safe-name_1.0~x");
    defer a.free(plain);
    try testing.expectEqualStrings("safe-name_1.0~x", plain);
}

test "parseHeaders reads length and range support" {
    const raw =
        "HTTP/1.1 302 Found\r\n" ++
        "Location: https://cdn.example.com/x\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n" ++
        "HTTP/1.1 200 OK\r\n" ++
        "Accept-Ranges: bytes\r\n" ++
        "Content-Length: 1048576\r\n\r\n";

    const info = parseHeaders(raw);
    try testing.expectEqual(@as(u64, 1048576), info.content_length.?);
    try testing.expect(info.accepts_ranges);

    const none = parseHeaders("HTTP/1.1 200 OK\r\n\r\n");
    try testing.expect(none.content_length == null);
    try testing.expect(!none.accepts_ranges);
}

test "isSafeUrl rejects userinfo, spaces and backslashes" {
    try testing.expect(!isSafeUrl("https://github.com@evil.com/x")); // host confusion
    try testing.expect(!isSafeUrl("https://user:pw@github.com/x"));
    try testing.expect(!isSafeUrl("https://a b"));
    try testing.expect(!isSafeUrl("https://github.com\\@evil.com/x"));
    try testing.expect(!isSafeUrl("https://github.com/x\\..\\y"));
    try testing.expect(!isSafeUrl("http://x"));

    // An '@' outside the authority is just a path character.
    try testing.expect(isSafeUrl("https://github.com/owner/repo/releases/download/v1/@scope.tgz"));
    try testing.expect(isSafeUrl("https://github.com/a/b?x=y@z"));
}

test "isSafeUrl accepts normal GitHub release URLs" {
    try testing.expect(isSafeUrl("https://github.com/owner/repo/releases/download/v1.2.3/pkg-x86_64-linux.tar.gz"));
    try testing.expect(isSafeUrl("https://api.github.com/repos/owner/repo/releases/latest"));
    try testing.expect(isSafeUrl("https://objects.githubusercontent.com/github-production-release-asset/123?X-Amz-Expires=300"));
}

test "buildCurlArgv starts with -q and enforces https, tls 1.2 and a size cap" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const argv = try buildCurlArgv(arena, "https://github.com/a/b", null, .{}, &.{});
    try testing.expectEqualStrings("curl", argv[0]);
    try testing.expectEqualStrings("-q", argv[1]);
    try testing.expectEqualStrings("https://github.com/a/b", argv[argv.len - 1]);

    const cap = try std.fmt.allocPrint(arena, "{d}", .{max_download_bytes});
    var saw_cap = false;
    var saw_tls12 = false;
    var saw_proto = false;
    for (argv, 0..) |a, i| {
        if (std.mem.eql(u8, a, "--max-filesize")) {
            try testing.expectEqualStrings(cap, argv[i + 1]);
            saw_cap = true;
        } else if (std.mem.eql(u8, a, "--tlsv1.2")) {
            saw_tls12 = true;
        } else if (std.mem.eql(u8, a, "--proto") and std.mem.eql(u8, argv[i + 1], "=https")) {
            saw_proto = true;
        }
    }
    try testing.expect(saw_cap and saw_tls12 and saw_proto);
}

test "download refuses an unsafe url before spawning anything" {
    try testing.expectError(Error.UnsafeUrl, download(testing.allocator, "file:///etc/passwd", "/tmp/x", .{}));
    try testing.expectError(Error.UnsafeUrl, download(testing.allocator, "http://x.test/y", "/tmp/x", .{}));
}

test "ABV0_DOWNLOADER parses builtin, curl and auto; anything else is auto" {
    try testing.expectEqual(Downloader.auto, parseDownloader(null));
    try testing.expectEqual(Downloader.auto, parseDownloader(""));
    try testing.expectEqual(Downloader.auto, parseDownloader("auto"));
    try testing.expectEqual(Downloader.auto, parseDownloader("wget"));
    try testing.expectEqual(Downloader.builtin, parseDownloader("builtin"));
    try testing.expectEqual(Downloader.builtin, parseDownloader("BUILTIN"));
    try testing.expectEqual(Downloader.curl, parseDownloader("curl"));
}

test "decideRoute: forced modes win, auto skips what failed before" {
    try testing.expectEqual(Route.builtin, decideRoute(.auto, false, false));
    try testing.expectEqual(Route.curl, decideRoute(.auto, false, true));
    try testing.expectEqual(Route.curl, decideRoute(.auto, true, false));
    // A forced mode ignores the memory.
    try testing.expectEqual(Route.builtin, decideRoute(.builtin, true, true));
    try testing.expectEqual(Route.curl, decideRoute(.curl, false, false));
}

test "FallbackMemory round trips through the file and expires after 24 hours" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const t0: i64 = 1_800_000_000;

    var first = FallbackMemory.init(testing.allocator);
    defer first.deinit();
    first.record(tmp.dir, "github.com", "ConnectionResetByPeer", t0);
    first.record(tmp.dir, "Objects.GitHubUserContent.com", "TlsAlert", t0 + 60);

    // A later run reads the file back.
    var second = FallbackMemory.init(testing.allocator);
    defer second.deinit();
    second.load(tmp.dir, t0 + 120);
    try testing.expect(second.shouldSkip("github.com", t0 + 120));
    try testing.expect(second.shouldSkip("GITHUB.COM", t0 + 120)); // host names are case-insensitive
    try testing.expect(second.shouldSkip("objects.githubusercontent.com", t0 + 120));
    try testing.expect(!second.shouldSkip("example.com", t0 + 120));

    // Still in force just before the 24 hours are up, gone at the mark.
    try testing.expect(second.shouldSkip("github.com", t0 + fallback_ttl_s - 1));
    try testing.expect(!second.shouldSkip("github.com", t0 + fallback_ttl_s));
    // Expired lines are dropped when loading, not resurrected.
    var third = FallbackMemory.init(testing.allocator);
    defer third.deinit();
    third.load(tmp.dir, t0 + fallback_ttl_s + 30);
    try testing.expect(!third.shouldSkip("github.com", t0 + fallback_ttl_s + 30));
    try testing.expect(third.shouldSkip("objects.githubusercontent.com", t0 + fallback_ttl_s + 30));
}

test "FallbackMemory file keeps host, reason and time, and replaces atomically" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const t0: i64 = 1_800_000_000;

    var m = FallbackMemory.init(testing.allocator);
    defer m.deinit();
    m.record(tmp.dir, "github.com", "TlsAlert", t0);
    m.record(tmp.dir, "github.com", "ConnectionResetByPeer", t0 + 10); // same host: replaced, not duplicated

    const text = try tmp.dir.readFileAlloc(testing.allocator, FallbackMemory.file_name, 4096);
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "github.com\t1800000010\tConnectionResetByPeer\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "TlsAlert") == null);

    // No temporary file is left behind by the atomic write.
    var it = tmp.dir.iterate();
    var n: usize = 0;
    while (try it.next()) |_| n += 1;
    try testing.expectEqual(@as(usize, 1), n);
}

test "FallbackMemory ignores garbage, comments and future-dated lines" {
    const now: i64 = 1_800_000_000;
    const text =
        "# a comment\n" ++
        "\n" ++
        "no-time-field\n" ++
        "bad.test\tnot-a-number\tx\n" ++
        "future.test\t1900000000\tx\n" ++ // clock was wrong when written
        "has space.test\t1800000000\tx\n" ++
        "ok.test\t1799999000\tTlsFailure\r\n";
    var m = FallbackMemory.init(testing.allocator);
    defer m.deinit();
    try m.parse(text, now);
    try testing.expectEqual(@as(usize, 1), m.entries.items.len);
    try testing.expect(m.shouldSkip("ok.test", now));
    try testing.expect(!m.shouldSkip("future.test", now));
}

test "FallbackMemory wildcard entry covers every host and the table is bounded" {
    const now: i64 = 1_800_000_000;
    var m = FallbackMemory.init(testing.allocator);
    defer m.deinit();
    m.record(null, "*", "ConnectionResetByPeer", now);
    try testing.expect(m.shouldSkip("anything.example", now));

    var other = FallbackMemory.init(testing.allocator);
    defer other.deinit();
    var i: usize = 0;
    while (i < FallbackMemory.max_entries + 10) : (i += 1) {
        var buf: [32]u8 = undefined;
        other.record(null, std.fmt.bufPrint(&buf, "h{d}.test", .{i}) catch unreachable, "x", now + @as(i64, @intCast(i)));
    }
    try testing.expectEqual(@as(usize, FallbackMemory.max_entries), other.entries.items.len);
    // The oldest were dropped, the newest kept.
    try testing.expect(!other.shouldSkip("h0.test", now + 100));
    try testing.expect(other.shouldSkip("h41.test", now + 100));
}

test "FallbackMemory refuses a host that would break the file format" {
    var m = FallbackMemory.init(testing.allocator);
    defer m.deinit();
    m.record(null, "a\tb", "x", 1_800_000_000);
    m.record(null, "a\nb", "x", 1_800_000_000);
    m.record(null, "", "x", 1_800_000_000);
    try testing.expectEqual(@as(usize, 0), m.entries.items.len);
}

test "HTTP answers stay errors; transport failures are what falls back to curl" {
    // The contract downloadBuiltin relies on, pinned next to its users.
    try testing.expect(http.isTransportError(error.ConnectionResetByPeer));
    try testing.expect(http.isTransportError(error.TlsAlert));
    try testing.expect(!http.isTransportError(error.HttpStatus));
    try testing.expect(!http.isTransportError(error.UnsafeRedirect));
    try testing.expect(!http.isTransportError(error.TooManyRedirects));
}

test "buildCurlArgv passes headers as a file reference, never their values" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const headers = [_][]const u8{"Authorization: Bearer ghp_TESTSECRET123"};
    const argv = try buildCurlArgv(arena, "https://api.github.com/x", null, .{
        .headers = &headers,
        .header_file = "/home/u/.abv0/tmp/abv0-headers-1",
    }, &.{});

    var saw_header = false;
    for (argv, 0..) |a, i| {
        try testing.expect(std.mem.indexOf(u8, a, "TESTSECRET") == null);
        if (std.mem.eql(u8, a, "--header")) {
            try testing.expectEqualStrings("@/home/u/.abv0/tmp/abv0-headers-1", argv[i + 1]);
            saw_header = true;
        }
    }
    try testing.expect(saw_header);

    // Headers with no file to go in cannot be sent, so the call fails rather
    // than silently dropping them.
    try testing.expectError(Error.HeaderFileMissing, buildCurlArgv(arena, "https://api.github.com/x", null, .{ .headers = &headers }, &.{}));
}

test "header lines with CR, LF or NUL are refused" {
    try testing.expect(validHeaders(&.{}));
    try testing.expect(validHeaders(&.{"Authorization: Bearer x"}));
    try testing.expect(!validHeaders(&.{"Authorization: Bearer x\r"}));
    try testing.expect(!validHeaders(&.{"Authorization: Bearer x\nEvil: 1"}));
    try testing.expect(!validHeaders(&.{"X: a\r\nY: b"}));
    try testing.expect(!validHeaders(&.{"X: a\x00b"}));

    // A bad header creates no file at all.
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const dir_path = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(dir_path);
    try testing.expectError(Error.UnsafeHeader, writeHeaderFile(testing.allocator, dir_path, &.{"X: a\r\nY: b"}));
    var it = tmp.dir.iterate();
    var n: usize = 0;
    while (try it.next()) |_| n += 1;
    try testing.expectEqual(@as(usize, 0), n);
}

test "header file holds the headers and is private (mode 0600)" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const dir_path = try tmp.dir.realpathAlloc(arena, ".");

    const path = (try writeHeaderFile(arena, dir_path, &.{ "Authorization: Bearer secret", "Accept: application/json" })).?;
    const text = try tmp.dir.readFileAlloc(arena, std.fs.path.basename(path), 4096);
    try testing.expectEqualStrings("Authorization: Bearer secret\nAccept: application/json\n", text);

    if (!platform.is_windows) {
        const st = try std.fs.cwd().statFile(path);
        try testing.expectEqual(@as(std.fs.File.Mode, 0), st.mode & 0o077);
    }
    removeHeaderFile(path);
}

/// Stand-in for a curl run that fails.
fn failingCurl(header_file: ?[]const u8) Error!void {
    _ = header_file;
    return Error.DownloadFailed;
}

test "header file is removed after a failing curl call" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const dir_path = try tmp.dir.realpathAlloc(arena, ".");

    {
        // The same write-then-defer-remove shape as the callers use.
        const header_file = try writeHeaderFile(arena, dir_path, &.{"Authorization: Bearer secret"});
        defer removeHeaderFile(header_file);
        try testing.expectError(Error.DownloadFailed, failingCurl(header_file));
    }

    var it = tmp.dir.iterate();
    var left: usize = 0;
    while (try it.next()) |_| left += 1;
    try testing.expectEqual(@as(usize, 0), left);
}

test "download and fetchToString refuse a header with a line break before spawning anything" {
    const bad = [_][]const u8{"Authorization: x\r\nEvil: y"};
    try testing.expectError(Error.UnsafeHeader, download(testing.allocator, "https://x.test/y", "/nonexistent/x", .{ .headers = &bad }));
    try testing.expectError(Error.UnsafeHeader, fetchToString(testing.allocator, "https://x.test/y", 1024, .{ .headers = &bad }));
}
