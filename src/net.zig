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

const std = @import("std");
const builtin = @import("builtin");
const platform = @import("platform.zig");

pub const Options = struct {
    connect_timeout_s: u32 = 20,
    max_time_s: u32 = 600,
    retries: u32 = 2,
    user_agent: []const u8 = "abv0",
};

pub const Error = error{
    UnsafeUrl,
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
    if (dest) |d| try args.appendSlice(&.{ "--output", d });
    try args.append(url);
    return args.toOwnedSlice();
}

/// Download `url` to `dest_path`. Returns an error on any HTTP failure.
pub fn download(
    allocator: std.mem.Allocator,
    url: []const u8,
    dest_path: []const u8,
    opts: Options,
) !void {
    if (!isSafeUrl(url)) return Error.UnsafeUrl;

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const argv = try buildCurlArgv(arena, url, dest_path, opts, &.{});

    const res = std.process.Child.run(.{
        .allocator = arena,
        .argv = argv,
        .max_output_bytes = 64 * 1024,
    }) catch |e| switch (e) {
        error.FileNotFound => return downloadFallback(arena, url, dest_path, opts),
        else => return Error.DownloadFailed,
    };

    if (res.term != .Exited or res.term.Exited != 0) {
        std.fs.cwd().deleteFile(dest_path) catch {};
        return Error.DownloadFailed;
    }
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

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const argv = try buildCurlArgv(arena, url, null, opts, &.{});

    const res = std.process.Child.run(.{
        .allocator = arena,
        .argv = argv,
        .max_output_bytes = max_bytes,
    }) catch return Error.DownloadFailed;

    if (res.term != .Exited or res.term.Exited != 0) return Error.DownloadFailed;
    return allocator.dupe(u8, res.stdout);
}

/// Remote size via a HEAD request, plus whether ranges are supported.
pub const RemoteInfo = struct {
    content_length: ?u64 = null,
    accepts_ranges: bool = false,
};

pub fn head(allocator: std.mem.Allocator, url: []const u8, opts: Options) !RemoteInfo {
    if (!isSafeUrl(url)) return Error.UnsafeUrl;

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const argv = try buildCurlArgv(arena, url, null, opts, &.{ "--head", "--request", "GET" });
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
        const argv = buildCurlArgv(arena, self.url, self.dest, self.opts, &.{ "--range", range }) catch return;

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
