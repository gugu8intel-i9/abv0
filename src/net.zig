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

    const host_start = "https://".len;
    if (host_start >= url.len) return false;
    if (url[host_start] == '/' or url[host_start] == '@') return false;
    return true;
}

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

fn curlArgs(
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

    try args.appendSlice(&.{
        "curl",
        "--fail", // non-zero exit on HTTP >= 400
        "--silent",
        "--show-error",
        "--location", // follow redirects...
        "--max-redirs", "5",
        "--proto",       "=https", // ...but only ever over https
        "--proto-redir", "=https",
        "--connect-timeout", connect,
        "--max-time",        maxtime,
        "--retry",           retries,
        "--user-agent",      opts.user_agent,
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

    const argv = try curlArgs(arena, url, dest_path, opts, &.{});

    const res = std.process.Child.run(.{
        .allocator = arena,
        .argv = argv,
        .max_output_bytes = 64 * 1024,
    }) catch |e| switch (e) {
        error.FileNotFound => return downloadFallback(arena, url, dest_path),
        else => return Error.DownloadFailed,
    };

    if (res.term != .Exited or res.term.Exited != 0) {
        std.fs.cwd().deleteFile(dest_path) catch {};
        return Error.DownloadFailed;
    }
}

/// Windows ships curl.exe since Windows 10 1803, but fall back to PowerShell
/// if it is missing.
fn downloadFallback(allocator: std.mem.Allocator, url: []const u8, dest_path: []const u8) !void {
    if (!platform.is_windows) return Error.NoDownloaderAvailable;

    const script = try std.fmt.allocPrint(
        allocator,
        "$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -UseBasicParsing -Uri $env:ABV0_URL -OutFile $env:ABV0_DEST",
        .{},
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

    const argv = try curlArgs(arena, url, null, opts, &.{});

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

    const argv = try curlArgs(arena, url, null, opts, &.{ "--head", "--request", "GET" });
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
        const argv = curlArgs(arena, self.url, self.dest, self.opts, &.{ "--range", range }) catch return;

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

test "download refuses an unsafe url before spawning anything" {
    try testing.expectError(Error.UnsafeUrl, download(testing.allocator, "file:///etc/passwd", "/tmp/x", .{}));
    try testing.expectError(Error.UnsafeUrl, download(testing.allocator, "http://x.test/y", "/tmp/x", .{}));
}
