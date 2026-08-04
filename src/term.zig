//! Buffered, thread-safe, colour-aware terminal output.
//!
//! Replaces the previous `std.debug.print` usage, which had three problems:
//!   1. it is unbuffered, so every call was a separate write(2);
//!   2. it writes to stderr, so `abv0 list | grep foo` produced nothing;
//!   3. it emitted ANSI escapes unconditionally, even into a pipe or a file.

const std = @import("std");
const builtin = @import("builtin");

const BufferedWriter = std.io.BufferedWriter(32 * 1024, std.fs.File.Writer);

var buffered: BufferedWriter = undefined;
var mutex: std.Thread.Mutex = .{};
var ready: bool = false;

/// Colour escapes. Empty strings when colour is disabled, so format strings
/// stay identical either way.
pub var reset: []const u8 = "";
pub var bold: []const u8 = "";
pub var red: []const u8 = "";
pub var green: []const u8 = "";
pub var yellow: []const u8 = "";
pub var blue: []const u8 = "";
pub var magenta: []const u8 = "";
pub var cyan: []const u8 = "";
pub var dim: []const u8 = "";

/// `no_color` forces colour off regardless of TTY state (used by --no-color).
pub fn init(no_color: bool) void {
    const stdout_file = std.io.getStdOut();
    buffered = .{ .unbuffered_writer = stdout_file.writer() };
    ready = true;

    if (no_color or !colorSupported(stdout_file)) return;

    reset = "\x1b[0m";
    bold = "\x1b[1m";
    red = "\x1b[31m";
    green = "\x1b[32m";
    yellow = "\x1b[33m";
    blue = "\x1b[34m";
    magenta = "\x1b[35m";
    cyan = "\x1b[36m";
    dim = "\x1b[2m";
}

fn colorSupported(file: std.fs.File) bool {
    // https://no-color.org/
    if (std.process.hasEnvVarConstant("NO_COLOR")) return false;
    if (!file.isTty()) return false;

    if (builtin.os.tag == .windows) {
        // Only claim ANSI support if virtual terminal processing is on.
        return switch (std.io.tty.detectConfig(file)) {
            .escape_codes => true,
            else => false,
        };
    }
    return true;
}

pub fn print(comptime fmt: []const u8, args: anytype) void {
    if (!ready) init(false);
    mutex.lock();
    defer mutex.unlock();
    buffered.writer().print(fmt, args) catch {};
}

pub fn writeAll(bytes: []const u8) void {
    if (!ready) init(false);
    mutex.lock();
    defer mutex.unlock();
    buffered.writer().writeAll(bytes) catch {};
}

pub fn flush() void {
    if (!ready) return;
    mutex.lock();
    defer mutex.unlock();
    buffered.flush() catch {};
}

var reported = std.atomic.Value(bool).init(false);

/// Diagnostics belong on stderr so they survive `abv0 list > file`.
pub fn err(comptime fmt: []const u8, args: anytype) void {
    reported.store(true, .release);
    flush();
    std.io.getStdErr().writer().print(fmt, args) catch {};
}

/// True once any diagnostic has been written. Top-level handlers use this to
/// avoid printing a second, less informative copy of a failure.
pub fn anythingReported() bool {
    return reported.load(.acquire);
}

/// Direct access for callers that want to stream (e.g. JSON output).
pub fn writer() BufferedWriter.Writer {
    if (!ready) init(false);
    return buffered.writer();
}

pub const bar_len: usize = 20;

/// Pure rendering half of `progress`, split out so it can be unit tested
/// without writing to the process' real stdout. `filled` is clamped so a
/// caller passing filled > total can no longer walk off the end of `bar`.
pub fn renderBar(bar: *[bar_len]u8, filled: usize, total: usize) []const u8 {
    const denom = if (total == 0) 1 else total;
    const num = @min(filled, denom);

    var scaled = (num * bar_len) / denom;
    if (scaled > bar_len) scaled = bar_len;

    for (0..bar_len) |i| {
        bar[i] = if (i < scaled) '=' else if (i == scaled) '>' else ' ';
    }
    return bar[0..];
}

/// A determinate progress bar.
pub fn progress(msg: []const u8, filled: usize, total: usize) void {
    var bar: [bar_len]u8 = undefined;
    print("{s}[{s}]{s} {s}\n", .{ dim, renderBar(&bar, filled, total), reset, msg });
}

test "renderBar clamps out-of-range input instead of overflowing" {
    // Historically printProgressBar indexed a fixed buffer with
    // (filled * 20) / total, which panics once filled > total.
    var bar: [bar_len]u8 = undefined;

    try std.testing.expectEqualStrings("====================", renderBar(&bar, 50, 4));
    // total == 0 means "nothing to do", which reads as complete rather than
    // dividing by zero.
    try std.testing.expectEqualStrings("====================", renderBar(&bar, 1, 0));
    try std.testing.expectEqualStrings(">                   ", renderBar(&bar, 0, 0));
    try std.testing.expectEqualStrings("==========>         ", renderBar(&bar, 2, 4));
    try std.testing.expectEqualStrings(">                   ", renderBar(&bar, 0, 4));
    try std.testing.expectEqualStrings("====================", renderBar(&bar, 4, 4));
}

test "writes go to stdout, never stderr, and stay buffered until flush" {
    // Regression test for `abv0 list | grep ...` printing nothing: output used
    // to go to stderr. Redirect the global writer at a temp file rather than
    // the real stdout so the test never disturbs the process' own streams.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("out.txt", .{ .read = true });
    defer file.close();

    const saved_ready = ready;
    const saved_buffered = buffered;
    defer {
        buffered = saved_buffered;
        ready = saved_ready;
    }

    buffered = .{ .unbuffered_writer = file.writer() };
    ready = true;

    print("hello {d}\n", .{7});
    writeAll("world\n");

    // Still buffered: nothing has reached the file yet.
    try std.testing.expectEqual(@as(u64, 0), try file.getEndPos());

    flush();

    var buf: [64]u8 = undefined;
    const n = try file.preadAll(&buf, 0);
    try std.testing.expectEqualStrings("hello 7\nworld\n", buf[0..n]);
}
