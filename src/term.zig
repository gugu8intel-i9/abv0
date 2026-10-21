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

/// `--color=auto|always|never`. `--no-color` is an alias for `never`.
pub const ColorMode = enum { auto, always, never };

/// Set by main to `stdout is a TTY && !quiet`. When false, live download
/// lines are never drawn.
pub var progress_enabled: bool = false;

fn stdoutFile() std.fs.File {
    // Under `zig build test` stdout is the build runner's control channel, so
    // output from code under test goes to stderr instead of corrupting it.
    return if (builtin.is_test) std.io.getStdErr() else std.io.getStdOut();
}

pub fn stdoutIsTty() bool {
    return stdoutFile().isTty();
}

/// `always` forces colour on even when stdout is not a TTY; `auto` checks
/// NO_COLOR and the TTY state.
pub fn init(mode: ColorMode) void {
    const stdout_file = stdoutFile();
    buffered = .{ .unbuffered_writer = stdout_file.writer() };
    ready = true;

    const on = switch (mode) {
        .never => false,
        .always => true,
        .auto => colorSupported(stdout_file),
    };
    if (!on) return;

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
    if (!ready) init(.auto);
    mutex.lock();
    defer mutex.unlock();
    clearBlockLocked();
    buffered.writer().print(fmt, args) catch {};
}

pub fn writeAll(bytes: []const u8) void {
    if (!ready) init(.auto);
    mutex.lock();
    defer mutex.unlock();
    clearBlockLocked();
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
    clearProgress();
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
    if (!ready) init(.auto);
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

// ---------------------------------------------------------------------------
// Live download lines
//
// While a streaming install reads its body, each download shows one line that
// is redrawn in place. The block is cleared before any other output so
// `fetch`, `verify` and `link` lines print cleanly underneath.
// ---------------------------------------------------------------------------

/// Downloads drawn at once. One that finds no free slot is simply not shown.
pub const max_slots = 8;
/// Longest label shown, so a row stays within an 80-column terminal.
pub const max_label = 24;
const redraw_interval_ns = 100 * std.time.ns_per_ms;

/// Handle for one active download; null means nothing is drawn for it.
pub const Download = usize;

/// One visible row: everything the redraw needs and nothing more.
pub const Row = struct {
    label: []const u8,
    bytes: u64,
    rate_bps: u64,
};

const Slot = struct {
    label: [max_label]u8 = undefined,
    label_len: usize = 0,
    bytes: u64 = 0,
    started_ns: i128 = 0,
};

var slots: [max_slots]?Slot = [_]?Slot{null} ** max_slots;
/// Screen lines the live block occupies right now. Zero when none is drawn.
var block_lines: usize = 0;
var last_draw_ns: i128 = 0;

/// Register a download. Its label is taken from the URL's last path segment.
pub fn beginDownload(url: []const u8) ?Download {
    if (!progress_enabled) return null;
    const label = labelFromUrl(url);

    mutex.lock();
    defer mutex.unlock();
    for (&slots, 0..) |*slot, i| {
        if (slot.* != null) continue;
        var s = Slot{ .started_ns = std.time.nanoTimestamp(), .label_len = label.len };
        @memcpy(s.label[0..label.len], label);
        slot.* = s;
        redrawLocked(true);
        return i;
    }
    return null;
}

/// Count `n` more bytes for a download. Redraws at most every 100 ms.
pub fn addBytes(d: ?Download, n: u64) void {
    const i = d orelse return;
    mutex.lock();
    defer mutex.unlock();
    if (slots[i]) |*s| s.bytes += n;
    redrawLocked(false);
}

/// Remove a download's slot and redraw what remains (or clear the block).
pub fn endDownload(d: ?Download) void {
    const i = d orelse return;
    mutex.lock();
    defer mutex.unlock();
    slots[i] = null;
    redrawLocked(true);
}

/// Remove the live block from the screen, if one is drawn.
pub fn clearProgress() void {
    mutex.lock();
    defer mutex.unlock();
    clearBlockLocked();
}

/// Caller holds `mutex`. Pending buffered output is written first, so the
/// cursor movement below starts from where that output left it.
fn clearBlockLocked() void {
    if (block_lines == 0) return;
    buffered.flush() catch {};
    renderBlock(buffered.unbuffered_writer, block_lines, &.{}) catch {};
    block_lines = 0;
}

/// Caller holds `mutex`.
fn redrawLocked(force: bool) void {
    if (!progress_enabled) return;
    const now = std.time.nanoTimestamp();
    if (!force and now - last_draw_ns < redraw_interval_ns) return;
    last_draw_ns = now;

    var rows: [max_slots]Row = undefined;
    var n: usize = 0;
    for (0..max_slots) |k| {
        if (slots[k]) |*s| {
            const elapsed: u64 = @intCast(@max(now - s.started_ns, 0));
            rows[n] = .{
                .label = s.label[0..s.label_len],
                .bytes = s.bytes,
                .rate_bps = rateBps(s.bytes, elapsed),
            };
            n += 1;
        }
    }

    buffered.flush() catch {};
    // One write for the whole block, so a redraw never shows half of itself.
    var out: [4096]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&out);
    renderBlock(fbs.writer(), block_lines, rows[0..n]) catch return;
    buffered.unbuffered_writer.writeAll(fbs.getWritten()) catch {};
    block_lines = n;
}

/// Pure: the escape sequence that replaces `prev_lines` drawn lines with
/// `rows`. Moves up over the old block, clears each old line, moves back up,
/// then draws one line per row.
pub fn renderBlock(w: anytype, prev_lines: usize, rows: []const Row) !void {
    if (prev_lines > 0) {
        try w.print("\x1b[{d}A\r", .{prev_lines});
        for (0..prev_lines) |_| try w.writeAll("\x1b[2K\n");
        try w.print("\x1b[{d}A\r", .{prev_lines});
    }
    for (rows) |row| {
        var bytes_buf: [32]u8 = undefined;
        var rate_buf: [32]u8 = undefined;
        try w.print("\x1b[2K  \u{2193} {s:<24}  {s:>9}  {s}\n", .{
            row.label,
            formatBytes(&bytes_buf, row.bytes),
            formatRate(&rate_buf, row.rate_bps),
        });
    }
}

/// Pure: `n` as B, KiB, MiB or GiB with one decimal place above bytes.
pub fn formatBytes(buf: []u8, n: u64) []const u8 {
    if (n < 1024) return std.fmt.bufPrint(buf, "{d} B", .{n}) catch "?";
    const units = [_][]const u8{ "KiB", "MiB", "GiB" };
    var v: f64 = @floatFromInt(n);
    var unit: usize = 0;
    while (v >= 1024.0 and unit < units.len) : (unit += 1) v /= 1024.0;
    return std.fmt.bufPrint(buf, "{d:.1} {s}", .{ v, units[unit - 1] }) catch "?";
}

/// Pure: a byte rate such as `8.4 MiB/s`.
pub fn formatRate(buf: []u8, bps: u64) []const u8 {
    var tmp: [32]u8 = undefined;
    return std.fmt.bufPrint(buf, "{s}/s", .{formatBytes(&tmp, bps)}) catch "?";
}

/// Pure: average bytes per second. Zero elapsed time reads as zero.
pub fn rateBps(bytes: u64, elapsed_ns: u64) u64 {
    if (elapsed_ns == 0) return 0;
    const r = @as(u128, bytes) * std.time.ns_per_s / elapsed_ns;
    return @intCast(@min(r, std.math.maxInt(u64)));
}

/// Pure: the last path segment of `url` (no query or fragment), truncated to
/// `max_label` bytes. A URL with no segment reads as "download".
pub fn labelFromUrl(url: []const u8) []const u8 {
    const end = std.mem.indexOfAny(u8, url, "?#") orelse url.len;
    const path = url[0..end];
    const start = if (std.mem.lastIndexOfScalar(u8, path, '/')) |i| i + 1 else 0;
    const seg = path[start..];
    if (seg.len == 0) return "download";
    return seg[0..@min(seg.len, max_label)];
}

test "formatBytes prints B, KiB, MiB and GiB" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("0 B", formatBytes(&buf, 0));
    try std.testing.expectEqualStrings("512 B", formatBytes(&buf, 512));
    try std.testing.expectEqualStrings("1.0 KiB", formatBytes(&buf, 1024));
    try std.testing.expectEqualStrings("2.1 MiB", formatBytes(&buf, 2 * 1024 * 1024 + 104858));
    try std.testing.expectEqualStrings("3.0 GiB", formatBytes(&buf, 3 * 1024 * 1024 * 1024));
}

test "formatRate appends /s to a byte size" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("8.4 MiB/s", formatRate(&buf, 8808038));
    try std.testing.expectEqualStrings("0 B/s", formatRate(&buf, 0));
}

test "rateBps averages over elapsed time and guards zero" {
    try std.testing.expectEqual(@as(u64, 1000), rateBps(1000, std.time.ns_per_s));
    try std.testing.expectEqual(@as(u64, 2000), rateBps(1000, std.time.ns_per_s / 2));
    try std.testing.expectEqual(@as(u64, 0), rateBps(1000, 0));
}

test "labelFromUrl takes the last path segment and truncates it to 24 bytes" {
    try std.testing.expectEqualStrings("ripgrep.tar.gz", labelFromUrl("https://example.com/dl/ripgrep.tar.gz"));
    try std.testing.expectEqualStrings("jq", labelFromUrl("https://example.com/jq?token=abc#x"));
    try std.testing.expectEqualStrings("download", labelFromUrl("https://example.com/"));
    const long = labelFromUrl("https://example.com/a/this-name-is-much-longer-than-24.tar.gz");
    try std.testing.expectEqualStrings("this-name-is-much-longer", long);
    try std.testing.expectEqual(@as(usize, max_label), long.len);
}

test "renderBlock redraws two download slots in place" {
    var out: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&out);
    const rows = [_]Row{
        .{ .label = "ripgrep", .bytes = 2202010, .rate_bps = 8808038 },
        .{ .label = "node", .bytes = 512, .rate_bps = 1024 },
    };

    // First draw: nothing to clear.
    try renderBlock(fbs.writer(), 0, &rows);
    const first_line1 = "\x1b[2K  \u{2193} ripgrep" ++ (" " ** 21) ++ "2.1 MiB  8.4 MiB/s\n";
    const first_line2 = "\x1b[2K  \u{2193} node" ++ (" " ** 26) ++ "512 B  1.0 KiB/s\n";
    try std.testing.expectEqualStrings(first_line1 ++ first_line2, fbs.getWritten());

    // Redraw over the two lines just drawn: up 2, clear, back up 2, redraw.
    fbs.reset();
    try renderBlock(fbs.writer(), 2, &rows);
    const want = "\x1b[2A\r\x1b[2K\n\x1b[2K\n\x1b[2A\r" ++ first_line1 ++ first_line2;
    try std.testing.expectEqualStrings(want, fbs.getWritten());
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
