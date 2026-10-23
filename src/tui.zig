//! `abv0 browse`: a full-screen package picker.
//!
//! Type to filter the catalog, move with the arrow keys, Space or Tab to pick
//! packages, Enter to install (the picked ones, or the highlighted one when
//! none are picked), Esc to quit. No library: the terminal is put in raw mode
//! (termios on POSIX, console modes on Windows) and drawn with ANSI escapes on
//! the alternate screen, which is always restored on the way out.
//!
//! Everything except the terminal itself is plain state and functions, so the
//! key parser, the filter and the renderer are tested without a terminal.

const std = @import("std");
const builtin = @import("builtin");
const registry = @import("registry.zig");

const is_windows = builtin.os.tag == .windows;

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

pub const Key = union(enum) {
    char: u8,
    up,
    down,
    page_up,
    page_down,
    home,
    end,
    enter,
    backspace,
    toggle,
    clear,
    quit,
    /// Bytes we do not act on (an unknown escape sequence, non-ASCII input).
    ignored,
};

pub const Parsed = struct { key: Key, used: usize };

/// Decode the first key in `b` (non-empty). A lone ESC is quit; an escape
/// sequence we do not know is swallowed whole.
pub fn parseKey(b: []const u8) Parsed {
    const c = b[0];
    switch (c) {
        '\r', '\n' => return .{ .key = .enter, .used = 1 },
        0x7f, 0x08 => return .{ .key = .backspace, .used = 1 },
        '\t', ' ' => return .{ .key = .toggle, .used = 1 },
        0x03, 0x04 => return .{ .key = .quit, .used = 1 }, // Ctrl-C, Ctrl-D
        0x15 => return .{ .key = .clear, .used = 1 }, // Ctrl-U
        0x0e => return .{ .key = .down, .used = 1 }, // Ctrl-N
        0x10 => return .{ .key = .up, .used = 1 }, // Ctrl-P
        0x1b => {},
        else => {
            if (c >= 0x21 and c < 0x7f) return .{ .key = .{ .char = c }, .used = 1 };
            return .{ .key = .ignored, .used = 1 };
        },
    }
    if (b.len == 1) return .{ .key = .quit, .used = 1 };
    if (b[1] != '[' and b[1] != 'O') return .{ .key = .quit, .used = 1 };
    // CSI / SS3: parameters, then one final byte in 0x40..0x7e.
    var i: usize = 2;
    while (i < b.len and (b[i] < 0x40 or b[i] > 0x7e)) i += 1;
    if (i >= b.len) return .{ .key = .ignored, .used = b.len };
    const params = b[2..i];
    const key: Key = switch (b[i]) {
        'A' => .up,
        'B' => .down,
        'H' => .home,
        'F' => .end,
        '~' => if (std.mem.eql(u8, params, "5"))
            .page_up
        else if (std.mem.eql(u8, params, "6"))
            .page_down
        else if (std.mem.eql(u8, params, "1") or std.mem.eql(u8, params, "7"))
            .home
        else if (std.mem.eql(u8, params, "4") or std.mem.eql(u8, params, "8"))
            .end
        else
            .ignored,
        else => .ignored,
    };
    return .{ .key = key, .used = i + 1 };
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

pub const Entry = struct {
    name: []const u8,
    version: []const u8,
    description: []const u8,
    installed: bool,
};

pub const Action = enum { none, quit, install };

pub const State = struct {
    entries: []const Entry,
    picked: []bool,
    matches: std.ArrayList(u32),
    query_buf: [64]u8 = undefined,
    query_len: usize = 0,
    cursor: usize = 0,
    top: usize = 0,
    picked_count: usize = 0,

    pub fn init(a: std.mem.Allocator, entries: []const Entry) !State {
        const picked = try a.alloc(bool, entries.len);
        @memset(picked, false);
        var s = State{ .entries = entries, .picked = picked, .matches = std.ArrayList(u32).init(a) };
        try s.refilter();
        return s;
    }

    pub fn deinit(self: *State, a: std.mem.Allocator) void {
        a.free(self.picked);
        self.matches.deinit();
    }

    pub fn query(self: *const State) []const u8 {
        return self.query_buf[0..self.query_len];
    }

    /// Names first (exact, then prefix, then anywhere), then descriptions;
    /// alphabetical within each group because `entries` is sorted by name.
    pub fn refilter(self: *State) !void {
        self.matches.clearRetainingCapacity();
        const q = self.query();
        var tier: u8 = 0;
        while (tier < 4) : (tier += 1) {
            for (self.entries, 0..) |e, i| {
                if (rank(e, q) == tier) try self.matches.append(@intCast(i));
            }
        }
        self.cursor = 0;
        self.top = 0;
    }

    fn rank(e: Entry, q: []const u8) u8 {
        if (q.len == 0) return 0;
        if (std.ascii.eqlIgnoreCase(e.name, q)) return 0;
        if (std.ascii.startsWithIgnoreCase(e.name, q)) return 1;
        if (std.ascii.indexOfIgnoreCase(e.name, q) != null) return 2;
        if (std.ascii.indexOfIgnoreCase(e.description, q) != null) return 3;
        return 255;
    }

    /// The entry under the cursor, if anything matches.
    pub fn current(self: *const State) ?u32 {
        if (self.matches.items.len == 0) return null;
        return self.matches.items[self.cursor];
    }

    pub fn handle(self: *State, key: Key, page: usize) !Action {
        const n = self.matches.items.len;
        switch (key) {
            .char => |c| if (self.query_len < self.query_buf.len) {
                self.query_buf[self.query_len] = c;
                self.query_len += 1;
                try self.refilter();
            },
            .backspace => if (self.query_len > 0) {
                self.query_len -= 1;
                try self.refilter();
            },
            .clear => if (self.query_len > 0) {
                self.query_len = 0;
                try self.refilter();
            },
            .up => self.cursor -|= 1,
            .down => if (n > 0) {
                self.cursor = @min(self.cursor + 1, n - 1);
            },
            .page_up => self.cursor -|= @max(page, 1),
            .page_down => if (n > 0) {
                self.cursor = @min(self.cursor + @max(page, 1), n - 1);
            },
            .home => self.cursor = 0,
            .end => self.cursor = n -| 1,
            .toggle => if (self.current()) |i| {
                self.picked[i] = !self.picked[i];
                if (self.picked[i]) self.picked_count += 1 else self.picked_count -= 1;
                if (n > 0) self.cursor = @min(self.cursor + 1, n - 1);
            },
            .enter => {
                if (self.picked_count > 0) return .install;
                if (self.current()) |i| {
                    self.picked[i] = true;
                    self.picked_count = 1;
                    return .install;
                }
            },
            .quit => return .quit,
            .ignored => {},
        }
        return .none;
    }

    /// Names of the picked entries, in catalog order. Owned by `a`.
    pub fn pickedNames(self: *const State, a: std.mem.Allocator) ![]const []const u8 {
        var out = std.ArrayList([]const u8).init(a);
        for (self.entries, 0..) |e, i| {
            if (self.picked[i]) try out.append(e.name);
        }
        return out.toOwnedSlice();
    }

    /// Keep the cursor inside the `rows` visible list lines.
    fn scroll(self: *State, rows: usize) void {
        if (rows == 0) return;
        if (self.cursor < self.top) self.top = self.cursor;
        if (self.cursor >= self.top + rows) self.top = self.cursor + 1 - rows;
    }
};

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

const header_lines = 3;
const footer_lines = 3;

pub const Style = struct {
    bold: []const u8 = "\x1b[1m",
    dim: []const u8 = "\x1b[2m",
    green: []const u8 = "\x1b[32m",
    cyan: []const u8 = "\x1b[36m",
    reverse: []const u8 = "\x1b[7m",
    reset: []const u8 = "\x1b[0m",
    check: []const u8 = if (is_windows) "*" else "\xe2\x9c\x93",

    pub const plain = Style{ .bold = "", .dim = "", .green = "", .cyan = "", .reverse = "\x1b[7m", .reset = "\x1b[0m" };
};

/// Write up to `cols` columns of `text`, one column per code point, with
/// control bytes shown as spaces: catalog text comes from upstream projects and
/// must not be able to move the cursor or recolour the screen. Returns the
/// columns written.
fn putClipped(w: anytype, text: []const u8, cols: usize) !usize {
    var used: usize = 0;
    var i: usize = 0;
    while (i < text.len and used < cols) {
        const c = text[i];
        if (c < 0x80) {
            try w.writeByte(if (c < 0x20 or c == 0x7f) ' ' else c);
            i += 1;
        } else {
            const n = std.unicode.utf8ByteSequenceLength(c) catch {
                try w.writeByte('?');
                i += 1;
                used += 1;
                continue;
            };
            if (i + n > text.len or !std.unicode.utf8ValidateSlice(text[i .. i + n])) {
                try w.writeByte('?');
                i += 1;
            } else {
                // C1 controls (U+0080..U+009F) act like escapes on some terminals.
                const cp = std.unicode.utf8Decode(text[i .. i + n]) catch 0;
                const cw = columnsOf(cp);
                if (used + cw > cols) break;
                if (cp >= 0x80 and cp < 0xa0) try w.writeByte(' ') else try w.writeAll(text[i .. i + n]);
                i += n;
                used += cw;
                continue;
            }
        }
        used += 1;
    }
    return used;
}

/// Screen columns of a code point: 2 for East Asian wide characters and most
/// emoji, 0 for combining marks, joiners and variation selectors, else 1.
/// An approximation of wcwidth that is right for catalog descriptions.
fn columnsOf(cp: u21) usize {
    if ((cp >= 0x0300 and cp <= 0x036f) or cp == 0x200d or (cp >= 0xfe00 and cp <= 0xfe0f)) return 0;
    const wide = [_][2]u21{
        .{ 0x1100, 0x115f },   .{ 0x2e80, 0x303e },   .{ 0x3041, 0x33ff },   .{ 0x3400, 0x4dbf },
        .{ 0x4e00, 0x9fff },   .{ 0xa000, 0xa4cf },   .{ 0xac00, 0xd7a3 },   .{ 0xf900, 0xfaff },
        .{ 0xfe30, 0xfe4f },   .{ 0xff00, 0xff60 },   .{ 0xffe0, 0xffe6 },   .{ 0x1f300, 0x1f64f },
        .{ 0x1f680, 0x1f6ff }, .{ 0x1f900, 0x1f9ff }, .{ 0x1fa70, 0x1faff }, .{ 0x20000, 0x3fffd },
        .{ 0x2600, 0x26ff },   .{ 0x2700, 0x27bf },
    };
    for (wide) |r| {
        if (cp >= r[0] and cp <= r[1]) return 2;
    }
    return 1;
}

fn pad(w: anytype, n: usize) !void {
    try w.writeByteNTimes(' ', n);
}

/// Draw one full frame: home the cursor, write every line and clear to the end
/// of each, so nothing from the previous frame remains.
pub fn render(w: anytype, s: *State, rows_in: usize, cols_in: usize, st: Style) !void {
    const rows = @max(rows_in, header_lines + footer_lines + 1);
    const cols = @max(cols_in, 20);
    const list_rows = rows - header_lines - footer_lines;
    s.scroll(list_rows);

    try w.writeAll("\x1b[H");
    // Header.
    try w.print("{s}abv0 browse{s}{s}  {d} of {d} packages, {d} picked{s}\x1b[K\r\n", .{
        st.bold, st.reset, st.dim, s.matches.items.len, s.entries.len, s.picked_count, st.reset,
    });
    try w.print("{s}Search:{s} ", .{ st.cyan, st.reset });
    _ = try putClipped(w, s.query(), cols -| 10);
    try w.writeAll("\x1b[7m \x1b[0m\x1b[K\r\n");
    try w.writeByteNTimes('-', cols);
    try w.writeAll("\r\n");

    // Column widths from what is on screen.
    var name_w: usize = 4;
    var ver_w: usize = 1;
    const end = @min(s.top + list_rows, s.matches.items.len);
    for (s.matches.items[s.top..end]) |i| {
        name_w = @max(name_w, @min(s.entries[i].name.len, 28));
        ver_w = @max(ver_w, @min(s.entries[i].version.len, 14));
    }

    var line: usize = 0;
    while (line < list_rows) : (line += 1) {
        const at = s.top + line;
        if (at >= s.matches.items.len) {
            if (s.matches.items.len == 0 and line == 0) {
                try w.print("  {s}no package matches \"", .{st.dim});
                _ = try putClipped(w, s.query(), cols -| 24);
                try w.print("\"{s}", .{st.reset});
            }
            try w.writeAll("\x1b[K\r\n");
            continue;
        }
        const i = s.matches.items[at];
        const e = s.entries[i];
        const here = at == s.cursor;
        if (here) try w.writeAll(st.reverse);
        var used: usize = 0;
        try w.writeAll(if (here) "> " else "  ");
        try w.writeAll(if (s.picked[i]) "[x] " else "[ ] ");
        used += 6;
        if (!here and s.picked[i]) try w.writeAll(st.bold);
        const nw = try putClipped(w, e.name, @min(name_w, cols -| used));
        if (!here and s.picked[i]) try w.writeAll(st.reset);
        try pad(w, name_w -| nw);
        used += name_w;
        if (used + 2 < cols) {
            try w.writeAll("  ");
            used += 2;
            if (!here) try w.writeAll(st.dim);
            const vw = try putClipped(w, e.version, @min(ver_w, cols -| used));
            if (!here) try w.writeAll(st.reset);
            try pad(w, ver_w -| vw);
            used += ver_w;
        }
        if (used + 4 < cols) {
            try w.writeAll(" ");
            if (e.installed) {
                if (!here) try w.writeAll(st.green);
                try w.writeAll(st.check);
                if (!here) try w.writeAll(st.reset);
            } else try w.writeAll(" ");
            try w.writeAll("  ");
            used += 4;
            used += try putClipped(w, e.description, cols -| used);
        }
        if (here) {
            try pad(w, cols -| used);
            try w.writeAll(st.reset);
        }
        try w.writeAll("\x1b[K\r\n");
    }

    // Footer: the highlighted package in full, then the keys.
    try w.writeByteNTimes('-', cols);
    try w.writeAll("\r\n");
    if (s.current()) |i| {
        const e = s.entries[i];
        try w.writeAll(st.bold);
        var used = try putClipped(w, e.name, cols);
        try w.writeAll(st.reset);
        if (e.installed and used + 12 < cols) {
            try w.print(" {s}(installed){s}", .{ st.green, st.reset });
            used += 12;
        }
        if (used + 3 < cols) {
            try w.writeAll(": ");
            _ = try putClipped(w, e.description, cols - used - 2);
        }
    }
    try w.writeAll("\x1b[K\r\n");
    try w.writeAll(st.dim);
    _ = try putClipped(w, "type to search  \xe2\x86\x91\xe2\x86\x93 move  space pick  enter install  esc quit", cols);
    try w.writeAll(st.reset);
    try w.writeAll("\x1b[K\x1b[J");
}

// ---------------------------------------------------------------------------
// Terminal
// ---------------------------------------------------------------------------

const Terminal = struct {
    in: std.fs.File,
    out: std.fs.File,
    saved: Saved,

    const Saved = if (is_windows) struct { in_mode: u32, out_mode: u32, out_cp: u32 } else std.posix.termios;

    fn enter() !Terminal {
        const in = std.io.getStdIn();
        const out = std.io.getStdOut();
        if (!in.isTty() or !out.isTty()) return error.NotATerminal;
        var t = Terminal{ .in = in, .out = out, .saved = undefined };
        if (is_windows) {
            const k32 = std.os.windows.kernel32;
            var in_mode: u32 = 0;
            var out_mode: u32 = 0;
            if (k32.GetConsoleMode(in.handle, &in_mode) == 0 or k32.GetConsoleMode(out.handle, &out_mode) == 0) return error.NotATerminal;
            t.saved = .{ .in_mode = in_mode, .out_mode = out_mode, .out_cp = k32.GetConsoleOutputCP() };
            // Line input, echo and Ctrl-C processing off; arrow keys as VT sequences.
            const ENABLE_PROCESSED_INPUT = 0x1;
            const ENABLE_LINE_INPUT = 0x2;
            const ENABLE_ECHO_INPUT = 0x4;
            const ENABLE_VIRTUAL_TERMINAL_INPUT = 0x200;
            const ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x4;
            _ = k32.SetConsoleMode(in.handle, (in_mode & ~@as(u32, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT)) | ENABLE_VIRTUAL_TERMINAL_INPUT);
            _ = k32.SetConsoleMode(out.handle, out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            _ = k32.SetConsoleOutputCP(65001);
        } else {
            const orig = try std.posix.tcgetattr(in.handle);
            var raw = orig;
            raw.lflag.ICANON = false;
            raw.lflag.ECHO = false;
            raw.lflag.ISIG = false;
            raw.lflag.IEXTEN = false;
            raw.iflag.IXON = false;
            raw.iflag.ICRNL = false;
            raw.cc[@intFromEnum(std.posix.V.MIN)] = 1;
            raw.cc[@intFromEnum(std.posix.V.TIME)] = 0;
            try std.posix.tcsetattr(in.handle, .FLUSH, raw);
            t.saved = orig;
        }
        // Alternate screen, hidden cursor.
        out.writeAll("\x1b[?1049h\x1b[?25l") catch {};
        return t;
    }

    fn leave(self: *Terminal) void {
        self.out.writeAll("\x1b[0m\x1b[?25h\x1b[?1049l") catch {};
        if (is_windows) {
            const k32 = std.os.windows.kernel32;
            _ = k32.SetConsoleMode(self.in.handle, self.saved.in_mode);
            _ = k32.SetConsoleMode(self.out.handle, self.saved.out_mode);
            _ = k32.SetConsoleOutputCP(self.saved.out_cp);
        } else {
            std.posix.tcsetattr(self.in.handle, .FLUSH, self.saved) catch {};
        }
    }

    const Size = struct { rows: usize, cols: usize };

    fn size(self: *Terminal) Size {
        if (is_windows) {
            var info: std.os.windows.CONSOLE_SCREEN_BUFFER_INFO = undefined;
            if (std.os.windows.kernel32.GetConsoleScreenBufferInfo(self.out.handle, &info) != 0) {
                const w: i32 = @as(i32, info.srWindow.Right) - info.srWindow.Left + 1;
                const h: i32 = @as(i32, info.srWindow.Bottom) - info.srWindow.Top + 1;
                if (w > 0 and h > 0) return .{ .rows = @intCast(h), .cols = @intCast(w) };
            }
        } else {
            var ws: std.posix.winsize = undefined;
            const rc = std.posix.system.ioctl(self.out.handle, std.posix.T.IOCGWINSZ, @intFromPtr(&ws));
            if (std.posix.errno(rc) == .SUCCESS and ws.ws_row > 0 and ws.ws_col > 0) {
                return .{ .rows = ws.ws_row, .cols = ws.ws_col };
            }
        }
        return .{ .rows = 24, .cols = 80 };
    }
};

/// Run the picker over `reg`'s packages that have a build for `platform_name`.
/// Returns the picked names (owned by `a`), or null when the user quits.
pub fn browse(
    a: std.mem.Allocator,
    reg: *const registry.Registry,
    platform_name: []const u8,
    isInstalled: anytype,
    color: bool,
) !?[]const []const u8 {
    var entries = std.ArrayList(Entry).init(a);
    defer entries.deinit();
    for (reg.packages) |p| {
        if (p.platform(platform_name) == null) continue;
        try entries.append(.{
            .name = p.name,
            .version = p.version,
            .description = p.description,
            .installed = isInstalled.check(p),
        });
    }

    var state = try State.init(a, entries.items);
    defer state.deinit(a);

    var term = try Terminal.enter();
    defer term.leave();
    const style: Style = if (color) .{} else Style.plain;

    var frame = std.ArrayList(u8).init(a);
    defer frame.deinit();
    var inbuf: [64]u8 = undefined;
    var pending: []const u8 = &.{};

    while (true) {
        const sz = term.size();
        frame.clearRetainingCapacity();
        try render(frame.writer(), &state, sz.rows, sz.cols, style);
        try term.out.writeAll(frame.items);

        if (pending.len == 0) {
            const n = try term.in.read(&inbuf);
            if (n == 0) return null;
            pending = inbuf[0..n];
        }
        const k = parseKey(pending);
        pending = pending[k.used..];
        const page = sz.rows -| (header_lines + footer_lines);
        switch (try state.handle(k.key, page)) {
            .none => {},
            .quit => return null,
            .install => return try state.pickedNames(a),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parseKey decodes the keys the picker uses" {
    try testing.expectEqual(Key.up, parseKey("\x1b[A").key);
    try testing.expectEqual(Key.down, parseKey("\x1bOB").key);
    try testing.expectEqual(Key.page_up, parseKey("\x1b[5~").key);
    try testing.expectEqual(Key.page_down, parseKey("\x1b[6~").key);
    try testing.expectEqual(Key.home, parseKey("\x1b[1~").key);
    try testing.expectEqual(Key.end, parseKey("\x1b[F").key);
    try testing.expectEqual(Key.quit, parseKey("\x1b").key);
    try testing.expectEqual(Key.quit, parseKey("\x03").key);
    try testing.expectEqual(Key.enter, parseKey("\r").key);
    try testing.expectEqual(Key.backspace, parseKey("\x7f").key);
    try testing.expectEqual(Key.toggle, parseKey(" ").key);
    try testing.expectEqual(Key.toggle, parseKey("\t").key);
    try testing.expectEqual(Key.clear, parseKey("\x15").key);
    try testing.expectEqual(@as(u8, 'r'), parseKey("rg").key.char);
    try testing.expectEqual(@as(usize, 1), parseKey("rg").used);
    // An unknown sequence is consumed whole, not typed into the search box.
    const p = parseKey("\x1b[1;5Cx");
    try testing.expectEqual(Key.ignored, p.key);
    try testing.expectEqual(@as(usize, 6), p.used);
    try testing.expectEqual(Key.ignored, parseKey("\xc3\xa9").key);
}

const sample = [_]Entry{
    .{ .name = "bat", .version = "0.25.0", .description = "cat with wings", .installed = false },
    .{ .name = "fd", .version = "10.2.0", .description = "find, but fast", .installed = true },
    .{ .name = "jq", .version = "1.8.2", .description = "JSON processor", .installed = false },
    .{ .name = "ripgrep", .version = "15.2.0", .description = "fast grep", .installed = false },
    .{ .name = "rip", .version = "1.0", .description = "removes files", .installed = false },
    .{ .name = "xrip", .version = "2.0", .description = "other", .installed = false },
};

fn typeText(s: *State, text: []const u8) !void {
    for (text) |c| _ = try s.handle(.{ .char = c }, 10);
}

test "filter ranks exact, prefix, substring, then description matches" {
    var s = try State.init(testing.allocator, &sample);
    defer s.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, sample.len), s.matches.items.len);

    try typeText(&s, "rip");
    const names = blk: {
        var out: [8][]const u8 = undefined;
        for (s.matches.items, 0..) |i, k| out[k] = sample[i].name;
        break :blk out[0..s.matches.items.len];
    };
    try testing.expectEqual(@as(usize, 3), names.len);
    try testing.expectEqualStrings("rip", names[0]);
    try testing.expectEqualStrings("ripgrep", names[1]);
    try testing.expectEqualStrings("xrip", names[2]);

    _ = try s.handle(.clear, 10);
    try typeText(&s, "GREP");
    try testing.expectEqual(@as(usize, 1), s.matches.items.len);
    try typeText(&s, "zz");
    try testing.expectEqual(@as(usize, 0), s.matches.items.len);
    try testing.expectEqual(@as(?u32, null), s.current());
    _ = try s.handle(.backspace, 10);
    _ = try s.handle(.backspace, 10);
    try testing.expectEqual(@as(usize, 1), s.matches.items.len);
}

test "space picks and moves on; enter installs the picks or the highlighted one" {
    var s = try State.init(testing.allocator, &sample);
    defer s.deinit(testing.allocator);

    // Nothing picked: Enter takes the highlighted package.
    _ = try s.handle(.down, 10);
    try testing.expectEqual(Action.install, try s.handle(.enter, 10));
    const one = try s.pickedNames(testing.allocator);
    defer testing.allocator.free(one);
    try testing.expectEqual(@as(usize, 1), one.len);
    try testing.expectEqualStrings("fd", one[0]);

    var t = try State.init(testing.allocator, &sample);
    defer t.deinit(testing.allocator);
    _ = try t.handle(.toggle, 10); // bat, cursor -> fd
    _ = try t.handle(.down, 10); // jq
    _ = try t.handle(.toggle, 10); // jq
    _ = try t.handle(.home, 10);
    _ = try t.handle(.toggle, 10); // bat again: unpicked
    try testing.expectEqual(@as(usize, 1), t.picked_count);
    try testing.expectEqual(Action.install, try t.handle(.enter, 10));
    const picked = try t.pickedNames(testing.allocator);
    defer testing.allocator.free(picked);
    try testing.expectEqual(@as(usize, 1), picked.len);
    try testing.expectEqualStrings("jq", picked[0]);

    try testing.expectEqual(Action.quit, try t.handle(.quit, 10));
}

test "cursor stays in range and the list scrolls to keep it visible" {
    var s = try State.init(testing.allocator, &sample);
    defer s.deinit(testing.allocator);
    _ = try s.handle(.up, 3);
    try testing.expectEqual(@as(usize, 0), s.cursor);
    _ = try s.handle(.page_down, 3);
    try testing.expectEqual(@as(usize, 3), s.cursor);
    _ = try s.handle(.end, 3);
    try testing.expectEqual(@as(usize, sample.len - 1), s.cursor);
    _ = try s.handle(.down, 3);
    try testing.expectEqual(@as(usize, sample.len - 1), s.cursor);
    s.scroll(3);
    try testing.expectEqual(@as(usize, sample.len - 3), s.top);
    _ = try s.handle(.page_up, 3);
    s.scroll(3);
    try testing.expect(s.cursor >= s.top and s.cursor < s.top + 3);
}

test "render fits the width and never passes control bytes from catalog text" {
    const hostile = [_]Entry{
        .{ .name = "evil", .version = "1\x1b[2J", .description = "line\x1b]0;title\x07 \xc2\x9b31m", .installed = true },
        .{ .name = "wide", .version = "1", .description = "caf\xc3\xa9 " ++ "x" ** 300, .installed = false },
    };
    var s = try State.init(testing.allocator, &hostile);
    defer s.deinit(testing.allocator);
    var out = std.ArrayList(u8).init(testing.allocator);
    defer out.deinit();
    try render(out.writer(), &s, 12, 60, Style.plain);

    // Every escape in the frame is one of ours: CSI followed by our own codes.
    var i: usize = 0;
    while (std.mem.indexOfScalarPos(u8, out.items, i, 0x1b)) |at| {
        try testing.expect(at + 1 < out.items.len and out.items[at + 1] == '[');
        const rest = out.items[at + 2 ..];
        const ok = std.mem.startsWith(u8, rest, "H") or std.mem.startsWith(u8, rest, "K") or
            std.mem.startsWith(u8, rest, "J") or std.mem.startsWith(u8, rest, "0m") or
            std.mem.startsWith(u8, rest, "7m");
        try testing.expect(ok);
        i = at + 1;
    }
    try testing.expect(std.mem.indexOfScalar(u8, out.items, 0x07) == null);
    try testing.expect(std.mem.indexOf(u8, out.items, "\xc2\x9b") == null);

    // No line is wider than the screen (ASCII text here, so bytes = columns
    // once our escapes are removed).
    var lines = std.mem.splitSequence(u8, out.items, "\r\n");
    while (lines.next()) |l| {
        var cols: usize = 0;
        var k: usize = 0;
        while (k < l.len) {
            if (l[k] == 0x1b) {
                k += 2;
                while (k < l.len and (l[k] < 0x40 or l[k] > 0x7e)) k += 1;
                k += 1;
                continue;
            }
            if (l[k] & 0xc0 != 0x80) cols += 1;
            k += 1;
        }
        try testing.expect(cols <= 60);
    }
}

test "wide characters count as two columns and are not split at the edge" {
    var out = std.ArrayList(u8).init(testing.allocator);
    defer out.deinit();
    // "ab" + rocket (2 columns) + "c": 5 columns in all.
    try testing.expectEqual(@as(usize, 5), try putClipped(out.writer(), "ab\xf0\x9f\x9a\x80c", 10));
    out.clearRetainingCapacity();
    // Only 3 columns: the rocket would overflow, so it stops after "ab".
    try testing.expectEqual(@as(usize, 2), try putClipped(out.writer(), "ab\xf0\x9f\x9a\x80c", 3));
    try testing.expectEqualStrings("ab", out.items);
}

test "render shows the search, counts and an empty-result line" {
    var s = try State.init(testing.allocator, &sample);
    defer s.deinit(testing.allocator);
    try typeText(&s, "nothing-here");
    var out = std.ArrayList(u8).init(testing.allocator);
    defer out.deinit();
    try render(out.writer(), &s, 10, 80, Style.plain);
    try testing.expect(std.mem.indexOf(u8, out.items, "nothing-here") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "0 of 6 packages") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "no package matches") != null);
}
