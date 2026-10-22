//! A fast, streaming gzip/DEFLATE decoder.
//!
//! std.compress.gzip decodes one bit at a time through a generic reader and
//! copies every byte twice. Release tarballs are overwhelmingly `.tar.gz`, and
//! on those the decoder, not the disk, is the bottleneck. This one keeps a
//! 64-bit bit buffer refilled with a single unaligned load, resolves most codes
//! with one table lookup, and copies matches eight bytes at a time.
//!
//! The input is hostile. Every table index is masked or checked, a match never
//! reaches back past the start of the output, and the decoder refuses to read
//! past the end of its input: after a short stream it returns
//! `error.EndOfStream`, never garbage. The gzip CRC-32 and size are verified.

const std = @import("std");

pub const DecodeError = error{
    BadGzipHeader,
    InvalidBlockType,
    InvalidCode,
    InvalidDistance,
    BadStoredBlock,
    BadDynamicHeader,
    EndOfStream,
    WrongGzipChecksum,
    WrongGzipSize,
};

// Table entries are one u32: `len | kind << 8 | val << 16`.
//   len  bits to consume for this entry
//   kind 0..13  length/distance symbol; the number is the count of extra bits
//        k_lit  literal byte, or (in the code-length table) a symbol
//        k_eob  end of block
//        k_bad  a code no valid stream uses
//        k_sub | n  link to a subtable of 2^n entries starting at `val`
//   val  literal byte, base length/distance, or subtable offset
const k_lit: u32 = 0x40;
const k_eob: u32 = 0x41;
const k_bad: u32 = 0x43;
const k_sub: u32 = 0x50;

const lit_bits = 10;
const dist_bits = 8;
const clen_bits = 7;
const lit_table_len = 2048;
const dist_table_len = 1024;

inline fn entry(len: u32, kind: u32, val: u32) u32 {
    return len | (kind << 8) | (val << 16);
}

const len_base = [29]u16{
    3,  4,  5,  6,  7,  8,  9,  10,  11,  13,  15,  17,  19,  23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
};
const len_extra = [29]u8{
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
};
const dist_base = [30]u16{
    1,   2,   3,   4,   5,   7,    9,    13,   17,   25,   33,   49,   65,    97,    129,
    193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
};
const dist_extra = [30]u8{
    0, 0, 0, 0, 1, 1, 2, 2,  3,  3,  4,  4,  5,  5,  6,
    6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
};
const clen_order = [19]u8{ 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };

const TableKind = enum { litlen, dist, clen };

fn symbolEntry(comptime kind: TableKind, sym: usize, len: u32) u32 {
    switch (kind) {
        .litlen => {
            if (sym < 256) return entry(len, k_lit, @intCast(sym));
            if (sym == 256) return entry(len, k_eob, 0);
            if (sym <= 285) return entry(len, len_extra[sym - 257], len_base[sym - 257]);
            return entry(len, k_bad, 0);
        },
        .dist => {
            if (sym < 30) return entry(len, dist_extra[sym], dist_base[sym]);
            return entry(len, k_bad, 0);
        },
        .clen => return entry(len, k_lit, @intCast(sym)),
    }
}

/// Build a lookup table from code lengths. Rejects over-subscribed codes and
/// incomplete ones, except the two shapes zlib also accepts: no codes at all
/// (a distance tree for a block with no matches) and a single one-bit code.
fn buildTable(
    comptime kind: TableKind,
    lens: []const u8,
    tab: []u32,
    comptime primary: u5,
) DecodeError!void {
    var count = [_]u16{0} ** 16;
    var n_codes: usize = 0;
    for (lens) |l| {
        count[l] += 1;
        if (l != 0) n_codes += 1;
    }
    count[0] = 0;

    var left: i32 = 1;
    for (1..16) |l| {
        left <<= 1;
        left -= count[l];
        if (left < 0) return error.InvalidCode;
    }
    if (left > 0 and n_codes != 0 and !(n_codes == 1 and count[1] == 1)) return error.InvalidCode;

    const prim_len: usize = @as(usize, 1) << primary;
    const bad = entry(primary, k_bad, 0);
    @memset(tab[0..prim_len], bad);
    if (n_codes == 0) return;

    var next: [16]u32 = undefined;
    var code: u32 = 0;
    next[0] = 0;
    for (1..16) |l| {
        code = (code + count[l - 1]) << 1;
        next[l] = code;
    }

    // Pass 1: short codes fill the primary table; long ones only record how
    // deep their prefix's subtable must be.
    var sub_max = [_]u8{0} ** prim_len;
    var codes = next;
    for (lens, 0..) |l, sym| {
        if (l == 0) continue;
        const c = codes[l];
        codes[l] += 1;
        const rev: u32 = @as(u32, @bitReverse(@as(u16, @intCast(c)))) >> @intCast(16 - @as(u32, l));
        if (l <= primary) {
            var idx: usize = rev;
            const step: usize = @as(usize, 1) << @intCast(l);
            const e = symbolEntry(kind, sym, l);
            while (idx < prim_len) : (idx += step) tab[idx] = e;
        } else {
            const prefix = rev & @as(u32, @intCast(prim_len - 1));
            if (sub_max[prefix] < l) sub_max[prefix] = l;
        }
    }

    // Pass 2: lay out the subtables.
    var sub_off = [_]u16{0} ** prim_len;
    var cursor: usize = prim_len;
    for (0..prim_len) |p| {
        if (sub_max[p] == 0) continue;
        const bits: u32 = sub_max[p] - primary;
        const size = @as(usize, 1) << @intCast(bits);
        if (cursor + size > tab.len) return error.InvalidCode;
        tab[p] = entry(primary, k_sub | bits, @intCast(cursor));
        sub_off[p] = @intCast(cursor);
        @memset(tab[cursor..][0..size], entry(1, k_bad, 0));
        cursor += size;
    }

    // Pass 3: fill the subtables.
    codes = next;
    for (lens, 0..) |l, sym| {
        if (l == 0) continue;
        const c = codes[l];
        codes[l] += 1;
        if (l <= primary) continue;
        const rev: u32 = @as(u32, @bitReverse(@as(u16, @intCast(c)))) >> @intCast(16 - @as(u32, l));
        const prefix = rev & @as(u32, @intCast(prim_len - 1));
        const sub_bits: u32 = sub_max[prefix] - primary;
        const sub_len: u32 = l - primary;
        const base: usize = sub_off[prefix];
        var idx: usize = base + (rev >> primary);
        const step: usize = @as(usize, 1) << @intCast(sub_len);
        const e = symbolEntry(kind, sym, sub_len);
        while (idx < base + (@as(usize, 1) << @intCast(sub_bits))) : (idx += step) tab[idx] = e;
    }
}

/// CRC-32 (IEEE, as in gzip and zip), sixteen bytes per step. std's Crc32 runs at
/// roughly 400 MB/s here, which on a `.tar.gz` costs more than inflating it.
pub const Crc32 = struct {
    state: u32 = 0xFFFF_FFFF,

    const tables: [16][256]u32 = blk: {
        @setEvalBranchQuota(100_000);
        var t: [16][256]u32 = undefined;
        for (0..256) |i| {
            var c: u32 = @intCast(i);
            for (0..8) |_| c = if (c & 1 != 0) (c >> 1) ^ 0xEDB8_8320 else c >> 1;
            t[0][i] = c;
        }
        for (1..16) |k| {
            for (0..256) |i| t[k][i] = (t[k - 1][i] >> 8) ^ t[0][t[k - 1][i] & 0xFF];
        }
        break :blk t;
    };

    pub fn init() Crc32 {
        return .{};
    }

    pub fn update(self: *Crc32, data: []const u8) void {
        var crc = self.state;
        var p = data;
        if (@import("builtin").cpu.arch.endian() == .little) {
            const t = &tables;
            while (p.len >= 16) : (p = p[16..]) {
                const a = std.mem.readInt(u32, p[0..4], .little) ^ crc;
                const b = std.mem.readInt(u32, p[4..8], .little);
                const c = std.mem.readInt(u32, p[8..12], .little);
                const d = std.mem.readInt(u32, p[12..16], .little);
                crc = t[15][a & 0xFF] ^ t[14][(a >> 8) & 0xFF] ^ t[13][(a >> 16) & 0xFF] ^ t[12][a >> 24] ^
                    t[11][b & 0xFF] ^ t[10][(b >> 8) & 0xFF] ^ t[9][(b >> 16) & 0xFF] ^ t[8][b >> 24] ^
                    t[7][c & 0xFF] ^ t[6][(c >> 8) & 0xFF] ^ t[5][(c >> 16) & 0xFF] ^ t[4][c >> 24] ^
                    t[3][d & 0xFF] ^ t[2][(d >> 8) & 0xFF] ^ t[1][(d >> 16) & 0xFF] ^ t[0][d >> 24];
            }
        }
        for (p) |byte| crc = tables[0][(crc ^ byte) & 0xFF] ^ (crc >> 8);
        self.state = crc;
    }

    pub fn final(self: Crc32) u32 {
        return ~self.state;
    }

    pub fn hash(data: []const u8) u32 {
        var c = Crc32.init();
        c.update(data);
        return c.final();
    }
};

const State = enum { header, block_header, stored, huffman, trailer, done };

/// `gzip_framing` selects a gzip member (header, CRC-32 and size trailer, both
/// checked) or a bare DEFLATE stream, as zip stores it.
pub fn Inflater(comptime SrcReader: type, comptime gzip_framing: bool) type {
    return struct {
        const Self = @This();

        pub const ReadError = SrcReader.Error || DecodeError;
        pub const Reader = std.io.GenericReader(*Self, ReadError, read);

        allocator: std.mem.Allocator,
        src: SrcReader,

        inbuf: []u8,
        in_pos: usize = 0,
        in_end: usize = 0,
        src_eof: bool = false,

        /// Pending bits, least significant first. Bits above `bitcnt` are
        /// copies of the bytes that come next, which is why refilling with an
        /// OR is idempotent.
        bitbuf: u64 = 0,
        bitcnt: usize = 0,
        /// Zero bytes appended after the end of the input. Using any of them
        /// is an error.
        pad: usize = 0,

        /// Output window: `out[0..wr]` is history plus fresh output; the part
        /// not yet handed to the caller is `out[rd..wr]`.
        out: []u8,
        wr: usize = 0,
        rd: usize = 0,
        crc_pos: usize = 0,

        state: State = if (gzip_framing) .header else .block_header,
        final: bool = false,
        stored_left: usize = 0,

        crc: Crc32 = Crc32.init(),
        total: u32 = 0,

        lit_tab: [lit_table_len]u32 = undefined,
        dist_tab: [dist_table_len]u32 = undefined,

        const in_cap = 128 * 1024;
        pub const default_out_cap = 1024 * 1024;
        /// Room for the history, one run of symbols and a block header.
        pub const min_out_cap = history + 8192;
        const history = 32 * 1024;
        /// Longest match plus the eight-byte copy's overshoot.
        const symbol_room = 258 + 8;

        pub fn init(allocator: std.mem.Allocator, src: SrcReader) !Self {
            return initSized(allocator, src, default_out_cap);
        }

        /// `out_cap` bounds how much output is decoded ahead of the caller.
        pub fn initSized(allocator: std.mem.Allocator, src: SrcReader, out_cap: usize) !Self {
            const inbuf = try allocator.alloc(u8, in_cap);
            errdefer allocator.free(inbuf);
            const out = try allocator.alloc(u8, @max(out_cap, min_out_cap));
            return .{ .allocator = allocator, .src = src, .inbuf = inbuf, .out = out };
        }

        /// Start a new stream on `src`, keeping the buffers.
        pub fn reset(self: *Self, src: SrcReader) void {
            self.* = .{ .allocator = self.allocator, .src = src, .inbuf = self.inbuf, .out = self.out };
        }

        /// Input bytes pulled from the source but not used by the stream. After
        /// the end of a bare DEFLATE stream this should be zero.
        pub fn unreadBytes(self: *const Self) usize {
            return (self.in_end - self.in_pos) + (self.bitcnt / 8 - @min(self.pad, self.bitcnt / 8));
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.inbuf);
            self.allocator.free(self.out);
        }

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }

        /// The next run of decoded bytes without copying them, or null at the
        /// end of the stream. Valid until the next call.
        pub fn nextChunk(self: *Self) ReadError!?[]const u8 {
            while (true) {
                if (self.rd < self.wr) {
                    const chunk = self.out[self.rd..self.wr];
                    self.rd = self.wr;
                    return chunk;
                }
                if (self.state == .done) return null;
                try self.produce();
            }
        }

        pub fn read(self: *Self, dest: []u8) ReadError!usize {
            if (dest.len == 0) return 0;
            while (true) {
                if (self.rd < self.wr) {
                    const n = @min(dest.len, self.wr - self.rd);
                    @memcpy(dest[0..n], self.out[self.rd..][0..n]);
                    self.rd += n;
                    return n;
                }
                if (self.state == .done) return 0;
                try self.produce();
            }
        }

        // -------------------------------------------------------------------
        // Input
        // -------------------------------------------------------------------

        /// Move the unread input to the front and read more behind it.
        fn fillInput(self: *Self) ReadError!void {
            if (self.src_eof) return;
            const left = self.in_end - self.in_pos;
            if (self.in_pos > 0) {
                std.mem.copyForwards(u8, self.inbuf[0..left], self.inbuf[self.in_pos..self.in_end]);
                self.in_pos = 0;
                self.in_end = left;
            }
            const n = try self.src.read(self.inbuf[self.in_end..]);
            if (n == 0) self.src_eof = true else self.in_end += n;
        }

        /// Top the bit buffer up to at least 56 bits one byte at a time,
        /// padding with zeros after the end of the input.
        fn refillSlow(self: *Self) ReadError!void {
            while (self.bitcnt < 56) {
                if (self.in_pos == self.in_end) {
                    try self.fillInput();
                    if (self.in_pos == self.in_end) {
                        self.pad += 1;
                        self.bitcnt += 8;
                        continue;
                    }
                }
                self.bitbuf |= @as(u64, self.inbuf[self.in_pos]) << @intCast(self.bitcnt);
                self.in_pos += 1;
                self.bitcnt += 8;
            }
        }

        inline fn overrun(self: *const Self) bool {
            return self.bitcnt < self.pad * 8;
        }

        fn bits(self: *Self, n: u5) ReadError!u32 {
            if (self.bitcnt < 32) try self.refillSlow();
            const v: u32 = @intCast(self.bitbuf & ((@as(u64, 1) << n) - 1));
            self.bitbuf >>= n;
            self.bitcnt -= n;
            if (self.overrun()) return error.EndOfStream;
            return v;
        }

        /// One Huffman symbol through `tab`, for the rare header paths.
        fn symbol(self: *Self, tab: []const u32, comptime primary: u5) ReadError!u32 {
            if (self.bitcnt < 32) try self.refillSlow();
            var e = tab[@intCast(self.bitbuf & ((1 << primary) - 1))];
            if (((e >> 8) & 0xFF) >= k_sub) {
                const sb: u6 = @intCast((e >> 8) & 0xF);
                self.bitbuf >>= primary;
                self.bitcnt -= primary;
                e = tab[(e >> 16) + @as(usize, @intCast(self.bitbuf & ((@as(u64, 1) << sb) - 1)))];
            }
            const l: u6 = @intCast(e & 0xFF);
            self.bitbuf >>= l;
            self.bitcnt -= l;
            if (self.overrun()) return error.EndOfStream;
            return e;
        }

        // -------------------------------------------------------------------
        // Gzip framing
        // -------------------------------------------------------------------

        fn headerByte(self: *Self) ReadError!u8 {
            if (self.in_pos == self.in_end) {
                try self.fillInput();
                if (self.in_pos == self.in_end) return error.EndOfStream;
            }
            const b = self.inbuf[self.in_pos];
            self.in_pos += 1;
            return b;
        }

        fn skipHeaderBytes(self: *Self, n: usize) ReadError!void {
            for (0..n) |_| _ = try self.headerByte();
        }

        fn skipZeroTerminated(self: *Self) ReadError!void {
            while ((try self.headerByte()) != 0) {}
        }

        fn readHeader(self: *Self) ReadError!void {
            if ((try self.headerByte()) != 0x1f or (try self.headerByte()) != 0x8b) return error.BadGzipHeader;
            if ((try self.headerByte()) != 8) return error.BadGzipHeader;
            const flg = try self.headerByte();
            if (flg & 0xE0 != 0) return error.BadGzipHeader;
            try self.skipHeaderBytes(6); // mtime, xfl, os
            if (flg & 4 != 0) {
                const lo: usize = try self.headerByte();
                const hi: usize = try self.headerByte();
                try self.skipHeaderBytes(lo | (hi << 8));
            }
            if (flg & 8 != 0) try self.skipZeroTerminated();
            if (flg & 16 != 0) try self.skipZeroTerminated();
            if (flg & 2 != 0) try self.skipHeaderBytes(2);
        }

        fn readTrailer(self: *Self) ReadError!void {
            const drop = self.bitcnt & 7;
            self.bitbuf >>= @intCast(drop);
            self.bitcnt -= drop;
            const crc = try self.bits(16) | (try self.bits(16) << 16);
            const size = try self.bits(16) | (try self.bits(16) << 16);
            if (crc != self.crc.final()) return error.WrongGzipChecksum;
            if (size != self.total) return error.WrongGzipSize;
        }

        // -------------------------------------------------------------------
        // Blocks
        // -------------------------------------------------------------------

        fn blockHeader(self: *Self) ReadError!void {
            self.final = (try self.bits(1)) == 1;
            switch (try self.bits(2)) {
                0 => {
                    const drop = self.bitcnt & 7;
                    self.bitbuf >>= @intCast(drop);
                    self.bitcnt -= drop;
                    const len = try self.bits(16);
                    const nlen = try self.bits(16);
                    if (len != (~nlen & 0xFFFF)) return error.BadStoredBlock;
                    self.stored_left = len;
                    self.state = .stored;
                },
                1 => {
                    var lens: [288]u8 = undefined;
                    @memset(lens[0..144], 8);
                    @memset(lens[144..256], 9);
                    @memset(lens[256..280], 7);
                    @memset(lens[280..288], 8);
                    try buildTable(.litlen, &lens, &self.lit_tab, lit_bits);
                    const dl = [_]u8{5} ** 32;
                    try buildTable(.dist, &dl, &self.dist_tab, dist_bits);
                    self.state = .huffman;
                },
                2 => {
                    try self.dynamicTables();
                    self.state = .huffman;
                },
                else => return error.InvalidBlockType,
            }
        }

        fn dynamicTables(self: *Self) ReadError!void {
            const hlit = (try self.bits(5)) + 257;
            const hdist = (try self.bits(5)) + 1;
            const hclen = (try self.bits(4)) + 4;
            if (hlit > 286 or hdist > 30) return error.BadDynamicHeader;

            var cl = [_]u8{0} ** 19;
            for (0..hclen) |i| cl[clen_order[i]] = @intCast(try self.bits(3));
            var cl_tab: [1 << clen_bits]u32 = undefined;
            try buildTable(.clen, &cl, &cl_tab, clen_bits);

            var lens = [_]u8{0} ** (286 + 30);
            const total = hlit + hdist;
            var i: usize = 0;
            while (i < total) {
                const e = try self.symbol(&cl_tab, clen_bits);
                if (((e >> 8) & 0xFF) == k_bad) return error.BadDynamicHeader;
                const sym: u32 = e >> 16;
                if (sym < 16) {
                    lens[i] = @intCast(sym);
                    i += 1;
                    continue;
                }
                var rep: usize = undefined;
                var val: u8 = 0;
                switch (sym) {
                    16 => {
                        if (i == 0) return error.BadDynamicHeader;
                        val = lens[i - 1];
                        rep = 3 + try self.bits(2);
                    },
                    17 => rep = 3 + try self.bits(3),
                    else => rep = 11 + try self.bits(7),
                }
                if (i + rep > total) return error.BadDynamicHeader;
                @memset(lens[i..][0..rep], val);
                i += rep;
            }
            if (lens[256] == 0) return error.BadDynamicHeader;
            try buildTable(.litlen, lens[0..hlit], &self.lit_tab, lit_bits);
            try buildTable(.dist, lens[hlit..][0..hdist], &self.dist_tab, dist_bits);
        }

        /// Copy stored-block bytes. Returns when the block is done or the
        /// output window is full.
        fn storedRun(self: *Self) ReadError!void {
            // Whole bytes still sitting in the bit buffer come first.
            while (self.stored_left > 0 and self.wr < self.out.len and self.bitcnt - self.pad * 8 >= 8) {
                self.out[self.wr] = @truncate(self.bitbuf);
                self.wr += 1;
                self.bitbuf >>= 8;
                self.bitcnt -= 8;
                self.stored_left -= 1;
            }
            if (self.stored_left == 0) {
                self.state = if (self.final) .trailer else .block_header;
                return;
            }
            if (self.wr == self.out.len) return; // window full; resume later
            // Only padding is left in the bit buffer: the input ended inside
            // the block.
            if (self.pad != 0) return error.EndOfStream;
            self.bitbuf = 0; // the garbage above the count belonged to these bytes
            while (self.stored_left > 0 and self.wr < self.out.len) {
                if (self.in_pos == self.in_end) {
                    try self.fillInput();
                    if (self.in_pos == self.in_end) return error.EndOfStream;
                }
                const n = @min(@min(self.stored_left, self.out.len - self.wr), self.in_end - self.in_pos);
                @memcpy(self.out[self.wr..][0..n], self.inbuf[self.in_pos..][0..n]);
                self.wr += n;
                self.in_pos += n;
                self.stored_left -= n;
            }
            if (self.stored_left == 0) self.state = if (self.final) .trailer else .block_header;
        }

        /// Decode Huffman symbols until the block ends or the window is full.
        fn huffmanRun(self: *Self) ReadError!void {
            const out = self.out;
            var wr = self.wr;
            var bitbuf = self.bitbuf;
            var bitcnt = self.bitcnt;
            var in_pos = self.in_pos;
            const inbuf = self.inbuf;
            const in_end = self.in_end;
            const lit_tab = &self.lit_tab;
            const dist_tab = &self.dist_tab;
            const lmask: u64 = (1 << lit_bits) - 1;
            const dmask: u64 = (1 << dist_bits) - 1;

            // Fast path: 8 bytes of input and room for a longest match.
            while (in_end - in_pos >= 8 and wr + symbol_room <= out.len) {
                // One refill covers a whole length/distance pair: at most
                // 15 + 5 + 15 + 13 = 48 bits.
                bitbuf |= std.mem.readInt(u64, inbuf[in_pos..][0..8], .little) << @intCast(bitcnt);
                in_pos += (63 - bitcnt) >> 3;
                bitcnt |= 56;

                var e = lit_tab[@intCast(bitbuf & lmask)];
                var kind = (e >> 8) & 0xFF;
                if (kind >= k_sub) {
                    const sb: u6 = @intCast(kind & 0xF);
                    bitbuf >>= lit_bits;
                    bitcnt -= lit_bits;
                    e = lit_tab[(e >> 16) + @as(usize, @intCast(bitbuf & ((@as(u64, 1) << sb) - 1)))];
                    kind = (e >> 8) & 0xFF;
                }
                {
                    const l: u6 = @intCast(e & 0xFF);
                    bitbuf >>= l;
                    bitcnt -= l;
                }

                if (kind == k_lit) {
                    out[wr] = @intCast(e >> 16);
                    wr += 1;
                    // Two more literals often follow without another refill:
                    // at least 56 - 15 bits are left, enough for two codes.
                    var e2 = lit_tab[@intCast(bitbuf & lmask)];
                    if ((e2 >> 8) & 0xFF == k_lit) {
                        const l2: u6 = @intCast(e2 & 0xFF);
                        bitbuf >>= l2;
                        bitcnt -= l2;
                        out[wr] = @intCast(e2 >> 16);
                        wr += 1;
                        e2 = lit_tab[@intCast(bitbuf & lmask)];
                        if ((e2 >> 8) & 0xFF == k_lit) {
                            const l3: u6 = @intCast(e2 & 0xFF);
                            bitbuf >>= l3;
                            bitcnt -= l3;
                            out[wr] = @intCast(e2 >> 16);
                            wr += 1;
                        }
                    }
                    continue;
                }
                if (kind == k_eob) {
                    self.finishRun(wr, bitbuf, bitcnt, in_pos);
                    self.state = if (self.final) .trailer else .block_header;
                    return;
                }
                if (kind >= k_lit) return self.failRun(wr, bitbuf, bitcnt, in_pos);

                // A length.
                const lextra: u6 = @intCast(kind);
                const len: usize = (e >> 16) + @as(usize, @intCast(bitbuf & ((@as(u64, 1) << lextra) - 1)));
                bitbuf >>= lextra;
                bitcnt -= lextra;

                var d = dist_tab[@intCast(bitbuf & dmask)];
                var dkind = (d >> 8) & 0xFF;
                if (dkind >= k_sub) {
                    const sb: u6 = @intCast(dkind & 0xF);
                    bitbuf >>= dist_bits;
                    bitcnt -= dist_bits;
                    d = dist_tab[(d >> 16) + @as(usize, @intCast(bitbuf & ((@as(u64, 1) << sb) - 1)))];
                    dkind = (d >> 8) & 0xFF;
                }
                if (dkind >= k_lit) return self.failRun(wr, bitbuf, bitcnt, in_pos);
                {
                    const l: u6 = @intCast(d & 0xFF);
                    bitbuf >>= l;
                    bitcnt -= l;
                }
                const dextra: u6 = @intCast(dkind);
                const dist: usize = (d >> 16) + @as(usize, @intCast(bitbuf & ((@as(u64, 1) << dextra) - 1)));
                bitbuf >>= dextra;
                bitcnt -= dextra;

                if (dist > wr) {
                    self.finishRun(wr, bitbuf, bitcnt, in_pos);
                    return error.InvalidDistance;
                }
                copyMatch(out, wr, dist, len);
                wr += len;
            }

            self.finishRun(wr, bitbuf, bitcnt, in_pos);
            // Not enough input or output room for the fast path: one careful
            // symbol, which also refills the input.
            if (self.wr + symbol_room > out.len) return; // window full
            try self.slowSymbol();
        }

        fn finishRun(self: *Self, wr: usize, bitbuf: u64, bitcnt: usize, in_pos: usize) void {
            self.wr = wr;
            self.bitbuf = bitbuf;
            self.bitcnt = bitcnt;
            self.in_pos = in_pos;
        }

        fn failRun(self: *Self, wr: usize, bitbuf: u64, bitcnt: usize, in_pos: usize) ReadError {
            self.finishRun(wr, bitbuf, bitcnt, in_pos);
            return error.InvalidCode;
        }

        /// Decode a single symbol with no assumptions about how much input
        /// is left. Used near the ends of the input buffer and of the stream.
        fn slowSymbol(self: *Self) ReadError!void {
            if (self.in_end - self.in_pos < 64 and !self.src_eof) try self.fillInput();
            try self.refillSlow();
            const kind_of = struct {
                fn f(x: u32) u32 {
                    return (x >> 8) & 0xFF;
                }
            }.f;

            var e = try self.symbol(&self.lit_tab, lit_bits);
            const kind = kind_of(e);
            if (kind == k_lit) {
                self.out[self.wr] = @intCast(e >> 16);
                self.wr += 1;
                return;
            }
            if (kind == k_eob) {
                self.state = if (self.final) .trailer else .block_header;
                return;
            }
            if (kind >= k_lit) return error.InvalidCode;

            const len: usize = (e >> 16) + try self.bits(@intCast(kind));
            e = try self.symbol(&self.dist_tab, dist_bits);
            const dkind = kind_of(e);
            if (dkind >= k_lit) return error.InvalidCode;
            const dist: usize = (e >> 16) + try self.bits(@intCast(dkind));
            if (dist > self.wr) return error.InvalidDistance;
            copyMatch(self.out, self.wr, dist, len);
            self.wr += len;
        }

        // -------------------------------------------------------------------
        // Driver
        // -------------------------------------------------------------------

        /// Fold fresh output into the running CRC and size.
        fn account(self: *Self) void {
            if (!gzip_framing or self.wr <= self.crc_pos) return;
            self.crc.update(self.out[self.crc_pos..self.wr]);
            self.total +%= @intCast(self.wr - self.crc_pos);
            self.crc_pos = self.wr;
        }

        /// Decode until at least 64 KiB are ready, the window is full, or the
        /// stream ends.
        fn produce(self: *Self) ReadError!void {
            // Everything handed out; keep the last 32 KiB as history.
            if (self.out.len - self.wr < 4096) {
                const keep = @min(self.wr, history);
                std.mem.copyForwards(u8, self.out[0..keep], self.out[self.wr - keep .. self.wr]);
                self.wr = keep;
                self.rd = keep;
                self.crc_pos = keep;
            }
            const start = self.wr;
            defer self.account();
            while (self.wr - start < 64 * 1024 and self.out.len - self.wr >= 4096) {
                switch (self.state) {
                    .header => {
                        try self.readHeader();
                        self.state = .block_header;
                    },
                    .block_header => try self.blockHeader(),
                    .stored => try self.storedRun(),
                    .huffman => try self.huffmanRun(),
                    .trailer => {
                        if (gzip_framing) {
                            // The final bytes of output must be counted first.
                            self.account();
                            try self.readTrailer();
                        }
                        self.state = .done;
                        return;
                    },
                    .done => return,
                }
            }
        }
    };
}

/// Copy `len` bytes from `dist` back, eight at a time. The caller guarantees
/// `dist <= wr` and eight bytes of slack after `wr + len`.
inline fn copyMatch(out: []u8, wr: usize, dist: usize, len: usize) void {
    var s = wr - dist;
    var d = wr;
    const end = wr + len;
    if (dist >= 8) {
        while (d < end) {
            const chunk = std.mem.readInt(u64, out[s..][0..8], .little);
            std.mem.writeInt(u64, out[d..][0..8], chunk, .little);
            s += 8;
            d += 8;
        }
    } else if (dist == 1) {
        @memset(out[d..end], out[s]);
    } else {
        while (d < end) {
            out[d] = out[s];
            d += 1;
            s += 1;
        }
    }
}

pub fn Gzip(comptime SrcReader: type) type {
    return Inflater(SrcReader, true);
}

pub fn Raw(comptime SrcReader: type) type {
    return Inflater(SrcReader, false);
}

/// A gzip decoder over `src`. Call `deinit` when done.
pub fn gzip(allocator: std.mem.Allocator, src: anytype) !Gzip(@TypeOf(src)) {
    return Gzip(@TypeOf(src)).init(allocator, src);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn gzipBytes(allocator: std.mem.Allocator, data: []const u8, level: std.compress.flate.deflate.Level) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    var src = std.io.fixedBufferStream(data);
    try std.compress.gzip.compress(src.reader(), out.writer(), .{ .level = level });
    return out.toOwnedSlice();
}

fn inflateAll(allocator: std.mem.Allocator, comp: []const u8) ![]u8 {
    var fbs = std.io.fixedBufferStream(comp);
    var dec = try gzip(allocator, fbs.reader());
    defer dec.deinit();
    return dec.reader().readAllAlloc(allocator, 1 << 28);
}

fn testData(allocator: std.mem.Allocator, n: usize, seed: u64) ![]u8 {
    const data = try allocator.alloc(u8, n);
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    var i: usize = 0;
    while (i < n) {
        switch (rnd.uintLessThan(u8, 4)) {
            0 => { // random bytes
                const k = @min(n - i, rnd.uintLessThan(usize, 300));
                rnd.bytes(data[i..][0..k]);
                i += k;
            },
            1 => { // a run
                const k = @min(n - i, rnd.uintLessThan(usize, 600));
                @memset(data[i..][0..k], rnd.int(u8));
                i += k;
            },
            2 => { // text-like
                const k = @min(n - i, rnd.uintLessThan(usize, 400));
                for (data[i..][0..k]) |*b| b.* = "etaoin shrdlu\n"[rnd.uintLessThan(usize, 14)];
                i += k;
            },
            else => { // a copy of earlier data
                if (i < 10) continue;
                const dist = 1 + rnd.uintLessThan(usize, @min(i, 40000));
                const k = @min(n - i, 3 + rnd.uintLessThan(usize, 500));
                for (0..k) |j| data[i + j] = data[i + j - dist];
                i += k;
            },
        }
    }
    return data;
}

test "inflate matches the input at every compression level" {
    const a = testing.allocator;
    const sizes = [_]usize{ 0, 1, 7, 100, 4095, 70_000, 1_300_000 };
    for (sizes, 0..) |n, si| {
        const data = try testData(a, n, 1234 + si);
        defer a.free(data);
        inline for (.{ .fast, .default, .best }) |lvl| {
            const comp = try gzipBytes(a, data, lvl);
            defer a.free(comp);
            const got = inflateAll(a, comp) catch |e| {
                std.debug.print("size {d} level {s}: {s}\n", .{ n, @tagName(lvl), @errorName(e) });
                return e;
            };
            defer a.free(got);
            try testing.expectEqualSlices(u8, data, got);
        }
    }
}

test "inflate handles stored blocks and an input that arrives a byte at a time" {
    const a = testing.allocator;
    const data = try testData(a, 150_000, 99);
    defer a.free(data);

    // Hand-built stored blocks, including an empty one in the middle.
    var comp_list = std.ArrayList(u8).init(a);
    defer comp_list.deinit();
    try comp_list.appendSlice(&.{ 0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3 });
    var off: usize = 0;
    while (off < data.len) {
        const n = @min(data.len - off, 40_000);
        const last = off + n == data.len;
        try comp_list.append(if (last) 1 else 0);
        try comp_list.writer().writeInt(u16, @intCast(n), .little);
        try comp_list.writer().writeInt(u16, ~@as(u16, @intCast(n)), .little);
        try comp_list.appendSlice(data[off..][0..n]);
        off += n;
        if (!last and off == 80_000) {
            try comp_list.appendSlice(&.{ 0, 0, 0, 0xff, 0xff });
        }
    }
    try comp_list.writer().writeInt(u32, std.hash.Crc32.hash(data), .little);
    try comp_list.writer().writeInt(u32, @intCast(data.len), .little);
    const stored = try inflateAll(a, comp_list.items);
    defer a.free(stored);
    try testing.expectEqualSlices(u8, data, stored);

    const comp = try gzipBytes(a, data, .default);
    defer a.free(comp);
    const Trickle = struct {
        data: []const u8,
        pos: usize = 0,
        pub const Error = error{};
        fn read(self: *@This(), buf: []u8) Error!usize {
            if (self.pos >= self.data.len or buf.len == 0) return 0;
            buf[0] = self.data[self.pos];
            self.pos += 1;
            return 1;
        }
        fn reader(self: *@This()) std.io.GenericReader(*@This(), Error, read) {
            return .{ .context = self };
        }
    };
    var t: Trickle = .{ .data = comp };
    var dec = try gzip(a, t.reader());
    defer dec.deinit();
    const got = try dec.reader().readAllAlloc(a, 1 << 24);
    defer a.free(got);
    try testing.expectEqualSlices(u8, data, got);
}

test "inflate rejects truncated and corrupted streams without crashing" {
    const a = testing.allocator;
    const data = try testData(a, 60_000, 7);
    defer a.free(data);
    const comp = try gzipBytes(a, data, .default);
    defer a.free(comp);

    // Every truncation is an error, never a short success.
    var cut: usize = 0;
    while (cut < comp.len) : (cut += 1 + comp.len / 300) {
        try testing.expect(std.meta.isError(inflateAll(a, comp[0..cut])));
    }

    // Flipped bits either fail or (rarely) still decode; they must not crash,
    // and a success must be exact because the CRC is checked.
    var prng = std.Random.DefaultPrng.init(42);
    const rnd = prng.random();
    const bad = try a.dupe(u8, comp);
    defer a.free(bad);
    for (0..400) |_| {
        @memcpy(bad, comp);
        for (0..1 + rnd.uintLessThan(usize, 4)) |_| {
            bad[rnd.uintLessThan(usize, bad.len)] ^= @as(u8, 1) << @intCast(rnd.uintLessThan(u4, 8));
        }
        if (inflateAll(a, bad)) |got| {
            defer a.free(got);
            try testing.expectEqualSlices(u8, data, got);
        } else |_| {}
    }
}

test "inflate refuses a match that reaches before the start" {
    // Fixed-Huffman block: length code 257 (len 3) then distance code 0 (dist 1)
    // with nothing written yet.
    const a = testing.allocator;
    var raw = [_]u8{ 0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3, 0x03, 0x02, 0x00, 0, 0, 0, 0, 0, 0, 0, 0 };
    try testing.expect(std.meta.isError(inflateAll(a, &raw)));
}

test "Crc32 agrees with std at every length and alignment" {
    var buf: [300]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(5);
    prng.random().bytes(&buf);
    for (0..40) |off| {
        for ([_]usize{ 0, 1, 15, 16, 17, 31, 32, 33, 100, 255 }) |n| {
            const d = buf[off..][0..n];
            try testing.expectEqual(std.hash.Crc32.hash(d), Crc32.hash(d));
        }
    }
    // Incremental updates split anywhere give the same answer.
    var c = Crc32.init();
    c.update(buf[0..37]);
    c.update(buf[37..200]);
    c.update(buf[200..]);
    try testing.expectEqual(std.hash.Crc32.hash(&buf), c.final());
}
