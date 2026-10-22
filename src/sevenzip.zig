//! In-process, sandboxed 7z extraction.
//!
//! Many Windows packages ship as `.7z`: nodejs, git's PortableGit,
//! firefox. Like `archive.zig`, this treats the archive as hostile input.
//!
//! * Every number read from the archive is bounds-checked and every size is
//!   u64 math. Allocations are bounded by the header size, by `max_members`,
//!   or by the amount of data the archive actually has to produce.
//! * Both the signature header, the (possibly LZMA-compressed) header and every
//!   file carry a CRC32. A mismatch is an error, never a warning.
//! * Every member name is converted from UTF-16, `\` becomes `/`, and the result
//!   must pass `safepath.isSafeRelPath` and contain no ':'. One bad name refuses
//!   the whole archive, before anything is written.
//! * Links (Windows reparse points, unix symlinks) are not extracted.
//! * Limits (`max_bytes`, `max_members`) are checked from the header, before any
//!   data is decoded.
//!
//! Supported coders: Copy, LZMA, LZMA2 and the x86 BCJ filter in front of
//! either. PPMd, BZip2, Deflate, BCJ2, Delta, other branch filters and AES
//! encryption are refused with `error.Unsupported7zMethod`.
//!
//! The LZMA decoder here is not `std.compress.lzma`. That one is a pull reader
//! that needs one growing buffer for LZMA2 and decodes through a generic
//! per-byte reader. This one decodes straight from a buffered file into a
//! fixed-size sliding window, so memory is bounded by the dictionary (itself
//! capped by the folder's size) no matter how large the archive is.
//!
//! 7z locates its streams by offset, so the archive must be a seekable file.
//! Each folder (a solid block) is decoded exactly once, in order, and its
//! substreams are written to their files as the bytes come out.

const std = @import("std");
const safepath = @import("safepath.zig");
const platform = @import("platform.zig");
const archive = @import("archive.zig");

const Allocator = std.mem.Allocator;
const Crc32 = std.hash.Crc32;

/// The first six bytes of every 7z archive.
pub const magic = [6]u8{ '7', 'z', 0xBC, 0xAF, 0x27, 0x1C };

const sig_header_len = 32;

/// The header (plain or decoded) is read into memory. Real archives with a few
/// hundred thousand files stay far below this.
const max_header_bytes: u64 = 128 * 1024 * 1024;

/// Largest LZMA dictionary window that is allocated. The window is also capped
/// by the folder's unpacked size, so this only bites on huge folders.
const max_dict_bytes: u64 = 512 * 1024 * 1024;

/// How many nested EncodedHeaders are followed. 7-Zip writes one.
const max_header_depth = 4;

const io_buf_len = 64 * 1024;

// Property ids.
const k_end = 0x00;
const k_header = 0x01;
const k_archive_properties = 0x02;
const k_additional_streams_info = 0x03;
const k_main_streams_info = 0x04;
const k_files_info = 0x05;
const k_pack_info = 0x06;
const k_unpack_info = 0x07;
const k_substreams_info = 0x08;
const k_size = 0x09;
const k_crc = 0x0A;
const k_folder = 0x0B;
const k_coders_unpack_size = 0x0C;
const k_num_unpack_stream = 0x0D;
const k_empty_stream = 0x0E;
const k_empty_file = 0x0F;
const k_anti = 0x10;
const k_names = 0x11;
const k_win_attributes = 0x15;
const k_encoded_header = 0x17;

// Windows attribute bits. 7-Zip stores the unix mode in the high 16 bits when
// the 0x8000 extension bit is set.
const attr_directory = 0x10;
const attr_reparse_point = 0x400;
const attr_unix_extension = 0x8000;

const s_ifmt = 0o170000;
const s_ifreg = 0o100000;
const s_ifdir = 0o040000;
const s_iflnk = 0o120000;

// Method ids.
const id_copy = 0x00;
const id_lzma2 = 0x21;
const id_bcj_x86_new = 0x04;
const id_lzma = 0x030101;
const id_bcj_x86 = 0x03030103;

// ---------------------------------------------------------------------------
// Header reader
// ---------------------------------------------------------------------------

/// A bounds-checked cursor over header bytes. Every read that would run past
/// the end is `error.Corrupt7z`.
const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn remaining(self: Reader) usize {
        return self.buf.len - self.pos;
    }

    fn byte(self: *Reader) !u8 {
        if (self.pos >= self.buf.len) return error.Corrupt7z;
        const b = self.buf[self.pos];
        self.pos += 1;
        return b;
    }

    fn bytes(self: *Reader, n: u64) ![]const u8 {
        if (n > self.remaining()) return error.Corrupt7z;
        const len: usize = @intCast(n);
        const s = self.buf[self.pos..][0..len];
        self.pos += len;
        return s;
    }

    fn u16le(self: *Reader) !u16 {
        const b = try self.bytes(2);
        return std.mem.readInt(u16, b[0..2], .little);
    }

    fn u32le(self: *Reader) !u32 {
        const b = try self.bytes(4);
        return std.mem.readInt(u32, b[0..4], .little);
    }

    /// 7z's variable-length NUMBER: the count of leading 1 bits in the first
    /// byte is the count of extra little-endian bytes that follow.
    fn number(self: *Reader) !u64 {
        const first = try self.byte();
        var mask: u8 = 0x80;
        var value: u64 = 0;
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            if (first & mask == 0) {
                const high: u64 = first & (mask - 1);
                return value | (high << @intCast(8 * i));
            }
            value |= @as(u64, try self.byte()) << @intCast(8 * i);
            mask >>= 1;
        }
        return value;
    }

    /// A NUMBER used as a count of things that each need at least one byte of
    /// header, so it cannot exceed `limit`. This keeps allocations proportional
    /// to the input.
    fn count(self: *Reader, limit: u64) !usize {
        const n = try self.number();
        if (n > limit) return error.Corrupt7z;
        return @intCast(n);
    }

    /// `n` bits, most significant bit first.
    fn bitVector(self: *Reader, a: Allocator, n: usize) ![]bool {
        const raw = try self.bytes((n + 7) / 8);
        const out = try a.alloc(bool, n);
        for (out, 0..) |*o, i| o.* = (raw[i / 8] >> @intCast(7 - (i % 8))) & 1 != 0;
        return out;
    }

    /// An "all defined" byte, followed by a bit vector when it is zero.
    fn definedVector(self: *Reader, a: Allocator, n: usize) ![]bool {
        if ((try self.byte()) != 0) {
            const out = try a.alloc(bool, n);
            @memset(out, true);
            return out;
        }
        return self.bitVector(a, n);
    }

    fn digests(self: *Reader, a: Allocator, n: usize) ![]?u32 {
        const defined = try self.definedVector(a, n);
        const out = try a.alloc(?u32, n);
        for (out, defined) |*o, d| o.* = if (d) try self.u32le() else null;
        return out;
    }

    /// Property data that is preceded by its own size.
    fn skipData(self: *Reader) !void {
        const size = try self.number();
        _ = try self.bytes(size);
    }
};

// ---------------------------------------------------------------------------
// Header model
// ---------------------------------------------------------------------------

const Coder = struct {
    id: u64,
    props: []const u8,
    num_in: u32,
    num_out: u32,
};

const BindPair = struct { in_index: u32, out_index: u32 };

const Folder = struct {
    coders: []Coder = &.{},
    bind_pairs: []BindPair = &.{},
    /// In-stream indexes that are read from pack streams.
    packed_streams: []u32 = &.{},
    /// One per out stream.
    unpack_sizes: []u64 = &.{},
    /// The size of the stream no bind pair consumes: what the folder produces.
    unpack_size: u64 = 0,
    crc: ?u32 = null,
    /// Index of this folder's first pack stream.
    first_pack: usize = 0,
    num_substreams: usize = 1,
    /// Index of this folder's first substream, over all folders.
    first_substream: usize = 0,
};

const StreamsInfo = struct {
    pack_pos: u64 = 0,
    pack_sizes: []u64 = &.{},
    folders: []Folder = &.{},
    sub_sizes: []u64 = &.{},
    sub_crcs: []?u32 = &.{},
};

const FilesInfo = struct {
    names: [][]const u8 = &.{},
    empty_stream: []bool = &.{},
    empty_file: []bool = &.{},
    anti: []bool = &.{},
    attrib: []?u32 = &.{},
};

const Limits = struct {
    max_members: usize,
};

fn parsePackInfo(r: *Reader, a: Allocator, si: *StreamsInfo) !void {
    si.pack_pos = try r.number();
    const n = try r.count(r.remaining());
    var sizes: ?[]u64 = null;
    while (true) {
        const id = try r.byte();
        switch (id) {
            k_end => break,
            k_size => {
                const out = try a.alloc(u64, n);
                for (out) |*s| s.* = try r.number();
                sizes = out;
            },
            k_crc => _ = try r.digests(a, n),
            else => try r.skipData(),
        }
    }
    si.pack_sizes = sizes orelse if (n == 0) &.{} else return error.Corrupt7z;
}

fn parseFolder(r: *Reader, a: Allocator) !Folder {
    const num_coders = try r.count(32);
    if (num_coders == 0) return error.Corrupt7z;
    const coders = try a.alloc(Coder, num_coders);
    var total_in: u32 = 0;
    var total_out: u32 = 0;
    for (coders) |*c| {
        const flags = try r.byte();
        // Bit 7 marks "alternative methods", which no current 7-Zip writes.
        if (flags & 0x80 != 0) return error.Unsupported7zMethod;
        const id_size = flags & 0x0F;
        if (id_size > 8) return error.Unsupported7zMethod;
        var id: u64 = 0;
        for (try r.bytes(id_size)) |b| id = (id << 8) | b;
        var num_in: u64 = 1;
        var num_out: u64 = 1;
        if (flags & 0x10 != 0) {
            num_in = try r.number();
            num_out = try r.number();
            if (num_in > 32 or num_out > 32) return error.Corrupt7z;
        }
        var props: []const u8 = &.{};
        if (flags & 0x20 != 0) {
            const size = try r.number();
            props = try r.bytes(size);
        }
        c.* = .{ .id = id, .props = props, .num_in = @intCast(num_in), .num_out = @intCast(num_out) };
        total_in += c.num_in;
        total_out += c.num_out;
    }
    if (total_out == 0) return error.Corrupt7z;

    const num_bind = total_out - 1;
    if (total_in < num_bind) return error.Corrupt7z;
    const bind_pairs = try a.alloc(BindPair, num_bind);
    for (bind_pairs) |*bp| {
        const in_index = try r.number();
        const out_index = try r.number();
        if (in_index >= total_in or out_index >= total_out) return error.Corrupt7z;
        bp.* = .{ .in_index = @intCast(in_index), .out_index = @intCast(out_index) };
    }

    const num_packed = total_in - num_bind;
    const packed_streams = try a.alloc(u32, num_packed);
    if (num_packed == 1) {
        var found = false;
        var i: u32 = 0;
        while (i < total_in) : (i += 1) {
            var bound = false;
            for (bind_pairs) |bp| {
                if (bp.in_index == i) bound = true;
            }
            if (!bound) {
                packed_streams[0] = i;
                found = true;
                break;
            }
        }
        if (!found) return error.Corrupt7z;
    } else {
        for (packed_streams) |*p| {
            const idx = try r.number();
            if (idx >= total_in) return error.Corrupt7z;
            p.* = @intCast(idx);
        }
    }

    const unpack_sizes = try a.alloc(u64, total_out);
    return .{
        .coders = coders,
        .bind_pairs = bind_pairs,
        .packed_streams = packed_streams,
        .unpack_sizes = unpack_sizes,
    };
}

fn parseUnpackInfo(r: *Reader, a: Allocator, si: *StreamsInfo) !void {
    if ((try r.byte()) != k_folder) return error.Corrupt7z;
    const num_folders = try r.count(r.remaining());
    if ((try r.byte()) != 0) return error.Unsupported7zMethod; // external
    const folders = try a.alloc(Folder, num_folders);
    var pack: usize = 0;
    for (folders) |*f| {
        f.* = try parseFolder(r, a);
        f.first_pack = pack;
        pack += f.packed_streams.len;
    }
    if ((try r.byte()) != k_coders_unpack_size) return error.Corrupt7z;
    for (folders) |*f| {
        for (f.unpack_sizes) |*s| s.* = try r.number();
        f.unpack_size = try mainOutSize(f.*);
    }
    while (true) {
        const id = try r.byte();
        switch (id) {
            k_end => break,
            k_crc => {
                const crcs = try r.digests(a, num_folders);
                for (folders, crcs) |*f, c| f.crc = c;
            },
            else => try r.skipData(),
        }
    }
    si.folders = folders;
}

/// The size of the out stream that no bind pair feeds onward.
fn mainOutSize(f: Folder) !u64 {
    for (f.unpack_sizes, 0..) |size, out_index| {
        var bound = false;
        for (f.bind_pairs) |bp| {
            if (bp.out_index == out_index) bound = true;
        }
        if (!bound) return size;
    }
    return error.Corrupt7z;
}

fn parseSubStreams(r: *Reader, a: Allocator, si: *StreamsInfo, limits: Limits) !void {
    const folders = si.folders;
    for (folders) |*f| f.num_substreams = 1;

    var id = try r.byte();
    while (true) {
        if (id == k_num_unpack_stream) {
            for (folders) |*f| {
                const n = try r.number();
                if (n > limits.max_members) return error.ArchiveTooManyMembers;
                f.num_substreams = @intCast(n);
            }
        } else if (id == k_size or id == k_crc or id == k_end) {
            break;
        } else {
            try r.skipData();
        }
        id = try r.byte();
    }

    var total: usize = 0;
    for (folders) |*f| {
        f.first_substream = total;
        total +|= f.num_substreams;
        if (total > limits.max_members) return error.ArchiveTooManyMembers;
    }

    const sizes = try a.alloc(u64, total);
    for (folders) |f| {
        const n = f.num_substreams;
        if (n == 0) continue;
        const out = sizes[f.first_substream..][0..n];
        if (id == k_size) {
            var sum: u64 = 0;
            for (out[0 .. n - 1]) |*s| {
                s.* = try r.number();
                sum = std.math.add(u64, sum, s.*) catch return error.Corrupt7z;
            }
            if (sum > f.unpack_size) return error.Corrupt7z;
            out[n - 1] = f.unpack_size - sum;
        } else {
            // Without explicit sizes only a single substream is well defined.
            if (n != 1) return error.Corrupt7z;
            out[0] = f.unpack_size;
        }
    }
    if (id == k_size) id = try r.byte();

    // A folder with one substream and a folder CRC reuses that CRC. Every other
    // substream gets its digest from the list.
    const crcs = try a.alloc(?u32, total);
    @memset(crcs, null);
    var need: usize = 0;
    for (folders) |f| {
        if (f.num_substreams == 1 and f.crc != null) {
            crcs[f.first_substream] = f.crc;
        } else {
            need += f.num_substreams;
        }
    }
    while (id != k_end) {
        if (id == k_crc) {
            const list = try r.digests(a, need);
            var k: usize = 0;
            for (folders) |f| {
                if (f.num_substreams == 1 and f.crc != null) continue;
                for (0..f.num_substreams) |j| {
                    crcs[f.first_substream + j] = list[k];
                    k += 1;
                }
            }
        } else {
            try r.skipData();
        }
        id = try r.byte();
    }

    si.sub_sizes = sizes;
    si.sub_crcs = crcs;
}

fn parseStreamsInfo(r: *Reader, a: Allocator, limits: Limits) !StreamsInfo {
    var si = StreamsInfo{};
    var have_substreams = false;
    var id = try r.byte();
    if (id == k_pack_info) {
        try parsePackInfo(r, a, &si);
        id = try r.byte();
    }
    if (id == k_unpack_info) {
        try parseUnpackInfo(r, a, &si);
        id = try r.byte();
    }
    if (id == k_substreams_info) {
        try parseSubStreams(r, a, &si, limits);
        have_substreams = true;
        id = try r.byte();
    }
    if (id != k_end) return error.Corrupt7z;

    var packs: usize = 0;
    for (si.folders) |f| packs += f.packed_streams.len;
    if (packs > si.pack_sizes.len) return error.Corrupt7z;

    if (!have_substreams) {
        // One substream per folder, inheriting its size and CRC.
        const sizes = try a.alloc(u64, si.folders.len);
        const crcs = try a.alloc(?u32, si.folders.len);
        for (si.folders, 0..) |*f, i| {
            f.num_substreams = 1;
            f.first_substream = i;
            sizes[i] = f.unpack_size;
            crcs[i] = f.crc;
        }
        si.sub_sizes = sizes;
        si.sub_crcs = crcs;
    }
    return si;
}

/// UTF-16LE, NUL-terminated names. Unpaired surrogates are refused.
fn parseNames(sub: *Reader, a: Allocator, n: usize) ![][]const u8 {
    if ((try sub.byte()) != 0) return error.Unsupported7zMethod; // external
    const names = try a.alloc([]const u8, n);
    for (names) |*name| {
        var out = std.ArrayList(u8).init(a);
        while (true) {
            const u = try sub.u16le();
            if (u == 0) break;
            var cp: u21 = u;
            if (u >= 0xD800 and u < 0xDC00) {
                const lo = try sub.u16le();
                if (lo < 0xDC00 or lo > 0xDFFF) return error.Corrupt7z;
                cp = 0x10000 + ((@as(u21, u) - 0xD800) << 10) + (@as(u21, lo) - 0xDC00);
            } else if (u >= 0xDC00 and u < 0xE000) {
                return error.Corrupt7z;
            }
            var tmp: [4]u8 = undefined;
            const len = std.unicode.utf8Encode(cp, &tmp) catch return error.Corrupt7z;
            try out.appendSlice(tmp[0..len]);
            if (out.items.len > safepath.max_rel_path_len) return error.UnsafeArchiveMember;
        }
        name.* = try out.toOwnedSlice();
    }
    return names;
}

fn parseFilesInfo(r: *Reader, a: Allocator, limits: Limits) !FilesInfo {
    const raw_n = try r.number();
    if (raw_n > limits.max_members) return error.ArchiveTooManyMembers;
    // Every file needs at least a NUL in the names, which is two bytes.
    if (raw_n > r.remaining()) return error.Corrupt7z;
    const n: usize = @intCast(raw_n);

    var fi = FilesInfo{
        .empty_stream = try a.alloc(bool, n),
        .empty_file = try a.alloc(bool, n),
        .anti = try a.alloc(bool, n),
        .attrib = try a.alloc(?u32, n),
    };
    @memset(fi.empty_stream, false);
    @memset(fi.empty_file, false);
    @memset(fi.anti, false);
    @memset(fi.attrib, null);
    var have_names = false;
    var num_empty: usize = 0;

    while (true) {
        const t = try r.byte();
        if (t == k_end) break;
        const size = try r.number();
        var sub = Reader{ .buf = try r.bytes(size) };
        switch (t) {
            k_empty_stream => {
                const bits = try sub.bitVector(a, n);
                fi.empty_stream = bits;
                num_empty = 0;
                for (bits) |b| num_empty += @intFromBool(b);
            },
            k_empty_file, k_anti => {
                // These are indexed over the empty-stream files only.
                const bits = try sub.bitVector(a, num_empty);
                const dst = if (t == k_empty_file) fi.empty_file else fi.anti;
                @memset(dst, false);
                var k: usize = 0;
                for (fi.empty_stream, 0..) |is_empty, i| {
                    if (!is_empty) continue;
                    dst[i] = bits[k];
                    k += 1;
                }
            },
            k_names => {
                fi.names = try parseNames(&sub, a, n);
                have_names = true;
            },
            k_win_attributes => {
                const defined = try sub.definedVector(a, n);
                if ((try sub.byte()) != 0) return error.Unsupported7zMethod; // external
                for (fi.attrib, defined) |*attr, d| attr.* = if (d) try sub.u32le() else null;
            },
            // Times, start positions, the dummy padding and anything newer.
            else => {},
        }
    }
    if (!have_names) return error.Corrupt7z;
    return fi;
}

const Header = struct {
    streams: StreamsInfo = .{},
    files: FilesInfo = .{},
};

fn parseHeader(r: *Reader, a: Allocator, limits: Limits) !Header {
    var h = Header{};
    while (true) {
        const id = try r.byte();
        switch (id) {
            k_end => break,
            k_archive_properties => {
                while (true) {
                    const t = try r.byte();
                    if (t == k_end) break;
                    try r.skipData();
                }
            },
            k_additional_streams_info => _ = try parseStreamsInfo(r, a, limits),
            k_main_streams_info => h.streams = try parseStreamsInfo(r, a, limits),
            k_files_info => h.files = try parseFilesInfo(r, a, limits),
            else => return error.Corrupt7z,
        }
    }
    return h;
}

// ---------------------------------------------------------------------------
// Pack stream input
// ---------------------------------------------------------------------------

/// A buffered reader over one pack stream of the archive file. Reads past the
/// end of the stream are `error.Corrupt7z`.
const InStream = struct {
    file: std.fs.File,
    start: u64,
    /// File offset of the next read into `buf`.
    pos: u64,
    end: u64,
    buf: []u8,
    i: usize = 0,
    n: usize = 0,

    fn init(file: std.fs.File, buf: []u8, offset: u64, size: u64) InStream {
        return .{ .file = file, .start = offset, .pos = offset, .end = offset + size, .buf = buf };
    }

    fn fill(self: *InStream) !void {
        const want: usize = @intCast(@min(self.buf.len, self.end - self.pos));
        if (want == 0) return error.Corrupt7z;
        const got = try self.file.pread(self.buf[0..want], self.pos);
        if (got == 0) return error.Corrupt7z;
        self.pos += got;
        self.i = 0;
        self.n = got;
    }

    inline fn byte(self: *InStream) !u8 {
        if (self.i == self.n) try self.fill();
        const b = self.buf[self.i];
        self.i += 1;
        return b;
    }

    fn be16(self: *InStream) !u16 {
        const hi: u16 = try self.byte();
        return (hi << 8) | try self.byte();
    }

    /// The buffered bytes, refilling when empty. Never empty on success.
    fn peek(self: *InStream) ![]const u8 {
        if (self.i == self.n) try self.fill();
        return self.buf[self.i..self.n];
    }

    fn consume(self: *InStream, n: usize) void {
        self.i += n;
    }

    /// Bytes handed out so far.
    fn consumed(self: *const InStream) u64 {
        return (self.pos - self.start) - (self.n - self.i);
    }
};

// ---------------------------------------------------------------------------
// LZMA
// ---------------------------------------------------------------------------

const prob_init: u16 = 1024;
const range_top: u32 = 1 << 24;

// Layout of the probability array (the same arrangement as LzmaDec.c).
const len_choice = 0;
const len_choice2 = 1;
const len_low = 2; // 16 pos states x 8
const len_mid = len_low + 16 * 8;
const len_high = len_mid + 16 * 8; // 256
const len_size = len_high + 256;

const off_is_match = 0; // 12 states x 16 pos states
const off_is_rep = off_is_match + 12 * 16;
const off_is_rep_g0 = off_is_rep + 12;
const off_is_rep_g1 = off_is_rep_g0 + 12;
const off_is_rep_g2 = off_is_rep_g1 + 12;
const off_is_rep0_long = off_is_rep_g2 + 12; // 12 x 16
const off_pos_slot = off_is_rep0_long + 12 * 16; // 4 x 64
const off_pos_special = off_pos_slot + 4 * 64; // 114
const off_align = off_pos_special + 114; // 16
const off_len = off_align + 16;
const off_rep_len = off_len + len_size;
const off_lit = off_rep_len + len_size;

/// An LZMA decoder with a sliding window. Output leaves through `Sink` whenever
/// the window wraps and at `flush`.
const Lzma = struct {
    a: Allocator,
    probs: []u16,
    win: []u8,
    /// Next write position in `win`.
    pos: usize = 0,
    /// Everything before this has been handed to the sink.
    flushed: usize = 0,
    /// Valid bytes in the window: min(total, win.len).
    full: usize = 0,
    /// Bytes produced since the last dictionary reset. Only its low bits matter
    /// (for the position state), so wrapping is harmless.
    total: usize = 0,
    lc: u4 = 0,
    lp: u3 = 0,
    pb: u3 = 0,
    state: usize = 0,
    rep: [4]u32 = .{ 0, 0, 0, 0 },
    range: u32 = 0,
    code: u32 = 0,

    /// `lit_bits` is the largest lc + lp that will be used.
    fn init(a: Allocator, win_size: usize, lit_bits: u5) !Lzma {
        const probs = try a.alloc(u16, off_lit + (@as(usize, 0x300) << lit_bits));
        errdefer a.free(probs);
        const win = try a.alloc(u8, win_size);
        return .{ .a = a, .probs = probs, .win = win };
    }

    fn deinit(self: *Lzma) void {
        self.a.free(self.probs);
        self.a.free(self.win);
    }

    fn setProps(self: *Lzma, lc: u4, lp: u3, pb: u3) void {
        self.lc = lc;
        self.lp = lp;
        self.pb = pb;
    }

    fn resetState(self: *Lzma) void {
        @memset(self.probs, prob_init);
        self.state = 0;
        self.rep = .{ 0, 0, 0, 0 };
    }

    fn resetDict(self: *Lzma, sink: *Sink) !void {
        try self.flush(sink);
        self.pos = 0;
        self.flushed = 0;
        self.full = 0;
        self.total = 0;
    }

    /// Reads the five range-coder start bytes.
    fn startRange(self: *Lzma, in: *InStream) !void {
        if ((try in.byte()) != 0) return error.Corrupt7z;
        var code: u32 = 0;
        for (0..4) |_| code = (code << 8) | try in.byte();
        self.code = code;
        self.range = 0xFFFF_FFFF;
    }

    fn flush(self: *Lzma, sink: *Sink) !void {
        if (self.pos > self.flushed) try sink.write(self.win[self.flushed..self.pos]);
        self.flushed = self.pos;
    }

    fn wrapIfFull(self: *Lzma, sink: *Sink) !void {
        if (self.pos == self.win.len) {
            try self.flush(sink);
            self.pos = 0;
            self.flushed = 0;
        }
    }

    inline fn put(self: *Lzma, sink: *Sink, b: u8) !void {
        self.win[self.pos] = b;
        self.pos += 1;
        self.total +%= 1;
        if (self.full < self.win.len) self.full += 1;
        if (self.pos == self.win.len) try self.wrapIfFull(sink);
    }

    /// Appends literal bytes (an LZMA2 uncompressed chunk).
    fn putSlice(self: *Lzma, sink: *Sink, data: []const u8) !void {
        var rest = data;
        while (rest.len > 0) {
            const n = @min(self.win.len - self.pos, rest.len);
            @memcpy(self.win[self.pos..][0..n], rest[0..n]);
            self.pos += n;
            self.total +%= n;
            self.full = @min(self.full + n, self.win.len);
            rest = rest[n..];
            try self.wrapIfFull(sink);
        }
    }

    fn copyMatch(self: *Lzma, sink: *Sink, dist: usize, len: usize) !void {
        if (dist > self.full) return error.Corrupt7z;
        var src = if (self.pos >= dist) self.pos - dist else self.pos + self.win.len - dist;
        var left = len;
        while (left > 0) {
            const n = @min(left, self.win.len - self.pos);
            const dst = self.win[self.pos..][0..n];
            for (dst) |*d| {
                d.* = self.win[src];
                src += 1;
                if (src == self.win.len) src = 0;
            }
            self.pos += n;
            self.total +%= n;
            self.full = @min(self.full + n, self.win.len);
            left -= n;
            try self.wrapIfFull(sink);
        }
    }

    inline fn norm(self: *Lzma, in: *InStream) !void {
        if (self.range < range_top) {
            self.range <<= 8;
            self.code = (self.code << 8) | try in.byte();
        }
    }

    inline fn bit(self: *Lzma, in: *InStream, idx: usize) !u1 {
        try self.norm(in);
        const p = self.probs[idx];
        const bound = (self.range >> 11) * @as(u32, p);
        if (self.code < bound) {
            self.range = bound;
            self.probs[idx] = p + ((2048 - p) >> 5);
            return 0;
        }
        self.range -= bound;
        self.code -= bound;
        self.probs[idx] = p - (p >> 5);
        return 1;
    }

    fn direct(self: *Lzma, in: *InStream, n: u5) !u32 {
        var res: u32 = 0;
        var i: u5 = 0;
        while (i < n) : (i += 1) {
            try self.norm(in);
            self.range >>= 1;
            self.code -%= self.range;
            const t: u32 = 0 -% (self.code >> 31);
            self.code +%= self.range & t;
            res = (res << 1) +% (t +% 1);
        }
        return res;
    }

    fn tree(self: *Lzma, in: *InStream, base: usize, nbits: u5) !u32 {
        var m: u32 = 1;
        var i: u5 = 0;
        while (i < nbits) : (i += 1) m = (m << 1) | try self.bit(in, base + m);
        return m - (@as(u32, 1) << nbits);
    }

    fn treeRev(self: *Lzma, in: *InStream, base: usize, nbits: u5) !u32 {
        var m: u32 = 1;
        var sym: u32 = 0;
        var i: u5 = 0;
        while (i < nbits) : (i += 1) {
            const b: u32 = try self.bit(in, base + m);
            m = (m << 1) | b;
            sym |= b << i;
        }
        return sym;
    }

    fn decodeLen(self: *Lzma, in: *InStream, base: usize, pos_state: usize) !usize {
        if ((try self.bit(in, base + len_choice)) == 0) {
            return try self.tree(in, base + len_low + pos_state * 8, 3);
        }
        if ((try self.bit(in, base + len_choice2)) == 0) {
            return 8 + try self.tree(in, base + len_mid + pos_state * 8, 3);
        }
        return 16 + try self.tree(in, base + len_high, 8);
    }

    fn decodeDist(self: *Lzma, in: *InStream, len: usize) !u32 {
        const len_state: usize = @min(len, 3);
        const slot = try self.tree(in, off_pos_slot + len_state * 64, 6);
        if (slot < 4) return slot;
        const nd: u5 = @intCast((slot >> 1) - 1);
        var dist: u32 = (2 | (slot & 1)) << nd;
        if (slot < 14) {
            dist += try self.treeRev(in, off_pos_special + dist - slot - 1, nd);
        } else {
            dist +%= (try self.direct(in, nd - 4)) << 4;
            dist +%= try self.treeRev(in, off_align, 4);
        }
        return dist;
    }

    /// Decodes exactly `count` bytes. An end marker or a match that runs past
    /// `count` is corrupt.
    fn decode(self: *Lzma, in: *InStream, count: u64, sink: *Sink) !void {
        var left = count;
        const pb_mask = (@as(usize, 1) << self.pb) - 1;
        const lp_mask = (@as(usize, 1) << self.lp) - 1;
        while (left > 0) {
            const pos_state = self.total & pb_mask;
            const st = self.state;

            if ((try self.bit(in, off_is_match + (st << 4) + pos_state)) == 0) {
                const prev: usize = if (self.full > 0)
                    self.win[if (self.pos == 0) self.win.len - 1 else self.pos - 1]
                else
                    0;
                const lit_state = ((self.total & lp_mask) << self.lc) + (prev >> (8 - self.lc));
                const base = off_lit + 0x300 * lit_state;
                var sym: usize = 1;
                if (st >= 7) {
                    const dist = @as(usize, self.rep[0]) + 1;
                    if (dist > self.full) return error.Corrupt7z;
                    const at = if (self.pos >= dist) self.pos - dist else self.pos + self.win.len - dist;
                    var match_byte: usize = self.win[at];
                    while (sym < 0x100) {
                        match_byte <<= 1;
                        const mbit = match_byte & 0x100;
                        const b: usize = try self.bit(in, base + 0x100 + mbit + sym);
                        sym = (sym << 1) | b;
                        if ((mbit != 0) != (b == 1)) break;
                    }
                }
                while (sym < 0x100) {
                    const b: usize = try self.bit(in, base + sym);
                    sym = (sym << 1) | b;
                }
                try self.put(sink, @truncate(sym));
                self.state = if (st < 4) 0 else if (st < 10) st - 3 else st - 6;
                left -= 1;
                continue;
            }

            var len: usize = undefined;
            if ((try self.bit(in, off_is_rep + st)) == 0) {
                self.rep[3] = self.rep[2];
                self.rep[2] = self.rep[1];
                self.rep[1] = self.rep[0];
                len = try self.decodeLen(in, off_len, pos_state);
                self.state = if (st < 7) 7 else 10;
                const dist = try self.decodeDist(in, len);
                // The end marker. The size is known, so it is premature.
                if (dist == 0xFFFF_FFFF) return error.Corrupt7z;
                self.rep[0] = dist;
            } else {
                if (self.full == 0) return error.Corrupt7z;
                if ((try self.bit(in, off_is_rep_g0 + st)) == 0) {
                    if ((try self.bit(in, off_is_rep0_long + (st << 4) + pos_state)) == 0) {
                        // A single byte from the last distance.
                        self.state = if (st < 7) 9 else 11;
                        try self.copyMatch(sink, @as(usize, self.rep[0]) + 1, 1);
                        left -= 1;
                        continue;
                    }
                } else {
                    var dist: u32 = undefined;
                    if ((try self.bit(in, off_is_rep_g1 + st)) == 0) {
                        dist = self.rep[1];
                    } else {
                        if ((try self.bit(in, off_is_rep_g2 + st)) == 0) {
                            dist = self.rep[2];
                        } else {
                            dist = self.rep[3];
                            self.rep[3] = self.rep[2];
                        }
                        self.rep[2] = self.rep[1];
                    }
                    self.rep[1] = self.rep[0];
                    self.rep[0] = dist;
                }
                len = try self.decodeLen(in, off_rep_len, pos_state);
                self.state = if (st < 7) 8 else 11;
            }

            len += 2;
            if (len > left) return error.Corrupt7z;
            try self.copyMatch(sink, @as(usize, self.rep[0]) + 1, len);
            left -= len;
        }
    }
};

/// The window never needs to be larger than what the stream will produce.
fn windowSize(dict_size: u64, unpack_size: u64) !usize {
    const size = @min(dict_size, unpack_size);
    if (size > max_dict_bytes) return error.ArchiveTooLarge;
    return @intCast(size);
}

fn decodeLzma(a: Allocator, in: *InStream, props: []const u8, unpack_size: u64, sink: *Sink) !void {
    if (props.len != 5) return error.Corrupt7z;
    if (unpack_size == 0) return;
    var d: u32 = props[0];
    if (d >= 9 * 5 * 5) return error.Corrupt7z;
    const lc: u4 = @intCast(d % 9);
    d /= 9;
    const lp: u3 = @intCast(d % 5);
    const pb: u3 = @intCast(d / 5);
    const dict_size = std.mem.readInt(u32, props[1..5], .little);

    var lz = try Lzma.init(a, try windowSize(@max(dict_size, 4096), unpack_size), @as(u5, lc) + lp);
    defer lz.deinit();
    lz.setProps(lc, lp, pb);
    lz.resetState();
    try lz.startRange(in);
    try lz.decode(in, unpack_size, sink);
    try lz.flush(sink);
}

fn decodeLzma2(a: Allocator, in: *InStream, props: []const u8, unpack_size: u64, sink: *Sink) !void {
    if (props.len != 1 or props[0] > 40) return error.Corrupt7z;
    if (unpack_size == 0) return;
    const p: u64 = props[0];
    const dict_size: u64 = if (p == 40) 0xFFFF_FFFF else (2 | (p & 1)) << @intCast(p / 2 + 11);

    var lz = try Lzma.init(a, try windowSize(dict_size, unpack_size), 4);
    defer lz.deinit();

    var produced: u64 = 0;
    var need_dict_reset = true;
    var need_props = true;
    while (produced < unpack_size) {
        const control = try in.byte();
        if (control == 0) return error.Corrupt7z; // ended before the promised size
        if (control == 1 or control == 2) {
            if (control == 1) {
                try lz.resetDict(sink);
                need_dict_reset = false;
                need_props = true;
            } else if (need_dict_reset) {
                return error.Corrupt7z;
            }
            var size: u64 = @as(u64, try in.be16()) + 1;
            if (size > unpack_size - produced) return error.Corrupt7z;
            produced += size;
            while (size > 0) {
                const chunk = try in.peek();
                const n: usize = @intCast(@min(size, chunk.len));
                try lz.putSlice(sink, chunk[0..n]);
                in.consume(n);
                size -= n;
            }
            continue;
        }
        if (control < 0x80) return error.Corrupt7z;

        const chunk_unpack = ((@as(u64, control & 0x1F) << 16) | try in.be16()) + 1;
        const chunk_pack = @as(u64, try in.be16()) + 1;
        const reset = (control >> 5) & 3;
        if (reset == 3) {
            try lz.resetDict(sink);
            need_dict_reset = false;
        } else if (need_dict_reset) {
            return error.Corrupt7z;
        }
        if (reset >= 2) {
            var pr: u32 = try in.byte();
            if (pr >= 9 * 5 * 5) return error.Corrupt7z;
            const lc: u4 = @intCast(pr % 9);
            pr /= 9;
            const lp: u3 = @intCast(pr % 5);
            const pb: u3 = @intCast(pr / 5);
            if (@as(u32, lc) + lp > 4) return error.Corrupt7z;
            lz.setProps(lc, lp, pb);
            need_props = false;
        } else if (need_props) {
            return error.Corrupt7z;
        }
        if (reset >= 1) lz.resetState();

        if (chunk_unpack > unpack_size - produced) return error.Corrupt7z;
        const start = in.consumed();
        try lz.startRange(in);
        try lz.decode(in, chunk_unpack, sink);
        // The encoder's final flush leaves up to one byte for the decoder to
        // pull in; the chunk must end exactly on its stated size.
        try lz.norm(in);
        if (lz.code != 0 or in.consumed() - start != chunk_pack) return error.Corrupt7z;
        produced += chunk_unpack;
    }
    try lz.flush(sink);
}

fn decodeCopy(in: *InStream, unpack_size: u64, sink: *Sink) !void {
    var left = unpack_size;
    while (left > 0) {
        const chunk = try in.peek();
        const n: usize = @intCast(@min(left, chunk.len));
        try sink.write(chunk[0..n]);
        in.consume(n);
        left -= n;
    }
}

// ---------------------------------------------------------------------------
// BCJ (x86) filter
// ---------------------------------------------------------------------------

fn isMsByte(b: u8) bool {
    return b == 0 or b == 0xFF;
}

/// Reverses the x86 branch converter: absolute CALL/JMP targets go back to the
/// original relative ones. Returns how many leading bytes are final; the
/// remainder (at most four) must be presented again with more data behind it.
/// This is the 7-Zip Bra86 algorithm, with `state` carrying the lookback mask
/// across calls.
fn x86Convert(data: []u8, ip_start: u32, state: *u32) usize {
    const allowed = [8]bool{ true, true, true, false, true, false, false, false };
    const bit_number = [8]u5{ 0, 1, 2, 2, 3, 3, 3, 3 };

    if (data.len < 5) return 0;
    const ip = ip_start +% 5;
    const limit = data.len - 4;
    var buffer_pos: usize = 0;
    var prev_mask: u32 = state.* & 7;
    var prev_pos: usize = std.math.maxInt(usize);

    while (true) {
        var p = buffer_pos;
        while (p < limit and (data[p] & 0xFE) != 0xE8) p += 1;
        buffer_pos = p;
        if (p >= limit) break;

        const gap = buffer_pos -% prev_pos;
        if (gap > 3) {
            prev_mask = 0;
        } else {
            prev_mask = (prev_mask << @intCast(gap - 1)) & 7;
            if (prev_mask != 0) {
                const b = data[p + 4 - bit_number[prev_mask]];
                if (!allowed[prev_mask] or isMsByte(b)) {
                    prev_pos = buffer_pos;
                    prev_mask = ((prev_mask << 1) & 7) | 1;
                    buffer_pos += 1;
                    continue;
                }
            }
        }
        prev_pos = buffer_pos;

        if (isMsByte(data[p + 4])) {
            var src = std.mem.readInt(u32, data[p + 1 ..][0..4], .little);
            var dest: u32 = undefined;
            while (true) {
                dest = src -% (ip +% @as(u32, @intCast(buffer_pos)));
                if (prev_mask == 0) break;
                const index: u5 = bit_number[prev_mask] * 8;
                const b: u8 = @truncate(dest >> (24 - index));
                if (!isMsByte(b)) break;
                src = dest ^ ((@as(u32, 1) << (31 - index + 1)) - 1);
            }
            data[p + 4] = ~((@as(u8, @truncate(dest >> 24)) & 1) -% 1);
            data[p + 3] = @truncate(dest >> 16);
            data[p + 2] = @truncate(dest >> 8);
            data[p + 1] = @truncate(dest);
            buffer_pos += 5;
        } else {
            prev_mask = ((prev_mask << 1) & 7) | 1;
            buffer_pos += 1;
        }
    }

    const gap = buffer_pos -% prev_pos;
    state.* = if (gap > 3) 0 else (prev_mask << @intCast(gap - 1)) & 7;
    return buffer_pos;
}

const bcj_buf_len = 64 * 1024;

const X86Filter = struct {
    a: Allocator,
    buf: []u8,
    len: usize = 0,
    ip: u32 = 0,
    state: u32 = 0,

    fn init(a: Allocator) !X86Filter {
        return .{ .a = a, .buf = try a.alloc(u8, bcj_buf_len) };
    }

    fn deinit(self: *X86Filter) void {
        self.a.free(self.buf);
    }

    fn write(self: *X86Filter, data: []const u8, sink: *Sink) !void {
        var rest = data;
        while (rest.len > 0) {
            const n = @min(self.buf.len - self.len, rest.len);
            @memcpy(self.buf[self.len..][0..n], rest[0..n]);
            self.len += n;
            rest = rest[n..];
            if (self.len == self.buf.len) try self.convert(sink);
        }
    }

    fn convert(self: *X86Filter, sink: *Sink) !void {
        const done = x86Convert(self.buf[0..self.len], self.ip, &self.state);
        try sink.emit(self.buf[0..done]);
        self.ip +%= @truncate(done);
        std.mem.copyForwards(u8, self.buf[0 .. self.len - done], self.buf[done..self.len]);
        self.len -= done;
    }

    /// The last up to four bytes can never start a conversion; pass them on.
    fn finish(self: *X86Filter, sink: *Sink) !void {
        try self.convert(sink);
        try sink.emit(self.buf[0..self.len]);
        self.len = 0;
    }
};

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/// One extractable thing, after names are validated.
const Entry = struct {
    name: []const u8,
    kind: enum { dir, file, skip },
    executable: bool,
};

/// Cuts a folder's decoded bytes into its substreams and writes each to its
/// file, checking every CRC as the last byte of a substream arrives.
const Splitter = struct {
    dest: std.fs.Dir,
    entries: []const Entry,
    /// Per substream (over all folders): which entry it belongs to.
    stream_entry: []const u32,
    sizes: []const u64,
    crcs: []const ?u32,
    /// Next substream to open, and one past this folder's last.
    next: usize,
    end: usize,

    active: bool = false,
    cur: ?std.fs.File = null,
    cur_index: usize = 0,
    remaining: u64 = 0,
    hasher: Crc32 = Crc32.init(),
    folder_crc: ?u32,
    folder_hasher: Crc32 = Crc32.init(),

    fn deinit(self: *Splitter) void {
        if (self.cur) |f| f.close();
        self.cur = null;
    }

    fn openFor(self: *Splitter, stream: usize) !?std.fs.File {
        const e = self.entries[self.stream_entry[stream]];
        if (e.kind != .file) return null;
        if (std.fs.path.dirname(e.name)) |d| try self.dest.makePath(d);
        // Only the permission bits matter. The mode is one of two fixed values,
        // so setuid, setgid and sticky can never be set.
        const mode: std.fs.File.Mode = if (std.fs.has_executable_bit and e.executable)
            platform.mode_bin
        else
            platform.mode_public;
        return try self.dest.createFile(e.name, .{ .mode = mode });
    }

    fn finishCurrent(self: *Splitter) !void {
        if (self.cur) |f| f.close();
        self.cur = null;
        if (self.crcs[self.cur_index]) |want| {
            if (self.hasher.final() != want) return error.Crc7zMismatch;
        }
    }

    /// Opens the next substream that has bytes. Empty ones are finished on the
    /// spot, which creates the file and checks its (empty) CRC.
    fn startNext(self: *Splitter) !void {
        self.active = false;
        while (self.next < self.end) {
            const i = self.next;
            self.next += 1;
            self.cur = try self.openFor(i);
            self.cur_index = i;
            self.hasher = Crc32.init();
            self.remaining = self.sizes[i];
            if (self.remaining == 0) {
                try self.finishCurrent();
                continue;
            }
            self.active = true;
            return;
        }
    }

    fn write(self: *Splitter, data: []const u8) !void {
        if (self.folder_crc != null) self.folder_hasher.update(data);
        var rest = data;
        while (rest.len > 0) {
            if (!self.active) return error.Corrupt7z; // more bytes than substreams
            const n: usize = @intCast(@min(rest.len, self.remaining));
            if (self.cur) |f| try f.writeAll(rest[0..n]);
            self.hasher.update(rest[0..n]);
            self.remaining -= n;
            rest = rest[n..];
            if (self.remaining == 0) {
                try self.finishCurrent();
                try self.startNext();
            }
        }
    }

    /// The folder's decoder is done: every substream must be complete.
    fn finish(self: *Splitter) !void {
        if (self.active) return error.Corrupt7z;
        if (self.folder_crc) |want| {
            if (self.folder_hasher.final() != want) return error.Crc7zMismatch;
        }
    }
};

const Out = union(enum) {
    split: *Splitter,
    mem: *std.ArrayList(u8),
};

/// Where decoded bytes go: through the optional x86 filter, then to the target.
const Sink = struct {
    out: Out,
    bcj: ?*X86Filter = null,

    fn write(self: *Sink, data: []const u8) !void {
        if (self.bcj) |f| return f.write(data, self);
        return self.emit(data);
    }

    fn emit(self: *Sink, data: []const u8) !void {
        switch (self.out) {
            .split => |s| try s.write(data),
            .mem => |m| try m.appendSlice(data),
        }
    }

    fn finish(self: *Sink) !void {
        if (self.bcj) |f| try f.finish(self);
    }
};

// ---------------------------------------------------------------------------
// Folder decoding
// ---------------------------------------------------------------------------

const Source = enum { copy, lzma, lzma2 };

/// How to decode one folder: a source coder, optionally followed by BCJ.
const Plan = struct {
    source: Source,
    props: []const u8,
    /// What the source coder produces.
    source_size: u64,
    bcj: bool,
    first_pack: usize,
};

fn sourceKind(id: u64) ?Source {
    return switch (id) {
        id_copy => .copy,
        id_lzma => .lzma,
        id_lzma2 => .lzma2,
        else => null,
    };
}

fn isX86Filter(id: u64) bool {
    return id == id_bcj_x86 or id == id_bcj_x86_new;
}

/// Works out how to decode a folder, or refuses it. Nothing is read from the
/// archive body, so every folder can be checked before extraction starts.
fn planFolder(f: Folder) !Plan {
    // Method ids first: PPMd, BZip2, Deflate, BCJ2, Delta, AES and anything
    // else we do not implement are refused regardless of how the folder is wired.
    for (f.coders) |c| {
        if (sourceKind(c.id) == null and !isX86Filter(c.id)) return error.Unsupported7zMethod;
    }
    for (f.coders) |c| {
        if (c.num_in != 1 or c.num_out != 1) return error.Corrupt7z;
    }
    if (f.packed_streams.len != 1) return error.Corrupt7z;

    switch (f.coders.len) {
        1 => {
            const c = f.coders[0];
            const src = sourceKind(c.id) orelse return error.Unsupported7zMethod;
            if (f.bind_pairs.len != 0 or f.packed_streams[0] != 0) return error.Corrupt7z;
            return .{
                .source = src,
                .props = c.props,
                .source_size = f.unpack_sizes[0],
                .bcj = false,
                .first_pack = f.first_pack,
            };
        },
        2 => {
            if (f.bind_pairs.len != 1) return error.Corrupt7z;
            const bp = f.bind_pairs[0];
            // The filter consumes the other coder's output.
            if (bp.in_index > 1 or bp.out_index > 1 or bp.in_index == bp.out_index) return error.Corrupt7z;
            const filter = f.coders[bp.in_index];
            const source = f.coders[bp.out_index];
            if (!isX86Filter(filter.id)) return error.Unsupported7zMethod;
            const src = sourceKind(source.id) orelse return error.Unsupported7zMethod;
            if (f.packed_streams[0] != bp.out_index) return error.Corrupt7z;
            // A branch filter never changes the size.
            if (f.unpack_sizes[0] != f.unpack_sizes[1]) return error.Corrupt7z;
            return .{
                .source = src,
                .props = source.props,
                .source_size = f.unpack_sizes[bp.out_index],
                .bcj = true,
                .first_pack = f.first_pack,
            };
        },
        else => return error.Unsupported7zMethod,
    }
}

/// Decodes one folder into `out`. `io_buf` is the shared read buffer.
fn decodeFolder(
    allocator: Allocator,
    file: std.fs.File,
    io_buf: []u8,
    plan: Plan,
    pack_offset: u64,
    pack_size: u64,
    out: Out,
) !void {
    var filter: X86Filter = undefined;
    var sink = Sink{ .out = out };
    if (plan.bcj) {
        filter = try X86Filter.init(allocator);
        sink.bcj = &filter;
    }
    defer if (plan.bcj) filter.deinit();

    var in = InStream.init(file, io_buf, pack_offset, pack_size);
    switch (plan.source) {
        .copy => {
            if (pack_size < plan.source_size) return error.Corrupt7z;
            try decodeCopy(&in, plan.source_size, &sink);
        },
        .lzma => try decodeLzma(allocator, &in, plan.props, plan.source_size, &sink),
        .lzma2 => try decodeLzma2(allocator, &in, plan.props, plan.source_size, &sink),
    }
    try sink.finish();
}

/// Where each pack stream starts in the file, checked against the file size.
fn packOffsets(a: Allocator, si: StreamsInfo, file_size: u64) ![]u64 {
    const offsets = try a.alloc(u64, si.pack_sizes.len);
    var off = std.math.add(u64, sig_header_len, si.pack_pos) catch return error.Corrupt7z;
    for (si.pack_sizes, offsets) |size, *o| {
        o.* = off;
        off = std.math.add(u64, off, size) catch return error.Corrupt7z;
        if (off > file_size) return error.Corrupt7z;
    }
    return offsets;
}

/// Reads the one folder of an EncodedHeader into memory.
fn decodeEncodedHeader(
    allocator: Allocator,
    a: Allocator,
    file: std.fs.File,
    file_size: u64,
    io_buf: []u8,
    si: StreamsInfo,
) ![]u8 {
    if (si.folders.len != 1) return error.Corrupt7z;
    const f = si.folders[0];
    if (f.unpack_size > max_header_bytes) return error.ArchiveTooLarge;
    const plan = try planFolder(f);
    const offsets = try packOffsets(a, si, file_size);
    if (plan.first_pack >= offsets.len) return error.Corrupt7z;

    var list = std.ArrayList(u8).init(a);
    try list.ensureTotalCapacityPrecise(@intCast(f.unpack_size));
    try decodeFolder(allocator, file, io_buf, plan, offsets[plan.first_pack], si.pack_sizes[plan.first_pack], .{ .mem = &list });
    if (list.items.len != f.unpack_size) return error.Corrupt7z;
    if (f.crc) |want| {
        if (Crc32.hash(list.items) != want) return error.Crc7zMismatch;
    }
    return list.items;
}

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

fn stripComponents(path: []const u8, count: u32) []const u8 {
    return archive.stripComponents(path, count);
}

/// Classifies every file, validates every name, and drops what is not
/// extracted. Any unsafe name fails the whole archive here.
fn buildEntries(a: Allocator, h: Header, strip: u32) ![]Entry {
    const fi = h.files;
    const entries = try a.alloc(Entry, fi.names.len);
    for (entries, 0..) |*e, i| {
        const name = try a.dupe(u8, fi.names[i]);
        // 7z records Windows names with backslashes. Treat them as separators,
        // then validate the result like any other archive member.
        std.mem.replaceScalar(u8, name, '\\', '/');
        if (!safepath.isSafeRelPath(name) or std.mem.indexOfScalar(u8, name, ':') != null) {
            return error.UnsafeArchiveMember;
        }

        const has_stream = !fi.empty_stream[i];
        const attr = fi.attrib[i] orelse 0;
        const mode: ?u32 = if (attr & attr_unix_extension != 0) attr >> 16 else null;
        const fmt: u32 = if (mode) |m| m & s_ifmt else 0;

        var is_dir = (!has_stream and !fi.empty_file[i]) or attr & attr_directory != 0 or fmt == s_ifdir;
        if (is_dir and has_stream) return error.Corrupt7z;
        // Links are not extracted, and neither are devices, pipes or the
        // anti-items that exist only to delete files from an older archive.
        const unsupported = fi.anti[i] or attr & attr_reparse_point != 0 or
            (fmt != 0 and fmt != s_ifreg and fmt != s_ifdir);
        if (fmt == s_ifdir) is_dir = true;

        var rel = stripComponents(name, strip);
        while (rel.len > 0 and rel[rel.len - 1] == '/') rel = rel[0 .. rel.len - 1];
        if (!is_dir and std.mem.endsWith(u8, name, "/")) return error.UnsafeArchiveMember;

        e.* = .{
            .name = rel,
            .kind = if (unsupported or rel.len == 0) .skip else if (is_dir) .dir else .file,
            .executable = if (mode) |m| m & 0o100 != 0 else false,
        };
    }
    return entries;
}

/// Extract the 7z archive in `file` into `dest`.
pub fn extract(
    allocator: Allocator,
    file: std.fs.File,
    dest: std.fs.Dir,
    options: archive.Options,
) !void {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const file_size = (try file.stat()).size;
    if (file_size < sig_header_len) return error.Corrupt7z;

    var sh: [sig_header_len]u8 = undefined;
    if ((try file.preadAll(&sh, 0)) != sh.len) return error.Corrupt7z;
    if (!std.mem.eql(u8, sh[0..6], &magic)) return error.Corrupt7z;
    if (sh[6] != 0) return error.Corrupt7z; // major version
    if (std.mem.readInt(u32, sh[8..12], .little) != Crc32.hash(sh[12..32])) return error.Crc7zMismatch;
    const next_offset = std.mem.readInt(u64, sh[12..20], .little);
    const next_size = std.mem.readInt(u64, sh[20..28], .little);
    const next_crc = std.mem.readInt(u32, sh[28..32], .little);

    // An archive with nothing in it has no header at all.
    if (next_size == 0) return;
    if (next_size > max_header_bytes) return error.ArchiveTooLarge;
    const body = file_size - sig_header_len;
    if (next_offset > body or next_size > body - next_offset) return error.Corrupt7z;

    const io_buf = try allocator.alloc(u8, io_buf_len);
    defer allocator.free(io_buf);

    var header_bytes = try a.alloc(u8, @intCast(next_size));
    if ((try file.preadAll(header_bytes, sig_header_len + next_offset)) != header_bytes.len) return error.Corrupt7z;
    if (Crc32.hash(header_bytes) != next_crc) return error.Crc7zMismatch;

    const limits = Limits{ .max_members = options.max_members };

    // The header is either plain or itself compressed (an EncodedHeader).
    var header: Header = undefined;
    var depth: usize = 0;
    while (true) {
        var r = Reader{ .buf = header_bytes };
        const id = try r.byte();
        if (id == k_header) {
            header = try parseHeader(&r, a, limits);
            break;
        }
        if (id != k_encoded_header) return error.Corrupt7z;
        depth += 1;
        if (depth > max_header_depth) return error.Corrupt7z;
        const si = try parseStreamsInfo(&r, a, limits);
        header_bytes = try decodeEncodedHeader(allocator, a, file, file_size, io_buf, si);
    }

    const si = header.streams;
    const folders = si.folders;

    // Everything below is checked before the first byte is written.
    var total: u64 = 0;
    for (folders) |f| {
        total +|= f.unpack_size;
        if (total > options.max_bytes) return error.ArchiveTooLarge;
    }

    const plans = try a.alloc(Plan, folders.len);
    for (folders, plans) |f, *p| p.* = try planFolder(f);
    const offsets = try packOffsets(a, si, file_size);
    for (plans) |p| {
        if (p.first_pack >= offsets.len) return error.Corrupt7z;
    }

    const entries = try buildEntries(a, header, options.strip_components);

    // Files that own a substream, in order, are matched to the substreams.
    const stream_entry = try a.alloc(u32, si.sub_sizes.len);
    var next_stream: usize = 0;
    for (entries, 0..) |_, i| {
        if (header.files.empty_stream[i]) continue;
        if (next_stream >= stream_entry.len) return error.Corrupt7z;
        stream_entry[next_stream] = @intCast(i);
        next_stream += 1;
    }
    if (next_stream != stream_entry.len) return error.Corrupt7z;

    // Directories and empty files have no data to decode.
    for (entries, 0..) |e, i| {
        switch (e.kind) {
            .dir => try dest.makePath(e.name),
            .file => if (header.files.empty_stream[i]) {
                if (std.fs.path.dirname(e.name)) |d| try dest.makePath(d);
                const mode: std.fs.File.Mode = if (std.fs.has_executable_bit and e.executable)
                    platform.mode_bin
                else
                    platform.mode_public;
                const f = try dest.createFile(e.name, .{ .mode = mode });
                f.close();
            },
            .skip => {},
        }
    }

    for (folders, plans) |f, p| {
        var splitter = Splitter{
            .dest = dest,
            .entries = entries,
            .stream_entry = stream_entry,
            .sizes = si.sub_sizes,
            .crcs = si.sub_crcs,
            .next = f.first_substream,
            .end = f.first_substream + f.num_substreams,
            .folder_crc = f.crc,
        };
        defer splitter.deinit();
        try splitter.startNext();
        try decodeFolder(allocator, file, io_buf, p, offsets[p.first_pack], si.pack_sizes[p.first_pack], .{ .split = &splitter });
        try splitter.finish();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn fixture(a: Allocator, name: []const u8) ![]u8 {
    const path = try std.fmt.allocPrint(a, "tests/fixtures/7z/{s}", .{name});
    defer a.free(path);
    return std.fs.cwd().readFileAlloc(a, path, 1 << 20);
}

/// Extracts `bytes` into `out` inside `tmp`.
fn extractBytes(tmp: *testing.TmpDir, bytes: []const u8, options: archive.Options) !void {
    try tmp.dir.writeFile(.{ .sub_path = "in.7z", .data = bytes });
    try tmp.dir.makePath("out");
    var f = try tmp.dir.openFile("in.7z", .{});
    defer f.close();
    var out = try tmp.dir.openDir("out", .{});
    defer out.close();
    try extract(testing.allocator, f, out, options);
}

fn dirIsEmpty(dir: std.fs.Dir) !bool {
    var d = try dir.openDir(".", .{ .iterate = true });
    defer d.close();
    var it = d.iterate();
    return (try it.next()) == null;
}

/// The tree every generated fixture holds (see tests/fixtures/README.md).
fn expectStandardTree(out: std.fs.Dir) !void {
    const hello = try out.readFileAlloc(testing.allocator, "hello.txt", 64);
    defer testing.allocator.free(hello);
    try testing.expectEqualStrings("hello 7z world\n", hello);

    const uni = try out.readFileAlloc(testing.allocator, "\u{fc}n\u{ef}-\u{6587}\u{4ef6}.txt", 64);
    defer testing.allocator.free(uni);
    try testing.expectEqualStrings("unicode name\n", uni);

    try testing.expectEqual(@as(u64, 0), (try out.statFile("empty.txt")).size);
    try out.access("emptydir", .{});
    try out.access("sub/dir", .{});

    const data = try out.readFileAlloc(testing.allocator, "sub/dir/data.txt", 1 << 20);
    defer testing.allocator.free(data);
    try testing.expectEqual(@as(usize, 34488), data.len);
    try testing.expectEqual(@as(u32, 0xD15E95B4), Crc32.hash(data));

    const exe = try out.readFileAlloc(testing.allocator, "bin/prog.exe", 1 << 20);
    defer testing.allocator.free(exe);
    try testing.expectEqual(@as(usize, 30002), exe.len);
    try testing.expectEqual(@as(u32, 0xCCBABBE4), Crc32.hash(exe));

    // The archive holds a symlink; it is not extracted.
    try testing.expectError(error.FileNotFound, out.access("link.txt", .{}));
}

test "extracts every supported method combination" {
    const names = [_][]const u8{
        "lzma2.7z",    "lzma.7z",     "copy.7z",           "bcj_lzma.7z",        "bcj_lzma2.7z",
        "nonsolid.7z", "plainhdr.7z", "smalldict_lzma.7z", "smalldict_lzma2.7z",
    };
    for (names) |name| {
        const bytes = try fixture(testing.allocator, name);
        defer testing.allocator.free(bytes);
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        extractBytes(&tmp, bytes, .{}) catch |e| {
            std.debug.print("fixture {s} failed: {s}\n", .{ name, @errorName(e) });
            return e;
        };
        var out = try tmp.dir.openDir("out", .{});
        defer out.close();
        expectStandardTree(out) catch |e| {
            std.debug.print("fixture {s} tree mismatch: {s}\n", .{ name, @errorName(e) });
            return e;
        };
    }
}

test "LZMA2 with uncompressed and compressed chunks mixed" {
    const bytes = try fixture(testing.allocator, "lzma2_mixed.7z");
    defer testing.allocator.free(bytes);
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try extractBytes(&tmp, bytes, .{});
    var out = try tmp.dir.openDir("out", .{});
    defer out.close();

    const random = try out.readFileAlloc(testing.allocator, "random.bin", 1 << 20);
    defer testing.allocator.free(random);
    try testing.expectEqual(@as(usize, 140000), random.len);
    try testing.expectEqual(@as(u32, 0x19AFDAAC), Crc32.hash(random));
    const text = try out.readFileAlloc(testing.allocator, "tail.txt", 1 << 20);
    defer testing.allocator.free(text);
    try testing.expectEqual(@as(usize, 20000), text.len);
}

test "unsupported methods and encryption are refused before anything is written" {
    const names = [_][]const u8{ "ppmd.7z", "bzip2.7z", "deflate.7z", "bcj2.7z", "enc_data.7z", "enc_hdr.7z" };
    for (names) |name| {
        const bytes = try fixture(testing.allocator, name);
        defer testing.allocator.free(bytes);
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        try testing.expectError(error.Unsupported7zMethod, extractBytes(&tmp, bytes, .{}));
        var out = try tmp.dir.openDir("out", .{});
        defer out.close();
        try testing.expect(try dirIsEmpty(out));
    }
}

test "corrupted bytes are checksum errors" {
    const orig = try fixture(testing.allocator, "copy.7z");
    defer testing.allocator.free(orig);

    // Packed data: only the per-file CRC can notice.
    {
        const bytes = try testing.allocator.dupe(u8, orig);
        defer testing.allocator.free(bytes);
        bytes[40] ^= 0x01;
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        try testing.expectError(error.Crc7zMismatch, extractBytes(&tmp, bytes, .{}));
    }
    // Header.
    {
        const bytes = try testing.allocator.dupe(u8, orig);
        defer testing.allocator.free(bytes);
        bytes[bytes.len - 3] ^= 0x01;
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        try testing.expectError(error.Crc7zMismatch, extractBytes(&tmp, bytes, .{}));
    }
    // Start header.
    {
        const bytes = try testing.allocator.dupe(u8, orig);
        defer testing.allocator.free(bytes);
        bytes[14] ^= 0x01;
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        try testing.expectError(error.Crc7zMismatch, extractBytes(&tmp, bytes, .{}));
    }
    // Compressed data, solid LZMA2 and BCJ: any failure is fine, success is not.
    for ([_][]const u8{ "lzma2.7z", "lzma.7z", "bcj_lzma.7z", "nonsolid.7z" }) |name| {
        const clean = try fixture(testing.allocator, name);
        defer testing.allocator.free(clean);
        var i: usize = 33;
        while (i < 33 + 400) : (i += 37) {
            const bytes = try testing.allocator.dupe(u8, clean);
            defer testing.allocator.free(bytes);
            bytes[i] ^= 0x10;
            var tmp = testing.tmpDir(.{});
            defer tmp.cleanup();
            if (extractBytes(&tmp, bytes, .{})) |_| {
                return error.TestUnexpectedResult;
            } else |_| {}
        }
    }
}

test "truncated archives fail cleanly" {
    const orig = try fixture(testing.allocator, "lzma2.7z");
    defer testing.allocator.free(orig);
    for ([_]usize{ 0, 10, 31, 32, 100, orig.len / 2, orig.len - 1 }) |len| {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        if (extractBytes(&tmp, orig[0..len], .{})) |_| {
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

test "empty archive and non-archive" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // The signature header of an archive with no entries: zero-sized header.
    var bytes = [_]u8{0} ** 32;
    @memcpy(bytes[0..6], &magic);
    bytes[7] = 4;
    std.mem.writeInt(u32, bytes[8..12], Crc32.hash(bytes[12..32]), .little);
    try extractBytes(&tmp, &bytes, .{});

    var tmp2 = testing.tmpDir(.{});
    defer tmp2.cleanup();
    try testing.expectError(error.Corrupt7z, extractBytes(&tmp2, "<!DOCTYPE html><html>not an archive at all</html>", .{}));
}

// ---- hand-built archives ----

const TestFile = struct {
    name: []const u8,
    /// Null means a directory.
    data: ?[]const u8 = null,
    attr: ?u32 = null,
};

fn putNumber(list: *std.ArrayList(u8), v: u64) !void {
    // Always the widest form; it exercises the decoder's multi-byte path.
    if (v < 0x80) {
        try list.append(@intCast(v));
    } else {
        try list.append(0xFF);
        try list.writer().writeInt(u64, v, .little);
    }
}

/// A Copy-method archive: one folder per file with data, a plain header.
fn buildCopy7z(a: Allocator, files: []const TestFile) ![]u8 {
    var packed_data = std.ArrayList(u8).init(a);
    defer packed_data.deinit();
    var h = std.ArrayList(u8).init(a);
    defer h.deinit();

    var streams: usize = 0;
    for (files) |f| {
        if (f.data) |d| {
            if (d.len > 0) streams += 1;
        }
    }

    try h.append(k_header);
    if (streams > 0) {
        try h.append(k_main_streams_info);
        try h.append(k_pack_info);
        try putNumber(&h, 0);
        try putNumber(&h, streams);
        try h.append(k_size);
        for (files) |f| if (f.data) |d| if (d.len > 0) {
            try putNumber(&h, d.len);
            try packed_data.appendSlice(d);
        };
        try h.append(k_end);

        try h.append(k_unpack_info);
        try h.append(k_folder);
        try putNumber(&h, streams);
        try h.append(0);
        for (0..streams) |_| {
            try h.append(1); // one coder
            try h.append(0x01); // 1-byte id, simple
            try h.append(id_copy);
        }
        try h.append(k_coders_unpack_size);
        for (files) |f| if (f.data) |d| if (d.len > 0) try putNumber(&h, d.len);
        try h.append(k_crc);
        try h.append(1); // all defined
        for (files) |f| if (f.data) |d| if (d.len > 0) try h.writer().writeInt(u32, Crc32.hash(d), .little);
        try h.append(k_end);

        try h.append(k_substreams_info);
        try h.append(k_end);
        try h.append(k_end);
    }

    try h.append(k_files_info);
    try putNumber(&h, files.len);

    var any_empty = false;
    for (files) |f| {
        if (f.data == null or f.data.?.len == 0) any_empty = true;
    }
    if (any_empty) {
        const nbytes = (files.len + 7) / 8;
        try h.append(k_empty_stream);
        try putNumber(&h, nbytes);
        var bits = try a.alloc(u8, nbytes);
        defer a.free(bits);
        @memset(bits, 0);
        for (files, 0..) |f, i| {
            if (f.data == null or f.data.?.len == 0) bits[i / 8] |= @as(u8, 0x80) >> @intCast(i % 8);
        }
        try h.appendSlice(bits);

        // Empty files (as opposed to directories), indexed over empty streams.
        var n_empty: usize = 0;
        for (files) |f| {
            if (f.data == null or f.data.?.len == 0) n_empty += 1;
        }
        const ebytes = (n_empty + 7) / 8;
        var ebits = try a.alloc(u8, ebytes);
        defer a.free(ebits);
        @memset(ebits, 0);
        var k: usize = 0;
        for (files) |f| {
            if (f.data == null or f.data.?.len == 0) {
                if (f.data != null) ebits[k / 8] |= @as(u8, 0x80) >> @intCast(k % 8);
                k += 1;
            }
        }
        try h.append(k_empty_file);
        try putNumber(&h, ebytes);
        try h.appendSlice(ebits);
    }

    var names = std.ArrayList(u8).init(a);
    defer names.deinit();
    try names.append(0); // not external
    for (files) |f| {
        for (f.name) |c| {
            try names.append(c);
            try names.append(0);
        }
        try names.appendSlice(&.{ 0, 0 });
    }
    try h.append(k_names);
    try putNumber(&h, names.items.len);
    try h.appendSlice(names.items);

    var any_attr = false;
    for (files) |f| {
        if (f.attr != null) any_attr = true;
    }
    if (any_attr) {
        try h.append(k_win_attributes);
        try putNumber(&h, 2 + files.len * 4);
        try h.append(1); // all defined
        try h.append(0); // not external
        for (files) |f| try h.writer().writeInt(u32, f.attr orelse 0x20, .little);
    }
    try h.append(k_end);
    try h.append(k_end);

    var out = std.ArrayList(u8).init(a);
    errdefer out.deinit();
    var start = [_]u8{0} ** 20;
    std.mem.writeInt(u64, start[0..8], packed_data.items.len, .little);
    std.mem.writeInt(u64, start[8..16], h.items.len, .little);
    std.mem.writeInt(u32, start[16..20], Crc32.hash(h.items), .little);
    try out.appendSlice(&magic);
    try out.appendSlice(&.{ 0, 4 });
    try out.writer().writeInt(u32, Crc32.hash(&start), .little);
    try out.appendSlice(&start);
    try out.appendSlice(packed_data.items);
    try out.appendSlice(h.items);
    return out.toOwnedSlice();
}

test "hand-built Copy archive extracts, including empty files and directories" {
    const bytes = try buildCopy7z(testing.allocator, &.{
        .{ .name = "d" },
        .{ .name = "d/a.txt", .data = "alpha" },
        .{ .name = "d\\b.txt", .data = "bravo" }, // backslash is a separator
        .{ .name = "empty", .data = "" },
        .{ .name = "z.txt", .data = "zulu" },
    });
    defer testing.allocator.free(bytes);
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try extractBytes(&tmp, bytes, .{});
    var out = try tmp.dir.openDir("out", .{});
    defer out.close();

    for ([_][2][]const u8{ .{ "d/a.txt", "alpha" }, .{ "d/b.txt", "bravo" }, .{ "z.txt", "zulu" } }) |p| {
        const got = try out.readFileAlloc(testing.allocator, p[0], 64);
        defer testing.allocator.free(got);
        try testing.expectEqualStrings(p[1], got);
    }
    try testing.expectEqual(@as(u64, 0), (try out.statFile("empty")).size);
}

test "unsafe member names refuse the whole archive and write nothing" {
    const bad_names = [_][]const u8{
        "..\\evil.txt",
        "../evil.txt",
        "C:/x",
        "C:\\x",
        "C:x",
        "/abs.txt",
        "\\\\srv\\share\\x",
        "a/../../b",
        "a\\..\\..\\b",
        "a.txt:stream",
        "a//b",
        "dir/",
    };
    for (bad_names) |name| {
        // The safe member comes first, so it would be written before the bad
        // one was reached if names were checked lazily.
        const bytes = try buildCopy7z(testing.allocator, &.{
            .{ .name = "ok.txt", .data = "fine" },
            .{ .name = name, .data = "pwned" },
        });
        defer testing.allocator.free(bytes);
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        try testing.expectError(error.UnsafeArchiveMember, extractBytes(&tmp, bytes, .{}));
        var out = try tmp.dir.openDir("out", .{});
        defer out.close();
        try testing.expect(try dirIsEmpty(out));
        try testing.expectError(error.FileNotFound, tmp.parent_dir.access("evil.txt", .{}));
    }
}

test "links are skipped, setuid bits are dropped" {
    const exec_suid: u32 = 0x8000 | (@as(u32, 0o104755) << 16) | 0x20;
    const symlink: u32 = 0x8000 | (@as(u32, 0o120777) << 16) | 0x20;
    const reparse: u32 = 0x400 | 0x20;
    const bytes = try buildCopy7z(testing.allocator, &.{
        .{ .name = "bin/tool", .data = "#!/bin/sh\n", .attr = exec_suid },
        .{ .name = "link", .data = "tool", .attr = symlink },
        .{ .name = "junction", .data = "C:\\Windows", .attr = reparse },
        .{ .name = "plain.txt", .data = "plain", .attr = 0x20 },
    });
    defer testing.allocator.free(bytes);
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try extractBytes(&tmp, bytes, .{});
    var out = try tmp.dir.openDir("out", .{});
    defer out.close();

    try testing.expectError(error.FileNotFound, out.access("link", .{}));
    try testing.expectError(error.FileNotFound, out.access("junction", .{}));
    const plain = try out.readFileAlloc(testing.allocator, "plain.txt", 16);
    defer testing.allocator.free(plain);
    try testing.expectEqualStrings("plain", plain);

    if (!platform.is_windows) {
        const st = try out.statFile("bin/tool");
        try testing.expectEqual(@as(std.fs.File.Mode, 0), st.mode & 0o7000);
        try testing.expectEqual(@as(std.fs.File.Mode, 0o755), st.mode & 0o777);
        const pst = try out.statFile("plain.txt");
        try testing.expectEqual(@as(std.fs.File.Mode, 0o644), pst.mode & 0o777);
    }
}

test "member and byte limits are enforced before extraction" {
    const bytes = try buildCopy7z(testing.allocator, &.{
        .{ .name = "a", .data = "1" },
        .{ .name = "b", .data = "22" },
        .{ .name = "c", .data = "333" },
    });
    defer testing.allocator.free(bytes);

    {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        try testing.expectError(error.ArchiveTooManyMembers, extractBytes(&tmp, bytes, .{ .max_members = 2 }));
        var out = try tmp.dir.openDir("out", .{});
        defer out.close();
        try testing.expect(try dirIsEmpty(out));
    }
    {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        try testing.expectError(error.ArchiveTooLarge, extractBytes(&tmp, bytes, .{ .max_bytes = 5 }));
        var out = try tmp.dir.openDir("out", .{});
        defer out.close();
        try testing.expect(try dirIsEmpty(out));
    }
    {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        try extractBytes(&tmp, bytes, .{ .max_members = 3, .max_bytes = 6 });
        var out = try tmp.dir.openDir("out", .{});
        defer out.close();
        try out.access("c", .{});
    }
}

test "strip_components applies after validation" {
    const bytes = try buildCopy7z(testing.allocator, &.{
        .{ .name = "pkg-1.0" },
        .{ .name = "pkg-1.0/bin/tool.exe", .data = "MZ" },
        .{ .name = "top.txt", .data = "gone" },
    });
    defer testing.allocator.free(bytes);
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try extractBytes(&tmp, bytes, .{ .strip_components = 1 });
    var out = try tmp.dir.openDir("out", .{});
    defer out.close();
    try out.access("bin/tool.exe", .{});
    try testing.expectError(error.FileNotFound, out.access("top.txt", .{}));
    try testing.expectError(error.FileNotFound, out.access("pkg-1.0", .{}));
}

test "header numbers are bounds-checked" {
    var r = Reader{ .buf = &.{ 0xFF, 1, 2, 3 } };
    try testing.expectError(error.Corrupt7z, r.number());
    r = Reader{ .buf = &.{ 0x05, 0x99 } };
    try testing.expectEqual(@as(u64, 5), try r.number());
    r = Reader{ .buf = &.{ 0x81, 0x02 } };
    try testing.expectEqual(@as(u64, 0x102), try r.number());
    r = Reader{ .buf = &.{ 0xC1, 0x02, 0x03 } };
    try testing.expectEqual(@as(u64, 0x010302), try r.number());
    r = Reader{ .buf = &.{ 0xFF, 1, 0, 0, 0, 0, 0, 0, 0x80 } };
    try testing.expectEqual(@as(u64, 0x8000000000000001), try r.number());
    r = Reader{ .buf = &.{ 0x20, 0x20 } };
    try testing.expectError(error.Corrupt7z, r.bytes(3));
    try testing.expectError(error.Corrupt7z, r.count(5));
}

test "x86 filter output does not depend on how the input is chunked" {
    var prng = std.Random.DefaultPrng.init(42);
    const rnd = prng.random();
    const data = try testing.allocator.alloc(u8, 200_000);
    defer testing.allocator.free(data);
    for (data) |*b| {
        b.* = switch (rnd.uintLessThan(u8, 8)) {
            0 => 0xE8,
            1 => 0xE9,
            2 => 0x00,
            3 => 0xFF,
            else => rnd.int(u8),
        };
    }

    var whole = std.ArrayList(u8).init(testing.allocator);
    defer whole.deinit();
    var chunked = std.ArrayList(u8).init(testing.allocator);
    defer chunked.deinit();

    {
        var f = try X86Filter.init(testing.allocator);
        defer f.deinit();
        var sink = Sink{ .out = .{ .mem = &whole }, .bcj = &f };
        try sink.write(data);
        try sink.finish();
    }
    {
        var f = try X86Filter.init(testing.allocator);
        defer f.deinit();
        var sink = Sink{ .out = .{ .mem = &chunked }, .bcj = &f };
        var i: usize = 0;
        var size: usize = 1;
        while (i < data.len) {
            const n = @min(size, data.len - i);
            try sink.write(data[i..][0..n]);
            i += n;
            size = size % 9000 + 7;
        }
        try sink.finish();
    }
    try testing.expectEqual(data.len, whole.items.len);
    try testing.expectEqualSlices(u8, whole.items, chunked.items);
    // The filter really did rewrite something.
    try testing.expect(!std.mem.eql(u8, data, whole.items));
}
