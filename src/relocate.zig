//! Homebrew bottle relocation ("pouring").
//!
//! A bottle marked `:any` was built against the placeholder prefix
//! `@@HOMEBREW_PREFIX@@` and friends. Before it can run those placeholders
//! have to be replaced with real paths:
//!
//!   * ELF (Linux): the PT_INTERP string, DT_RUNPATH/DT_RPATH and any
//!     DT_NEEDED entry are rewritten in place inside the file image.
//!   * Mach-O (macOS, thin and fat): LC_LOAD_DYLIB-style commands and
//!     LC_RPATH are rebuilt, growing into the header padding when the new path
//!     is longer, and the file is ad hoc re-signed on macOS.
//!   * Everything else that is text: placeholders are substituted textually.
//!
//! Bottles are hostile input. Every header field is bounds checked, symlinks
//! are never followed, nothing outside the keg is touched, and every changed
//! file is replaced through a temp file + rename in its own directory (which
//! also breaks hard links, so a file shared with another tree is never
//! modified in place).

const std = @import("std");
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;

pub const Prefix = struct {
    /// Homebrew prefix, e.g. `<abv0 root>/brew`.
    prefix: []const u8,
    /// Cellar directory, e.g. `<prefix>/Cellar`.
    cellar: []const u8,
};

pub const Report = struct {
    elf_patched: u32 = 0,
    macho_patched: u32 = 0,
    text_patched: u32 = 0,
    /// Files left alone because they could not be handled (unsupported or
    /// oversized binaries, opaque binary blobs).
    skipped: u32 = 0,
    /// ELF files whose RUNPATH was too short for `$ORIGIN/../lib:<P>/lib` and
    /// got plain `$ORIGIN/../lib`. Their dependencies must be reachable from
    /// `<keg>/lib`, so the caller has to link them there another way.
    runpath_short: u32 = 0,
    /// Mach-O files that were modified but not re-signed (non-macOS host).
    /// They must be ad hoc signed before they run on Apple Silicon.
    signing_pending: u32 = 0,
};

pub const Host = struct {
    os: std.Target.Os.Tag,
    arch: std.Target.Cpu.Arch,
    /// Absolute path of the system dynamic loader to substitute into ELF
    /// PT_INTERP, or null when the host has no glibc loader (musl-only).
    elf_interpreter: ?[]const u8,
};

pub const Error = error{
    /// ELF with a Homebrew interpreter on a host without a glibc loader.
    NoGlibcLoader,
    /// The host loader path does not fit in the PT_INTERP segment.
    InterpreterTooLong,
    /// A DT_NEEDED entry with a placeholder grows beyond its string.
    NeededTooLong,
    /// Mach-O load commands cannot grow: not enough header padding.
    NoHeaderPad,
    InvalidPrefix,
    TooManyFiles,
    TooMuchData,
    TreeTooDeep,
};

pub const max_files: u32 = 200_000;
pub const max_total_bytes: u64 = 16 * 1024 * 1024 * 1024;
pub const max_text_bytes: u64 = 16 * 1024 * 1024;
pub const max_binary_bytes: u64 = 512 * 1024 * 1024;
const max_depth = 64;
const text_probe_len = 8192;

/// Pick the glibc loader this machine provides, if any. abv0 itself is a
/// static musl binary, so the loader cannot be read from /proc/self/exe.
pub fn detectHost(a: Allocator) !Host {
    _ = a;
    const arch = builtin.cpu.arch;
    var interp: ?[]const u8 = null;
    if (builtin.os.tag == .linux) {
        const candidates: []const []const u8 = switch (arch) {
            .x86_64 => &.{ "/lib64/ld-linux-x86-64.so.2", "/usr/lib64/ld-linux-x86-64.so.2" },
            .aarch64 => &.{ "/lib/ld-linux-aarch64.so.1", "/usr/lib/ld-linux-aarch64.so.1" },
            else => &.{},
        };
        for (candidates) |c| {
            if (std.fs.cwd().statFile(c)) |_| {
                interp = c;
                break;
            } else |_| {}
        }
    }
    return .{ .os = builtin.os.tag, .arch = arch, .elf_interpreter = interp };
}

// ---------------------------------------------------------------------------
// Placeholder substitution
// ---------------------------------------------------------------------------

const marker = "@@HOMEBREW_";
const prefix_placeholder = "@@HOMEBREW_PREFIX@@";

const Placeholder = struct { name: []const u8, value: []const u8 };

const Subst = struct {
    items: [6]Placeholder,

    /// `arena` owns the derived strings.
    fn init(arena: Allocator, p: Prefix, os: std.Target.Os.Tag) !Subst {
        const library = try std.fmt.allocPrint(arena, "{s}/Library", .{p.prefix});
        const perl = if (os == .macos) "/usr/bin/perl" else try std.fmt.allocPrint(arena, "{s}/opt/perl/bin/perl", .{p.prefix});
        const java = try std.fmt.allocPrint(arena, "{s}/opt/openjdk/bin/java", .{p.prefix});
        return .{ .items = .{
            .{ .name = "@@HOMEBREW_PREFIX@@", .value = p.prefix },
            .{ .name = "@@HOMEBREW_CELLAR@@", .value = p.cellar },
            .{ .name = "@@HOMEBREW_REPOSITORY@@", .value = p.prefix },
            .{ .name = "@@HOMEBREW_LIBRARY@@", .value = library },
            .{ .name = "@@HOMEBREW_PERL@@", .value = perl },
            .{ .name = "@@HOMEBREW_JAVA@@", .value = java },
        } };
    }

    /// First known placeholder at or after `from`.
    fn find(self: *const Subst, s: []const u8, from: usize) ?struct { pos: usize, item: Placeholder } {
        var i = from;
        while (std.mem.indexOfPos(u8, s, i, marker)) |pos| {
            for (self.items) |it| {
                if (std.mem.startsWith(u8, s[pos..], it.name)) return .{ .pos = pos, .item = it };
            }
            i = pos + marker.len;
        }
        return null;
    }

    fn has(self: *const Subst, s: []const u8) bool {
        return self.find(s, 0) != null;
    }

    /// Copy of `s` with every placeholder expanded, or null when it has none.
    fn replaceAll(self: *const Subst, a: Allocator, s: []const u8) !?[]u8 {
        var first = self.find(s, 0) orelse return null;
        var out = std.ArrayList(u8).init(a);
        errdefer out.deinit();
        var last: usize = 0;
        while (true) {
            try out.appendSlice(s[last..first.pos]);
            try out.appendSlice(first.item.value);
            last = first.pos + first.item.name.len;
            first = self.find(s, last) orelse break;
        }
        try out.appendSlice(s[last..]);
        return try out.toOwnedSlice();
    }
};

// ---------------------------------------------------------------------------
// Bounds-checked readers
// ---------------------------------------------------------------------------

const Range = struct { start: usize, end: usize };

fn range(len: usize, off: u64, size: u64) error{Malformed}!Range {
    const end = std.math.add(u64, off, size) catch return error.Malformed;
    if (end > len) return error.Malformed;
    return .{ .start = @intCast(off), .end = @intCast(end) };
}

fn rd(comptime T: type, buf: []const u8, off: u64, endian: std.builtin.Endian) error{Malformed}!T {
    const r = try range(buf.len, off, @sizeOf(T));
    return std.mem.readInt(T, buf[r.start..][0..@sizeOf(T)], endian);
}

fn isAllZero(s: []const u8) bool {
    for (s) |b| if (b != 0) return false;
    return true;
}

/// Overwrite `dst` with `src` and NUL-pad the remainder. `src.len <= dst.len`.
fn overwritePadded(dst: []u8, src: []const u8) void {
    std.debug.assert(src.len <= dst.len);
    @memcpy(dst[0..src.len], src);
    @memset(dst[src.len..], 0);
}

// ---------------------------------------------------------------------------
// ELF
// ---------------------------------------------------------------------------

const elf_magic = "\x7fELF";
const pt_load = 1;
const pt_dynamic = 2;
const pt_interp = 3;
const dt_needed = 1;
const dt_strtab = 5;
const dt_strsz = 10;
const dt_rpath = 15;
const dt_runpath = 29;

const ElfOutcome = struct { changed: bool = false, runpath_short: bool = false };

const Phdr = struct { type: u32, offset: u64, vaddr: u64, filesz: u64 };

fn elfPhdr(buf: []const u8, phoff: u64, i: u64) error{Malformed}!Phdr {
    const base = std.math.add(u64, phoff, i * 56) catch return error.Malformed;
    return .{
        .type = try rd(u32, buf, base, .little),
        .offset = try rd(u64, buf, base + 8, .little),
        .vaddr = try rd(u64, buf, base + 16, .little),
        .filesz = try rd(u64, buf, base + 32, .little),
    };
}

fn elfVaddrToOff(buf: []const u8, phoff: u64, phnum: u64, vaddr: u64) error{Malformed}!?u64 {
    var i: u64 = 0;
    while (i < phnum) : (i += 1) {
        const ph = try elfPhdr(buf, phoff, i);
        if (ph.type != pt_load) continue;
        if (vaddr < ph.vaddr or vaddr - ph.vaddr >= ph.filesz) continue;
        return std.math.add(u64, ph.offset, vaddr - ph.vaddr) catch return error.Malformed;
    }
    return null;
}

fn isElf(buf: []const u8) bool {
    return buf.len >= 4 and std.mem.eql(u8, buf[0..4], elf_magic);
}

/// Patch an ELF64 little-endian image in place. `error.Unsupported` for
/// other ELF flavours, `error.Malformed` for inconsistent headers; in both
/// cases `buf` may be partially modified and must be discarded.
fn patchElf(a: Allocator, buf: []u8, subst: *const Subst, p: Prefix, host: Host) !ElfOutcome {
    if (buf.len < 64 or !isElf(buf)) return error.Unsupported;
    if (buf[4] != 2 or buf[5] != 1) return error.Unsupported; // ELFCLASS64, LSB
    const machine = try rd(u16, buf, 18, .little);
    if (machine != 62 and machine != 183) return error.Unsupported; // x86_64, aarch64

    const phoff = try rd(u64, buf, 0x20, .little);
    const phentsize = try rd(u16, buf, 0x36, .little);
    const phnum: u64 = try rd(u16, buf, 0x38, .little);
    if (phnum == 0) return .{};
    if (phentsize != 56) return error.Malformed;
    _ = try range(buf.len, phoff, phnum * 56);

    var out: ElfOutcome = .{};
    var dyn: ?Phdr = null;

    var i: u64 = 0;
    while (i < phnum) : (i += 1) {
        const ph = try elfPhdr(buf, phoff, i);
        switch (ph.type) {
            pt_dynamic => if (dyn == null) {
                dyn = ph;
            },
            pt_interp => {
                const r = try range(buf.len, ph.offset, ph.filesz);
                const region = buf[r.start..r.end];
                const nul = std.mem.indexOfScalar(u8, region, 0) orelse return error.Malformed;
                if (std.mem.indexOf(u8, region[0..nul], prefix_placeholder) == null) continue;
                const interp = host.elf_interpreter orelse return error.NoGlibcLoader;
                if (interp.len + 1 > region.len) return error.InterpreterTooLong;
                overwritePadded(region, interp);
                out.changed = true;
            },
            else => {},
        }
    }

    const d = dyn orelse return out;
    const dr = try range(buf.len, d.offset, d.filesz);
    const dyn_count = (dr.end - dr.start) / 16;

    var strtab: ?u64 = null;
    var strsz: ?u64 = null;
    var k: usize = 0;
    while (k < dyn_count) : (k += 1) {
        const o = dr.start + k * 16;
        const tag = try rd(i64, buf, o, .little);
        if (tag == 0) break;
        const val = try rd(u64, buf, o + 8, .little);
        if (tag == dt_strtab) strtab = val;
        if (tag == dt_strsz) strsz = val;
    }
    const st_vaddr = strtab orelse return out;
    const st_size = strsz orelse return out;
    const st_off = (try elfVaddrToOff(buf, phoff, phnum, st_vaddr)) orelse return error.Malformed;
    const sr = try range(buf.len, st_off, st_size);

    const run_a = try std.fmt.allocPrint(a, "$ORIGIN/../lib:{s}/lib", .{p.prefix});
    defer a.free(run_a);
    const run_b = "$ORIGIN/../lib";

    k = 0;
    while (k < dyn_count) : (k += 1) {
        const o = dr.start + k * 16;
        const tag = try rd(i64, buf, o, .little);
        if (tag == 0) break;
        if (tag != dt_needed and tag != dt_rpath and tag != dt_runpath) continue;
        const val = try rd(u64, buf, o + 8, .little);
        if (val >= st_size) return error.Malformed;
        const tab = buf[sr.start..sr.end];
        const rest = tab[@intCast(val)..];
        const len = std.mem.indexOfScalar(u8, rest, 0) orelse return error.Malformed;
        const s = rest[0..len];
        if (!subst.has(s)) continue;

        if (tag == dt_needed) {
            const repl = (try subst.replaceAll(a, s)).?;
            defer a.free(repl);
            if (repl.len > s.len) return error.NeededTooLong;
            overwritePadded(s, repl);
        } else if (run_a.len <= s.len) {
            overwritePadded(s, run_a);
        } else {
            overwritePadded(s, run_b);
            out.runpath_short = true;
        }
        out.changed = true;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Mach-O
// ---------------------------------------------------------------------------

const mh_magic_64: u32 = 0xfeedfacf;
const lc_segment_64: u32 = 0x19;
const lc_id_dylib: u32 = 0xd;
const lc_load_dylib: u32 = 0xc;
const lc_lazy_load_dylib: u32 = 0x20;
const lc_load_weak_dylib: u32 = 0x80000018;
const lc_reexport_dylib: u32 = 0x8000001f;
const lc_load_upward_dylib: u32 = 0x80000023;
const lc_rpath: u32 = 0x8000001c;

/// Magic numbers as read little-endian from the first four bytes.
const magic_thin_64_le: u32 = 0xfeedfacf; // CF FA ED FE
const magic_thin_32_le: u32 = 0xfeedface;
const magic_thin_be_32: u32 = 0xcefaedfe;
const magic_thin_be_64: u32 = 0xcffaedfe;
const magic_fat_le: u32 = 0xbebafeca; // CA FE BA BE
const magic_fat64_le: u32 = 0xbfbafeca; // CA FE BA BF

fn looksLikeMachO(head: []const u8) bool {
    if (head.len < 4) return false;
    return switch (std.mem.readInt(u32, head[0..4], .little)) {
        magic_thin_64_le, magic_thin_32_le, magic_thin_be_32, magic_thin_be_64, magic_fat_le, magic_fat64_le => true,
        else => false,
    };
}

fn dylibNameMin(cmd: u32) ?u32 {
    return switch (cmd) {
        lc_id_dylib, lc_load_dylib, lc_lazy_load_dylib, lc_load_weak_dylib, lc_reexport_dylib, lc_load_upward_dylib => 24,
        lc_rpath => 12,
        else => null,
    };
}

fn align8(n: usize) usize {
    return (n + 7) & ~@as(usize, 7);
}

/// Patch one thin 64-bit little-endian Mach-O image. Returns whether it
/// changed. Nothing is written unless the whole rewrite fits.
fn patchMachOThin(a: Allocator, s: []u8, subst: *const Subst) !bool {
    if (s.len < 32) return error.Malformed;
    const ncmds = try rd(u32, s, 16, .little);
    const sizeofcmds = try rd(u32, s, 20, .little);
    const cmds_end: u64 = 32 + @as(u64, sizeofcmds);
    if (cmds_end > s.len) return error.Malformed;
    if (ncmds > sizeofcmds / 8) return error.Malformed;

    // Where the header padding ends: the earliest file offset that holds
    // real data.
    var limit: u64 = s.len;
    var out = std.ArrayList(u8).init(a);
    defer out.deinit();
    var changed = false;

    var off: u64 = 32;
    var i: u32 = 0;
    while (i < ncmds) : (i += 1) {
        const cmd = try rd(u32, s, off, .little);
        const size = try rd(u32, s, off + 4, .little);
        if (size < 8 or size % 4 != 0) return error.Malformed;
        if (off + size > cmds_end) return error.Malformed;
        const body = s[@intCast(off)..@intCast(off + size)];

        if (cmd == lc_segment_64) {
            if (size < 72) return error.Malformed;
            const fileoff = try rd(u64, body, 40, .little);
            const filesize = try rd(u64, body, 48, .little);
            const nsects = try rd(u32, body, 64, .little);
            if (72 + @as(u64, nsects) * 80 > size) return error.Malformed;
            if (fileoff > 0 and filesize > 0) limit = @min(limit, fileoff);
            var si: u32 = 0;
            while (si < nsects) : (si += 1) {
                const so = 72 + @as(u64, si) * 80;
                const sect_size = try rd(u64, body, so + 40, .little);
                const sect_off = try rd(u32, body, so + 48, .little);
                const flags = try rd(u32, body, so + 64, .little);
                const typ = flags & 0xff;
                if (typ == 0x1 or typ == 0xc or typ == 0x12) continue; // zerofill
                if (sect_size > 0 and sect_off > 0) limit = @min(limit, sect_off);
            }
        }

        var replaced = false;
        if (dylibNameMin(cmd)) |name_min| {
            const name_off = try rd(u32, body, 8, .little);
            if (name_off < name_min or name_off >= size) return error.Malformed;
            const rest = body[name_off..];
            const len = std.mem.indexOfScalar(u8, rest, 0) orelse return error.Malformed;
            if (subst.has(rest[0..len])) {
                const repl = (try subst.replaceAll(a, rest[0..len])).?;
                defer a.free(repl);
                const new_size = align8(name_off + repl.len + 1);
                if (new_size > std.math.maxInt(u32)) return error.Malformed;
                const start = out.items.len;
                try out.appendSlice(body[0..name_off]);
                try out.appendSlice(repl);
                try out.appendNTimes(0, new_size - (name_off + repl.len));
                std.mem.writeInt(u32, out.items[start + 4 ..][0..4], @intCast(new_size), .little);
                replaced = true;
                changed = true;
            }
        }
        if (!replaced) try out.appendSlice(body);
        off += size;
    }
    if (off != cmds_end) return error.Malformed;
    if (!changed) return false;

    // The rewritten commands must fit before the first byte of real data.
    const new_total = out.items.len;
    if (new_total > sizeofcmds) {
        if (32 + @as(u64, new_total) > limit) return error.NoHeaderPad;
        if (!isAllZero(s[@intCast(cmds_end)..][0 .. 32 + new_total - @as(usize, @intCast(cmds_end))])) return error.NoHeaderPad;
    }
    @memcpy(s[32..][0..new_total], out.items);
    if (new_total < sizeofcmds) @memset(s[32 + new_total .. @as(usize, @intCast(cmds_end))], 0);
    std.mem.writeInt(u32, s[20..][0..4], @intCast(new_total), .little);
    return true;
}

/// Patch a thin or fat Mach-O file image. `error.NotMachO` when the bytes do
/// not hold a coherent Mach-O (e.g. a Java class file with the fat magic).
fn patchMachO(a: Allocator, buf: []u8, subst: *const Subst) !bool {
    if (buf.len < 8) return error.NotMachO;
    switch (std.mem.readInt(u32, buf[0..4], .little)) {
        magic_thin_64_le => return patchMachOThin(a, buf, subst),
        magic_thin_32_le, magic_thin_be_32, magic_thin_be_64 => return error.Unsupported,
        magic_fat_le, magic_fat64_le => |m| {
            const is64 = m == magic_fat64_le;
            const nfat = std.mem.readInt(u32, buf[4..8], .big);
            if (nfat == 0 or nfat > 32) return error.NotMachO;
            const entry: u64 = if (is64) 32 else 20;
            var slices: [32]Range = undefined;
            var i: u32 = 0;
            while (i < nfat) : (i += 1) {
                const eo = 8 + @as(u64, i) * entry;
                const so = if (is64) try rd(u64, buf, eo + 8, .big) else try rd(u32, buf, eo + 8, .big);
                const sz = if (is64) try rd(u64, buf, eo + 16, .big) else try rd(u32, buf, eo + 12, .big);
                slices[i] = range(buf.len, so, sz) catch return error.NotMachO;
            }
            var changed = false;
            i = 0;
            while (i < nfat) : (i += 1) {
                const sl = buf[slices[i].start..slices[i].end];
                if (sl.len < 4) return error.NotMachO;
                switch (std.mem.readInt(u32, sl[0..4], .little)) {
                    magic_thin_64_le => {
                        if (try patchMachOThin(a, sl, subst)) changed = true;
                    },
                    magic_thin_32_le, magic_thin_be_32, magic_thin_be_64 => {},
                    else => return error.NotMachO,
                }
            }
            return changed;
        },
        else => return error.NotMachO,
    }
}

/// Ad hoc re-sign a patched Mach-O. Returns false if signing did not happen.
fn codesign(a: Allocator, path: []const u8) bool {
    if (builtin.os.tag != .macos) return false;
    const res = std.process.Child.run(.{
        .allocator = a,
        .argv = &.{ "codesign", "--force", "--sign", "-", "--preserve-metadata=entitlements,requirements,flags,runtime", path },
    }) catch return false;
    defer a.free(res.stdout);
    defer a.free(res.stderr);
    return switch (res.term) {
        .Exited => |c| c == 0,
        else => false,
    };
}

// ---------------------------------------------------------------------------
// Tree walk
// ---------------------------------------------------------------------------

const Walker = struct {
    a: Allocator,
    subst: *const Subst,
    p: Prefix,
    host: Host,
    report: Report = .{},
    files: u32 = 0,
    bytes: u64 = 0,
    tmp_counter: u32 = 0,

    fn walkDir(self: *Walker, dir: std.fs.Dir, dir_path: []const u8, depth: u32) anyerror!void {
        if (depth > max_depth) return error.TreeTooDeep;
        const Entry = struct { name: []u8, kind: std.fs.File.Kind };
        var entries = std.ArrayList(Entry).init(self.a);
        defer {
            for (entries.items) |e| self.a.free(e.name);
            entries.deinit();
        }
        // Snapshot first: we rename files while walking.
        var it = dir.iterate();
        while (try it.next()) |e| {
            try entries.append(.{ .name = try self.a.dupe(u8, e.name), .kind = e.kind });
        }

        for (entries.items) |e| {
            switch (e.kind) {
                .file => try self.processFile(dir, dir_path, e.name),
                .directory => {
                    if (depth == 0 and std.mem.eql(u8, e.name, ".brew")) continue;
                    var sub = try dir.openDir(e.name, .{ .iterate = true, .no_follow = true });
                    defer sub.close();
                    const sub_path = try std.fs.path.join(self.a, &.{ dir_path, e.name });
                    defer self.a.free(sub_path);
                    try self.walkDir(sub, sub_path, depth + 1);
                },
                else => {}, // symlinks, devices, sockets: never touched
            }
        }
    }

    fn openNoFollow(dir: std.fs.Dir, name: []const u8) !std.fs.File {
        if (comptime builtin.os.tag == .windows) return dir.openFile(name, .{});
        const fd = try std.posix.openat(dir.fd, name, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        return .{ .handle = fd };
    }

    fn processFile(self: *Walker, dir: std.fs.Dir, dir_path: []const u8, name: []const u8) !void {
        const file = openNoFollow(dir, name) catch |err| switch (err) {
            // Raced with a symlink swap: not a regular file any more.
            error.SymLinkLoop, error.FileNotFound => return,
            else => return err,
        };
        defer file.close();
        const st = try file.stat();
        if (st.kind != .file) return;

        self.files += 1;
        if (self.files > max_files) return error.TooManyFiles;
        self.bytes += st.size;
        if (self.bytes > max_total_bytes) return error.TooMuchData;

        var head: [text_probe_len]u8 = undefined;
        const head_n = try file.preadAll(&head, 0);
        const head_s = head[0..head_n];

        const is_elf = isElf(head_s);
        const binary = is_elf or looksLikeMachO(head_s);
        if (binary) {
            if (st.size > max_binary_bytes) {
                self.report.skipped += 1;
                return;
            }
        } else if (st.size > max_text_bytes) {
            self.report.skipped += 1;
            return;
        }
        if (!binary and std.mem.indexOfScalar(u8, head_s, 0) != null) {
            self.report.skipped += 1;
            return;
        }

        const size: usize = @intCast(st.size);
        const buf = try self.a.alloc(u8, size);
        defer self.a.free(buf);
        if (try file.preadAll(buf, 0) != size) return; // truncated under us

        if (is_elf) {
            const o = patchElf(self.a, buf, self.subst, self.p, self.host) catch |err| switch (err) {
                error.Unsupported, error.Malformed => {
                    self.report.skipped += 1;
                    return;
                },
                else => return err,
            };
            if (o.changed) {
                try self.replaceFile(dir, name, st.mode, buf);
                self.report.elf_patched += 1;
            }
            if (o.runpath_short) self.report.runpath_short += 1;
            return;
        }

        if (binary) {
            const changed = patchMachO(self.a, buf, self.subst) catch |err| switch (err) {
                error.NotMachO => return self.handleText(dir, name, st.mode, buf),
                error.Unsupported, error.Malformed => {
                    self.report.skipped += 1;
                    return;
                },
                else => return err,
            };
            if (changed) {
                try self.replaceFile(dir, name, st.mode, buf);
                self.report.macho_patched += 1;
                const full = try std.fs.path.join(self.a, &.{ dir_path, name });
                defer self.a.free(full);
                if (!codesign(self.a, full)) self.report.signing_pending += 1;
            }
            return;
        }

        try self.handleText(dir, name, st.mode, buf);
    }

    fn handleText(self: *Walker, dir: std.fs.Dir, name: []const u8, mode: std.fs.File.Mode, buf: []const u8) !void {
        if (buf.len > max_text_bytes or std.mem.indexOfScalar(u8, buf[0..@min(buf.len, text_probe_len)], 0) != null) {
            self.report.skipped += 1;
            return;
        }
        const repl = (try self.subst.replaceAll(self.a, buf)) orelse return;
        defer self.a.free(repl);
        try self.replaceFile(dir, name, mode, repl);
        self.report.text_patched += 1;
    }

    /// Write `data` to a temp file next to `name`, restore the mode, rename
    /// over the original. The original inode (and any hard links) is left
    /// untouched.
    fn replaceFile(self: *Walker, dir: std.fs.Dir, name: []const u8, mode: std.fs.File.Mode, data: []const u8) !void {
        var tmp_buf: [64]u8 = undefined;
        self.tmp_counter += 1;
        const tmp = try std.fmt.bufPrint(&tmp_buf, ".abv0-reloc-{d}.tmp", .{self.tmp_counter});
        const f = try dir.createFile(tmp, .{ .exclusive = true, .mode = mode });
        var done = false;
        defer if (!done) dir.deleteFile(tmp) catch {};
        {
            defer f.close();
            try f.writeAll(data);
            if (comptime builtin.os.tag != .windows) try f.chmod(mode);
        }
        try dir.rename(tmp, name);
        done = true;
    }
};

/// Relocate every file under `keg_dir` in place. Never follows symlinks;
/// never touches files outside `keg_dir`.
pub fn relocateKeg(a: Allocator, keg_dir: []const u8, p: Prefix, host: Host) !Report {
    if (p.prefix.len == 0 or !std.fs.path.isAbsolute(p.prefix)) return error.InvalidPrefix;
    if (std.mem.indexOfScalar(u8, p.prefix, 0) != null or std.mem.indexOfScalar(u8, p.cellar, 0) != null) return error.InvalidPrefix;

    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const subst = try Subst.init(arena.allocator(), p, host.os);

    var root = try std.fs.cwd().openDir(keg_dir, .{ .iterate = true });
    defer root.close();

    var w = Walker{ .a = a, .subst = &subst, .p = p, .host = host };
    try w.walkDir(root, keg_dir, 0);
    return w.report;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const test_prefix: Prefix = .{ .prefix = "/opt/abv/brew", .cellar = "/opt/abv/brew/Cellar" };
const test_host: Host = .{ .os = .linux, .arch = .x86_64, .elf_interpreter = "/lib64/ld-linux-x86-64.so.2" };

fn putInt(buf: []u8, off: usize, comptime T: type, v: T, e: std.builtin.Endian) void {
    std.mem.writeInt(T, buf[off..][0..@sizeOf(T)], v, e);
}

/// Minimal ELF64: header, PT_INTERP, PT_LOAD (whole file), PT_DYNAMIC with
/// DT_NEEDED, DT_RUNPATH, DT_STRTAB, DT_STRSZ.
fn buildElf(a: Allocator, interp: []const u8, needed: []const u8, runpath: []const u8) ![]u8 {
    const buf = try a.alloc(u8, 0x400);
    @memset(buf, 0);
    @memcpy(buf[0..4], elf_magic);
    buf[4] = 2;
    buf[5] = 1;
    buf[6] = 1;
    putInt(buf, 16, u16, 3, .little); // ET_DYN
    putInt(buf, 18, u16, 62, .little);
    putInt(buf, 0x20, u64, 64, .little); // phoff
    putInt(buf, 0x36, u16, 56, .little);
    putInt(buf, 0x38, u16, 3, .little);

    const interp_off = 0x100;
    const strtab_off = 0x140;
    const dyn_off = 0x300;
    const base: u64 = 0x400000;

    // strtab: "\0" needed "\0" runpath "\0"
    var st: usize = strtab_off + 1;
    const needed_idx = st - strtab_off;
    @memcpy(buf[st..][0..needed.len], needed);
    st += needed.len + 1;
    const run_idx = st - strtab_off;
    @memcpy(buf[st..][0..runpath.len], runpath);
    st += runpath.len + 1;
    const strsz = st - strtab_off;
    @memcpy(buf[interp_off..][0..interp.len], interp);

    // PT_INTERP
    var ph: usize = 64;
    putInt(buf, ph, u32, pt_interp, .little);
    putInt(buf, ph + 8, u64, interp_off, .little);
    putInt(buf, ph + 16, u64, base + interp_off, .little);
    putInt(buf, ph + 32, u64, 30, .little);
    // PT_LOAD
    ph += 56;
    putInt(buf, ph, u32, pt_load, .little);
    putInt(buf, ph + 8, u64, 0, .little);
    putInt(buf, ph + 16, u64, base, .little);
    putInt(buf, ph + 32, u64, buf.len, .little);
    putInt(buf, ph + 40, u64, buf.len, .little);
    // PT_DYNAMIC
    ph += 56;
    putInt(buf, ph, u32, pt_dynamic, .little);
    putInt(buf, ph + 8, u64, dyn_off, .little);
    putInt(buf, ph + 16, u64, base + dyn_off, .little);
    putInt(buf, ph + 32, u64, 16 * 5, .little);

    const dyn = [_][2]u64{
        .{ dt_needed, needed_idx },
        .{ dt_runpath, run_idx },
        .{ dt_strtab, base + strtab_off },
        .{ dt_strsz, strsz },
        .{ 0, 0 },
    };
    for (dyn, 0..) |d, i| {
        putInt(buf, dyn_off + i * 16, u64, d[0], .little);
        putInt(buf, dyn_off + i * 16 + 8, u64, d[1], .little);
    }
    return buf;
}

/// Re-parse a (relocated) synthetic ELF: returns interp, needed and runpath.
fn readElf(buf: []const u8) !struct { interp: []const u8, needed: []const u8, runpath: []const u8 } {
    const interp_region = buf[0x100..][0..30];
    const interp = interp_region[0..std.mem.indexOfScalar(u8, interp_region, 0).?];
    const strtab = buf[0x140..];
    const ni = try rd(u64, buf, 0x300 + 8, .little);
    const ri = try rd(u64, buf, 0x300 + 16 + 8, .little);
    const needed = std.mem.sliceTo(strtab[@intCast(ni)..], 0);
    const runpath = std.mem.sliceTo(strtab[@intCast(ri)..], 0);
    return .{ .interp = interp, .needed = needed, .runpath = runpath };
}

fn testSubst(arena: Allocator) !Subst {
    return Subst.init(arena, test_prefix, .linux);
}

test "ELF: interpreter and runpath rewritten in place" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const subst = try testSubst(arena.allocator());
    const buf = try buildElf(
        testing.allocator,
        "@@HOMEBREW_PREFIX@@/lib/ld.so",
        "libc.so.6",
        "@@HOMEBREW_PREFIX@@/Cellar/fd/10.5.0/lib:@@HOMEBREW_PREFIX@@/opt/gcc/lib/gcc/current:@@HOMEBREW_PREFIX@@/lib",
    );
    defer testing.allocator.free(buf);
    const len = buf.len;
    const out = try patchElf(testing.allocator, buf, &subst, test_prefix, test_host);
    try testing.expect(out.changed);
    try testing.expect(!out.runpath_short);
    try testing.expectEqual(len, buf.len);
    const r = try readElf(buf);
    try testing.expectEqualStrings("/lib64/ld-linux-x86-64.so.2", r.interp);
    try testing.expectEqualStrings("libc.so.6", r.needed);
    try testing.expectEqualStrings("$ORIGIN/../lib:/opt/abv/brew/lib", r.runpath);
}

test "ELF: short runpath falls back to $ORIGIN/../lib and is reported" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const subst = try testSubst(arena.allocator());
    const buf = try buildElf(testing.allocator, "@@HOMEBREW_PREFIX@@/lib/ld.so", "libc.so.6", "@@HOMEBREW_CELLAR@@");
    defer testing.allocator.free(buf);
    const out = try patchElf(testing.allocator, buf, &subst, test_prefix, test_host);
    try testing.expect(out.changed and out.runpath_short);
    try testing.expectEqualStrings("$ORIGIN/../lib", (try readElf(buf)).runpath);
}

test "ELF: no glibc loader, interpreter too long, needed too long" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const subst = try testSubst(arena.allocator());
    const buf = try buildElf(testing.allocator, "@@HOMEBREW_PREFIX@@/lib/ld.so", "libc.so.6", "x");
    defer testing.allocator.free(buf);
    const copy = try testing.allocator.dupe(u8, buf);
    defer testing.allocator.free(copy);

    var h = test_host;
    h.elf_interpreter = null;
    try testing.expectError(error.NoGlibcLoader, patchElf(testing.allocator, buf, &subst, test_prefix, h));
    h.elf_interpreter = "/a/very/long/path/to/a/loader/that/cannot/possibly/fit/ld.so";
    try testing.expectError(error.InterpreterTooLong, patchElf(testing.allocator, copy, &subst, test_prefix, h));

    const nb = try buildElf(testing.allocator, "/lib64/ld-linux-x86-64.so.2", "@@HOMEBREW_PREFIX@@", "x");
    defer testing.allocator.free(nb);
    const long: Prefix = .{ .prefix = "/opt/abv/brew-with-a-long-name", .cellar = "/c" };
    var arena2 = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena2.deinit();
    const s2 = try Subst.init(arena2.allocator(), long, .linux);
    try testing.expectError(error.NeededTooLong, patchElf(testing.allocator, nb, &s2, long, test_host));
}

test "ELF: hostile headers are rejected, never read out of bounds" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const subst = try testSubst(arena.allocator());
    const good = try buildElf(testing.allocator, "@@HOMEBREW_PREFIX@@/lib/ld.so", "libc.so.6", "@@HOMEBREW_PREFIX@@/lib");
    defer testing.allocator.free(good);

    // Truncate at every length: must error or succeed, never trap.
    var n: usize = 0;
    while (n < good.len) : (n += 7) {
        const t = try testing.allocator.dupe(u8, good[0..n]);
        defer testing.allocator.free(t);
        _ = patchElf(testing.allocator, t, &subst, test_prefix, test_host) catch {};
    }
    // Corrupt single 8-byte fields across the headers.
    var off: usize = 0;
    while (off < 0x340) : (off += 8) {
        const t = try testing.allocator.dupe(u8, good);
        defer testing.allocator.free(t);
        @memset(t[off..][0..8], 0xff);
        _ = patchElf(testing.allocator, t, &subst, test_prefix, test_host) catch {};
    }
}

/// Synthetic Mach-O: one __TEXT segment with one section at `sect_off`, then
/// LC_LOAD_DYLIB with `dylib`.
fn buildMachO(a: Allocator, dylib: []const u8, sect_off: u32) ![]u8 {
    const buf = try a.alloc(u8, 0x400);
    @memset(buf, 0);
    putInt(buf, 0, u32, mh_magic_64, .little);
    putInt(buf, 4, u32, 0x0100000c, .little); // arm64
    putInt(buf, 12, u32, 2, .little); // MH_EXECUTE
    const dylib_size = align8(24 + dylib.len + 1);
    const seg_size = 72 + 80;
    putInt(buf, 16, u32, 2, .little);
    putInt(buf, 20, u32, @intCast(seg_size + dylib_size), .little);

    var o: usize = 32;
    putInt(buf, o, u32, lc_segment_64, .little);
    putInt(buf, o + 4, u32, seg_size, .little);
    @memcpy(buf[o + 8 ..][0..6], "__TEXT");
    putInt(buf, o + 40, u64, 0, .little); // fileoff
    putInt(buf, o + 48, u64, buf.len, .little); // filesize
    putInt(buf, o + 64, u32, 1, .little); // nsects
    const s = o + 72;
    @memcpy(buf[s..][0..6], "__text");
    putInt(buf, s + 40, u64, 16, .little); // size
    putInt(buf, s + 48, u32, sect_off, .little); // offset
    @memset(buf[sect_off..][0..16], 0x90);

    o += seg_size;
    putInt(buf, o, u32, lc_load_dylib, .little);
    putInt(buf, o + 4, u32, @intCast(dylib_size), .little);
    putInt(buf, o + 8, u32, 24, .little);
    @memcpy(buf[o + 24 ..][0..dylib.len], dylib);
    return buf;
}

fn machoDylib(buf: []const u8) ![]const u8 {
    const o = 32 + 72 + 80;
    const size = try rd(u32, buf, o + 4, .little);
    const name_off = try rd(u32, buf, o + 8, .little);
    try testing.expectEqual(@as(u32, 0), size % 8);
    try testing.expectEqual(@as(u32, @intCast(152 + size)), try rd(u32, buf, 20, .little));
    return std.mem.sliceTo(buf[o + name_off ..], 0);
}

test "Mach-O: dylib path grows into header padding" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const subst = try testSubst(arena.allocator());
    const buf = try buildMachO(testing.allocator, "@@HOMEBREW_PREFIX@@/opt/pcre2/lib/libpcre2-8.0.dylib", 0x300);
    defer testing.allocator.free(buf);
    try testing.expect(try patchMachO(testing.allocator, buf, &subst));
    try testing.expectEqualStrings("/opt/abv/brew/opt/pcre2/lib/libpcre2-8.0.dylib", try machoDylib(buf));
    // Section data after the padding is untouched.
    try testing.expectEqual(@as(u8, 0x90), buf[0x300]);
    // Idempotent.
    try testing.expect(!(try patchMachO(testing.allocator, buf, &subst)));
}

test "Mach-O: shorter path shrinks the load command" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const short: Prefix = .{ .prefix = "/p", .cellar = "/p/Cellar" };
    const subst = try Subst.init(arena.allocator(), short, .macos);
    const buf = try buildMachO(testing.allocator, "@@HOMEBREW_PREFIX@@/lib/libx.dylib", 0x300);
    defer testing.allocator.free(buf);
    try testing.expect(try patchMachO(testing.allocator, buf, &subst));
    try testing.expectEqualStrings("/p/lib/libx.dylib", try machoDylib(buf));
}

test "Mach-O: no header padding is an error and leaves the file unchanged" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const long: Prefix = .{ .prefix = "/very/long/prefix/for/the/abv0/brew/root", .cellar = "/c" };
    const subst = try Subst.init(arena.allocator(), long, .linux);
    // Section data starts immediately after the load commands.
    const dylib = "@@HOMEBREW_PREFIX@@/lib/libx.dylib";
    const first_free = 32 + 152 + align8(24 + dylib.len + 1);
    const buf = try buildMachO(testing.allocator, dylib, @intCast(first_free));
    defer testing.allocator.free(buf);
    const before = try testing.allocator.dupe(u8, buf);
    defer testing.allocator.free(before);
    try testing.expectError(error.NoHeaderPad, patchMachO(testing.allocator, buf, &subst));
    try testing.expectEqualSlices(u8, before, buf);
}

test "Mach-O: fat binary patches each architecture" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const subst = try testSubst(arena.allocator());
    const a1 = try buildMachO(testing.allocator, "@@HOMEBREW_PREFIX@@/lib/liba.dylib", 0x300);
    defer testing.allocator.free(a1);
    const fat = try testing.allocator.alloc(u8, 0x1000 + a1.len);
    defer testing.allocator.free(fat);
    @memset(fat, 0);
    putInt(fat, 0, u32, 0xcafebabe, .big);
    putInt(fat, 4, u32, 2, .big);
    for (0..2) |i| {
        const e = 8 + i * 20;
        putInt(fat, e, u32, 0x0100000c, .big);
        putInt(fat, e + 8, u32, @intCast(0x400 + i * 0x800), .big);
        putInt(fat, e + 12, u32, @intCast(a1.len), .big);
        @memcpy(fat[0x400 + i * 0x800 ..][0..a1.len], a1);
    }
    try testing.expect(try patchMachO(testing.allocator, fat, &subst));
    try testing.expectEqualStrings("/opt/abv/brew/lib/liba.dylib", try machoDylib(fat[0x400..][0..a1.len]));
    try testing.expectEqualStrings("/opt/abv/brew/lib/liba.dylib", try machoDylib(fat[0xc00..][0..a1.len]));
}

test "Mach-O: Java class file with the fat magic is not Mach-O" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const subst = try testSubst(arena.allocator());
    var cls = [_]u8{ 0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0x34, 0, 1, 2, 3 };
    try testing.expectError(error.NotMachO, patchMachO(testing.allocator, &cls, &subst));
}

test "text substitution expands every placeholder kind" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const subst = try testSubst(arena.allocator());
    const out = (try subst.replaceAll(testing.allocator, "a @@HOMEBREW_PREFIX@@ b @@HOMEBREW_CELLAR@@/x @@HOMEBREW_LIBRARY@@ @@HOMEBREW_UNKNOWN@@ @@HOMEBREW_PERL@@")).?;
    defer testing.allocator.free(out);
    try testing.expectEqualStrings(
        "a /opt/abv/brew b /opt/abv/brew/Cellar/x /opt/abv/brew/Library @@HOMEBREW_UNKNOWN@@ /opt/abv/brew/opt/perl/bin/perl",
        out,
    );
    try testing.expect((try subst.replaceAll(testing.allocator, "nothing here @@HOMEBREW_")) == null);
}

test "relocateKeg: whole keg, symlinks and .brew left alone" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);

    try tmp.dir.makePath("keg/bin");
    try tmp.dir.makePath("keg/lib");
    try tmp.dir.makePath("keg/share/doc");
    try tmp.dir.makePath("keg/.brew");
    try tmp.dir.makePath("outside");

    const elf = try buildElf(testing.allocator, "@@HOMEBREW_PREFIX@@/lib/ld.so", "libc.so.6", "@@HOMEBREW_PREFIX@@/Cellar/x/1/lib:@@HOMEBREW_PREFIX@@/lib");
    defer testing.allocator.free(elf);
    try tmp.dir.writeFile(.{ .sub_path = "keg/bin/tool", .data = elf, .flags = .{ .mode = 0o755 } });

    const macho = try buildMachO(testing.allocator, "@@HOMEBREW_PREFIX@@/opt/y/lib/liby.dylib", 0x300);
    defer testing.allocator.free(macho);
    try tmp.dir.writeFile(.{ .sub_path = "keg/lib/liby.dylib", .data = macho });

    try tmp.dir.writeFile(.{ .sub_path = "keg/share/script.sh", .data = "#!@@HOMEBREW_PREFIX@@/bin/sh\necho @@HOMEBREW_CELLAR@@\n", .flags = .{ .mode = 0o750 } });
    try tmp.dir.writeFile(.{ .sub_path = "keg/share/doc/blob.bin", .data = "bin\x00@@HOMEBREW_PREFIX@@" });
    try tmp.dir.writeFile(.{ .sub_path = "keg/.brew/x.rb", .data = "@@HOMEBREW_PREFIX@@" });
    try tmp.dir.writeFile(.{ .sub_path = "keg/share/plain.txt", .data = "nothing to do" });
    try tmp.dir.writeFile(.{ .sub_path = "outside/secret", .data = "@@HOMEBREW_PREFIX@@" });
    try tmp.dir.symLink("../../outside/secret", "keg/share/link", .{});
    try tmp.dir.symLink("../../outside", "keg/share/dirlink", .{ .is_directory = true });
    // A hard link to the script from outside the keg must keep its content.
    try std.posix.linkat(tmp.dir.fd, "keg/share/script.sh", tmp.dir.fd, "outside/hard", 0);

    const keg = try std.fs.path.join(testing.allocator, &.{ root, "keg" });
    defer testing.allocator.free(keg);
    const rep = try relocateKeg(testing.allocator, keg, test_prefix, test_host);
    try testing.expectEqual(@as(u32, 1), rep.elf_patched);
    try testing.expectEqual(@as(u32, 1), rep.macho_patched);
    try testing.expectEqual(@as(u32, 1), rep.text_patched);
    try testing.expectEqual(@as(u32, 1), rep.skipped);
    try testing.expectEqual(@as(u32, 0), rep.runpath_short);
    if (builtin.os.tag != .macos) try testing.expectEqual(@as(u32, 1), rep.signing_pending);

    const out_elf = try tmp.dir.readFileAlloc(testing.allocator, "keg/bin/tool", 1 << 20);
    defer testing.allocator.free(out_elf);
    const r = try readElf(out_elf);
    try testing.expectEqualStrings("/lib64/ld-linux-x86-64.so.2", r.interp);
    try testing.expectEqualStrings("$ORIGIN/../lib:/opt/abv/brew/lib", r.runpath);
    try testing.expectEqual(@as(u32, 0o755), (try tmp.dir.statFile("keg/bin/tool")).mode & 0o777);

    const out_macho = try tmp.dir.readFileAlloc(testing.allocator, "keg/lib/liby.dylib", 1 << 20);
    defer testing.allocator.free(out_macho);
    try testing.expectEqualStrings("/opt/abv/brew/opt/y/lib/liby.dylib", try machoDylib(out_macho));

    const script = try tmp.dir.readFileAlloc(testing.allocator, "keg/share/script.sh", 1 << 20);
    defer testing.allocator.free(script);
    try testing.expectEqualStrings("#!/opt/abv/brew/bin/sh\necho /opt/abv/brew/Cellar\n", script);
    try testing.expectEqual(@as(u32, 0o750), (try tmp.dir.statFile("keg/share/script.sh")).mode & 0o777);

    // Untouched: .brew, binary blob, symlink targets outside the keg, hard link.
    const brew = try tmp.dir.readFileAlloc(testing.allocator, "keg/.brew/x.rb", 1 << 10);
    defer testing.allocator.free(brew);
    try testing.expectEqualStrings("@@HOMEBREW_PREFIX@@", brew);
    const blob = try tmp.dir.readFileAlloc(testing.allocator, "keg/share/doc/blob.bin", 1 << 10);
    defer testing.allocator.free(blob);
    try testing.expectEqualStrings("bin\x00@@HOMEBREW_PREFIX@@", blob);
    const secret = try tmp.dir.readFileAlloc(testing.allocator, "outside/secret", 1 << 10);
    defer testing.allocator.free(secret);
    try testing.expectEqualStrings("@@HOMEBREW_PREFIX@@", secret);
    const hard = try tmp.dir.readFileAlloc(testing.allocator, "outside/hard", 1 << 10);
    defer testing.allocator.free(hard);
    try testing.expectEqualStrings("#!@@HOMEBREW_PREFIX@@/bin/sh\necho @@HOMEBREW_CELLAR@@\n", hard);

    // No temp files left behind.
    var d = try tmp.dir.openDir("keg/share", .{ .iterate = true });
    defer d.close();
    var it = d.iterate();
    while (try it.next()) |e| try testing.expect(!std.mem.endsWith(u8, e.name, ".tmp"));
}

test "relocateKeg: ELF on a musl-only host is NoGlibcLoader" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    const elf = try buildElf(testing.allocator, "@@HOMEBREW_PREFIX@@/lib/ld.so", "libc.so.6", "x");
    defer testing.allocator.free(elf);
    try tmp.dir.writeFile(.{ .sub_path = "tool", .data = elf });
    var h = test_host;
    h.elf_interpreter = null;
    try testing.expectError(error.NoGlibcLoader, relocateKeg(testing.allocator, root, test_prefix, h));
}

test "relocateKeg: rejects a relative prefix" {
    try testing.expectError(error.InvalidPrefix, relocateKeg(testing.allocator, ".", .{ .prefix = "brew", .cellar = "brew/Cellar" }, test_host));
}

test "detectHost returns a loader that exists, or null" {
    const h = try detectHost(testing.allocator);
    if (h.elf_interpreter) |p| try testing.expect(std.fs.path.isAbsolute(p));
}
