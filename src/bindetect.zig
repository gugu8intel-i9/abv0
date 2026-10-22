//! Finding the executables inside an unpacked package.
//!
//! A `gh:` install has no recipe, so nobody has said which files in the archive
//! are the program. This module looks at the bytes: a file is an executable if
//! it starts with ELF, Mach-O or PE magic, or (on POSIX) if it carries an exec
//! bit and starts with `#!`.
//!
//! What is deliberately left out:
//!   * Shared libraries and object files, by file name (`.so`, `.so.N`,
//!     `.dylib`, `.dll`, `.a`, `.o`, ...) and, where the header says so, by
//!     ELF/Mach-O file type.
//!   * Anything under a directory called docs, man, completions, contrib,
//!     examples, test and the like: those hold samples, not the tool.
//!   * Symlinks. They are never followed, so an archive cannot make abv0 link
//!     a file from outside the package, and never descended into either.
//!
//! The walk is bounded in depth, entries visited and results returned, so a
//! hostile archive of a million files costs a bounded amount of work.

const std = @import("std");
const builtin = @import("builtin");
const safepath = @import("safepath.zig");

pub const Bin = struct {
    /// Relative to the root directory, with forward slashes.
    path: []const u8,
    /// The link name: the file's name without `.exe`.
    name: []const u8,
};

/// `rank` orders the best candidate first; callers link at most this many.
pub const max_bins = 16;

const max_found = 256;
const max_entries = 50_000;
const max_depth = 12;
const head_bytes = 64;

/// What the leading bytes of a file say it is.
const Class = enum {
    none,
    /// Native executable format: needs no exec bit to count.
    binary,
    /// `#!` script: only an executable when the exec bit is set.
    script,
};

fn be32(b: []const u8) u32 {
    return std.mem.readInt(u32, b[0..4], .big);
}

fn classify(head: []const u8, os: std.Target.Os.Tag) Class {
    if (head.len >= 2 and head[0] == '#' and head[1] == '!') {
        return if (os == .windows) .none else .script;
    }
    if (head.len < 4) return .none;

    // ELF. Relocatable objects (1) and core dumps (4) are not programs.
    if (std.mem.eql(u8, head[0..4], "\x7fELF")) {
        if (head.len >= 18) {
            const endian: std.builtin.Endian = if (head[5] == 2) .big else .little;
            const kind = std.mem.readInt(u16, head[16..18], endian);
            if (kind == 1 or kind == 4) return .none;
        }
        return .binary;
    }

    // Mach-O, thin. The file type sits at offset 12 in the file's own byte
    // order. Objects, dylibs, bundles, stubs and dSYM files are not programs.
    const machos = [_]struct { magic: [4]u8, endian: std.builtin.Endian }{
        .{ .magic = .{ 0xfe, 0xed, 0xfa, 0xce }, .endian = .big },
        .{ .magic = .{ 0xfe, 0xed, 0xfa, 0xcf }, .endian = .big },
        .{ .magic = .{ 0xce, 0xfa, 0xed, 0xfe }, .endian = .little },
        .{ .magic = .{ 0xcf, 0xfa, 0xed, 0xfe }, .endian = .little },
    };
    for (machos) |m| {
        if (!std.mem.eql(u8, head[0..4], &m.magic)) continue;
        if (head.len >= 16) {
            const ft = std.mem.readInt(u32, head[12..16], m.endian);
            switch (ft) {
                1, 6, 8, 9, 10 => return .none,
                else => {},
            }
        }
        return .binary;
    }

    // Mach-O universal (fat). 0xcafebabe is also the Java class magic; a fat
    // header's next word is a small architecture count, a class file's is its
    // version (45 or more).
    if (head.len >= 8 and (be32(head) == 0xcafebabe or be32(head) == 0xcafebabf)) {
        const n = be32(head[4..]);
        if (n >= 1 and n <= 30) return .binary;
        return .none;
    }

    // PE. Two bytes is weak evidence, so on its own it only counts when the
    // target is Windows; `findExecutables` also accepts it for a `.exe` name.
    if (head[0] == 'M' and head[1] == 'Z') return if (os == .windows) .binary else .none;

    return .none;
}

/// Whether `head` (the first bytes of a file) looks like a program for `os`.
/// ELF and Mach-O are accepted for any `os`; "MZ" only for Windows; a "#!"
/// line for POSIX targets (the caller still needs the exec bit to agree).
pub fn isExecutableBytes(head: []const u8, os: std.Target.Os.Tag) bool {
    return classify(head, os) != .none;
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

const skip_exts = [_][]const u8{
    ".dylib", ".dll", ".a",   ".o",  ".obj", ".lib",   ".pdb",  ".sys", ".ocx",
    ".node",  ".pyd", ".exp", ".la", ".pyc", ".debug", ".dsym",
};

/// Shared libraries and objects, by name. `libfoo.so.1.2` counts as well as
/// `libfoo.so`.
fn isLibraryName(name: []const u8) bool {
    for (skip_exts) |ext| {
        if (std.ascii.endsWithIgnoreCase(name, ext)) return true;
    }
    var from: usize = 0;
    while (std.ascii.indexOfIgnoreCasePos(name, from, ".so")) |i| {
        const end = i + 3;
        if (end == name.len or name[end] == '.') return true;
        from = i + 1;
    }
    return false;
}

const skip_dirs = [_][]const u8{
    "doc",          "docs",           "documentation",   "man",     "completion", "completions",
    "autocomplete", "autocompletion", "autocompletions", "contrib", "example",    "examples",
    "test",         "tests",          "testdata",        "samples", "sample",     ".git",
};

/// Directories that hold documentation, samples or tests rather than the tool.
/// `man1`..`man9` count as `man`.
fn isSkippedDir(name: []const u8) bool {
    for (skip_dirs) |d| {
        if (std.ascii.eqlIgnoreCase(name, d)) return true;
    }
    if (name.len == 4 and std.ascii.startsWithIgnoreCase(name, "man") and std.ascii.isDigit(name[3])) return true;
    return false;
}

fn linkName(file_name: []const u8) []const u8 {
    if (std.ascii.endsWithIgnoreCase(file_name, ".exe")) return file_name[0 .. file_name.len - 4];
    return file_name;
}

fn isExecBit(mode: std.fs.File.Mode) bool {
    // Windows has no mode bits; a script there is never run by shebang anyway.
    if (comptime builtin.os.tag == .windows) return true;
    return mode & 0o111 != 0;
}

// ---------------------------------------------------------------------------
// Walk
// ---------------------------------------------------------------------------

const Walk = struct {
    a: std.mem.Allocator,
    os: std.Target.Os.Tag,
    found: std.ArrayList(Bin),
    visited: usize = 0,

    fn full(self: *const Walk) bool {
        return self.visited >= max_entries or self.found.items.len >= max_found;
    }

    fn visit(self: *Walk, dir: std.fs.Dir, prefix: []const u8, depth: usize) !void {
        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (self.full()) return;
            self.visited += 1;

            switch (entry.kind) {
                .directory => {
                    if (depth + 1 >= max_depth or isSkippedDir(entry.name)) continue;
                    var sub = dir.openDir(entry.name, .{ .iterate = true, .no_follow = true }) catch continue;
                    defer sub.close();
                    const child = try joinRel(self.a, prefix, entry.name);
                    defer self.a.free(child);
                    try self.visit(sub, child, depth + 1);
                },
                .file => try self.consider(dir, prefix, entry.name),
                // Symlinks are skipped on purpose. `.unknown` comes from file
                // systems that do not report a type; the name check below needs
                // a real stat, so those are looked at the same way.
                .unknown => {
                    var buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
                    if (dir.readLink(entry.name, &buf)) |_| continue else |_| {}
                    const st = dir.statFile(entry.name) catch continue;
                    if (st.kind == .file) try self.consider(dir, prefix, entry.name);
                },
                else => {},
            }
        }
    }

    fn consider(self: *Walk, dir: std.fs.Dir, prefix: []const u8, file_name: []const u8) !void {
        if (isLibraryName(file_name)) return;
        const name = linkName(file_name);
        if (!safepath.isValidId(name)) return;

        var file = dir.openFile(file_name, .{}) catch return;
        defer file.close();
        const st = file.stat() catch return;
        if (st.kind != .file or st.size < 2) return;

        var head: [head_bytes]u8 = undefined;
        const n = file.readAll(&head) catch return;

        var class = classify(head[0..n], self.os);
        if (class == .none and n >= 2 and head[0] == 'M' and head[1] == 'Z' and
            std.ascii.endsWithIgnoreCase(file_name, ".exe")) class = .binary;
        switch (class) {
            .none => return,
            .binary => {},
            .script => if (!isExecBit(st.mode)) return,
        }

        const path = try joinRel(self.a, prefix, file_name);
        errdefer self.a.free(path);
        const owned_name = try self.a.dupe(u8, name);
        errdefer self.a.free(owned_name);
        try self.found.append(.{ .path = path, .name = owned_name });
    }
};

fn joinRel(a: std.mem.Allocator, prefix: []const u8, name: []const u8) ![]u8 {
    if (prefix.len == 0) return a.dupe(u8, name);
    return std.fmt.allocPrint(a, "{s}/{s}", .{ prefix, name });
}

fn depthOf(path: []const u8) usize {
    return std.mem.count(u8, path, "/");
}

fn byDepthThenPath(_: void, x: Bin, y: Bin) bool {
    const dx = depthOf(x.path);
    const dy = depthOf(y.path);
    if (dx != dy) return dx < dy;
    return std.mem.order(u8, x.path, y.path) == .lt;
}

/// Executables inside an unpacked package, shallowest first. Paths and names
/// are allocated from `a`, which should be an arena: nothing is freed
/// individually. When two files would link under the same name, only the
/// shallowest is kept. Returns at most 256 entries and visits at most 50,000.
pub fn findExecutables(a: std.mem.Allocator, root: std.fs.Dir, os: std.Target.Os.Tag) ![]Bin {
    var root_dir = try root.openDir(".", .{ .iterate = true, .no_follow = true });
    defer root_dir.close();

    var w = Walk{ .a = a, .os = os, .found = std.ArrayList(Bin).init(a) };
    try w.visit(root_dir, "", 0);

    const all = w.found.items;
    std.mem.sort(Bin, all, {}, byDepthThenPath);

    var seen = std.StringHashMap(void).init(a);
    defer seen.deinit();
    var out = std.ArrayList(Bin).init(a);
    for (all) |b| {
        if ((try seen.fetchPut(b.name, {})) != null) continue;
        try out.append(b);
    }
    return out.toOwnedSlice();
}

// ---------------------------------------------------------------------------
// Ranking
// ---------------------------------------------------------------------------

/// Lowercase `s` without '-' and '_' into `buf`. Null when it does not fit.
fn normalize(buf: []u8, s: []const u8) ?[]const u8 {
    var n: usize = 0;
    for (s) |c| {
        if (c == '-' or c == '_') continue;
        if (n >= buf.len) return null;
        buf[n] = std.ascii.toLower(c);
        n += 1;
    }
    return buf[0..n];
}

/// 0: the name is the repo's name; 1: it is a prefix or suffix of it, or the
/// repo's name is a prefix of it (`fzf-tmux` for `fzf`); 2: anything else.
fn nameTier(repo_norm: ?[]const u8, name: []const u8) u8 {
    const repo = repo_norm orelse return 2;
    var buf: [128]u8 = undefined;
    const n = normalize(&buf, name) orelse return 2;
    if (n.len == 0 or repo.len == 0) return 2;
    if (std.mem.eql(u8, n, repo)) return 0;
    if (n.len >= 2 and (std.mem.startsWith(u8, repo, n) or std.mem.endsWith(u8, repo, n))) return 1;
    if (repo.len >= 2 and std.mem.startsWith(u8, n, repo)) return 1;
    return 2;
}

fn inBinDir(path: []const u8) u8 {
    if (std.mem.startsWith(u8, path, "bin/") or std.mem.indexOf(u8, path, "/bin/") != null) return 0;
    return 1;
}

const RankCtx = struct { repo_norm: ?[]const u8 };

fn rankLess(ctx: RankCtx, x: Bin, y: Bin) bool {
    const tx = nameTier(ctx.repo_norm, x.name);
    const ty = nameTier(ctx.repo_norm, y.name);
    if (tx != ty) return tx < ty;
    const bx = inBinDir(x.path);
    const by = inBinDir(y.path);
    if (bx != by) return bx < by;
    const dx = depthOf(x.path);
    const dy = depthOf(y.path);
    if (dx != dy) return dx < dy;
    const nm = std.mem.order(u8, x.name, y.name);
    if (nm != .eq) return nm == .lt;
    return std.mem.order(u8, x.path, y.path) == .lt;
}

/// Put the program the project is named after first: a name equal to the
/// repository's (ignoring case, `-` and `_`), then names that are a prefix or
/// suffix of it, then files in a `bin/` directory, then shallower paths. Ties
/// fall back to name and path so the order is the same on every run. Link at
/// most `max_bins` of the result; `top` slices it.
pub fn rank(bins: []Bin, repo_name: []const u8) void {
    var buf: [128]u8 = undefined;
    std.mem.sort(Bin, bins, RankCtx{ .repo_norm = normalize(&buf, repo_name) }, rankLess);
}

/// The first `max_bins` entries of a ranked list.
pub fn top(bins: []Bin) []Bin {
    return bins[0..@min(bins.len, max_bins)];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn elfBytes(kind: u16) [64]u8 {
    var b = [_]u8{0} ** 64;
    @memcpy(b[0..7], "\x7fELF\x02\x01\x01");
    std.mem.writeInt(u16, b[16..18], kind, .little);
    return b;
}

fn machoBytes(filetype: u32) [64]u8 {
    var b = [_]u8{0} ** 64;
    @memcpy(b[0..4], "\xcf\xfa\xed\xfe");
    std.mem.writeInt(u32, b[12..16], filetype, .little);
    return b;
}

fn put(dir: std.fs.Dir, path: []const u8, data: []const u8, mode: u32) !void {
    if (std.fs.path.dirname(path)) |d| try dir.makePath(d);
    // Windows has no mode bits (File.Mode is u0 there).
    const m: std.fs.File.Mode = if (builtin.os.tag == .windows) 0 else @intCast(mode);
    const f = try dir.createFile(path, .{ .mode = m });
    defer f.close();
    try f.writeAll(data);
}

fn hasPath(bins: []const Bin, path: []const u8) bool {
    for (bins) |b| {
        if (std.mem.eql(u8, b.path, path)) return true;
    }
    return false;
}

test "isExecutableBytes recognises native formats and shebangs" {
    const elf = elfBytes(2);
    try testing.expect(isExecutableBytes(&elf, .linux));
    const pie = elfBytes(3);
    try testing.expect(isExecutableBytes(&pie, .linux));
    const obj = elfBytes(1);
    try testing.expect(!isExecutableBytes(&obj, .linux));
    const core = elfBytes(4);
    try testing.expect(!isExecutableBytes(&core, .linux));

    const exe = machoBytes(2);
    try testing.expect(isExecutableBytes(&exe, .macos));
    const dylib = machoBytes(6);
    try testing.expect(!isExecutableBytes(&dylib, .macos));
    const bundle = machoBytes(8);
    try testing.expect(!isExecutableBytes(&bundle, .macos));
    try testing.expect(isExecutableBytes("\xca\xfe\xba\xbe\x00\x00\x00\x02rest", .macos));
    // A Java class file shares the fat magic but has a version, not a count.
    try testing.expect(!isExecutableBytes("\xca\xfe\xba\xbe\x00\x00\x00\x34rest", .macos));

    try testing.expect(isExecutableBytes("MZ\x90\x00\x03\x00", .windows));
    try testing.expect(!isExecutableBytes("MZ\x90\x00\x03\x00", .linux));

    try testing.expect(isExecutableBytes("#!/bin/sh\necho hi\n", .linux));
    try testing.expect(isExecutableBytes("#!/usr/bin/env python3\n", .macos));
    try testing.expect(!isExecutableBytes("#!/bin/sh\n", .windows));

    try testing.expect(!isExecutableBytes("", .linux));
    try testing.expect(!isExecutableBytes("#", .linux));
    try testing.expect(!isExecutableBytes("hello world, plain text", .linux));
    try testing.expect(!isExecutableBytes("\x89PNG\r\n\x1a\n", .linux));
}

test "library and directory names are recognised" {
    try testing.expect(isLibraryName("libfoo.so"));
    try testing.expect(isLibraryName("libfoo.so.1"));
    try testing.expect(isLibraryName("libfoo.so.1.2.3"));
    try testing.expect(isLibraryName("libfoo.1.dylib"));
    try testing.expect(isLibraryName("FOO.DLL"));
    try testing.expect(isLibraryName("libz.a"));
    try testing.expect(isLibraryName("main.o"));
    try testing.expect(!isLibraryName("sox"));
    try testing.expect(!isLibraryName("some-tool"));
    try testing.expect(!isLibraryName("tool.exe"));
    try testing.expect(!isLibraryName("socat"));

    try testing.expect(isSkippedDir("docs"));
    try testing.expect(isSkippedDir("Completions"));
    try testing.expect(isSkippedDir("man1"));
    try testing.expect(isSkippedDir("tests"));
    try testing.expect(isSkippedDir("contrib"));
    try testing.expect(isSkippedDir("autocomplete"));
    try testing.expect(isSkippedDir("examples"));
    try testing.expect(!isSkippedDir("bin"));
    try testing.expect(!isSkippedDir("manager"));
    try testing.expect(!isSkippedDir("testing-tools"));
}

test "findExecutables picks programs and skips everything else" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var outside = testing.tmpDir(.{ .iterate = true });
    defer outside.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const elf = elfBytes(2);
    const macho = machoBytes(2);
    const dylib = machoBytes(6);
    const obj = elfBytes(1);

    try put(tmp.dir, "tool-1.0/bin/tool", &elf, 0o755);
    try put(tmp.dir, "tool-1.0/bin/tool-helper", "#!/bin/sh\nexec tool\n", 0o755);
    try put(tmp.dir, "tool-1.0/mac/maccy", &macho, 0o644);
    try put(tmp.dir, "tool-1.0/win/winny.exe", "MZ\x90\x00\x03\x00\x00\x00", 0o644);
    try put(tmp.dir, "tool-1.0/scripts/run.sh", "#!/bin/sh\necho\n", 0o755);
    // A shebang file without an exec bit is a text file.
    try put(tmp.dir, "tool-1.0/scripts/noexec.sh", "#!/bin/sh\necho\n", 0o644);
    // Libraries, objects and plain files.
    try put(tmp.dir, "tool-1.0/lib/libfoo.so", &elf, 0o755);
    try put(tmp.dir, "tool-1.0/lib/libfoo.so.1.2", &elf, 0o755);
    try put(tmp.dir, "tool-1.0/lib/libbar.dylib", &dylib, 0o755);
    try put(tmp.dir, "tool-1.0/lib/baz.dll", "MZ\x90\x00\x03\x00", 0o644);
    try put(tmp.dir, "tool-1.0/lib/thing.o", &obj, 0o644);
    try put(tmp.dir, "tool-1.0/README.md", "# tool\n", 0o644);
    try put(tmp.dir, "tool-1.0/empty", "", 0o755);
    // Directories that hold samples, not the tool.
    try put(tmp.dir, "tool-1.0/docs/demo", &elf, 0o755);
    try put(tmp.dir, "tool-1.0/completions/tool.bash", "#!/bin/bash\n", 0o755);
    try put(tmp.dir, "tool-1.0/man/man1/helper", &elf, 0o755);
    try put(tmp.dir, "tool-1.0/contrib/x", &elf, 0o755);
    try put(tmp.dir, "tool-1.0/examples/y", &elf, 0o755);
    try put(tmp.dir, "tool-1.0/tests/z", &elf, 0o755);
    try put(tmp.dir, "tool-1.0/autocomplete/w", &elf, 0o755);

    // Links never count, whether to a file or to a directory outside the tree.
    try put(outside.dir, "evil", &elf, 0o755);
    try put(outside.dir, "dir/inner", &elf, 0o755);
    const evil = try outside.dir.realpathAlloc(a, "evil");
    const evil_dir = try outside.dir.realpathAlloc(a, "dir");
    try tmp.dir.symLink(evil, "tool-1.0/bin/sneaky", .{});
    try tmp.dir.symLink(evil_dir, "tool-1.0/linkdir", .{ .is_directory = true });
    try tmp.dir.symLink("tool", "tool-1.0/bin/alias", .{});

    const bins = try findExecutables(a, tmp.dir, .linux);
    try testing.expectEqual(@as(usize, 5), bins.len);
    try testing.expect(hasPath(bins, "tool-1.0/bin/tool"));
    try testing.expect(hasPath(bins, "tool-1.0/bin/tool-helper"));
    try testing.expect(hasPath(bins, "tool-1.0/mac/maccy"));
    try testing.expect(hasPath(bins, "tool-1.0/win/winny.exe"));
    try testing.expect(hasPath(bins, "tool-1.0/scripts/run.sh"));

    for (bins) |b| {
        if (std.mem.eql(u8, b.path, "tool-1.0/win/winny.exe")) try testing.expectEqualStrings("winny", b.name);
        if (std.mem.eql(u8, b.path, "tool-1.0/bin/tool")) try testing.expectEqualStrings("tool", b.name);
    }
}

test "findExecutables keeps the shallowest file for a repeated name" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const elf = elfBytes(2);
    try put(tmp.dir, "a/b/c/tool", &elf, 0o755);
    try put(tmp.dir, "bin/tool", &elf, 0o755);
    try put(tmp.dir, "x/tool", &elf, 0o755);

    const bins = try findExecutables(a, tmp.dir, .linux);
    try testing.expectEqual(@as(usize, 1), bins.len);
    try testing.expectEqualStrings("bin/tool", bins[0].path);
}

test "findExecutables handles a single file at the root and an empty tree" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    try testing.expectEqual(@as(usize, 0), (try findExecutables(a, tmp.dir, .linux)).len);

    const elf = elfBytes(2);
    try put(tmp.dir, "rg", &elf, 0o755);
    const bins = try findExecutables(a, tmp.dir, .linux);
    try testing.expectEqual(@as(usize, 1), bins.len);
    try testing.expectEqualStrings("rg", bins[0].path);
    try testing.expectEqualStrings("rg", bins[0].name);
}

test "rank puts the project's own program first" {
    var list = [_]Bin{
        .{ .path = "deep/er/other", .name = "other" },
        .{ .path = "bin/helper", .name = "helper" },
        .{ .path = "zzz", .name = "zzz" },
        .{ .path = "bin/rip", .name = "rip" },
        .{ .path = "x/Ripgrep", .name = "Ripgrep" },
        .{ .path = "bin/ripgrep-extra", .name = "ripgrep-extra" },
    };
    rank(&list, "ripgrep");
    // Exact (case-insensitive) first, then prefix/suffix names, then bin/, then depth.
    try testing.expectEqualStrings("Ripgrep", list[0].name);
    try testing.expectEqualStrings("rip", list[1].name);
    try testing.expectEqualStrings("ripgrep-extra", list[2].name);
    try testing.expectEqualStrings("helper", list[3].name);
    try testing.expectEqualStrings("zzz", list[4].name);
    try testing.expectEqualStrings("other", list[5].name);
}

test "rank treats dashes and underscores as the same name" {
    var list = [_]Bin{
        .{ .path = "bin/aaa", .name = "aaa" },
        .{ .path = "bin/git_delta", .name = "git_delta" },
    };
    rank(&list, "git-delta");
    try testing.expectEqualStrings("git_delta", list[0].name);

    var list2 = [_]Bin{
        .{ .path = "bin/aaa", .name = "aaa" },
        .{ .path = "bin/delta", .name = "delta" },
    };
    rank(&list2, "git-delta");
    try testing.expectEqualStrings("delta", list2[0].name);
}

test "rank prefers bin/ and shallow paths when names say nothing" {
    var list = [_]Bin{
        .{ .path = "a/b/qqq", .name = "qqq" },
        .{ .path = "ppp", .name = "ppp" },
        .{ .path = "bin/rrr", .name = "rrr" },
        .{ .path = "x/bin/sss", .name = "sss" },
    };
    rank(&list, "unrelated");
    try testing.expectEqualStrings("rrr", list[0].name);
    try testing.expectEqualStrings("sss", list[1].name);
    try testing.expectEqualStrings("ppp", list[2].name);
    try testing.expectEqualStrings("qqq", list[3].name);
}

test "top caps the list at sixteen" {
    var many: [20]Bin = undefined;
    for (&many, 0..) |*b, i| b.* = .{ .path = "p", .name = if (i == 0) "a" else "b" };
    try testing.expectEqual(@as(usize, 16), top(&many).len);
    try testing.expectEqual(@as(usize, 3), top(many[0..3]).len);
}
