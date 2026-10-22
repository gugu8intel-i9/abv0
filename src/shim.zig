//! Launcher shims.
//!
//! On Windows the loader looks for DLLs in the directory of the *executable*,
//! and a hard link lives in the link's directory, not the target's. Linking
//! `rg.exe` straight into abv0's bin dir therefore breaks every package whose
//! exe needs a DLL or data file sitting next to it in the store.
//!
//! The fix: abv0.exe doubles as the shim. Installing a
//! bin `rg` creates
//!
//!     <bin>/rg.exe    hard link (or copy) of abv0's own executable
//!     <bin>/rg.shim   path = <absolute target exe>
//!                     args = <extra args>
//!
//! When the process starts as `rg.exe`, `main` notices that its own basename is
//! not `abv0`, reads `rg.shim`, and runs the target with the target's own
//! directory as the image location, so DLL lookup works.
//!
//! The shim file is data fetched from nothing but abv0 itself, yet it is still
//! parsed strictly: a shim that names a relative path, carries a line break
//! inside a value, or lacks `path` is refused rather than interpreted.
//!
//! The same mechanism works on Linux and macOS, where abv0 normally keeps using
//! symlinks and hard links; it costs nothing there unless a shim file exists.

const std = @import("std");
const builtin = @import("builtin");
const safepath = @import("safepath.zig");
const platform = @import("platform.zig");
const registry = @import("registry.zig");

pub const shim_suffix = ".shim";

/// Shim files are tiny. Anything larger is not one.
pub const max_shim_bytes = 64 * 1024;
pub const max_args = 256;

pub const Error = error{
    InvalidShimName,
    InvalidShimTarget,
    InvalidShimArgs,
    ShimTooLarge,
    MalformedShim,
    MissingShimPath,
    DuplicateShimKey,
    RelativeShimPath,
    WouldOverwriteNonShim,
};

pub const Shim = struct {
    /// Absolute path of the real executable.
    path: []const u8,
    /// Arguments placed between the target and the caller's own arguments.
    args: []const []const u8 = &.{},
};

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

/// Directory-independent basename of `path`: the text after the last `/` or
/// `\`, with a trailing `.exe` (any case) removed. Works on Windows-style
/// paths even when running on POSIX.
pub fn baseName(path: []const u8) []const u8 {
    var start: usize = 0;
    for (path, 0..) |c, i| {
        if (c == '/' or c == '\\') start = i + 1;
    }
    var base = path[start..];
    if (base.len > 4 and std.ascii.eqlIgnoreCase(base[base.len - 4 ..], ".exe")) {
        base = base[0 .. base.len - 4];
    }
    return base;
}

/// True for the names abv0 itself runs under: `abv0`, `abv0.exe` and the
/// release artifact names such as `abv0-linux-x86_64`. Such a process is never
/// a shim and must not touch the filesystem to find out.
pub fn isPlainName(base: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(base, "abv0")) return true;
    if (base.len > 5 and std.ascii.eqlIgnoreCase(base[0..5], "abv0-")) return true;
    return false;
}

/// Can `name` be installed as a shim? A single valid id that is not reserved,
/// not one of abv0's own names and without an executable or shim suffix.
pub fn isValidShimName(name: []const u8) bool {
    if (!registry.isUsableBinName(name)) return false;
    if (isPlainName(name)) return false;
    if (endsWithIgnoreCase(name, ".exe") or endsWithIgnoreCase(name, shim_suffix)) return false;
    return true;
}

fn endsWithIgnoreCase(s: []const u8, suffix: []const u8) bool {
    return s.len >= suffix.len and std.ascii.eqlIgnoreCase(s[s.len - suffix.len ..], suffix);
}

// ---------------------------------------------------------------------------
// Argument encoding
// ---------------------------------------------------------------------------

fn isArgSpace(c: u8) bool {
    return c == ' ' or c == '\t';
}

fn hasBadControl(s: []const u8) bool {
    for (s) |c| {
        if (c < 0x20 and c != '\t') return true;
        if (c == 0x7f) return true;
    }
    return false;
}

/// Split a command-line fragment into arguments. Tokens are separated by
/// spaces or tabs; a double quote groups text (including spaces) and is
/// removed. There are no escapes. Fails on an unbalanced quote, control
/// characters or too many arguments.
pub fn splitArgs(a: std.mem.Allocator, line: []const u8) Error![]const []const u8 {
    if (hasBadControl(line)) return error.InvalidShimArgs;
    var list = std.ArrayList([]const u8).init(a);
    var cur = std.ArrayList(u8).init(a);
    var in_quote = false;
    var have = false;
    for (line) |c| {
        if (c == '"') {
            in_quote = !in_quote;
            have = true;
        } else if (isArgSpace(c) and !in_quote) {
            if (have) {
                try pushArg(&list, &cur);
                have = false;
            }
        } else {
            cur.append(c) catch return error.InvalidShimArgs;
            have = true;
        }
    }
    if (in_quote) return error.InvalidShimArgs;
    if (have) try pushArg(&list, &cur);
    return list.toOwnedSlice() catch error.InvalidShimArgs;
}

fn pushArg(list: *std.ArrayList([]const u8), cur: *std.ArrayList(u8)) Error!void {
    if (list.items.len >= max_args) return error.InvalidShimArgs;
    const owned = cur.toOwnedSlice() catch return error.InvalidShimArgs;
    list.append(owned) catch return error.InvalidShimArgs;
}

/// Inverse of `splitArgs`. An argument containing a double quote cannot be
/// represented and is refused.
fn writeArgs(w: anytype, args: []const []const u8) !void {
    for (args, 0..) |arg, i| {
        if (hasBadControl(arg) or std.mem.indexOfScalar(u8, arg, '"') != null)
            return error.InvalidShimArgs;
        if (i != 0) try w.writeByte(' ');
        var needs_quote = arg.len == 0;
        for (arg) |c| {
            if (isArgSpace(c)) needs_quote = true;
        }
        if (needs_quote) {
            try w.writeByte('"');
            try w.writeAll(arg);
            try w.writeByte('"');
        } else {
            try w.writeAll(arg);
        }
    }
}

// ---------------------------------------------------------------------------
// Shim file format
// ---------------------------------------------------------------------------

/// Absolute path check that does not depend on the host: a POSIX root, a
/// Windows drive root (`C:\` or `C:/`) or a UNC prefix. A root-relative
/// `\foo` or a drive-relative `C:foo` is not absolute. Control characters,
/// NUL and `..` components are refused.
pub fn isAbsoluteTarget(p: []const u8) bool {
    if (p.len < 2 or p.len > safepath.max_rel_path_len) return false;
    for (p) |c| {
        if (c < 0x20 or c == 0x7f) return false;
    }
    if (p[0] == ' ' or p[p.len - 1] == ' ') return false;

    const abs = blk: {
        if (p[0] == '/') break :blk true;
        if (p.len >= 3 and std.ascii.isAlphabetic(p[0]) and p[1] == ':' and (p[2] == '\\' or p[2] == '/'))
            break :blk true;
        if (p.len >= 3 and p[0] == '\\' and p[1] == '\\') break :blk true;
        break :blk false;
    };
    if (!abs) return false;

    var it = std.mem.splitAny(u8, p, "/\\");
    while (it.next()) |component| {
        if (std.mem.eql(u8, component, "..")) return false;
    }
    return true;
}

/// Parse the text of a `.shim` file. Exactly the keys `path` and (optionally)
/// `args` may appear, each at most once, as `key = value` lines ended by `\n`.
/// `path` is required and must be absolute. Memory comes from `a`.
pub fn readShim(a: std.mem.Allocator, bytes: []const u8) Error!Shim {
    if (bytes.len > max_shim_bytes) return error.ShimTooLarge;
    if (std.mem.indexOfScalar(u8, bytes, 0) != null) return error.MalformedShim;
    if (std.mem.indexOfScalar(u8, bytes, '\r') != null) return error.MalformedShim;
    if (!std.unicode.utf8ValidateSlice(bytes)) return error.MalformedShim;

    var path: ?[]const u8 = null;
    var args_line: ?[]const u8 = null;

    var rest = bytes;
    while (rest.len > 0) {
        const nl = std.mem.indexOfScalar(u8, rest, '\n');
        const line = if (nl) |i| rest[0..i] else rest;
        rest = if (nl) |i| rest[i + 1 ..] else rest[rest.len..];

        if (std.mem.startsWith(u8, line, "path = ")) {
            if (path != null) return error.DuplicateShimKey;
            path = line["path = ".len..];
        } else if (std.mem.startsWith(u8, line, "args = ")) {
            if (args_line != null) return error.DuplicateShimKey;
            args_line = line["args = ".len..];
        } else if (std.mem.eql(u8, line, "args =")) {
            if (args_line != null) return error.DuplicateShimKey;
            args_line = "";
        } else {
            return error.MalformedShim;
        }
    }

    const p = path orelse return error.MissingShimPath;
    if (p.len == 0) return error.MissingShimPath;
    if (!isAbsoluteTarget(p)) return error.RelativeShimPath;

    const args = if (args_line) |l| try splitArgs(a, l) else &[_][]const u8{};
    const path_owned = a.dupe(u8, p) catch return error.MalformedShim;
    return .{ .path = path_owned, .args = args };
}

/// Render a shim file. Refuses a target or argument that `readShim` would
/// refuse, so a shim that is written always reads back.
pub fn formatShim(a: std.mem.Allocator, target_abs: []const u8, args: []const []const u8) ![]u8 {
    if (!isAbsoluteTarget(target_abs)) return error.InvalidShimTarget;
    if (args.len > max_args) return error.InvalidShimArgs;
    var buf = std.ArrayList(u8).init(a);
    errdefer buf.deinit();
    const w = buf.writer();
    try w.print("path = {s}\n", .{target_abs});
    try w.writeAll("args = ");
    try writeArgs(w, args);
    try w.writeByte('\n');
    return buf.toOwnedSlice();
}

// ---------------------------------------------------------------------------
// Installing a shim
// ---------------------------------------------------------------------------

fn exeFileName(a: std.mem.Allocator, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(a, "{s}{s}", .{ name, platform.exe_suffix });
}

/// Create `<bin_dir>/<name>[.exe]` as a link to abv0's own executable and
/// `<bin_dir>/<name>.shim` pointing at `target_abs`.
///
/// The shim file is written atomically. An existing exe is only replaced when
/// a valid shim sits next to it, so a real program that happens to share the
/// name is never overwritten (`error.WouldOverwriteNonShim`).
pub fn writeShim(
    a: std.mem.Allocator,
    bin_dir: []const u8,
    name: []const u8,
    target_abs: []const u8,
    args: []const []const u8,
) !void {
    return writeShimWithSelf(a, bin_dir, name, target_abs, args, null);
}

/// `writeShim` with the file that becomes the launcher exe made explicit.
/// `self_exe` null means this process's own executable (the only value the
/// program itself uses); tests pass a stand-in file.
///
/// Self-update note: `abv0 self-update` replaces abv0.exe, but every existing
/// `<name>.exe` launcher stays a hard link/copy of the OLD abv0.exe. That is
/// fine: a launcher only reads its `.shim` file and starts the target, and the
/// `.shim` format is stable. Launchers pick up the new binary the next time
/// they are rewritten (reinstall or `abv0 fix`).
pub fn writeShimWithSelf(
    a: std.mem.Allocator,
    bin_dir: []const u8,
    name: []const u8,
    target_abs: []const u8,
    args: []const []const u8,
    self_exe: ?[]const u8,
) !void {
    if (!isValidShimName(name)) return error.InvalidShimName;
    if (!isAbsoluteTarget(target_abs)) return error.InvalidShimTarget;

    const content = try formatShim(a, target_abs, args);
    defer a.free(content);

    var dir = try std.fs.cwd().openDir(bin_dir, .{});
    defer dir.close();

    const exe_name = try exeFileName(a, name);
    defer a.free(exe_name);
    const shim_name = try std.fmt.allocPrint(a, "{s}{s}", .{ name, shim_suffix });
    defer a.free(shim_name);

    // Inspect what is already there.
    const exe_exists = fileExists(dir, exe_name);
    const shim_exists = fileExists(dir, shim_name);
    if (shim_exists) {
        // Never trample something that is not one of ours.
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const old = dir.readFileAlloc(arena.allocator(), shim_name, max_shim_bytes + 1) catch
            return error.WouldOverwriteNonShim;
        _ = readShim(arena.allocator(), old) catch return error.WouldOverwriteNonShim;
    } else if (exe_exists) {
        return error.WouldOverwriteNonShim;
    }

    // Link first, shim second: a shim file without its exe is harmless, but an
    // exe without a shim would be a bare copy of abv0 under another name.
    try linkSelf(a, dir, exe_name, exe_exists, self_exe);

    var af = try dir.atomicFile(shim_name, .{});
    defer af.deinit();
    try af.file.writeAll(content);
    try af.finish();
}

fn fileExists(dir: std.fs.Dir, name: []const u8) bool {
    dir.access(name, .{}) catch return false;
    return true;
}

/// Hard-link (or copy) this process's executable to `dir/exe_name`. A hard
/// link is not a symlink: the loader must see the link's own path as the image
/// path, so a symlink would be resolved straight back to abv0.
fn linkSelf(a: std.mem.Allocator, dir: std.fs.Dir, exe_name: []const u8, replace: bool, self_exe: ?[]const u8) !void {
    var self_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const self_path = self_exe orelse try std.fs.selfExePath(&self_buf);

    const tmp_name = try std.fmt.allocPrint(a, "{s}.new{d}", .{ exe_name, platform.processId() });
    defer a.free(tmp_name);
    dir.deleteFile(tmp_name) catch {};

    // Resolve the directory so the link is created relative to it.
    var dir_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const dir_path = try dir.realpath(".", &dir_buf);
    const tmp_path = try std.fs.path.join(a, &.{ dir_path, tmp_name });
    defer a.free(tmp_path);

    try hardLinkOrCopy(self_path, tmp_path);
    errdefer dir.deleteFile(tmp_name) catch {};

    dir.rename(tmp_name, exe_name) catch |e| {
        dir.deleteFile(tmp_name) catch {};
        // A running shim cannot be replaced on Windows. The existing exe is a
        // link to an older abv0, which behaves identically, so keep it.
        if (replace) return;
        return e;
    };
}

fn hardLinkOrCopy(src: []const u8, dst: []const u8) !void {
    if (platform.is_windows) {
        // fastLink hard-links and falls back to a copy; it never symlinks.
        _ = try platform.fastLink(src, dst);
        return;
    }
    std.posix.link(src, dst, 0) catch {
        try std.fs.cwd().copyFile(src, std.fs.cwd(), dst, .{});
        return;
    };
}

/// Read and parse the `.shim` file at `path`. Memory comes from `a`.
pub fn readShimFile(a: std.mem.Allocator, path: []const u8) !Shim {
    const bytes = try std.fs.cwd().readFileAlloc(a, path, max_shim_bytes + 1);
    return readShim(a, bytes);
}

// ---------------------------------------------------------------------------
// Running as a shim
// ---------------------------------------------------------------------------

/// If `exe_path` is a shim launcher, the path of its `.shim` file.
///
/// `exe_path`'s basename decides first. A process named `abv0`/`abv0.exe`
/// returns null without touching the filesystem.
pub fn shimPathFor(a: std.mem.Allocator, exe_path: []const u8) !?[]u8 {
    const base = baseName(exe_path);
    if (base.len == 0 or isPlainName(base)) return null;
    if (!safepath.isSafeRelPath(base)) return null;

    const dir_part = std.fs.path.dirname(exe_path) orelse ".";
    const candidate = try std.fmt.allocPrint(a, "{s}{c}{s}{s}", .{
        dir_part, std.fs.path.sep, base, shim_suffix,
    });
    errdefer a.free(candidate);

    std.fs.cwd().access(candidate, .{}) catch {
        a.free(candidate);
        return null;
    };
    return candidate;
}

/// The name this process was started under, without any syscall or
/// allocation. Null when the platform cannot say cheaply.
fn startedAsName(buf: []u8) ?[]const u8 {
    if (builtin.os.tag == .windows) {
        const params = std.os.windows.peb().ProcessParameters;
        const img = params.ImagePathName;
        const buffer = img.Buffer orelse return null;
        const units = buffer[0 .. img.Length / 2];
        var start: usize = 0;
        for (units, 0..) |u, i| {
            if (u == '\\' or u == '/') start = i + 1;
        }
        const n = std.unicode.utf16LeToUtf8(buf, units[start..]) catch return null;
        return baseName(buf[0..n]);
    }
    if (builtin.os.tag == .wasi or builtin.os.tag == .freestanding) return null;
    if (std.os.argv.len == 0) return null;
    return baseName(std.mem.span(std.os.argv[0]));
}

/// The `.shim` file belonging to this process, if it was started under a name
/// other than abv0 and such a file sits next to the executable.
pub fn shimPathForSelf(a: std.mem.Allocator) !?[]u8 {
    var name_buf: [512]u8 = undefined;
    if (startedAsName(&name_buf)) |n| {
        // The common case: running as abv0. No syscalls, no allocation.
        if (isPlainName(n)) return null;
    }
    var self_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const self_path = std.fs.selfExePath(&self_buf) catch return null;
    return try shimPathFor(a, self_path);
}

/// Run `shim.path` with `shim.args ++ argv_rest`. Inherits stdio and returns
/// the child's exit code. On POSIX the process image is replaced instead, so
/// this only returns on failure.
pub fn runShim(a: std.mem.Allocator, shim: Shim, argv_rest: []const []const u8) !u8 {
    var argv = std.ArrayList([]const u8).init(a);
    defer argv.deinit();
    try argv.append(shim.path);
    try argv.appendSlice(shim.args);
    try argv.appendSlice(argv_rest);

    if (platform.is_posix) {
        return std.process.execv(a, argv.items);
    }

    var child = std.process.Child.init(argv.items, a);
    child.stdin_behavior = .Inherit;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    try child.spawn();
    const term = try child.wait();
    return switch (term) {
        .Exited => |code| code,
        else => 1,
    };
}

/// Entry-point hook for `main`. Returns null when this process is plain abv0
/// (the normal case, which costs a basename comparison and nothing else), or
/// the exit code to return after running a shim.
pub fn maybeRun(base: std.mem.Allocator) ?u8 {
    // Everything below lives until the child exits; an arena keeps the leak
    // checker quiet without tracking each allocation.
    var arena = std.heap.ArenaAllocator.init(base);
    defer arena.deinit();
    const a = arena.allocator();

    const shim_path = (shimPathForSelf(a) catch return null) orelse return null;

    const fail = struct {
        fn f(comptime fmt: []const u8, args: anytype) u8 {
            std.io.getStdErr().writer().print("abv0 shim: " ++ fmt ++ "\n", args) catch {};
            return 1;
        }
    }.f;

    const bytes = std.fs.cwd().readFileAlloc(a, shim_path, max_shim_bytes + 1) catch |e|
        return fail("cannot read {s}: {s}", .{ shim_path, @errorName(e) });
    const shim = readShim(a, bytes) catch |e|
        return fail("invalid shim {s}: {s}", .{ shim_path, @errorName(e) });

    const argv = std.process.argsAlloc(a) catch return fail("out of memory", .{});
    const rest: []const []const u8 = if (argv.len > 1) argv[1..] else &.{};

    return runShim(a, shim, rest) catch |e|
        fail("cannot run {s}: {s}", .{ shim.path, @errorName(e) });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "baseName strips directories and .exe on either separator style" {
    try testing.expectEqualStrings("abv0", baseName("abv0"));
    try testing.expectEqualStrings("abv0", baseName("/usr/bin/abv0"));
    try testing.expectEqualStrings("abv0", baseName("C:\\Users\\me\\.abv0\\bin\\abv0.exe"));
    try testing.expectEqualStrings("RG", baseName("C:\\bin\\RG.EXE"));
    try testing.expectEqualStrings("rg", baseName("bin/rg.exe"));
    try testing.expectEqualStrings(".exe", baseName("dir/.exe"));
    try testing.expectEqualStrings("", baseName("dir/"));
}

test "isPlainName covers abv0 and release artifact names only" {
    try testing.expect(isPlainName("abv0"));
    try testing.expect(isPlainName("ABV0"));
    try testing.expect(isPlainName("abv0-linux-x86_64"));
    try testing.expect(isPlainName("abv0-windows-aarch64"));
    try testing.expect(!isPlainName("rg"));
    try testing.expect(!isPlainName("abv0x"));
    try testing.expect(!isPlainName(""));
}

test "isValidShimName rejects reserved, suffixed and unsafe names" {
    try testing.expect(isValidShimName("rg"));
    try testing.expect(isValidShimName("7z"));
    try testing.expect(!isValidShimName("abv0"));
    try testing.expect(!isValidShimName("abv0-x"));
    try testing.expect(!isValidShimName("rg.exe"));
    try testing.expect(!isValidShimName("rg.shim"));
    try testing.expect(!isValidShimName("sudo"));
    try testing.expect(!isValidShimName("../rg"));
    try testing.expect(!isValidShimName("a/b"));
    try testing.expect(!isValidShimName(""));
    try testing.expect(!isValidShimName("-rg"));
}

test "splitArgs and writeArgs round trip" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const args = try splitArgs(a, "--flag  \"two words\" x=\"a b\" \"\" last");
    try testing.expectEqual(@as(usize, 5), args.len);
    try testing.expectEqualStrings("--flag", args[0]);
    try testing.expectEqualStrings("two words", args[1]);
    try testing.expectEqualStrings("x=a b", args[2]);
    try testing.expectEqualStrings("", args[3]);
    try testing.expectEqualStrings("last", args[4]);

    try testing.expectEqual(@as(usize, 0), (try splitArgs(a, "")).len);
    try testing.expectEqual(@as(usize, 0), (try splitArgs(a, "   ")).len);
    try testing.expectError(error.InvalidShimArgs, splitArgs(a, "\"open"));
    try testing.expectError(error.InvalidShimArgs, splitArgs(a, "a\x01b"));

    var buf = std.ArrayList(u8).init(a);
    try writeArgs(buf.writer(), &.{ "--flag", "two words", "", "x" });
    try testing.expectEqualStrings("--flag \"two words\" \"\" x", buf.items);
    try testing.expectError(error.InvalidShimArgs, writeArgs(buf.writer(), &.{"a\"b"}));
    try testing.expectError(error.InvalidShimArgs, writeArgs(buf.writer(), &.{"a\nb"}));
}

test "shim file round trip" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const targets = [_][]const u8{
        "/home/u/.abv0/store/ripgrep@15.2.0@x86_64-windows/rg.exe",
        "C:\\Users\\me\\.abv0\\store\\ripgrep@15.2.0\\rg.exe",
        "C:/Users/me/Program Files/x/rg.exe",
        "\\\\server\\share\\rg.exe",
    };
    for (targets) |t| {
        const text = try formatShim(a, t, &.{ "--color=always", "two words" });
        const s = try readShim(a, text);
        try testing.expectEqualStrings(t, s.path);
        try testing.expectEqual(@as(usize, 2), s.args.len);
        try testing.expectEqualStrings("--color=always", s.args[0]);
        try testing.expectEqualStrings("two words", s.args[1]);
    }

    const no_args = try formatShim(a, "/x/y", &.{});
    try testing.expectEqualStrings("path = /x/y\nargs = \n", no_args);
    const s = try readShim(a, no_args);
    try testing.expectEqual(@as(usize, 0), s.args.len);

    // The args line is optional when reading.
    const s2 = try readShim(a, "path = /x/y\n");
    try testing.expectEqualStrings("/x/y", s2.path);
    // Key order does not matter.
    const s3 = try readShim(a, "args = -v\npath = /x/y");
    try testing.expectEqualStrings("-v", s3.args[0]);
}

test "malicious or malformed shims are rejected" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try testing.expectError(error.RelativeShimPath, readShim(a, "path = rg.exe\n"));
    try testing.expectError(error.RelativeShimPath, readShim(a, "path = ..\\evil.exe\n"));
    try testing.expectError(error.RelativeShimPath, readShim(a, "path = \\Windows\\evil.exe\n"));
    try testing.expectError(error.RelativeShimPath, readShim(a, "path = C:evil.exe\n"));
    try testing.expectError(error.RelativeShimPath, readShim(a, "path = /a/../../etc/x\n"));
    try testing.expectError(error.MissingShimPath, readShim(a, "args = -v\n"));
    try testing.expectError(error.MissingShimPath, readShim(a, ""));
    try testing.expectError(error.MissingShimPath, readShim(a, "path = \n"));
    try testing.expectError(error.DuplicateShimKey, readShim(a, "path = /a\npath = /b\n"));
    try testing.expectError(error.DuplicateShimKey, readShim(a, "path = /a\nargs = \nargs = x\n"));
    // Newline injection: a smuggled third line, an unknown key, a CR, a NUL.
    try testing.expectError(error.MalformedShim, readShim(a, "path = /a\nargs = x\ncmd = calc\n"));
    try testing.expectError(error.MalformedShim, readShim(a, "path = /a\n\nargs = x\n"));
    try testing.expectError(error.MalformedShim, readShim(a, "path = /a\r\nargs = x\r\n"));
    try testing.expectError(error.MalformedShim, readShim(a, "path = /a\x00b\n"));
    try testing.expectError(error.MalformedShim, readShim(a, "path = /a\n\xff\xfe\n"));
    try testing.expectError(error.MalformedShim, readShim(a, "path=/a\n"));
    try testing.expectError(error.InvalidShimArgs, readShim(a, "path = /a\nargs = \"unterminated\n"));
    const big = try a.alloc(u8, max_shim_bytes + 1);
    @memset(big, 'x');
    try testing.expectError(error.ShimTooLarge, readShim(a, big));

    // And the writer refuses to produce any of them.
    try testing.expectError(error.InvalidShimTarget, formatShim(a, "rg.exe", &.{}));
    try testing.expectError(error.InvalidShimTarget, formatShim(a, "/a\nargs = calc", &.{}));
    try testing.expectError(error.InvalidShimArgs, formatShim(a, "/a", &.{"x\ny"}));
    try testing.expectError(error.InvalidShimArgs, formatShim(a, "/a", &.{"x\"y"}));
}

test "shimPathFor: plain abv0 never touches the filesystem, others need a shim file" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "rg.shim", .data = "path = /x\n" });
    try tmp.dir.writeFile(.{ .sub_path = "abv0.shim", .data = "path = /x\n" });
    const root = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(root);

    // abv0 / abv0.exe: null even though abv0.shim exists.
    const abv0 = try std.fs.path.join(a, &.{ root, "abv0" });
    defer a.free(abv0);
    try testing.expect((try shimPathFor(a, abv0)) == null);
    const abv0_exe = try std.fmt.allocPrint(a, "{s}.exe", .{abv0});
    defer a.free(abv0_exe);
    try testing.expect((try shimPathFor(a, abv0_exe)) == null);

    // rg with a shim file next to it.
    const rg = try std.fs.path.join(a, &.{ root, "rg" });
    defer a.free(rg);
    const found = (try shimPathFor(a, rg)).?;
    defer a.free(found);
    try testing.expect(std.mem.endsWith(u8, found, "rg.shim"));

    const rg_exe = try std.fmt.allocPrint(a, "{s}.exe", .{rg});
    defer a.free(rg_exe);
    const found2 = (try shimPathFor(a, rg_exe)).?;
    defer a.free(found2);
    try testing.expectEqualStrings(found, found2);

    // No shim file: not a shim.
    const fd = try std.fs.path.join(a, &.{ root, "fd" });
    defer a.free(fd);
    try testing.expect((try shimPathFor(a, fd)) == null);
}

test "shimPathForSelf is null for the test binary (no sibling shim file)" {
    const r = try shimPathForSelf(testing.allocator);
    if (r) |p| testing.allocator.free(p);
    try testing.expect(r == null);
}

test "writeShim creates exe link plus shim, refuses to clobber a real program" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("bin");
    const bin = try tmp.dir.realpathAlloc(a, "bin");
    defer a.free(bin);

    const target: []const u8 = if (platform.is_windows) "C:\\store\\rg.exe" else "/store/rg";
    try writeShim(a, bin, "rg", target, &.{"--smart-case"});

    var bin_dir = try tmp.dir.openDir("bin", .{});
    defer bin_dir.close();
    const exe_name = "rg" ++ platform.exe_suffix;
    const st = try bin_dir.statFile(exe_name);
    try testing.expect(st.size > 0);

    const text = try bin_dir.readFileAlloc(a, "rg.shim", 4096);
    defer a.free(text);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const s = try readShim(arena.allocator(), text);
    try testing.expectEqualStrings(target, s.path);
    try testing.expectEqualStrings("--smart-case", s.args[0]);

    // Rewriting an existing shim works and updates it.
    try writeShim(a, bin, "rg", target, &.{});
    const text2 = try bin_dir.readFileAlloc(a, "rg.shim", 4096);
    defer a.free(text2);
    try testing.expectEqualStrings(try std.fmt.allocPrint(arena.allocator(), "path = {s}\nargs = \n", .{target}), text2);

    // A real program with no shim next to it is never replaced.
    try bin_dir.writeFile(.{ .sub_path = "fd" ++ platform.exe_suffix, .data = "MZ real program" });
    try testing.expectError(error.WouldOverwriteNonShim, writeShim(a, bin, "fd", target, &.{}));
    const kept = try bin_dir.readFileAlloc(a, "fd" ++ platform.exe_suffix, 100);
    defer a.free(kept);
    try testing.expectEqualStrings("MZ real program", kept);

    // A garbage .shim is not ours either.
    try bin_dir.writeFile(.{ .sub_path = "jq.shim", .data = "not a shim" });
    try testing.expectError(error.WouldOverwriteNonShim, writeShim(a, bin, "jq", target, &.{}));

    // Bad inputs.
    try testing.expectError(error.InvalidShimName, writeShim(a, bin, "abv0", target, &.{}));
    try testing.expectError(error.InvalidShimName, writeShim(a, bin, "../x", target, &.{}));
    try testing.expectError(error.InvalidShimTarget, writeShim(a, bin, "x", "relative/path", &.{}));
}
