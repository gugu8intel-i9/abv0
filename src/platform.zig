//! Cross-platform OS primitives for Linux, macOS and Windows.
//!
//! Everything that used to be a subprocess (`chmod`, `open`, `xdg-open`) or a
//! POSIX-only call (`std.posix.getenv`, which is unimplemented on Windows) is
//! funnelled through here.

const std = @import("std");
const builtin = @import("builtin");

pub const is_windows = builtin.os.tag == .windows;
pub const is_macos = builtin.os.tag == .macos;
pub const is_posix = !is_windows;

/// Appended to executable names when linking into the bin directory.
pub const exe_suffix = if (is_windows) ".exe" else "";

/// `std.fs.File.Mode` is `u0` on Windows, which has no POSIX permission bits,
/// so writing `.mode = 0o600` there is a compile error ("type 'u0' cannot
/// represent integer value '384'"). These constants give one spelling that
/// compiles on every target while still creating tight files on POSIX.
pub const mode_private: std.fs.File.Mode = if (is_windows) 0 else 0o600;
pub const mode_public: std.fs.File.Mode = if (is_windows) 0 else 0o644;
pub const mode_exec: std.fs.File.Mode = if (is_windows) 0 else 0o700;
pub const mode_bin: std.fs.File.Mode = if (is_windows) 0 else 0o755;

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

/// The user's home directory. `std.posix.getenv` is a compile error on Windows,
/// which is why the original code could never have built for that target.
pub fn homeDir(allocator: std.mem.Allocator) ![]u8 {
    if (is_windows) {
        if (std.process.getEnvVarOwned(allocator, "USERPROFILE")) |v| {
            if (v.len > 0) return v;
            allocator.free(v);
        } else |_| {}

        // Fall back to HOMEDRIVE + HOMEPATH.
        const drive = std.process.getEnvVarOwned(allocator, "HOMEDRIVE") catch return error.HomeDirNotFound;
        defer allocator.free(drive);
        const path = std.process.getEnvVarOwned(allocator, "HOMEPATH") catch return error.HomeDirNotFound;
        defer allocator.free(path);
        return std.mem.concat(allocator, u8, &.{ drive, path });
    }

    const v = std.process.getEnvVarOwned(allocator, "HOME") catch return error.HomeDirNotFound;
    if (v.len == 0) {
        allocator.free(v);
        return error.HomeDirNotFound;
    }
    return v;
}

/// Returns an owned copy of an environment variable, or null when unset.
pub fn envOwned(allocator: std.mem.Allocator, key: []const u8) ?[]u8 {
    return std.process.getEnvVarOwned(allocator, key) catch null;
}

// ---------------------------------------------------------------------------
// ABV0_* path overrides
// ---------------------------------------------------------------------------

/// Accepts an `ABV0_HOME`, `ABV0_BIN_DIR` or `ABV0_REGISTRY_DIR` value only
/// when it is an absolute path with no NUL or line breaks. Anything else is
/// ignored, so the default under ~/.abv0 is used instead.
pub fn acceptAbsolutePath(value: []const u8) ?[]const u8 {
    if (value.len == 0) return null;
    if (std.mem.indexOfAny(u8, value, "\x00\r\n") != null) return null;
    if (!std.fs.path.isAbsolute(value)) return null;
    return value;
}

fn envAbsolutePath(allocator: std.mem.Allocator, key: []const u8) ?[]u8 {
    const raw = envOwned(allocator, key) orelse return null;
    if (acceptAbsolutePath(raw) == null) {
        allocator.free(raw);
        return null;
    }
    return raw;
}

/// Root of the abv0 tree from `ABV0_HOME`, replacing `<home>/.abv0`.
/// Caller frees the result.
pub fn homeOverride(allocator: std.mem.Allocator) ?[]u8 {
    return envAbsolutePath(allocator, "ABV0_HOME");
}

/// Bin directory from `ABV0_BIN_DIR`, replacing `<root>/bin`.
/// Caller frees the result.
pub fn binDirOverride(allocator: std.mem.Allocator) ?[]u8 {
    return envAbsolutePath(allocator, "ABV0_BIN_DIR");
}

/// Registry directory from `ABV0_REGISTRY_DIR`, replacing `<root>/registry`.
/// Caller frees the result.
pub fn registryDirOverride(allocator: std.mem.Allocator) ?[]u8 {
    return envAbsolutePath(allocator, "ABV0_REGISTRY_DIR");
}

/// Only https manifest URLs are accepted; a plain http or file URL is ignored.
fn acceptRegistryUrl(url: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, url, "https://")) return null;
    if (std.mem.indexOfAny(u8, url, "\x00\r\n") != null) return null;
    return url;
}

/// Backing store for `registryUrlOverride`. The returned slice must outlive
/// the call, and no allocator is passed in, so it lives in static memory.
var registry_url_buf: [2048]u8 = undefined;

/// Manifest URL from `ABV0_REGISTRY_URL`, if set to an https URL that fits in
/// 2 KiB. The result points into static storage and is never freed.
pub fn registryUrlOverride() ?[]const u8 {
    var fba = std.heap.FixedBufferAllocator.init(&registry_url_buf);
    const raw = std.process.getEnvVarOwned(fba.allocator(), "ABV0_REGISTRY_URL") catch return null;
    return acceptRegistryUrl(raw);
}

/// The interactive shell to spawn for `abv0 shell`.
pub fn defaultShell(allocator: std.mem.Allocator) ![]u8 {
    if (is_windows) {
        if (envOwned(allocator, "COMSPEC")) |v| return v;
        return allocator.dupe(u8, "cmd.exe");
    }
    if (envOwned(allocator, "SHELL")) |v| return v;
    return allocator.dupe(u8, "/bin/sh");
}

/// Canonical `<arch>-<os>` tag for the host.
pub fn defaultPlatformTag() []const u8 {
    const arch = switch (builtin.cpu.arch) {
        .aarch64, .aarch64_be => "aarch64",
        .x86_64 => "x86_64",
        .x86 => "x86",
        .riscv64 => "riscv64",
        else => "unknown",
    };
    const os = switch (builtin.os.tag) {
        .macos => "macos",
        .linux => "linux",
        .windows => "windows",
        .freebsd => "freebsd",
        else => "unknown",
    };
    // Comptime-known concatenation; no allocation.
    return arch ++ "-" ++ os;
}

/// Is `tag` a platform identifier we understand? Rejects nonsense early rather
/// than letting it become a directory name.
pub fn isKnownPlatformTag(tag: []const u8) bool {
    const known = [_][]const u8{
        "x86_64-macos",   "aarch64-macos",
        "x86_64-linux",   "aarch64-linux",
        "x86_64-windows", "aarch64-windows",
    };
    for (known) |k| {
        if (std.mem.eql(u8, k, tag)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

/// In-process chmod. Was three `Child.run("chmod")` spawns per invocation.
/// No-op on Windows, which has no POSIX mode bits.
pub fn chmodPath(path: []const u8, mode: u32) void {
    if (is_windows) return;
    const file = std.fs.cwd().openFile(path, .{}) catch {
        // Directories need openDir on some platforms.
        var dir = std.fs.cwd().openDir(path, .{}) catch return;
        defer dir.close();
        std.posix.fchmod(dir.fd, @intCast(mode)) catch {};
        return;
    };
    defer file.close();
    std.posix.fchmod(file.handle, @intCast(mode)) catch {};
}

/// Mark a file executable (owner/group/other execute, honouring the umask
/// intent of 0o755). No-op on Windows.
pub fn setExecutable(path: []const u8) void {
    if (is_windows) return;
    const file = std.fs.cwd().openFile(path, .{}) catch return;
    defer file.close();
    const st = file.stat() catch return;
    const new_mode: u32 = @as(u32, @intCast(st.mode)) | 0o100;
    std.posix.fchmod(file.handle, @intCast(new_mode)) catch {};
}

/// Create a directory tree that only the owner can traverse.
pub fn makeSecureDir(path: []const u8) !void {
    try std.fs.cwd().makePath(path);
    chmodPath(path, 0o700);
}

/// `makeSecureDir` for directories touched on every run. The chmod is only
/// paid when the directory is missing or does not already have mode 0700.
pub fn ensureSecureDir(path: []const u8) !void {
    if (comptime is_posix) {
        if (std.fs.cwd().statFile(path)) |st| {
            if (st.kind == .directory and (st.mode & 0o777) == 0o700) return;
        } else |_| {}
    }
    try makeSecureDir(path);
}

/// True when anything exists at `path`, including a dangling symlink.
pub fn pathExists(path: []const u8) bool {
    if (std.fs.cwd().statFile(path)) |_| return true else |_| {}
    if (comptime is_posix) {
        var buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        if (std.posix.readlink(path, &buf)) |_| return true else |e| return e != error.FileNotFound;
    }
    return false;
}

extern "c" fn getpid() c_int;

/// Id of the current process, embedded in ephemeral directory names so that
/// cleanup can tell whether the owner is still running. 0 on Windows.
pub fn processId() i32 {
    if (comptime is_windows) return 0;
    if (comptime builtin.os.tag == .linux) return std.os.linux.getpid();
    return getpid();
}

/// Whether process `pid` exists. Unclear answers (such as EPERM) count as
/// alive, so a live process's directory is never reclaimed by mistake.
pub fn processAlive(pid: i32) bool {
    if (comptime is_posix) {
        std.posix.kill(pid, 0) catch |e| return e != error.ProcessNotFound;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Fast linking
// ---------------------------------------------------------------------------

pub const LinkKind = enum {
    cloned, // APFS copy-on-write clone (macOS)
    hardlinked, // same-filesystem hard link
    symlinked, // symbolic link
    copied, // byte copy

    pub fn label(self: LinkKind) []const u8 {
        return switch (self) {
            .cloned => "APFS clone",
            .hardlinked => "hard link",
            .symlinked => "symlink",
            .copied => "copy",
        };
    }
};

const CLONE_NOFOLLOW: u32 = 0x0001;

extern "c" fn clonefile(src: [*:0]const u8, dst: [*:0]const u8, flags: u32) c_int;

const windows = std.os.windows;
extern "kernel32" fn CreateHardLinkW(
    lpFileName: [*:0]const u16,
    lpExistingFileName: [*:0]const u16,
    lpSecurityAttributes: ?*anyopaque,
) callconv(windows.WINAPI) windows.BOOL;

/// Link an installed program into the bin directory. On Linux and macOS
/// this is a symbolic link, as Homebrew does: a program that finds its own
/// data relative to its executable (cmake's modules, a toolchain's lib/)
/// resolves the link back into the store, which a hard link or a copy would
/// not. Falls back to `fastLink` where a symlink cannot be made. Windows
/// uses launcher shims instead and never reaches this.
pub fn linkProgram(src_path: []const u8, dst_path: []const u8) !LinkKind {
    if (is_windows) return fastLink(src_path, dst_path);
    if (src_path.len >= std.fs.MAX_PATH_BYTES or dst_path.len >= std.fs.MAX_PATH_BYTES)
        return error.NameTooLong;
    std.fs.cwd().deleteFile(dst_path) catch |e| switch (e) {
        error.FileNotFound => {},
        error.IsDir => return error.DestinationIsDirectory,
        else => {},
    };
    // A relative target would resolve against the bin directory, not ours.
    var buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const target = if (std.fs.path.isAbsolute(src_path))
        src_path
    else
        std.fs.cwd().realpath(src_path, &buf) catch return fastLink(src_path, dst_path);
    if (std.posix.symlink(target, dst_path)) |_| return .symlinked else |_| {}
    return fastLink(src_path, dst_path);
}

/// Link `src` to `dst` using the cheapest mechanism the platform offers.
///
/// Unlike the original, this allocates nothing: the old implementation spun up
/// a fresh ArenaAllocator over `page_allocator` on every call, costing an
/// mmap/munmap pair on the exact code path the README advertises as free.
pub fn fastLink(src_path: []const u8, dst_path: []const u8) !LinkKind {
    if (src_path.len >= std.fs.MAX_PATH_BYTES or dst_path.len >= std.fs.MAX_PATH_BYTES)
        return error.NameTooLong;

    // Every strategy below requires the destination to be absent. A directory
    // here is never removed recursively on the caller's behalf.
    std.fs.cwd().deleteFile(dst_path) catch |e| switch (e) {
        error.FileNotFound => {},
        error.IsDir => return error.DestinationIsDirectory,
        else => {},
    };

    if (is_macos) {
        var src_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        var dst_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        @memcpy(src_buf[0..src_path.len], src_path);
        src_buf[src_path.len] = 0;
        @memcpy(dst_buf[0..dst_path.len], dst_path);
        dst_buf[dst_path.len] = 0;

        const src_z: [*:0]const u8 = @ptrCast(&src_buf);
        const dst_z: [*:0]const u8 = @ptrCast(&dst_buf);
        if (clonefile(src_z, dst_z, CLONE_NOFOLLOW) == 0) return .cloned;
    }

    if (is_windows) {
        var src_w: [std.fs.MAX_PATH_BYTES]u16 = undefined;
        var dst_w: [std.fs.MAX_PATH_BYTES]u16 = undefined;
        const src_len = try std.unicode.utf8ToUtf16Le(&src_w, src_path);
        src_w[src_len] = 0;
        const dst_len = try std.unicode.utf8ToUtf16Le(&dst_w, dst_path);
        dst_w[dst_len] = 0;

        const src_z: [*:0]const u16 = @ptrCast(&src_w);
        const dst_z: [*:0]const u16 = @ptrCast(&dst_w);
        if (CreateHardLinkW(dst_z, src_z, null) != 0) return .hardlinked;

        try copyPath(src_path, dst_path);
        return .copied;
    }

    // Hard links beat symlinks: no readlink hop at exec time and no dangling
    // reference if the store entry is later moved.
    if (std.posix.link(src_path, dst_path, 0)) |_| {
        return .hardlinked;
    } else |_| {}

    if (std.posix.symlink(src_path, dst_path)) |_| {
        return .symlinked;
    } else |_| {}

    try copyPath(src_path, dst_path);
    return .copied;
}

fn copyPath(src_path: []const u8, dst_path: []const u8) !void {
    const stat = try std.fs.cwd().statFile(src_path);
    if (stat.kind == .directory) {
        try copyTree(src_path, dst_path);
        return;
    }
    try std.fs.cwd().copyFile(src_path, std.fs.cwd(), dst_path, .{});
}

/// Recursive directory copy, used for `.app` bundles when cloning is
/// unavailable. Replaces a `cp -R` subprocess.
pub fn copyTree(src_path: []const u8, dst_path: []const u8) !void {
    var src_dir = try std.fs.cwd().openDir(src_path, .{ .iterate = true });
    defer src_dir.close();
    try std.fs.cwd().makePath(dst_path);
    var dst_dir = try std.fs.cwd().openDir(dst_path, .{});
    defer dst_dir.close();

    var walker_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    var it = src_dir.iterate();
    while (try it.next()) |entry| {
        const sub_src = try std.fmt.bufPrint(&walker_buf, "{s}/{s}", .{ src_path, entry.name });
        switch (entry.kind) {
            .directory => {
                var sub_dst_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
                const sub_dst = try std.fmt.bufPrint(&sub_dst_buf, "{s}/{s}", .{ dst_path, entry.name });
                try copyTree(sub_src, sub_dst);
            },
            .file => try src_dir.copyFile(entry.name, dst_dir, entry.name, .{}),
            else => {}, // skip sockets, fifos, and dangling symlinks
        }
    }
}

// ---------------------------------------------------------------------------
// Browser launch
// ---------------------------------------------------------------------------

pub fn openBrowser(allocator: std.mem.Allocator, url: []const u8) void {
    // Only ever hand a vetted https URL to the OS handler.
    if (!std.mem.startsWith(u8, url, "https://")) return;

    const argv: []const []const u8 = if (is_macos)
        &.{ "open", url }
    else if (is_windows)
        // The empty string is the window title; without it `start` treats the
        // URL as the title. No shell metacharacters reach a shell here.
        &.{ "cmd", "/c", "start", "", url }
    else
        &.{ "xdg-open", url };

    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    _ = child.spawnAndWait() catch return;
}

// ---------------------------------------------------------------------------
// Memory-mapped files
// ---------------------------------------------------------------------------

/// Read-only view of a file. Uses mmap where available so the binary registry
/// index costs no parsing and no copying; falls back to a heap read on Windows.
pub const MappedFile = struct {
    bytes: []const u8,
    map: ?[]align(std.mem.page_size) u8 = null,
    heap: ?[]u8 = null,
    allocator: std.mem.Allocator,

    pub fn open(allocator: std.mem.Allocator, path: []const u8) !MappedFile {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const size = (try file.stat()).size;
        if (size == 0) return error.EmptyFile;
        if (size > std.math.maxInt(usize)) return error.FileTooBig;
        const len: usize = @intCast(size);

        // `comptime` on the condition keeps the untaken branch out of
        // semantic analysis entirely: std.posix.mmap resolves to std.c.mmap on
        // Windows, which would demand libc for a code path that never runs.
        if (comptime is_posix) {
            const m = try std.posix.mmap(
                null,
                len,
                std.posix.PROT.READ,
                .{ .TYPE = .PRIVATE },
                file.handle,
                0,
            );
            return .{ .bytes = m[0..len], .map = m, .allocator = allocator };
        } else {
            const buf = try allocator.alloc(u8, len);
            errdefer allocator.free(buf);
            const read = try file.readAll(buf);
            if (read != len) return error.UnexpectedEndOfFile;
            return .{ .bytes = buf, .heap = buf, .allocator = allocator };
        }
    }

    pub fn deinit(self: *MappedFile) void {
        if (comptime is_posix) {
            if (self.map) |m| std.posix.munmap(m);
        }
        if (self.heap) |h| self.allocator.free(h);
        self.* = undefined;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "defaultPlatformTag matches a known platform" {
    try std.testing.expect(isKnownPlatformTag(defaultPlatformTag()));
}

test "isKnownPlatformTag rejects junk" {
    try std.testing.expect(!isKnownPlatformTag("../../etc"));
    try std.testing.expect(!isKnownPlatformTag(""));
    try std.testing.expect(!isKnownPlatformTag("sparc-solaris"));
    try std.testing.expect(isKnownPlatformTag("x86_64-linux"));
}

test "absolute ABV0_* override is applied" {
    const abs = if (is_windows) "C:\\abv0-test" else "/opt/abv0-test";
    try std.testing.expectEqualStrings(abs, acceptAbsolutePath(abs).?);
}

test "relative, empty and malformed ABV0_* overrides are ignored" {
    try std.testing.expect(acceptAbsolutePath("relative/dir") == null);
    try std.testing.expect(acceptAbsolutePath("") == null);
    try std.testing.expect(acceptAbsolutePath("/opt/abv0\nevil") == null);
    try std.testing.expect(acceptAbsolutePath("/opt/abv0\x00evil") == null);
}

test "ABV0_REGISTRY_URL accepts only https" {
    try std.testing.expectEqualStrings("https://example.com/index.json", acceptRegistryUrl("https://example.com/index.json").?);
    try std.testing.expect(acceptRegistryUrl("http://example.com/index.json") == null);
    try std.testing.expect(acceptRegistryUrl("file:///etc/passwd") == null);
    try std.testing.expect(acceptRegistryUrl("https://example.com/\nx") == null);
}

test "fastLink produces a usable destination and is idempotent" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const dir_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(dir_path);

    const src = try std.fs.path.join(std.testing.allocator, &.{ dir_path, "src.bin" });
    defer std.testing.allocator.free(src);
    const dst = try std.fs.path.join(std.testing.allocator, &.{ dir_path, "dst.bin" });
    defer std.testing.allocator.free(dst);

    {
        const f = try std.fs.cwd().createFile(src, .{});
        defer f.close();
        try f.writeAll("payload");
    }

    _ = try fastLink(src, dst);
    // Re-linking over an existing destination must succeed, not fail.
    _ = try fastLink(src, dst);

    const content = try std.fs.cwd().readFileAlloc(std.testing.allocator, dst, 64);
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("payload", content);
}

test "MappedFile round-trips file contents" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(dir_path);
    const p = try std.fs.path.join(std.testing.allocator, &.{ dir_path, "m.bin" });
    defer std.testing.allocator.free(p);

    {
        const f = try std.fs.cwd().createFile(p, .{});
        defer f.close();
        try f.writeAll("mapped-content");
    }

    var mf = try MappedFile.open(std.testing.allocator, p);
    defer mf.deinit();
    try std.testing.expectEqualStrings("mapped-content", mf.bytes);
}

test "linkProgram symlinks to an absolute target off Windows" {
    if (is_windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("store/bin");
    try tmp.dir.makePath("bin");
    try tmp.dir.writeFile(.{ .sub_path = "store/bin/tool", .data = "x" });
    var root_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const root = try tmp.dir.realpath(".", &root_buf);
    var src_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    var dst_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const src = try std.fmt.bufPrint(&src_buf, "{s}/store/bin/tool", .{root});
    const dst = try std.fmt.bufPrint(&dst_buf, "{s}/bin/tool", .{root});
    try tmp.dir.writeFile(.{ .sub_path = "bin/tool", .data = "old" });
    try std.testing.expectEqual(LinkKind.symlinked, try linkProgram(src, dst));
    var link_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    try std.testing.expectEqualStrings(src, try tmp.dir.readLink("bin/tool", &link_buf));
}
