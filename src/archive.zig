//! In-process, sandboxed archive extraction.
//!
//! Previously extraction shelled out to `tar`, `unzip` and `hdiutil`. That was
//! slow (a fork+exec per install), unavailable on Windows (`unzip` does not
//! ship there), and unsafe: nothing validated member paths, so a malicious
//! tarball could write outside the store via `../` members or via a symlink
//! pointing out of the extraction root.
//!
//! Every member name is now checked with `safepath` before it touches the
//! filesystem, and symlink targets are resolved against the extraction root.

const std = @import("std");
const builtin = @import("builtin");
const safepath = @import("safepath.zig");
const platform = @import("platform.zig");

pub const Kind = enum {
    tar,
    tar_gz,
    tar_xz,
    tar_zst,
    zip,
    raw,
    dmg,

    pub fn fromString(s: []const u8) ?Kind {
        const table = .{
            .{ "tar", Kind.tar },
            .{ "tar.gz", Kind.tar_gz },
            .{ "tgz", Kind.tar_gz },
            .{ "tar.xz", Kind.tar_xz },
            .{ "txz", Kind.tar_xz },
            .{ "tar.zst", Kind.tar_zst },
            .{ "zip", Kind.zip },
            .{ "raw", Kind.raw },
            .{ "dmg", Kind.dmg },
        };
        inline for (table) |pair| {
            if (std.mem.eql(u8, s, pair[0])) return pair[1];
        }
        return null;
    }

    pub fn fromFilename(name: []const u8) ?Kind {
        const table = .{
            .{ ".tar.gz", Kind.tar_gz },
            .{ ".tgz", Kind.tar_gz },
            .{ ".tar.xz", Kind.tar_xz },
            .{ ".txz", Kind.tar_xz },
            .{ ".tar.zst", Kind.tar_zst },
            .{ ".tar", Kind.tar },
            .{ ".zip", Kind.zip },
            .{ ".dmg", Kind.dmg },
        };
        inline for (table) |pair| {
            if (std.mem.endsWith(u8, name, pair[0])) return pair[1];
        }
        return null;
    }
};

/// What the bytes on disk actually are, regardless of what the manifest claims.
///
/// This catches the common failure where a CDN returns an HTML error page and
/// the package manager cheerfully installs it as an executable.
pub fn sniff(path: []const u8) ?Kind {
    const file = std.fs.cwd().openFile(path, .{}) catch return null;
    defer file.close();

    var head: [512]u8 = undefined;
    const n = file.readAll(&head) catch return null;
    const buf = head[0..n];

    if (n >= 2 and buf[0] == 0x1f and buf[1] == 0x8b) return .tar_gz;
    if (n >= 6 and std.mem.eql(u8, buf[0..6], &.{ 0xFD, '7', 'z', 'X', 'Z', 0x00 })) return .tar_xz;
    if (n >= 4 and std.mem.eql(u8, buf[0..4], &.{ 0x28, 0xB5, 0x2F, 0xFD })) return .tar_zst;
    if (n >= 4 and std.mem.eql(u8, buf[0..4], &.{ 'P', 'K', 0x03, 0x04 })) return .zip;
    if (n >= 262 and std.mem.eql(u8, buf[257..262], "ustar")) return .tar;
    return null;
}

/// True when the payload is obviously an HTML/text error page rather than a
/// binary or archive.
pub fn looksLikeErrorPage(path: []const u8) bool {
    const file = std.fs.cwd().openFile(path, .{}) catch return false;
    defer file.close();

    var head: [256]u8 = undefined;
    const n = file.readAll(&head) catch return false;
    if (n == 0) return true; // a zero-byte "binary" is never valid

    const buf = head[0..n];
    const markers = [_][]const u8{ "<!DOCTYPE", "<!doctype", "<html", "<HTML", "404: Not Found", "Not Found" };
    for (markers) |m| {
        if (std.mem.indexOf(u8, buf, m) != null) return true;
    }
    return false;
}

/// Upper bounds on what one archive may expand to. A few kilobytes of gzip can
/// claim terabytes of output, so extraction stops once either limit is passed.
pub const max_extract_bytes: u64 = 4 * 1024 * 1024 * 1024;
pub const max_extract_members: usize = 200_000;

pub const Options = struct {
    /// Destination name for `raw` payloads (a bare executable, not an archive).
    raw_name: []const u8 = "payload",
    /// Directory levels to strip from member paths.
    strip_components: u32 = 0,
    /// Total member bytes allowed before extraction is refused.
    max_bytes: u64 = max_extract_bytes,
    /// Member count allowed before extraction is refused.
    max_members: usize = max_extract_members,
};

/// Extract `archive_path` into `dest_dir_path`.
pub fn extract(
    allocator: std.mem.Allocator,
    kind: Kind,
    archive_path: []const u8,
    dest_dir_path: []const u8,
    options: Options,
) !void {
    var dest = try std.fs.cwd().openDir(dest_dir_path, .{});
    defer dest.close();

    switch (kind) {
        .raw => {
            if (!safepath.isSafeRelPath(options.raw_name)) return error.UnsafePath;
            if (std.fs.path.dirname(options.raw_name)) |d| dest.makePath(d) catch {};
            const dst = try std.fs.path.join(allocator, &.{ dest_dir_path, options.raw_name });
            defer allocator.free(dst);
            try std.fs.cwd().rename(archive_path, dst);
            platform.setExecutable(dst);
        },
        .zip => {
            const file = try std.fs.cwd().openFile(archive_path, .{});
            defer file.close();
            try checkZipLimits(file, options);
            // std.zip rejects absolute paths and `..` components internally.
            // It only creates files and directories, so it cannot plant a link.
            try std.zip.extract(dest, file.seekableStream(), .{});
        },
        .tar, .tar_gz, .tar_xz, .tar_zst => try extractTar(allocator, kind, archive_path, dest, options),
        .dmg => try extractDmg(allocator, archive_path, dest_dir_path),
    }
}

fn extractTar(
    allocator: std.mem.Allocator,
    kind: Kind,
    archive_path: []const u8,
    dest: std.fs.Dir,
    options: Options,
) !void {
    const file = try std.fs.cwd().openFile(archive_path, .{});
    defer file.close();

    var buffered = std.io.bufferedReaderSize(64 * 1024, file.reader());
    const src = buffered.reader();

    switch (kind) {
        .tar => try pipeTar(allocator, src, dest, options),
        .tar_gz => {
            var dec = std.compress.gzip.decompressor(src);
            try pipeTar(allocator, dec.reader(), dest, options);
        },
        .tar_xz => {
            var dec = try std.compress.xz.decompress(allocator, src);
            defer dec.deinit();
            try pipeTar(allocator, dec.reader(), dest, options);
        },
        .tar_zst => {
            const window = try allocator.alloc(u8, 1 << 23);
            defer allocator.free(window);
            var dec = std.compress.zstd.decompressor(src, .{ .window_buffer = window });
            try pipeTar(allocator, dec.reader(), dest, options);
        },
        else => unreachable,
    }
}

/// std.zip has no limits of its own, so read the central directory first and
/// refuse before anything is written.
fn checkZipLimits(file: std.fs.File, options: Options) !void {
    const Stream = @TypeOf(file.seekableStream());
    var iter = try std.zip.Iterator(Stream).init(file.seekableStream());

    var members: usize = 0;
    var total: u64 = 0;
    while (try iter.next()) |entry| {
        members += 1;
        if (members > options.max_members) return error.ArchiveTooManyMembers;
        total +|= entry.uncompressed_size;
        if (total > options.max_bytes) return error.ArchiveTooLarge;
    }
}

fn stripComponents(path: []const u8, count: u32) []const u8 {
    var i: usize = 0;
    var c = count;
    while (c > 0) : (c -= 1) {
        if (std.mem.indexOfScalarPos(u8, path, i, '/')) |pos| {
            i = pos + 1;
        } else {
            return path[path.len..];
        }
    }
    return path[i..];
}

/// The safety-critical loop. `std.tar.pipeToFileSystem` is deliberately not
/// used because it performs no containment check on member names.
fn pipeTar(
    allocator: std.mem.Allocator,
    reader: anytype,
    dest: std.fs.Dir,
    options: Options,
) !void {
    var file_name_buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    var link_name_buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;

    var it = std.tar.iterator(reader, .{
        .file_name_buffer = &file_name_buffer,
        .link_name_buffer = &link_name_buffer,
    });

    var members: usize = 0;
    var total_bytes: u64 = 0;

    while (try it.next()) |entry| {
        // Counted before any filtering, so skipped members cannot hide cost.
        members += 1;
        if (members > options.max_members) return error.ArchiveTooManyMembers;
        total_bytes +|= entry.size;
        if (total_bytes > options.max_bytes) return error.ArchiveTooLarge;

        const name = stripComponents(entry.name, options.strip_components);
        if (name.len == 0) continue;

        // Refuse anything that could land outside the extraction root.
        if (!safepath.isSafeRelPath(name)) continue;

        // createFile and makePath follow links. An earlier member may have
        // created a link on disk (`a/l -> ..`), so a later name can route
        // through it. Check every existing component, including the last.
        if (passesThroughSymlink(dest, name, true)) continue;

        switch (entry.kind) {
            .directory => {
                dest.makePath(name) catch continue;
            },
            .file => {
                if (std.fs.path.dirname(name)) |d| dest.makePath(d) catch {};
                // Only the permission bits matter here. setuid, setgid and
                // sticky are dropped, and the mode is one of two fixed values.
                const perm = entry.mode & 0o777;
                const mode: std.fs.File.Mode = if (std.fs.has_executable_bit and (perm & 0o100) != 0)
                    platform.mode_bin
                else
                    platform.mode_public;
                const out = dest.createFile(name, .{ .mode = mode }) catch continue;
                defer out.close();
                try entry.writeAll(out);
            },
            .sym_link => {
                const link_dir = std.fs.path.dirname(name) orelse "";
                // A member name can be safe while its symlink target escapes.
                if (!safepath.symlinkStaysInside(link_dir, entry.link_name)) continue;
                // The target text can also run through a link already on disk.
                if (try targetCrossesSymlink(allocator, dest, link_dir, entry.link_name)) continue;
                if (std.fs.path.dirname(name)) |d| dest.makePath(d) catch {};
                // Unprivileged Windows accounts cannot create symlinks; skip.
                dest.symLink(entry.link_name, name, .{}) catch continue;
            },
        }
    }
}

/// True when `rel` names a symbolic link on disk under `dest`.
fn isLinkOnDisk(dest: std.fs.Dir, rel: []const u8) bool {
    var buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    _ = dest.readLink(rel, &buf) catch return false;
    return true;
}

/// True when some existing parent of `rel` is a symlink, or, with
/// `include_last` set, when `rel` itself is one.
fn passesThroughSymlink(dest: std.fs.Dir, rel: []const u8, include_last: bool) bool {
    var end: usize = 0;
    while (std.mem.indexOfAnyPos(u8, rel, end, "/\\")) |sep| {
        if (sep > end and isLinkOnDisk(dest, rel[0..sep])) return true;
        end = sep + 1;
    }
    return include_last and rel.len > end and isLinkOnDisk(dest, rel);
}

/// `safepath.symlinkStaysInside` reads only the link text. A target such as
/// `a/l/..` also depends on what `a/l` is on disk. Every component the target
/// walks through before its last one must therefore not be a link already.
/// The last component may be one, since that is an ordinary link chain.
fn targetCrossesSymlink(
    allocator: std.mem.Allocator,
    dest: std.fs.Dir,
    link_dir: []const u8,
    target: []const u8,
) !bool {
    // Where the walk currently is, relative to `dest`.
    var here = std.ArrayList([]const u8).init(allocator);
    defer here.deinit();
    var dir_it = std.mem.tokenizeAny(u8, link_dir, "/\\");
    while (dir_it.next()) |c| try here.append(c);

    var steps = std.ArrayList([]const u8).init(allocator);
    defer steps.deinit();
    var tgt_it = std.mem.tokenizeAny(u8, target, "/\\");
    while (tgt_it.next()) |c| {
        if (std.mem.eql(u8, c, ".")) continue;
        try steps.append(c);
    }

    for (steps.items, 0..) |c, i| {
        if (std.mem.eql(u8, c, "..")) {
            // safepath has already ensured the walk never leaves the root.
            if (here.items.len > 0) _ = here.pop();
            continue;
        }
        try here.append(c);
        if (i + 1 < steps.items.len) {
            const joined = try std.mem.join(allocator, "/", here.items);
            defer allocator.free(joined);
            if (isLinkOnDisk(dest, joined)) return true;
        }
    }
    return false;
}

fn extractDmg(allocator: std.mem.Allocator, archive_path: []const u8, dest_dir_path: []const u8) !void {
    if (!platform.is_macos) return error.DmgUnsupportedOnThisPlatform;

    // Attach at a mount point we create, so the only volume we read from or
    // detach is the one this image produced. Scanning /Volumes could reach an
    // unrelated disk.
    const mount_name = try std.fmt.allocPrint(allocator, ".abv0-dmg-{x}", .{std.crypto.random.int(u64)});
    defer allocator.free(mount_name);
    const mount_point = try std.fs.path.join(allocator, &.{ dest_dir_path, mount_name });
    defer allocator.free(mount_point);

    try std.fs.cwd().makePath(mount_point);
    // Runs last, after the detach below.
    defer std.fs.cwd().deleteDir(mount_point) catch {};

    const attach = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "hdiutil", "attach", "-readonly", "-nobrowse", "-noverify", "-noautoopen", "-quiet", "-mountpoint", mount_point, archive_path },
    });
    defer {
        allocator.free(attach.stdout);
        allocator.free(attach.stderr);
    }
    if (attach.term != .Exited or attach.term.Exited != 0) return error.DmgMountFailed;

    // The image is attached from here on, so detach on every path out.
    defer detachDmg(allocator, mount_point);

    var mounted = std.fs.cwd().openDir(mount_point, .{ .iterate = true }) catch return error.DmgMountFailed;
    defer mounted.close();

    var entries = mounted.iterate();
    while (try entries.next()) |entry| {
        if (!std.mem.endsWith(u8, entry.name, ".app")) continue;

        const src_app = try std.fs.path.join(allocator, &.{ mount_point, entry.name });
        defer allocator.free(src_app);
        const dst_app = try std.fs.path.join(allocator, &.{ dest_dir_path, entry.name });
        defer allocator.free(dst_app);

        try platform.copyTree(src_app, dst_app);
        return;
    }
    return error.DmgNoApplicationFound;
}

/// Detach our own mount point. A failure here is not fatal, because the copy
/// is already finished, but the mount is left for the user to eject.
fn detachDmg(allocator: std.mem.Allocator, mount_point: []const u8) void {
    const detach = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "hdiutil", "detach", "-quiet", mount_point },
    }) catch return;
    allocator.free(detach.stdout);
    allocator.free(detach.stderr);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "Kind parsing" {
    try testing.expectEqual(Kind.tar_gz, Kind.fromString("tar.gz").?);
    try testing.expectEqual(Kind.zip, Kind.fromString("zip").?);
    try testing.expectEqual(Kind.raw, Kind.fromString("raw").?);
    try testing.expect(Kind.fromString("rar") == null);
    try testing.expectEqual(Kind.tar_xz, Kind.fromFilename("tool-v1.2.3-x86_64.tar.xz").?);
    try testing.expectEqual(Kind.zip, Kind.fromFilename("tool.zip").?);
}

test "stripComponents" {
    try testing.expectEqualStrings("bin/jq", stripComponents("jq-1.7/bin/jq", 1));
    try testing.expectEqualStrings("jq", stripComponents("jq-1.7/bin/jq", 2));
    try testing.expectEqualStrings("jq-1.7/bin/jq", stripComponents("jq-1.7/bin/jq", 0));
    try testing.expectEqualStrings("", stripComponents("jq", 3));
}

fn writeTarEntry(w: anytype, name: []const u8, content: []const u8, kind: u8, link: []const u8) !void {
    try writeTarEntryMode(w, name, content, kind, link, 0o644);
}

fn writeTarEntryMode(w: anytype, name: []const u8, content: []const u8, kind: u8, link: []const u8, mode: u32) !void {
    var header = [_]u8{0} ** 512;
    @memcpy(header[0..name.len], name);
    _ = try std.fmt.bufPrint(header[100..108], "{o:0>7}\x00", .{mode});
    _ = try std.fmt.bufPrint(header[108..116], "0000000\x00", .{});
    _ = try std.fmt.bufPrint(header[116..124], "0000000\x00", .{});
    _ = try std.fmt.bufPrint(header[124..136], "{o:0>11} ", .{content.len});
    _ = try std.fmt.bufPrint(header[136..148], "{o:0>11} ", .{@as(u64, 0)});
    header[156] = kind;
    if (link.len > 0) @memcpy(header[157..][0..link.len], link);
    @memcpy(header[257..262], "ustar");
    header[263] = '0';
    header[264] = '0';

    // Checksum: sum of all bytes with the checksum field treated as spaces.
    @memset(header[148..156], ' ');
    var sum: u32 = 0;
    for (header) |b| sum += b;
    _ = try std.fmt.bufPrint(header[148..156], "{o:0>6}\x00 ", .{sum});

    try w.writeAll(&header);
    if (content.len > 0) {
        try w.writeAll(content);
        const pad = (512 - (content.len % 512)) % 512;
        try w.writeByteNTimes(0, pad);
    }
}

fn buildTar(list: *std.ArrayList(u8), entries: anytype) !void {
    const w = list.writer();
    inline for (entries) |e| {
        try writeTarEntry(w, e[0], e[1], e[2], e[3]);
    }
    try w.writeByteNTimes(0, 1024); // end-of-archive
}

test "tar extraction writes safe members" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try buildTar(&buf, .{
        .{ "bin/tool", "#!/bin/sh\necho hi\n", '0', "" },
        .{ "README", "docs", '0', "" },
    });

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var stream = std.io.fixedBufferStream(buf.items);
    try pipeTar(testing.allocator, stream.reader(), tmp.dir, .{});

    const content = try tmp.dir.readFileAlloc(testing.allocator, "bin/tool", 128);
    defer testing.allocator.free(content);
    try testing.expectEqualStrings("#!/bin/sh\necho hi\n", content);
}

test "tar extraction refuses ../ members (tar slip)" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try buildTar(&buf, .{
        .{ "../../escaped.txt", "pwned", '0', "" },
        .{ "safe.txt", "ok", '0', "" },
    });

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var stream = std.io.fixedBufferStream(buf.items);
    try pipeTar(testing.allocator, stream.reader(), tmp.dir, .{});

    // The safe member landed...
    const ok = try tmp.dir.readFileAlloc(testing.allocator, "safe.txt", 16);
    defer testing.allocator.free(ok);
    try testing.expectEqualStrings("ok", ok);

    // ...and the escaping member did not, anywhere.
    try testing.expectError(error.FileNotFound, tmp.dir.access("../../escaped.txt", .{}));
    try testing.expectError(error.FileNotFound, tmp.dir.access("escaped.txt", .{}));
}

test "tar extraction refuses absolute member paths" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try buildTar(&buf, .{.{ "/tmp/abv0-should-not-exist", "pwned", '0', "" }});

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var stream = std.io.fixedBufferStream(buf.items);
    try pipeTar(testing.allocator, stream.reader(), tmp.dir, .{});

    try testing.expectError(error.FileNotFound, std.fs.cwd().access("/tmp/abv0-should-not-exist", .{}));
}

test "tar extraction refuses symlinks that escape the root" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try buildTar(&buf, .{
        .{ "escape", "", '2', "../../../../etc/passwd" },
        .{ "inside", "", '2', "real" },
        .{ "real", "content", '0', "" },
    });

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var stream = std.io.fixedBufferStream(buf.items);
    try pipeTar(testing.allocator, stream.reader(), tmp.dir, .{});

    try testing.expectError(error.FileNotFound, tmp.dir.access("escape", .{}));
    if (!platform.is_windows) {
        try tmp.dir.access("inside", .{});
    }
}

test "tar extraction refuses to write through a symlink chain" {
    if (platform.is_windows) return error.SkipZigTest;

    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    // Each name passes on its own. Together, `p/...` lands in the directory
    // above the root, because `a/l/..` resolves through the earlier `a/l`.
    try buildTar(&buf, .{
        .{ "a/l", "", '2', ".." },
        .{ "p", "", '2', "a/l/.." },
        .{ "p/abv0-escape-probe", "pwned", '0', "" },
    });

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var stream = std.io.fixedBufferStream(buf.items);
    try pipeTar(testing.allocator, stream.reader(), tmp.dir, .{});

    // The escape target is the parent of the extraction root.
    try testing.expectError(error.FileNotFound, tmp.parent_dir.access("abv0-escape-probe", .{}));
    // The chain's second link was never created.
    var link_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    try testing.expectError(error.NotLink, tmp.dir.readLink("p", &link_buf));
}

test "tar extraction refuses members that route through an earlier symlink" {
    if (platform.is_windows) return error.SkipZigTest;

    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try buildTar(&buf, .{
        .{ "a/l", "", '2', ".." },
        .{ "a/l/abv0-escape-probe", "pwned", '0', "" },
        .{ "a/l/sub/file", "pwned", '0', "" },
    });

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var stream = std.io.fixedBufferStream(buf.items);
    try pipeTar(testing.allocator, stream.reader(), tmp.dir, .{});

    // Neither write goes through the link, so nothing lands at the root.
    try testing.expectError(error.FileNotFound, tmp.dir.access("abv0-escape-probe", .{}));
    try testing.expectError(error.FileNotFound, tmp.dir.access("sub/file", .{}));
}

test "tar extraction strips setuid, setgid and sticky bits" {
    if (platform.is_windows) return error.SkipZigTest;

    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    const w = buf.writer();
    try writeTarEntryMode(w, "bin/suid", "#!/bin/sh\n", '0', "", 0o4755);
    try writeTarEntryMode(w, "bin/sgid", "#!/bin/sh\n", '0', "", 0o2755);
    try writeTarEntryMode(w, "bin/sticky", "#!/bin/sh\n", '0', "", 0o1755);
    try w.writeByteNTimes(0, 1024);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var stream = std.io.fixedBufferStream(buf.items);
    try pipeTar(testing.allocator, stream.reader(), tmp.dir, .{});

    for ([_][]const u8{ "bin/suid", "bin/sgid", "bin/sticky" }) |name| {
        const st = try tmp.dir.statFile(name);
        try testing.expectEqual(@as(std.fs.File.Mode, 0), st.mode & 0o7000);
        try testing.expectEqual(@as(std.fs.File.Mode, 0o755), st.mode & 0o777);
    }
}

test "tar extraction stops at the member and byte caps" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try buildTar(&buf, .{
        .{ "a", "1", '0', "" },
        .{ "b", "2", '0', "" },
        .{ "c", "3", '0', "" },
    });

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var stream = std.io.fixedBufferStream(buf.items);
    try testing.expectError(
        error.ArchiveTooManyMembers,
        pipeTar(testing.allocator, stream.reader(), tmp.dir, .{ .max_members = 2 }),
    );

    stream.reset();
    try testing.expectError(
        error.ArchiveTooLarge,
        pipeTar(testing.allocator, stream.reader(), tmp.dir, .{ .max_bytes = 2 }),
    );

    // Under the limits the same archive extracts normally.
    stream.reset();
    try pipeTar(testing.allocator, stream.reader(), tmp.dir, .{ .max_members = 3, .max_bytes = 3 });
    try tmp.dir.access("c", .{});
}

test "sniff identifies formats and rejects an HTML error page" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);

    const html = try std.fs.path.join(testing.allocator, &.{ root, "err.bin" });
    defer testing.allocator.free(html);
    {
        const f = try std.fs.cwd().createFile(html, .{});
        defer f.close();
        try f.writeAll("<!DOCTYPE html><html><body>404: Not Found</body></html>");
    }
    try testing.expect(looksLikeErrorPage(html));
    try testing.expect(sniff(html) == null);

    const gz = try std.fs.path.join(testing.allocator, &.{ root, "a.gz" });
    defer testing.allocator.free(gz);
    {
        const f = try std.fs.cwd().createFile(gz, .{});
        defer f.close();
        try f.writeAll(&.{ 0x1f, 0x8b, 0x08, 0x00 });
    }
    try testing.expectEqual(Kind.tar_gz, sniff(gz).?);

    const empty = try std.fs.path.join(testing.allocator, &.{ root, "empty.bin" });
    defer testing.allocator.free(empty);
    (try std.fs.cwd().createFile(empty, .{})).close();
    // A zero-byte download is exactly the shipped abv0-darwin-x86_64 bug.
    try testing.expect(looksLikeErrorPage(empty));
}
