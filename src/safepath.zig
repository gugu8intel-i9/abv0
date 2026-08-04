//! Path and identifier validation.
//!
//! Every string that reaches the filesystem after originating in a manifest,
//! an archive, or the command line passes through here first. Manifests are
//! fetched over the network, so they are treated as hostile input.

const std = @import("std");

pub const max_id_len = 128;
pub const max_rel_path_len = 4096;

/// Valid for use as a single path component that abv0 itself constructs
/// (package names, versions, platform ids). Deliberately strict.
pub fn isValidId(id: []const u8) bool {
    if (id.len == 0 or id.len > max_id_len) return false;

    // "." and ".." are the classic traversal primitives.
    if (std.mem.eql(u8, id, ".") or std.mem.eql(u8, id, "..")) return false;

    // A leading dash can be parsed as a flag by any tool we hand this to.
    if (id[0] == '-') return false;

    for (id) |ch| {
        switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '_', '.', '+' => {},
            else => return false,
        }
    }
    return true;
}

/// Valid as a *relative* path underneath a directory we control.
///
/// Rejects absolute paths, parent traversal, Windows drive letters, UNC
/// prefixes, NUL bytes and empty components. Accepts both separators because
/// a zip produced on Windows can legitimately contain backslashes, and we must
/// evaluate those as separators rather than as ordinary filename characters.
pub fn isSafeRelPath(p: []const u8) bool {
    if (p.len == 0 or p.len > max_rel_path_len) return false;
    if (std.mem.indexOfScalar(u8, p, 0) != null) return false;

    // Absolute (POSIX) or root-relative / UNC (Windows).
    if (p[0] == '/' or p[0] == '\\') return false;

    // Drive-qualified path such as "C:" or "C:\evil".
    if (p.len >= 2 and p[1] == ':') return false;

    var it = std.mem.splitAny(u8, p, "/\\");
    var component_count: usize = 0;
    while (it.next()) |component| {
        // A trailing separator yields a final empty component; that is fine.
        if (component.len == 0) {
            if (it.rest().len == 0) continue;
            return false; // "a//b" - ambiguous, refuse it
        }
        if (std.mem.eql(u8, component, "..")) return false;
        if (std.mem.eql(u8, component, ".")) return false;
        component_count += 1;
    }
    return component_count > 0;
}

/// True when `target` (the destination of a symlink stored at `link_dir_rel`)
/// stays inside the extraction root. Symlinks are the standard way to escape a
/// tar sandbox even when every member name looks safe.
pub fn symlinkStaysInside(link_dir_rel: []const u8, target: []const u8) bool {
    if (target.len == 0) return false;
    if (std.mem.indexOfScalar(u8, target, 0) != null) return false;
    if (target[0] == '/' or target[0] == '\\') return false;
    if (target.len >= 2 and target[1] == ':') return false;

    // Walk the link's directory, applying the target's components, and make
    // sure the running depth never goes negative.
    var depth: isize = 0;
    var dir_it = std.mem.splitAny(u8, link_dir_rel, "/\\");
    while (dir_it.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".")) continue;
        depth += 1;
    }

    var it = std.mem.splitAny(u8, target, "/\\");
    while (it.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".")) continue;
        if (std.mem.eql(u8, component, "..")) {
            depth -= 1;
            if (depth < 0) return false;
        } else {
            depth += 1;
        }
    }
    return true;
}

/// Join `rel` onto `base` only if `rel` cannot escape it.
pub fn joinSafe(allocator: std.mem.Allocator, base: []const u8, rel: []const u8) ![]u8 {
    if (!isSafeRelPath(rel)) return error.UnsafePath;
    return std.fs.path.join(allocator, &.{ base, rel });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "isValidId accepts ordinary package identifiers" {
    try std.testing.expect(isValidId("jq"));
    try std.testing.expect(isValidId("ripgrep"));
    try std.testing.expect(isValidId("1.7.1"));
    try std.testing.expect(isValidId("x86_64-macos"));
    try std.testing.expect(isValidId("1.0.0+build.5"));
}

test "isValidId rejects traversal and injection primitives" {
    try std.testing.expect(!isValidId(""));
    try std.testing.expect(!isValidId("."));
    try std.testing.expect(!isValidId(".."));
    try std.testing.expect(!isValidId("../etc"));
    try std.testing.expect(!isValidId("a/b"));
    try std.testing.expect(!isValidId("a\\b"));
    try std.testing.expect(!isValidId("--force"));
    try std.testing.expect(!isValidId("a b"));
    try std.testing.expect(!isValidId("a;rm -rf /"));
    try std.testing.expect(!isValidId("a\x00b"));
    try std.testing.expect(!isValidId("$(whoami)"));
    try std.testing.expect(!isValidId("a" ** 129));
}

test "isSafeRelPath accepts ordinary archive members" {
    try std.testing.expect(isSafeRelPath("bin/jq"));
    try std.testing.expect(isSafeRelPath("jq"));
    try std.testing.expect(isSafeRelPath("a/b/c/d.txt"));
    try std.testing.expect(isSafeRelPath("dir/"));
}

test "isSafeRelPath blocks the v1.5.0 traversal that was never actually fixed" {
    try std.testing.expect(!isSafeRelPath("../../../../.ssh/authorized_keys"));
    try std.testing.expect(!isSafeRelPath("/etc/passwd"));
    try std.testing.expect(!isSafeRelPath("..\\..\\Windows\\System32\\evil.dll"));
    try std.testing.expect(!isSafeRelPath("C:\\Windows\\evil"));
    try std.testing.expect(!isSafeRelPath("\\\\server\\share"));
    try std.testing.expect(!isSafeRelPath("bin/../../out"));
    try std.testing.expect(!isSafeRelPath("bin\x00/jq"));
    try std.testing.expect(!isSafeRelPath(""));
    try std.testing.expect(!isSafeRelPath("a//b"));
}

test "symlinkStaysInside permits internal links and blocks escapes" {
    try std.testing.expect(symlinkStaysInside("bin", "jq"));
    try std.testing.expect(symlinkStaysInside("bin", "../lib/libz.so"));
    try std.testing.expect(symlinkStaysInside("a/b/c", "../../d"));
    try std.testing.expect(!symlinkStaysInside("bin", "../../etc/passwd"));
    try std.testing.expect(!symlinkStaysInside("", "../x"));
    try std.testing.expect(!symlinkStaysInside("bin", "/etc/passwd"));
    try std.testing.expect(!symlinkStaysInside("bin", "C:\\evil"));
}

test "joinSafe refuses to build an escaping path" {
    const a = std.testing.allocator;
    const ok = try joinSafe(a, "/tmp/store", "bin/jq");
    defer a.free(ok);
    try std.testing.expect(std.mem.endsWith(u8, ok, "bin/jq"));
    try std.testing.expectError(error.UnsafePath, joinSafe(a, "/tmp/store", "../../etc/passwd"));
}
