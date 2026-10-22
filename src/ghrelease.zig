//! GitHub release support for `abv0 install gh:owner/repo[@tag]`.
//!
//! A `gh:` install takes its binary from a release asset that the project
//! itself published. This module does three things with the REST API:
//!
//!   * `parseSpec` and `apiUrl` turn the user's `owner/repo[@tag]` into a
//!     validated `releases/latest` or `releases/tags/{tag}` URL.
//!   * `parseRelease` reads the JSON response. Only the fields the installer
//!     needs are kept, and each asset's `digest` is captured so the download
//!     can be checked against GitHub's own SHA-256 before anything is
//!     extracted.
//!   * `pickAsset` chooses the one asset that matches the host, by file name.
//!
//! Why unexpected types are errors: a field with the wrong type usually means
//! the response is not what we asked for (a proxy page, an API change). Guessing
//! a value could install the wrong file, so the whole release is rejected.
//!
//! Why a missing or malformed `digest` is `null` rather than an error: the field
//! only exists on assets GitHub has hashed. The installer decides what to do
//! without a hash, and this module never fabricates one.
//!
//! Why asset URLs must be https: the download URL comes from the response. The
//! shared `net.isSafeUrl` check rejects plain http, `file://`, userinfo and
//! characters that could be read as shell or option syntax. An asset that fails
//! the check is dropped instead of failing the whole release, so one odd entry
//! cannot hide the rest.
//!
//! Why asset names are checked as plain file names: they become file names in
//! the download directory. Names containing a path separator, a control
//! character, or equal to `.` or `..` are dropped for the same reason.

const std = @import("std");
const net = @import("net.zig");
const platform = @import("platform.zig");

pub const Asset = struct {
    name: []const u8,
    url: []const u8,
    size: u64,
    /// The 64 lowercase hex characters of the SHA-256 from GitHub's `digest`
    /// field (the hex text itself, not raw bytes), or null when absent.
    sha256: ?[64]u8,
};

pub const Release = struct {
    tag: []const u8,
    assets: []Asset,
};

/// A parsed `owner/repo[@tag]` specification. Slices point into the input.
pub const Spec = struct {
    owner: []const u8,
    repo: []const u8,
    tag: ?[]const u8,
};

const max_name_len = 100;
const max_tag_len = 255;

// ---------------------------------------------------------------------------
// Specs and URLs
// ---------------------------------------------------------------------------

fn isNameChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == '-';
}

/// `owner` and `repo` as GitHub accepts them: 1..100 characters from
/// `[A-Za-z0-9._-]`, not `.` or `..`, and no leading `-`, so the name can never
/// be read as a command-line option.
fn validName(s: []const u8) bool {
    if (s.len == 0 or s.len > max_name_len) return false;
    if (s[0] == '-') return false;
    if (std.mem.eql(u8, s, ".") or std.mem.eql(u8, s, "..")) return false;
    for (s) |c| {
        if (!isNameChar(c)) return false;
    }
    return true;
}

/// A release tag from `[A-Za-z0-9._+/-]`. `..` and a bare `.` are refused
/// because an HTTP client would normalise them as path segments and request a
/// different endpoint than the one the user named.
fn validTag(s: []const u8) bool {
    if (s.len == 0 or s.len > max_tag_len) return false;
    if (std.mem.eql(u8, s, ".")) return false;
    if (std.mem.indexOf(u8, s, "..") != null) return false;
    for (s) |c| {
        const ok = std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == '+' or c == '-' or c == '/';
        if (!ok) return false;
    }
    return true;
}

/// Parses `owner/repo` with an optional `@tag` suffix. The leading `gh:`
/// scheme used on the command line is accepted and stripped, so either form
/// works. Returns null for anything that is not exactly one owner, one repo and
/// an optional valid tag.
pub fn parseSpec(spec: []const u8) ?Spec {
    const body = if (std.mem.startsWith(u8, spec, "gh:")) spec["gh:".len..] else spec;

    const at = std.mem.indexOfScalar(u8, body, '@');
    const path = if (at) |i| body[0..i] else body;
    const tag: ?[]const u8 = if (at) |i| body[i + 1 ..] else null;
    if (tag) |t| {
        if (!validTag(t)) return null;
    }

    const slash = std.mem.indexOfScalar(u8, path, '/') orelse return null;
    const owner = path[0..slash];
    const repo = path[slash + 1 ..];
    if (std.mem.indexOfScalar(u8, repo, '/') != null) return null;
    if (!validName(owner) or !validName(repo)) return null;
    return .{ .owner = owner, .repo = repo, .tag = tag };
}

/// Builds `https://api.github.com/repos/{owner}/{repo}/releases/latest`, or
/// `.../releases/tags/{tag}` when a tag is given. The tag is percent-encoded
/// (`+` becomes `%2B`, `/` becomes `%2F`), so it can never add a path segment or
/// query parameter. Caller frees the result.
pub fn apiUrl(a: std.mem.Allocator, owner: []const u8, repo: []const u8, tag: ?[]const u8) ![]u8 {
    if (!validName(owner) or !validName(repo)) return error.InvalidName;

    var out = std.ArrayList(u8).init(a);
    errdefer out.deinit();
    const w = out.writer();
    try w.print("https://api.github.com/repos/{s}/{s}/releases", .{ owner, repo });

    if (tag) |t| {
        if (!validTag(t)) return error.InvalidTag;
        try w.writeAll("/tags/");
        for (t) |c| {
            if (std.ascii.isAlphanumeric(c) or c == '-' or c == '.' or c == '_') {
                try w.writeByte(c);
            } else {
                try w.print("%{X:0>2}", .{c});
            }
        }
    } else {
        try w.writeAll("/latest");
    }
    return out.toOwnedSlice();
}

// ---------------------------------------------------------------------------
// Release JSON
// ---------------------------------------------------------------------------

fn requireString(obj: std.json.ObjectMap, key: []const u8) ![]const u8 {
    const v = obj.get(key) orelse return error.MalformedRelease;
    return switch (v) {
        .string => |s| s,
        else => error.MalformedRelease,
    };
}

fn requireSize(obj: std.json.ObjectMap, key: []const u8) !u64 {
    const v = obj.get(key) orelse return error.MalformedRelease;
    return switch (v) {
        .integer => |i| std.math.cast(u64, i) orelse error.MalformedRelease,
        else => error.MalformedRelease,
    };
}

/// Accepts only `sha256:` followed by 64 lowercase hex characters. Any other
/// shape (another algorithm, uppercase hex, a non-string) yields null, so the
/// asset is kept but unverified rather than mis-verified.
fn parseDigest(v: ?std.json.Value) ?[64]u8 {
    const val = v orelse return null;
    const s = switch (val) {
        .string => |str| str,
        else => return null,
    };
    const prefix = "sha256:";
    if (!std.mem.startsWith(u8, s, prefix) or s.len != prefix.len + 64) return null;

    var out: [64]u8 = undefined;
    for (s[prefix.len..], 0..) |c, i| {
        const lower_hex = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        if (!lower_hex) return null;
        out[i] = c;
    }
    return out;
}

/// A name that can be used as a single file name in the download directory.
fn isPlainFileName(s: []const u8) bool {
    if (s.len == 0 or std.mem.eql(u8, s, ".") or std.mem.eql(u8, s, "..")) return false;
    for (s) |c| {
        if (c == '/' or c == '\\' or c < 0x20 or c == 0x7f) return false;
    }
    return true;
}

/// Parses a `GET /repos/{o}/{r}/releases/latest` or `/releases/tags/{tag}`
/// response. The returned slices may point into `json` or into `arena`, so both
/// must outlive the result.
///
/// Errors:
///   * `error.GitHubApiMessage`: the body is an API error such as a rate-limit
///     or 404 (`{"message": ...}` without a `tag_name`).
///   * `error.MalformedRelease`: a required field is missing or has the wrong
///     type, or the root is not an object.
///   * Any `std.json` error for truncated or invalid JSON.
///
/// Assets with a non-https URL, or with a name that is not a plain file name,
/// are dropped rather than failing the release.
pub fn parseRelease(arena: std.mem.Allocator, json: []const u8) !Release {
    const root = try std.json.parseFromSliceLeaky(std.json.Value, arena, json, .{});
    const obj = switch (root) {
        .object => |o| o,
        else => return error.MalformedRelease,
    };

    if (obj.get("tag_name") == null) {
        if (obj.get("message") != null) return error.GitHubApiMessage;
        return error.MalformedRelease;
    }
    const tag = try requireString(obj, "tag_name");
    if (tag.len == 0) return error.MalformedRelease;

    const assets_val = obj.get("assets") orelse return error.MalformedRelease;
    const items = switch (assets_val) {
        .array => |arr| arr.items,
        else => return error.MalformedRelease,
    };

    var list = std.ArrayList(Asset).init(arena);
    for (items) |item| {
        const a = switch (item) {
            .object => |o| o,
            else => return error.MalformedRelease,
        };
        const name = try requireString(a, "name");
        const url = try requireString(a, "browser_download_url");
        const size = try requireSize(a, "size");
        const sha256 = parseDigest(a.get("digest"));

        if (!net.isSafeUrl(url) or !isPlainFileName(name)) continue;
        try list.append(.{ .name = name, .url = url, .size = size, .sha256 = sha256 });
    }

    return .{ .tag = tag, .assets = try list.toOwnedSlice() };
}

// ---------------------------------------------------------------------------
// Asset selection
// ---------------------------------------------------------------------------

const Arch = enum { x86_64, aarch64 };
const Os = enum { linux, macos, windows };
const Target = struct { arch: Arch, os: Os };

fn parsePlatformTag(tag: []const u8) ?Target {
    // Reuses the canonical list so this module cannot drift from platform.zig.
    if (!platform.isKnownPlatformTag(tag)) return null;
    const dash = std.mem.lastIndexOfScalar(u8, tag, '-') orelse return null;
    const arch: Arch = if (std.mem.eql(u8, tag[0..dash], "x86_64"))
        .x86_64
    else if (std.mem.eql(u8, tag[0..dash], "aarch64"))
        .aarch64
    else
        return null;
    const os: Os = if (std.mem.eql(u8, tag[dash + 1 ..], "linux"))
        .linux
    else if (std.mem.eql(u8, tag[dash + 1 ..], "macos"))
        .macos
    else if (std.mem.eql(u8, tag[dash + 1 ..], "windows"))
        .windows
    else
        return null;
    return .{ .arch = arch, .os = os };
}

/// How a needle must sit inside a file name.
const Match = enum {
    /// Bounded on both sides by a non-alphanumeric character or the name's
    /// edge. Stops `win` matching inside `windows` and `arm64` inside `arm64e`.
    token,
    /// Bounded on the left only. Used for architecture names such as `ppc64le`
    /// or `riscv64gc`, where a suffix is still the same architecture.
    prefix,
    /// Plain case-insensitive substring.
    substring,
};

/// Case-insensitive search for `needle` in `name`, honouring `mode`.
fn has(name: []const u8, needle: []const u8, mode: Match) bool {
    var start: usize = 0;
    while (std.ascii.indexOfIgnoreCasePos(name, start, needle)) |i| {
        const end = i + needle.len;
        const left_ok = i == 0 or !std.ascii.isAlphanumeric(name[i - 1]);
        const right_ok = end == name.len or !std.ascii.isAlphanumeric(name[end]);
        const ok = switch (mode) {
            .token => left_ok and right_ok,
            .prefix => left_ok,
            .substring => true,
        };
        if (ok) return true;
        start = i + 1;
    }
    return false;
}

fn hasAny(name: []const u8, needles: []const []const u8) bool {
    for (needles) |n| {
        if (has(name, n, .token)) return true;
    }
    return false;
}

const macos_tokens = [_][]const u8{ "darwin", "macos", "mac", "osx", "apple" };
const windows_tokens = [_][]const u8{ "windows", "win64", "win" };
const x86_tokens = [_][]const u8{ "x86_64", "amd64", "x64", "x86-64" };
const arm_tokens = [_][]const u8{ "aarch64", "arm64", "armv8" };

/// Names that are never a runnable binary for abv0: checksums, signatures,
/// SBOMs, distro packages and installers, and debug output.
const reject_suffixes = [_][]const u8{
    ".sha256", ".sha512", ".sha1", ".md5",  ".sig", ".asc",
    ".pem",    ".sbom",   ".txt",  ".json", ".deb", ".rpm",
    ".apk",    ".msi",    ".pkg",  ".pdb",  ".sum", ".sha256sum",
};

/// Words that mark a file as source, debug output or a checksum set. Matched
/// as whole tokens, so `source` does not reject `resourceful`.
const reject_tokens = [_][]const u8{
    "checksum",  "checksums", "sha256sums", "sha512sums", "sbom",
    "signature", "src",       "source",     "debug",      "dbgsym",
    "symbols",
};

/// Operating systems abv0 does not target. `ios` also guards against `apple`
/// (an iOS triple) being read as macOS.
const reject_os_tokens = [_][]const u8{
    "freebsd", "netbsd", "openbsd", "dragonfly", "android", "illumos", "solaris",
    "ios",     "tvos",   "wasm",    "wasi",
};

/// Architectures other than x86_64 and aarch64, matched at the start of a
/// word (so `ppc64le` and `riscv64gc` are caught by their stem).
const reject_arch_prefixes = [_][]const u8{
    "i386",  "i686",  "386",   "armv5", "armv6",   "armv7", "armhf",
    "armel", "arm-",  "s390x", "ppc",   "powerpc", "mips",  "riscv",
    "loong", "sparc",
};

const archive_suffixes = [_]struct { ext: []const u8, kind: []const u8 }{
    .{ .ext = ".tar.gz", .kind = "tar.gz" },
    .{ .ext = ".tgz", .kind = "tar.gz" },
    .{ .ext = ".tar.xz", .kind = "tar.xz" },
    .{ .ext = ".txz", .kind = "tar.xz" },
    .{ .ext = ".tar.zst", .kind = "tar.zst" },
    .{ .ext = ".tar", .kind = "tar" },
    .{ .ext = ".zip", .kind = "zip" },
    .{ .ext = ".dmg", .kind = "dmg" },
    .{ .ext = ".exe", .kind = "raw" },
    .{ .ext = ".AppImage", .kind = "raw" },
};

/// The abv0 `archive_type` string (as used in packages/index.json) for an
/// asset name, or null when abv0 cannot unpack it.
///
/// A name with no extension, or whose last dot-piece contains a non-alphanumeric
/// character or is all digits (as in `tool-1.7.1-linux-amd64`), is a raw binary.
/// A word extension abv0 does not know (`.7z`, `.deb`) is null.
pub fn archiveKindOf(name: []const u8) ?[]const u8 {
    for (archive_suffixes) |s| {
        if (std.ascii.endsWithIgnoreCase(name, s.ext)) return s.kind;
    }

    const dot = std.mem.lastIndexOfScalar(u8, name, '.') orelse return "raw";
    const ext = name[dot + 1 ..];
    if (ext.len == 0) return null;

    for (ext) |c| {
        if (!std.ascii.isAlphanumeric(c)) return "raw";
    }
    for (ext) |c| {
        if (!std.ascii.isDigit(c)) return null;
    }
    return "raw";
}

/// Architecture band for a name, or null when the name's architecture does not
/// match `want_arch` (or names several, or none). Exact match scores 100, a
/// `64bit`-only hint 50, and a macOS universal binary 10.
fn archScore(name: []const u8, os: Os, want_arch: Arch) ?u32 {
    if (has(name, "universal", .token) or has(name, "universal2", .token)) {
        return if (os == .macos) 10 else null;
    }
    const x86 = hasAny(name, &x86_tokens);
    const arm = hasAny(name, &arm_tokens);
    if (x86 and arm) return null;
    if (x86) return if (want_arch == .x86_64) 100 else null;
    if (arm) return if (want_arch == .aarch64) 100 else null;
    if (has(name, "64bit", .token)) return if (want_arch == .x86_64) 50 else null;
    return null;
}

/// Score for one asset against the wanted target, or null when it cannot be
/// used. Higher is better. The bands are chosen so an exact architecture match
/// always beats a weaker match, and libc and archive preferences only order
/// candidates that already match.
fn scoreAsset(name: []const u8, want: Target) ?u32 {
    if (name.len == 0) return null;
    for (reject_suffixes) |s| {
        if (std.ascii.endsWithIgnoreCase(name, s)) return null;
    }
    for (reject_tokens) |t| {
        if (has(name, t, .token)) return null;
    }
    for (reject_os_tokens) |t| {
        if (has(name, t, .token)) return null;
    }
    for (reject_arch_prefixes) |t| {
        if (has(name, t, .prefix)) return null;
    }
    if (has(name, "eabi", .substring)) return null;

    // OS. A `.exe` name is a Windows hint. A name that matches two systems is
    // ambiguous, so it is refused.
    const is_exe = std.ascii.endsWithIgnoreCase(name, ".exe");
    const is_linux = has(name, "linux", .token);
    const is_macos = hasAny(name, &macos_tokens);
    const is_windows = hasAny(name, &windows_tokens) or is_exe;
    const os_count = @as(u8, @intFromBool(is_linux)) + @intFromBool(is_macos) + @intFromBool(is_windows);
    if (os_count != 1) return null;
    const os: Os = if (is_linux) .linux else if (is_macos) .macos else .windows;
    if (os != want.os) return null;

    // Architecture. `universal` is a macOS fat binary that runs on both Macs.
    // It scores below an exact match. `64bit` alone is a weak x86_64 hint.
    const arch_score = archScore(name, os, want.arch) orelse return null;

    // libc, on Linux only. A static musl build runs on any distribution, so it
    // is preferred over glibc. A name with no libc marker is treated as neutral.
    const libc_score: u32 = if (os != .linux)
        0
    else if (has(name, "musl", .token))
        8
    else if (has(name, "gnu", .token))
        0
    else
        4;

    // Archive kind. Archives beat raw binaries, and a Windows `.zip` beats
    // anything else on Windows.
    const kind = archiveKindOf(name) orelse return null;
    const kind_score: u32 = if (std.mem.eql(u8, kind, "tar.gz"))
        4
    else if (std.mem.eql(u8, kind, "zip"))
        if (os == .windows) 5 else 4
    else if (std.mem.eql(u8, kind, "tar.xz") or std.mem.eql(u8, kind, "tar.zst"))
        3
    else if (std.mem.eql(u8, kind, "tar"))
        2
    else if (std.mem.eql(u8, kind, "dmg"))
        if (os == .macos) 2 else return null
    else if (std.mem.eql(u8, kind, "raw")) blk: {
        // AppImage is a self-contained Linux binary. It is usable but ranks last.
        if (std.ascii.endsWithIgnoreCase(name, ".AppImage")) {
            if (os != .linux) return null;
            break :blk 0;
        }
        break :blk 1;
    } else return null;

    return arch_score + libc_score + kind_score;
}

/// Index of the asset that best matches `platform_tag` (one of the six tags in
/// platform.zig, such as `x86_64-linux` or `aarch64-macos`), or null when none
/// fits or the tag is unknown. Ties go to the shorter file name, then to the
/// earlier entry.
pub fn pickAsset(assets: []const Asset, platform_tag: []const u8) ?usize {
    const want = parsePlatformTag(platform_tag) orelse return null;

    var best: ?usize = null;
    var best_score: u32 = 0;
    for (assets, 0..) |asset, i| {
        const score = scoreAsset(asset.name, want) orelse continue;
        const better = if (best) |b|
            (score > best_score or (score == best_score and asset.name.len < assets[b].name.len))
        else
            true;
        if (better) {
            best = i;
            best_score = score;
        }
    }
    return best;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn makeAssets(arena: std.mem.Allocator, names: []const []const u8) ![]Asset {
    const out = try arena.alloc(Asset, names.len);
    for (names, out) |n, *a| {
        a.* = .{ .name = n, .url = "https://example.com/download", .size = 0, .sha256 = null };
    }
    return out;
}

fn expectPick(assets: []const Asset, platform_tag: []const u8, want: ?[]const u8) !void {
    const got = pickAsset(assets, platform_tag);
    if (want) |name| {
        const idx = got orelse {
            std.debug.print("{s}: expected {s}, got null\n", .{ platform_tag, name });
            return error.TestExpectedEqual;
        };
        testing.expectEqualStrings(name, assets[idx].name) catch |e| {
            std.debug.print("{s}: expected {s}\n", .{ platform_tag, name });
            return e;
        };
    } else {
        if (got) |idx| {
            std.debug.print("{s}: expected null, got {s}\n", .{ platform_tag, assets[idx].name });
            return error.TestUnexpectedResult;
        }
    }
}

const ripgrep_names = [_][]const u8{
    "ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz",
    "ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz.sha256",
    "ripgrep-14.1.1-aarch64-unknown-linux-gnu.tar.gz",
    "ripgrep-14.1.1-aarch64-unknown-linux-gnu.tar.gz.sha256",
    "ripgrep-14.1.1-i686-unknown-linux-musl.tar.gz",
    "ripgrep-14.1.1-x86_64-apple-darwin.tar.gz",
    "ripgrep-14.1.1-x86_64-apple-darwin.tar.gz.sha256",
    "ripgrep-14.1.1-aarch64-apple-darwin.tar.gz",
    "ripgrep-14.1.1-aarch64-apple-darwin.tar.gz.sha256",
    "ripgrep-14.1.1-x86_64-pc-windows-msvc.zip",
    "ripgrep-14.1.1-x86_64-pc-windows-msvc.zip.sha256",
    "ripgrep-14.1.1-i686-pc-windows-msvc.zip",
    "ripgrep_14.1.1-1_amd64.deb",
    "ripgrep-14.1.1-1.x86_64.rpm",
};

const gh_names = [_][]const u8{
    "gh_2.65.0_linux_386.tar.gz",
    "gh_2.65.0_linux_amd64.tar.gz",
    "gh_2.65.0_linux_arm64.tar.gz",
    "gh_2.65.0_linux_armv6.tar.gz",
    "gh_2.65.0_macOS_amd64.zip",
    "gh_2.65.0_macOS_arm64.zip",
    "gh_2.65.0_windows_amd64.zip",
    "gh_2.65.0_windows_arm64.zip",
    "gh_2.65.0_linux_amd64.deb",
    "gh_2.65.0_linux_amd64.rpm",
    "gh_2.65.0_checksums.txt",
};

const fzf_names = [_][]const u8{
    "fzf-0.55.0-linux_amd64.tar.gz",
    "fzf-0.55.0-linux_arm64.tar.gz",
    "fzf-0.55.0-linux_armv5.tar.gz",
    "fzf-0.55.0-darwin_amd64.tar.gz",
    "fzf-0.55.0-darwin_arm64.tar.gz",
    "fzf-0.55.0-windows_amd64.zip",
    "fzf-0.55.0-windows_arm64.zip",
    "fzf-0.55.0_checksums.txt",
};

const jq_names = [_][]const u8{
    "jq-linux-amd64",
    "jq-linux-arm64",
    "jq-linux-i386",
    "jq-linux-armel",
    "jq-linux-ppc64el",
    "jq-macos-amd64",
    "jq-macos-arm64",
    "jq-windows-amd64.exe",
    "jq-windows-i386.exe",
};

const zoxide_names = [_][]const u8{
    "zoxide-0.9.6-x86_64-unknown-linux-musl.tar.gz",
    "zoxide-0.9.6-x86_64-unknown-linux-musl.tar.gz.sha256",
    "zoxide-0.9.6-aarch64-unknown-linux-musl.tar.gz",
    "zoxide-0.9.6-armv7-unknown-linux-musleabihf.tar.gz",
    "zoxide-0.9.6-i686-unknown-linux-musl.tar.gz",
    "zoxide-0.9.6-x86_64-apple-darwin.tar.gz",
    "zoxide-0.9.6-aarch64-apple-darwin.tar.gz",
    "zoxide-0.9.6-x86_64-pc-windows-msvc.zip",
};

const lazygit_names = [_][]const u8{
    "lazygit_0.44.1_Linux_x86_64.tar.gz",
    "lazygit_0.44.1_Linux_arm64.tar.gz",
    "lazygit_0.44.1_Linux_armv6.tar.gz",
    "lazygit_0.44.1_Darwin_x86_64.tar.gz",
    "lazygit_0.44.1_Darwin_arm64.tar.gz",
    "lazygit_0.44.1_Windows_x86_64.zip",
    "lazygit_0.44.1_Windows_arm64.zip",
    "lazygit_0.44.1_checksums.txt",
};

test "pickAsset: ripgrep" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const assets = try makeAssets(arena.allocator(), &ripgrep_names);

    try expectPick(assets, "x86_64-linux", "ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz");
    try expectPick(assets, "aarch64-linux", "ripgrep-14.1.1-aarch64-unknown-linux-gnu.tar.gz");
    try expectPick(assets, "x86_64-macos", "ripgrep-14.1.1-x86_64-apple-darwin.tar.gz");
    try expectPick(assets, "aarch64-macos", "ripgrep-14.1.1-aarch64-apple-darwin.tar.gz");
    try expectPick(assets, "x86_64-windows", "ripgrep-14.1.1-x86_64-pc-windows-msvc.zip");
    try expectPick(assets, "aarch64-windows", null);
}

test "pickAsset: gh CLI" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const assets = try makeAssets(arena.allocator(), &gh_names);

    try expectPick(assets, "x86_64-linux", "gh_2.65.0_linux_amd64.tar.gz");
    try expectPick(assets, "aarch64-linux", "gh_2.65.0_linux_arm64.tar.gz");
    try expectPick(assets, "x86_64-macos", "gh_2.65.0_macOS_amd64.zip");
    try expectPick(assets, "aarch64-macos", "gh_2.65.0_macOS_arm64.zip");
    try expectPick(assets, "x86_64-windows", "gh_2.65.0_windows_amd64.zip");
    try expectPick(assets, "aarch64-windows", "gh_2.65.0_windows_arm64.zip");
}

test "pickAsset: fzf" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const assets = try makeAssets(arena.allocator(), &fzf_names);

    try expectPick(assets, "x86_64-linux", "fzf-0.55.0-linux_amd64.tar.gz");
    try expectPick(assets, "aarch64-linux", "fzf-0.55.0-linux_arm64.tar.gz");
    try expectPick(assets, "x86_64-macos", "fzf-0.55.0-darwin_amd64.tar.gz");
    try expectPick(assets, "aarch64-macos", "fzf-0.55.0-darwin_arm64.tar.gz");
    try expectPick(assets, "x86_64-windows", "fzf-0.55.0-windows_amd64.zip");
    try expectPick(assets, "aarch64-windows", "fzf-0.55.0-windows_arm64.zip");
}

test "pickAsset: jq raw binaries and .exe" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const assets = try makeAssets(arena.allocator(), &jq_names);

    try expectPick(assets, "x86_64-linux", "jq-linux-amd64");
    try expectPick(assets, "aarch64-linux", "jq-linux-arm64");
    try expectPick(assets, "x86_64-macos", "jq-macos-amd64");
    try expectPick(assets, "aarch64-macos", "jq-macos-arm64");
    try expectPick(assets, "x86_64-windows", "jq-windows-amd64.exe");
    try expectPick(assets, "aarch64-windows", null);
}

test "pickAsset: zoxide" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const assets = try makeAssets(arena.allocator(), &zoxide_names);

    try expectPick(assets, "x86_64-linux", "zoxide-0.9.6-x86_64-unknown-linux-musl.tar.gz");
    try expectPick(assets, "aarch64-linux", "zoxide-0.9.6-aarch64-unknown-linux-musl.tar.gz");
    try expectPick(assets, "x86_64-macos", "zoxide-0.9.6-x86_64-apple-darwin.tar.gz");
    try expectPick(assets, "aarch64-macos", "zoxide-0.9.6-aarch64-apple-darwin.tar.gz");
    try expectPick(assets, "x86_64-windows", "zoxide-0.9.6-x86_64-pc-windows-msvc.zip");
    try expectPick(assets, "aarch64-windows", null);
}

test "pickAsset: lazygit" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const assets = try makeAssets(arena.allocator(), &lazygit_names);

    try expectPick(assets, "x86_64-linux", "lazygit_0.44.1_Linux_x86_64.tar.gz");
    try expectPick(assets, "aarch64-linux", "lazygit_0.44.1_Linux_arm64.tar.gz");
    try expectPick(assets, "x86_64-macos", "lazygit_0.44.1_Darwin_x86_64.tar.gz");
    try expectPick(assets, "aarch64-macos", "lazygit_0.44.1_Darwin_arm64.tar.gz");
    try expectPick(assets, "x86_64-windows", "lazygit_0.44.1_Windows_x86_64.zip");
    try expectPick(assets, "aarch64-windows", "lazygit_0.44.1_Windows_arm64.zip");
}

test "pickAsset: musl beats gnu, universal ranks below exact, unknown tag is null" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const names = [_][]const u8{
        "tool-1.0-x86_64-unknown-linux-gnu.tar.gz",
        "tool-1.0-x86_64-unknown-linux-musl.tar.gz",
        "tool-1.0-macos-universal.tar.gz",
        "tool-1.0-darwin-x86_64.tar.gz",
        "tool-1.0-linux-x86_64.tar.xz",
    };
    const assets = try makeAssets(arena.allocator(), &names);

    try expectPick(assets, "x86_64-linux", "tool-1.0-x86_64-unknown-linux-musl.tar.gz");
    try expectPick(assets, "x86_64-macos", "tool-1.0-darwin-x86_64.tar.gz");
    try expectPick(assets, "aarch64-macos", "tool-1.0-macos-universal.tar.gz");
    try expectPick(assets, "x86-linux", null);
}

test "pickAsset: refuses ambiguous and non-binary names" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const names = [_][]const u8{
        "tool-linux-x86_64-source.tar.gz",
        "tool-linux-x86_64-debug.tar.gz",
        "tool-linux-x86_64.pdb",
        "tool-linux-x86_64.sha256",
        "tool-linux-x86_64.7z",
        "tool-linux-x86_64-android.tar.gz",
        "tool-linux-windows-x86_64.tar.gz",
        "tool-linux-x86_64.AppImage",
        "tool-linux-x86_64-ios.tar.gz",
    };
    const assets = try makeAssets(arena.allocator(), &names);

    // Only the AppImage is a usable Linux file here, and it ranks last.
    try expectPick(assets, "x86_64-linux", "tool-linux-x86_64.AppImage");
    try expectPick(assets, "x86_64-macos", null);
}

test "pickAsset: name length breaks ties" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const names = [_][]const u8{
        "tool-linux-amd64-long-name",
        "tool-linux-amd64",
    };
    const assets = try makeAssets(arena.allocator(), &names);
    try expectPick(assets, "x86_64-linux", "tool-linux-amd64");
}

test "archiveKindOf maps names to archive_type strings" {
    try testing.expectEqualStrings("tar.gz", archiveKindOf("x-linux.tar.gz").?);
    try testing.expectEqualStrings("tar.gz", archiveKindOf("x-linux.tgz").?);
    try testing.expectEqualStrings("tar.xz", archiveKindOf("x-linux.tar.xz").?);
    try testing.expectEqualStrings("tar.zst", archiveKindOf("x-linux.tar.zst").?);
    try testing.expectEqualStrings("zip", archiveKindOf("x-windows.ZIP").?);
    try testing.expectEqualStrings("dmg", archiveKindOf("x-macos.dmg").?);
    try testing.expectEqualStrings("raw", archiveKindOf("jq-linux-amd64").?);
    try testing.expectEqualStrings("raw", archiveKindOf("jq-windows-amd64.exe").?);
    try testing.expectEqualStrings("raw", archiveKindOf("tool-1.7.1-linux-amd64").?);
    try testing.expectEqualStrings("raw", archiveKindOf("tool-linux.AppImage").?);
    try testing.expect(archiveKindOf("x.7z") == null);
    try testing.expect(archiveKindOf("x.deb") == null);
    try testing.expect(archiveKindOf("x.sha256") == null);
}

test "parseSpec accepts owner/repo with optional tag" {
    const a = parseSpec("ripgrep/ripgrep").?;
    try testing.expectEqualStrings("ripgrep", a.owner);
    try testing.expectEqualStrings("ripgrep", a.repo);
    try testing.expect(a.tag == null);

    const b = parseSpec("gh:cli/cli@v2.65.0").?;
    try testing.expectEqualStrings("cli", b.owner);
    try testing.expectEqualStrings("cli", b.repo);
    try testing.expectEqualStrings("v2.65.0", b.tag.?);

    const c = parseSpec("o.w-n_er/r.e-p_o@release/2.0+build.1").?;
    try testing.expectEqualStrings("release/2.0+build.1", c.tag.?);

    const long = "a" ** 100;
    try testing.expect(parseSpec(long ++ "/" ++ long) != null);
}

test "parseSpec rejects malformed specs" {
    const bad = [_][]const u8{
        "",
        "owner",
        "a/b/c",
        "/repo",
        "owner/",
        "-a/b",
        "./x",
        "../x",
        "a/..",
        "a/.",
        "o/r@",
        "o/r@a..b",
        "o/r@a b",
        "o/r@a@b",
        "o/r@.",
        "o:x/r",
        "a" ** 101 ++ "/r",
        "gh:",
    };
    for (bad) |s| {
        if (parseSpec(s)) |_| {
            std.debug.print("parseSpec accepted {s}\n", .{s});
            return error.TestUnexpectedResult;
        }
    }
}

test "apiUrl builds latest and tag URLs with the tag percent-encoded" {
    const a = testing.allocator;

    const latest = try apiUrl(a, "cli", "cli", null);
    defer a.free(latest);
    try testing.expectEqualStrings("https://api.github.com/repos/cli/cli/releases/latest", latest);

    const tagged = try apiUrl(a, "o", "r", "v1.0+rc/1");
    defer a.free(tagged);
    try testing.expectEqualStrings("https://api.github.com/repos/o/r/releases/tags/v1.0%2Brc%2F1", tagged);

    try testing.expectError(error.InvalidName, apiUrl(a, "o/x", "r", null));
    try testing.expectError(error.InvalidTag, apiUrl(a, "o", "r", "a..b"));
}

const sample_with_digest =
    \\{"url":"https://api.github.com/x","tag_name":"v1.2.3","name":"v1.2.3","draft":false,
    \\"assets":[
    \\{"name":"tool-linux-amd64.tar.gz","size":1234,
    \\ "browser_download_url":"https://github.com/o/r/releases/download/v1.2.3/tool-linux-amd64.tar.gz",
    \\ "digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
    \\{"name":"tool-linux-amd64.tar.gz.sha256","size":90,
    \\ "browser_download_url":"https://github.com/o/r/releases/download/v1.2.3/tool-linux-amd64.tar.gz.sha256"}
    \\]}
;

test "parseRelease reads tag, url, size and digest" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const rel = try parseRelease(arena.allocator(), sample_with_digest);

    try testing.expectEqualStrings("v1.2.3", rel.tag);
    try testing.expectEqual(@as(usize, 2), rel.assets.len);
    try testing.expectEqualStrings("tool-linux-amd64.tar.gz", rel.assets[0].name);
    try testing.expectEqualStrings(
        "https://github.com/o/r/releases/download/v1.2.3/tool-linux-amd64.tar.gz",
        rel.assets[0].url,
    );
    try testing.expectEqual(@as(u64, 1234), rel.assets[0].size);
    try testing.expectEqualStrings(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        &rel.assets[0].sha256.?,
    );
}

test "parseRelease leaves sha256 null when digest is absent" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const rel = try parseRelease(arena.allocator(), sample_with_digest);
    try testing.expect(rel.assets[1].sha256 == null);
}

test "parseRelease ignores digests that are not sha256 lowercase hex" {
    const json =
        \\{"tag_name":"v1","assets":[
        \\{"name":"a-linux","size":1,"browser_download_url":"https://h/a-linux","digest":"sha512:00"},
        \\{"name":"b-linux","size":1,"browser_download_url":"https://h/b-linux",
        \\ "digest":"sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"},
        \\{"name":"c-linux","size":1,"browser_download_url":"https://h/c-linux","digest":42}
        \\]}
    ;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const rel = try parseRelease(arena.allocator(), json);
    try testing.expectEqual(@as(usize, 3), rel.assets.len);
    for (rel.assets) |a| try testing.expect(a.sha256 == null);
}

test "parseRelease reports a rate-limit body as an API error" {
    const body =
        \\{"message":"API rate limit exceeded for 203.0.113.7.","documentation_url":"https://docs.github.com/rest"}
    ;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.GitHubApiMessage, parseRelease(arena.allocator(), body));
}

test "parseRelease rejects truncated JSON" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const truncated = sample_with_digest[0 .. sample_with_digest.len / 2];
    if (parseRelease(arena.allocator(), truncated)) |_| {
        return error.TestUnexpectedResult;
    } else |_| {}
}

test "parseRelease rejects wrong field types" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectError(error.MalformedRelease, parseRelease(a,
        \\{"tag_name":7,"assets":[]}
    ));
    try testing.expectError(error.MalformedRelease, parseRelease(a,
        \\{"tag_name":"v1","assets":{}}
    ));
    try testing.expectError(error.MalformedRelease, parseRelease(a,
        \\{"tag_name":"v1","assets":[{"name":"x","size":"12","browser_download_url":"https://h/x"}]}
    ));
    try testing.expectError(error.MalformedRelease, parseRelease(a,
        \\{"tag_name":"v1","assets":[{"name":"x","size":-1,"browser_download_url":"https://h/x"}]}
    ));
    try testing.expectError(error.MalformedRelease, parseRelease(a, "[]"));
}

test "parseRelease drops assets with unsafe URLs or names" {
    const json =
        \\{"tag_name":"v1","assets":[
        \\{"name":"http-plain","size":1,"browser_download_url":"http://h/x"},
        \\{"name":"file-url","size":1,"browser_download_url":"file:///etc/passwd"},
        \\{"name":"userinfo","size":1,"browser_download_url":"https://user@evil.example/x"},
        \\{"name":"sub/dir","size":1,"browser_download_url":"https://h/y"},
        \\{"name":"..","size":1,"browser_download_url":"https://h/z"},
        \\{"name":"good-linux","size":1,"browser_download_url":"https://h/good"}
        \\]}
    ;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const rel = try parseRelease(arena.allocator(), json);
    try testing.expectEqual(@as(usize, 1), rel.assets.len);
    try testing.expectEqualStrings("good-linux", rel.assets[0].name);
}
