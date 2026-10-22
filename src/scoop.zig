//! Scoop manifests as a package source for Windows.
//!
//! Scoop's buckets (Main, Extras, Versions) are the largest curated catalogue
//! of Windows command-line software, and every manifest carries a pinned hash.
//! This module turns one manifest into a `Resolved` description that the
//! installer can treat like any other abv0 platform entry.
//!
//! What it deliberately does NOT do: run PowerShell. Scoop manifests may carry
//! `installer`, `pre_install`, `post_install` and `uninstaller` scripts. They
//! are never executed here. A manifest that cannot work without its installer
//! or pre_install script is reported as unsupported; scripts that are usually
//! cosmetic (`post_install`, `uninstaller`) are skipped and listed in `notes`.
//!
//! Manifests are fetched over the network, so everything in them is hostile
//! until proven otherwise: field types are checked, every path that will reach
//! the filesystem passes `safepath`, and nothing here can panic on bad JSON.

const std = @import("std");
const safepath = @import("safepath.zig");
const net = @import("net.zig");
const shim = @import("shim.zig");
const registry = @import("registry.zig");
const archive = @import("archive.zig");

const Value = std.json.Value;
const ObjectMap = std.json.ObjectMap;

/// Largest manifest accepted. Real ones are a few KiB.
pub const max_manifest_bytes = 1024 * 1024;
const max_bins = 256;

pub const Error = error{
    InvalidManifest,
    ManifestTooLarge,
    InvalidName,
    InvalidBucket,
    InvalidVersion,
    OutOfMemory,
};

pub const Bin = struct {
    /// Path of the executable relative to the extracted root (after
    /// `extract_dir` is applied). Validated; separators are normalised to `/`.
    path: []const u8,
    /// Name to expose on PATH, without `.exe`.
    alias: []const u8,
    /// Arguments the shim passes before the user's own.
    args: []const []const u8 = &.{},
};

pub const Resolved = struct {
    name: []const u8 = "",
    version: []const u8 = "",
    description: []const u8 = "",
    homepage: []const u8 = "",
    license: []const u8 = "",
    /// Download URL with any `#/name` fragment removed.
    url: []const u8 = "",
    /// Name the download should be stored under: the fragment's name if there
    /// was one (Scoop's rename trick), otherwise the URL's last path component.
    /// For `raw` downloads this is the file the `bins` paths refer to.
    filename: []const u8 = "",
    sha256: ?[32]u8 = null,
    sha512: ?[64]u8 = null,
    /// abv0 archive kind string (`zip`, `tar.gz`, `raw`, ...), or a label such
    /// as `7z` / `msi` for formats abv0 cannot extract. Empty when unknown.
    archive_type: []const u8 = "",
    extract_dir: ?[]const u8 = null,
    bins: []const Bin = &.{},
    /// Non-null means abv0 must not install this manifest; the text says why.
    unsupported: ?[]const u8 = null,
    /// True when an arm64 host was given the x64 build (Windows on ARM
    /// emulates x64).
    emulated: bool = false,
    /// Things that were skipped or ignored, such as `skipped script: post_install`.
    notes: []const []const u8 = &.{},

    pub fn isSupported(self: Resolved) bool {
        return self.unsupported == null;
    }

    /// True when a checksum is present for the download.
    pub fn isVerified(self: Resolved) bool {
        return self.sha256 != null or self.sha512 != null;
    }
};

pub const Options = struct {
    /// Package name to record in `Resolved.name`; validated when non-empty.
    name: []const u8 = "",
    /// Accept manifests whose hash is missing or weak (md5/sha1). Off by
    /// default: abv0 verifies what it installs.
    allow_unverified: bool = false,
};

// ---------------------------------------------------------------------------
// Manifest URLs
// ---------------------------------------------------------------------------

const Bucket = struct { key: []const u8, repo: []const u8 };
const buckets = [_]Bucket{
    .{ .key = "main", .repo = "ScoopInstaller/Main" },
    .{ .key = "extras", .repo = "ScoopInstaller/Extras" },
    .{ .key = "versions", .repo = "ScoopInstaller/Versions" },
};

/// URL of `<name>.json` in a known bucket (`main`, `extras`, `versions`; case
/// is ignored). Caller frees.
pub fn manifestUrl(a: std.mem.Allocator, bucket: []const u8, name: []const u8) ![]u8 {
    if (!safepath.isValidId(name)) return error.InvalidName;
    for (buckets) |b| {
        if (std.ascii.eqlIgnoreCase(bucket, b.key)) {
            return std.fmt.allocPrint(
                a,
                "https://raw.githubusercontent.com/{s}/master/bucket/{s}.json",
                .{ b.repo, name },
            );
        }
    }
    return error.InvalidBucket;
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// Resolve a manifest for `arch` with default options.
pub fn resolve(arena: std.mem.Allocator, json: []const u8, arch: std.Target.Cpu.Arch) Error!Resolved {
    return resolveOpts(arena, json, arch, .{});
}

/// Resolve a manifest. Returns an error only for input that is not a manifest
/// at all (bad JSON, no usable version); a manifest that is valid but cannot be
/// installed comes back with `unsupported` set. All memory is owned by `arena`.
pub fn resolveOpts(
    arena: std.mem.Allocator,
    json: []const u8,
    arch: std.Target.Cpu.Arch,
    opts: Options,
) Error!Resolved {
    if (json.len > max_manifest_bytes) return error.ManifestTooLarge;
    if (opts.name.len != 0 and !safepath.isValidId(opts.name)) return error.InvalidName;

    var text = json;
    if (std.mem.startsWith(u8, text, "\xEF\xBB\xBF")) text = text[3..];

    const root = std.json.parseFromSliceLeaky(Value, arena, text, .{ .allocate = .alloc_always }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidManifest,
    };
    const top = switch (root) {
        .object => |o| o,
        else => return error.InvalidManifest,
    };

    const version = switch (top.get("version") orelse return error.InvalidManifest) {
        .string => |s| s,
        else => return error.InvalidManifest,
    };
    if (!safepath.isValidId(version)) return error.InvalidVersion;

    var b = Builder{
        .arena = arena,
        .top = top,
        .opts = opts,
        .r = .{ .name = opts.name, .version = version },
    };
    try b.run(arch);
    b.r.notes = try b.notes.toOwnedSlice();
    return b.r;
}

const Builder = struct {
    arena: std.mem.Allocator,
    top: ObjectMap,
    /// The architecture-specific block selected for this host, if any.
    sel: ?ObjectMap = null,
    opts: Options,
    r: Resolved,
    notes: std.ArrayList([]const u8) = undefined,

    fn fail(self: *Builder, reason: []const u8) void {
        if (self.r.unsupported == null) self.r.unsupported = reason;
    }

    fn note(self: *Builder, text: []const u8) !void {
        try self.notes.append(text);
    }

    /// Scoop's `arch_specific`: the architecture block's value if it has the
    /// key, otherwise the top-level value. JSON null counts as absent.
    fn lookup(self: *const Builder, key: []const u8) ?Value {
        if (self.sel) |s| {
            if (s.get(key)) |v| if (v != .null) return v;
        }
        if (self.top.get(key)) |v| if (v != .null) return v;
        return null;
    }

    fn lookupStr(self: *const Builder, key: []const u8) ?[]const u8 {
        const v = self.lookup(key) orelse return null;
        return switch (v) {
            .string => |s| s,
            else => null,
        };
    }

    fn run(self: *Builder, arch: std.Target.Cpu.Arch) Error!void {
        self.notes = std.ArrayList([]const u8).init(self.arena);

        if (self.top.get("description")) |v| {
            if (v == .string) self.r.description = v.string;
        }
        if (self.top.get("homepage")) |v| {
            if (v == .string) self.r.homepage = v.string;
        }
        if (self.top.get("license")) |v| switch (v) {
            .string => |s| self.r.license = s,
            .object => |o| {
                if (o.get("identifier")) |id| if (id == .string) {
                    self.r.license = id.string;
                };
            },
            else => {},
        };

        self.selectArch(arch);
        try self.checkScripts();
        try self.resolveDownload();
        try self.resolveExtractDir();
        try self.resolveBins();

        // A raw download is a single file; bins must name exactly that file.
        if (std.mem.eql(u8, self.r.archive_type, "raw") and self.r.unsupported == null) {
            if (self.r.extract_dir != null) self.fail("extract_dir on a plain executable");
            for (self.r.bins) |bin| {
                if (!std.ascii.eqlIgnoreCase(bin.path, self.r.filename))
                    self.fail("bin does not match the downloaded file");
            }
        }
    }

    fn selectArch(self: *Builder, arch: std.Target.Cpu.Arch) void {
        const block = switch (self.top.get("architecture") orelse .null) {
            .object => |o| o,
            else => null,
        };
        switch (arch) {
            .x86_64 => {
                if (block) |o| {
                    if (archBlock(o, "64bit")) |s| self.sel = s;
                }
            },
            .aarch64 => {
                if (block) |o| {
                    if (archBlock(o, "arm64")) |s| {
                        self.sel = s;
                    } else if (archBlock(o, "64bit")) |s| {
                        // Windows on ARM runs x64 binaries under emulation.
                        self.sel = s;
                        self.r.emulated = true;
                    }
                }
            },
            else => self.fail("unsupported CPU architecture"),
        }
    }

    fn archBlock(o: ObjectMap, key: []const u8) ?ObjectMap {
        const v = o.get(key) orelse return null;
        return switch (v) {
            .object => |s| s,
            else => null,
        };
    }

    /// Scripts are never run. Decide which absences are fatal.
    fn checkScripts(self: *Builder) !void {
        if (self.lookup("installer")) |v| {
            if (isPresent(v)) self.fail("needs install scripts");
        }
        if (self.lookup("pre_install")) |v| {
            if (isPresent(v)) self.fail("needs install scripts");
        }
        if (self.lookup("psmodule")) |v| {
            if (isPresent(v)) self.fail("needs a PowerShell module install");
        }
        if (self.lookup("innosetup")) |v| {
            if (v == .bool and v.bool) self.fail("needs Inno Setup extraction");
        }
        if (self.lookup("extract_to")) |v| {
            if (isPresent(v)) self.fail("extract_to is not supported");
        }

        if (self.lookup("post_install")) |v| {
            if (isPresent(v)) try self.note("skipped script: post_install");
        }
        if (self.lookup("uninstaller")) |v| {
            if (isPresent(v)) try self.note("skipped script: uninstaller");
        }
        if (self.lookup("persist")) |v| {
            if (isPresent(v)) try self.note("ignored: persist");
        }
        if (self.lookup("env_add_path")) |v| {
            if (isPresent(v)) try self.note("ignored: env_add_path");
        }
        if (self.lookup("env_set")) |v| {
            if (isPresent(v)) try self.note("ignored: env_set");
        }
        if (self.lookup("depends")) |v| {
            if (isPresent(v)) try self.note("ignored: depends");
        }
    }

    fn resolveDownload(self: *Builder) !void {
        const url_v = self.lookup("url") orelse {
            self.fail("no download for this architecture");
            return;
        };
        const raw_url = single(url_v) orelse {
            self.fail(if (urlCount(url_v) > 1) "multiple downloads" else "malformed url");
            return;
        };

        // Split off the fragment; `#/name.ext` is Scoop's rename trick.
        var base_url = raw_url;
        var frag: []const u8 = "";
        if (std.mem.indexOfScalar(u8, raw_url, '#')) |i| {
            base_url = raw_url[0..i];
            frag = raw_url[i + 1 ..];
        }
        if (!net.isSafeUrl(base_url)) {
            self.fail("unsafe download url");
            return;
        }
        self.r.url = base_url;

        var fname: []const u8 = "";
        if (frag.len > 1 and frag[0] == '/') {
            fname = frag[1..];
        } else {
            fname = urlBasename(base_url);
        }
        if (isSafeFilename(fname)) {
            self.r.filename = fname;
        } else {
            self.fail("unsafe download file name");
        }

        self.classify(self.r.filename);
        try self.resolveHash();
    }

    /// A string, or an array holding exactly one string.
    fn single(v: Value) ?[]const u8 {
        switch (v) {
            .string => |str| return str,
            .array => |arr| {
                if (arr.items.len == 1 and arr.items[0] == .string) return arr.items[0].string;
                return null;
            },
            else => return null,
        }
    }

    fn urlCount(v: Value) usize {
        return switch (v) {
            .array => |arr| arr.items.len,
            else => 1,
        };
    }

    /// Decide the archive kind from the file name.
    fn classify(self: *Builder, name: []const u8) void {
        if (name.len == 0) {
            self.r.archive_type = "";
            return;
        }
        if (endsWithI(name, ".zip")) {
            self.r.archive_type = "zip";
        } else if (endsWithI(name, ".tar.gz") or endsWithI(name, ".tgz")) {
            self.r.archive_type = "tar.gz";
        } else if (endsWithI(name, ".tar.xz") or endsWithI(name, ".txz")) {
            self.r.archive_type = "tar.xz";
        } else if (endsWithI(name, ".tar.zst")) {
            self.r.archive_type = "tar.zst";
        } else if (endsWithI(name, ".tar")) {
            self.r.archive_type = "tar";
        } else if (endsWithI(name, ".7z")) {
            self.r.archive_type = "7z";
            self.fail("7z archives are not supported");
        } else if (endsWithI(name, ".msi")) {
            self.r.archive_type = "msi";
            self.fail("MSI installers are not supported");
        } else if (endsWithI(name, ".exe")) {
            // A bare .exe is Scoop's "portable executable" case.
            self.r.archive_type = "raw";
        } else {
            self.fail("unsupported download type");
        }
    }

    fn resolveHash(self: *Builder) !void {
        const hash_v = self.lookup("hash");
        const hash_text: ?[]const u8 = if (hash_v) |v| single(v) else null;

        const text = hash_text orelse {
            // Missing (or an object, which only autoupdate uses).
            if (!self.opts.allow_unverified) self.fail("weak or missing hash");
            return;
        };

        switch (parseHash(text)) {
            .sha256 => |h| self.r.sha256 = h,
            .sha512 => |h| self.r.sha512 = h,
            .weak => {
                if (!self.opts.allow_unverified) self.fail("weak or missing hash");
            },
            .invalid => self.fail("malformed hash"),
        }
    }

    fn resolveExtractDir(self: *Builder) !void {
        const v = self.lookup("extract_dir") orelse return;
        const s = single(v) orelse {
            self.fail("malformed extract_dir");
            return;
        };
        if (s.len == 0) return;
        const norm = try normalizeRel(self.arena, s) orelse {
            self.fail("unsafe extract_dir");
            return;
        };
        self.r.extract_dir = norm;
    }

    fn resolveBins(self: *Builder) !void {
        const v = self.lookup("bin") orelse return;
        var list = std.ArrayList(Bin).init(self.arena);

        switch (v) {
            .string => |s| try self.addBin(&list, s, null, &.{}),
            .array => |arr| {
                for (arr.items) |item| {
                    switch (item) {
                        .string => |s| try self.addBin(&list, s, null, &.{}),
                        .array => |sub| try self.addBinTuple(&list, sub.items),
                        else => self.fail("malformed bin"),
                    }
                }
            },
            else => self.fail("malformed bin"),
        }
        self.r.bins = try list.toOwnedSlice();
    }

    fn addBinTuple(self: *Builder, list: *std.ArrayList(Bin), items: []const Value) !void {
        if (items.len == 0 or items[0] != .string) {
            self.fail("malformed bin");
            return;
        }
        var alias: ?[]const u8 = null;
        if (items.len >= 2) {
            switch (items[1]) {
                .string => |s| {
                    if (s.len != 0) alias = s;
                },
                .null => {},
                else => {
                    self.fail("malformed bin");
                    return;
                },
            }
        }
        var args = std.ArrayList([]const u8).init(self.arena);
        if (items.len >= 3) {
            for (items[2..]) |item| {
                if (item != .string) {
                    self.fail("malformed bin");
                    return;
                }
                if (std.mem.indexOf(u8, item.string, "\\\"") != null) {
                    self.fail("unsupported bin arguments");
                    return;
                }
                const toks = shim.splitArgs(self.arena, item.string) catch {
                    self.fail("unsupported bin arguments");
                    return;
                };
                try args.appendSlice(toks);
            }
        }
        if (args.items.len > shim.max_args) {
            self.fail("unsupported bin arguments");
            return;
        }
        try self.addBin(list, items[0].string, alias, args.items);
    }

    fn addBin(
        self: *Builder,
        list: *std.ArrayList(Bin),
        path_in: []const u8,
        alias_in: ?[]const u8,
        args: []const []const u8,
    ) !void {
        if (list.items.len >= max_bins) {
            self.fail("too many bins");
            return;
        }
        const path = try normalizeRel(self.arena, path_in) orelse {
            self.fail("unsafe bin path");
            return;
        };
        const leaf = lastComponent(path);
        if (!(endsWithI(leaf, ".exe") or endsWithI(leaf, ".com"))) {
            self.fail("bin is not an executable (script shims are not supported)");
            return;
        }

        var alias = alias_in orelse leaf[0 .. leaf.len - 4];
        if (endsWithI(alias, ".exe") and alias.len > 4) alias = alias[0 .. alias.len - 4];
        if (!shim.isValidShimName(alias)) {
            self.fail("bin name is invalid or reserved");
            return;
        }
        for (list.items) |other| {
            if (std.ascii.eqlIgnoreCase(other.alias, alias)) {
                self.fail("duplicate bin name");
                return;
            }
        }
        try list.append(.{
            .path = path,
            .alias = try self.arena.dupe(u8, alias),
            .args = try self.arena.dupe([]const u8, args),
        });
    }
};

/// A script field counts as present when it is something other than an empty
/// string, array or object.
fn isPresent(v: Value) bool {
    return switch (v) {
        .null => false,
        .bool => |b| b,
        .string => |s| s.len != 0,
        .array => |a| a.items.len != 0,
        .object => |o| o.count() != 0,
        else => true,
    };
}

fn endsWithI(s: []const u8, suffix: []const u8) bool {
    return s.len >= suffix.len and std.ascii.eqlIgnoreCase(s[s.len - suffix.len ..], suffix);
}

fn lastComponent(p: []const u8) []const u8 {
    var start: usize = 0;
    for (p, 0..) |c, i| {
        if (c == '/' or c == '\\') start = i + 1;
    }
    return p[start..];
}

/// Last path component of a URL, ignoring any query string. Empty for a URL
/// with no path.
fn urlBasename(url: []const u8) []const u8 {
    var end = url.len;
    if (std.mem.indexOfScalar(u8, url, '?')) |i| end = i;
    const no_query = url[0..end];
    const scheme_end = std.mem.indexOf(u8, no_query, "://") orelse return "";
    const after = no_query[scheme_end + 3 ..];
    // Skip the authority so "https://host" yields "" rather than "host".
    const path_start = std.mem.indexOfScalar(u8, after, '/') orelse return "";
    return lastComponent(after[path_start..]);
}

/// A file name that is safe to create inside a directory we control.
fn isSafeFilename(name: []const u8) bool {
    if (name.len == 0 or name.len > 255) return false;
    if (std.mem.indexOfAny(u8, name, "/\\:*?\"<>|") != null) return false;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return false;
    return safepath.isSafeRelPath(name);
}

/// Normalise a manifest-supplied relative path: backslashes become `/`, a
/// trailing separator is dropped, and the result must pass `isSafeRelPath`.
/// Variables (`$dir`) and wildcards are refused. Null when unsafe or empty.
fn normalizeRel(arena: std.mem.Allocator, p: []const u8) !?[]const u8 {
    if (std.mem.indexOfAny(u8, p, "$*?%\"<>|") != null) return null;
    var end = p.len;
    while (end > 0 and (p[end - 1] == '/' or p[end - 1] == '\\')) end -= 1;
    if (end == 0) return null;
    const out = try arena.dupe(u8, p[0..end]);
    for (out) |*c| {
        if (c.* == '\\') c.* = '/';
    }
    if (!safepath.isSafeRelPath(out)) return null;
    return out;
}

const ParsedHash = union(enum) {
    sha256: [32]u8,
    sha512: [64]u8,
    /// Well-formed but too weak to trust (md5, sha1).
    weak,
    invalid,
};

/// Parse Scoop's hash notations: bare hex (algorithm inferred from length) or
/// `algo:hex`.
pub fn parseHash(text: []const u8) ParsedHash {
    var algo: []const u8 = "";
    var hex = text;
    if (std.mem.indexOfScalar(u8, text, ':')) |i| {
        algo = text[0..i];
        hex = text[i + 1 ..];
    }

    for (hex) |c| {
        if (!std.ascii.isHex(c)) return .invalid;
    }

    var kind: enum { sha256, sha512, weak, unknown } = .unknown;
    if (algo.len == 0) {
        kind = switch (hex.len) {
            64 => .sha256,
            128 => .sha512,
            32, 40 => .weak,
            else => .unknown,
        };
    } else if (std.ascii.eqlIgnoreCase(algo, "sha256")) {
        if (hex.len == 64) kind = .sha256;
    } else if (std.ascii.eqlIgnoreCase(algo, "sha512")) {
        if (hex.len == 128) kind = .sha512;
    } else if (std.ascii.eqlIgnoreCase(algo, "sha1")) {
        if (hex.len == 40) kind = .weak;
    } else if (std.ascii.eqlIgnoreCase(algo, "md5")) {
        if (hex.len == 32) kind = .weak;
    }

    switch (kind) {
        .sha256 => {
            var out: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&out, hex) catch return .invalid;
            return .{ .sha256 = out };
        },
        .sha512 => {
            var out: [64]u8 = undefined;
            _ = std.fmt.hexToBytes(&out, hex) catch return .invalid;
            return .{ .sha512 = out };
        },
        .weak => return .weak,
        .unknown => return .invalid,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const h64 = "0a" ** 32;
const h64b = "0b" ** 32;
const h64u = "0A" ** 32;
const h64z = "00" ** 32;
const h64ab = "ab" ** 32;
const h62 = "ab" ** 31;
const h128 = "ab" ** 64;
const h128u = "AB" ** 64;
const h40 = "0a" ** 20;
const h40ab = "ab" ** 20;
const h32 = "0a" ** 16;
const h32ab = "ab" ** 16;
const hzz = "zz" ** 32;

/// Real manifests copied from the Scoop buckets. Read at run time because the
/// test module's package root is src/ and cannot embed files above it; `zig
/// build test` runs from the repository root.
fn fixture(a: std.mem.Allocator, comptime name: []const u8) ![]u8 {
    return std.fs.cwd().readFileAlloc(a, "tests/fixtures/scoop/" ++ name ++ ".json", 1 << 20);
}

fn hex256(h: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(h, .lower);
}

fn expectResolve(arena: std.mem.Allocator, comptime name: []const u8, arch: std.Target.Cpu.Arch) !Resolved {
    return resolveOpts(arena, try fixture(arena, name), arch, .{ .name = name });
}

test "manifestUrl builds bucket URLs and rejects hostile input" {
    const a = testing.allocator;
    const u = try manifestUrl(a, "main", "ripgrep");
    defer a.free(u);
    try testing.expectEqualStrings(
        "https://raw.githubusercontent.com/ScoopInstaller/Main/master/bucket/ripgrep.json",
        u,
    );
    const e = try manifestUrl(a, "Extras", "firefox");
    defer a.free(e);
    try testing.expect(std.mem.indexOf(u8, e, "ScoopInstaller/Extras/master/bucket/firefox.json") != null);
    const v = try manifestUrl(a, "versions", "python27");
    defer a.free(v);
    try testing.expect(std.mem.indexOf(u8, v, "ScoopInstaller/Versions") != null);

    try testing.expectError(error.InvalidName, manifestUrl(a, "main", "../x"));
    try testing.expectError(error.InvalidName, manifestUrl(a, "main", "a/b"));
    try testing.expectError(error.InvalidName, manifestUrl(a, "main", ""));
    try testing.expectError(error.InvalidName, manifestUrl(a, "main", "a?b=1"));
    try testing.expectError(error.InvalidBucket, manifestUrl(a, "evil/repo", "jq"));
    try testing.expectError(error.InvalidBucket, manifestUrl(a, "", "jq"));
}

test "ripgrep: zip with extract_dir, x86_64 and arm64" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const r = try expectResolve(arena.allocator(), "ripgrep", .x86_64);
    try testing.expect(r.isSupported());
    try testing.expectEqualStrings("ripgrep", r.name);
    try testing.expectEqualStrings("15.2.0", r.version);
    try testing.expectEqualStrings("MIT", r.license);
    try testing.expectEqualStrings("zip", r.archive_type);
    try testing.expect(std.mem.endsWith(u8, r.url, "x86_64-pc-windows-msvc.zip"));
    try testing.expectEqualStrings("ripgrep-15.2.0-x86_64-pc-windows-msvc", r.extract_dir.?);
    try testing.expectEqual(@as(usize, 1), r.bins.len);
    try testing.expectEqualStrings("rg.exe", r.bins[0].path);
    try testing.expectEqualStrings("rg", r.bins[0].alias);
    try testing.expect(r.sha512 == null);
    try testing.expectEqualStrings(
        "71b2fef860abe467217a538ff31de02f5258807c0129f771846f87bd029aafc5",
        &hex256(r.sha256.?),
    );
    try testing.expect(!r.emulated);
    try testing.expect(archive.Kind.fromString(r.archive_type) != null);

    const arm = try expectResolve(arena.allocator(), "ripgrep", .aarch64);
    try testing.expect(arm.isSupported());
    try testing.expect(!arm.emulated);
    try testing.expect(std.mem.endsWith(u8, arm.url, "aarch64-pc-windows-msvc.zip"));
    try testing.expectEqualStrings("ripgrep-15.2.0-aarch64-pc-windows-msvc", arm.extract_dir.?);
    try testing.expectEqualStrings(
        "e4abca10c3a64ebea742667dd7009449d49403db5460dd6873e389fa2945360f",
        &hex256(arm.sha256.?),
    );
}

test "fd: zip, both architectures" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    for ([_]std.Target.Cpu.Arch{ .x86_64, .aarch64 }) |arch| {
        const r = try expectResolve(arena.allocator(), "fd", arch);
        try testing.expect(r.isSupported());
        try testing.expectEqualStrings("zip", r.archive_type);
        try testing.expectEqualStrings("fd", r.bins[0].alias);
        try testing.expect(r.isVerified());
    }
}

test "neovim: bins live in a subdirectory, both architectures supported" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const r = try expectResolve(arena.allocator(), "neovim", .x86_64);
    try testing.expect(r.isSupported());
    try testing.expectEqualStrings("nvim-win64", r.extract_dir.?);
    try testing.expectEqual(@as(usize, 2), r.bins.len);
    try testing.expectEqualStrings("bin/nvim.exe", r.bins[0].path);
    try testing.expectEqualStrings("nvim", r.bins[0].alias);
    try testing.expectEqualStrings("bin/xxd.exe", r.bins[1].path);
    try testing.expectEqualStrings("xxd", r.bins[1].alias);

    const arm = try expectResolve(arena.allocator(), "neovim", .aarch64);
    try testing.expect(arm.isSupported());
    try testing.expect(!arm.emulated);
    try testing.expect(std.mem.indexOf(u8, arm.url, "nvim-win-arm64.zip") != null);
}

test "jq: a #/jq.exe fragment gives the file name; a bare exe is a raw download" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const r = try expectResolve(arena.allocator(), "jq", .x86_64);
    try testing.expect(r.isSupported());
    try testing.expectEqualStrings("raw", r.archive_type);
    try testing.expectEqualStrings("jq.exe", r.filename);
    try testing.expect(std.mem.indexOfScalar(u8, r.url, '#') == null);
    try testing.expect(std.mem.endsWith(u8, r.url, "jq-windows-amd64.exe"));
    try testing.expect(r.extract_dir == null);
    try testing.expectEqualStrings("jq", r.bins[0].alias);
    try testing.expectEqualStrings("jq.exe", r.bins[0].path);

    const arm = try expectResolve(arena.allocator(), "jq", .aarch64);
    try testing.expect(arm.isSupported());
    try testing.expect(std.mem.endsWith(u8, arm.url, "jq-windows-arm64.exe"));
}

test "7zip: MSI on x64 and a pre_install script on arm64 are unsupported" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const r = try expectResolve(arena.allocator(), "7zip", .x86_64);
    try testing.expect(!r.isSupported());
    try testing.expectEqualStrings("msi", r.archive_type);
    try testing.expectEqualStrings("Files/7-Zip", r.extract_dir.?);
    try testing.expectEqual(@as(usize, 3), r.bins.len);
    try testing.expectEqualStrings("7z", r.bins[0].alias);
    try testing.expectEqualStrings("7zG", r.bins[1].alias);
    // Scripts were not run, only recorded.
    var saw_post = false;
    for (r.notes) |n| {
        if (std.mem.eql(u8, n, "skipped script: post_install")) saw_post = true;
    }
    try testing.expect(saw_post);

    const arm = try expectResolve(arena.allocator(), "7zip", .aarch64);
    try testing.expectEqualStrings("needs install scripts", arm.unsupported.?);
}

test "git, python, nodejs, firefox are unsupported with the right reason" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const git = try expectResolve(a, "git", .x86_64);
    try testing.expectEqualStrings("needs install scripts", git.unsupported.?);
    try testing.expectEqualStrings("dl.7z", git.filename);
    try testing.expectEqualStrings("7z", git.archive_type);

    const py = try expectResolve(a, "python", .x86_64);
    try testing.expectEqualStrings("needs install scripts", py.unsupported.?);
    try testing.expectEqualStrings("setup.exe", py.filename);

    const node = try expectResolve(a, "nodejs", .x86_64);
    try testing.expectEqualStrings("7z archives are not supported", node.unsupported.?);
    try testing.expectEqualStrings("7z", node.archive_type);
    try testing.expectEqualStrings("node-v26.12.1-win-x64", node.extract_dir.?);
    try testing.expect(node.isVerified());
    const node_arm = try expectResolve(a, "nodejs", .aarch64);
    try testing.expect(!node_arm.isSupported());
    try testing.expect(!node_arm.emulated);

    const ff = try expectResolve(a, "firefox", .x86_64);
    try testing.expectEqualStrings("7z archives are not supported", ff.unsupported.?);
    try testing.expectEqualStrings("dl.7z", ff.filename);
    try testing.expect(ff.sha256 == null);
    try testing.expect(ff.sha512 != null);
    try testing.expectEqualStrings("core", ff.extract_dir.?);
    try testing.expectEqualStrings("firefox", ff.bins[0].alias);
    const ff_arm = try expectResolve(a, "firefox", .aarch64);
    try testing.expect(std.mem.indexOf(u8, ff_arm.url, "win64-aarch64") != null);
}

test "unsupported CPU architectures" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const r = try expectResolve(arena.allocator(), "ripgrep", .x86);
    try testing.expectEqualStrings("unsupported CPU architecture", r.unsupported.?);
    // 32-bit blocks are never selected, even when they are the only ones.
    const only32 =
        \\{"version":"1.0","architecture":{"32bit":{"url":"https://x.test/a.zip","hash":"
    ++ h64z ++
        \\"}},"bin":"a.exe"}
    ;
    const r2 = try resolve(arena.allocator(), only32, .x86_64);
    try testing.expectEqualStrings("no download for this architecture", r2.unsupported.?);
}

test "arm64 falls back to the 64bit build and is marked emulated" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const m =
        \\{"version":"2.0","architecture":{"64bit":{"url":"https://x.test/t-2.0.zip",
        \\"hash":"sha512:
    ++ h128 ++
        \\"}},"bin":"t.exe"}
    ;
    const r = try resolve(arena.allocator(), m, .aarch64);
    try testing.expect(r.isSupported());
    try testing.expect(r.emulated);
    try testing.expect(r.sha256 == null);
    try testing.expectEqual(@as(u8, 0xab), r.sha512.?[63]);
    const x = try resolve(arena.allocator(), m, .x86_64);
    try testing.expect(!x.emulated);
}

test "top-level url, hash forms, and unverified opt-in" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const sha1 = "{\"version\":\"1\",\"url\":\"https://x.test/a.zip\",\"hash\":\"sha1:" ++ h40 ++ "\",\"bin\":\"a.exe\"}";
    const md5 = "{\"version\":\"1\",\"url\":\"https://x.test/a.zip\",\"hash\":\"md5:" ++ h32 ++ "\",\"bin\":\"a.exe\"}";
    const none = "{\"version\":\"1\",\"url\":\"https://x.test/a.zip\",\"bin\":\"a.exe\"}";
    const prefixed = "{\"version\":\"1\",\"url\":[\"https://x.test/a.zip\"],\"hash\":[\"SHA256:" ++ h64u ++ "\"],\"bin\":\"a.exe\"}";
    const bare = "{\"version\":\"1\",\"url\":\"https://x.test/a.zip\",\"hash\":\"" ++ h64 ++ "\",\"bin\":\"a.exe\"}";

    for ([_][]const u8{ sha1, md5, none }) |m| {
        const r = try resolve(a, m, .x86_64);
        try testing.expectEqualStrings("weak or missing hash", r.unsupported.?);
        try testing.expect(r.sha256 == null and r.sha512 == null);

        const ok = try resolveOpts(a, m, .x86_64, .{ .allow_unverified = true });
        try testing.expect(ok.isSupported());
        try testing.expect(!ok.isVerified());
    }

    const p = try resolve(a, prefixed, .x86_64);
    try testing.expect(p.isSupported());
    try testing.expectEqual(@as(u8, 0x0a), p.sha256.?[0]);
    const b = try resolve(a, bare, .aarch64);
    try testing.expect(b.isSupported());
    try testing.expect(!b.emulated); // no architecture block: nothing was emulated
    try testing.expect(b.sha256 != null);
}

test "malformed hashes are never waved through, even when unverified is allowed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_][]const u8{
        hzz,
        "abcd",
        "sha256:" ++ h62,
        "sha512:" ++ h64ab,
        "crc32:deadbeef",
        "sha256:",
    }) |h| {
        const m = try std.fmt.allocPrint(a, "{{\"version\":\"1\",\"url\":\"https://x.test/a.zip\",\"hash\":\"{s}\"}}", .{h});
        const r = try resolveOpts(a, m, .x86_64, .{ .allow_unverified = true });
        try testing.expectEqualStrings("malformed hash", r.unsupported.?);
    }
}

test "multiple urls are unsupported" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const m =
        \\{"version":"1","url":["https://x.test/a.zip","https://x.test/b.zip"],
        \\"hash":["
    ++ h64 ++ "\",\"" ++ h64b ++
        \\"],"bin":"a.exe"}
    ;
    const r = try resolve(arena.allocator(), m, .x86_64);
    try testing.expectEqualStrings("multiple downloads", r.unsupported.?);
}

test "scripts are classified, never run" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const head = "{\"version\":\"1\",\"url\":\"https://x.test/a.zip\",\"hash\":\"" ++ h64 ++ "\",\"bin\":\"a.exe\",";

    const installer = try resolve(a, head ++ "\"installer\":{\"script\":\"Remove-Item C:\\\\\"}}", .x86_64);
    try testing.expectEqualStrings("needs install scripts", installer.unsupported.?);
    const pre = try resolve(a, head ++ "\"pre_install\":\"calc\"}", .x86_64);
    try testing.expectEqualStrings("needs install scripts", pre.unsupported.?);
    const pre_empty = try resolve(a, head ++ "\"pre_install\":[]}", .x86_64);
    try testing.expect(pre_empty.isSupported());

    const post = try resolve(a, head ++ "\"post_install\":[\"x\"],\"uninstaller\":{\"script\":\"y\"},\"persist\":\"data\",\"env_add_path\":\"bin\",\"env_set\":{\"A\":\"b\"},\"depends\":\"vcredist\"}", .x86_64);
    try testing.expect(post.isSupported());
    try testing.expectEqual(@as(usize, 6), post.notes.len);
    try testing.expectEqualStrings("skipped script: post_install", post.notes[0]);
}

test "unsafe paths in extract_dir and bin are refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const head = "{\"version\":\"1\",\"url\":\"https://x.test/a.zip\",\"hash\":\"" ++ h64 ++ "\",";

    const bad_extract = [_][]const u8{
        "\"extract_dir\":\"../../etc\"",
        "\"extract_dir\":\"..\\\\..\\\\Windows\"",
        "\"extract_dir\":\"C:\\\\Windows\"",
        "\"extract_dir\":\"/abs\"",
        "\"extract_dir\":\"$dir\\\\x\"",
        "\"extract_dir\":\"a/*\"",
        "\"extract_dir\":5",
    };
    for (bad_extract) |frag| {
        const m = try std.fmt.allocPrint(a, "{s}{s},\"bin\":\"a.exe\"}}", .{ head, frag });
        const r = try resolve(a, m, .x86_64);
        try testing.expect(!r.isSupported());
        try testing.expect(r.extract_dir == null);
    }

    const bad_bin = [_][]const u8{
        "\"bin\":\"../evil.exe\"",
        "\"bin\":\"..\\\\evil.exe\"",
        "\"bin\":\"C:\\\\evil.exe\"",
        "\"bin\":\"/evil.exe\"",
        "\"bin\":\"$dir\\\\evil.exe\"",
        "\"bin\":\"run.ps1\"",
        "\"bin\":\"run.cmd\"",
        "\"bin\":\"\"",
        "\"bin\":7",
        "\"bin\":[7]",
        "\"bin\":[[]]",
        "\"bin\":[[\"a.exe\",\"../x\"]]",
        "\"bin\":[[\"a.exe\",\"sudo\"]]",
        "\"bin\":[[\"a.exe\",\"abv0\"]]",
        "\"bin\":[[\"a.exe\",\"x\",\"\\\"open\"]]",
        "\"bin\":[\"a.exe\",\"sub/a.exe\"]",
    };
    for (bad_bin) |frag| {
        const m = try std.fmt.allocPrint(a, "{s}{s}}}", .{ head, frag });
        const r = try resolve(a, m, .x86_64);
        try testing.expect(!r.isSupported());
    }
}

test "bin tuples carry an alias and arguments" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const m = "{\"version\":\"1\",\"url\":\"https://x.test/a.zip\",\"hash\":\"" ++ h64 ++
        "\",\"extract_dir\":\"pkg\\\\\",\"bin\":[\"plain.exe\",[\"tools\\\\tool.exe\",\"t\",\"--mode fast\",\"--name \\\"a b\\\"\"]]}";
    const r = try resolve(arena.allocator(), m, .x86_64);
    try testing.expect(r.isSupported());
    try testing.expectEqualStrings("pkg", r.extract_dir.?);
    try testing.expectEqual(@as(usize, 2), r.bins.len);
    try testing.expectEqualStrings("plain", r.bins[0].alias);
    try testing.expectEqualStrings("tools/tool.exe", r.bins[1].path);
    try testing.expectEqualStrings("t", r.bins[1].alias);
    try testing.expectEqual(@as(usize, 4), r.bins[1].args.len);
    try testing.expectEqualStrings("--mode", r.bins[1].args[0]);
    try testing.expectEqualStrings("fast", r.bins[1].args[1]);
    try testing.expectEqualStrings("--name", r.bins[1].args[2]);
    try testing.expectEqualStrings("a b", r.bins[1].args[3]);

    // Duplicate aliases collide on PATH.
    const dup = "{\"version\":\"1\",\"url\":\"https://x.test/a.zip\",\"hash\":\"" ++ h64 ++
        "\",\"bin\":[\"a.exe\",\"sub/A.exe\"]}";
    const d = try resolve(arena.allocator(), dup, .x86_64);
    try testing.expectEqualStrings("duplicate bin name", d.unsupported.?);
}

test "unsafe or odd URLs" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const tail = ",\"hash\":\"" ++ h64 ++ "\",\"bin\":\"a.exe\"}";

    for ([_][]const u8{
        "http://x.test/a.zip",
        "file:///etc/passwd",
        "https://user@evil.test/a.zip",
        "https://x.test/a b.zip",
        "ftp://x.test/a.zip",
    }) |u| {
        const m = try std.fmt.allocPrint(a, "{{\"version\":\"1\",\"url\":\"{s}\"{s}", .{ u, tail });
        const r = try resolve(a, m, .x86_64);
        try testing.expect(!r.isSupported());
    }

    // The fragment can rename the download but not escape the directory.
    for ([_][]const u8{ "#/../x.zip", "#/a/b.zip", "#/..", "#/C:evil.zip" }) |frag| {
        const m = try std.fmt.allocPrint(a, "{{\"version\":\"1\",\"url\":\"https://x.test/a.zip{s}\"{s}", .{ frag, tail });
        const r = try resolve(a, m, .x86_64);
        try testing.expectEqualStrings("unsafe download file name", r.unsupported.?);
    }

    // Query strings do not leak into the file name used for classification.
    const q = try resolve(a, "{\"version\":\"1\",\"url\":\"https://x.test/dl/a.zip?token=1\"" ++ tail, .x86_64);
    try testing.expect(q.isSupported());
    try testing.expectEqualStrings("a.zip", q.filename);
    // Unknown types and non-archives are not guessed at.
    const unk = try resolve(a, "{\"version\":\"1\",\"url\":\"https://x.test/download\"" ++ tail, .x86_64);
    try testing.expectEqualStrings("unsupported download type", unk.unsupported.?);
    const host_only = try resolve(a, "{\"version\":\"1\",\"url\":\"https://x.test\"" ++ tail, .x86_64);
    try testing.expect(!host_only.isSupported());
}

test "raw downloads must match their bin" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const tail = ",\"hash\":\"" ++ h64 ++ "\"";
    const ok = try resolve(a, "{\"version\":\"1\",\"url\":\"https://x.test/tool.exe\"" ++ tail ++ ",\"bin\":\"tool.exe\"}", .x86_64);
    try testing.expect(ok.isSupported());
    const mismatch = try resolve(a, "{\"version\":\"1\",\"url\":\"https://x.test/tool-1.0.exe\"" ++ tail ++ ",\"bin\":\"tool.exe\"}", .x86_64);
    try testing.expect(!mismatch.isSupported());
}

test "hostile JSON never panics" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try testing.expectError(error.InvalidManifest, resolve(a, "", .x86_64));
    try testing.expectError(error.InvalidManifest, resolve(a, "not json", .x86_64));
    try testing.expectError(error.InvalidManifest, resolve(a, "[]", .x86_64));
    try testing.expectError(error.InvalidManifest, resolve(a, "\"str\"", .x86_64));
    try testing.expectError(error.InvalidManifest, resolve(a, "null", .x86_64));
    try testing.expectError(error.InvalidManifest, resolve(a, "{}", .x86_64));
    try testing.expectError(error.InvalidManifest, resolve(a, "{\"version\":1}", .x86_64));
    try testing.expectError(error.InvalidManifest, resolve(a, "{\"version\":\"1\"", .x86_64));
    try testing.expectError(error.InvalidVersion, resolve(a, "{\"version\":\"../../x\"}", .x86_64));
    try testing.expectError(error.InvalidVersion, resolve(a, "{\"version\":\"\"}", .x86_64));
    try testing.expectError(error.InvalidName, resolveOpts(a, "{\"version\":\"1\"}", .x86_64, .{ .name = "../x" }));

    // Wrong types everywhere: unsupported, not a crash.
    const weird = [_][]const u8{
        "{\"version\":\"1\",\"url\":5}",
        "{\"version\":\"1\",\"url\":[]}",
        "{\"version\":\"1\",\"url\":[5]}",
        "{\"version\":\"1\",\"url\":{}}",
        "{\"version\":\"1\",\"architecture\":5,\"url\":\"https://x.test/a.zip\"}",
        "{\"version\":\"1\",\"architecture\":[],\"url\":\"https://x.test/a.zip\"}",
        "{\"version\":\"1\",\"architecture\":{\"64bit\":5}}",
        "{\"version\":\"1\",\"architecture\":{\"64bit\":null,\"arm64\":[]}}",
        "{\"version\":\"1\",\"url\":\"https://x.test/a.zip\",\"hash\":{}}",
        "{\"version\":\"1\",\"url\":\"https://x.test/a.zip\",\"hash\":[5]}",
        "{\"version\":\"1\",\"url\":\"https://x.test/a.zip\",\"hash\":[]}",
        "{\"version\":\"1\",\"url\":\"https://x.test/a.zip\",\"extract_dir\":[\"a\",\"b\"]}",
        "{\"version\":\"1\",\"url\":\"https://x.test/a.zip\",\"bin\":{}}",
        "{\"version\":\"1\",\"url\":\"https://x.test/a.zip\",\"bin\":[[[]]]}",
        "{\"version\":\"1\",\"url\":\"https://x.test/a.zip\",\"bin\":[[\"a.exe\",5]]}",
        "{\"version\":\"1\",\"url\":\"https://x.test/a.zip\",\"bin\":[[\"a.exe\",\"a\",5]]}",
        "{\"version\":\"1\",\"description\":5,\"homepage\":[],\"license\":{\"identifier\":5}}",
        "{\"version\":\"1\",\"url\":\"https://x.test/a.zip\",\"installer\":null,\"pre_install\":false}",
    };
    for (weird) |m| {
        const r = try resolve(a, m, .x86_64);
        try testing.expect(!r.isSupported());
        _ = try resolve(a, m, .aarch64);
    }

    // BOM is tolerated; deep nesting and oversized input do not blow up.
    const bom = try resolve(a, "\xEF\xBB\xBF{\"version\":\"1\"}", .x86_64);
    try testing.expect(!bom.isSupported());
    const deep = try a.alloc(u8, 200_000);
    @memset(deep, '[');
    try testing.expectError(error.InvalidManifest, resolve(a, deep, .x86_64));
    const huge = try a.alloc(u8, max_manifest_bytes + 1);
    @memset(huge, ' ');
    try testing.expectError(error.ManifestTooLarge, resolve(a, huge, .x86_64));
}

test "parseHash" {
    try testing.expect(parseHash(h64ab) == .sha256);
    try testing.expect(parseHash(h128u) == .sha512);
    try testing.expect(parseHash("sha256:" ++ h64ab) == .sha256);
    try testing.expect(parseHash("sha1:" ++ h40ab) == .weak);
    try testing.expect(parseHash("md5:" ++ h32ab) == .weak);
    try testing.expect(parseHash(h40ab) == .weak);
    try testing.expect(parseHash("") == .invalid);
    try testing.expect(parseHash("xyz") == .invalid);
}
