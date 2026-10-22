//! Self-building catalog: turns `catalog/sources.txt` into the registry
//! `packages/index.json` by reading each project's official GitHub releases.
//!
//!   build-catalog --sources catalog/sources.txt --out packages/index.json
//!                 [--previous packages/index.json] [--manual catalog/manual.json]
//!                 [--only name,...] [--force] [--jobs N] [--curl]
//!                 [--offline-fixtures dir] [--allow-shrink] [--allow-failures]
//!                 [--max-download-mb N] [--summary report.md]
//!
//! For every source line the tool
//!   1. asks the GitHub API for the latest (or the pinned) release,
//!   2. picks one asset for each of abv0's six platforms with the same scorer
//!      the `abv0 install gh:` command uses (src/ghrelease.zig),
//!   3. pins each asset's SHA-256 from GitHub's `digest` field, else from a
//!      checksums file in the release, else by downloading and hashing it,
//!   4. downloads ONE asset per changed package, unpacks it with abv0's own
//!      extractor and finds the executables inside, and
//!   5. reads description, license and homepage from the repository record.
//!
//! A `kind=app` source is a macOS application (a "cask"): only the two Mac
//! platforms are published, as a .dmg or .zip, with `app_bundles` set and no
//! executables detected. A .dmg needs `app=Name.app` on its line; for a .zip the
//! tool downloads it once and lists the `*.app` directories at its top level.
//!
//! It is incremental: a package whose version equals the one in `--previous`
//! is copied over untouched, with no download. A source that fails keeps its
//! previous entry (reported as "stale"), so one flaky upstream never removes a
//! package from the catalog. The result is deterministic JSON, checked by
//! loading it back through `registry.loadFromJsonFile` before it replaces the
//! output file. Signing is a separate step (`sign-manifest sign`).

const std = @import("std");
const builtin = @import("builtin");
const deps = @import("catalog_deps");

const ghrelease = deps.ghrelease;
const archive = deps.archive;
const registry = deps.registry;
const safepath = deps.safepath;
const net = deps.net;
const bindetect = deps.bindetect;
const ghverify = deps.ghverify;

const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

const user_agent = "abv0-build-catalog";
const max_bins = 8;
const max_description_len = 240;
const max_checksum_bytes = 4 * 1024 * 1024;
const default_max_download_bytes: u64 = 400 * 1024 * 1024;
/// Sources processed at once. The work is network bound, so this is well above
/// the core count; the GitHub API allows far more requests than a run makes.
const default_jobs: usize = 8;

// ---------------------------------------------------------------------------
// Platforms
// ---------------------------------------------------------------------------

/// The six platform tags of platform.zig, in sorted order so output is stable.
pub const platform_tags = [_][]const u8{
    "aarch64-linux", "aarch64-macos", "aarch64-windows",
    "x86_64-linux",  "x86_64-macos",  "x86_64-windows",
};

const OsKind = enum { linux, macos, windows };

fn platformIndex(tag: []const u8) ?usize {
    for (platform_tags, 0..) |t, i| {
        if (std.mem.eql(u8, t, tag)) return i;
    }
    return null;
}

fn osOfPlatform(index: usize) OsKind {
    const tag = platform_tags[index];
    if (std.mem.endsWith(u8, tag, "-windows")) return .windows;
    if (std.mem.endsWith(u8, tag, "-macos")) return .macos;
    return .linux;
}

fn stdOs(os: OsKind) std.Target.Os.Tag {
    return switch (os) {
        .linux => .linux,
        .macos => .macos,
        .windows => .windows,
    };
}

/// The order in which an asset is chosen for bin detection: Linux first
/// because it is the cheapest to unpack and carries real mode bits.
const detect_order = [_]usize{ 3, 0, 5, 2, 4, 1 };

// ---------------------------------------------------------------------------
// sources.txt
// ---------------------------------------------------------------------------

/// What a source publishes: command-line tools found by unpacking (`cli`), or
/// a macOS application bundle to link under the apps directory (`app`).
pub const SourceKind = enum { cli, app };

pub const Source = struct {
    name: []const u8,
    owner: []const u8,
    repo: []const u8,
    /// Executable names that replace detection. Empty means "detect".
    bin: []const []const u8 = &.{},
    /// `asset.<platform>=<substring>`: force the asset whose name matches.
    assets: [6]?[]const u8 = .{null} ** 6,
    skip: [6]bool = .{false} ** 6,
    desc: ?[]const u8 = null,
    license: ?[]const u8 = null,
    tag: ?[]const u8 = null,
    kind: SourceKind = .cli,
    /// `app=Name.app`: the bundle's name. Required when the macOS asset is a
    /// .dmg (its contents cannot be listed off macOS); detected for a .zip.
    apps: []const []const u8 = &.{},
    line: usize = 0,
};

pub const Problem = struct { line: usize, text: []const u8 };

pub const Parsed = struct {
    sources: []Source,
    problems: []Problem,
};

const TokenError = error{ UnterminatedQuote, OutOfMemory };

/// Splits one line into whitespace separated tokens. Double quotes group
/// characters (including spaces) into a token and are removed; inside quotes
/// `\"` and `\\` are escapes. A `#` that starts a token outside quotes begins
/// a comment that runs to the end of the line.
fn tokenize(arena: Allocator, line: []const u8) TokenError![]const []const u8 {
    var toks = std.ArrayList([]const u8).init(arena);
    var i: usize = 0;
    while (i < line.len) {
        while (i < line.len and (line[i] == ' ' or line[i] == '\t' or line[i] == '\r')) i += 1;
        if (i >= line.len or line[i] == '#') break;

        var tok = std.ArrayList(u8).init(arena);
        var in_quote = false;
        while (i < line.len) : (i += 1) {
            const c = line[i];
            if (in_quote) {
                if (c == '\\' and i + 1 < line.len and (line[i + 1] == '"' or line[i + 1] == '\\')) {
                    i += 1;
                    try tok.append(line[i]);
                } else if (c == '"') {
                    in_quote = false;
                } else {
                    try tok.append(c);
                }
            } else {
                if (c == '"') {
                    in_quote = true;
                } else if (c == ' ' or c == '\t' or c == '\r') {
                    break;
                } else {
                    try tok.append(c);
                }
            }
        }
        if (in_quote) return error.UnterminatedQuote;
        try toks.append(try tok.toOwnedSlice());
    }
    return toks.toOwnedSlice();
}

/// A bundle name abv0 can link: one plain `Name.app` path component.
pub fn isUsableAppName(name: []const u8) bool {
    if (name.len <= ".app".len or !std.mem.endsWith(u8, name, ".app")) return false;
    for (name) |c| {
        if (c < 0x20 or c == 0x7f or c == '/' or c == '\\' or c == ':') return false;
    }
    return safepath.isSafeRelPath(name);
}

const LineResult = union(enum) { source: Source, bad: []const u8 };

fn bad(arena: Allocator, comptime fmt: []const u8, args: anytype) !LineResult {
    return .{ .bad = try std.fmt.allocPrint(arena, fmt, args) };
}

fn parseLine(arena: Allocator, toks: []const []const u8, line_no: usize) !LineResult {
    if (toks.len < 2) return bad(arena, "expected `name owner/repo [key=value ...]`", .{});

    const name = toks[0];
    if (!safepath.isValidId(name)) return bad(arena, "invalid package name '{s}'", .{name});

    if (std.mem.indexOfScalar(u8, toks[1], '@') != null) {
        return bad(arena, "'{s}': pin a tag with tag=..., not owner/repo@tag", .{toks[1]});
    }
    const spec = ghrelease.parseSpec(toks[1]) orelse
        return bad(arena, "'{s}' is not a valid owner/repo", .{toks[1]});

    var src = Source{ .name = name, .owner = spec.owner, .repo = spec.repo, .line = line_no };
    var kind_key: ?SourceKind = null;

    for (toks[2..]) |t| {
        const eq = std.mem.indexOfScalar(u8, t, '=') orelse
            return bad(arena, "expected key=value, got '{s}'", .{t});
        const key = t[0..eq];
        const val = t[eq + 1 ..];
        if (val.len == 0) return bad(arena, "empty value for '{s}'", .{key});

        if (std.mem.eql(u8, key, "bin")) {
            var list = std.ArrayList([]const u8).init(arena);
            var it = std.mem.splitScalar(u8, val, ',');
            while (it.next()) |b| {
                if (!registry.isUsableBinName(b)) return bad(arena, "bin '{s}' is not a usable executable name", .{b});
                try list.append(b);
            }
            src.bin = try list.toOwnedSlice();
        } else if (std.mem.eql(u8, key, "skip")) {
            var it = std.mem.splitScalar(u8, val, ',');
            while (it.next()) |p| {
                const pi = platformIndex(p) orelse return bad(arena, "unknown platform '{s}' in skip", .{p});
                src.skip[pi] = true;
            }
        } else if (std.mem.eql(u8, key, "desc")) {
            src.desc = val;
        } else if (std.mem.eql(u8, key, "license")) {
            src.license = val;
        } else if (std.mem.eql(u8, key, "tag")) {
            const probe = try std.fmt.allocPrint(arena, "{s}/{s}@{s}", .{ spec.owner, spec.repo, val });
            if (ghrelease.parseSpec(probe) == null) return bad(arena, "'{s}' is not a valid release tag", .{val});
            src.tag = val;
        } else if (std.mem.eql(u8, key, "kind")) {
            if (std.mem.eql(u8, val, "app")) {
                kind_key = .app;
            } else if (std.mem.eql(u8, val, "cli")) {
                kind_key = .cli;
            } else return bad(arena, "unknown kind '{s}' (want app or cli)", .{val});
        } else if (std.mem.eql(u8, key, "app")) {
            var list = std.ArrayList([]const u8).init(arena);
            var it = std.mem.splitScalar(u8, val, ',');
            while (it.next()) |n| {
                if (!isUsableAppName(n)) return bad(arena, "app '{s}' is not a usable bundle name (want Name.app)", .{n});
                try list.append(n);
            }
            src.apps = try list.toOwnedSlice();
        } else if (std.mem.startsWith(u8, key, "asset.")) {
            const pi = platformIndex(key["asset.".len..]) orelse
                return bad(arena, "unknown platform in '{s}'", .{key});
            src.assets[pi] = val;
        } else {
            return bad(arena, "unknown key '{s}'", .{key});
        }
    }
    // `app=` alone means an app source; `kind=` says it outright.
    src.kind = kind_key orelse if (src.apps.len != 0) SourceKind.app else SourceKind.cli;
    if (src.kind == .cli and src.apps.len != 0) return bad(arena, "app= needs kind=app", .{});
    if (src.kind == .app and src.bin.len != 0) return bad(arena, "bin= does not apply to kind=app", .{});
    return .{ .source = src };
}

/// Parses `sources.txt`. Bad lines are collected as problems and skipped; they
/// never abort the run. Everything is allocated from `arena`.
pub fn parseSources(arena: Allocator, text: []const u8) !Parsed {
    var sources = std.ArrayList(Source).init(arena);
    var problems = std.ArrayList(Problem).init(arena);
    var seen = std.StringHashMap(void).init(arena);

    var line_no: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        line_no += 1;
        const toks = tokenize(arena, raw) catch |e| switch (e) {
            error.UnterminatedQuote => {
                try problems.append(.{ .line = line_no, .text = "unterminated quote" });
                continue;
            },
            error.OutOfMemory => return error.OutOfMemory,
        };
        if (toks.len == 0) continue;

        switch (try parseLine(arena, toks, line_no)) {
            .source => |s| {
                if (seen.contains(s.name)) {
                    try problems.append(.{ .line = line_no, .text = try std.fmt.allocPrint(arena, "duplicate package name '{s}'", .{s.name}) });
                    continue;
                }
                try seen.put(s.name, {});
                try sources.append(s);
            },
            .bad => |msg| try problems.append(.{ .line = line_no, .text = msg }),
        }
    }
    return .{ .sources = try sources.toOwnedSlice(), .problems = try problems.toOwnedSlice() };
}

// ---------------------------------------------------------------------------
// Versions
// ---------------------------------------------------------------------------

/// The package version for a release tag, or null when no valid version id can
/// be made from it. A leading `v` is dropped (`v1.2.3`), and so is a project
/// prefix (`jq-1.7.1`, `bun-v1.1.30`, `release-2.0`, `cli/v3.4`) when what
/// follows starts with a digit. Anything else that is a valid id is kept as is
/// (`nightly`).
pub fn versionFromTag(tag: []const u8) ?[]const u8 {
    var t = tag;
    if (std.mem.lastIndexOfScalar(u8, t, '/')) |i| t = t[i + 1 ..];
    if (t.len == 0) return null;

    const isSep = struct {
        fn f(c: u8) bool {
            return c == '-' or c == '_' or c == '@';
        }
    }.f;

    if ((t[0] == 'v' or t[0] == 'V') and t.len > 1 and std.ascii.isDigit(t[1])) {
        t = t[1..];
    } else if (!std.ascii.isDigit(t[0])) {
        var i: usize = 1;
        while (i < t.len) : (i += 1) {
            if (!std.ascii.isDigit(t[i])) continue;
            if (isSep(t[i - 1])) {
                t = t[i..];
                break;
            }
            if ((t[i - 1] == 'v' or t[i - 1] == 'V') and i >= 2 and isSep(t[i - 2])) {
                t = t[i..];
                break;
            }
        }
    }
    return if (safepath.isValidId(t)) t else null;
}

// ---------------------------------------------------------------------------
// Hash text
// ---------------------------------------------------------------------------

fn isHex64(s: []const u8) bool {
    if (s.len != 64) return false;
    for (s) |c| {
        if (!std.ascii.isHex(c)) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Package entries (the shape of one object in index.json)
// ---------------------------------------------------------------------------

pub const PlatEntry = struct {
    tag: []const u8,
    url: []const u8,
    sha256: []const u8,
    archive_type: []const u8,
    bin_path: []const u8,
};

pub const Entry = struct {
    name: []const u8,
    version: []const u8,
    description: []const u8 = "",
    homepage: []const u8 = "",
    license: []const u8 = "",
    bin: []const []const u8 = &.{},
    app_bundles: []const []const u8 = &.{},
    deps: []const []const u8 = &.{},
    plats: []const PlatEntry = &.{},
};

fn dupeStrings(a: Allocator, list: []const []const u8) ![]const []const u8 {
    const out = try a.alloc([]const u8, list.len);
    for (list, out) |s, *o| o.* = try a.dupe(u8, s);
    return out;
}

fn cloneEntry(a: Allocator, e: Entry) !Entry {
    const plats = try a.alloc(PlatEntry, e.plats.len);
    for (e.plats, plats) |p, *o| o.* = .{
        .tag = try a.dupe(u8, p.tag),
        .url = try a.dupe(u8, p.url),
        .sha256 = try a.dupe(u8, p.sha256),
        .archive_type = try a.dupe(u8, p.archive_type),
        .bin_path = try a.dupe(u8, p.bin_path),
    };
    return .{
        .name = try a.dupe(u8, e.name),
        .version = try a.dupe(u8, e.version),
        .description = try a.dupe(u8, e.description),
        .homepage = try a.dupe(u8, e.homepage),
        .license = try a.dupe(u8, e.license),
        .bin = try dupeStrings(a, e.bin),
        .app_bundles = try dupeStrings(a, e.app_bundles),
        .deps = try dupeStrings(a, e.deps),
        .plats = plats,
    };
}

/// Why `e` could not be published, or null when it passes the same rules the
/// registry loader applies (plus the ones only a generator can enforce: a
/// pinned hash, a known archive type and at least one executable).
pub fn validateEntry(e: Entry) ?[]const u8 {
    const pkg = registry.Package{
        .name = e.name,
        .version = e.version,
        .bin = e.bin,
        .app_bundles = e.app_bundles,
        .deps = e.deps,
    };
    if (!registry.isUsablePackage(pkg)) return "name, version, bin or dependency rejected by registry rules";
    if (e.bin.len == 0 and e.app_bundles.len == 0) return "no executables";
    for (e.app_bundles) |a| {
        if (!isUsableAppName(a)) return "app bundle name is not a plain Name.app";
    }
    if (e.plats.len == 0) return "no platforms";
    if (e.homepage.len != 0 and !net.isSafeUrl(e.homepage)) return "homepage is not an https URL";
    for (e.plats) |p| {
        if (platformIndex(p.tag) == null) return "unknown platform tag";
        if (!registry.isUsablePlatform(p.tag, p.url, p.bin_path)) return "platform url or bin_path rejected by registry rules";
        if (!isHex64(p.sha256)) return "sha256 is not 64 hex characters";
        for (p.sha256) |c| {
            if (std.ascii.isUpper(c)) return "sha256 must be lowercase";
        }
        if (archive.Kind.fromString(p.archive_type) == null) return "unknown archive_type";
    }
    return null;
}

fn jsonString(w: anytype, s: []const u8) !void {
    try std.json.encodeJsonString(s, .{}, w);
}

fn jsonStringArray(w: anytype, list: []const []const u8) !void {
    try w.writeByte('[');
    for (list, 0..) |s, i| {
        if (i != 0) try w.writeAll(", ");
        try jsonString(w, s);
    }
    try w.writeByte(']');
}

fn lessEntry(_: void, x: Entry, y: Entry) bool {
    return std.mem.order(u8, x.name, y.name) == .lt;
}

fn lessPlat(_: void, x: PlatEntry, y: PlatEntry) bool {
    return std.mem.order(u8, x.tag, y.tag) == .lt;
}

/// Deterministic index.json: packages and platforms sorted by name, two-space
/// indent, short arrays on one line, a trailing newline. The same entries and
/// timestamp always give the same bytes.
pub fn renderIndex(a: Allocator, entries_in: []const Entry, updated_at: []const u8) ![]u8 {
    const entries = try a.dupe(Entry, entries_in);
    defer a.free(entries);
    std.mem.sort(Entry, entries, {}, lessEntry);

    var out = std.ArrayList(u8).init(a);
    errdefer out.deinit();
    const w = out.writer();

    try w.writeAll("{\n  \"registry_version\": 1,\n  \"updated_at\": ");
    try jsonString(w, updated_at);
    if (entries.len == 0) {
        try w.writeAll(",\n  \"packages\": {}\n}\n");
        return out.toOwnedSlice();
    }
    try w.writeAll(",\n  \"packages\": {\n");
    for (entries, 0..) |e, i| {
        if (i != 0) try w.writeAll(",\n");
        try w.writeAll("    ");
        try jsonString(w, e.name);
        try w.writeAll(": {\n      \"name\": ");
        try jsonString(w, e.name);
        try w.writeAll(",\n      \"version\": ");
        try jsonString(w, e.version);
        try w.writeAll(",\n      \"description\": ");
        try jsonString(w, e.description);
        try w.writeAll(",\n      \"homepage\": ");
        try jsonString(w, e.homepage);
        try w.writeAll(",\n      \"license\": ");
        try jsonString(w, e.license);
        try w.writeAll(",\n      \"bin\": ");
        try jsonStringArray(w, e.bin);
        try w.writeAll(",\n      \"app_bundles\": ");
        try jsonStringArray(w, e.app_bundles);
        if (e.deps.len != 0) {
            try w.writeAll(",\n      \"deps\": ");
            try jsonStringArray(w, e.deps);
        }
        try w.writeAll(",\n      \"platforms\": {\n");

        const plats = try a.dupe(PlatEntry, e.plats);
        defer a.free(plats);
        std.mem.sort(PlatEntry, plats, {}, lessPlat);
        for (plats, 0..) |p, j| {
            if (j != 0) try w.writeAll(",\n");
            try w.writeAll("        ");
            try jsonString(w, p.tag);
            try w.writeAll(": {\n          \"url\": ");
            try jsonString(w, p.url);
            try w.writeAll(",\n          \"sha256\": ");
            try jsonString(w, p.sha256);
            try w.writeAll(",\n          \"archive_type\": ");
            try jsonString(w, p.archive_type);
            try w.writeAll(",\n          \"bin_path\": ");
            try jsonString(w, p.bin_path);
            try w.writeAll("\n        }");
        }
        try w.writeAll("\n      }\n    }");
    }
    try w.writeAll("\n  }\n}\n");
    return out.toOwnedSlice();
}

fn jsonStr(obj: std.json.ObjectMap, key: []const u8) []const u8 {
    const v = obj.get(key) orelse return "";
    return switch (v) {
        .string => |s| s,
        else => "",
    };
}

fn jsonStrList(arena: Allocator, obj: std.json.ObjectMap, key: []const u8) ![]const []const u8 {
    const v = obj.get(key) orelse return &.{};
    const items = switch (v) {
        .array => |arr| arr.items,
        else => return error.MalformedEntry,
    };
    const out = try arena.alloc([]const u8, items.len);
    for (items, out) |item, *o| {
        o.* = switch (item) {
            .string => |s| s,
            else => return error.MalformedEntry,
        };
    }
    return out;
}

fn entryFromJson(arena: Allocator, key: []const u8, obj: std.json.ObjectMap) !Entry {
    const platforms = switch (obj.get("platforms") orelse return error.MalformedEntry) {
        .object => |o| o,
        else => return error.MalformedEntry,
    };
    var plats = std.ArrayList(PlatEntry).init(arena);
    var it = platforms.iterator();
    while (it.next()) |kv| {
        const po = switch (kv.value_ptr.*) {
            .object => |o| o,
            else => return error.MalformedEntry,
        };
        try plats.append(.{
            .tag = kv.key_ptr.*,
            .url = jsonStr(po, "url"),
            .sha256 = jsonStr(po, "sha256"),
            .archive_type = if (po.get("archive_type") != null) jsonStr(po, "archive_type") else "raw",
            .bin_path = jsonStr(po, "bin_path"),
        });
    }
    std.mem.sort(PlatEntry, plats.items, {}, lessPlat);
    const name = if (obj.get("name") != null) jsonStr(obj, "name") else key;
    if (!std.mem.eql(u8, name, key)) return error.MalformedEntry;
    return .{
        .name = name,
        .version = jsonStr(obj, "version"),
        .description = jsonStr(obj, "description"),
        .homepage = jsonStr(obj, "homepage"),
        .license = jsonStr(obj, "license"),
        .bin = try jsonStrList(arena, obj, "bin"),
        .app_bundles = try jsonStrList(arena, obj, "app_bundles"),
        .deps = try jsonStrList(arena, obj, "deps"),
        .plats = try plats.toOwnedSlice(),
    };
}

pub const Loaded = struct {
    entries: std.StringHashMap(Entry),
    updated_at: []const u8 = "",
    skipped: usize = 0,
};

/// Reads the `packages` object of an index.json (or of a manual.json) into
/// entries. Entries that fail validation are dropped and counted, never reused.
pub fn loadEntries(arena: Allocator, bytes: []const u8) !Loaded {
    var loaded = Loaded{ .entries = std.StringHashMap(Entry).init(arena) };
    const root = try std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{});
    const obj = switch (root) {
        .object => |o| o,
        else => return error.MalformedIndex,
    };
    loaded.updated_at = jsonStr(obj, "updated_at");
    const pkgs = switch (obj.get("packages") orelse return error.MalformedIndex) {
        .object => |o| o,
        else => return error.MalformedIndex,
    };
    var it = pkgs.iterator();
    while (it.next()) |kv| {
        const po = switch (kv.value_ptr.*) {
            .object => |o| o,
            else => {
                loaded.skipped += 1;
                continue;
            },
        };
        const e = entryFromJson(arena, kv.key_ptr.*, po) catch {
            loaded.skipped += 1;
            continue;
        };
        if (validateEntry(e) != null) {
            loaded.skipped += 1;
            continue;
        }
        try loaded.entries.put(e.name, e);
    }
    return loaded;
}

fn stripExe(name: []const u8) []const u8 {
    if (name.len > 4 and std.ascii.eqlIgnoreCase(name[name.len - 4 ..], ".exe")) return name[0 .. name.len - 4];
    return name;
}

// ---------------------------------------------------------------------------
// Layout of the executable inside each platform's archive
// ---------------------------------------------------------------------------

/// The asset file name without its archive extension, which is also the name
/// of the single top-level directory most releases unpack to.
pub fn assetStem(name: []const u8) []const u8 {
    const exts = [_][]const u8{ ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.zst", ".tar", ".zip", ".dmg" };
    for (exts) |ext| {
        if (std.ascii.endsWithIgnoreCase(name, ext)) return name[0 .. name.len - ext.len];
    }
    return name;
}

fn looksPlatformSpecific(s: []const u8, version: []const u8) bool {
    if (version.len >= 3 and std.mem.indexOf(u8, s, version) != null) return true;
    const tokens = [_][]const u8{
        "linux", "darwin",  "macos", "windows", "apple", "x86_64", "x86-64", "amd64",
        "arm64", "aarch64", "x64",   "musl",    "win64", "win32",  "osx",
    };
    var buf: [256]u8 = undefined;
    if (s.len > buf.len) return true;
    const lower = std.ascii.lowerString(&buf, s);
    for (tokens) |t| {
        if (std.mem.indexOf(u8, lower, t) != null) return true;
    }
    return false;
}

pub const LayoutInput = struct {
    /// Path of the primary executable inside the unpacked detection asset.
    primary_rel: []const u8,
    /// Stem of the asset that was unpacked.
    detected_stem: []const u8,
    /// The name the executable is exposed as.
    bin_name: []const u8,
    /// The executable is stored under a different name than `bin_name`.
    renamed: bool,
    version: []const u8,
};

/// `bin_path` for one platform, assuming its archive has the same layout as
/// the unpacked one. Returns null when the name of the executable itself
/// depends on the platform and cannot be mapped (the platform is then left out
/// instead of guessed).
///
/// A top-level directory equal to the asset stem follows the target asset's
/// stem. One that mentions a version or platform but is not the stem is
/// dropped, leaving the bare file name for abv0's tree walk to find.
pub fn binPathFor(
    a: Allocator,
    in: LayoutInput,
    target_asset: []const u8,
    target_os: OsKind,
    target_is_raw: bool,
) !?[]const u8 {
    const exe = if (target_os == .windows) ".exe" else "";
    if (target_is_raw) return try std.fmt.allocPrint(a, "{s}{s}", .{ in.bin_name, exe });

    const rel = stripExe(in.primary_rel);
    const target_stem = assetStem(target_asset);

    var comps = std.ArrayList([]const u8).init(a);
    var it = std.mem.splitScalar(u8, rel, '/');
    while (it.next()) |c| try comps.append(c);
    const last = comps.items.len - 1;

    var leaf = comps.items[last];
    if (in.renamed) {
        if (!std.mem.eql(u8, leaf, in.detected_stem)) return null;
        leaf = target_stem;
    }

    var out = std.ArrayList(u8).init(a);
    if (comps.items.len > 1) {
        const top = comps.items[0];
        if (std.mem.eql(u8, top, in.detected_stem)) {
            try out.appendSlice(target_stem);
            for (comps.items[1..last]) |c| {
                try out.append('/');
                try out.appendSlice(c);
            }
            try out.append('/');
            try out.appendSlice(leaf);
        } else if (looksPlatformSpecific(top, in.version)) {
            try out.appendSlice(leaf);
        } else {
            for (comps.items[0..last]) |c| {
                try out.appendSlice(c);
                try out.append('/');
            }
            try out.appendSlice(leaf);
        }
    } else {
        try out.appendSlice(leaf);
    }
    try out.appendSlice(exe);
    return try out.toOwnedSlice();
}

/// When a lone executable carries the platform in its name (`yq_linux_amd64`),
/// expose it under the project's name instead.
pub fn normalizeBinName(detected: []const u8, repo: []const u8) []const u8 {
    if (repo.len == 0 or detected.len <= repo.len) return detected;
    if (!std.ascii.startsWithIgnoreCase(detected, repo)) return detected;
    const c = detected[repo.len];
    if (c != '-' and c != '_' and c != '.') return detected;
    if (!looksPlatformSpecific(detected[repo.len..], "")) return detected;
    return repo;
}

// ---------------------------------------------------------------------------
// Networking
// ---------------------------------------------------------------------------

pub const NetError = error{
    NotFound,
    RateLimited,
    Forbidden,
    ServerError,
    BadStatus,
    CurlFailed,
    TooLarge,
    NoFixture,
    UnsafeUrl,
};

fn netErrorName(e: anyerror) []const u8 {
    return switch (e) {
        error.NotFound => "not found (404)",
        error.RateLimited => "GitHub API rate limit reached",
        error.Forbidden => "forbidden (403)",
        error.ServerError => "server error (5xx)",
        error.NoFixture => "no offline fixture",
        else => @errorName(e),
    };
}

pub const Mode = enum(u8) { http, curl, fixtures };

pub const Net = struct {
    gpa: Allocator,
    mode: std.atomic.Value(u8),
    token: ?[]const u8,
    fixtures_dir: ?[]const u8,
    tmp_root: []const u8,
    hdr_path: []const u8 = "",
    client: std.http.Client,
    api_calls: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    rate_limited: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    switch_mutex: std.Thread.Mutex = .{},

    fn currentMode(self: *const Net) Mode {
        return @enumFromInt(self.mode.load(.acquire));
    }

    pub fn init(
        arena: Allocator,
        gpa: Allocator,
        mode: Mode,
        token: ?[]const u8,
        fixtures_dir: ?[]const u8,
        tmp_root: []const u8,
    ) !Net {
        var n = Net{
            .gpa = gpa,
            .mode = std.atomic.Value(u8).init(@intFromEnum(mode)),
            .token = token,
            .fixtures_dir = fixtures_dir,
            .tmp_root = tmp_root,
            .client = .{ .allocator = gpa },
        };
        if (mode != .fixtures) {
            n.client.initDefaultProxies(arena) catch {};
            n.hdr_path = try std.fs.path.join(arena, &.{ tmp_root, "api.hdr" });
            const f = try std.fs.cwd().createFile(n.hdr_path, .{ .mode = if (builtin.os.tag == .windows) 0 else 0o600 });
            defer f.close();
            try f.writeAll("Accept: application/vnd.github+json\nX-GitHub-Api-Version: 2022-11-28\n");
            if (token) |t| try f.writer().print("Authorization: Bearer {s}\n", .{t});
        }
        return n;
    }

    pub fn deinit(self: *Net) void {
        self.client.deinit();
    }

    // ---- fixtures ---------------------------------------------------------

    fn fixturePath(self: *Net, a: Allocator, comptime fmt: []const u8, args: anytype) ![]u8 {
        const dir = self.fixtures_dir orelse return error.NoFixture;
        const rel = try std.fmt.allocPrint(a, fmt, args);
        return std.fs.path.join(a, &.{ dir, rel });
    }

    fn readFixture(self: *Net, a: Allocator, path: []const u8) ![]u8 {
        _ = self;
        const data = std.fs.cwd().readFileAlloc(a, path, 64 * 1024 * 1024) catch |e| switch (e) {
            error.FileNotFound => return error.NoFixture,
            else => return e,
        };
        return data;
    }

    /// `owner/repo` and the file name from a GitHub release download URL.
    fn splitDownloadUrl(url: []const u8) ?struct { owner: []const u8, repo: []const u8, file: []const u8 } {
        const prefix = "https://github.com/";
        if (!std.mem.startsWith(u8, url, prefix)) return null;
        var it = std.mem.splitScalar(u8, url[prefix.len..], '/');
        const owner = it.next() orelse return null;
        const repo = it.next() orelse return null;
        const releases = it.next() orelse return null;
        const dl_word = it.next() orelse return null;
        if (!std.mem.eql(u8, releases, "releases") or !std.mem.eql(u8, dl_word, "download")) return null;
        _ = it.next() orelse return null; // tag
        const file = it.rest();
        if (file.len == 0 or std.mem.indexOfScalar(u8, file, '/') != null) return null;
        return .{ .owner = owner, .repo = repo, .file = file };
    }

    fn fixtureAssetPath(self: *Net, a: Allocator, url: []const u8) ![]u8 {
        const parts = splitDownloadUrl(url) orelse return error.NoFixture;
        return self.fixturePath(a, "{s}__{s}/{s}", .{ parts.owner, parts.repo, parts.file });
    }

    // ---- API --------------------------------------------------------------

    /// Body of `GET /repos/{owner}/{repo}/releases/latest` (or `/tags/{tag}`).
    pub fn fetchRelease(self: *Net, a: Allocator, owner: []const u8, repo: []const u8, tag: ?[]const u8) ![]u8 {
        if (self.currentMode() == .fixtures) {
            if (tag) |t| {
                const p = try self.fixturePath(a, "{s}__{s}@{s}.release.json", .{ owner, repo, t });
                if (self.readFixture(a, p)) |d| return d else |_| {}
            }
            const p = try self.fixturePath(a, "{s}__{s}.release.json", .{ owner, repo });
            _ = self.api_calls.fetchAdd(1, .monotonic);
            return self.readFixture(a, p);
        }
        const url = try ghrelease.apiUrl(a, owner, repo, tag);
        return self.apiGet(a, url);
    }

    /// Body of `GET /repos/{owner}/{repo}`.
    pub fn fetchRepo(self: *Net, a: Allocator, owner: []const u8, repo: []const u8) ![]u8 {
        if (self.currentMode() == .fixtures) {
            const p = try self.fixturePath(a, "{s}__{s}.repo.json", .{ owner, repo });
            _ = self.api_calls.fetchAdd(1, .monotonic);
            return self.readFixture(a, p);
        }
        const url = try std.fmt.allocPrint(a, "https://api.github.com/repos/{s}/{s}", .{ owner, repo });
        return self.apiGet(a, url);
    }

    fn apiGet(self: *Net, a: Allocator, url: []const u8) ![]u8 {
        if (self.rate_limited.load(.acquire)) return error.RateLimited;
        _ = self.api_calls.fetchAdd(1, .monotonic);
        return self.withRetry([]u8, a, apiGetOnce, .{url});
    }

    fn apiGetOnce(self: *Net, a: Allocator, url: []const u8) ![]u8 {
        return switch (self.currentMode()) {
            .http => self.httpGet(a, url, true, 64 * 1024 * 1024),
            else => self.curlGet(a, url),
        };
    }

    /// Small text resource (a checksums file). No credentials are sent.
    pub fn fetchText(self: *Net, a: Allocator, url: []const u8, max_bytes: usize) ![]u8 {
        if (!net.isSafeUrl(url)) return error.UnsafeUrl;
        if (self.currentMode() == .fixtures) {
            const p = try self.fixtureAssetPath(a, url);
            return self.readFixture(a, p);
        }
        const body = try self.withRetry([]u8, a, fetchTextOnce, .{ url, max_bytes });
        _ = self.bytes.fetchAdd(body.len, .monotonic);
        return body;
    }

    fn fetchTextOnce(self: *Net, a: Allocator, url: []const u8, max_bytes: usize) ![]u8 {
        return switch (self.currentMode()) {
            .http => self.httpGet(a, url, false, max_bytes),
            else => blk: {
                const body = try self.curlGet(a, url);
                if (body.len > max_bytes) return error.TooLarge;
                break :blk body;
            },
        };
    }

    fn statusToError(self: *Net, code: u16, body: []const u8) !void {
        if (code >= 200 and code < 300) return;
        if (code == 404) return error.NotFound;
        if (code == 403 or code == 429) {
            if (std.ascii.indexOfIgnoreCase(body, "rate limit") != null) {
                self.rate_limited.store(true, .release);
                return error.RateLimited;
            }
            return error.Forbidden;
        }
        if (code >= 500) return error.ServerError;
        return error.BadStatus;
    }

    fn isStatusError(e: anyerror) bool {
        return switch (e) {
            error.NotFound, error.RateLimited, error.Forbidden, error.BadStatus, error.TooLarge, error.NoFixture, error.UnsafeUrl, error.OutOfMemory => true,
            else => false,
        };
    }

    /// Runs `func` up to three times, backing off between tries. A transport
    /// failure from std.http (TLS setup, proxy, DNS) switches the whole run
    /// to curl once, if curl exists.
    fn withRetry(self: *Net, comptime T: type, a: Allocator, comptime func: anytype, args: anytype) !T {
        var attempt: u32 = 0;
        while (true) : (attempt += 1) {
            const result = @call(.auto, func, .{ self, a } ++ args);
            if (result) |v| return v else |e| {
                if (isStatusError(e)) return e;
                if (self.currentMode() == .http and self.curlAvailable()) {
                    self.switchToCurl(e);
                    if (attempt < 3) continue;
                }
                if (attempt >= 2) return e;
                std.time.sleep(@as(u64, 400 * std.time.ns_per_ms) * (attempt + 1));
            }
        }
    }

    fn curlAvailable(self: *Net) bool {
        _ = self;
        const res = std.process.Child.run(.{
            .allocator = std.heap.page_allocator,
            .argv = &.{ "curl", "--version" },
            .max_output_bytes = 4096,
        }) catch return false;
        defer std.heap.page_allocator.free(res.stdout);
        defer std.heap.page_allocator.free(res.stderr);
        return res.term == .Exited and res.term.Exited == 0;
    }

    fn switchToCurl(self: *Net, why: anyerror) void {
        self.switch_mutex.lock();
        defer self.switch_mutex.unlock();
        if (self.currentMode() == .http) {
            std.debug.print("note: std.http failed ({s}); switching to curl for the rest of the run\n", .{@errorName(why)});
            self.mode.store(@intFromEnum(Mode.curl), .release);
        }
    }

    // ---- std.http ---------------------------------------------------------

    fn httpGet(self: *Net, a: Allocator, url: []const u8, api: bool, max_bytes: usize) ![]u8 {
        var body = std.ArrayList(u8).init(a);
        errdefer body.deinit();

        const api_headers = [_]std.http.Header{
            .{ .name = "Accept", .value = "application/vnd.github+json" },
            .{ .name = "X-GitHub-Api-Version", .value = "2022-11-28" },
        };
        var bearer: []const u8 = "";
        if (api) {
            if (self.token) |t| bearer = try std.fmt.allocPrint(a, "Bearer {s}", .{t});
        }
        const auth = [_]std.http.Header{.{ .name = "Authorization", .value = bearer }};

        const res = try self.client.fetch(.{
            .location = .{ .url = url },
            .method = .GET,
            .headers = .{ .user_agent = .{ .override = user_agent } },
            .extra_headers = if (api) &api_headers else &.{},
            .privileged_headers = if (api and bearer.len != 0) &auth else &.{},
            .response_storage = .{ .dynamic = &body },
            .max_append_size = max_bytes,
        });
        try self.statusToError(@intFromEnum(res.status), body.items);
        return body.toOwnedSlice();
    }

    fn httpDownload(self: *Net, url: []const u8, dest: []const u8, max_bytes: u64) !Downloaded {
        const uri = try std.Uri.parse(url);
        var header_buf: [16 * 1024]u8 = undefined;
        var req = try self.client.open(.GET, uri, .{
            .server_header_buffer = &header_buf,
            .headers = .{ .user_agent = .{ .override = user_agent } },
            .redirect_behavior = @enumFromInt(5),
        });
        defer req.deinit();
        try req.send();
        try req.finish();
        try req.wait();
        try self.statusToError(@intFromEnum(req.response.status), "");

        const file = try std.fs.cwd().createFile(dest, .{});
        defer file.close();
        var hasher = Sha256.init(.{});
        var buf: [64 * 1024]u8 = undefined;
        var total: u64 = 0;
        const r = req.reader();
        while (true) {
            const n = try r.read(&buf);
            if (n == 0) break;
            total += n;
            if (total > max_bytes) return error.TooLarge;
            hasher.update(buf[0..n]);
            try file.writeAll(buf[0..n]);
        }
        return .{ .sha256 = std.fmt.bytesToHex(hasher.finalResult(), .lower), .size = total };
    }

    // ---- curl -------------------------------------------------------------

    fn curlGet(self: *Net, a: Allocator, url: []const u8) ![]u8 {
        const hdr_arg = try std.fmt.allocPrint(a, "@{s}", .{self.hdr_path});
        const argv = [_][]const u8{
            "curl",              "-q",             "--silent",   "--show-error",
            "--location",        "--max-redirs",   "5",          "--proto",
            "=https",            "--proto-redir",  "=https",     "--tlsv1.2",
            "--connect-timeout", "20",             "--max-time", "120",
            "--user-agent",      user_agent,       "-H",         hdr_arg,
            "--write-out",       "\n%{http_code}", url,
        };
        // The credentials header file is only for the API; a plain download of
        // a public file must not carry the token.
        const is_api = std.mem.startsWith(u8, url, "https://api.github.com/");
        const real_argv: []const []const u8 = if (is_api) &argv else (argv[0..18] ++ argv[20..]);
        const res = std.process.Child.run(.{
            .allocator = a,
            .argv = real_argv,
            .max_output_bytes = 64 * 1024 * 1024,
        }) catch return error.CurlFailed;
        if (res.term != .Exited or res.term.Exited != 0) return error.CurlFailed;
        const nl = std.mem.lastIndexOfScalar(u8, res.stdout, '\n') orelse return error.CurlFailed;
        const code = std.fmt.parseInt(u16, std.mem.trim(u8, res.stdout[nl + 1 ..], " \r\n"), 10) catch return error.CurlFailed;
        const body = res.stdout[0..nl];
        try self.statusToError(code, body);
        return body;
    }

    // ---- downloads --------------------------------------------------------

    pub const Downloaded = struct { sha256: [64]u8, size: u64 };

    /// Fetches `url` into `dest` and returns its SHA-256 and size.
    pub fn download(self: *Net, a: Allocator, url: []const u8, dest: []const u8, max_bytes: u64) !Downloaded {
        if (!net.isSafeUrl(url)) return error.UnsafeUrl;
        const got = switch (self.currentMode()) {
            .fixtures => try self.copyFixture(a, url, dest),
            else => try self.downloadWithFallback(a, url, dest, max_bytes),
        };
        _ = self.bytes.fetchAdd(got.size, .monotonic);
        return got;
    }

    fn copyFixture(self: *Net, a: Allocator, url: []const u8, dest: []const u8) !Downloaded {
        const src = try self.fixtureAssetPath(a, url);
        std.fs.cwd().copyFile(src, std.fs.cwd(), dest, .{}) catch |e| switch (e) {
            error.FileNotFound => return error.NoFixture,
            else => return e,
        };
        return hashFile(dest);
    }

    fn downloadWithFallback(self: *Net, a: Allocator, url: []const u8, dest: []const u8, max_bytes: u64) !Downloaded {
        var attempt: u32 = 0;
        while (true) : (attempt += 1) {
            const r: anyerror!Downloaded = switch (self.currentMode()) {
                .http => self.httpDownload(url, dest, max_bytes),
                else => self.curlDownload(a, url, dest),
            };
            if (r) |v| return v else |e| {
                std.fs.cwd().deleteFile(dest) catch {};
                if (isStatusError(e)) return e;
                if (self.currentMode() == .http and self.curlAvailable()) {
                    self.switchToCurl(e);
                    if (attempt < 3) continue;
                }
                if (attempt >= 2) return e;
                std.time.sleep(@as(u64, 600 * std.time.ns_per_ms) * (attempt + 1));
            }
        }
    }

    fn curlDownload(self: *Net, a: Allocator, url: []const u8, dest: []const u8) !Downloaded {
        _ = self;
        net.download(a, url, dest, .{ .user_agent = user_agent, .max_time_s = 900 }) catch |e| switch (e) {
            error.DownloadFailed => return error.CurlFailed,
            else => return e,
        };
        return hashFile(dest);
    }
};

fn hashFile(path: []const u8) !Net.Downloaded {
    const f = try std.fs.cwd().openFile(path, .{});
    defer f.close();
    var hasher = Sha256.init(.{});
    var buf: [64 * 1024]u8 = undefined;
    var total: u64 = 0;
    while (true) {
        const n = try f.read(&buf);
        if (n == 0) break;
        total += n;
        hasher.update(buf[0..n]);
    }
    return .{ .sha256 = std.fmt.bytesToHex(hasher.finalResult(), .lower), .size = total };
}

// ---------------------------------------------------------------------------
// Repository metadata
// ---------------------------------------------------------------------------

pub const RepoInfo = struct {
    description: []const u8 = "",
    license: []const u8 = "",
    homepage: []const u8 = "",
};

/// Collapses whitespace and control characters, trims, and cuts at
/// `max_description_len` bytes on a UTF-8 boundary.
fn cleanText(a: Allocator, s: []const u8, max_len: usize) ![]u8 {
    var out = std.ArrayList(u8).init(a);
    var pending_space = false;
    for (s) |c| {
        if (c <= 0x20 or c == 0x7f) {
            pending_space = out.items.len != 0;
            continue;
        }
        if (pending_space) {
            try out.append(' ');
            pending_space = false;
        }
        try out.append(c);
    }
    if (out.items.len > max_len) {
        var cut = max_len;
        while (cut > 0 and (out.items[cut] & 0xC0) == 0x80) cut -= 1;
        out.shrinkRetainingCapacity(cut);
        while (out.items.len > 0 and out.items[out.items.len - 1] == ' ') _ = out.pop();
    }
    return out.toOwnedSlice();
}

fn validLicense(s: []const u8) bool {
    if (s.len == 0 or s.len > 64) return false;
    for (s) |c| {
        const ok = std.ascii.isAlphanumeric(c) or c == '.' or c == '+' or c == '-' or c == '/' or c == '(' or c == ')' or c == ' ';
        if (!ok) return false;
    }
    return true;
}

/// Reads `description`, `license.spdx_id`, `homepage` (else `html_url`) from a
/// repository record. Missing or odd fields become empty strings or the
/// repository URL, never errors, except for a body that is not a repo record.
pub fn parseRepoInfo(a: Allocator, json: []const u8, owner: []const u8, repo: []const u8) !RepoInfo {
    const root = try std.json.parseFromSliceLeaky(std.json.Value, a, json, .{});
    const obj = switch (root) {
        .object => |o| o,
        else => return error.MalformedRepo,
    };
    if (obj.get("full_name") == null and obj.get("html_url") == null) return error.MalformedRepo;

    var info = RepoInfo{};
    if (obj.get("description")) |d| switch (d) {
        .string => |s| info.description = try cleanText(a, s, max_description_len),
        else => {},
    };
    if (obj.get("license")) |l| switch (l) {
        .object => |lo| {
            const id = jsonStr(lo, "spdx_id");
            if (!std.mem.eql(u8, id, "NOASSERTION") and validLicense(id)) info.license = id;
        },
        else => {},
    };
    const fallback = try std.fmt.allocPrint(a, "https://github.com/{s}/{s}", .{ owner, repo });
    info.homepage = fallback;
    if (obj.get("homepage")) |h| switch (h) {
        .string => |s| {
            const t = std.mem.trim(u8, s, " \t\r\n");
            if (net.isSafeUrl(t)) info.homepage = t;
        },
        else => {},
    };
    return info;
}

// ---------------------------------------------------------------------------
// The per-package pipeline
// ---------------------------------------------------------------------------

pub const Options = struct {
    sources_path: []const u8,
    out_path: []const u8,
    previous_path: ?[]const u8 = null,
    manual_path: ?[]const u8 = null,
    only: []const []const u8 = &.{},
    fixtures_dir: ?[]const u8 = null,
    use_curl: bool = false,
    jobs: usize = default_jobs,
    force: bool = false,
    allow_shrink: bool = false,
    allow_failures: bool = false,
    max_download_bytes: u64 = default_max_download_bytes,
    /// Overrides the clock (seconds since the epoch); SOURCE_DATE_EPOCH sets it.
    now_epoch: ?i64 = null,
    token: ?[]const u8 = null,
    quiet: bool = false,
    /// Markdown report (counts and failures with reasons) for a CI summary page.
    summary_path: ?[]const u8 = null,
};

const Status = enum { new, updated, kept, stale, skipped, carried, not_selected };

const Result = struct {
    status: Status = .skipped,
    entry: ?Entry = null,
    note: []const u8 = "",
};

const Outcome = union(enum) {
    built: Entry,
    reuse,
    fail: []const u8,
};

fn failf(a: Allocator, comptime fmt: []const u8, args: anytype) Outcome {
    return .{ .fail = std.fmt.allocPrint(a, fmt, args) catch "out of memory" };
}

const Ctx = struct {
    gpa: Allocator,
    opts: Options,
    net: *Net,
    sources: []const Source,
    prev: *const std.StringHashMap(Entry),
    only: ?*const std.StringHashMap(void),
    results: []Result,
    arenas: []std.heap.ArenaAllocator,
    tmp_root: []const u8,
    done: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
};

const Local = struct { asset: usize, path: []const u8, sha: [64]u8 };

fn findAssetNamed(assets: []const ghrelease.Asset, want: []const u8) ?usize {
    // An exact name wins; otherwise the shortest name containing the text.
    var best: ?usize = null;
    for (assets, 0..) |asset, i| {
        if (std.mem.eql(u8, asset.name, want)) return i;
        if (std.mem.indexOf(u8, asset.name, want) == null) continue;
        if (ghrelease.archiveKindOf(asset.name) == null) continue;
        if (best == null or asset.name.len < assets[best.?].name.len) best = i;
    }
    return best;
}

fn makeTmpDir(a: Allocator, root: []const u8, name: []const u8) ![]u8 {
    const p = try std.fs.path.join(a, &.{ root, name });
    std.fs.cwd().deleteTree(p) catch {};
    try std.fs.cwd().makePath(p);
    return p;
}

fn ensureLocal(
    ctx: *Ctx,
    a: Allocator,
    assets: []const ghrelease.Asset,
    idx: usize,
    tmp_dir: []const u8,
    locals: *std.ArrayList(Local),
) !*const Local {
    for (locals.items) |*l| {
        if (l.asset == idx) return l;
    }
    const asset = assets[idx];
    if (asset.size > ctx.opts.max_download_bytes) return error.TooLarge;
    const path = try std.fmt.allocPrint(a, "{s}{c}dl{d}", .{ tmp_dir, std.fs.path.sep, idx });
    const got = try ctx.net.download(a, asset.url, path, ctx.opts.max_download_bytes);
    try locals.append(.{ .asset = idx, .path = path, .sha = got.sha256 });
    return &locals.items[locals.items.len - 1];
}

const Picked = struct {
    plat: usize,
    asset: usize,
    sha: [64]u8,
};

fn buildEntry(ctx: *Ctx, a: Allocator, src: Source, prev: ?Entry, index: usize) !Outcome {
    const opts = ctx.opts;

    if (!opts.force and src.tag != null and prev != null) {
        if (versionFromTag(src.tag.?)) |v| {
            if (std.mem.eql(u8, v, prev.?.version)) return .reuse;
        }
    }

    const rel_json = ctx.net.fetchRelease(a, src.owner, src.repo, src.tag) catch |e|
        return failf(a, "release lookup failed: {s}", .{netErrorName(e)});
    const rel = ghrelease.parseRelease(a, rel_json) catch |e|
        return failf(a, "unreadable release data: {s}", .{@errorName(e)});
    const version = versionFromTag(rel.tag) orelse
        return failf(a, "tag '{s}' does not give a valid version", .{rel.tag});

    if (!opts.force) {
        if (prev) |p| {
            if (std.mem.eql(u8, p.version, version)) return .reuse;
        }
    }

    const tmp_dir = try makeTmpDir(a, ctx.tmp_root, try std.fmt.allocPrint(a, "t{d}", .{index}));
    defer std.fs.cwd().deleteTree(tmp_dir) catch {};

    // ---- 1. one asset per platform -----------------------------------------
    var pick: [6]?usize = .{null} ** 6;
    var notes = std.ArrayList(u8).init(a);
    for (platform_tags, 0..) |tag, i| {
        if (src.skip[i]) continue;
        if (src.kind == .app) {
            // An app source publishes macOS bundles only.
            if (osOfPlatform(i) != .macos) continue;
            const found = if (src.assets[i]) |want| findAssetNamed(rel.assets, want) else pickAppAsset(rel.assets, tag, src.apps.len != 0);
            const chosen = found orelse {
                try notes.writer().print("{s}: no .dmg or .zip for this Mac; ", .{tag});
                continue;
            };
            const akind = ghrelease.archiveKindOf(rel.assets[chosen].name) orelse "";
            if (!std.mem.eql(u8, akind, "dmg") and !std.mem.eql(u8, akind, "zip")) {
                try notes.writer().print("{s}: {s} is not a .dmg or .zip; ", .{ tag, rel.assets[chosen].name });
                continue;
            }
            if (std.mem.eql(u8, akind, "dmg") and src.apps.len == 0) {
                try notes.writer().print("{s}: {s} is a .dmg, so the line needs app=Name.app; ", .{ tag, rel.assets[chosen].name });
                continue;
            }
            pick[i] = chosen;
            continue;
        }
        const idx = if (src.assets[i]) |want| findAssetNamed(rel.assets, want) else ghrelease.pickAsset(rel.assets, tag);
        const chosen = idx orelse continue;
        const kind = ghrelease.archiveKindOf(rel.assets[chosen].name) orelse continue;
        if (std.mem.eql(u8, kind, "dmg")) continue; // cannot be unpacked off macOS
        pick[i] = chosen;
    }
    var n_picked: usize = 0;
    for (pick) |p| {
        if (p != null) n_picked += 1;
    }
    if (n_picked == 0) return failf(a, "no usable asset for any platform ({d} assets in {s}) {s}", .{ rel.assets.len, rel.tag, notes.items });

    // ---- 2. checksums ------------------------------------------------------
    var locals = std.ArrayList(Local).init(a);
    var shas: [6]?[64]u8 = .{null} ** 6;
    var missing: usize = 0;
    for (pick, 0..) |p, i| {
        const idx = p orelse continue;
        if (rel.assets[idx].sha256) |s| {
            shas[i] = s;
        } else missing += 1;
    }

    if (missing > 0) {
        // A checksum file in the release: one made for the asset
        // (`<asset>.sha256`) or a list (`SHA256SUMS`). The same rules abv0's
        // own `install gh:` applies. Each file is fetched at most once.
        var texts = std.AutoHashMap(usize, ?[]const u8).init(a);
        for (pick, 0..) |p, i| {
            const idx = p orelse continue;
            if (shas[i] != null) continue;
            const name = rel.assets[idx].name;
            const cands = try ghverify.checksumCandidates(a, rel.assets, idx);
            for (cands) |ci| {
                const slot = try texts.getOrPut(ci);
                if (!slot.found_existing) {
                    slot.value_ptr.* = ctx.net.fetchText(a, rel.assets[ci].url, max_checksum_bytes) catch null;
                }
                const text = slot.value_ptr.* orelse continue;
                if (ghverify.findChecksum(text, name, ghverify.isDedicated(name, rel.assets[ci].name))) |h| {
                    shas[i] = h;
                    break;
                }
            }
        }
        // Last resort: hash the file ourselves.
        for (pick, 0..) |p, i| {
            const idx = p orelse continue;
            if (shas[i] != null) continue;
            const l = ensureLocal(ctx, a, rel.assets, idx, tmp_dir, &locals) catch |e| {
                try notes.writer().print("{s}: no checksum and download failed ({s}); ", .{ platform_tags[i], netErrorName(e) });
                pick[i] = null;
                continue;
            };
            shas[i] = l.sha;
        }
    }

    // A platform without a hash is dropped, never published unpinned.
    n_picked = 0;
    for (pick) |p| {
        if (p != null) n_picked += 1;
    }
    if (n_picked == 0) return failf(a, "no platform could be pinned: {s}", .{notes.items});

    // An application bundle is linked as it is: nothing to detect.
    if (src.kind == .app) return buildApp(ctx, a, src, rel, version, &pick, shas, &locals, tmp_dir, &notes);

    // ---- 3. executables ----------------------------------------------------
    const Detected = struct {
        plat: usize,
        asset: usize,
        raw: bool,
        bins: []bindetect.Bin,
    };
    var detected: ?Detected = null;
    var detect_error: []const u8 = "no asset could be unpacked";

    // Prefer an asset that is already on disk, then the usual order.
    var order = std.ArrayList(usize).init(a);
    for (detect_order) |pi| {
        if (pick[pi]) |idx| {
            for (locals.items) |l| {
                if (l.asset == idx) {
                    try order.append(pi);
                    break;
                }
            }
        }
    }
    for (detect_order) |pi| {
        if (pick[pi] != null) {
            var present = false;
            for (order.items) |o| {
                if (o == pi) present = true;
            }
            if (!present) try order.append(pi);
        }
    }

    var attempts: usize = 0;
    for (order.items) |pi| {
        if (attempts >= 3) break;
        const idx = pick[pi].?;
        const asset = rel.assets[idx];
        const kind_str = ghrelease.archiveKindOf(asset.name).?;
        attempts += 1;

        if (std.mem.eql(u8, kind_str, "raw")) {
            // A bare executable: nothing to unpack. Its name is the project's.
            const nm = if (src.bin.len > 0) src.bin[0] else if (registry.isUsableBinName(src.repo)) src.repo else src.name;
            const one = try a.alloc(bindetect.Bin, 1);
            one[0] = .{ .path = nm, .name = nm };
            detected = .{ .plat = pi, .asset = idx, .raw = true, .bins = one };
            break;
        }

        const l = ensureLocal(ctx, a, rel.assets, idx, tmp_dir, &locals) catch |e| {
            detect_error = try std.fmt.allocPrint(a, "download of {s} failed: {s}", .{ asset.name, netErrorName(e) });
            continue;
        };
        if (!std.mem.eql(u8, &l.sha, &(shas[pi].?))) {
            return failf(a, "{s}: downloaded file does not match its published SHA-256", .{asset.name});
        }

        const x_dir = try makeTmpDir(a, tmp_dir, try std.fmt.allocPrint(a, "x{d}", .{pi}));
        const kind = archive.Kind.fromString(kind_str).?;
        archive.extract(a, kind, l.path, x_dir, .{}) catch |e| {
            detect_error = try std.fmt.allocPrint(a, "cannot unpack {s}: {s}", .{ asset.name, @errorName(e) });
            continue;
        };
        var root = try std.fs.cwd().openDir(x_dir, .{ .iterate = true });
        defer root.close();
        const found = try bindetect.findExecutables(a, root, stdOs(osOfPlatform(pi)));
        if (found.len == 0) {
            detect_error = try std.fmt.allocPrint(a, "no executables found in {s}", .{asset.name});
            continue;
        }
        detected = .{ .plat = pi, .asset = idx, .raw = false, .bins = found };
        break;
    }

    // ---- 4. bin names and per-platform bin_path ----------------------------
    var names = std.ArrayList([]const u8).init(a);
    var primary_rel: []const u8 = "";
    var renamed = false;
    var det_stem: []const u8 = "";
    var have_layout = false;

    if (detected) |d| {
        det_stem = assetStem(rel.assets[d.asset].name);
        bindetect.rank(d.bins, src.repo);
        if (src.bin.len > 0) {
            var primary: ?bindetect.Bin = null;
            for (d.bins) |b| {
                if (std.mem.eql(u8, b.name, src.bin[0])) {
                    primary = b;
                    break;
                }
            }
            if (primary == null) {
                if (d.bins.len == 1 or d.raw) {
                    primary = d.bins[0];
                    renamed = !d.raw;
                } else {
                    var found = std.ArrayList(u8).init(a);
                    for (d.bins, 0..) |b, i| {
                        if (i != 0) try found.appendSlice(", ");
                        try found.appendSlice(b.name);
                    }
                    return failf(a, "bin={s} not found in {s} (found: {s})", .{ src.bin[0], rel.assets[d.asset].name, found.items });
                }
            }
            primary_rel = primary.?.path;
            try names.appendSlice(src.bin);
            have_layout = true;
        } else {
            for (d.bins) |b| {
                if (names.items.len >= max_bins) break;
                if (!registry.isUsableBinName(b.name)) continue;
                var dup = false;
                for (names.items) |n| {
                    if (std.mem.eql(u8, n, b.name)) dup = true;
                }
                if (!dup) try names.append(b.name);
            }
            if (names.items.len == 0) return failf(a, "executables in {s} have unusable names", .{rel.assets[d.asset].name});
            // First usable one is the primary.
            for (d.bins) |b| {
                if (std.mem.eql(u8, b.name, names.items[0])) {
                    primary_rel = b.path;
                    break;
                }
            }
            if (d.bins.len == 1 and !d.raw) {
                const nice = normalizeBinName(names.items[0], src.repo);
                if (!std.mem.eql(u8, nice, names.items[0]) and registry.isUsableBinName(nice)) {
                    names.items[0] = nice;
                    renamed = true;
                }
            }
            have_layout = true;
        }
    } else if (src.bin.len > 0) {
        try names.appendSlice(src.bin);
    } else {
        return failf(a, "cannot detect executables: {s}", .{detect_error});
    }

    var plats = std.ArrayList(PlatEntry).init(a);
    for (platform_tags, 0..) |tag, pi| {
        const idx = pick[pi] orelse continue;
        const asset = rel.assets[idx];
        const kind = ghrelease.archiveKindOf(asset.name).?;
        const is_raw = std.mem.eql(u8, kind, "raw");

        const bin_path: []const u8 = blk: {
            if (!have_layout) {
                // No unpacked sample: name the executable and let abv0 walk.
                const exe = if (osOfPlatform(pi) == .windows) ".exe" else "";
                break :blk try std.fmt.allocPrint(a, "{s}{s}", .{ names.items[0], exe });
            }
            const maybe = try binPathFor(a, .{
                .primary_rel = primary_rel,
                .detected_stem = det_stem,
                .bin_name = names.items[0],
                .renamed = renamed,
                .version = version,
            }, asset.name, osOfPlatform(pi), is_raw);
            break :blk maybe orelse {
                try notes.writer().print("{s}: executable name differs per platform; ", .{tag});
                continue;
            };
        };
        const sha = shas[pi].?;
        try plats.append(.{
            .tag = tag,
            .url = asset.url,
            .sha256 = try a.dupe(u8, &sha),
            .archive_type = kind,
            .bin_path = bin_path,
        });
    }
    if (plats.items.len == 0) return failf(a, "no platform left after layout checks: {s}", .{notes.items});

    return finishEntry(ctx, a, src, version, try names.toOwnedSlice(), &.{}, try plats.toOwnedSlice());
}

/// Step 5, shared by both kinds: description, license and homepage from the
/// repository record, then the entry itself, checked against the registry's rules.
fn finishEntry(
    ctx: *Ctx,
    a: Allocator,
    src: Source,
    version: []const u8,
    bin: []const []const u8,
    apps: []const []const u8,
    plats: []const PlatEntry,
) !Outcome {
    const repo_json = ctx.net.fetchRepo(a, src.owner, src.repo) catch |e|
        return failf(a, "repository lookup failed: {s}", .{netErrorName(e)});
    const info = parseRepoInfo(a, repo_json, src.owner, src.repo) catch |e|
        return failf(a, "unreadable repository data: {s}", .{@errorName(e)});

    var description: []const u8 = info.description;
    if (src.desc) |d| description = try cleanText(a, d, max_description_len);
    if (description.len == 0) description = try std.fmt.allocPrint(a, "{s} (github.com/{s}/{s})", .{ src.name, src.owner, src.repo });
    var license: []const u8 = info.license;
    if (src.license) |l| license = if (validLicense(l)) l else "";

    const entry = Entry{
        .name = src.name,
        .version = version,
        .description = description,
        .homepage = info.homepage,
        .license = license,
        .bin = bin,
        .app_bundles = apps,
        .plats = plats,
    };
    if (validateEntry(entry)) |why| return failf(a, "invalid entry: {s}", .{why});
    return .{ .built = entry };
}

// ---------------------------------------------------------------------------
// macOS application bundles (GUI apps)
// ---------------------------------------------------------------------------

/// Words that mark a .dmg or .zip as something other than the Mac app itself.
const app_reject_tokens = [_][]const u8{
    "linux",   "windows",  "win",       "win32",   "win64",    "ios",   "ipados", "tvos",
    "android", "freebsd",  "appimage",  "exe",     "msi",      "deb",   "rpm",    "snap",
    "flatpak", "src",      "source",    "sources", "debug",    "dsym",  "dsyms",  "symbols",
    "sbom",    "checksum", "checksums", "sha256",  "blockmap", "delta", "deltas", "sparkle",
};
const app_mac_tokens = [_][]const u8{ "mac", "macos", "darwin", "osx", "apple" };
const app_arm_hints = [_][]const u8{ "arm64", "aarch64", "apple-silicon", "apple_silicon", "applesilicon", "silicon" };
const app_x86_hints = [_][]const u8{ "x86_64", "x86-64", "x64", "amd64", "intel", "x86" };

fn hasWord(name: []const u8, words: []const []const u8) bool {
    var it = std.mem.tokenizeAny(u8, name, "-_. +()[]");
    while (it.next()) |t| {
        for (words) |w| {
            if (std.ascii.eqlIgnoreCase(t, w)) return true;
        }
    }
    return false;
}

fn hasSubstring(name: []const u8, needles: []const []const u8) bool {
    for (needles) |n| {
        if (std.ascii.indexOfIgnoreCase(name, n) != null) return true;
    }
    return false;
}

/// The release asset that installs the app on the Mac `platform_tag` names, or
/// null. Only .dmg and .zip files count. An asset for the other architecture,
/// or for another system, never does; one that names no architecture (or says
/// `universal`) fits both. With `know_app` (the line has `app=`) a .dmg is
/// preferred, because abv0 unpacks it with the system and keeps symlinks and
/// permissions; without it a .zip is, because its bundle name can be read.
pub fn pickAppAsset(assets: []const ghrelease.Asset, platform_tag: []const u8, know_app: bool) ?usize {
    const want_arm = std.mem.startsWith(u8, platform_tag, "aarch64");
    var best: ?usize = null;
    var best_score: u32 = 0;
    for (assets, 0..) |asset, i| {
        const name = asset.name;
        const is_dmg = std.ascii.endsWithIgnoreCase(name, ".dmg");
        if (!is_dmg and !std.ascii.endsWithIgnoreCase(name, ".zip")) continue;
        if (hasWord(name, &app_reject_tokens)) continue;

        const arm = hasSubstring(name, &app_arm_hints);
        const x86 = hasSubstring(name, &app_x86_hints);
        var score: u32 = 50;
        if (std.ascii.indexOfIgnoreCase(name, "universal") != null or (arm and x86)) {
            score = 50;
        } else if (arm) {
            if (!want_arm) continue;
            score = 100;
        } else if (x86) {
            if (want_arm) continue;
            score = 100;
        }
        // The kind of file outranks the architecture: a universal .zip is
        // taken over an Apple-silicon-only .dmg when the bundle name is unknown.
        if (is_dmg == know_app) score += 1000;
        if (hasWord(name, &app_mac_tokens)) score += 2;

        const better = if (best) |b|
            (score > best_score or (score == best_score and name.len < assets[b].name.len))
        else
            true;
        if (better) {
            best = i;
            best_score = score;
        }
    }
    return best;
}

/// The names of the `*.app` directories at the top level of a zip archive,
/// sorted. `seekable` is a `std.io.SeekableStream` over the archive.
pub fn zipTopLevelApps(a: Allocator, seekable: anytype) ![]const []const u8 {
    var iter = try std.zip.Iterator(@TypeOf(seekable)).init(seekable);
    var found = std.ArrayList([]const u8).init(a);
    var name_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    while (try iter.next()) |entry| {
        if (entry.filename_len > name_buf.len) continue;
        const name = name_buf[0..entry.filename_len];
        try iter.stream.seekTo(entry.header_zip_offset + @sizeOf(std.zip.CentralDirectoryFileHeader));
        const got = try iter.stream.context.reader().readAll(name);
        if (got != name.len) return error.ZipTruncated;

        // A bundle is a directory: its name is followed by '/'.
        const slash = std.mem.indexOfScalar(u8, name, '/') orelse continue;
        const top = name[0..slash];
        if (!isUsableAppName(top)) continue;
        var dup = false;
        for (found.items) |f| {
            if (std.mem.eql(u8, f, top)) dup = true;
        }
        if (!dup) try found.append(try a.dupe(u8, top));
    }
    std.mem.sort([]const u8, found.items, {}, struct {
        fn lt(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.order(u8, x, y) == .lt;
        }
    }.lt);
    return found.toOwnedSlice();
}

fn zipAppsOfFile(a: Allocator, path: []const u8) ![]const []const u8 {
    const f = try std.fs.cwd().openFile(path, .{});
    defer f.close();
    return zipTopLevelApps(a, f.seekableStream());
}

fn containsName(list: []const []const u8, want: []const u8) bool {
    for (list) |n| {
        if (std.mem.eql(u8, n, want)) return true;
    }
    return false;
}

/// Entry for an application source. A .zip is downloaded (once) to read the
/// bundle names it holds and to make sure the bundle sits at its top level,
/// which is where abv0 looks for it. A .dmg is taken on the line's word.
fn buildApp(
    ctx: *Ctx,
    a: Allocator,
    src: Source,
    rel: ghrelease.Release,
    version: []const u8,
    pick: *[6]?usize,
    shas: [6]?[64]u8,
    locals: *std.ArrayList(Local),
    tmp_dir: []const u8,
    notes: *std.ArrayList(u8),
) !Outcome {
    var apps: []const []const u8 = src.apps;

    for (pick, 0..) |p, pi| {
        const idx = p orelse continue;
        const asset = rel.assets[idx];
        const kind = ghrelease.archiveKindOf(asset.name).?;
        if (!std.mem.eql(u8, kind, "zip")) continue;
        var on_disk = false;
        for (locals.items) |l| {
            if (l.asset == idx) on_disk = true;
        }
        // With app= and no copy on disk, the line's word is enough.
        if (apps.len != 0 and !on_disk) continue;

        const l = ensureLocal(ctx, a, rel.assets, idx, tmp_dir, locals) catch |e| {
            try notes.writer().print("{s}: cannot download {s} to read its app ({s}); ", .{ platform_tags[pi], asset.name, netErrorName(e) });
            pick[pi] = null;
            continue;
        };
        if (!std.mem.eql(u8, &l.sha, &(shas[pi].?))) {
            return failf(a, "{s}: downloaded file does not match its published SHA-256", .{asset.name});
        }
        const listed = zipAppsOfFile(a, l.path) catch |e| {
            try notes.writer().print("{s}: cannot read {s} ({s}); ", .{ platform_tags[pi], asset.name, @errorName(e) });
            pick[pi] = null;
            continue;
        };
        if (listed.len == 0) {
            try notes.writer().print("{s}: {s} has no .app at its top level; ", .{ platform_tags[pi], asset.name });
            pick[pi] = null;
            continue;
        }
        if (apps.len == 0) {
            apps = listed;
        } else for (apps) |want| {
            if (!containsName(listed, want)) {
                try notes.writer().print("{s}: {s} has no top-level {s}; ", .{ platform_tags[pi], asset.name, want });
                pick[pi] = null;
                break;
            }
        }
    }

    var plats = std.ArrayList(PlatEntry).init(a);
    for (pick, 0..) |p, pi| {
        const idx = p orelse continue;
        const asset = rel.assets[idx];
        try plats.append(.{
            .tag = platform_tags[pi],
            .url = asset.url,
            .sha256 = try a.dupe(u8, &(shas[pi].?)),
            .archive_type = ghrelease.archiveKindOf(asset.name).?,
            .bin_path = "",
        });
    }
    if (plats.items.len == 0 or apps.len == 0) return failf(a, "no installable app bundle: {s}", .{notes.items});
    return finishEntry(ctx, a, src, version, &.{}, apps, try plats.toOwnedSlice());
}

fn processSource(ctx: *Ctx, a: Allocator, res: Allocator, i: usize) Result {
    const src = ctx.sources[i];
    const prev: ?Entry = ctx.prev.get(src.name);

    if (ctx.only) |only| {
        if (!only.contains(src.name)) {
            if (prev) |p| return .{ .status = .carried, .entry = p, .note = "not selected" };
            return .{ .status = .not_selected };
        }
    }

    const outcome = buildEntry(ctx, a, src, prev, i) catch |e|
        failf(a, "unexpected error: {s}", .{@errorName(e)});

    switch (outcome) {
        .reuse => return .{ .status = .kept, .entry = prev.?, .note = "unchanged" },
        .built => |e| {
            const cloned = cloneEntry(res, e) catch @panic("out of memory");
            const note: []const u8 = if (prev) |p|
                std.fmt.allocPrint(res, "was {s}", .{p.version}) catch ""
            else
                "";
            return .{ .status = if (prev == null) .new else .updated, .entry = cloned, .note = note };
        },
        .fail => |msg| {
            const m = res.dupe(u8, msg) catch "failed";
            if (prev) |p| return .{ .status = .stale, .entry = p, .note = m };
            return .{ .status = .skipped, .note = m };
        },
    }
}

fn runTask(ctx: *Ctx, i: usize) void {
    var scratch = std.heap.ArenaAllocator.init(ctx.gpa);
    defer scratch.deinit();
    ctx.results[i] = processSource(ctx, scratch.allocator(), ctx.arenas[i].allocator(), i);
    const n = ctx.done.fetchAdd(1, .monotonic) + 1;
    const shown = ctx.results[i].status != .not_selected and
        ctx.results[i].status != .carried;
    if (!ctx.opts.quiet and shown) {
        const r = ctx.results[i];
        std.debug.print("[{d:>3}/{d}] {s:<22} {s}{s}{s}\n", .{
            n,
            ctx.sources.len,
            ctx.sources[i].name,
            @tagName(r.status),
            if (r.note.len != 0) " - " else "",
            r.note,
        });
    }
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

pub const Report = struct {
    packages: usize = 0,
    new: usize = 0,
    updated: usize = 0,
    kept: usize = 0,
    carried: usize = 0,
    stale: usize = 0,
    skipped: usize = 0,
    manual: usize = 0,
    api_calls: usize = 0,
    bytes: u64 = 0,
    changed: bool = false,
};

pub fn formatUtc(buf: *[20]u8, epoch: i64) []const u8 {
    const secs: u64 = if (epoch < 0) 0 else @intCast(epoch);
    const es = std.time.epoch.EpochSeconds{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year,
        md.month.numeric(),
        md.day_index + 1,
        ds.getHoursIntoDay(),
        ds.getMinutesIntoHour(),
        ds.getSecondsIntoMinute(),
    }) catch unreachable;
}

fn readOptional(arena: Allocator, path: []const u8) !?[]u8 {
    return std.fs.cwd().readFileAlloc(arena, path, 32 * 1024 * 1024) catch |e| switch (e) {
        error.FileNotFound => null,
        else => e,
    };
}

fn tempRoot(arena: Allocator) ![]u8 {
    const base = std.process.getEnvVarOwned(arena, "RUNNER_TEMP") catch
        std.process.getEnvVarOwned(arena, "TMPDIR") catch
        std.process.getEnvVarOwned(arena, "TEMP") catch
        try arena.dupe(u8, if (builtin.os.tag == .windows) "." else "/tmp");
    const name = try std.fmt.allocPrint(arena, "abv0-catalog-{x}", .{std.crypto.random.int(u64)});
    const p = try std.fs.path.join(arena, &.{ base, name });
    try std.fs.cwd().makePath(p);
    return p;
}

const status_order = [_]Status{ .new, .updated, .stale, .skipped, .kept };

pub fn execute(gpa: Allocator, opts: Options, out: anytype) !Report {
    var timer = try std.time.Timer.start();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const text = std.fs.cwd().readFileAlloc(arena, opts.sources_path, 8 * 1024 * 1024) catch |e| {
        try out.print("error: cannot read {s}: {s}\n", .{ opts.sources_path, @errorName(e) });
        return e;
    };
    const parsed = try parseSources(arena, text);
    for (parsed.problems) |p| try out.print("warning: {s}:{d}: {s}\n", .{ opts.sources_path, p.line, p.text });

    // Previous catalog, for incremental reuse and for keeping updated_at stable.
    var prev_loaded = Loaded{ .entries = std.StringHashMap(Entry).init(arena) };
    var prev_bytes: ?[]u8 = null;
    if (opts.previous_path) |pp| {
        if (try readOptional(arena, pp)) |bytes| {
            prev_bytes = bytes;
            if (loadEntries(arena, bytes)) |l| {
                prev_loaded = l;
                if (l.skipped != 0) try out.print("note: {d} entries of {s} were invalid and will be rebuilt\n", .{ l.skipped, pp });
            } else |e| try out.print("warning: cannot use {s} ({s}); building everything\n", .{ pp, @errorName(e) });
        } else try out.print("note: {s} does not exist; building everything\n", .{pp});
    }

    // Hand-written entries for software that is not distributed through
    // GitHub releases. They are copied through unchanged and win over a source.
    var manual = std.StringHashMap(Entry).init(arena);
    if (opts.manual_path) |mp| {
        if (try readOptional(arena, mp)) |bytes| {
            const l = try loadEntries(arena, bytes);
            manual = l.entries;
            if (l.skipped != 0) try out.print("warning: {d} entries of {s} are invalid and were ignored\n", .{ l.skipped, mp });
        }
    }

    var only_set = std.StringHashMap(void).init(arena);
    for (opts.only) |n| try only_set.put(n, {});

    const tmp_root = try tempRoot(arena);
    defer std.fs.cwd().deleteTree(tmp_root) catch {};

    const mode: Mode = if (opts.fixtures_dir != null) .fixtures else if (opts.use_curl) .curl else .http;
    var network = try Net.init(arena, gpa, mode, opts.token, opts.fixtures_dir, tmp_root);
    defer network.deinit();

    const results = try arena.alloc(Result, parsed.sources.len);
    @memset(results, .{});
    const arenas = try arena.alloc(std.heap.ArenaAllocator, parsed.sources.len);
    for (arenas) |*x| x.* = std.heap.ArenaAllocator.init(gpa);
    defer for (arenas) |*x| x.deinit();

    var ctx = Ctx{
        .gpa = gpa,
        .opts = opts,
        .net = &network,
        .sources = parsed.sources,
        .prev = &prev_loaded.entries,
        .only = if (opts.only.len != 0) &only_set else null,
        .results = results,
        .arenas = arenas,
        .tmp_root = tmp_root,
    };

    if (opts.jobs <= 1 or parsed.sources.len <= 1) {
        for (0..parsed.sources.len) |i| runTask(&ctx, i);
    } else {
        var pool: std.Thread.Pool = undefined;
        try pool.init(.{ .allocator = gpa, .n_jobs = @intCast(@min(opts.jobs, parsed.sources.len)) });
        defer pool.deinit();
        var wg: std.Thread.WaitGroup = .{};
        for (0..parsed.sources.len) |i| pool.spawnWg(&wg, runTask, .{ &ctx, i });
        wg.wait();
    }

    // ---- assemble ----------------------------------------------------------
    var report = Report{};
    var entries = std.ArrayList(Entry).init(arena);
    var in_sources = std.StringHashMap(void).init(arena);
    for (parsed.sources, results) |src, r| {
        try in_sources.put(src.name, {});
        switch (r.status) {
            .new => report.new += 1,
            .updated => report.updated += 1,
            .kept => report.kept += 1,
            .stale => report.stale += 1,
            .skipped => report.skipped += 1,
            .carried => report.carried += 1,
            .not_selected => {},
        }
        if (manual.contains(src.name)) continue;
        if (r.entry) |e| try entries.append(e);
    }
    var mit = manual.valueIterator();
    while (mit.next()) |e| {
        try entries.append(e.*);
        report.manual += 1;
    }

    try printSummary(out, parsed.sources, results, opts.only.len != 0);

    var removed = std.ArrayList([]const u8).init(arena);
    var pit = prev_loaded.entries.keyIterator();
    while (pit.next()) |k| {
        if (!in_sources.contains(k.*) and !manual.contains(k.*)) try removed.append(k.*);
    }
    std.mem.sort([]const u8, removed.items, {}, struct {
        fn lt(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.order(u8, x, y) == .lt;
        }
    }.lt);
    if (removed.items.len != 0) {
        try out.print("removed (no longer in sources): ", .{});
        for (removed.items, 0..) |n, i| try out.print("{s}{s}", .{ if (i != 0) ", " else "", n });
        try out.print("\n", .{});
    }

    report.packages = entries.items.len;
    report.api_calls = network.api_calls.load(.monotonic);
    report.bytes = network.bytes.load(.monotonic);

    // Written before the guards, so a run that refuses to publish still says why.
    if (opts.summary_path) |sp| {
        var md = std.ArrayList(u8).init(arena);
        const fetch_secs = @as(f64, @floatFromInt(timer.read())) / 1e9;
        writeSummaryMarkdown(md.writer(), entries.items, parsed.sources, results, report, fetch_secs, opts.jobs) catch {};
        std.fs.cwd().writeFile(.{ .sub_path = sp, .data = md.items }) catch |e| {
            try out.print("warning: cannot write {s}: {s}\n", .{ sp, @errorName(e) });
        };
    }

    // ---- guards: never publish an empty or collapsed catalog ---------------
    if (entries.items.len == 0) {
        try out.print("error: no packages were produced; leaving {s} untouched\n", .{opts.out_path});
        return error.EmptyCatalog;
    }
    // A network outage or an exhausted rate limit fails nearly every source.
    // The old entries would survive as "stale", but a green run that updated
    // nothing would hide the problem, so it is an error instead.
    const attempted = report.new + report.updated + report.kept + report.stale + report.skipped;
    if (!opts.allow_failures and attempted >= 10 and (report.stale + report.skipped) * 2 > attempted) {
        try out.print("error: {d} of {d} sources failed (network, rate limit?); not writing {s} (use --allow-failures)\n", .{ report.stale + report.skipped, attempted, opts.out_path });
        return error.TooManyFailures;
    }
    if (!opts.allow_shrink and prev_loaded.entries.count() >= 10 and entries.items.len * 2 < prev_loaded.entries.count()) {
        try out.print("error: {d} packages vs {d} before; refusing to shrink by more than half (use --allow-shrink)\n", .{ entries.items.len, prev_loaded.entries.count() });
        return error.CatalogShrank;
    }

    // ---- render, validate, write -------------------------------------------
    // If nothing but the clock would change, keep the old timestamp so the
    // file stays byte-identical and the scheduled run commits nothing.
    var now_buf: [20]u8 = undefined;
    const now = formatUtc(&now_buf, opts.now_epoch orelse std.time.timestamp());
    var rendered: []u8 = undefined;
    if (prev_bytes != null and prev_loaded.updated_at.len != 0) {
        const candidate = try renderIndex(arena, entries.items, prev_loaded.updated_at);
        rendered = if (std.mem.eql(u8, candidate, prev_bytes.?)) candidate else try renderIndex(arena, entries.items, now);
    } else {
        rendered = try renderIndex(arena, entries.items, now);
    }
    report.changed = prev_bytes == null or !std.mem.eql(u8, rendered, prev_bytes.?);

    const tmp_out = try std.fmt.allocPrint(arena, "{s}.tmp", .{opts.out_path});
    try std.fs.cwd().writeFile(.{ .sub_path = tmp_out, .data = rendered });
    errdefer std.fs.cwd().deleteFile(tmp_out) catch {};

    var diags = registry.LoadDiagnostics{};
    var reg = registry.loadFromJsonFile(gpa, tmp_out, &diags) catch |e| {
        try out.print("error: the generated catalog does not load: {s}\n", .{@errorName(e)});
        return error.InvalidCatalog;
    };
    defer reg.deinit();
    if (diags.rejected_packages != 0 or reg.count() != entries.items.len) {
        try out.print("error: registry loader rejected {d} package(s) (first: {s}); not writing {s}\n", .{
            diags.rejected_packages,
            diags.first_error orelse "?",
            opts.out_path,
        });
        return error.InvalidCatalog;
    }
    try std.fs.cwd().rename(tmp_out, opts.out_path);

    const secs = @as(f64, @floatFromInt(timer.read())) / 1e9;
    try out.print(
        "\n{d} packages in {s} ({s}): {d} new, {d} updated, {d} kept, {d} carried, {d} stale, {d} skipped, {d} manual\n" ++
            "API calls: {d}   downloaded: {d:.1} MB   time: {d:.1}s ({d} jobs)   registry check: 0 rejected\n",
        .{
            report.packages,                                opts.out_path,
            if (report.changed) "changed" else "unchanged", report.new,
            report.updated,                                 report.kept,
            report.carried,                                 report.stale,
            report.skipped,                                 report.manual,
            report.api_calls,                               @as(f64, @floatFromInt(report.bytes)) / 1048576.0,
            secs,                                           if (opts.jobs <= 1 or parsed.sources.len <= 1) 1 else @min(opts.jobs, parsed.sources.len),
        },
    );
    return report;
}

fn mdCell(w: anytype, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '|' => try w.writeAll("\\|"),
            '\n', '\r' => try w.writeByte(' '),
            else => try w.writeByte(c),
        }
    }
}

/// GitHub-flavoured Markdown for `$GITHUB_STEP_SUMMARY`: counts, then every
/// source that failed with the reason.
fn writeSummaryMarkdown(
    w: anytype,
    entries: []const Entry,
    sources: []const Source,
    results: []const Result,
    report: Report,
    secs: f64,
    jobs: usize,
) !void {
    var apps: usize = 0;
    for (entries) |e| {
        if (e.app_bundles.len != 0) apps += 1;
    }
    try w.print("### Catalog build\n\n", .{});
    try w.print("| | |\n| :--- | ---: |\n", .{});
    try w.print("| Packages | {d} ({d} GUI apps, {d} manual) |\n", .{ report.packages, apps, report.manual });
    try w.print("| New | {d} |\n| Updated | {d} |\n| Unchanged | {d} |\n", .{ report.new, report.updated, report.kept });
    try w.print("| Stale (failed, previous entry kept) | {d} |\n| Skipped (failed, nothing to keep) | {d} |\n", .{ report.stale, report.skipped });
    try w.print("| GitHub API calls | {d} |\n| Downloaded | {d:.1} MB |\n", .{ report.api_calls, @as(f64, @floatFromInt(report.bytes)) / 1048576.0 });
    try w.print("| Time | {d:.1} s with {d} jobs |\n\n", .{ secs, jobs });

    if (report.stale + report.skipped == 0) {
        try w.writeAll("No source failed.\n");
        return;
    }
    try w.print("#### Failures ({d})\n\n| Package | Source | Outcome | Reason |\n| :--- | :--- | :--- | :--- |\n", .{report.stale + report.skipped});
    for (sources, results) |src, r| {
        if (r.status != .stale and r.status != .skipped) continue;
        try w.print("| {s} | {s}/{s} | {s} | ", .{ src.name, src.owner, src.repo, if (r.status == .stale) "stale" else "skipped" });
        try mdCell(w, r.note);
        try w.writeAll(" |\n");
    }
}

fn printSummary(out: anytype, sources: []const Source, results: []const Result, selective: bool) !void {
    try out.print("\n{s:<8} {s:<24} {s:<16} {s:<6} {s}\n", .{ "STATUS", "PACKAGE", "VERSION", "PLATS", "NOTE" });
    for (status_order) |st| {
        for (sources, results) |src, r| {
            if (r.status != st) continue;
            // An unchanged package is the common case; list it only on request.
            if (st == .kept and !selective and sources.len > 40) continue;
            const ver = if (r.entry) |e| e.version else "-";
            const np = if (r.entry) |e| e.plats.len else 0;
            try out.print("{s:<8} {s:<24} {s:<16} {d}/6    {s}\n", .{ @tagName(st), src.name, ver, np, r.note });
        }
    }
}

// ---------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------

const usage =
    \\usage: build-catalog --sources FILE --out FILE [options]
    \\
    \\  --sources FILE          catalog/sources.txt: `name owner/repo [key=value ...]`
    \\  --out FILE              the registry to write (packages/index.json)
    \\  --previous FILE         reuse entries whose version is unchanged (no downloads)
    \\  --manual FILE           hand-written entries copied through (default: manual.json
    \\                          beside the sources file, if it exists)
    \\  --only a,b              refresh only these packages; the rest come from --previous
    \\  --force                 ignore --previous and rebuild every selected package
    \\  --jobs N                packages processed in parallel (default 8)
    \\  --summary FILE          also write a Markdown report (counts, failures and why)
    \\  --curl                  use curl instead of std.http for all network access
    \\  --offline-fixtures DIR  read <owner>__<repo>.release.json / .repo.json and
    \\                          <owner>__<repo>/<asset> from DIR instead of the network
    \\  --max-download-mb N     skip assets larger than this when they must be fetched
    \\  --allow-shrink          allow the catalog to lose more than half its packages
    \\  --allow-failures        write the catalog even when most sources failed
    \\
    \\Reads GITHUB_TOKEN from the environment to raise the API rate limit.
    \\SOURCE_DATE_EPOCH, if set, replaces the clock used for updated_at.
    \\
;

fn die(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("build-catalog: " ++ fmt ++ "\n", args);
    std.process.exit(2);
}

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    const gpa = gpa_state.allocator();

    const argv = try std.process.argsAlloc(gpa);
    var sources: ?[]const u8 = null;
    var out_path: ?[]const u8 = null;
    var opts = Options{ .sources_path = "", .out_path = "" };
    var only = std.ArrayList([]const u8).init(gpa);

    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        const value_opts = [_][]const u8{ "--sources", "--out", "--previous", "--manual", "--only", "--offline-fixtures", "--jobs", "--max-download-mb", "--summary" };
        var needs_value = false;
        for (value_opts) |o| {
            if (std.mem.eql(u8, arg, o)) needs_value = true;
        }
        var value: []const u8 = "";
        if (needs_value) {
            i += 1;
            if (i >= argv.len) die("{s} needs a value", .{arg});
            value = argv[i];
        }
        if (std.mem.eql(u8, arg, "--sources")) {
            sources = value;
        } else if (std.mem.eql(u8, arg, "--out")) {
            out_path = value;
        } else if (std.mem.eql(u8, arg, "--previous")) {
            opts.previous_path = value;
        } else if (std.mem.eql(u8, arg, "--manual")) {
            opts.manual_path = value;
        } else if (std.mem.eql(u8, arg, "--only")) {
            var it = std.mem.splitScalar(u8, value, ',');
            while (it.next()) |n| {
                if (n.len != 0) try only.append(n);
            }
        } else if (std.mem.eql(u8, arg, "--offline-fixtures")) {
            opts.fixtures_dir = value;
        } else if (std.mem.eql(u8, arg, "--jobs")) {
            opts.jobs = std.fmt.parseInt(usize, value, 10) catch die("--jobs wants a number", .{});
            if (opts.jobs == 0) opts.jobs = 1;
        } else if (std.mem.eql(u8, arg, "--summary")) {
            opts.summary_path = value;
        } else if (std.mem.eql(u8, arg, "--max-download-mb")) {
            const mb = std.fmt.parseInt(u64, value, 10) catch die("--max-download-mb wants a number", .{});
            opts.max_download_bytes = mb * 1024 * 1024;
        } else if (std.mem.eql(u8, arg, "--curl")) {
            opts.use_curl = true;
        } else if (std.mem.eql(u8, arg, "--force")) {
            opts.force = true;
        } else if (std.mem.eql(u8, arg, "--allow-shrink")) {
            opts.allow_shrink = true;
        } else if (std.mem.eql(u8, arg, "--allow-failures")) {
            opts.allow_failures = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try std.io.getStdOut().writeAll(usage);
            return;
        } else {
            die("unknown option '{s}'\n\n{s}", .{ arg, usage });
        }
    }

    opts.sources_path = sources orelse die("--sources is required\n\n{s}", .{usage});
    opts.out_path = out_path orelse die("--out is required\n\n{s}", .{usage});
    opts.only = try only.toOwnedSlice();

    if (opts.manual_path == null) {
        const dir = std.fs.path.dirname(opts.sources_path) orelse ".";
        opts.manual_path = try std.fs.path.join(gpa, &.{ dir, "manual.json" });
    }
    if (std.process.getEnvVarOwned(gpa, "GITHUB_TOKEN")) |t| {
        if (t.len != 0) opts.token = t;
    } else |_| {}
    if (std.process.getEnvVarOwned(gpa, "SOURCE_DATE_EPOCH")) |s| {
        opts.now_epoch = std.fmt.parseInt(i64, std.mem.trim(u8, s, " \n"), 10) catch null;
    } else |_| {}

    var bw = std.io.bufferedWriter(std.io.getStdOut().writer());
    const w = bw.writer();
    const result = execute(gpa, opts, w);
    bw.flush() catch {};
    _ = result catch |e| {
        std.debug.print("build-catalog: failed: {s}\n", .{@errorName(e)});
        std.process.exit(1);
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "sources: comments, quotes, overrides and bad lines" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const text =
        \\# a comment
        \\
        \\ripgrep BurntSushi/ripgrep bin=rg   # trailing comment
        \\fd sharkdp/fd
        \\yt-dlp yt-dlp/yt-dlp asset.x86_64-linux=yt-dlp_linux asset.aarch64-macos=yt-dlp_macos skip=x86_64-windows,aarch64-windows
        \\quoted foo/bar desc="A tool, with \"quotes\" and # hash" license=MIT tag=v1.2.3
        \\pnpm pnpm/pnpm
        \\onlyname
        \\bad!name foo/bar
        \\badrepo not-a-repo
        \\fd sharkdp/fd-again
        \\unk foo/bar color=red
        \\noval foo/bar bin=
        \\badplat foo/bar skip=beos-ppc
        \\unterminated foo/bar desc="oops
        \\reserved foo/bar bin=sudo
        \\pinned foo/bar@v1
        \\ok2 owner/repo2
    ;
    const parsed = try parseSources(a, text);

    try testing.expectEqual(@as(usize, 6), parsed.sources.len);
    try testing.expectEqualStrings("ripgrep", parsed.sources[0].name);
    try testing.expectEqualStrings("BurntSushi", parsed.sources[0].owner);
    try testing.expectEqualStrings("rg", parsed.sources[0].bin[0]);
    try testing.expectEqualStrings("yt-dlp_linux", parsed.sources[2].assets[3].?);
    try testing.expectEqualStrings("yt-dlp_macos", parsed.sources[2].assets[1].?);
    try testing.expect(parsed.sources[2].skip[5] and parsed.sources[2].skip[2] and !parsed.sources[2].skip[3]);
    try testing.expectEqualStrings("A tool, with \"quotes\" and # hash", parsed.sources[3].desc.?);
    try testing.expectEqualStrings("MIT", parsed.sources[3].license.?);
    try testing.expectEqualStrings("v1.2.3", parsed.sources[3].tag.?);
    try testing.expectEqualStrings("ok2", parsed.sources[5].name);
    try testing.expectEqual(@as(usize, 18), parsed.sources[5].line);

    // Every bad line is reported once, with its line number, and none aborts.
    const expect_lines = [_]usize{ 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 };
    try testing.expectEqual(expect_lines.len, parsed.problems.len);
    for (expect_lines, parsed.problems) |want, p| try testing.expectEqual(want, p.line);
    try testing.expect(std.mem.indexOf(u8, parsed.problems[8].text, "usable") != null);
}

test "version from tag" {
    const cases = [_][2][]const u8{
        .{ "v1.2.3", "1.2.3" },
        .{ "14.1.1", "14.1.1" },
        .{ "jq-1.7.1", "1.7.1" },
        .{ "bun-v1.1.30", "1.1.30" },
        .{ "release-2.0", "2.0" },
        .{ "cli/v3.4.5", "3.4.5" },
        .{ "@biomejs/biome@1.9.4", "1.9.4" },
        .{ "nightly", "nightly" },
        .{ "V2", "2" },
        .{ "v0.13.0-rc.1", "0.13.0-rc.1" },
    };
    for (cases) |c| try testing.expectEqualStrings(c[1], versionFromTag(c[0]).?);
    try testing.expect(versionFromTag("") == null);
    try testing.expect(versionFromTag("v1 2") == null);
}

test "checksum files are parsed by the same code as `install gh:`" {
    const h1 = "f84757b07f425fe5cf11d87df6644691c644a5cd2348a2c670894272999d3ba7";
    const h2 = "AB4D882FC945E5A9B6080A5C0506F7FE4AAEA191C1865355428DD4BFA096F974";
    const text = h1 ++ "  ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz\n" ++
        h2 ++ " *./dist/fzf-0.55.0-linux_amd64.tar.gz\r\n" ++
        "SHA256 (tool-1.0.zip) = " ++ h1 ++ "\n" ++
        "not a checksum line\n";
    try testing.expectEqualStrings(h1, &ghverify.findChecksum(text, "ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz", false).?);
    // Upper case hex is normalised, "*" and "./dir/" prefixes are ignored.
    try testing.expectEqualStrings("ab4d882fc945e5a9b6080a5c0506f7fe4aaea191c1865355428dd4bfa096f974", &ghverify.findChecksum(text, "fzf-0.55.0-linux_amd64.tar.gz", false).?);
    try testing.expectEqualStrings(h1, &ghverify.findChecksum(text, "tool-1.0.zip", false).?);
    try testing.expect(ghverify.findChecksum(text, "missing.tar.gz", false) == null);
    try testing.expect(ghverify.findChecksum(text, "ripgrep-14.1.1", false) == null);

    try testing.expectEqualStrings(h1, &ghverify.findChecksum(h1 ++ "\n", "anything", true).?);
    try testing.expect(ghverify.findChecksum(h1 ++ "\n", "anything", false) == null);
    try testing.expect(ghverify.findChecksum("deadbeef  x\n", "x", false) == null);
}

test "bin_path layout across platforms" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const rg = LayoutInput{
        .primary_rel = "ripgrep-14.1.1-x86_64-unknown-linux-musl/rg",
        .detected_stem = "ripgrep-14.1.1-x86_64-unknown-linux-musl",
        .bin_name = "rg",
        .renamed = false,
        .version = "14.1.1",
    };
    try testing.expectEqualStrings(
        "ripgrep-14.1.1-aarch64-apple-darwin/rg",
        (try binPathFor(a, rg, "ripgrep-14.1.1-aarch64-apple-darwin.tar.gz", .macos, false)).?,
    );
    try testing.expectEqualStrings(
        "ripgrep-14.1.1-x86_64-pc-windows-msvc/rg.exe",
        (try binPathFor(a, rg, "ripgrep-14.1.1-x86_64-pc-windows-msvc.zip", .windows, false)).?,
    );

    // A directory that is not the asset stem but names a version/platform: walk.
    const odd = LayoutInput{ .primary_rel = "tool-v1.0-linux/bin/tool", .detected_stem = "tool-linux-amd64", .bin_name = "tool", .renamed = false, .version = "1.0" };
    try testing.expectEqualStrings("tool", (try binPathFor(a, odd, "tool-darwin-arm64.tar.gz", .macos, false)).?);

    // A neutral directory is kept; a flat archive stays flat.
    const neutral = LayoutInput{ .primary_rel = "usr/bin/fastfetch", .detected_stem = "x", .bin_name = "fastfetch", .renamed = false, .version = "2.0" };
    try testing.expectEqualStrings("usr/bin/fastfetch", (try binPathFor(a, neutral, "other.tar.gz", .linux, false)).?);
    const flat = LayoutInput{ .primary_rel = "btm", .detected_stem = "bottom_x86_64-unknown-linux-musl", .bin_name = "btm", .renamed = false, .version = "0.12.3" };
    try testing.expectEqualStrings("btm", (try binPathFor(a, flat, "bottom_aarch64-apple-darwin.tar.gz", .macos, false)).?);

    // A raw asset is stored under the bin name.
    const jq = LayoutInput{ .primary_rel = "jq", .detected_stem = "jq-linux-amd64", .bin_name = "jq", .renamed = false, .version = "1.7.1" };
    try testing.expectEqualStrings("jq.exe", (try binPathFor(a, jq, "jq-windows-amd64.exe", .windows, true)).?);
    try testing.expectEqualStrings("jq", (try binPathFor(a, jq, "jq-linux-amd64", .linux, true)).?);

    // A renamed executable follows the asset stem, or the platform is dropped.
    const yq = LayoutInput{ .primary_rel = "yq_linux_amd64", .detected_stem = "yq_linux_amd64", .bin_name = "yq", .renamed = true, .version = "4.0" };
    try testing.expectEqualStrings("yq_darwin_arm64", (try binPathFor(a, yq, "yq_darwin_arm64.tar.gz", .macos, false)).?);
    const yq_odd = LayoutInput{ .primary_rel = "yq_linux", .detected_stem = "yq_linux_amd64", .bin_name = "yq", .renamed = true, .version = "4.0" };
    try testing.expect((try binPathFor(a, yq_odd, "yq_darwin_arm64.tar.gz", .macos, false)) == null);

    try testing.expectEqualStrings("yq", normalizeBinName("yq_linux_amd64", "yq"));
    try testing.expectEqualStrings("rg", normalizeBinName("rg", "ripgrep"));
    try testing.expectEqualStrings("tool-helper", normalizeBinName("tool-helper", "tool"));
    try testing.expectEqualStrings("ripgrep-14.1.1-x86_64-unknown-linux-musl", assetStem("ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz"));
    try testing.expectEqualStrings("jq-linux-amd64", assetStem("jq-linux-amd64"));
}

test "rank puts the project's own executable first" {
    var bins = [_]bindetect.Bin{
        .{ .path = "pkg/libexec/helper", .name = "helper" },
        .{ .path = "pkg/bin/zeta", .name = "zeta" },
        .{ .path = "pkg/bin/ripgrep-all", .name = "ripgrep-all" },
        .{ .path = "pkg/bin/rg", .name = "rg" },
        .{ .path = "ripgrep", .name = "ripgrep" },
    };
    bindetect.rank(&bins, "ripgrep");
    try testing.expectEqualStrings("ripgrep", bins[0].name);
    try testing.expectEqualStrings("ripgrep-all", bins[1].name);
}

test "output is sorted and deterministic" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const sha = "0" ** 63 ++ "1";
    const plats_a = [_]PlatEntry{
        .{ .tag = "x86_64-linux", .url = "https://example.com/a-linux", .sha256 = sha, .archive_type = "tar.gz", .bin_path = "a" },
        .{ .tag = "aarch64-macos", .url = "https://example.com/a-mac", .sha256 = sha, .archive_type = "zip", .bin_path = "a" },
    };
    const e_a = Entry{ .name = "alpha", .version = "1.0.0", .description = "A \"quoted\"\ttool", .homepage = "https://example.com", .license = "MIT", .bin = &.{"a"}, .plats = &plats_a };
    const e_b = Entry{ .name = "beta", .version = "2.0.0", .bin = &.{ "b", "b2" }, .deps = &.{"alpha"}, .plats = &plats_a };

    const one = try renderIndex(a, &.{ e_b, e_a }, "2026-01-02T03:04:05Z");
    const two = try renderIndex(a, &.{ e_a, e_b }, "2026-01-02T03:04:05Z");
    try testing.expectEqualStrings(one, two);
    try testing.expect(std.mem.indexOf(u8, one, "\"alpha\"").? < std.mem.indexOf(u8, one, "\"beta\"").?);
    try testing.expect(std.mem.indexOf(u8, one, "\"aarch64-macos\"").? < std.mem.indexOf(u8, one, "\"x86_64-linux\"").?);
    try testing.expect(std.mem.indexOf(u8, one, "\"deps\": [\"alpha\"]") != null);
    try testing.expect(std.mem.endsWith(u8, one, "}\n"));

    // What was written reads back to the same entries and renders identically.
    const loaded = try loadEntries(a, one);
    try testing.expectEqualStrings("2026-01-02T03:04:05Z", loaded.updated_at);
    try testing.expectEqual(@as(usize, 2), loaded.entries.count());
    const back = loaded.entries.get("alpha").?;
    try testing.expectEqualStrings("A \"quoted\"\ttool", back.description);
    const three = try renderIndex(a, &.{ back, loaded.entries.get("beta").? }, loaded.updated_at);
    try testing.expectEqualStrings(one, three);

    var buf: [20]u8 = undefined;
    try testing.expectEqualStrings("2026-06-18T00:00:00Z", formatUtc(&buf, 1781740800));
    try testing.expectEqualStrings("1970-01-01T00:00:00Z", formatUtc(&buf, 0));
}

test "validateEntry applies the registry's rules" {
    const sha = "a" ** 64;
    const good = [_]PlatEntry{.{ .tag = "x86_64-linux", .url = "https://example.com/x", .sha256 = sha, .archive_type = "raw", .bin_path = "x" }};
    var e = Entry{ .name = "x", .version = "1.0", .bin = &.{"x"}, .plats = &good };
    try testing.expect(validateEntry(e) == null);

    e.bin = &.{"sudo"};
    try testing.expect(validateEntry(e) != null);
    e.bin = &.{};
    try testing.expect(validateEntry(e) != null);
    e.bin = &.{"x"};
    e.version = "1 0";
    try testing.expect(validateEntry(e) != null);
    e.version = "1.0";

    const http = [_]PlatEntry{.{ .tag = "x86_64-linux", .url = "http://example.com/x", .sha256 = sha, .archive_type = "raw", .bin_path = "x" }};
    e.plats = &http;
    try testing.expect(validateEntry(e) != null);
    const traversal = [_]PlatEntry{.{ .tag = "x86_64-linux", .url = "https://example.com/x", .sha256 = sha, .archive_type = "raw", .bin_path = "../x" }};
    e.plats = &traversal;
    try testing.expect(validateEntry(e) != null);
    const nohash = [_]PlatEntry{.{ .tag = "x86_64-linux", .url = "https://example.com/x", .sha256 = "SKIP", .archive_type = "raw", .bin_path = "x" }};
    e.plats = &nohash;
    try testing.expect(validateEntry(e) != null);
}

// ---- end to end on fabricated fixtures -------------------------------------

/// Appends one ustar member to `list`.
fn tarMember(list: *std.ArrayList(u8), name: []const u8, mode: u32, content: []const u8) !void {
    var hdr = [_]u8{0} ** 512;
    @memcpy(hdr[0..name.len], name);
    _ = try std.fmt.bufPrint(hdr[100..108], "{o:0>7}", .{mode});
    _ = try std.fmt.bufPrint(hdr[108..116], "{o:0>7}", .{0});
    _ = try std.fmt.bufPrint(hdr[116..124], "{o:0>7}", .{0});
    _ = try std.fmt.bufPrint(hdr[124..136], "{o:0>11}", .{content.len});
    _ = try std.fmt.bufPrint(hdr[136..148], "{o:0>11}", .{0});
    @memset(hdr[148..156], ' ');
    hdr[156] = '0';
    @memcpy(hdr[257..263], "ustar\x00");
    @memcpy(hdr[263..265], "00");
    var sum: u32 = 0;
    for (hdr) |b| sum += b;
    _ = try std.fmt.bufPrint(hdr[148..155], "{o:0>6}\x00", .{sum});
    hdr[155] = ' ';
    try list.appendSlice(&hdr);
    try list.appendSlice(content);
    const pad = (512 - content.len % 512) % 512;
    try list.appendNTimes(0, pad);
}

fn hexOf(bytes: []const u8) [64]u8 {
    var d: [32]u8 = undefined;
    Sha256.hash(bytes, &d, .{});
    return std.fmt.bytesToHex(d, .lower);
}

fn writeTestFile(dir: std.fs.Dir, path: []const u8, data: []const u8) !void {
    if (std.fs.path.dirname(path)) |d| try dir.makePath(d);
    try dir.writeFile(.{ .sub_path = path, .data = data });
}

const TestEnv = struct {
    tmp: std.testing.TmpDir,
    root: []u8,
    fixtures: []u8,
    sources: []u8,
    out: []u8,

    fn init(a: Allocator) !TestEnv {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        const root = try tmp.dir.realpathAlloc(a, ".");
        try tmp.dir.makePath("fx/acme__widget");
        try tmp.dir.makePath("fx/acme__gizmo");
        return .{
            .tmp = tmp,
            .root = root,
            .fixtures = try std.fs.path.join(a, &.{ root, "fx" }),
            .sources = try std.fs.path.join(a, &.{ root, "sources.txt" }),
            .out = try std.fs.path.join(a, &.{ root, "index.json" }),
        };
    }
};

const widget_release =
    \\{{"tag_name":"v1.2.0","assets":[
    \\ {{"name":"widget-1.2.0-x86_64-unknown-linux-musl.tar","browser_download_url":"https://github.com/acme/widget/releases/download/v1.2.0/widget-1.2.0-x86_64-unknown-linux-musl.tar","size":3072,"digest":"sha256:{s}"}},
    \\ {{"name":"widget-1.2.0-aarch64-apple-darwin.tar","browser_download_url":"https://github.com/acme/widget/releases/download/v1.2.0/widget-1.2.0-aarch64-apple-darwin.tar","size":3072,"digest":"sha256:{s}"}},
    \\ {{"name":"widget-1.2.0-source.tar.gz","browser_download_url":"https://github.com/acme/widget/releases/download/v1.2.0/widget-1.2.0-source.tar.gz","size":10}}
    \\]}}
;

const widget_repo_json =
    \\{"full_name":"acme/widget","description":"A   widget\n tool","license":{"spdx_id":"MIT"},"homepage":"","html_url":"https://github.com/acme/widget"}
;

test "end to end on fixtures, then incrementally with no downloads" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var env = try TestEnv.init(a);
    defer env.tmp.cleanup();

    // A tiny tarball with the executable and some noise.
    var tar_linux = std.ArrayList(u8).init(a);
    try tarMember(&tar_linux, "widget-1.2.0-x86_64-unknown-linux-musl/widget", 0o755, "\x7fELF widget");
    try tarMember(&tar_linux, "widget-1.2.0-x86_64-unknown-linux-musl/README.md", 0o644, "readme");
    try tarMember(&tar_linux, "widget-1.2.0-x86_64-unknown-linux-musl/complete/widget.bash", 0o755, "# completion");
    try tar_linux.appendNTimes(0, 1024);
    var tar_mac = std.ArrayList(u8).init(a);
    try tarMember(&tar_mac, "widget-1.2.0-aarch64-apple-darwin/widget", 0o755, "\x7fELF mac");
    try tar_mac.appendNTimes(0, 1024);

    const h_linux = hexOf(tar_linux.items);
    const h_mac = hexOf(tar_mac.items);
    const release = try std.fmt.allocPrint(a, widget_release, .{ h_linux, h_mac });
    try writeTestFile(env.tmp.dir, "fx/acme__widget.release.json", release);
    try writeTestFile(env.tmp.dir, "fx/acme__widget.repo.json", widget_repo_json);
    try writeTestFile(env.tmp.dir, "fx/acme__widget/widget-1.2.0-x86_64-unknown-linux-musl.tar", tar_linux.items);
    try writeTestFile(env.tmp.dir, "fx/acme__widget/widget-1.2.0-aarch64-apple-darwin.tar", tar_mac.items);

    // gizmo: no digest, a checksums file in the release, and a raw asset.
    const gizmo_bytes = "\x7fELF fake gizmo";
    const h_gizmo = hexOf(gizmo_bytes);
    try writeTestFile(env.tmp.dir, "fx/acme__gizmo.release.json",
        \\{"tag_name":"gizmo-0.9.1","assets":[
        \\ {"name":"gizmo-linux-amd64","browser_download_url":"https://github.com/acme/gizmo/releases/download/gizmo-0.9.1/gizmo-linux-amd64","size":14},
        \\ {"name":"gizmo_0.9.1_checksums.txt","browser_download_url":"https://github.com/acme/gizmo/releases/download/gizmo-0.9.1/gizmo_0.9.1_checksums.txt","size":100}
        \\]}
    );
    try writeTestFile(env.tmp.dir, "fx/acme__gizmo.repo.json", "{\"full_name\":\"acme/gizmo\",\"description\":null,\"license\":null,\"homepage\":\"https://gizmo.example\"}");
    try writeTestFile(env.tmp.dir, "fx/acme__gizmo/gizmo-linux-amd64", gizmo_bytes);
    const sums = try std.fmt.allocPrint(a, "{s}  gizmo-linux-amd64\n", .{h_gizmo});
    try writeTestFile(env.tmp.dir, "fx/acme__gizmo/gizmo_0.9.1_checksums.txt", sums);

    try writeTestFile(env.tmp.dir, "sources.txt",
        \\widget acme/widget
        \\gizmo acme/gizmo license=Apache-2.0
        \\missing acme/missing
        \\broken acme
    );

    var sink = std.ArrayList(u8).init(a);
    const base = Options{ .sources_path = env.sources, .out_path = env.out, .fixtures_dir = env.fixtures, .jobs = 1, .now_epoch = 1781740800, .quiet = true };

    const first = try execute(testing.allocator, base, sink.writer());
    try testing.expectEqual(@as(usize, 2), first.packages);
    try testing.expectEqual(@as(usize, 2), first.new);
    try testing.expectEqual(@as(usize, 1), first.skipped);
    try testing.expect(first.bytes > 0);

    // The registry's own loader accepts the file with nothing rejected.
    var diags = registry.LoadDiagnostics{};
    var reg = try registry.loadFromJsonFile(testing.allocator, env.out, &diags);
    defer reg.deinit();
    try testing.expectEqual(@as(usize, 0), diags.rejected_packages);
    try testing.expectEqual(@as(usize, 2), reg.count());

    const widget = reg.get("widget").?;
    try testing.expectEqualStrings("1.2.0", widget.version);
    try testing.expectEqualStrings("widget", widget.bin[0]);
    try testing.expectEqual(@as(usize, 1), widget.bin.len); // README and completion script are not executables
    try testing.expectEqualStrings("A widget tool", widget.description);
    try testing.expectEqualStrings("MIT", widget.license);
    try testing.expectEqualStrings("https://github.com/acme/widget", widget.homepage);
    try testing.expectEqual(@as(usize, 2), widget.platforms.len);
    const lin = widget.platform("x86_64-linux").?;
    try testing.expectEqualStrings("tar", lin.archive_type);
    try testing.expectEqualStrings("widget-1.2.0-x86_64-unknown-linux-musl/widget", lin.bin_path);
    try testing.expectEqualStrings(&h_linux, lin.sha256);
    // The macOS asset was never unpacked; its layout follows the asset stem.
    try testing.expectEqualStrings("widget-1.2.0-aarch64-apple-darwin/widget", widget.platform("aarch64-macos").?.bin_path);

    const gizmo = reg.get("gizmo").?;
    try testing.expectEqualStrings("0.9.1", gizmo.version);
    try testing.expectEqualStrings("raw", gizmo.platforms[0].archive_type);
    try testing.expectEqualStrings(&h_gizmo, gizmo.platforms[0].sha256);
    try testing.expectEqualStrings("Apache-2.0", gizmo.license);
    try testing.expectEqualStrings("https://gizmo.example", gizmo.homepage);

    // Same inputs, same bytes.
    const bytes1 = try std.fs.cwd().readFileAlloc(a, env.out, 1 << 20);
    const out2 = try std.fs.path.join(a, &.{ env.root, "index2.json" });
    var o2 = base;
    o2.out_path = out2;
    _ = try execute(testing.allocator, o2, sink.writer());
    const bytes2 = try std.fs.cwd().readFileAlloc(a, out2, 1 << 20);
    try testing.expectEqualStrings(bytes1, bytes2);

    // Incremental: with --previous and the assets gone, nothing is fetched and
    // the file is byte-identical even though the clock moved on.
    try env.tmp.dir.deleteTree("fx/acme__widget");
    try env.tmp.dir.deleteTree("fx/acme__gizmo");
    const out3 = try std.fs.path.join(a, &.{ env.root, "index3.json" });
    var o3 = base;
    o3.out_path = out3;
    o3.previous_path = env.out;
    o3.now_epoch = 1781740800 + 86400;
    const third = try execute(testing.allocator, o3, sink.writer());
    try testing.expectEqual(@as(usize, 2), third.kept);
    try testing.expectEqual(@as(u64, 0), third.bytes);
    try testing.expect(!third.changed);
    const bytes3 = try std.fs.cwd().readFileAlloc(a, out3, 1 << 20);
    try testing.expectEqualStrings(bytes1, bytes3);
}

test "a failing source keeps its previous entry; a new version replaces it" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var env = try TestEnv.init(a);
    defer env.tmp.cleanup();

    try writeTestFile(env.tmp.dir, "sources.txt", "widget acme/widget bin=widget\n");
    const bytes = "binary";
    const h = hexOf(bytes);
    const mk = struct {
        fn release(al: Allocator, tag: []const u8, hash: []const u8) ![]u8 {
            return std.fmt.allocPrint(al,
                \\{{"tag_name":"{s}","assets":[{{"name":"widget-linux-amd64","browser_download_url":"https://github.com/acme/widget/releases/download/{s}/widget-linux-amd64","size":6,"digest":"sha256:{s}"}}]}}
            , .{ tag, tag, hash });
        }
    };
    try writeTestFile(env.tmp.dir, "fx/acme__widget.release.json", try mk.release(a, "v1.0.0", &h));
    try writeTestFile(env.tmp.dir, "fx/acme__widget.repo.json", widget_repo_json);
    try writeTestFile(env.tmp.dir, "fx/acme__widget/widget-linux-amd64", bytes);

    var sink = std.ArrayList(u8).init(a);
    const base = Options{ .sources_path = env.sources, .out_path = env.out, .fixtures_dir = env.fixtures, .jobs = 1, .now_epoch = 1781740800, .quiet = true };
    _ = try execute(testing.allocator, base, sink.writer());

    // The release disappears: the old entry survives as "stale".
    try env.tmp.dir.deleteFile("fx/acme__widget.release.json");
    const out2 = try std.fs.path.join(a, &.{ env.root, "stale.json" });
    var o2 = base;
    o2.out_path = out2;
    o2.previous_path = env.out;
    const stale = try execute(testing.allocator, o2, sink.writer());
    try testing.expectEqual(@as(usize, 1), stale.stale);
    try testing.expectEqual(@as(usize, 1), stale.packages);

    // A new tag with a new digest is downloaded, verified and replaces it.
    const bytes2 = "binary v2";
    const h2 = hexOf(bytes2);
    try writeTestFile(env.tmp.dir, "fx/acme__widget.release.json", try mk.release(a, "v2.0.0", &h2));
    try writeTestFile(env.tmp.dir, "fx/acme__widget/widget-linux-amd64", bytes2);
    const out3 = try std.fs.path.join(a, &.{ env.root, "new.json" });
    var o3 = base;
    o3.out_path = out3;
    o3.previous_path = env.out;
    const upd = try execute(testing.allocator, o3, sink.writer());
    try testing.expectEqual(@as(usize, 1), upd.updated);

    // A digest that does not match the downloaded archive is refused, and the
    // previous entry is kept instead.
    var tar = std.ArrayList(u8).init(a);
    try tarMember(&tar, "widget-3.0.0/widget", 0o755, "tampered");
    try tar.appendNTimes(0, 1024);
    const claimed = hexOf("what the release claims");
    const bad_release = try std.fmt.allocPrint(a,
        \\{{"tag_name":"v3.0.0","assets":[{{"name":"widget-3.0.0-linux-amd64.tar","browser_download_url":"https://github.com/acme/widget/releases/download/v3.0.0/widget-3.0.0-linux-amd64.tar","size":2048,"digest":"sha256:{s}"}}]}}
    , .{claimed});
    try writeTestFile(env.tmp.dir, "fx/acme__widget.release.json", bad_release);
    try writeTestFile(env.tmp.dir, "fx/acme__widget/widget-3.0.0-linux-amd64.tar", tar.items);
    const out4 = try std.fs.path.join(a, &.{ env.root, "bad.json" });
    var o4 = base;
    o4.out_path = out4;
    o4.previous_path = out3;
    sink.clearRetainingCapacity();
    const bad_run = try execute(testing.allocator, o4, sink.writer());
    try testing.expectEqual(@as(usize, 0), bad_run.updated);
    try testing.expectEqual(@as(usize, 1), bad_run.stale);
    try testing.expect(std.mem.indexOf(u8, sink.items, "does not match its published SHA-256") != null);
}

test "sidecar checksum, download-and-hash fallback, and --only" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var env = try TestEnv.init(a);
    defer env.tmp.cleanup();

    var tar = std.ArrayList(u8).init(a);
    try tarMember(&tar, "gadget", 0o755, "\x7fELF gadget");
    try tar.appendNTimes(0, 1024);
    const want = hexOf(tar.items);
    try writeTestFile(env.tmp.dir, "fx/acme__widget.release.json",
        \\{"tag_name":"v4.1.0","assets":[
        \\ {"name":"gadget-v4.1.0-x86_64-unknown-linux-gnu.tar","browser_download_url":"https://github.com/acme/widget/releases/download/v4.1.0/gadget-v4.1.0-x86_64-unknown-linux-gnu.tar","size":2048},
        \\ {"name":"gadget-v4.1.0-x86_64-unknown-linux-gnu.tar.sha256","browser_download_url":"https://github.com/acme/widget/releases/download/v4.1.0/gadget-v4.1.0-x86_64-unknown-linux-gnu.tar.sha256","size":100},
        \\ {"name":"gadget-v4.1.0-aarch64-unknown-linux-gnu.tar","browser_download_url":"https://github.com/acme/widget/releases/download/v4.1.0/gadget-v4.1.0-aarch64-unknown-linux-gnu.tar","size":2048}
        \\]}
    );
    try writeTestFile(env.tmp.dir, "fx/acme__widget.repo.json", widget_repo_json);
    try writeTestFile(env.tmp.dir, "fx/acme__widget/gadget-v4.1.0-x86_64-unknown-linux-gnu.tar", tar.items);
    // aarch64 has no checksum anywhere and its file is missing: it is left
    // out, never published unpinned.
    const sidecar = try std.fmt.allocPrint(a, "{s}\n", .{want});
    try writeTestFile(env.tmp.dir, "fx/acme__widget/gadget-v4.1.0-x86_64-unknown-linux-gnu.tar.sha256", sidecar);
    try writeTestFile(env.tmp.dir, "sources.txt", "widget acme/widget bin=gadget\nother acme/other\n");

    var sink = std.ArrayList(u8).init(a);
    const base = Options{ .sources_path = env.sources, .out_path = env.out, .fixtures_dir = env.fixtures, .jobs = 1, .now_epoch = 1781740800, .quiet = true };

    // Pinned from the sidecar file; the unpinnable platform is dropped.
    var run1 = base;
    run1.only = &.{"widget"};
    const first = try execute(testing.allocator, run1, sink.writer());
    try testing.expectEqual(@as(usize, 1), first.new);
    try testing.expectEqual(@as(usize, 1), first.packages);
    try testing.expectEqual(@as(usize, 0), first.skipped); // "other" was not selected

    var reg = try registry.loadFromJsonFile(testing.allocator, env.out, null);
    defer reg.deinit();
    const w = reg.get("widget").?;
    try testing.expectEqual(@as(usize, 1), w.platforms.len);
    try testing.expectEqualStrings("x86_64-linux", w.platforms[0].name);
    try testing.expectEqualStrings(&want, w.platforms[0].sha256);
    try testing.expectEqualStrings("gadget", w.bin[0]);
    try testing.expectEqualStrings("gadget", w.platforms[0].bin_path);

    // Without the sidecar the same asset is downloaded and hashed instead.
    try env.tmp.dir.deleteFile("fx/acme__widget/gadget-v4.1.0-x86_64-unknown-linux-gnu.tar.sha256");
    var run2 = base;
    run2.only = &.{"widget"};
    run2.force = true;
    run2.out_path = try std.fs.path.join(a, &.{ env.root, "second.json" });
    const second = try execute(testing.allocator, run2, sink.writer());
    try testing.expect(second.bytes >= tar.items.len);
    const text = try std.fs.cwd().readFileAlloc(a, run2.out_path, 1 << 20);
    try testing.expect(std.mem.indexOf(u8, text, &want) != null);
}

test "when most sources fail nothing is written" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var env = try TestEnv.init(a);
    defer env.tmp.cleanup();

    var list = std.ArrayList(u8).init(a);
    for (0..12) |i| try list.writer().print("pkg{d} acme/missing{d}\n", .{ i, i });
    try writeTestFile(env.tmp.dir, "sources.txt", list.items);
    try writeTestFile(env.tmp.dir, "manual.json",
        \\{"packages":{"hand":{"name":"hand","version":"1","bin":["hand"],"platforms":{"x86_64-linux":{"url":"https://example.com/hand","sha256":"0000000000000000000000000000000000000000000000000000000000000001","archive_type":"raw","bin_path":"hand"}}}}}
    );

    var sink = std.ArrayList(u8).init(a);
    var opts = Options{ .sources_path = env.sources, .out_path = env.out, .fixtures_dir = env.fixtures, .jobs = 1, .quiet = true };
    opts.manual_path = try std.fs.path.join(a, &.{ env.root, "manual.json" });
    try testing.expectError(error.TooManyFailures, execute(testing.allocator, opts, sink.writer()));
    try testing.expectError(error.FileNotFound, std.fs.cwd().access(env.out, .{}));

    // Explicitly allowed, the manual entry alone is published.
    opts.allow_failures = true;
    const r = try execute(testing.allocator, opts, sink.writer());
    try testing.expectEqual(@as(usize, 12), r.skipped);
    try testing.expectEqual(@as(usize, 1), r.packages);
    try testing.expectEqual(@as(usize, 1), r.manual);
}

// ---- GUI apps: parsing, picking, zip listing --------------------------------

test "sources: kind=app and app=" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const text =
        \\rectangle rxhanson/Rectangle kind=app app=Rectangle.app
        \\maccy p0deje/Maccy kind=app
        \\brave brave/brave-browser app="Brave Browser.app" skip=x86_64-macos
        \\tool acme/tool
        \\both acme/both kind=cli app=Both.app
        \\appbin acme/appbin kind=app bin=appbin
        \\badkind acme/badkind kind=gui
        \\notapp acme/notapp app=NotAnApp
        \\slash acme/slash app=../Evil.app
        \\colon acme/colon app=C:Evil.app
        \\two acme/two app=One.app,Two.app
    ;
    const parsed = try parseSources(a, text);
    try testing.expectEqual(@as(usize, 5), parsed.sources.len);

    try testing.expect(parsed.sources[0].kind == .app);
    try testing.expectEqualStrings("Rectangle.app", parsed.sources[0].apps[0]);
    // No app= is fine for a .zip: the name is read from the archive.
    try testing.expect(parsed.sources[1].kind == .app);
    try testing.expectEqual(@as(usize, 0), parsed.sources[1].apps.len);
    // app= alone implies kind=app; quotes keep the space.
    try testing.expect(parsed.sources[2].kind == .app);
    try testing.expectEqualStrings("Brave Browser.app", parsed.sources[2].apps[0]);
    try testing.expect(parsed.sources[2].skip[4]);
    try testing.expect(parsed.sources[3].kind == .cli);
    try testing.expectEqual(@as(usize, 2), parsed.sources[4].apps.len);

    const bad_lines = [_]usize{ 5, 6, 7, 8, 9, 10 };
    try testing.expectEqual(bad_lines.len, parsed.problems.len);
    for (bad_lines, parsed.problems) |want, p| try testing.expectEqual(want, p.line);
}

test "app bundle names" {
    try testing.expect(isUsableAppName("Rectangle.app"));
    try testing.expect(isUsableAppName("Brave Browser.app"));
    try testing.expect(!isUsableAppName(".app"));
    try testing.expect(!isUsableAppName("Rectangle"));
    try testing.expect(!isUsableAppName("a/b.app"));
    try testing.expect(!isUsableAppName("a\\b.app"));
    try testing.expect(!isUsableAppName("C:b.app"));
    try testing.expect(!isUsableAppName("../b.app"));
    try testing.expect(!isUsableAppName("a\nb.app"));
}

fn namedAssets(arena: Allocator, names: []const []const u8) ![]ghrelease.Asset {
    const out = try arena.alloc(ghrelease.Asset, names.len);
    for (names, out) |n, *x| x.* = .{ .name = n, .url = "https://example.com/dl", .size = 0, .sha256 = null };
    return out;
}

fn expectAppPick(assets: []const ghrelease.Asset, tag: []const u8, know_app: bool, want: ?[]const u8) !void {
    const got = pickAppAsset(assets, tag, know_app);
    if (want) |w| {
        try testing.expectEqualStrings(w, assets[got orelse return error.TestExpectedEqual].name);
    } else {
        try testing.expect(got == null);
    }
}

test "the app picker chooses the right .dmg or .zip for each Mac" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    // One universal disk image.
    const one = try namedAssets(a, &.{ "Rectangle0.80.dmg", "Rectangle0.80.dmg.sha256", "source.zip" });
    try expectAppPick(one, "aarch64-macos", true, "Rectangle0.80.dmg");
    try expectAppPick(one, "x86_64-macos", true, "Rectangle0.80.dmg");

    // Per-architecture images, plus Windows and Linux files that must not match.
    const split = try namedAssets(a, &.{
        "App-1.0-arm64.dmg",    "App-1.0-x64.dmg",             "App-1.0-win-x64.zip",
        "App-1.0-linux.zip",    "App-1.0.AppImage",            "App-1.0-arm64.dmg.blockmap",
        "App-1.0-mac-dSYM.zip", "App-1.0-macos-universal.zip",
    });
    try expectAppPick(split, "aarch64-macos", true, "App-1.0-arm64.dmg");
    try expectAppPick(split, "x86_64-macos", true, "App-1.0-x64.dmg");

    // Without app= a .zip wins, because its bundle name can be read.
    try expectAppPick(split, "aarch64-macos", false, "App-1.0-macos-universal.zip");

    // An x64-only release has nothing for Apple silicon.
    const intel = try namedAssets(a, &.{"App-intel.dmg"});
    try expectAppPick(intel, "aarch64-macos", true, null);
    try expectAppPick(intel, "x86_64-macos", true, "App-intel.dmg");

    // A bare name with no hints is taken for both Macs.
    const bare = try namedAssets(a, &.{ "Ice.zip", "Ice.zip.sig" });
    try expectAppPick(bare, "aarch64-macos", false, "Ice.zip");
    try expectAppPick(bare, "x86_64-macos", false, "Ice.zip");

    const none = try namedAssets(a, &.{ "tool-linux-amd64.tar.gz", "tool-windows.zip", "tool-ios.zip" });
    try expectAppPick(none, "aarch64-macos", false, null);
}

/// Appends a stored (uncompressed) zip with the given members. A name ending
/// in '/' is a directory.
fn storedZip(list: *std.ArrayList(u8), members: []const struct { name: []const u8, data: []const u8 }) !void {
    const w = list.writer();
    var offsets: [16]u32 = undefined;
    for (members, 0..) |m, i| {
        offsets[i] = @intCast(list.items.len);
        try w.writeInt(u32, 0x04034b50, .little);
        try w.writeInt(u16, 20, .little);
        try w.writeInt(u16, 0, .little);
        try w.writeInt(u16, 0, .little);
        try w.writeInt(u32, 0, .little);
        try w.writeInt(u32, std.hash.Crc32.hash(m.data), .little);
        try w.writeInt(u32, @intCast(m.data.len), .little);
        try w.writeInt(u32, @intCast(m.data.len), .little);
        try w.writeInt(u16, @intCast(m.name.len), .little);
        try w.writeInt(u16, 0, .little);
        try w.writeAll(m.name);
        try w.writeAll(m.data);
    }
    const cd_start: u32 = @intCast(list.items.len);
    for (members, 0..) |m, i| {
        try w.writeInt(u32, 0x02014b50, .little);
        try w.writeInt(u16, 20, .little);
        try w.writeInt(u16, 20, .little);
        try w.writeInt(u16, 0, .little);
        try w.writeInt(u16, 0, .little);
        try w.writeInt(u32, 0, .little);
        try w.writeInt(u32, std.hash.Crc32.hash(m.data), .little);
        try w.writeInt(u32, @intCast(m.data.len), .little);
        try w.writeInt(u32, @intCast(m.data.len), .little);
        try w.writeInt(u16, @intCast(m.name.len), .little);
        try w.writeInt(u16, 0, .little);
        try w.writeInt(u16, 0, .little);
        try w.writeInt(u16, 0, .little);
        try w.writeInt(u16, 0, .little);
        try w.writeInt(u32, 0, .little);
        try w.writeInt(u32, offsets[i], .little);
        try w.writeAll(m.name);
    }
    const cd_len: u32 = @as(u32, @intCast(list.items.len)) - cd_start;
    try w.writeInt(u32, 0x06054b50, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u16, @intCast(members.len), .little);
    try w.writeInt(u16, @intCast(members.len), .little);
    try w.writeInt(u32, cd_len, .little);
    try w.writeInt(u32, cd_start, .little);
    try w.writeInt(u16, 0, .little);
}

test "zip listing finds the top-level .app bundles" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var z = std.ArrayList(u8).init(a);
    try storedZip(&z, &.{
        .{ .name = "Zeta.app/", .data = "" },
        .{ .name = "Zeta.app/Contents/MacOS/zeta", .data = "\xcf\xfa\xed\xfe" },
        .{ .name = "Alpha Tool.app/Contents/Info.plist", .data = "<plist/>" },
        .{ .name = "__MACOSX/._Zeta.app", .data = "x" },
        .{ .name = "README.txt", .data = "hello" },
        .{ .name = "nested/Inner.app/Contents/Info.plist", .data = "<plist/>" },
        .{ .name = "Zeta.app/Contents/Resources/Helper.app/Contents/Info.plist", .data = "<plist/>" },
    });
    var fbs = std.io.fixedBufferStream(z.items);
    const apps = try zipTopLevelApps(a, fbs.seekableStream());
    try testing.expectEqual(@as(usize, 2), apps.len);
    try testing.expectEqualStrings("Alpha Tool.app", apps[0]);
    try testing.expectEqualStrings("Zeta.app", apps[1]);

    // An archive whose bundle is not at the top level has none for abv0 to link.
    var nested = std.ArrayList(u8).init(a);
    try storedZip(&nested, &.{
        .{ .name = "Thing-1.0/Thing.app/Contents/Info.plist", .data = "<plist/>" },
        .{ .name = "Thing-1.0/README", .data = "x" },
    });
    var fbs2 = std.io.fixedBufferStream(nested.items);
    try testing.expectEqual(@as(usize, 0), (try zipTopLevelApps(a, fbs2.seekableStream())).len);
}

test "an app source: bundle name read from a zip, dmg taken from app=, dmg without app= refused" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var env = try TestEnv.init(a);
    defer env.tmp.cleanup();

    // foo: a universal zip; its bundle is found by listing it.
    var zip = std.ArrayList(u8).init(a);
    try storedZip(&zip, &.{
        .{ .name = "Foo Pro.app/Contents/MacOS/foo", .data = "\xcf\xfa\xed\xfe" },
        .{ .name = "__MACOSX/._Foo Pro.app", .data = "x" },
    });
    const h_zip = hexOf(zip.items);
    const foo_release = try std.fmt.allocPrint(a,
        \\{{"tag_name":"v2.1.0","assets":[
        \\ {{"name":"Foo-2.1.0.zip","browser_download_url":"https://github.com/acme/foo/releases/download/v2.1.0/Foo-2.1.0.zip","size":{d},"digest":"sha256:{s}"}},
        \\ {{"name":"Foo-2.1.0-windows.zip","browser_download_url":"https://github.com/acme/foo/releases/download/v2.1.0/Foo-2.1.0-windows.zip","size":10,"digest":"sha256:{s}"}},
        \\ {{"name":"Foo-2.1.0.AppImage","browser_download_url":"https://github.com/acme/foo/releases/download/v2.1.0/Foo-2.1.0.AppImage","size":10,"digest":"sha256:{s}"}}
        \\]}}
    , .{ zip.items.len, h_zip, h_zip, h_zip });
    try writeTestFile(env.tmp.dir, "fx/acme__foo.release.json", foo_release);
    try writeTestFile(env.tmp.dir, "fx/acme__foo.repo.json", widget_repo_json);
    try writeTestFile(env.tmp.dir, "fx/acme__foo/Foo-2.1.0.zip", zip.items);

    // bar: per-architecture disk images; nothing is downloaded, the line names the app.
    const h_dmg = hexOf("not a real disk image");
    const bar_release = try std.fmt.allocPrint(a,
        \\{{"tag_name":"1.4","assets":[
        \\ {{"name":"Bar-1.4-arm64.dmg","browser_download_url":"https://github.com/acme/bar/releases/download/1.4/Bar-1.4-arm64.dmg","size":99,"digest":"sha256:{s}"}},
        \\ {{"name":"Bar-1.4-x64.dmg","browser_download_url":"https://github.com/acme/bar/releases/download/1.4/Bar-1.4-x64.dmg","size":99,"digest":"sha256:{s}"}}
        \\]}}
    , .{ h_dmg, h_dmg });
    try writeTestFile(env.tmp.dir, "fx/acme__bar.release.json", bar_release);
    try writeTestFile(env.tmp.dir, "fx/acme__bar.repo.json", widget_repo_json);

    // baz: a .dmg and no app= - cannot be listed off macOS, so it is refused.
    const baz_release = try std.fmt.allocPrint(a,
        \\{{"tag_name":"v3","assets":[{{"name":"Baz.dmg","browser_download_url":"https://github.com/acme/baz/releases/download/v3/Baz.dmg","size":99,"digest":"sha256:{s}"}}]}}
    , .{h_dmg});
    try writeTestFile(env.tmp.dir, "fx/acme__baz.release.json", baz_release);
    try writeTestFile(env.tmp.dir, "fx/acme__baz.repo.json", widget_repo_json);

    // qux: a zip whose bundle is one level down.
    var nested = std.ArrayList(u8).init(a);
    try storedZip(&nested, &.{.{ .name = "Qux-1/Qux.app/Contents/Info.plist", .data = "<plist/>" }});
    const qux_release = try std.fmt.allocPrint(a,
        \\{{"tag_name":"v1","assets":[{{"name":"Qux.zip","browser_download_url":"https://github.com/acme/qux/releases/download/v1/Qux.zip","size":99,"digest":"sha256:{s}"}}]}}
    , .{hexOf(nested.items)});
    try writeTestFile(env.tmp.dir, "fx/acme__qux.release.json", qux_release);
    try writeTestFile(env.tmp.dir, "fx/acme__qux.repo.json", widget_repo_json);
    try writeTestFile(env.tmp.dir, "fx/acme__qux/Qux.zip", nested.items);

    try writeTestFile(env.tmp.dir, "sources.txt",
        \\bar acme/bar app="Bar Studio.app"
        \\baz acme/baz kind=app
        \\foo acme/foo kind=app
        \\qux acme/qux kind=app
    );

    var sink = std.ArrayList(u8).init(a);
    const summary = try std.fs.path.join(a, &.{ env.root, "summary.md" });
    const opts = Options{ .sources_path = env.sources, .out_path = env.out, .fixtures_dir = env.fixtures, .jobs = 2, .now_epoch = 1781740800, .quiet = true, .summary_path = summary, .allow_failures = true };
    const r = try execute(testing.allocator, opts, sink.writer());
    try testing.expectEqual(@as(usize, 2), r.new);
    try testing.expectEqual(@as(usize, 2), r.skipped);

    var diags = registry.LoadDiagnostics{};
    var reg = try registry.loadFromJsonFile(testing.allocator, env.out, &diags);
    defer reg.deinit();
    try testing.expectEqual(@as(usize, 0), diags.rejected_packages);
    try testing.expectEqual(@as(usize, 2), reg.count());

    const foo = reg.get("foo").?;
    try testing.expectEqual(@as(usize, 0), foo.bin.len);
    try testing.expectEqual(@as(usize, 1), foo.app_bundles.len);
    try testing.expectEqualStrings("Foo Pro.app", foo.app_bundles[0]);
    try testing.expectEqual(@as(usize, 2), foo.platforms.len); // the Windows zip and the AppImage are not Mac apps
    for (foo.platforms) |p| {
        try testing.expect(std.mem.endsWith(u8, p.name, "-macos"));
        try testing.expectEqualStrings("zip", p.archive_type);
        try testing.expectEqualStrings("", p.bin_path);
        try testing.expectEqualStrings(&h_zip, p.sha256);
    }

    const bar = reg.get("bar").?;
    try testing.expectEqualStrings("Bar Studio.app", bar.app_bundles[0]);
    try testing.expectEqualStrings("1.4", bar.version);
    try testing.expectEqualStrings("dmg", bar.platform("aarch64-macos").?.archive_type);
    try testing.expect(std.mem.indexOf(u8, bar.platform("aarch64-macos").?.url, "arm64") != null);
    try testing.expect(std.mem.indexOf(u8, bar.platform("x86_64-macos").?.url, "x64") != null);

    try testing.expect(std.mem.indexOf(u8, sink.items, "needs app=Name.app") != null);
    try testing.expect(std.mem.indexOf(u8, sink.items, "no .app at its top level") != null);

    // The Markdown report names the failures and the reasons.
    const md = try std.fs.cwd().readFileAlloc(a, summary, 1 << 20);
    try testing.expect(std.mem.indexOf(u8, md, "### Catalog build") != null);
    try testing.expect(std.mem.indexOf(u8, md, "| baz | acme/baz | skipped |") != null);
    try testing.expect(std.mem.indexOf(u8, md, "| qux | acme/qux | skipped |") != null);

    // App entries survive the round trip through --previous: nothing is fetched.
    try env.tmp.dir.deleteTree("fx/acme__foo");
    var again = opts;
    again.out_path = try std.fs.path.join(a, &.{ env.root, "again.json" });
    again.previous_path = env.out;
    again.summary_path = null;
    const second = try execute(testing.allocator, again, sink.writer());
    try testing.expectEqual(@as(usize, 2), second.kept);
    // Only qux, which has no previous entry and fails again, is fetched.
    try testing.expectEqual(@as(u64, nested.items.len), second.bytes);
    try testing.expect(!second.changed);
}

// ---- the real catalog/sources.txt -------------------------------------------

fn readRealSources(a: Allocator) ![]u8 {
    return std.fs.cwd().readFileAlloc(a, "catalog/sources.txt", 8 * 1024 * 1024) catch |e| switch (e) {
        error.FileNotFound => error.SkipZigTest, // not run from the repository root
        else => e,
    };
}

test "catalog/sources.txt parses cleanly with unique names" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const text = try readRealSources(a);
    const parsed = try parseSources(a, text);
    for (parsed.problems) |p| std.debug.print("sources.txt:{d}: {s}\n", .{ p.line, p.text });
    try testing.expectEqual(@as(usize, 0), parsed.problems.len);
    try testing.expect(parsed.sources.len >= 250);

    // parseSources reports a repeat as a problem; this checks the names again,
    // independently of that.
    var seen = std.StringHashMap(void).init(a);
    for (parsed.sources) |s| {
        const slot = try seen.getOrPut(s.name);
        if (slot.found_existing) std.debug.print("duplicate name {s}\n", .{s.name});
        try testing.expect(!slot.found_existing);
    }

    var apps: usize = 0;
    for (parsed.sources) |s| {
        if (s.kind == .app) apps += 1;
    }
    try testing.expect(apps >= 25);
}

test "catalog/sources.txt is sorted within each section" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const text = try readRealSources(a);
    var prev: []const u8 = "";
    var line_no: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        line_no += 1;
        const line = std.mem.trim(u8, raw, " \t\r");
        if (std.mem.startsWith(u8, line, "# ----")) {
            prev = "";
            continue;
        }
        if (line.len == 0 or line[0] == '#') continue;
        const end = std.mem.indexOfAny(u8, line, " \t") orelse line.len;
        const name = line[0..end];
        if (prev.len != 0 and std.mem.order(u8, prev, name) != .lt) {
            std.debug.print("sources.txt:{d}: '{s}' should come before '{s}'\n", .{ line_no, name, prev });
            return error.TestUnexpectedResult;
        }
        prev = name;
    }
}
