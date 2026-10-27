//! Self-building catalog: turns `catalog/sources.txt` into the registry
//! `packages/index.json` by reading each project's official GitHub releases.
//!
//!   build-catalog --sources catalog/sources.txt --out packages/index.json
//!                 [--previous packages/index.json] [--manual catalog/manual.json]
//!                 [--only name,...] [--force] [--jobs N] [--curl]
//!                 [--offline-fixtures dir] [--allow-shrink] [--allow-failures]
//!                 [--max-download-mb N] [--summary report.md]
//!                 [--max-wait-min N] [--etag-cache file] [--no-graphql] [--batch N]
//!
//! For every source line the tool
//!   1. asks the GitHub API for the latest (or the pinned) release. With a token
//!      this is ONE GraphQL query per `--batch` repositories (about 40), carrying
//!      the repository record and the release together; without one (or if
//!      GraphQL fails) it is two REST calls per source,
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
//! package from the catalog.
//!
//! API rate limits are part of the design, not an error. Every response's
//! `x-ratelimit-*` / `retry-after` headers are tracked per bucket (REST,
//! GraphQL). An empty bucket is waited out when its reset is within
//! `--max-wait-min` minutes in total (default 20); otherwise the tool stops
//! calling the API and every source it has not fetched yet keeps its previous
//! entry, reported as "rate limited (carried forward)" and kept apart from real
//! failures. REST GETs are conditional (`--etag-cache`): a 304 costs no quota. The result is deterministic JSON, checked by
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
const api = @import("catalog_api.zig");
const discover = @import("discover.zig");

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
    /// `win=Name.exe` or `win="Display=Name*.exe"`: the program of a portable
    /// Windows build (a .zip that runs where it is unpacked). `*` matches any
    /// run of characters; the name found in the archive is recorded.
    win: []const []const u8 = &.{},
    /// `deps=a,b`: catalog packages this one needs; installed with it.
    deps: []const []const u8 = &.{},
    /// Found by `discover` (catalog/auto-sources.txt), not written by hand.
    /// Such a source is refreshed weekly, may be added at most
    /// `max_new_auto` at a time, and a failure is remembered instead of
    /// reported.
    auto: bool = false,
    /// A vendor source (catalog/vendor.txt): software published on its maker's
    /// own site, not as GitHub releases. Its line names the homepage instead of
    /// owner/repo, and `url.<platform>=` gives each download link.
    vendor: ?Vendor = null,
    line: usize = 0,
};

pub const Vendor = struct {
    homepage: []const u8,
    /// The official download link per platform. It may redirect; `{version}`
    /// is replaced by the version once it is known.
    urls: [6]?[]const u8 = .{null} ** 6,
    /// A page whose text names the current version (a JSON update feed, an
    /// appcast), read when the download links do not carry it.
    version_url: ?[]const u8 = null,
    /// The version is the text right after this marker in the version page
    /// (or in the final download URL when there is no version page).
    version_after: ?[]const u8 = null,
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

    var vendor: ?Vendor = null;
    var spec: ghrelease.Spec = .{ .owner = "", .repo = "", .tag = null };
    if (std.mem.startsWith(u8, toks[1], "https://")) {
        if (!net.isSafeUrl(toks[1])) return bad(arena, "'{s}' is not a usable homepage URL", .{toks[1]});
        vendor = .{ .homepage = toks[1] };
    } else {
        if (std.mem.indexOfScalar(u8, toks[1], '@') != null) {
            return bad(arena, "'{s}': pin a tag with tag=..., not owner/repo@tag", .{toks[1]});
        }
        spec = ghrelease.parseSpec(toks[1]) orelse
            return bad(arena, "'{s}' is not a valid owner/repo", .{toks[1]});
    }

    var src = Source{ .name = name, .owner = spec.owner, .repo = spec.repo, .line = line_no, .vendor = vendor };
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
        } else if (std.mem.eql(u8, key, "deps")) {
            var list = std.ArrayList([]const u8).init(arena);
            var it = std.mem.splitScalar(u8, val, ',');
            while (it.next()) |n| {
                if (!safepath.isValidId(n) or std.mem.eql(u8, n, name)) return bad(arena, "deps '{s}' is not a package name", .{n});
                try list.append(n);
            }
            src.deps = try list.toOwnedSlice();
        } else if (std.mem.eql(u8, key, "win")) {
            var list = std.ArrayList([]const u8).init(arena);
            var it = std.mem.splitScalar(u8, val, ',');
            while (it.next()) |n| {
                if (!isUsableWinPattern(n)) return bad(arena, "win '{s}' is not a usable program name (want Name.exe or Display=Name.exe)", .{n});
                try list.append(n);
            }
            src.win = try list.toOwnedSlice();
        } else if (std.mem.startsWith(u8, key, "url.")) {
            const v = if (src.vendor) |*x| x else return bad(arena, "url.* needs a vendor line (a homepage URL instead of owner/repo)", .{});
            const probe = try std.mem.replaceOwned(u8, arena, val, "{version}", "1.0");
            if (!net.isSafeUrl(probe)) return bad(arena, "'{s}' is not a usable https URL", .{val});
            const plat = key["url.".len..];
            if (std.mem.eql(u8, plat, "macos")) {
                v.urls[platformIndex("aarch64-macos").?] = val;
                v.urls[platformIndex("x86_64-macos").?] = val;
            } else {
                const pi = platformIndex(plat) orelse return bad(arena, "unknown platform in '{s}'", .{key});
                v.urls[pi] = val;
            }
        } else if (std.mem.eql(u8, key, "version-url")) {
            const v = if (src.vendor) |*x| x else return bad(arena, "version-url needs a vendor line", .{});
            if (!net.isSafeUrl(val)) return bad(arena, "'{s}' is not a usable https URL", .{val});
            v.version_url = val;
        } else if (std.mem.eql(u8, key, "version-after")) {
            const v = if (src.vendor) |*x| x else return bad(arena, "version-after needs a vendor line", .{});
            v.version_after = val;
        } else if (std.mem.startsWith(u8, key, "asset.")) {
            const pi = platformIndex(key["asset.".len..]) orelse
                return bad(arena, "unknown platform in '{s}'", .{key});
            src.assets[pi] = val;
        } else {
            return bad(arena, "unknown key '{s}'", .{key});
        }
    }
    // `app=` alone means an app source; `kind=` says it outright.
    src.kind = kind_key orelse if (src.apps.len != 0 or src.win.len != 0) SourceKind.app else SourceKind.cli;
    if (src.kind == .cli and src.apps.len != 0) return bad(arena, "app= needs kind=app", .{});
    if (src.kind == .cli and src.win.len != 0) return bad(arena, "win= needs kind=app", .{});
    if (src.kind == .app and src.bin.len != 0) return bad(arena, "bin= does not apply to kind=app", .{});
    if (src.vendor) |v| {
        var any = false;
        var templated = false;
        for (v.urls) |u| {
            if (u) |x| {
                any = true;
                if (std.mem.indexOf(u8, x, "{version}") != null) templated = true;
            }
        }
        if (!any) return bad(arena, "a vendor line needs at least one url.<platform>=", .{});
        if (templated and v.version_url == null) return bad(arena, "{{version}} in a URL needs version-url=", .{});
        if (v.version_url != null and v.version_after == null) return bad(arena, "version-url needs version-after=", .{});
        if (src.tag != null) return bad(arena, "tag= does not apply to a vendor line", .{});
    }
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
        if (!isUsableAppName(a) and deps.winapp.parseEntry(a) == null) return "app entry is neither a plain Name.app nor a Windows Name.exe";
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
    NotModified,
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
        error.NotModified => "unexpected 304",
        error.Forbidden => "forbidden (403)",
        error.ServerError => "server error (5xx)",
        error.NoFixture => "no offline fixture",
        else => @errorName(e),
    };
}

pub const Mode = enum(u8) { http, curl, fixtures };

const api_origin = "https://api.github.com/";
const graphql_url = api_origin ++ "graphql";

/// One API round trip. `body` makes it a POST of JSON (GraphQL).
pub const ApiRequest = struct {
    url: []const u8,
    body: ?[]const u8 = null,
    if_none_match: ?[]const u8 = null,
};

pub const ApiResponse = struct {
    status: u16,
    body: []const u8,
    info: api.RateInfo = .{},
};

/// Replaces the network for API calls; tests use it to play GitHub.
pub const Transport = struct {
    ctx: ?*anyopaque = null,
    callFn: *const fn (ctx: ?*anyopaque, a: Allocator, req: ApiRequest) anyerror!ApiResponse,
};

/// A record read ahead by a GraphQL batch: REST-shaped JSON, or "it is not there".
const Pre = union(enum) { json: []const u8, missing: []const u8 };

/// Lower-case `owner/repo`, plus `@tag` for a pinned release. GitHub treats
/// owner and repo case-insensitively; a tag is case-sensitive.
fn preKey(a: Allocator, owner: []const u8, repo: []const u8, tag: ?[]const u8) ![]u8 {
    const key = try std.fmt.allocPrint(a, "{s}/{s}{s}{s}", .{ owner, repo, if (tag != null) "@" else "", tag orelse "" });
    const end = owner.len + 1 + repo.len;
    _ = std.ascii.lowerString(key[0..end], key[0..end]);
    return key;
}

pub const Net = struct {
    gpa: Allocator,
    mode: std.atomic.Value(u8),
    token: ?[]const u8,
    fixtures_dir: ?[]const u8,
    tmp_root: []const u8,
    hdr_path: []const u8 = "",
    client: std.http.Client,
    api_calls: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    graphql_calls: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    etag_hits: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    seq: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    switch_mutex: std.Thread.Mutex = .{},

    /// Seconds the whole run may spend waiting for rate limits, shared by both buckets.
    budget: api.Budget = .{ .left_s = 0 },
    rest: api.Limiter = .{ .name = "REST" },
    gql: api.Limiter = .{ .name = "GraphQL" },
    clock: api.Clock = .{},
    transport: ?Transport = null,
    etags: ?*api.EtagCache = null,

    /// Records read ahead by GraphQL; filled once, before any worker starts, and
    /// only read afterwards.
    pre_release: std.StringHashMap(Pre),
    pre_repo: std.StringHashMap(Pre),
    /// Cleared when a GraphQL schema turns out to have no asset `digest`.
    graphql_digest: bool = true,
    graphql_ok: bool = true,

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
            .pre_release = std.StringHashMap(Pre).init(arena),
            .pre_repo = std.StringHashMap(Pre).init(arena),
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

    /// Wires the limiters to the shared wait budget. Call once, after the
    /// `Net` has reached its final address.
    pub fn link(self: *Net, max_wait_s: u64, quiet: bool) void {
        self.budget.left_s = max_wait_s;
        self.rest.budget = &self.budget;
        self.gql.budget = &self.budget;
        self.rest.quiet = quiet;
        self.gql.quiet = quiet;
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

    /// Body of the release record in REST shape: read ahead by a GraphQL batch
    /// when there was one, else `GET /repos/{owner}/{repo}/releases/latest` (or
    /// `/tags/{tag}`).
    pub fn fetchRelease(self: *Net, a: Allocator, owner: []const u8, repo: []const u8, tag: ?[]const u8) ![]const u8 {
        if (self.currentMode() == .fixtures) {
            if (tag) |t| {
                const p = try self.fixturePath(a, "{s}__{s}@{s}.release.json", .{ owner, repo, t });
                if (self.readFixture(a, p)) |d| return d else |_| {}
            }
            const p = try self.fixturePath(a, "{s}__{s}.release.json", .{ owner, repo });
            _ = self.api_calls.fetchAdd(1, .monotonic);
            return self.readFixture(a, p);
        }
        if (self.pre_release.count() != 0) {
            if (self.pre_release.get(try preKey(a, owner, repo, tag))) |p| switch (p) {
                .json => |j| return j,
                .missing => return error.NotFound,
            };
        }
        const url = try ghrelease.apiUrl(a, owner, repo, tag);
        return self.apiGet(a, url);
    }

    /// Body of the repository record in REST shape (GraphQL batch, else `GET /repos/{owner}/{repo}`).
    pub fn fetchRepo(self: *Net, a: Allocator, owner: []const u8, repo: []const u8) ![]const u8 {
        if (self.currentMode() == .fixtures) {
            const p = try self.fixturePath(a, "{s}__{s}.repo.json", .{ owner, repo });
            _ = self.api_calls.fetchAdd(1, .monotonic);
            return self.readFixture(a, p);
        }
        if (self.pre_repo.count() != 0) {
            if (self.pre_repo.get(try preKey(a, owner, repo, null))) |p| switch (p) {
                .json => |j| return j,
                .missing => return error.NotFound,
            };
        }
        const url = try std.fmt.allocPrint(a, "https://api.github.com/repos/{s}/{s}", .{ owner, repo });
        return self.apiGet(a, url);
    }

    /// Why a record the GraphQL batch could not find is missing, if it said.
    pub fn lookupMessage(self: *Net, a: Allocator, owner: []const u8, repo: []const u8, tag: ?[]const u8) ?[]const u8 {
        const key = preKey(a, owner, repo, tag) catch return null;
        const p = self.pre_release.get(key) orelse return null;
        return switch (p) {
            .missing => |m| m,
            .json => null,
        };
    }

    /// A REST GET. Sends `If-None-Match` when the ETag cache knows the URL; a
    /// 304 then serves the cached body and costs no quota.
    fn apiGet(self: *Net, a: Allocator, url: []const u8) ![]const u8 {
        var cached: ?[]u8 = null;
        var inm: ?[]const u8 = null;
        if (self.etags) |c| {
            if (c.lookup(url)) |item| {
                if (c.readBody(a, item)) |b| {
                    cached = b;
                    inm = item.etag;
                }
            }
        }
        const resp = try self.apiExchange(a, &self.rest, .{ .url = url, .if_none_match = inm });
        if (resp.status == 304) {
            const b = cached orelse return error.NotModified;
            _ = self.etag_hits.fetchAdd(1, .monotonic);
            self.etags.?.touch(url);
            return b;
        }
        try statusToError(resp.status);
        if (self.etags) |c| {
            if (resp.info.etag) |e| c.store(url, e, resp.body) catch {};
        }
        return resp.body;
    }

    /// One API request with the rate-limit rules applied: wait first if the
    /// bucket is empty and the reset is near, send, record the headers, and on a
    /// 403/429 that is a limit wait and send again. Returns whatever the server
    /// finally said; `error.RateLimited` means no further calls will be made.
    fn apiExchange(self: *Net, a: Allocator, lim: *api.Limiter, req: ApiRequest) !ApiResponse {
        var tries: u32 = 0;
        while (true) {
            try lim.gate(&self.clock);
            _ = self.api_calls.fetchAdd(1, .monotonic);
            if (lim == &self.gql) _ = self.graphql_calls.fetchAdd(1, .monotonic);
            const resp = try self.withRetry(ApiResponse, a, apiOnce, .{req});
            lim.observe(resp.info, self.clock.now());
            if (resp.status == 403 or resp.status == 429) {
                switch (try lim.limited(resp.status, resp.body, resp.info, &self.clock)) {
                    .retry => {
                        tries += 1;
                        if (tries > 4) return error.RateLimited;
                        continue;
                    },
                    .not_limited => {},
                }
            }
            return resp;
        }
    }

    fn apiOnce(self: *Net, a: Allocator, req: ApiRequest) !ApiResponse {
        if (self.transport) |t| return t.callFn(t.ctx, a, req);
        return switch (self.currentMode()) {
            .http => self.httpApi(a, req),
            else => self.curlApi(a, req),
        };
    }

    // ---- GraphQL batches ----------------------------------------------------

    /// Looks up `reqs` with as few GraphQL queries as possible (`batch` repositories
    /// each) and keeps the answers for `fetchRelease` / `fetchRepo`. Anything
    /// that cannot be answered this way (an error, a release with more assets
    /// than a page holds) is simply left out, and the REST path serves it later.
    pub fn prefetch(self: *Net, arena: Allocator, reqs: []const api.RepoRequest, batch: usize) void {
        const step = @max(batch, 1);
        var i: usize = 0;
        while (i < reqs.len) : (i += step) {
            if (!self.graphql_ok or self.gql.isStopped()) return;
            self.prefetchBatch(arena, reqs[i..@min(reqs.len, i + step)]);
        }
    }

    fn prefetchBatch(self: *Net, arena: Allocator, reqs: []const api.RepoRequest) void {
        var scratch = std.heap.ArenaAllocator.init(self.gpa);
        defer scratch.deinit();
        const a = scratch.allocator();

        var rate_retries: u32 = 0;
        while (true) {
            const query = api.buildQuery(a, reqs, self.graphql_digest) catch |e| {
                std.debug.print("note: GraphQL batch not sent ({s}); using REST for {d} repositories\n", .{ @errorName(e), reqs.len });
                return;
            };
            const body = api.buildRequestBody(a, query) catch return;
            const resp = self.apiExchange(a, &self.gql, .{ .url = graphql_url, .body = body }) catch |e| {
                if (e != error.RateLimited) std.debug.print("note: GraphQL batch of {d} failed ({s}); using REST for those\n", .{ reqs.len, @errorName(e) });
                return;
            };
            if (resp.status == 401) {
                std.debug.print("note: GraphQL rejected the token (401); using REST for the rest of the run\n", .{});
                self.graphql_ok = false;
                return;
            }
            if (resp.status >= 500 or resp.status == 408) return self.splitBatch(arena, reqs, "server error");
            if (resp.status != 200) {
                std.debug.print("note: GraphQL answered HTTP {d}; using REST for {d} repositories\n", .{ resp.status, reqs.len });
                return;
            }
            const parsed = api.parseResponse(a, resp.body, reqs) catch return;
            switch (parsed) {
                .repos => |repos| return self.storePrefetch(arena, reqs, repos),
                .batch_error => |be| switch (be.kind) {
                    .digest_unsupported => {
                        if (!self.graphql_digest) {
                            std.debug.print("note: GraphQL error: {s}; using REST for {d} repositories\n", .{ be.message, reqs.len });
                            return;
                        }
                        std.debug.print("note: this GraphQL schema has no asset digest; asking again without it (checksums files or hashing will pin the assets)\n", .{});
                        self.graphql_digest = false;
                    },
                    .rate_limited => {
                        const r = self.gql.limited(403, "rate limit exceeded", resp.info, &self.clock) catch return;
                        rate_retries += 1;
                        if (r != .retry or rate_retries > 3) return;
                    },
                    .too_big => return self.splitBatch(arena, reqs, be.message),
                    .other => {
                        std.debug.print("note: GraphQL error: {s}; using REST for {d} repositories\n", .{ be.message, reqs.len });
                        return;
                    },
                },
            }
        }
    }

    fn splitBatch(self: *Net, arena: Allocator, reqs: []const api.RepoRequest, why: []const u8) void {
        if (reqs.len <= 1) {
            std.debug.print("note: GraphQL could not answer {s}/{s} ({s}); using REST\n", .{ reqs[0].owner, reqs[0].repo, why });
            return;
        }
        const mid = reqs.len / 2;
        std.debug.print("note: GraphQL batch of {d} failed ({s}); splitting it\n", .{ reqs.len, why });
        self.prefetchBatch(arena, reqs[0..mid]);
        self.prefetchBatch(arena, reqs[mid..]);
    }

    fn storePrefetch(self: *Net, arena: Allocator, reqs: []const api.RepoRequest, repos: []const api.Looked) void {
        for (reqs, repos) |req, looked| {
            self.storeOne(arena, req, looked) catch {};
        }
    }

    fn putPre(arena: Allocator, map: *std.StringHashMap(Pre), key: []const u8, value: Pre) !void {
        const k = try arena.dupe(u8, key);
        const v: Pre = switch (value) {
            .json => |j| .{ .json = try arena.dupe(u8, j) },
            .missing => |m| .{ .missing = try arena.dupe(u8, m) },
        };
        try map.put(k, v);
    }

    fn putRel(self: *Net, arena: Allocator, key: []const u8, rel: api.Rel, absent_msg: []const u8) !void {
        switch (rel) {
            .json => |j| try putPre(arena, &self.pre_release, key, .{ .json = j }),
            .absent => try putPre(arena, &self.pre_release, key, .{ .missing = absent_msg }),
            .truncated => {}, // REST will serve this one
        }
    }

    fn storeOne(self: *Net, arena: Allocator, req: api.RepoRequest, looked: api.Looked) !void {
        const base = try preKey(arena, req.owner, req.repo, null);
        switch (looked.state) {
            .failed => return, // REST will have its say
            .not_found => {
                try putPre(arena, &self.pre_repo, base, .{ .missing = looked.message });
                if (req.want_latest) try putPre(arena, &self.pre_release, base, .{ .missing = looked.message });
                for (req.tags) |t| {
                    const k = try preKey(arena, req.owner, req.repo, t);
                    try putPre(arena, &self.pre_release, k, .{ .missing = looked.message });
                }
            },
            .ok => {
                try putPre(arena, &self.pre_repo, base, .{ .json = looked.repo_json });
                if (req.want_latest) try self.putRel(arena, base, looked.latest, "no published release (the repository has no latest release)");
                for (req.tags, looked.tags) |t, rel| {
                    const k = try preKey(arena, req.owner, req.repo, t);
                    try self.putRel(arena, k, rel, "no release with this tag");
                }
            },
        }
    }

    /// Small text resource (a checksums file). No credentials are sent.
    pub fn fetchText(self: *Net, a: Allocator, url: []const u8, max_bytes: usize) ![]u8 {
        if (!net.isSafeUrl(url)) return error.UnsafeUrl;
        if (self.currentMode() == .fixtures) {
            const p = self.fixtureAssetPath(a, url) catch try self.webFixturePath(a, url);
            return self.readFixture(a, p);
        }
        const body = try self.withRetry([]u8, a, fetchTextOnce, .{ url, max_bytes });
        _ = self.bytes.fetchAdd(body.len, .monotonic);
        return body;
    }

    fn fetchTextOnce(self: *Net, a: Allocator, url: []const u8, max_bytes: usize) ![]u8 {
        return switch (self.currentMode()) {
            .http => self.httpGet(a, url, max_bytes),
            else => blk: {
                const body = try self.curlGet(a, url);
                if (body.len > max_bytes) return error.TooLarge;
                break :blk body;
            },
        };
    }

    fn statusToError(code: u16) !void {
        if (code >= 200 and code < 300) return;
        if (code == 404) return error.NotFound;
        if (code == 403) return error.Forbidden;
        if (code >= 500) return error.ServerError;
        return error.BadStatus;
    }

    fn isStatusError(e: anyerror) bool {
        return switch (e) {
            error.NotFound, error.RateLimited, error.NotModified, error.Forbidden, error.BadStatus, error.TooLarge, error.NoFixture, error.UnsafeUrl, error.OutOfMemory => true,
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

    /// A plain GET of a public file. No credentials are ever sent.
    fn httpGet(self: *Net, a: Allocator, url: []const u8, max_bytes: usize) ![]u8 {
        var body = std.ArrayList(u8).init(a);
        errdefer body.deinit();
        const res = try self.client.fetch(.{
            .location = .{ .url = url },
            .method = .GET,
            .headers = .{ .user_agent = .{ .override = user_agent } },
            .response_storage = .{ .dynamic = &body },
            .max_append_size = max_bytes,
        });
        try statusToError(@intFromEnum(res.status));
        return body.toOwnedSlice();
    }

    /// An API request over std.http, with the response headers kept.
    ///
    /// The token goes out as an ordinary header: this Zig's std.http never
    /// writes `privileged_headers` at all, so using them would silently send
    /// the request anonymously (60 requests an hour instead of 1,000+).
    /// Because an ordinary header would also follow a redirect to another host,
    /// redirects are not left to std.http: one is followed here only when it
    /// stays on the API origin.
    fn httpApi(self: *Net, a: Allocator, req: ApiRequest) !ApiResponse {
        var url = req.url;
        var hops: u8 = 0;
        while (true) {
            const once = try self.httpApiOnce(a, url, req);
            const redirect = switch (once.resp.status) {
                301, 302, 303, 307, 308 => true,
                else => false,
            };
            if (redirect and hops < 3) {
                if (once.location) |loc| {
                    // A POST is only repeated by 307/308; others would turn into a GET.
                    const keeps_method = req.body == null or once.resp.status == 307 or once.resp.status == 308;
                    if (keeps_method and std.mem.startsWith(u8, loc, api_origin)) {
                        url = loc;
                        hops += 1;
                        continue;
                    }
                }
            }
            return once.resp;
        }
    }

    const HttpOnce = struct { resp: ApiResponse, location: ?[]const u8 };

    fn httpApiOnce(self: *Net, a: Allocator, url: []const u8, req: ApiRequest) !HttpOnce {
        const uri = try std.Uri.parse(url);
        var header_buf: [16 * 1024]u8 = undefined;

        var extra = std.ArrayList(std.http.Header).init(a);
        try extra.append(.{ .name = "Accept", .value = "application/vnd.github+json" });
        try extra.append(.{ .name = "X-GitHub-Api-Version", .value = "2022-11-28" });
        if (req.if_none_match) |e| try extra.append(.{ .name = "If-None-Match", .value = e });
        if (self.token) |t| try extra.append(.{ .name = "Authorization", .value = try std.fmt.allocPrint(a, "Bearer {s}", .{t}) });

        var r = try self.client.open(if (req.body != null) .POST else .GET, uri, .{
            .server_header_buffer = &header_buf,
            .redirect_behavior = .unhandled,
            .headers = .{
                .user_agent = .{ .override = user_agent },
                .content_type = if (req.body != null) .{ .override = "application/json" } else .default,
            },
            .extra_headers = extra.items,
        });
        defer r.deinit();
        if (req.body) |b| r.transfer_encoding = .{ .content_length = b.len };
        try r.send();
        if (req.body) |b| try r.writeAll(b);
        try r.finish();
        try r.wait();

        var info = api.RateInfo{};
        var it = r.response.iterateHeaders();
        while (it.next()) |h| api.noteHeader(a, &info, h.name, h.value);
        const location: ?[]const u8 = if (r.response.location) |l| try a.dupe(u8, l) else null;
        var body = std.ArrayList(u8).init(a);
        errdefer body.deinit();
        try r.reader().readAllArrayList(&body, 64 * 1024 * 1024);
        return .{
            .resp = .{ .status = @intFromEnum(r.response.status), .body = try body.toOwnedSlice(), .info = info },
            .location = location,
        };
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
        try statusToError(@intFromEnum(req.response.status));

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
        _ = self;
        // A plain download of a public file must not carry the API token.
        const argv = [_][]const u8{
            "curl",              "-q",            "--silent",    "--show-error",
            "--location",        "--max-redirs",  "5",           "--proto",
            "=https",            "--proto-redir", "=https",      "--tlsv1.2",
            "--connect-timeout", "20",            "--max-time",  "120",
            "--user-agent",      user_agent,      "--write-out", "\n%{http_code}",
            url,
        };
        const res = std.process.Child.run(.{
            .allocator = a,
            .argv = &argv,
            .max_output_bytes = 64 * 1024 * 1024,
        }) catch return error.CurlFailed;
        if (res.term != .Exited or res.term.Exited != 0) return error.CurlFailed;
        const nl = std.mem.lastIndexOfScalar(u8, res.stdout, '\n') orelse return error.CurlFailed;
        const code = std.fmt.parseInt(u16, std.mem.trim(u8, res.stdout[nl + 1 ..], " \r\n"), 10) catch return error.CurlFailed;
        try statusToError(code);
        return res.stdout[0..nl];
    }

    /// An API request through curl. The token and Accept headers come from a
    /// private file (`-H @file`), never from the command line; the response
    /// headers are dumped to a file and read back for the rate-limit fields.
    fn curlApi(self: *Net, a: Allocator, req: ApiRequest) !ApiResponse {
        const n = self.seq.fetchAdd(1, .monotonic);
        const dump_path = try std.fmt.allocPrint(a, "{s}{c}resp{d}.hdr", .{ self.tmp_root, std.fs.path.sep, n });
        defer std.fs.cwd().deleteFile(dump_path) catch {};
        const body_path = try std.fmt.allocPrint(a, "{s}{c}req{d}.json", .{ self.tmp_root, std.fs.path.sep, n });
        defer std.fs.cwd().deleteFile(body_path) catch {};

        var argv = std.ArrayList([]const u8).init(a);
        try argv.appendSlice(&.{
            "curl",              "-q",            "--silent",   "--show-error",
            "--location",        "--max-redirs",  "5",          "--proto",
            "=https",            "--proto-redir", "=https",     "--tlsv1.2",
            "--connect-timeout", "20",            "--max-time", "120",
            "--user-agent",      user_agent,      "-D",         dump_path,
            "-H",
        });
        try argv.append(try std.fmt.allocPrint(a, "@{s}", .{self.hdr_path}));
        if (req.if_none_match) |e| {
            try argv.append("-H");
            try argv.append(try std.fmt.allocPrint(a, "If-None-Match: {s}", .{e}));
        }
        if (req.body) |b| {
            try std.fs.cwd().writeFile(.{ .sub_path = body_path, .data = b });
            try argv.appendSlice(&.{ "-H", "Content-Type: application/json", "--data-binary" });
            try argv.append(try std.fmt.allocPrint(a, "@{s}", .{body_path}));
        }
        try argv.appendSlice(&.{ "--write-out", "\n%{http_code}", req.url });

        const res = std.process.Child.run(.{
            .allocator = a,
            .argv = argv.items,
            .max_output_bytes = 64 * 1024 * 1024,
        }) catch return error.CurlFailed;
        if (res.term != .Exited or res.term.Exited != 0) return error.CurlFailed;
        const nl = std.mem.lastIndexOfScalar(u8, res.stdout, '\n') orelse return error.CurlFailed;
        const code = std.fmt.parseInt(u16, std.mem.trim(u8, res.stdout[nl + 1 ..], " \r\n"), 10) catch return error.CurlFailed;
        const dump = std.fs.cwd().readFileAlloc(a, dump_path, 1024 * 1024) catch "";
        return .{ .status = code, .body = res.stdout[0..nl], .info = api.infoFromHeaderDump(a, dump) };
    }

    // ---- vendor links -----------------------------------------------------

    pub const Resolved = struct {
        /// Where the link lands after its redirects.
        final_url: []const u8,
        disposition: ?[]const u8 = null,
        last_modified: ?[]const u8 = null,
    };

    /// Follows a download link's redirects (https only, at most 10) and reads
    /// the final response's headers without downloading the file. In fixture
    /// mode, `web/<url with / ? & = replaced by _>.resolve` holds
    /// `final-url`, then optional `content-disposition:` and `last-modified:`
    /// lines; without one the link resolves to itself.
    pub fn resolve(self: *Net, a: Allocator, url: []const u8) !Resolved {
        if (!net.isSafeUrl(url)) return error.UnsafeUrl;
        switch (self.currentMode()) {
            .fixtures => {
                const p = try std.fmt.allocPrint(a, "{s}.resolve", .{try self.webFixturePath(a, url)});
                const text = self.readFixture(a, p) catch return .{ .final_url = url };
                var lines = std.mem.splitScalar(u8, text, '\n');
                var r = Resolved{ .final_url = try a.dupe(u8, std.mem.trim(u8, lines.next() orelse url, " \r")) };
                while (lines.next()) |l| {
                    const line = std.mem.trim(u8, l, " \r");
                    if (headerValue(line, "content-disposition")) |v| r.disposition = try a.dupe(u8, v);
                    if (headerValue(line, "last-modified")) |v| r.last_modified = try a.dupe(u8, v);
                }
                return r;
            },
            .http => {
                if (self.httpResolve(a, url)) |r| return r else |e| {
                    if (isStatusError(e) or !self.curlAvailable()) return e;
                    self.switchToCurl(e);
                    return self.curlResolve(a, url);
                }
            },
            else => return self.curlResolve(a, url),
        }
    }

    fn headerValue(line: []const u8, name: []const u8) ?[]const u8 {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return null;
        if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " "), name)) return null;
        return std.mem.trim(u8, line[colon + 1 ..], " \t\r");
    }

    fn webFixturePath(self: *Net, a: Allocator, url: []const u8) ![]u8 {
        const rel = try a.dupe(u8, url["https://".len..]);
        for (rel) |*c| {
            if (c.* == '/' or c.* == '?' or c.* == '&' or c.* == '=' or c.* == ':') c.* = '_';
        }
        return self.fixturePath(a, "web/{s}", .{rel});
    }

    /// The redirect target `location` relative to `base`.
    pub fn joinLocation(a: Allocator, base: []const u8, location: []const u8) ![]u8 {
        if (std.mem.startsWith(u8, location, "https://")) return a.dupe(u8, location);
        if (std.mem.startsWith(u8, location, "http://")) return error.InsecureRedirect;
        const after = base["https://".len..];
        const host_end = "https://".len + (std.mem.indexOfScalar(u8, after, '/') orelse after.len);
        if (std.mem.startsWith(u8, location, "//")) return std.fmt.allocPrint(a, "https:{s}", .{location});
        if (std.mem.startsWith(u8, location, "/")) return std.fmt.allocPrint(a, "{s}{s}", .{ base[0..host_end], location });
        const no_query = base[0 .. std.mem.indexOfAny(u8, base, "?#") orelse base.len];
        const dir_end = if (std.mem.lastIndexOfScalar(u8, no_query, '/')) |i| @max(i + 1, host_end) else host_end;
        if (dir_end == host_end) return std.fmt.allocPrint(a, "{s}/{s}", .{ base[0..host_end], location });
        return std.fmt.allocPrint(a, "{s}{s}", .{ no_query[0..dir_end], location });
    }

    fn httpResolve(self: *Net, a: Allocator, start: []const u8) !Resolved {
        var url = try a.dupe(u8, start);
        var hops: u8 = 0;
        while (true) : (hops += 1) {
            if (hops > 10) return error.TooManyRedirects;
            if (!net.isSafeUrl(url)) return error.UnsafeUrl;
            var header_buf: [32 * 1024]u8 = undefined;
            var req = try self.client.open(.GET, try std.Uri.parse(url), .{
                .server_header_buffer = &header_buf,
                .headers = .{ .user_agent = .{ .override = user_agent } },
                // Ask for one byte: enough for the headers, and servers that
                // ignore Range are not read past them.
                .extra_headers = &.{.{ .name = "Range", .value = "bytes=0-0" }},
                .redirect_behavior = .unhandled,
            });
            defer req.deinit();
            try req.send();
            try req.finish();
            try req.wait();
            const code = @intFromEnum(req.response.status);
            var location: ?[]const u8 = null;
            var r = Resolved{ .final_url = url };
            var it = req.response.iterateHeaders();
            while (it.next()) |h| {
                if (std.ascii.eqlIgnoreCase(h.name, "location")) location = try a.dupe(u8, h.value);
                if (std.ascii.eqlIgnoreCase(h.name, "content-disposition")) r.disposition = try a.dupe(u8, h.value);
                if (std.ascii.eqlIgnoreCase(h.name, "last-modified")) r.last_modified = try a.dupe(u8, h.value);
            }
            switch (code) {
                301, 302, 303, 307, 308 => {
                    url = try joinLocation(a, url, location orelse return error.BadStatus);
                    continue;
                },
                200, 206 => return r,
                else => {
                    try statusToError(code);
                    return error.BadStatus;
                },
            }
        }
    }

    fn curlResolve(self: *Net, a: Allocator, url: []const u8) !Resolved {
        const n = self.seq.fetchAdd(1, .monotonic);
        const sink = try std.fmt.allocPrint(a, "{s}{c}resolve{d}", .{ self.tmp_root, std.fs.path.sep, n });
        defer std.fs.cwd().deleteFile(sink) catch {};
        const argv = [_][]const u8{
            "curl",              "-q",                              "--silent",      "--show-error",
            "--location",        "--max-redirs",                    "10",            "--proto",
            "=https",            "--proto-redir",                   "=https",        "--tlsv1.2",
            "--connect-timeout", "20",                              "--max-time",    "60",
            "--user-agent",      user_agent,                        "--range",       "0-0",
            "--output",          sink,                              "--dump-header", "-",
            "--write-out",       "\n%{http_code} %{url_effective}", url,
        };
        const res = std.process.Child.run(.{ .allocator = a, .argv = &argv, .max_output_bytes = 1024 * 1024 }) catch return error.CurlFailed;
        if (res.term != .Exited or res.term.Exited != 0) return error.CurlFailed;
        const nl = std.mem.lastIndexOfScalar(u8, res.stdout, '\n') orelse return error.CurlFailed;
        const tail = std.mem.trim(u8, res.stdout[nl + 1 ..], " \r\n");
        const sp = std.mem.indexOfScalar(u8, tail, ' ') orelse return error.CurlFailed;
        const code = std.fmt.parseInt(u16, tail[0..sp], 10) catch return error.CurlFailed;
        if (code != 206) try statusToError(code);
        var r = Resolved{ .final_url = try a.dupe(u8, tail[sp + 1 ..]) };
        // Headers of every hop are dumped; the last block is the final response.
        var lines = std.mem.splitScalar(u8, res.stdout[0..nl], '\n');
        while (lines.next()) |l| {
            const line = std.mem.trim(u8, l, " \r");
            if (std.mem.startsWith(u8, line, "HTTP/")) {
                r.disposition = null;
                r.last_modified = null;
            }
            if (headerValue(line, "content-disposition")) |v| r.disposition = try a.dupe(u8, v);
            if (headerValue(line, "last-modified")) |v| r.last_modified = try a.dupe(u8, v);
        }
        return r;
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
        const src = self.fixtureAssetPath(a, url) catch try self.webFixturePath(a, url);
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
    /// Total seconds the run may spend waiting for API rate limits to reset.
    /// A longer wait is not taken: the API is left alone and unfetched sources
    /// keep their previous entries.
    max_wait_s: u64 = default_max_wait_s,
    /// ETag cache index (JSON); the bodies sit in `<path>.bodies/`.
    etag_cache_path: ?[]const u8 = null,
    /// Look repositories up in GraphQL batches when a token is available.
    use_graphql: bool = true,
    /// Repositories per GraphQL query.
    batch_size: usize = default_batch_size,
    /// catalog/vendor.txt: proprietary software downloaded from its maker's
    /// site. Defaults to vendor.txt beside the sources file, if it exists.
    vendor_path: ?[]const u8 = null,
    /// catalog/auto-sources.txt: sources found by `discover`. A name or
    /// repository that is also in `sources_path` or the manual entries is
    /// left out; the hand-written one wins.
    auto_sources_path: ?[]const u8 = null,
    /// Repositories that turned out unusable (`owner/repo day` lines), skipped
    /// for `reject_days` and updated after the run.
    rejects_path: ?[]const u8 = null,
    /// Discovered packages added per run; the rest wait for the next run.
    max_new_auto: usize = 500,
    /// A discovered package is looked at again once in this many days.
    auto_refresh_days: u32 = 7,
    reject_days: u32 = 30,
    /// Test hooks: stand in for the network and the clock.
    transport: ?Transport = null,
    clock: ?api.Clock = null,
};

const default_max_wait_s: u64 = 20 * 60;
const default_batch_size: usize = 40;

const Status = enum { new, updated, kept, stale, skipped, carried, limited, not_selected };

const Result = struct {
    status: Status = .skipped,
    entry: ?Entry = null,
    note: []const u8 = "",
    /// A new discovered package whose programs are named after its owner,
    /// not its repository: published as `owner-repo` (see `nameCheck`).
    rename_to_owner: bool = false,
};

/// Lower-case letters and digits only.
fn squash(buf: []u8, s: []const u8) []const u8 {
    var n: usize = 0;
    for (s) |c| {
        if (n == buf.len) break;
        if (std.ascii.isAlphanumeric(c)) {
            buf[n] = std.ascii.toLower(c);
            n += 1;
        }
    }
    return buf[0..n];
}

/// A program name that belongs to `word` (a repository or owner name): one
/// contains the other, ignoring case and punctuation, with at least three
/// characters in common. `fd` and `fd-find`, `gitea` and `gitea`, `zen` and
/// `zen-browser`; not `chrome-sandbox` and `react-native`.
pub fn relatedName(bin: []const u8, word: []const u8) bool {
    var b1: [128]u8 = undefined;
    var b2: [128]u8 = undefined;
    const b = squash(&b1, bin);
    const w = squash(&b2, word);
    const short = @min(b.len, w.len);
    if (short < 2) return false;
    if (short < 3 and !std.mem.eql(u8, b, w)) return false;
    return std.mem.indexOf(u8, w, b) != null or std.mem.indexOf(u8, b, w) != null;
}

pub const NameCheck = enum { repo, owner, none };

/// Whether a discovered project's programs are named after it. One that
/// ships only helpers (`chrome-sandbox`, `updater`) is not the tool its name
/// promises; one whose programs carry only the owner's name gets `owner-repo`
/// so a generic repository name (`desktop`) is not taken.
pub fn nameCheck(bins: []const []const u8, owner: []const u8, repo: []const u8) NameCheck {
    for (bins) |b| {
        if (relatedName(b, repo)) return .repo;
    }
    for (bins) |b| {
        if (relatedName(b, owner)) return .owner;
    }
    return .none;
}

/// A version at the start of `s`: a digit, then digits, letters and `._+-`,
/// with at least one `.` among the digits, and no trailing punctuation. A
/// leading `v` is skipped. Null when `s` does not start with one.
pub fn versionAt(s: []const u8) ?[]const u8 {
    var t = s;
    if (t.len > 1 and (t[0] == 'v' or t[0] == 'V') and std.ascii.isDigit(t[1])) t = t[1..];
    if (t.len == 0 or !std.ascii.isDigit(t[0])) return null;
    var n: usize = 0;
    var dot = false;
    while (n < t.len and n < 64) : (n += 1) {
        const c = t[n];
        if (c == '.') {
            if (n + 1 >= t.len or !std.ascii.isDigit(t[n + 1])) break;
            dot = true;
        } else if (!std.ascii.isDigit(c)) break;
    }
    if (!dot) return null;
    return t[0..n];
}

/// The first version anywhere in a URL's path (not its host or query), or
/// null: `.../4.53.269/Slack-4.53.269-macOS.dmg` gives `4.53.269`.
pub fn versionInUrl(url: []const u8) ?[]const u8 {
    const after_scheme = url["https://".len..];
    const slash = std.mem.indexOfScalar(u8, after_scheme, '/') orelse return null;
    const path_full = after_scheme[slash..];
    const path = path_full[0 .. std.mem.indexOfAny(u8, path_full, "?#") orelse path_full.len];
    var i: usize = 0;
    while (i < path.len) : (i += 1) {
        const prev_ok = i == 0 or !std.ascii.isAlphanumeric(path[i - 1]) or (path[i] == 'v' or path[i] == 'V');
        if (!prev_ok) continue;
        if (versionAt(path[i..])) |v| return v;
    }
    return null;
}

/// The version right after `marker` in `text`, or null.
pub fn versionAfter(text: []const u8, marker: []const u8) ?[]const u8 {
    const at = std.mem.indexOf(u8, text, marker) orelse return null;
    return versionAt(std.mem.trimLeft(u8, text[at + marker.len ..], " \t"));
}

/// `2026.10.26` from an HTTP date (`Mon, 26 Oct 2026 19:40:18 GMT`): the
/// version of a download whose link and page name none.
pub fn versionFromHttpDate(a: Allocator, date: []const u8) !?[]const u8 {
    var it = std.mem.tokenizeAny(u8, date, " ,");
    _ = it.next() orelse return null; // weekday
    const day = std.fmt.parseInt(u8, it.next() orelse return null, 10) catch return null;
    const mon_s = it.next() orelse return null;
    const year = std.fmt.parseInt(u16, it.next() orelse return null, 10) catch return null;
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    for (months, 1..) |m, k| {
        if (std.ascii.eqlIgnoreCase(m, mon_s)) return try std.fmt.allocPrint(a, "{d}.{d}.{d}", .{ year, k, day });
    }
    return null;
}

/// The file name a download is saved as: `filename=` from Content-Disposition
/// when it has one, else the last part of the URL's path. Null when neither
/// is a usable file name.
pub fn downloadFileName(a: Allocator, final_url: []const u8, disposition: ?[]const u8) !?[]const u8 {
    if (disposition) |d| {
        if (std.ascii.indexOfIgnoreCase(d, "filename=")) |at| {
            var v = std.mem.trim(u8, d[at + "filename=".len ..], " ");
            if (std.mem.indexOfScalar(u8, v, ';')) |semi| v = v[0..semi];
            v = std.mem.trim(u8, v, "\" ");
            // %20 and friends, as in `Postman%20for%20macOS%20(arm64).zip`.
            const out = try a.alloc(u8, v.len);
            var n: usize = 0;
            var k: usize = 0;
            while (k < v.len) : (k += 1) {
                if (v[k] == '%' and k + 2 < v.len) {
                    if (std.fmt.parseInt(u8, v[k + 1 .. k + 3], 16)) |b| {
                        out[n] = b;
                        n += 1;
                        k += 2;
                        continue;
                    } else |_| {}
                }
                out[n] = v[k];
                n += 1;
            }
            const name = std.fs.path.basename(out[0..n]);
            if (isPlainFileName(name)) return name;
        }
    }
    const no_query = final_url[0 .. std.mem.indexOfAny(u8, final_url, "?#") orelse final_url.len];
    const slash = std.mem.lastIndexOfScalar(u8, no_query, '/') orelse return null;
    const name = no_query[slash + 1 ..];
    if (!isPlainFileName(name)) return null;
    return name;
}

fn isPlainFileName(name: []const u8) bool {
    if (name.len == 0 or name.len > 200 or name[0] == '.') return false;
    for (name) |c| {
        if (c < 0x20 or c == 0x7f or c == '/' or c == '\\' or c == ':' or c == '"') return false;
    }
    return true;
}

/// The release a vendor source stands for: one asset per platform whose link
/// was given, named after the file it downloads, and the version from the
/// version page, the final download URL, or the file's Last-Modified date (in
/// that order). A link that redirects to a stable, versioned file is pinned
/// as that file; one that lands on a signed, expiring URL (a query string)
/// stays the original link, which abv0 follows at install time.
pub const VendorRelease = struct {
    rel: ghrelease.Release,
    /// The asset each platform installs (several may share one file).
    pick: [6]?usize,
};

fn vendorRelease(ctx: *Ctx, a: Allocator, src_name: []const u8, v: Vendor) !VendorRelease {
    var version: ?[]const u8 = null;
    if (v.version_url) |vu| {
        const text = try ctx.net.fetchText(a, vu, 4 * 1024 * 1024);
        version = versionAfter(text, v.version_after.?) orelse return error.NoVersionInPage;
    }
    var assets = std.ArrayList(ghrelease.Asset).init(a);
    var pick: [6]?usize = .{null} ** 6;
    var asked = std.ArrayList([]const u8).init(a);
    var last_modified: ?[]const u8 = null;
    for (v.urls, 0..) |maybe, pi| {
        const tmpl = maybe orelse continue;
        const url = if (version) |ver| try std.mem.replaceOwned(u8, a, tmpl, "{version}", ver) else tmpl;
        // One link for several platforms (a universal Mac build) is one file.
        var same: ?usize = null;
        for (asked.items, 0..) |u, k| {
            if (std.mem.eql(u8, u, url)) same = k;
        }
        if (same) |k| {
            pick[pi] = k;
            continue;
        }
        // A platform whose link fails is left out; the others still count.
        const r = ctx.net.resolve(a, url) catch |e| {
            if (e == error.OutOfMemory) return e;
            if (!ctx.opts.quiet) std.debug.print("{s}: {s} link failed ({s}); leaving it out\n", .{ src_name, platform_tags[pi], netErrorName(e) });
            continue;
        };
        const file = (try downloadFileName(a, r.final_url, r.disposition)) orelse {
            if (!ctx.opts.quiet) std.debug.print("{s}: {s} link gives no file name; leaving it out\n", .{ src_name, platform_tags[pi] });
            continue;
        };
        if (version == null) {
            if (v.version_after) |m| {
                version = versionAfter(r.final_url, m);
            } else version = versionInUrl(r.final_url);
        }
        if (last_modified == null) last_modified = r.last_modified;
        const keep_final = std.mem.indexOfAny(u8, r.final_url, "?#") == null and net.isSafeUrl(r.final_url);
        pick[pi] = assets.items.len;
        try asked.append(url);
        try assets.append(.{ .name = file, .url = if (keep_final) r.final_url else url, .size = 0, .sha256 = null });
    }
    if (version == null) {
        if (last_modified) |lm| version = try versionFromHttpDate(a, lm);
    }
    if (assets.items.len == 0) return error.NoWorkingLink;
    const ver = version orelse return error.NoVersion;
    return .{ .rel = .{ .tag = ver, .assets = try assets.toOwnedSlice() }, .pick = pick };
}

const Outcome = union(enum) {
    built: Entry,
    reuse,
    fail: []const u8,
    /// The API rate limit stopped the lookup; not a failure of the source.
    limited,
};

/// The outcome of a lookup that failed with `e`: a rate limit is its own
/// thing, anything else a failure with the reason (and what GitHub said, when
/// a GraphQL batch already knew).
fn lookupFailed(ctx: *Ctx, a: Allocator, src: Source, what: []const u8, e: anyerror) Outcome {
    if (e == error.RateLimited) return .limited;
    const detail = ctx.net.lookupMessage(a, src.owner, src.repo, src.tag);
    return failf(a, "{s} lookup failed: {s}{s}{s}", .{ what, netErrorName(e), if (detail != null) ": " else "", detail orelse "" });
}

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
    /// Sources this run leaves alone (discovered ones outside today's slice or
    /// beyond the per-run limit). Empty means none.
    deferred: []const bool = &.{},
    done: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
};

fn isDeferred(ctx: *const Ctx, i: usize) bool {
    return i < ctx.deferred.len and ctx.deferred[i];
}

/// Which day of the refresh cycle a discovered package is looked at: a stable
/// hash of its name, so the work is spread evenly over the week.
pub fn refreshSlot(name: []const u8, days: u32) u32 {
    if (days <= 1) return 0;
    return @intCast(std.hash.Fnv1a_32.hash(name) % days);
}

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

/// A source pinned with `tag=` whose tag gives the version already in the
/// catalog needs no lookup at all.
fn pinnedUnchanged(opts: Options, src: Source, prev: ?Entry) bool {
    if (opts.force or src.tag == null or prev == null) return false;
    const v = versionFromTag(src.tag.?) orelse return false;
    return std.mem.eql(u8, v, prev.?.version);
}

/// A previous entry can stand in for its source only if the line has not
/// changed what the entry holds: the same dependencies, and Windows programs
/// exactly when the line has `win=`.
fn prevMatchesSource(src: Source, prev: Entry) bool {
    if (src.deps.len != prev.deps.len) return false;
    for (src.deps) |d| {
        if (!containsName(prev.deps, d)) return false;
    }
    var prev_win = false;
    for (prev.app_bundles) |a| {
        if (deps.winapp.parseEntry(a) != null) prev_win = true;
    }
    return prev_win == (src.win.len != 0);
}

fn buildEntry(ctx: *Ctx, a: Allocator, src: Source, prev: ?Entry, index: usize) !Outcome {
    const opts = ctx.opts;

    if (pinnedUnchanged(opts, src, prev) and prevMatchesSource(src, prev.?)) return .reuse;

    var vpick: ?[6]?usize = null;
    const rel: ghrelease.Release = if (src.vendor) |v| blk: {
        const vr = vendorRelease(ctx, a, src.name, v) catch |e|
            return failf(a, "vendor download lookup failed: {s}", .{netErrorName(e)});
        vpick = vr.pick;
        break :blk vr.rel;
    } else blk: {
        const rel_json = ctx.net.fetchRelease(a, src.owner, src.repo, src.tag) catch |e|
            return lookupFailed(ctx, a, src, "release", e);
        break :blk ghrelease.parseRelease(a, rel_json) catch |e|
            return failf(a, "unreadable release data: {s}", .{@errorName(e)});
    };
    const version = versionFromTag(rel.tag) orelse
        return failf(a, "tag '{s}' does not give a valid version", .{rel.tag});

    if (!opts.force) {
        if (prev) |p| {
            if (std.mem.eql(u8, p.version, version) and prevMatchesSource(src, p)) return .reuse;
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
            if (osOfPlatform(i) == .windows) {
                // Windows: only with win=, and only a portable .zip.
                if (src.win.len == 0) continue;
                if (vpick) |vp| if (vp[i] == null) continue;
                const found = if (vpick) |vp| vp[i] else if (src.assets[i]) |want| findAssetNamed(rel.assets, want) else pickWinAppAsset(rel.assets, tag);
                const chosen = found orelse {
                    try notes.writer().print("{s}: no portable .zip (zips:", .{tag});
                    for (rel.assets) |asset| {
                        if (std.ascii.endsWithIgnoreCase(asset.name, ".zip")) try notes.writer().print(" {s}", .{asset.name});
                    }
                    try notes.appendSlice("); ");
                    continue;
                };
                if (!std.ascii.endsWithIgnoreCase(rel.assets[chosen].name, ".zip")) {
                    try notes.writer().print("{s}: {s} is not a .zip; ", .{ tag, rel.assets[chosen].name });
                    continue;
                }
                pick[i] = chosen;
                continue;
            }
            // Otherwise an app source publishes macOS bundles; a line with
            // win= and no app= is for Windows only.
            if (osOfPlatform(i) != .macos) continue;
            if (src.win.len != 0 and src.apps.len == 0) continue;
            if (vpick) |vp| if (vp[i] == null) continue;
            const found = if (vpick) |vp| vp[i] else if (src.assets[i]) |want| findAssetNamed(rel.assets, want) else pickAppAsset(rel.assets, tag, src.apps.len != 0);
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
        const idx = if (vpick) |vp| vp[i] else if (src.assets[i]) |want| findAssetNamed(rel.assets, want) else ghrelease.pickAsset(rel.assets, tag);
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
        // The same scan abv0 runs at install time: a package it would refuse
        // never gets into the catalog.
        const scanned = deps.scan.scanTree(a, x_dir) catch |e| {
            detect_error = try std.fmt.allocPrint(a, "cannot scan {s}: {s}", .{ asset.name, @errorName(e) });
            continue;
        };
        if (scanned.blocked) {
            for (scanned.findings) |f| {
                if (f.strong) return failf(a, "malware scan: {s} ({s})", .{ f.reason, f.file });
            }
            return failf(a, "malware scan blocked {s}", .{asset.name});
        }
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
    // A vendor source has no repository record: its line says it all.
    const info: RepoInfo = if (src.vendor) |v| .{ .homepage = v.homepage, .license = "Proprietary" } else blk: {
        const repo_json = ctx.net.fetchRepo(a, src.owner, src.repo) catch |e|
            return lookupFailed(ctx, a, src, "repository", e);
        break :blk parseRepoInfo(a, repo_json, src.owner, src.repo) catch |e|
            return failf(a, "unreadable repository data: {s}", .{@errorName(e)});
    };

    var description: []const u8 = info.description;
    if (src.desc) |d| description = try cleanText(a, d, max_description_len);
    if (description.len == 0) {
        description = if (src.vendor) |v|
            try std.fmt.allocPrint(a, "{s} ({s})", .{ src.name, v.homepage })
        else
            try std.fmt.allocPrint(a, "{s} (github.com/{s}/{s})", .{ src.name, src.owner, src.repo });
    }
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
        .deps = src.deps,
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

// ---------------------------------------------------------------------------
// Windows portable apps
// ---------------------------------------------------------------------------

/// Words that mark a Windows asset as an installer or something other than a
/// portable build.
const win_reject_tokens = [_][]const u8{
    "setup", "installer", "install", "msi",      "msix",      "appx",    "linux",    "mac",
    "macos", "darwin",    "osx",     "src",      "source",    "sources", "debug",    "symbols",
    "pdb",   "dbg",       "sbom",    "checksum", "checksums", "sha256",  "blockmap", "android",
};
const win_os_tokens = [_][]const u8{ "win", "windows", "win32", "win64", "w64", "msvc", "mingw" };

/// The portable .zip for the Windows `platform_tag` names, or null. It has to
/// say it is for Windows; one that names no architecture counts as x86_64.
pub fn pickWinAppAsset(assets: []const ghrelease.Asset, platform_tag: []const u8) ?usize {
    const want_arm = std.mem.startsWith(u8, platform_tag, "aarch64");
    var best: ?usize = null;
    var best_score: u32 = 0;
    for (assets, 0..) |asset, i| {
        const name = asset.name;
        if (!std.ascii.endsWithIgnoreCase(name, ".zip")) continue;
        // "portable" also marks a Windows build: the reject words below
        // drop any that name another system.
        if (!hasWord(name, &win_os_tokens) and std.ascii.indexOfIgnoreCase(name, "windows") == null and
            std.ascii.indexOfIgnoreCase(name, "win64") == null and std.ascii.indexOfIgnoreCase(name, "win32") == null and
            std.ascii.indexOfIgnoreCase(name, "portable") == null) continue;
        if (hasWord(name, &win_reject_tokens)) continue;
        const arm = hasSubstring(name, &.{ "arm64", "aarch64" });
        const x86 = hasSubstring(name, &.{ "x86_64", "x86-64", "x64", "amd64", "win64" });
        const x86_32 = hasWord(name, &.{ "x86", "i386", "i686", "ia32", "win32", "32bit" }) and !x86;
        if (arm and x86) continue;
        if (arm != want_arm) continue;
        if (!arm and x86_32) continue;
        var score: u32 = if (arm or x86) 100 else 50;
        if (std.ascii.indexOfIgnoreCase(name, "portable") != null) score += 20;
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

/// A `win=` value: `Name.exe` or `Display=Name.exe`, where the file name may
/// hold `*` wildcards.
fn isUsableWinPattern(p: []const u8) bool {
    const eq = std.mem.indexOfScalar(u8, p, '=');
    const file = if (eq) |i| p[i + 1 ..] else p;
    if (eq) |i| {
        if (!deps.winapp.isSafeDisplayName(p[0..i])) return false;
    }
    // With the wildcards replaced, it must be a plain program name.
    var buf: [128]u8 = undefined;
    if (file.len > buf.len) return false;
    for (file, 0..) |c, k| buf[k] = if (c == '*') 'x' else c;
    return deps.winapp.isSafeExeName(buf[0..file.len]);
}

/// `name` matches `pattern`, ignoring case, where `*` matches any run.
fn globMatch(pattern: []const u8, name: []const u8) bool {
    if (pattern.len == 0) return name.len == 0;
    if (pattern[0] == '*') {
        var k: usize = 0;
        while (k <= name.len) : (k += 1) {
            if (globMatch(pattern[1..], name[k..])) return true;
        }
        return false;
    }
    if (name.len == 0 or std.ascii.toLower(pattern[0]) != std.ascii.toLower(name[0])) return false;
    return globMatch(pattern[1..], name[1..]);
}

/// The `app_bundles` entry for one `win=` value, from the file paths in the
/// archive: the shallowest file whose name matches, as `Display=File.exe`.
/// The display name is the one given, else the file's stem, else (with a
/// wildcard) the package name. Null when nothing matches.
fn resolveWinEntry(a: Allocator, pkg_name: []const u8, pattern: []const u8, paths: []const []const u8) !?[]const u8 {
    const eq = std.mem.indexOfScalar(u8, pattern, '=');
    const file_pat = if (eq) |i| pattern[i + 1 ..] else pattern;
    var best: ?[]const u8 = null;
    var best_depth: usize = std.math.maxInt(usize);
    for (paths) |path| {
        if (path.len == 0 or path[path.len - 1] == '/') continue;
        const base = if (std.mem.lastIndexOfScalar(u8, path, '/')) |s| path[s + 1 ..] else path;
        if (!globMatch(file_pat, base)) continue;
        const depth = std.mem.count(u8, path, "/");
        if (depth < best_depth) {
            best = base;
            best_depth = depth;
        }
    }
    const file = best orelse return null;
    if (!deps.winapp.isSafeExeName(file)) return null;
    const display = if (eq) |i|
        pattern[0..i]
    else if (std.mem.indexOfScalar(u8, file_pat, '*') == null)
        file[0 .. file.len - 4]
    else
        pkg_name;
    const entry = try std.fmt.allocPrint(a, "{s}={s}", .{ display, file });
    if (deps.winapp.parseEntry(entry) == null) return null;
    return entry;
}

/// Every file path in a zip archive (forward slashes, as stored).
pub fn zipFileNames(a: Allocator, seekable: anytype) ![]const []const u8 {
    var iter = try std.zip.Iterator(@TypeOf(seekable)).init(seekable);
    var found = std.ArrayList([]const u8).init(a);
    var name_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    while (try iter.next()) |entry| {
        if (entry.filename_len > name_buf.len) continue;
        const name = name_buf[0..entry.filename_len];
        try iter.stream.seekTo(entry.header_zip_offset + @sizeOf(std.zip.CentralDirectoryFileHeader));
        const got = try iter.stream.context.reader().readAll(name);
        if (got != name.len) return error.ZipTruncated;
        const copy = try a.dupe(u8, name);
        std.mem.replaceScalar(u8, copy, '\\', '/');
        try found.append(copy);
    }
    return found.toOwnedSlice();
}

fn zipFileNamesOfFile(a: Allocator, path: []const u8) ![]const []const u8 {
    const f = try std.fs.cwd().openFile(path, .{});
    defer f.close();
    return zipFileNames(a, f.seekableStream());
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
    var win_entries = std.ArrayList([]const u8).init(a);

    for (pick, 0..) |p, pi| {
        const idx = p orelse continue;
        const asset = rel.assets[idx];
        if (osOfPlatform(pi) == .windows) {
            const l = ensureLocal(ctx, a, rel.assets, idx, tmp_dir, locals) catch |e| {
                try notes.writer().print("{s}: cannot download {s} to find its program ({s}); ", .{ platform_tags[pi], asset.name, netErrorName(e) });
                pick[pi] = null;
                continue;
            };
            if (!std.mem.eql(u8, &l.sha, &(shas[pi].?))) {
                return failf(a, "{s}: downloaded file does not match its published SHA-256", .{asset.name});
            }
            const names = zipFileNamesOfFile(a, l.path) catch |e| {
                try notes.writer().print("{s}: cannot read {s} ({s}); ", .{ platform_tags[pi], asset.name, @errorName(e) });
                pick[pi] = null;
                continue;
            };
            for (src.win) |pattern| {
                const entry = resolveWinEntry(a, src.name, pattern, names) catch null orelse {
                    try notes.writer().print("{s}: {s} has no program matching {s}; ", .{ platform_tags[pi], asset.name, pattern });
                    pick[pi] = null;
                    break;
                };
                if (!containsName(win_entries.items, entry)) try win_entries.append(entry);
            }
            continue;
        }
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
    // Mac bundles are needed only when a Mac platform is published.
    var mac_published = false;
    for (pick, 0..) |p, pi| {
        if (p != null and osOfPlatform(pi) == .macos) mac_published = true;
    }
    if (!mac_published) apps = &.{};
    var all = std.ArrayList([]const u8).init(a);
    try all.appendSlice(apps);
    try all.appendSlice(win_entries.items);
    if (plats.items.len == 0 or all.items.len == 0) return failf(a, "no installable app: {s}", .{notes.items});
    // Platforms that were dropped still go to the log.
    if (notes.items.len != 0) std.debug.print("{s}: partial: {s}\n", .{ src.name, notes.items });
    return finishEntry(ctx, a, src, version, &.{}, try all.toOwnedSlice(), try plats.toOwnedSlice());
}

/// The distinct repositories the run will have to look up, merged: a source on
/// the latest release asks for `latestRelease`, one with `tag=` for that tag,
/// and several sources of one repository share a single record. Sources the
/// run will not touch (not selected by --only, or pinned and unchanged) are
/// left out, so a fully current catalog costs no lookups for them.
fn collectLookups(arena: Allocator, ctx: *Ctx) ![]api.RepoRequest {
    const Acc = struct { owner: []const u8, repo: []const u8, latest: bool, tags: std.ArrayList([]const u8) };
    var accs = std.ArrayList(Acc).init(arena);
    var index = std.StringHashMap(usize).init(arena);

    for (ctx.sources, 0..) |src, si| {
        if (isDeferred(ctx, si)) continue;
        if (src.vendor != null) continue;
        if (ctx.only) |only| {
            if (!only.contains(src.name)) continue;
        }
        if (pinnedUnchanged(ctx.opts, src, ctx.prev.get(src.name))) continue;
        const key = try preKey(arena, src.owner, src.repo, null);
        const slot = try index.getOrPut(key);
        if (!slot.found_existing) {
            slot.value_ptr.* = accs.items.len;
            try accs.append(.{ .owner = src.owner, .repo = src.repo, .latest = false, .tags = std.ArrayList([]const u8).init(arena) });
        }
        const acc = &accs.items[slot.value_ptr.*];
        if (src.tag) |t| {
            var dup = false;
            for (acc.tags.items) |x| {
                if (std.mem.eql(u8, x, t)) dup = true;
            }
            if (!dup) try acc.tags.append(t);
        } else acc.latest = true;
    }

    var reqs = std.ArrayList(api.RepoRequest).init(arena);
    for (accs.items) |acc| {
        const r = api.RepoRequest{ .owner = acc.owner, .repo = acc.repo, .want_latest = acc.latest, .tags = acc.tags.items };
        // A name the query builder refuses is left to the REST path, which refuses it too.
        api.validateRequest(arena, r) catch continue;
        try reqs.append(r);
    }
    return reqs.toOwnedSlice();
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

    if (isDeferred(ctx, i)) {
        if (prev) |p| return .{ .status = .kept, .entry = p, .note = "checked weekly" };
        return .{ .status = .not_selected };
    }

    const outcome = buildEntry(ctx, a, src, prev, i) catch |e|
        failf(a, "unexpected error: {s}", .{@errorName(e)});

    switch (outcome) {
        .reuse => return .{ .status = .kept, .entry = prev.?, .note = "unchanged" },
        .built => |e| {
            var rename = false;
            if (src.auto and prev == null) {
                switch (nameCheck(e.bin, src.owner, src.repo)) {
                    .repo => {},
                    .owner => rename = true,
                    .none => {
                        var names = std.ArrayList(u8).init(res);
                        for (e.bin, 0..) |b, k| names.writer().print("{s}{s}", .{ if (k != 0) ", " else "", b }) catch {};
                        return .{ .status = .skipped, .note = std.fmt.allocPrint(res, "none of its programs ({s}) is named after {s}/{s}", .{ names.items, src.owner, src.repo }) catch "no program named after the project" };
                    },
                }
            }
            const cloned = cloneEntry(res, e) catch @panic("out of memory");
            const note: []const u8 = if (prev) |p|
                std.fmt.allocPrint(res, "was {s}", .{p.version}) catch ""
            else
                "";
            return .{ .status = if (prev == null) .new else .updated, .entry = cloned, .note = note, .rename_to_owner = rename };
        },
        .fail => |msg| {
            const m = res.dupe(u8, msg) catch "failed";
            if (prev) |p| return .{ .status = .stale, .entry = p, .note = m };
            return .{ .status = .skipped, .note = m };
        },
        .limited => {
            // Never dropped because of a rate limit: the previous entry stays.
            if (prev) |p| return .{ .status = .limited, .entry = p, .note = "rate limited; previous entry carried forward" };
            return .{ .status = .limited, .note = "rate limited; not in the catalog yet" };
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
    /// Sources the API rate limit kept from being checked. Those with a
    /// previous entry are counted in `packages` too (carried forward).
    limited: usize = 0,
    /// Of `limited`, the ones that had no previous entry to keep.
    limited_missing: usize = 0,
    manual: usize = 0,
    api_calls: usize = 0,
    graphql_calls: usize = 0,
    etag_hits: usize = 0,
    rate_waits: usize = 0,
    rate_waited_s: u64 = 0,
    bytes: u64 = 0,
    changed: bool = false,
    /// Discovered sources: in the run, new this run, failed (remembered in
    /// the rejects file), and left for a later run.
    auto_sources: usize = 0,
    auto_new: usize = 0,
    auto_rejected: usize = 0,
    auto_waiting: usize = 0,
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
    return std.fs.cwd().readFileAlloc(arena, path, 64 * 1024 * 1024) catch |e| switch (e) {
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

const status_order = [_]Status{ .new, .updated, .stale, .skipped, .limited, .kept };

/// `owner/repo day` lines (day = days since the epoch), lower-cased keys.
pub fn parseRejects(arena: Allocator, text: []const u8) !std.StringHashMap(i64) {
    var map = std.StringHashMap(i64).init(arena);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        var it = std.mem.tokenizeAny(u8, line, " \t");
        const repo = it.next() orelse continue;
        const day = std.fmt.parseInt(i64, it.next() orelse continue, 10) catch continue;
        if (ghrelease.parseSpec(repo) == null) continue;
        try map.put(try std.ascii.allocLowerString(arena, repo), day);
    }
    return map;
}

pub fn renderRejects(a: Allocator, map: *const std.StringHashMap(i64)) ![]u8 {
    var keys = std.ArrayList([]const u8).init(a);
    var it = map.keyIterator();
    while (it.next()) |k| try keys.append(k.*);
    std.mem.sort([]const u8, keys.items, {}, struct {
        fn lt(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.order(u8, x, y) == .lt;
        }
    }.lt);
    var out = std.ArrayList(u8).init(a);
    try out.appendSlice("# Discovered repositories without a usable download, retried after a while.\n# owner/repo  day-since-1970\n");
    for (keys.items) |k| try out.writer().print("{s} {d}\n", .{ k, map.get(k).? });
    return out.toOwnedSlice();
}

fn repoKey(a: Allocator, src: Source) ![]u8 {
    const k = try std.fmt.allocPrint(a, "{s}/{s}", .{ src.owner, src.repo });
    return std.ascii.lowerString(k, k);
}

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

    // ---- discovered sources ------------------------------------------------
    const today: i64 = @divFloor(opts.now_epoch orelse std.time.timestamp(), 86400);
    var rejects = std.StringHashMap(i64).init(arena);
    if (opts.rejects_path) |rp| {
        if (try readOptional(arena, rp)) |bytes| rejects = try parseRejects(arena, bytes);
    }
    var all_sources = std.ArrayList(Source).init(arena);
    try all_sources.appendSlice(parsed.sources);
    // Vendor sources (proprietary software from its maker's site). A name that
    // sources.txt already uses stays with sources.txt.
    if (opts.vendor_path) |vp| {
        if (try readOptional(arena, vp)) |bytes| {
            const vparsed = try parseSources(arena, bytes);
            for (vparsed.problems) |pr| try out.print("warning: {s}:{d}: {s}\n", .{ vp, pr.line, pr.text });
            outer: for (vparsed.sources) |src| {
                if (src.vendor == null) {
                    try out.print("warning: {s}:{d}: {s} names owner/repo; GitHub projects belong in sources.txt\n", .{ vp, src.line, src.name });
                    continue;
                }
                for (parsed.sources) |h| {
                    if (std.mem.eql(u8, h.name, src.name)) {
                        try out.print("warning: {s}:{d}: {s} is already in sources.txt\n", .{ vp, src.line, src.name });
                        continue :outer;
                    }
                }
                try all_sources.append(src);
            }
        }
    }
    const hand_count = all_sources.items.len;
    if (opts.auto_sources_path) |ap| {
        if (try readOptional(arena, ap)) |bytes| {
            const auto_parsed = try parseSources(arena, bytes);
            var names = std.StringHashMap(void).init(arena);
            var repos = std.StringHashMap(void).init(arena);
            for (all_sources.items[0..hand_count]) |src| {
                try names.put(src.name, {});
                if (src.vendor == null) try repos.put(try repoKey(arena, src), {});
            }
            for (auto_parsed.sources) |src_in| {
                var src = src_in;
                if (src.kind != .cli) continue;
                if (names.contains(src.name) or manual.contains(src.name)) continue;
                const key = try repoKey(arena, src);
                if (repos.contains(key)) continue;
                if (rejects.get(key)) |day| {
                    // Still in the catalog from before: keep refreshing it.
                    if (today - day < opts.reject_days and !prev_loaded.entries.contains(src.name)) continue;
                }
                try names.put(src.name, {});
                try repos.put(key, {});
                src.auto = true;
                try all_sources.append(src);
            }
        }
    }
    const sources = all_sources.items;

    // Discovered packages: those already in the catalog are looked at on their
    // day of the week; new ones are added `max_new_auto` per run, in file
    // order (the most popular first).
    const deferred = try arena.alloc(bool, sources.len);
    @memset(deferred, false);
    var report = Report{};
    {
        var new_budget = opts.max_new_auto;
        const slot: u32 = @intCast(@mod(today, @as(i64, @max(opts.auto_refresh_days, 1))));
        for (sources, 0..) |src, si| {
            if (!src.auto) continue;
            report.auto_sources += 1;
            if (opts.only.len != 0) continue;
            if (prev_loaded.entries.contains(src.name)) {
                if (!opts.force and refreshSlot(src.name, opts.auto_refresh_days) != slot) deferred[si] = true;
            } else if (new_budget == 0) {
                deferred[si] = true;
                report.auto_waiting += 1;
            } else new_budget -= 1;
        }
    }

    const tmp_root = try tempRoot(arena);
    defer std.fs.cwd().deleteTree(tmp_root) catch {};

    const mode: Mode = if (opts.fixtures_dir != null) .fixtures else if (opts.use_curl) .curl else .http;
    var network = try Net.init(arena, gpa, mode, opts.token, opts.fixtures_dir, tmp_root);
    defer network.deinit();
    network.link(opts.max_wait_s, opts.quiet);
    network.transport = opts.transport;
    if (opts.clock) |c| network.clock = c;

    var etag_cache: api.EtagCache = undefined;
    if (opts.etag_cache_path) |ep| {
        if (mode != .fixtures) {
            etag_cache = try api.EtagCache.load(arena, ep);
            network.etags = &etag_cache;
        }
    }

    const results = try arena.alloc(Result, sources.len);
    @memset(results, .{});
    const arenas = try arena.alloc(std.heap.ArenaAllocator, sources.len);
    for (arenas) |*x| x.* = std.heap.ArenaAllocator.init(gpa);
    defer for (arenas) |*x| x.deinit();

    var ctx = Ctx{
        .gpa = gpa,
        .opts = opts,
        .net = &network,
        .sources = sources,
        .prev = &prev_loaded.entries,
        .only = if (opts.only.len != 0) &only_set else null,
        .results = results,
        .arenas = arenas,
        .tmp_root = tmp_root,
        .deferred = deferred,
    };

    // One GraphQL query per batch of repositories replaces two REST calls per
    // source. Only with a token (GraphQL refuses anonymous requests) and a real network.
    if (opts.use_graphql and opts.token != null and mode != .fixtures) {
        const reqs = try collectLookups(arena, &ctx);
        if (reqs.len != 0) {
            network.prefetch(arena, reqs, opts.batch_size);
            if (!opts.quiet) try out.print("GraphQL: {d} repositories, {d} queries, {d} release records read ahead\n", .{
                reqs.len,
                network.graphql_calls.load(.monotonic),
                network.pre_release.count(),
            });
        }
    }

    if (opts.jobs <= 1 or sources.len <= 1) {
        for (0..sources.len) |i| runTask(&ctx, i);
    } else {
        var pool: std.Thread.Pool = undefined;
        try pool.init(.{ .allocator = gpa, .n_jobs = @intCast(@min(opts.jobs, sources.len)) });
        defer pool.deinit();
        var wg: std.Thread.WaitGroup = .{};
        for (0..sources.len) |i| pool.spawnWg(&wg, runTask, .{ &ctx, i });
        wg.wait();
    }

    if (network.etags) |c| c.save() catch |e| {
        try out.print("warning: cannot save the ETag cache {s}: {s}\n", .{ opts.etag_cache_path.?, @errorName(e) });
    };

    // ---- assemble ----------------------------------------------------------
    var entries = std.ArrayList(Entry).init(arena);
    var in_sources = std.StringHashMap(void).init(arena);
    // Discovered packages that take `owner-repo` instead of the repository
    // name; written back into the auto-sources file so the name sticks.
    var used = std.StringHashMap(void).init(arena);
    for (sources) |src| try used.put(src.name, {});
    var mk = manual.keyIterator();
    while (mk.next()) |k| try used.put(k.*, {});
    const Rename = struct { old: []const u8, new: []const u8, repo: []const u8 };
    var renames = std.ArrayList(Rename).init(arena);
    for (sources, results) |src, *r| {
        if (!r.rename_to_owner or r.entry == null) continue;
        const long = try std.fmt.allocPrint(arena, "{s}-{s}", .{ src.owner, src.repo });
        const new = std.ascii.lowerString(long, long);
        if (!safepath.isValidId(new) or used.contains(new)) continue;
        try used.put(new, {});
        r.entry.?.name = new;
        try renames.append(.{ .old = src.name, .new = new, .repo = try std.fmt.allocPrint(arena, "{s}/{s}", .{ src.owner, src.repo }) });
    }
    for (sources, results) |src, r| {
        try in_sources.put(if (r.entry) |e| e.name else src.name, {});
        if (src.auto) {
            if (r.status == .new) report.auto_new += 1;
            if (r.status == .skipped) {
                report.auto_rejected += 1;
                try rejects.put(try repoKey(arena, src), today);
            }
        }
        switch (r.status) {
            .new => report.new += 1,
            .updated => report.updated += 1,
            .kept => report.kept += 1,
            .stale => report.stale += 1,
            .skipped => report.skipped += 1,
            .carried => report.carried += 1,
            .limited => {
                report.limited += 1;
                if (r.entry == null) report.limited_missing += 1;
            },
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

    try printSummary(out, sources, results, opts.only.len != 0);

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
    report.graphql_calls = network.graphql_calls.load(.monotonic);
    report.etag_hits = network.etag_hits.load(.monotonic);
    report.rate_waits = network.rest.waits + network.gql.waits;
    report.rate_waited_s = network.rest.waited_s + network.gql.waited_s;
    report.bytes = network.bytes.load(.monotonic);

    // Written before the guards, so a run that refuses to publish still says why.
    if (opts.summary_path) |sp| {
        var md = std.ArrayList(u8).init(arena);
        const fetch_secs = @as(f64, @floatFromInt(timer.read())) / 1e9;
        writeSummaryMarkdown(md.writer(), entries.items, sources, results, report, fetch_secs, opts.jobs) catch {};
        std.fs.cwd().writeFile(.{ .sub_path = sp, .data = md.items }) catch |e| {
            try out.print("warning: cannot write {s}: {s}\n", .{ sp, @errorName(e) });
        };
    }

    // ---- guards: never publish an empty or collapsed catalog ---------------
    if (entries.items.len == 0) {
        try out.print("error: no packages were produced; leaving {s} untouched\n", .{opts.out_path});
        return error.EmptyCatalog;
    }
    // A network outage fails nearly every source. The old entries would
    // survive as "stale", but a green run that updated nothing would hide the
    // problem, so it is an error instead. A rate limit is not counted here:
    // those sources are carried forward and reported on their own.
    // Discovered sources are left out: many of them fail by nature (no
    // download for any platform), which says nothing about the network.
    var attempted: usize = 0;
    var failed: usize = 0;
    for (sources, results) |src, r| {
        if (src.auto) continue;
        switch (r.status) {
            .new, .updated, .kept => attempted += 1,
            .stale, .skipped => {
                attempted += 1;
                failed += 1;
            },
            else => {},
        }
    }
    if (!opts.allow_failures and attempted >= 10 and failed * 2 > attempted) {
        try out.print("error: {d} of {d} sources failed (network?); not writing {s} (use --allow-failures)\n", .{ failed, attempted, opts.out_path });
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

    if (renames.items.len != 0) {
        if (opts.auto_sources_path) |ap| {
            const text_in = try std.fs.cwd().readFileAlloc(arena, ap, 64 * 1024 * 1024);
            var rewritten = std.ArrayList(u8).init(arena);
            var lit = std.mem.splitScalar(u8, text_in, '\n');
            var first_line = true;
            while (lit.next()) |line| {
                if (!first_line) try rewritten.append('\n');
                first_line = false;
                var toks = std.mem.tokenizeAny(u8, line, " \t");
                const n0 = toks.next() orelse "";
                const r0 = toks.next() orelse "";
                var replaced = false;
                for (renames.items) |rn| {
                    if (std.mem.eql(u8, n0, rn.old) and std.mem.eql(u8, r0, rn.repo)) {
                        try rewritten.writer().print("{s} {s}", .{ rn.new, rn.repo });
                        replaced = true;
                        break;
                    }
                }
                if (!replaced) try rewritten.appendSlice(line);
            }
            std.fs.cwd().writeFile(.{ .sub_path = ap, .data = rewritten.items }) catch |e| {
                try out.print("warning: cannot write {s}: {s}\n", .{ ap, @errorName(e) });
            };
        }
        for (renames.items) |rn| try out.print("named {s} for {s}: its programs carry the owner's name\n", .{ rn.new, rn.repo });
    }
    if (opts.rejects_path) |rp| {
        // Old rejects expire, so a project that starts publishing builds is
        // found again; one that is in the catalog now is no longer a reject.
        var keep = std.StringHashMap(i64).init(arena);
        var rit = rejects.iterator();
        while (rit.next()) |kv| {
            if (today - kv.value_ptr.* < opts.reject_days) try keep.put(kv.key_ptr.*, kv.value_ptr.*);
        }
        for (sources, results) |src, r| {
            if (r.entry != null) _ = keep.remove(try repoKey(arena, src));
        }
        std.fs.cwd().writeFile(.{ .sub_path = rp, .data = try renderRejects(arena, &keep) }) catch |e| {
            try out.print("warning: cannot write {s}: {s}\n", .{ rp, @errorName(e) });
        };
    }
    if (report.auto_sources != 0) {
        try out.print("discovered: {d} sources, {d} added this run, {d} without a usable download (remembered for {d} days), {d} waiting for a later run\n", .{
            report.auto_sources, report.auto_new, report.auto_rejected, opts.reject_days, report.auto_waiting,
        });
    }

    const secs = @as(f64, @floatFromInt(timer.read())) / 1e9;
    try out.print(
        "\n{d} packages in {s} ({s}): {d} new, {d} updated, {d} kept, {d} carried, {d} stale, {d} skipped, {d} rate limited, {d} manual\n" ++
            "API calls: {d} ({d} GraphQL, {d} REST, {d} not modified)   waited for rate limits: {d} s   downloaded: {d:.1} MB   time: {d:.1}s ({d} jobs)   registry check: 0 rejected\n",
        .{
            report.packages,                                                             opts.out_path,
            if (report.changed) "changed" else "unchanged",                              report.new,
            report.updated,                                                              report.kept,
            report.carried,                                                              report.stale,
            report.skipped,                                                              report.limited,
            report.manual,                                                               report.api_calls,
            report.graphql_calls,                                                        report.api_calls -| report.graphql_calls,
            report.etag_hits,                                                            report.rate_waited_s,
            @as(f64, @floatFromInt(report.bytes)) / 1048576.0,                           secs,
            if (opts.jobs <= 1 or sources.len <= 1) 1 else @min(opts.jobs, sources.len),
        },
    );
    if (report.limited != 0) {
        try out.print("warning: the GitHub API rate limit stopped {d} lookups; {d} of them keep their previous entry (carried forward), {d} are not in the catalog yet. They are retried on the next run.\n", .{
            report.limited, report.limited - report.limited_missing, report.limited_missing,
        });
    }
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
    try w.print("| Rate limited, carried forward (not a failure) | {d} |\n", .{report.limited - report.limited_missing});
    try w.print("| Rate limited, not in the catalog yet | {d} |\n", .{report.limited_missing});
    try w.print("| GitHub API calls | {d} ({d} GraphQL, {d} REST, {d} not modified) |\n", .{ report.api_calls, report.graphql_calls, report.api_calls -| report.graphql_calls, report.etag_hits });
    try w.print("| Waited for rate limits | {d} s in {d} pauses |\n", .{ report.rate_waited_s, report.rate_waits });
    try w.print("| Downloaded | {d:.1} MB |\n", .{@as(f64, @floatFromInt(report.bytes)) / 1048576.0});
    try w.print("| Time | {d:.1} s with {d} jobs |\n\n", .{ secs, jobs });

    if (report.limited != 0) {
        try w.print("#### Rate limited ({d})\n\nThe GitHub API rate limit stopped these lookups. This is not a failure of the projects: ", .{report.limited});
        try w.writeAll("each one keeps its previous catalog entry and is checked again on the next run.\n\n| Package | Source | Status |\n| :--- | :--- | :--- |\n");
        for (sources, results) |src, r| {
            if (r.status != .limited) continue;
            try w.print("| {s} | {s}/{s} | {s} |\n", .{ src.name, src.owner, src.repo, if (r.entry != null) "carried forward" else "not in the catalog yet" });
        }
        try w.writeAll("\n");
    }

    if (report.auto_sources != 0) {
        try w.print("#### Discovered projects\n\n{d} in the run, {d} added, {d} without a usable download (retried later), {d} waiting for a later run.\n\n", .{
            report.auto_sources, report.auto_new, report.auto_rejected, report.auto_waiting,
        });
    }
    const listed = report.stale + report.skipped -| report.auto_rejected;
    if (listed == 0) {
        try w.writeAll("No source failed.\n");
        return;
    }
    try w.print("#### Failures ({d})\n\n| Package | Source | Outcome | Reason |\n| :--- | :--- | :--- | :--- |\n", .{listed});
    for (sources, results) |src, r| {
        if (r.status != .stale and r.status != .skipped) continue;
        if (src.auto and r.status == .skipped) continue;
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
            // Discovered projects without a build are normal; they are counted.
            if (src.auto and (st == .skipped or st == .not_selected)) continue;
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
    \\       build-catalog discover --out catalog/auto-sources.txt [--min-stars 500]
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
    \\  --max-wait-min N        total minutes to wait for GitHub rate limits to reset
    \\                          (default 20). A longer wait is not taken: API calls stop
    \\                          and unfetched sources keep their previous entries
    \\  --etag-cache FILE       remember REST ETags/bodies (JSON index; bodies in
    \\                          FILE.bodies/) so unchanged records cost no quota
    \\  --batch N               repositories per GraphQL query (default 40)
    \\  --no-graphql            use the REST API only, two calls per source
    \\  --max-download-mb N     skip assets larger than this when they must be fetched
    \\  --allow-shrink          allow the catalog to lose more than half its packages
    \\  --allow-failures        write the catalog even when most sources failed
    \\  --vendor FILE           proprietary software from its maker's site (default: vendor.txt
    \\                          beside the sources file): `name https://homepage url.<platform>=...`
    \\  --auto-sources FILE     also build the projects `discover` found (catalog/auto-sources.txt);
    \\                          a hand-written source with the same name or repository wins
    \\  --rejects FILE          discovered repositories with no usable download, skipped for
    \\                          30 days; updated after the run
    \\  --max-new-auto N        discovered packages added per run (default 500); each one
    \\                          already in the catalog is looked at once a week
    \\
    \\Reads GITHUB_TOKEN from the environment: it raises the REST limit and enables
    \\the batched GraphQL lookups, which need a token.
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
    if (argv.len > 1 and std.mem.eql(u8, argv[1], "discover")) return discover.main(gpa, argv[2..]);
    var sources: ?[]const u8 = null;
    var out_path: ?[]const u8 = null;
    var opts = Options{ .sources_path = "", .out_path = "" };
    var only = std.ArrayList([]const u8).init(gpa);

    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        const value_opts = [_][]const u8{ "--sources", "--out", "--previous", "--manual", "--only", "--offline-fixtures", "--jobs", "--max-download-mb", "--summary", "--max-wait-min", "--etag-cache", "--batch", "--auto-sources", "--rejects", "--max-new-auto", "--vendor" };
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
        } else if (std.mem.eql(u8, arg, "--vendor")) {
            opts.vendor_path = value;
        } else if (std.mem.eql(u8, arg, "--auto-sources")) {
            opts.auto_sources_path = value;
        } else if (std.mem.eql(u8, arg, "--rejects")) {
            opts.rejects_path = value;
        } else if (std.mem.eql(u8, arg, "--max-new-auto")) {
            opts.max_new_auto = std.fmt.parseInt(usize, value, 10) catch die("--max-new-auto wants a number", .{});
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
        } else if (std.mem.eql(u8, arg, "--max-wait-min")) {
            const min = std.fmt.parseInt(u64, value, 10) catch die("--max-wait-min wants a number of minutes", .{});
            opts.max_wait_s = min *| 60;
        } else if (std.mem.eql(u8, arg, "--etag-cache")) {
            opts.etag_cache_path = value;
        } else if (std.mem.eql(u8, arg, "--batch")) {
            opts.batch_size = std.fmt.parseInt(usize, value, 10) catch die("--batch wants a number", .{});
            if (opts.batch_size == 0) opts.batch_size = 1;
        } else if (std.mem.eql(u8, arg, "--no-graphql")) {
            opts.use_graphql = false;
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
    if (opts.vendor_path == null) {
        const dir = std.fs.path.dirname(opts.sources_path) orelse ".";
        opts.vendor_path = try std.fs.path.join(gpa, &.{ dir, "vendor.txt" });
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

test {
    // The unit tests of the pure API helpers live in their own file.
    _ = api;
}

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

test "discovered sources: hand-written wins, a daily limit, failures remembered" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var env = try TestEnv.init(a);
    defer env.tmp.cleanup();

    const bytes = "binary";
    const h = hexOf(bytes);
    for ([_][]const u8{ "widget", "gizmo" }) |n| {
        try writeTestFile(env.tmp.dir, try std.fmt.allocPrint(a, "fx/acme__{s}.release.json", .{n}), try std.fmt.allocPrint(a,
            \\{{"tag_name":"v1.0.0","assets":[{{"name":"{s}-linux-amd64","browser_download_url":"https://github.com/acme/{s}/releases/download/v1.0.0/{s}-linux-amd64","size":6,"digest":"sha256:{s}"}}]}}
        , .{ n, n, n, &h }));
        try writeTestFile(env.tmp.dir, try std.fmt.allocPrint(a, "fx/acme__{s}.repo.json", .{n}), widget_repo_json);
        try writeTestFile(env.tmp.dir, try std.fmt.allocPrint(a, "fx/acme__{s}/{s}-linux-amd64", .{ n, n }), bytes);
    }
    try writeTestFile(env.tmp.dir, "sources.txt", "widget acme/widget bin=widget\n");
    // A name clash and a repository clash with sources.txt are dropped;
    // gizmo builds; twelve projects without a release fail.
    var auto = std.ArrayList(u8).init(a);
    try auto.appendSlice("widget someone/widget\nwidget2 acme/widget\ngizmo acme/gizmo\n");
    for (0..12) |i| try auto.writer().print("dud{d} acme/dud{d}\n", .{ i, i });
    try writeTestFile(env.tmp.dir, "auto.txt", auto.items);
    const auto_path = try std.fs.path.join(a, &.{ env.root, "auto.txt" });
    const rejects_path = try std.fs.path.join(a, &.{ env.root, "rejects.txt" });

    var sink = std.ArrayList(u8).init(a);
    var opts = Options{ .sources_path = env.sources, .out_path = env.out, .fixtures_dir = env.fixtures, .jobs = 1, .now_epoch = 1781740800, .quiet = true };
    opts.auto_sources_path = auto_path;
    opts.rejects_path = rejects_path;

    // One new discovered package per run: only gizmo is tried.
    opts.max_new_auto = 1;
    const r1 = try execute(testing.allocator, opts, sink.writer());
    try testing.expectEqual(@as(usize, 13), r1.auto_sources);
    try testing.expectEqual(@as(usize, 1), r1.auto_new);
    try testing.expectEqual(@as(usize, 12), r1.auto_waiting);
    try testing.expectEqual(@as(usize, 2), r1.packages);

    // With room for all, the twelve failures do not stop the run (they say
    // nothing about the network) and are written to the rejects file.
    opts.max_new_auto = 100;
    opts.previous_path = env.out;
    opts.out_path = try std.fs.path.join(a, &.{ env.root, "second.json" });
    const r2 = try execute(testing.allocator, opts, sink.writer());
    try testing.expectEqual(@as(usize, 12), r2.auto_rejected);
    try testing.expectEqual(@as(usize, 2), r2.packages);
    const rejects = try std.fs.cwd().readFileAlloc(a, rejects_path, 1 << 20);
    try testing.expect(std.mem.indexOf(u8, rejects, "acme/dud0 ") != null);
    try testing.expect(std.mem.indexOf(u8, rejects, "acme/gizmo") == null);

    // The next run leaves them alone, and gizmo stays in the catalog.
    opts.previous_path = opts.out_path;
    opts.out_path = try std.fs.path.join(a, &.{ env.root, "third.json" });
    const r3 = try execute(testing.allocator, opts, sink.writer());
    try testing.expectEqual(@as(usize, 1), r3.auto_sources);
    try testing.expectEqual(@as(usize, 0), r3.auto_rejected);
    var reg = try registry.loadFromJsonFile(testing.allocator, opts.out_path, null);
    defer reg.deinit();
    try testing.expect(reg.get("gizmo") != null);
    try testing.expect(reg.get("widget2") == null);

    // A month later they are tried again.
    opts.now_epoch = 1781740800 + 31 * 86400;
    opts.previous_path = opts.out_path;
    opts.out_path = try std.fs.path.join(a, &.{ env.root, "fourth.json" });
    const r4 = try execute(testing.allocator, opts, sink.writer());
    try testing.expectEqual(@as(usize, 13), r4.auto_sources);
}

test "a discovered package named after its owner's program becomes owner-repo, and the name sticks" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var env = try TestEnv.init(a);
    defer env.tmp.cleanup();
    try env.tmp.dir.makePath("fx/zen__desktop");
    try env.tmp.dir.makePath("fx/facebook__native");

    // zen/desktop ships `zen`; facebook/native ships only a sandbox helper.
    const Pkg = struct { owner: []const u8, repo: []const u8, member: []const u8 };
    for ([_]Pkg{ .{ .owner = "zen", .repo = "desktop", .member = "zen-1.0/zen" }, .{ .owner = "facebook", .repo = "native", .member = "native-1.0/chrome-sandbox" } }) |pk| {
        var tar = std.ArrayList(u8).init(a);
        try tarMember(&tar, pk.member, 0o755, "\x7fELF program");
        try tar.appendNTimes(0, 1024);
        const h = hexOf(tar.items);
        const asset = try std.fmt.allocPrint(a, "{s}-1.0-x86_64-unknown-linux-gnu.tar", .{pk.repo});
        try writeTestFile(env.tmp.dir, try std.fmt.allocPrint(a, "fx/{s}__{s}.release.json", .{ pk.owner, pk.repo }), try std.fmt.allocPrint(a,
            \\{{"tag_name":"v1.0.0","assets":[{{"name":"{s}","browser_download_url":"https://github.com/{s}/{s}/releases/download/v1.0.0/{s}","size":{d},"digest":"sha256:{s}"}}]}}
        , .{ asset, pk.owner, pk.repo, asset, tar.items.len, &h }));
        try writeTestFile(env.tmp.dir, try std.fmt.allocPrint(a, "fx/{s}__{s}.repo.json", .{ pk.owner, pk.repo }), widget_repo_json);
        try writeTestFile(env.tmp.dir, try std.fmt.allocPrint(a, "fx/{s}__{s}/{s}", .{ pk.owner, pk.repo, asset }), tar.items);
    }
    try writeTestFile(env.tmp.dir, "sources.txt", "");
    try writeTestFile(env.tmp.dir, "auto.txt", "# list\ndesktop zen/desktop\nnative facebook/native\n");

    var sink = std.ArrayList(u8).init(a);
    var opts = Options{ .sources_path = env.sources, .out_path = env.out, .fixtures_dir = env.fixtures, .jobs = 1, .now_epoch = 1781740800, .quiet = true };
    opts.auto_sources_path = try std.fs.path.join(a, &.{ env.root, "auto.txt" });
    opts.rejects_path = try std.fs.path.join(a, &.{ env.root, "rejects.txt" });
    const r = try execute(testing.allocator, opts, sink.writer());
    try testing.expectEqual(@as(usize, 1), r.packages);
    try testing.expectEqual(@as(usize, 1), r.auto_rejected);

    var reg = try registry.loadFromJsonFile(testing.allocator, env.out, null);
    defer reg.deinit();
    try testing.expect(reg.get("zen-desktop") != null);
    try testing.expect(reg.get("desktop") == null);
    // The list now carries the new name, so the next run finds the entry.
    const list = try std.fs.cwd().readFileAlloc(a, opts.auto_sources_path.?, 1 << 20);
    try testing.expectEqualStrings("# list\nzen-desktop zen/desktop\nnative facebook/native\n", list);
    const rejects = try std.fs.cwd().readFileAlloc(a, opts.rejects_path.?, 1 << 20);
    try testing.expect(std.mem.indexOf(u8, rejects, "facebook/native ") != null);

    opts.previous_path = env.out;
    opts.out_path = try std.fs.path.join(a, &.{ env.root, "second.json" });
    const r2 = try execute(testing.allocator, opts, sink.writer());
    try testing.expectEqual(@as(usize, 0), r2.auto_new);
    try testing.expectEqual(@as(usize, 1), r2.packages);
}

test "nameCheck: programs must be named after the project" {
    try testing.expectEqual(NameCheck.repo, nameCheck(&.{"gitea"}, "go-gitea", "gitea"));
    try testing.expectEqual(NameCheck.repo, nameCheck(&.{ "rg", "ripgrep" }, "BurntSushi", "ripgrep"));
    try testing.expectEqual(NameCheck.repo, nameCheck(&.{"fd"}, "sharkdp", "fd"));
    try testing.expectEqual(NameCheck.owner, nameCheck(&.{ "zen", "updater" }, "zen-browser", "desktop"));
    try testing.expectEqual(NameCheck.none, nameCheck(&.{ "chrome-sandbox", "chrome_crashpad_handler" }, "facebook", "react-native"));
    try testing.expectEqual(NameCheck.none, nameCheck(&.{"forc"}, "FuelLabs", "sway"));
    try testing.expect(!relatedName("a", "abc"));
    try testing.expect(!relatedName("go", "gogs"));
    try testing.expect(relatedName("gh", "gh"));
}

test "vendor lines: homepage instead of owner/repo, url.<platform>, version page" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const parsed = try parseSources(a,
        \\chrome https://www.google.com/chrome/ url.macos=https://dl.google.com/x.dmg "app=Google Chrome.app" version-url=https://v.example.com/feed "version-after=\"version\": \""
        \\tf https://www.hashicorp.com url.x86_64-linux=https://r.example.com/tf/{version}/tf_{version}_linux_amd64.zip version-url=https://api.example.com/tf "version-after=\"version\":\"" bin=tf
        \\nolink https://example.com
        \\notemplate https://example.com url.x86_64-linux=https://r.example.com/{version}.zip
        \\gh owner/repo url.x86_64-linux=https://example.com/x.zip
        \\badurl https://example.com url.x86_64-linux=http://example.com/x.zip
        \\
    );
    try testing.expectEqual(@as(usize, 2), parsed.sources.len);
    try testing.expectEqual(@as(usize, 4), parsed.problems.len);
    const chrome = parsed.sources[0];
    try testing.expect(chrome.kind == .app);
    try testing.expectEqualStrings("https://www.google.com/chrome/", chrome.vendor.?.homepage);
    try testing.expectEqualStrings("https://dl.google.com/x.dmg", chrome.vendor.?.urls[platformIndex("aarch64-macos").?].?);
    try testing.expectEqualStrings("https://dl.google.com/x.dmg", chrome.vendor.?.urls[platformIndex("x86_64-macos").?].?);
    try testing.expectEqualStrings("\"version\": \"", chrome.vendor.?.version_after.?);
    try testing.expect(parsed.sources[1].kind == .cli);
}

test "versions from feeds, download URLs and HTTP dates" {
    try testing.expectEqualStrings("156.0.8078.48", versionAfter("{\"versions\":[{\"version\": \"156.0.8078.48\"}", "\"version\": \"").?);
    try testing.expectEqualStrings("4.96.3", versionAfter("<title>Version 4.96.3 (244472)</title>", "<title>Version ").?);
    try testing.expectEqualStrings("4.53.269", versionInUrl("https://downloads.slack-edge.com/desktop-releases/mac/universal/4.53.269/Slack-4.53.269-macOS.dmg").?);
    try testing.expectEqualStrings("0.0.420", versionInUrl("https://stable.dl2.discordapp.net/apps/osx/0.0.420/Discord.dmg").?);
    try testing.expectEqualStrings("1.104.32", versionInUrl("https://r.example.com/Raycast_v1.104.32_6b800d2a_universal.dmg?X-Amz-Date=20261027").?);
    try testing.expectEqualStrings("0.2026.10.21.08.25", versionInUrl("https://releases.warp.dev/stable/v0.2026.10.21.08.25.stable_02/Warp.dmg").?);
    // The host and the query are not looked at.
    try testing.expect(versionInUrl("https://dl2.example.com/x/googlechrome.dmg?v=1.2.3") == null);
    try testing.expect(versionAt("123") == null);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings("2026.10.26", (try versionFromHttpDate(arena.allocator(), "Mon, 26 Oct 2026 19:40:18 GMT")).?);
    try testing.expect((try versionFromHttpDate(arena.allocator(), "yesterday")) == null);
}

test "download file names and redirect targets" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("Postman for macOS (arm64).zip", (try downloadFileName(a, "https://dl.pstmn.io/download/latest/osx_arm64", "attachment; filename=Postman%20for%20macOS%20(arm64).zip")).?);
    try testing.expectEqualStrings("Docker.dmg", (try downloadFileName(a, "https://desktop.docker.com/mac/main/arm64/Docker.dmg", "attachment")).?);
    try testing.expectEqualStrings("x.dmg", (try downloadFileName(a, "https://e.com/a/x.dmg?sig=1", null)).?);
    // A file name that climbs out is cut to its last part.
    try testing.expectEqualStrings("evil.dmg", (try downloadFileName(a, "https://e.com/a", "attachment; filename=\"../../evil.dmg\"")).?);
    try testing.expect((try downloadFileName(a, "https://e.com/", null)) == null);

    try testing.expectEqualStrings("https://cdn.e.com/f.dmg", try Net.joinLocation(a, "https://e.com/dl?x=1", "https://cdn.e.com/f.dmg"));
    try testing.expectEqualStrings("https://e.com/other/f.dmg", try Net.joinLocation(a, "https://e.com/dl/latest", "/other/f.dmg"));
    try testing.expectEqualStrings("https://e.com/dl/f.dmg", try Net.joinLocation(a, "https://e.com/dl/latest?x=1", "f.dmg"));
    try testing.expectEqualStrings("https://cdn.e.com/f", try Net.joinLocation(a, "https://e.com/dl", "//cdn.e.com/f"));
    try testing.expectError(error.InsecureRedirect, Net.joinLocation(a, "https://e.com/dl", "http://e.com/f"));
}

test "a vendor tool: version from its feed, links from a template, pinned by download" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var env = try TestEnv.init(a);
    defer env.tmp.cleanup();
    try env.tmp.dir.makePath("fx/web");

    var tar = std.ArrayList(u8).init(a);
    try tarMember(&tar, "tf", 0o755, "\x7fELF tf");
    try tar.appendNTimes(0, 1024);
    try writeTestFile(env.tmp.dir, "fx/web/api.example.com_tf", "{\"builds\":[],\"version\":\"1.9.8\"}");
    // The Linux link redirects to a versioned file; the Mac link fails.
    try writeTestFile(env.tmp.dir, "fx/web/r.example.com_tf_1.9.8_linux.resolve", "https://cdn.example.com/tf/1.9.8/tf_1.9.8_linux_amd64.tar\nlast-modified: Mon, 26 Oct 2026 19:40:18 GMT\n");
    try writeTestFile(env.tmp.dir, "fx/web/cdn.example.com_tf_1.9.8_tf_1.9.8_linux_amd64.tar", tar.items);
    try writeTestFile(env.tmp.dir, "sources.txt", "");
    try writeTestFile(env.tmp.dir, "vendor.txt",
        \\tf https://www.example.com/tf url.x86_64-linux=https://r.example.com/tf/{version}/linux url.x86_64-macos=https://r.example.com/tf/{version}/mac version-url=https://api.example.com/tf "version-after=\"version\":\"" bin=tf desc="A tool"
        \\
    );
    var sink = std.ArrayList(u8).init(a);
    var opts = Options{ .sources_path = env.sources, .out_path = env.out, .fixtures_dir = env.fixtures, .jobs = 1, .now_epoch = 1781740800, .quiet = true };
    opts.vendor_path = try std.fs.path.join(a, &.{ env.root, "vendor.txt" });
    const r = try execute(testing.allocator, opts, sink.writer());
    try testing.expectEqual(@as(usize, 1), r.new);

    var reg = try registry.loadFromJsonFile(testing.allocator, env.out, null);
    defer reg.deinit();
    const tf = reg.get("tf").?;
    try testing.expectEqualStrings("1.9.8", tf.version);
    try testing.expectEqualStrings("Proprietary", tf.license);
    try testing.expectEqualStrings("https://www.example.com/tf", tf.homepage);
    try testing.expectEqual(@as(usize, 1), tf.platforms.len);
    // Pinned as the versioned file it redirects to, with the hash of what was downloaded.
    try testing.expectEqualStrings("https://cdn.example.com/tf/1.9.8/tf_1.9.8_linux_amd64.tar", tf.platforms[0].url);
    try testing.expectEqualStrings(&hexOf(tar.items), tf.platforms[0].sha256);

    // Unchanged next day: reused without a download.
    opts.previous_path = env.out;
    opts.out_path = try std.fs.path.join(a, &.{ env.root, "second.json" });
    const r2 = try execute(testing.allocator, opts, sink.writer());
    try testing.expectEqual(@as(usize, 1), r2.kept);
    try testing.expectEqual(@as(u64, 0), r2.bytes);
}

test "refreshSlot spreads names over the week" {
    var seen = [_]bool{false} ** 7;
    for (0..200) |i| {
        var buf: [16]u8 = undefined;
        seen[refreshSlot(std.fmt.bufPrint(&buf, "pkg{d}", .{i}) catch unreachable, 7)] = true;
    }
    for (seen) |x| try testing.expect(x);
    try testing.expectEqual(@as(u32, 0), refreshSlot("x", 1));
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

// ---- GraphQL batches, rate limits and ETags against a fake GitHub ----------

const Script = *const fn (f: *FakeApi, a: Allocator, req: ApiRequest) anyerror!ApiResponse;

/// Plays api.github.com and the clock: counts what was asked, answers from a
/// per-test script, and "sleeps" by moving its own time forward.
const FakeApi = struct {
    script: Script,
    mutex: std.Thread.Mutex = .{},
    now: i64 = 1_800_000_000,
    slept: u64 = 0,
    sleeps: usize = 0,
    calls: usize = 0,
    gql: usize = 0,
    rest: usize = 0,
    inm_seen: usize = 0,

    fn transport(self: *FakeApi) Transport {
        return .{ .ctx = self, .callFn = callImpl };
    }

    fn clock(self: *FakeApi) api.Clock {
        return .{ .ctx = self, .nowFn = nowImpl, .sleepFn = sleepImpl };
    }

    fn callImpl(ctx: ?*anyopaque, a: Allocator, req: ApiRequest) anyerror!ApiResponse {
        const self: *FakeApi = @ptrCast(@alignCast(ctx.?));
        self.mutex.lock();
        defer self.mutex.unlock();
        self.calls += 1;
        if (req.body != null) self.gql += 1 else self.rest += 1;
        if (req.if_none_match != null) self.inm_seen += 1;
        return self.script(self, a, req);
    }

    fn nowImpl(ctx: ?*anyopaque) i64 {
        const self: *FakeApi = @ptrCast(@alignCast(ctx.?));
        return self.now;
    }

    fn sleepImpl(ctx: ?*anyopaque, secs: u64) void {
        const self: *FakeApi = @ptrCast(@alignCast(ctx.?));
        self.now += @intCast(secs);
        self.slept += secs;
        self.sleeps += 1;
    }
};

/// The names of the repositories a GraphQL request asks for, in order.
fn queryRepoNames(a: Allocator, req: ApiRequest) ![]const []const u8 {
    const root = try std.json.parseFromSliceLeaky(std.json.Value, a, req.body.?, .{});
    const q = root.object.get("query").?.string;
    var names = std.ArrayList([]const u8).init(a);
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, q, pos, ",name:\"")) |i| {
        const start = i + ",name:\"".len;
        const end = std.mem.indexOfScalarPos(u8, q, start, '"').?;
        try names.append(q[start..end]);
        pos = end;
    }
    return names.toOwnedSlice();
}

fn hexDigest(a: Allocator, data: []const u8) ![]u8 {
    const h = hexOf(data);
    return std.fmt.allocPrint(a, "sha256:{s}", .{h});
}

/// A GraphQL release object with one raw Linux asset and one raw macOS asset.
fn gqlRelease(a: Allocator, owner: []const u8, repo: []const u8, tag: []const u8, with_digest: bool) ![]u8 {
    const d1 = try hexDigest(a, repo);
    const d2 = try hexDigest(a, tag);
    const dig1 = if (with_digest) try std.fmt.allocPrint(a, ",\"digest\":\"{s}\"", .{d1}) else "";
    const dig2 = if (with_digest) try std.fmt.allocPrint(a, ",\"digest\":\"{s}\"", .{d2}) else "";
    return std.fmt.allocPrint(a,
        \\{{"tagName":"{s}","releaseAssets":{{"pageInfo":{{"hasNextPage":false}},"nodes":[
        \\ {{"name":"{s}-linux-amd64","downloadUrl":"https://github.com/{s}/{s}/releases/download/{s}/{s}-linux-amd64","size":10{s}}},
        \\ {{"name":"{s}-darwin-arm64","downloadUrl":"https://github.com/{s}/{s}/releases/download/{s}/{s}-darwin-arm64","size":11{s}}}
        \\]}}}}
    , .{ tag, repo, owner, repo, tag, repo, dig1, repo, owner, repo, tag, repo, dig2 });
}

fn scriptCatalog(f: *FakeApi, a: Allocator, req: ApiRequest) anyerror!ApiResponse {
    if (req.body == null) return .{ .status = 404, .body = "{\"message\":\"Not Found\"}" };
    const q = (try std.json.parseFromSliceLeaky(std.json.Value, a, req.body.?, .{})).object.get("query").?.string;
    // This stand-in knows the digest field.
    try testing.expect(std.mem.indexOf(u8, q, " digest}") != null);
    const names = try queryRepoNames(a, req);

    var data = std.ArrayList(u8).init(a);
    var errs = std.ArrayList(u8).init(a);
    const w = data.writer();
    for (names, 0..) |n, i| {
        if (i != 0) try w.writeAll(",");
        if (std.mem.eql(u8, n, "gone")) {
            try w.print("\"r{d}\":null", .{i});
            try errs.writer().print("{s}{{\"type\":\"NOT_FOUND\",\"path\":[\"r{d}\"],\"message\":\"Could not resolve to a Repository with the name 'acme/gone'.\"}}", .{ if (errs.items.len != 0) "," else "", i });
        } else if (std.mem.eql(u8, n, "norel")) {
            try w.print("\"r{d}\":{{\"description\":\"No releases\",\"homepageUrl\":null,\"url\":\"https://github.com/acme/norel\",\"licenseInfo\":null,\"latestRelease\":null}}", .{i});
        } else if (std.mem.eql(u8, n, "beta")) {
            try w.print("\"r{d}\":{{\"description\":\"B   tool\",\"homepageUrl\":\"https://beta.example\",\"url\":\"https://github.com/acme/beta\",\"licenseInfo\":{{\"spdxId\":\"Apache-2.0\"}},\"t0\":{s}}}", .{ i, try gqlRelease(a, "acme", "beta", "v2.0.0", true) });
        } else {
            try w.print("\"r{d}\":{{\"description\":\"Fast  tool\",\"homepageUrl\":\"\",\"url\":\"https://github.com/acme/{s}\",\"licenseInfo\":{{\"spdxId\":\"MIT\"}},\"latestRelease\":{s}}}", .{ i, n, try gqlRelease(a, "acme", n, "v1.0.0", true) });
        }
    }
    const body = try std.fmt.allocPrint(a, "{{\"data\":{{{s}}},\"errors\":[{s}]}}", .{ data.items, errs.items });
    return .{ .status = 200, .body = body, .info = .{ .remaining = 990, .reset = f.now + 3000 } };
}

test "GraphQL: one query serves many sources; a missing repo only fails itself" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var env = try TestEnv.init(a);
    defer env.tmp.cleanup();
    try writeTestFile(env.tmp.dir, "sources.txt",
        \\alpha acme/alpha
        \\alpha-b acme/Alpha
        \\beta acme/beta tag=v2.0.0
        \\gone acme/gone
        \\norel acme/norel
    );

    var fake = FakeApi{ .script = scriptCatalog };
    var sink = std.ArrayList(u8).init(a);
    const opts = Options{
        .sources_path = env.sources,
        .out_path = env.out,
        .token = "test-token",
        .transport = fake.transport(),
        .clock = fake.clock(),
        .jobs = 1,
        .now_epoch = 1781740800,
        .quiet = true,
        .allow_failures = true,
    };
    const r = try execute(testing.allocator, opts, sink.writer());

    // Five sources, four repositories, ONE API call, and no REST at all.
    try testing.expectEqual(@as(usize, 1), fake.calls);
    try testing.expectEqual(@as(usize, 1), fake.gql);
    try testing.expectEqual(@as(usize, 0), fake.rest);
    try testing.expectEqual(@as(usize, 1), r.api_calls);
    try testing.expectEqual(@as(usize, 1), r.graphql_calls);
    try testing.expectEqual(@as(usize, 3), r.new);
    try testing.expectEqual(@as(usize, 2), r.skipped);
    try testing.expectEqual(@as(usize, 0), r.limited);
    try testing.expect(std.mem.indexOf(u8, sink.items, "Could not resolve to a Repository with the name 'acme/gone'") != null);
    try testing.expect(std.mem.indexOf(u8, sink.items, "no published release") != null);

    var diags = registry.LoadDiagnostics{};
    var reg = try registry.loadFromJsonFile(testing.allocator, env.out, &diags);
    defer reg.deinit();
    try testing.expectEqual(@as(usize, 0), diags.rejected_packages);
    try testing.expectEqual(@as(usize, 3), reg.count());

    const alpha = reg.get("alpha").?;
    try testing.expectEqualStrings("1.0.0", alpha.version);
    try testing.expectEqualStrings("Fast tool", alpha.description);
    try testing.expectEqualStrings("MIT", alpha.license);
    try testing.expectEqualStrings("https://github.com/acme/alpha", alpha.homepage);
    try testing.expectEqual(@as(usize, 2), alpha.platforms.len);
    // The digest GraphQL reported is the pinned hash; nothing was downloaded.
    const want = hexOf("alpha");
    try testing.expectEqualStrings(&want, alpha.platform("x86_64-linux").?.sha256);
    try testing.expectEqual(@as(u64, 0), r.bytes);
    // The pinned source got its tag from release(tagName:), and the repository record's own fields.
    const beta = reg.get("beta").?;
    try testing.expectEqualStrings("2.0.0", beta.version);
    try testing.expectEqualStrings("B tool", beta.description);
    try testing.expectEqualStrings("Apache-2.0", beta.license);
    try testing.expectEqualStrings("https://beta.example", beta.homepage);
    try testing.expect(reg.get("alpha-b") != null);
}

fn scriptAlwaysLimited(f: *FakeApi, _: Allocator, _: ApiRequest) anyerror!ApiResponse {
    return .{
        .status = 403,
        .body = "{\"message\":\"API rate limit exceeded for installation ID 123456.\"}",
        .info = .{ .remaining = 0, .reset = f.now + 7200 },
    };
}

fn sampleEntry(name: []const u8, version: []const u8) Entry {
    const plats = [_]PlatEntry{.{
        .tag = "x86_64-linux",
        .url = "https://example.com/dl",
        .sha256 = "1" ** 64,
        .archive_type = "raw",
        .bin_path = "tool",
    }};
    return .{ .name = name, .version = version, .description = "old", .bin = &.{"tool"}, .plats = &plats };
}

test "rate limited: stop at once when the reset is too far, carry every entry forward" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var env = try TestEnv.init(a);
    defer env.tmp.cleanup();
    try writeTestFile(env.tmp.dir, "sources.txt",
        \\alpha acme/alpha
        \\beta acme/beta
        \\fresh acme/fresh
        \\gamma acme/gamma
    );
    // The previous catalog has three of the four; "fresh" was never built.
    const prev_text = try renderIndex(a, &.{ sampleEntry("alpha", "0.9.0"), sampleEntry("beta", "0.5.0"), sampleEntry("gamma", "2.0.0") }, "2026-01-02T03:04:05Z");
    try writeTestFile(env.tmp.dir, "prev.json", prev_text);
    const prev_path = try std.fs.path.join(a, &.{ env.root, "prev.json" });
    const summary = try std.fs.path.join(a, &.{ env.root, "summary.md" });

    var fake = FakeApi{ .script = scriptAlwaysLimited };
    var sink = std.ArrayList(u8).init(a);
    const opts = Options{
        .sources_path = env.sources,
        .out_path = env.out,
        .previous_path = prev_path,
        .summary_path = summary,
        .token = "test-token",
        .transport = fake.transport(),
        .clock = fake.clock(),
        .max_wait_s = 20 * 60, // the window resets in two hours: too long
        .jobs = 1,
        .now_epoch = 1781740800,
        .quiet = true,
    };
    // No --allow-failures: a rate limit must not trip the "most sources failed" guard.
    const r = try execute(testing.allocator, opts, sink.writer());

    // One GraphQL attempt and one REST attempt (separate buckets), then nothing.
    try testing.expectEqual(@as(usize, 2), fake.calls);
    try testing.expectEqual(@as(u64, 0), fake.slept);
    try testing.expectEqual(@as(usize, 4), r.limited);
    try testing.expectEqual(@as(usize, 1), r.limited_missing);
    try testing.expectEqual(@as(usize, 0), r.stale);
    try testing.expectEqual(@as(usize, 0), r.skipped);
    // Nothing dropped: all three previous entries are in the output, untouched.
    try testing.expectEqual(@as(usize, 3), r.packages);
    const out_text = try std.fs.cwd().readFileAlloc(a, env.out, 1 << 20);
    const loaded = try loadEntries(a, out_text);
    try testing.expectEqualStrings("0.9.0", loaded.entries.get("alpha").?.version);
    try testing.expectEqualStrings("0.5.0", loaded.entries.get("beta").?.version);
    try testing.expectEqualStrings("2.0.0", loaded.entries.get("gamma").?.version);
    try testing.expect(loaded.entries.get("fresh") == null);

    try testing.expect(std.mem.indexOf(u8, sink.items, "rate limited") != null);
    const md = try std.fs.cwd().readFileAlloc(a, summary, 1 << 20);
    try testing.expect(std.mem.indexOf(u8, md, "#### Rate limited (4)") != null);
    try testing.expect(std.mem.indexOf(u8, md, "| alpha | acme/alpha | carried forward |") != null);
    try testing.expect(std.mem.indexOf(u8, md, "| fresh | acme/fresh | not in the catalog yet |") != null);
    // It is not reported as a failure.
    try testing.expect(std.mem.indexOf(u8, md, "No source failed.") != null);
    try testing.expect(std.mem.indexOf(u8, md, "#### Failures") == null);
}

fn scriptLimitedOnce(f: *FakeApi, a: Allocator, req: ApiRequest) anyerror!ApiResponse {
    if (f.calls == 1) {
        return .{
            .status = 403,
            .body = "{\"message\":\"API rate limit exceeded\"}",
            .info = .{ .remaining = 0, .reset = f.now + 30 },
        };
    }
    return scriptCatalog(f, a, req);
}

test "rate limited: waits for a reset that fits the budget, then carries on" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var env = try TestEnv.init(a);
    defer env.tmp.cleanup();
    try writeTestFile(env.tmp.dir, "sources.txt", "alpha acme/alpha\n");

    var fake = FakeApi{ .script = scriptLimitedOnce };
    var sink = std.ArrayList(u8).init(a);
    const opts = Options{
        .sources_path = env.sources,
        .out_path = env.out,
        .token = "test-token",
        .transport = fake.transport(),
        .clock = fake.clock(),
        .max_wait_s = 600,
        .jobs = 1,
        .now_epoch = 1781740800,
        .quiet = true,
    };
    const r = try execute(testing.allocator, opts, sink.writer());
    try testing.expectEqual(@as(usize, 2), fake.calls); // the refused call and the repeat
    try testing.expectEqual(@as(u64, 32), fake.slept); // 30 s to the reset + 2 s slack
    try testing.expectEqual(@as(u64, 32), r.rate_waited_s);
    try testing.expectEqual(@as(usize, 1), r.new);
    try testing.expectEqual(@as(usize, 0), r.limited);
}

fn scriptSecondary(f: *FakeApi, a: Allocator, req: ApiRequest) anyerror!ApiResponse {
    // A secondary limit: plenty of quota left, but "retry-after" says slow down.
    if (f.calls == 1) return secondaryLimit(f);
    return scriptCatalog(f, a, req);
}

fn secondaryLimit(f: *FakeApi) ApiResponse {
    return .{
        .status = 403,
        .body = "{\"message\":\"You have exceeded a secondary rate limit.\"}",
        .info = .{ .remaining = 800, .reset = f.now + 2000, .retry_after = 45 },
    };
}

fn scriptSecondaryAlways(f: *FakeApi, _: Allocator, _: ApiRequest) anyerror!ApiResponse {
    return secondaryLimit(f);
}

test "rate limited: a secondary limit's retry-after is honoured, and refused when over budget" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var env = try TestEnv.init(a);
    defer env.tmp.cleanup();
    try writeTestFile(env.tmp.dir, "sources.txt", "alpha acme/alpha\n");
    var sink = std.ArrayList(u8).init(a);

    var fake = FakeApi{ .script = scriptSecondary };
    var opts = Options{
        .sources_path = env.sources,
        .out_path = env.out,
        .token = "test-token",
        .transport = fake.transport(),
        .clock = fake.clock(),
        .max_wait_s = 600,
        .jobs = 1,
        .now_epoch = 1781740800,
        .quiet = true,
    };
    const r = try execute(testing.allocator, opts, sink.writer());
    try testing.expectEqual(@as(u64, 47), fake.slept);
    try testing.expectEqual(@as(usize, 1), r.new);

    // The same pause does not fit a 30 s budget: stop, and keep going without the API.
    var fake2 = FakeApi{ .script = scriptSecondaryAlways };
    opts.transport = fake2.transport();
    opts.clock = fake2.clock();
    opts.max_wait_s = 30;
    opts.out_path = try std.fs.path.join(a, &.{ env.root, "second.json" });
    try testing.expectError(error.EmptyCatalog, execute(testing.allocator, opts, sink.writer()));
    try testing.expectEqual(@as(u64, 0), fake2.slept);
}

/// REST stand-in: a release and a repository record with ETags; answers 304
/// when the ETag it handed out comes back.
fn scriptRest(f: *FakeApi, a: Allocator, req: ApiRequest) anyerror!ApiResponse {
    const is_release = std.mem.endsWith(u8, req.url, "/releases/latest");
    const etag: []const u8 = if (is_release) "\"rel-1\"" else "\"repo-1\"";
    if (req.if_none_match) |inm| {
        if (std.mem.eql(u8, inm, etag)) return .{ .status = 304, .body = "", .info = .{ .remaining = 55 } };
    }
    const owned_etag = try a.dupe(u8, etag);
    const info = api.RateInfo{ .remaining = 58, .reset = f.now + 3000, .etag = owned_etag };
    if (is_release) {
        const rel = try gqlRelease(a, "acme", "alpha", "v1.0.0", true);
        // Same content in REST dress.
        const root = try std.json.parseFromSliceLeaky(std.json.Value, a, rel, .{});
        var body = std.ArrayList(u8).init(a);
        const w = body.writer();
        try w.print("{{\"tag_name\":\"{s}\",\"assets\":[", .{root.object.get("tagName").?.string});
        for (root.object.get("releaseAssets").?.object.get("nodes").?.array.items, 0..) |n, i| {
            if (i != 0) try w.writeAll(",");
            try w.print("{{\"name\":\"{s}\",\"browser_download_url\":\"{s}\",\"size\":{d},\"digest\":\"{s}\"}}", .{
                n.object.get("name").?.string,
                n.object.get("downloadUrl").?.string,
                n.object.get("size").?.integer,
                n.object.get("digest").?.string,
            });
        }
        try w.writeAll("]}");
        return .{ .status = 200, .body = body.items, .info = info };
    }
    return .{ .status = 200, .body = widget_repo_json, .info = info };
}

test "REST without a token: ETag cache turns the second run's lookups into 304s" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var env = try TestEnv.init(a);
    defer env.tmp.cleanup();
    try writeTestFile(env.tmp.dir, "sources.txt", "alpha acme/alpha\n");
    const etags = try std.fs.path.join(a, &.{ env.root, "etags", "cache.json" });
    var sink = std.ArrayList(u8).init(a);

    var fake = FakeApi{ .script = scriptRest };
    var opts = Options{
        .sources_path = env.sources,
        .out_path = env.out,
        .etag_cache_path = etags,
        .transport = fake.transport(),
        .clock = fake.clock(),
        .jobs = 1,
        .now_epoch = 1781740800,
        .quiet = true,
    };
    // No token: GraphQL is not used, the REST path is: a release and a repository call.
    const first = try execute(testing.allocator, opts, sink.writer());
    try testing.expectEqual(@as(usize, 2), fake.rest);
    try testing.expectEqual(@as(usize, 0), fake.gql);
    try testing.expectEqual(@as(usize, 0), first.etag_hits);
    try testing.expectEqual(@as(usize, 1), first.new);
    try std.fs.cwd().access(etags, .{});

    // Second run, fresh state: the cache answers both calls with 304.
    opts.out_path = try std.fs.path.join(a, &.{ env.root, "again.json" });
    const second = try execute(testing.allocator, opts, sink.writer());
    try testing.expectEqual(@as(usize, 4), fake.rest);
    try testing.expectEqual(@as(usize, 2), fake.inm_seen);
    try testing.expectEqual(@as(usize, 2), second.etag_hits);
    try testing.expectEqual(@as(usize, 1), second.new);
    const one = try std.fs.cwd().readFileAlloc(a, env.out, 1 << 20);
    const two = try std.fs.cwd().readFileAlloc(a, opts.out_path, 1 << 20);
    try testing.expectEqualStrings(one, two);
}

var prefetch_digest_seen: usize = 0;

/// First answer: the schema has no `digest`. Then a 502 for the whole batch, then good answers.
fn scriptPrefetch(f: *FakeApi, a: Allocator, req: ApiRequest) anyerror!ApiResponse {
    if (req.body == null) {
        // REST fallback for the repository whose assets did not fit one page.
        try testing.expect(std.mem.indexOf(u8, req.url, "/repos/acme/big/releases/latest") != null);
        return .{ .status = 200, .body = "{\"tag_name\":\"v9\",\"assets\":[]}" };
    }
    const q = (try std.json.parseFromSliceLeaky(std.json.Value, a, req.body.?, .{})).object.get("query").?.string;
    if (std.mem.indexOf(u8, q, " digest}") != null) {
        prefetch_digest_seen += 1;
        return .{ .status = 200, .body = "{\"errors\":[{\"path\":[\"fragment R\"],\"message\":\"Field 'digest' doesn't exist on type 'ReleaseAsset'\"}]}" };
    }
    const names = try queryRepoNames(a, req);
    if (names.len == 5) return .{ .status = 502, .body = "<html>Bad Gateway</html>" };

    var data = std.ArrayList(u8).init(a);
    const w = data.writer();
    for (names, 0..) |n, i| {
        if (i != 0) try w.writeAll(",");
        const big = std.mem.eql(u8, n, "big");
        try w.print("\"r{d}\":{{\"description\":\"repo {s}\",\"homepageUrl\":null,\"url\":\"https://github.com/acme/{s}\",\"licenseInfo\":null,\"latestRelease\":{{\"tagName\":\"v1\",\"releaseAssets\":{{\"pageInfo\":{{\"hasNextPage\":{s}}},\"nodes\":[]}}}}}}", .{ i, n, n, if (big) "true" else "false" });
    }
    _ = f;
    return .{ .status = 200, .body = try std.fmt.allocPrint(a, "{{\"data\":{{{s}}}}}", .{data.items}) };
}

test "prefetch: asks again without digest, splits a failing batch, leaves oversized releases to REST" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(a, ".");

    var net_ = try Net.init(a, testing.allocator, .http, "test-token", null, root);
    defer net_.deinit();
    net_.link(0, true);
    var fake = FakeApi{ .script = scriptPrefetch };
    net_.transport = fake.transport();
    net_.clock = fake.clock();
    prefetch_digest_seen = 0;

    const reqs = [_]api.RepoRequest{
        .{ .owner = "acme", .repo = "a" },
        .{ .owner = "acme", .repo = "b" },
        .{ .owner = "acme", .repo = "c" },
        .{ .owner = "acme", .repo = "d" },
        .{ .owner = "Acme", .repo = "big" },
    };
    net_.prefetch(a, &reqs, 40);

    // digest attempt, retry without it (502), then the two halves.
    try testing.expectEqual(@as(usize, 1), prefetch_digest_seen);
    try testing.expect(!net_.graphql_digest);
    try testing.expectEqual(@as(usize, 4), fake.gql);
    try testing.expectEqual(@as(usize, 0), fake.rest);

    // Every repository record arrived; lookups are case-insensitive on owner/repo.
    for ([_][]const u8{ "a", "b", "c", "d", "big" }) |n| {
        const body = try net_.fetchRepo(a, "acme", n);
        const want = try std.fmt.allocPrint(a, "repo {s}", .{n});
        try testing.expect(std.mem.indexOf(u8, body, want) != null);
    }
    try testing.expectEqual(@as(usize, 0), fake.rest);
    const rel = try net_.fetchRelease(a, "acme", "a", null);
    try testing.expect(std.mem.indexOf(u8, rel, "\"tag_name\":\"v1\"") != null);
    // The one with too many assets goes to REST, once.
    const big = try net_.fetchRelease(a, "acme", "big", null);
    try testing.expect(std.mem.indexOf(u8, big, "\"v9\"") != null);
    try testing.expectEqual(@as(usize, 1), fake.rest);
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

test "catalog/vendor.txt parses cleanly, sorted, with no name from sources.txt" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const text = std.fs.cwd().readFileAlloc(a, "catalog/vendor.txt", 1 << 20) catch |e| switch (e) {
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    };
    const parsed = try parseSources(a, text);
    for (parsed.problems) |pr| std.debug.print("vendor.txt:{d}: {s}\n", .{ pr.line, pr.text });
    try testing.expectEqual(@as(usize, 0), parsed.problems.len);
    try testing.expect(parsed.sources.len >= 10);
    const hand = try parseSources(a, try readRealSources(a));
    for (parsed.sources, 0..) |src, i| {
        try testing.expect(src.vendor != null);
        for (hand.sources) |h| try testing.expect(!std.mem.eql(u8, h.name, src.name));
        if (i > 0 and parsed.sources[i - 1].kind == src.kind) try testing.expect(std.mem.order(u8, parsed.sources[i - 1].name, src.name) == .lt);
    }
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

test "sources: win= for portable Windows apps" {
    const text =
        \\keepassxc keepassxreboot/keepassxc app=KeePassXC.app win=KeePassXC.exe
        \\godot godotengine/godot win="Godot=Godot_v*_win64.exe"
        \\badwin acme/badwin win=..\\evil.exe
        \\cliwin acme/cliwin kind=cli win=x.exe
        \\notexe acme/notexe win=tool.bat
    ;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const parsed = try parseSources(arena.allocator(), text);
    try testing.expectEqual(@as(usize, 2), parsed.sources.len);
    try testing.expectEqual(@as(usize, 3), parsed.problems.len);
    try testing.expect(parsed.sources[0].kind == .app);
    try testing.expectEqualStrings("KeePassXC.exe", parsed.sources[0].win[0]);
    try testing.expect(parsed.sources[1].kind == .app);
    try testing.expectEqualStrings("Godot=Godot_v*_win64.exe", parsed.sources[1].win[0]);
}

test "pickWinAppAsset takes the portable zip for the right architecture" {
    const names = [_][]const u8{
        "KeePassXC-2.7.9-Win64.msi",
        "KeePassXC-2.7.9-Win64.zip",
        "KeePassXC-2.7.9-Win64-LegacyWindows.zip.DIGEST",
        "KeePassXC-2.7.9-arm64.dmg",
        "VSCodium-win32-arm64-1.95.zip",
        "VSCodium-linux-x64-1.95.tar.gz",
        "app-setup-win64.zip",
        "app-1.0-windows-x86.zip",
        "sources.zip",
    };
    var assets: [names.len]ghrelease.Asset = undefined;
    for (names, 0..) |n, i| assets[i] = .{ .name = n, .url = "https://example.com/x", .size = 1, .sha256 = null };
    try testing.expectEqualStrings("KeePassXC-2.7.9-Win64.zip", names[pickWinAppAsset(&assets, "x86_64-windows").?]);
    try testing.expectEqualStrings("VSCodium-win32-arm64-1.95.zip", names[pickWinAppAsset(&assets, "aarch64-windows").?]);
    const none = [_]ghrelease.Asset{ .{ .name = "tool-setup-x64.exe", .url = "https://example.com/x", .size = 1, .sha256 = null }, .{ .name = "tool-linux.zip", .url = "https://example.com/x", .size = 1, .sha256 = null } };
    try testing.expect(pickWinAppAsset(&none, "x86_64-windows") == null);

    // "portable" alone marks a Windows build, unless another system is named.
    const portable = [_]ghrelease.Asset{
        .{ .name = "ShareX-21.0.0-portable-x64.zip", .url = "https://example.com/x", .size = 1, .sha256 = null },
        .{ .name = "Tool-portable-macos.zip", .url = "https://example.com/x", .size = 1, .sha256 = null },
    };
    try testing.expectEqual(@as(?usize, 0), pickWinAppAsset(&portable, "x86_64-windows"));
    try testing.expect(pickWinAppAsset(portable[1..], "x86_64-windows") == null);
}

test "resolveWinEntry finds the shallowest matching program" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const paths = [_][]const u8{
        "Godot_v4.3-stable_win64.exe",
        "Godot_v4.3-stable_win64_console.exe",
        "KeePassXC-2.7.9/",
        "KeePassXC-2.7.9/plugins/KeePassXC.exe",
        "KeePassXC-2.7.9/KeePassXC.exe",
        "KeePassXC-2.7.9/keepassxc-cli.exe",
    };
    try testing.expectEqualStrings("KeePassXC=KeePassXC.exe", (try resolveWinEntry(a, "keepassxc", "KeePassXC.exe", &paths)).?);
    try testing.expectEqualStrings("Godot=Godot_v4.3-stable_win64.exe", (try resolveWinEntry(a, "godot", "Godot=Godot_v*_win64.exe", &paths)).?);
    // A wildcard with no display name falls back to the package name.
    try testing.expectEqualStrings("godot=Godot_v4.3-stable_win64.exe", (try resolveWinEntry(a, "godot", "Godot_v*_win64.exe", &paths)).?);
    try testing.expect((try resolveWinEntry(a, "x", "Missing.exe", &paths)) == null);
    try testing.expect(globMatch("*.EXE", "a.exe"));
    try testing.expect(!globMatch("a*b.exe", "a.exe"));
}

test "validateEntry accepts Windows app entries and refuses unsafe ones" {
    const plats = [_]PlatEntry{.{ .tag = "x86_64-windows", .url = "https://example.com/a.zip", .sha256 = "0" ** 64, .archive_type = "zip", .bin_path = "" }};
    var e = Entry{ .name = "keepassxc", .version = "2.7.9", .app_bundles = &.{ "KeePassXC.app", "KeePassXC=KeePassXC.exe" }, .plats = &plats };
    try testing.expect(validateEntry(e) == null);
    e.app_bundles = &.{"x=..\\evil.exe"};
    try testing.expect(validateEntry(e) != null);
}

test "sources: deps= lists catalog packages" {
    const text =
        \\yt-dlp yt-dlp/yt-dlp deps=ffmpeg
        \\self acme/self deps=self
        \\bad acme/bad deps=../x
    ;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const parsed = try parseSources(arena.allocator(), text);
    try testing.expectEqual(@as(usize, 1), parsed.sources.len);
    try testing.expectEqualStrings("ffmpeg", parsed.sources[0].deps[0]);
    try testing.expectEqual(@as(usize, 2), parsed.problems.len);
}

test "an unchanged version is rebuilt when the line adds deps or win" {
    const prev = Entry{ .name = "x", .version = "1", .app_bundles = &.{"X.app"} };
    try testing.expect(prevMatchesSource(.{ .name = "x", .owner = "o", .repo = "x" }, prev));
    try testing.expect(!prevMatchesSource(.{ .name = "x", .owner = "o", .repo = "x", .deps = &.{"y"} }, prev));
    try testing.expect(!prevMatchesSource(.{ .name = "x", .owner = "o", .repo = "x", .win = &.{"X.exe"} }, prev));
    const prev_win = Entry{ .name = "x", .version = "1", .app_bundles = &.{ "X.app", "X=X.exe" }, .deps = &.{"y"} };
    try testing.expect(prevMatchesSource(.{ .name = "x", .owner = "o", .repo = "x", .deps = &.{"y"}, .win = &.{"X.exe"} }, prev_win));
}

test {
    _ = discover;
}
