//! Pure helpers for `abv0 install gh:owner/repo`: how a download is verified,
//! which checksum file to trust, and what the store calls the result.
//!
//! None of this touches the network or the disk, so every rule is unit tested.
//!
//! Trust model, strongest first:
//!   1. GitHub's own `digest` for the asset (computed by GitHub when the asset
//!      was uploaded and served over the API's TLS connection).
//!   2. A checksum file published in the same release (`checksums.txt`,
//!      `SHA256SUMS`, `<asset>.sha256`, ...). This catches corruption and a
//!      tampered CDN copy, but whoever can replace the asset in the release can
//!      replace the file too, so it is weaker than 1 and is reported as such.
//!   3. Nothing. Refused unless the user passes `--allow-unverified`.

const std = @import("std");
const ghrelease = @import("ghrelease.zig");
const safepath = @import("safepath.zig");

/// 64 lowercase hex characters.
pub const Hex = [64]u8;

pub const Source = enum {
    github_digest,
    checksums_file,

    /// The text printed after `verify   sha256`.
    pub fn label(self: Source) []const u8 {
        return switch (self) {
            .github_digest => "GitHub digest",
            .checksums_file => "release checksums file",
        };
    }
};

pub const Decision = union(enum) {
    verified: struct { hex: Hex, source: Source },
    /// No hash exists and the user opted in to installing without one.
    unverified,
    /// No hash exists and the user did not opt in.
    refused,
};

/// Decide how an asset will be verified. A GitHub digest wins over a checksum
/// file; with neither, the install proceeds only when `allow_unverified`.
pub fn decide(digest: ?Hex, from_file: ?Hex, allow_unverified: bool) Decision {
    if (digest) |d| return .{ .verified = .{ .hex = d, .source = .github_digest } };
    if (from_file) |f| return .{ .verified = .{ .hex = f, .source = .checksums_file } };
    return if (allow_unverified) .unverified else .refused;
}

// ---------------------------------------------------------------------------
// Store naming
// ---------------------------------------------------------------------------

const max_version_len = 100;

/// A release tag as a store version: a valid identifier. A leading `v` before
/// a digit is dropped (`v1.2.3` is `1.2.3`, like the registry writes it), and
/// every character an identifier cannot hold becomes `_` (`nightly-2024/10` is
/// `nightly-2024_10`). The real tag is kept separately, in the source file.
/// Caller frees.
pub fn versionFromTag(a: std.mem.Allocator, tag: []const u8) ![]u8 {
    var t = tag;
    if (t.len >= 2 and (t[0] == 'v' or t[0] == 'V') and std.ascii.isDigit(t[1])) t = t[1..];
    if (t.len > max_version_len) t = t[0..max_version_len];

    const out = try a.alloc(u8, t.len);
    for (t, out) |c, *o| {
        o.* = switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '_', '.', '+' => c,
            else => '_',
        };
    }
    // A leading '-' or an all-dots name is not a valid identifier.
    if (out.len > 0 and (out[0] == '-')) out[0] = '_';
    if (!safepath.isValidId(out)) {
        for (out) |*o| {
            if (o.* == '.') o.* = '_';
        }
    }
    if (out.len == 0) {
        a.free(out);
        return a.dupe(u8, "0");
    }
    return out;
}

/// Contents of the `.abv0-source` file: `gh:owner/repo@tag\n`.
pub fn sourceNote(a: std.mem.Allocator, owner: []const u8, repo: []const u8, tag: []const u8) ![]u8 {
    return std.fmt.allocPrint(a, "gh:{s}/{s}@{s}\n", .{ owner, repo, tag });
}

/// Parse a `.abv0-source` file back into a spec. Null for anything that is not
/// `gh:owner/repo@tag`: the file lives in the store, so it is not trusted.
pub fn parseSourceNote(text: []const u8) ?ghrelease.Spec {
    const line = std.mem.trim(u8, text, " \t\r\n");
    if (!std.mem.startsWith(u8, line, "gh:")) return null;
    const spec = ghrelease.parseSpec(line) orelse return null;
    if (spec.tag == null) return null;
    return spec;
}

/// Whether `spec` names a GitHub repository rather than a registry package:
/// a `gh:` prefix, or an `owner/repo` shape.
pub fn looksLikeSpec(spec: []const u8) bool {
    return std.mem.startsWith(u8, spec, "gh:") or std.mem.indexOfScalar(u8, spec, '/') != null;
}

// ---------------------------------------------------------------------------
// Checksum files
// ---------------------------------------------------------------------------

fn isHex64(s: []const u8) bool {
    if (s.len != 64) return false;
    for (s) |c| {
        if (!std.ascii.isHex(c)) return false;
    }
    return true;
}

fn lowerHex(s: []const u8) Hex {
    var out: Hex = undefined;
    for (s, 0..) |c, i| out[i] = std.ascii.toLower(c);
    return out;
}

/// Does a name in a checksum file refer to `asset`? Leading `*` (the binary
/// marker) and `./` are ignored, and so is any directory prefix: `dist/x.zip`
/// matches `x.zip`.
fn sameFile(listed: []const u8, asset: []const u8) bool {
    var n = listed;
    if (n.len > 0 and n[0] == '*') n = n[1..];
    while (std.mem.startsWith(u8, n, "./")) n = n[2..];
    if (std.mem.eql(u8, n, asset)) return true;
    if (std.mem.lastIndexOfAny(u8, n, "/\\")) |i| return std.mem.eql(u8, n[i + 1 ..], asset);
    return false;
}

/// The SHA-256 listed for `asset` in a checksum file, or null when the file
/// does not list it. Understands:
///   * GNU:  `<hex>  <name>`, `<hex> *<name>`, `<hex> <name>` (any run of
///     spaces or tabs)
///   * BSD:  `SHA256 (<name>) = <hex>`
/// and, when `bare_ok` (a file made for exactly this asset), a line holding
/// nothing but the hex. Lines with another digest length (SHA-512, SHA-1),
/// comments and blank lines are ignored. If the asset is listed twice with
/// different hashes the file is ambiguous and the result is null.
pub fn findChecksum(text: []const u8, asset: []const u8, bare_ok: bool) ?Hex {
    var found: ?Hex = null;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        var hit: ?Hex = null;
        if (parseBsd(line, asset)) |h| {
            hit = h;
        } else if (parseGnu(line, asset, bare_ok)) |h| {
            hit = h;
        }
        const h = hit orelse continue;
        if (found) |prev| {
            if (!std.mem.eql(u8, &prev, &h)) return null;
        }
        found = h;
    }
    return found;
}

fn parseBsd(line: []const u8, asset: []const u8) ?Hex {
    // SHA256 (name) = hex   (the space before '(' is optional in the wild)
    const algo = "SHA256";
    if (!std.ascii.startsWithIgnoreCase(line, algo)) return null;
    var rest = std.mem.trimLeft(u8, line[algo.len..], " ");
    if (rest.len == 0 or rest[0] != '(') return null;
    const close = std.mem.lastIndexOf(u8, rest, ")") orelse return null;
    const name = rest[1..close];
    rest = std.mem.trimLeft(u8, rest[close + 1 ..], " \t");
    if (rest.len == 0 or rest[0] != '=') return null;
    const hex = std.mem.trim(u8, rest[1..], " \t");
    if (!isHex64(hex) or !sameFile(name, asset)) return null;
    return lowerHex(hex);
}

fn parseGnu(line: []const u8, asset: []const u8, bare_ok: bool) ?Hex {
    if (line.len < 64 or !isHex64(line[0..64])) {
        return null;
    }
    const hex = line[0..64];
    const rest = std.mem.trim(u8, line[64..], " \t");
    if (rest.len == 0) return if (bare_ok) lowerHex(hex) else null;
    // The hex must be followed by whitespace, not run into the name.
    if (line[64] != ' ' and line[64] != '\t') return null;
    if (!sameFile(rest, asset)) return null;
    return lowerHex(hex);
}

/// Which release assets may hold a SHA-256 for `assets[chosen]`, best first,
/// as indices. A file made for the asset (`<asset>.sha256`, `.sha256sum`)
/// comes before an aggregate (`checksums.txt`, `SHA256SUMS`, `*_checksums.txt`,
/// `*.sha256`). Signatures, SHA-512 files, other assets and anything over 2 MiB
/// are left out. At most 4 are returned.
pub fn checksumCandidates(a: std.mem.Allocator, assets: []const ghrelease.Asset, chosen: usize) ![]usize {
    const asset = assets[chosen].name;
    var dedicated = std.ArrayList(usize).init(a);
    defer dedicated.deinit();
    var aggregate = std.ArrayList(usize).init(a);
    defer aggregate.deinit();

    for (assets, 0..) |cand, i| {
        if (i == chosen or cand.size > 2 * 1024 * 1024 or cand.size == 0) continue;
        const n = cand.name;
        if (isSignatureName(n) or std.ascii.indexOfIgnoreCase(n, "sha512") != null) continue;

        if (n.len > asset.len and std.mem.startsWith(u8, n, asset) and n[asset.len] == '.') {
            const suffix = n[asset.len + 1 ..];
            if (std.ascii.eqlIgnoreCase(suffix, "sha256") or
                std.ascii.eqlIgnoreCase(suffix, "sha256sum") or
                std.ascii.eqlIgnoreCase(suffix, "sha256.txt"))
            {
                try dedicated.append(i);
            }
            continue;
        }
        // A checksum file made for some other asset says nothing about this one.
        if (belongsToOtherAsset(assets, i)) continue;

        const aggregated = std.ascii.indexOfIgnoreCase(n, "checksum") != null or
            std.ascii.indexOfIgnoreCase(n, "sha256sum") != null or
            std.ascii.endsWithIgnoreCase(n, ".sha256") or
            std.ascii.endsWithIgnoreCase(n, ".sha256sum");
        if (aggregated) try aggregate.append(i);
    }

    var out = std.ArrayList(usize).init(a);
    errdefer out.deinit();
    for (dedicated.items) |i| if (out.items.len < 4) try out.append(i);
    for (aggregate.items) |i| if (out.items.len < 4) try out.append(i);
    return out.toOwnedSlice();
}

/// Whether `assets[i]` is `<other asset>.<something>`: a sidecar of a
/// different download.
fn belongsToOtherAsset(assets: []const ghrelease.Asset, i: usize) bool {
    const n = assets[i].name;
    for (assets, 0..) |other, j| {
        if (j == i or other.name.len >= n.len) continue;
        if (std.mem.startsWith(u8, n, other.name) and n[other.name.len] == '.') return true;
    }
    return false;
}

fn isSignatureName(n: []const u8) bool {
    const suffixes = [_][]const u8{ ".sig", ".asc", ".pem", ".minisig", ".sigstore", ".bundle", ".sbom", ".cert", ".crt" };
    for (suffixes) |s| {
        if (std.ascii.endsWithIgnoreCase(n, s)) return true;
    }
    return false;
}

/// Is this candidate a file made for one asset (so a bare hex line is fine)?
pub fn isDedicated(asset: []const u8, candidate: []const u8) bool {
    return candidate.len > asset.len and std.mem.startsWith(u8, candidate, asset) and candidate[asset.len] == '.';
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const h1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const h2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const h3 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

test "GNU checksum lines: two spaces, one space, tab, binary marker, dot-slash" {
    const text =
        h1 ++ "  tool-linux.tar.gz\n" ++
        h2 ++ " *tool-darwin.tar.gz\n" ++
        h3 ++ "\ttool-windows.zip\n" ++
        h1 ++ "    ./spaced.tar.gz\r\n" ++
        h2 ++ "  dist/nested.tar.gz\n";
    try testing.expectEqualStrings(h1, &findChecksum(text, "tool-linux.tar.gz", false).?);
    try testing.expectEqualStrings(h2, &findChecksum(text, "tool-darwin.tar.gz", false).?);
    try testing.expectEqualStrings(h3, &findChecksum(text, "tool-windows.zip", false).?);
    try testing.expectEqualStrings(h1, &findChecksum(text, "spaced.tar.gz", false).?);
    try testing.expectEqualStrings(h2, &findChecksum(text, "nested.tar.gz", false).?);
    try testing.expect(findChecksum(text, "missing.tar.gz", false) == null);
    // A name that merely ends the same way is another file.
    try testing.expect(findChecksum(text, "linux.tar.gz", false) == null);
}

test "BSD checksum lines" {
    const text =
        "SHA256 (tool-linux.tar.gz) = " ++ h1 ++ "\n" ++
        "SHA256 (tool-darwin.tar.gz)= " ++ h2 ++ "\n" ++
        "SHA512 (tool-linux.tar.gz) = " ++ ("c" ** 128) ++ "\n" ++
        "SHA256(odd name.zip) = " ++ h3 ++ "\n";
    try testing.expectEqualStrings(h1, &findChecksum(text, "tool-linux.tar.gz", false).?);
    try testing.expectEqualStrings(h2, &findChecksum(text, "tool-darwin.tar.gz", false).?);
    try testing.expectEqualStrings(h3, &findChecksum(text, "odd name.zip", false).?);
}

test "checksum hex is lowercased and other digest sizes are ignored" {
    const upper = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
    const text = upper ++ "  a.zip\n" ++ ("d" ** 128) ++ "  b.zip\n" ++ ("e" ** 40) ++ "  c.zip\n";
    try testing.expectEqualStrings("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", &findChecksum(text, "a.zip", false).?);
    try testing.expect(findChecksum(text, "b.zip", false) == null);
    try testing.expect(findChecksum(text, "c.zip", false) == null);
}

test "comments, blanks and garbage are skipped" {
    const text = "# sha256 sums\n\n   \nnot a checksum line\n" ++ h1 ++ "  ok.zip\n" ++ h2 ++ "ok2.zip\n";
    try testing.expectEqualStrings(h1, &findChecksum(text, "ok.zip", false).?);
    // Hex running straight into the name is not a valid line.
    try testing.expect(findChecksum(text, "ok2.zip", false) == null);
}

test "a bare hash only counts in a file made for the asset" {
    const text = h1 ++ "\n";
    try testing.expect(findChecksum(text, "x.zip", false) == null);
    try testing.expectEqualStrings(h1, &findChecksum(text, "x.zip", true).?);
    try testing.expectEqualStrings(h1, &findChecksum(h1 ++ "  x.zip\n", "x.zip", true).?);
}

test "an asset listed twice with different hashes is refused" {
    const text = h1 ++ "  x.zip\n" ++ h2 ++ "  x.zip\n";
    try testing.expect(findChecksum(text, "x.zip", false) == null);
    const same = h1 ++ "  x.zip\n" ++ h1 ++ " *x.zip\n";
    try testing.expectEqualStrings(h1, &findChecksum(same, "x.zip", false).?);
}

fn mkAsset(name: []const u8) ghrelease.Asset {
    return .{ .name = name, .url = "https://example.com/x", .size = 100, .sha256 = null };
}

test "checksum candidates: dedicated first, aggregates after, noise dropped" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const assets = [_]ghrelease.Asset{
        mkAsset("tool-1.0-linux-amd64.tar.gz"), // 0 chosen
        mkAsset("tool-1.0-darwin-arm64.tar.gz"),
        mkAsset("tool-1.0-darwin-arm64.tar.gz.sha256"), // someone else's
        mkAsset("tool-1.0-linux-amd64.tar.gz.sig"),
        mkAsset("tool-1.0-linux-amd64.tar.gz.sha256"), // dedicated
        mkAsset("tool_1.0_checksums.txt"), // aggregate
        mkAsset("SHA256SUMS"), // aggregate
        mkAsset("SHA512SUMS"), // wrong algorithm
        mkAsset("checksums.txt.sig"), // signature
    };
    const got = try checksumCandidates(a, &assets, 0);
    try testing.expectEqualSlices(usize, &.{ 4, 5, 6 }, got);
}

test "checksum candidates: none when the release publishes none" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const assets = [_]ghrelease.Asset{ mkAsset("tool-linux.tar.gz"), mkAsset("tool-darwin.tar.gz"), mkAsset("notes.txt") };
    try testing.expectEqual(@as(usize, 0), (try checksumCandidates(arena.allocator(), &assets, 0)).len);
}

test "checksum candidates skip huge or empty files" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var assets = [_]ghrelease.Asset{ mkAsset("tool.zip"), mkAsset("checksums.txt"), mkAsset("sha256sums.txt") };
    assets[1].size = 50 * 1024 * 1024;
    assets[2].size = 0;
    try testing.expectEqual(@as(usize, 0), (try checksumCandidates(arena.allocator(), &assets, 0)).len);
}

test "decide: digest beats file, file beats nothing, nothing needs opt-in" {
    const d: Hex = h1.*;
    const f: Hex = h2.*;

    const v1 = decide(d, f, false);
    try testing.expect(v1 == .verified);
    try testing.expectEqual(Source.github_digest, v1.verified.source);
    try testing.expectEqualStrings(h1, &v1.verified.hex);

    const v2 = decide(null, f, false);
    try testing.expectEqual(Source.checksums_file, v2.verified.source);
    try testing.expectEqualStrings(h2, &v2.verified.hex);

    // Verified stays verified even when the user allowed unverified installs.
    try testing.expect(decide(d, null, true) == .verified);

    try testing.expect(decide(null, null, false) == .refused);
    try testing.expect(decide(null, null, true) == .unverified);

    try testing.expectEqualStrings("GitHub digest", Source.github_digest.label());
    try testing.expectEqualStrings("release checksums file", Source.checksums_file.label());
}

test "store versions from tags" {
    const a = testing.allocator;
    const cases = [_][2][]const u8{
        .{ "v1.2.3", "1.2.3" },
        .{ "1.2.3", "1.2.3" },
        .{ "V2.0.0-rc.1", "2.0.0-rc.1" },
        .{ "nightly-2024/10", "nightly-2024_10" },
        .{ "release/v1.0 beta", "release_v1.0_beta" },
        .{ "version-1", "version-1" },
        .{ "v", "v" },
        .{ "v1.0+build5", "1.0+build5" },
        .{ "-weird", "_weird" },
        .{ "..", "__" },
        .{ ".", "_" },
    };
    for (cases) |c| {
        const got = try versionFromTag(a, c[0]);
        defer a.free(got);
        try testing.expectEqualStrings(c[1], got);
        try testing.expect(safepath.isValidId(got));
    }
    const long = try versionFromTag(a, "x" ** 300);
    defer a.free(long);
    try testing.expect(safepath.isValidId(long));
}

test "source note round trip" {
    const a = testing.allocator;
    const note = try sourceNote(a, "BurntSushi", "ripgrep", "14.1.1");
    defer a.free(note);
    try testing.expectEqualStrings("gh:BurntSushi/ripgrep@14.1.1\n", note);
    const spec = parseSourceNote(note).?;
    try testing.expectEqualStrings("BurntSushi", spec.owner);
    try testing.expectEqualStrings("ripgrep", spec.repo);
    try testing.expectEqualStrings("14.1.1", spec.tag.?);

    try testing.expect(parseSourceNote("") == null);
    try testing.expect(parseSourceNote("gh:a/b\n") == null);
    try testing.expect(parseSourceNote("https://evil/x@y") == null);
    try testing.expect(parseSourceNote("gh:../b@1\n") == null);

    const slashed = try sourceNote(a, "o", "r", "nightly/2024");
    defer a.free(slashed);
    try testing.expectEqualStrings("nightly/2024", parseSourceNote(slashed).?.tag.?);
}

test "which names are GitHub specs" {
    try testing.expect(looksLikeSpec("gh:a/b"));
    try testing.expect(looksLikeSpec("a/b"));
    try testing.expect(looksLikeSpec("a/b@v1"));
    try testing.expect(looksLikeSpec("gh:nope"));
    try testing.expect(!looksLikeSpec("ripgrep"));
    try testing.expect(!looksLikeSpec("jq"));
}
