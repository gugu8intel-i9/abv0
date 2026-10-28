//! Free, legal books and papers: `abv0 install book:gutenberg/1342`.
//!
//! Sources:
//!   * Project Gutenberg (`book:gutenberg/<number>`): public-domain books.
//!   * Standard Ebooks (`book:standard/<author>/<title>[/<translator>]`):
//!     carefully edited public-domain books.
//!   * Internet Archive (`book:archive/<identifier>`): only items anyone may
//!     download; lending-library (borrow-only) items are refused.
//!   * arXiv (`book:arxiv/<id>`): open-access research papers.
//!
//! Books go to `$ABV0_BOOKS_DIR`, else `~/Books`, named "Title - Author.ext".
//! Internet Archive files are checked against the SHA-1 and size the archive
//! lists. Every download must also look like the format asked for (a PDF
//! starts with `%PDF-`, an EPUB is a zip that says `application/epub+zip`,
//! ...), so an error page or a swapped file never lands as a book.

const std = @import("std");
const builtin = @import("builtin");
const net = @import("net.zig");
const platform = @import("platform.zig");
const term = @import("term.zig");

const Allocator = std.mem.Allocator;

pub const Source = enum {
    gutenberg,
    standard,
    archive,
    arxiv,

    pub fn label(self: Source) []const u8 {
        return switch (self) {
            .gutenberg => "Project Gutenberg",
            .standard => "Standard Ebooks",
            .archive => "Internet Archive",
            .arxiv => "arXiv",
        };
    }
};

pub const Spec = struct {
    source: Source,
    /// The number, slug path, identifier or paper id.
    id: []const u8,
};

pub const Format = enum {
    epub,
    pdf,
    txt,
    kindle,

    pub fn parse(s: []const u8) ?Format {
        if (std.mem.eql(u8, s, "epub")) return .epub;
        if (std.mem.eql(u8, s, "pdf")) return .pdf;
        if (std.mem.eql(u8, s, "txt") or std.mem.eql(u8, s, "text")) return .txt;
        if (std.mem.eql(u8, s, "kindle") or std.mem.eql(u8, s, "mobi") or std.mem.eql(u8, s, "azw3")) return .kindle;
        return null;
    }
};

fn allDigits(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (!std.ascii.isDigit(c)) return false;
    return true;
}

fn isSlug(s: []const u8) bool {
    if (s.len == 0 or s.len > 100 or s[0] == '-') return false;
    for (s) |c| if (!(std.ascii.isLower(c) or std.ascii.isDigit(c) or c == '-')) return false;
    return true;
}

fn isArchiveId(s: []const u8) bool {
    if (s.len == 0 or s.len > 100 or s[0] == '.' or s[0] == '-') return false;
    for (s) |c| if (!(std.ascii.isAlphanumeric(c) or c == '_' or c == '-' or c == '.')) return false;
    return std.mem.indexOf(u8, s, "..") == null;
}

/// `2401.12345`, `2401.12345v2`, or the old style `hep-th/9901001`.
fn isArxivId(s: []const u8) bool {
    var core = s;
    if (std.mem.lastIndexOfScalar(u8, s, 'v')) |v| {
        if (v + 1 < s.len and allDigits(s[v + 1 ..])) core = s[0..v];
    }
    if (std.mem.indexOfScalar(u8, core, '/')) |slash| {
        const arch = core[0..slash];
        if (arch.len == 0 or arch.len > 20) return false;
        for (arch) |c| if (!(std.ascii.isLower(c) or c == '-' or c == '.' or std.ascii.isUpper(c))) return false;
        return core.len - slash - 1 == 7 and allDigits(core[slash + 1 ..]);
    }
    const dot = std.mem.indexOfScalar(u8, core, '.') orelse return false;
    const tail = core[dot + 1 ..];
    return dot == 4 and allDigits(core[0..4]) and (tail.len == 4 or tail.len == 5) and allDigits(tail);
}

pub fn parseSpec(text: []const u8) ?Spec {
    if (!std.mem.startsWith(u8, text, "book:")) return null;
    const rest = text["book:".len..];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return null;
    const src = rest[0..slash];
    const id = rest[slash + 1 ..];
    if (std.mem.eql(u8, src, "gutenberg") or std.mem.eql(u8, src, "pg")) {
        if (!allDigits(id) or id.len > 8) return null;
        return .{ .source = .gutenberg, .id = id };
    }
    if (std.mem.eql(u8, src, "standard") or std.mem.eql(u8, src, "se")) {
        var n: usize = 0;
        var it = std.mem.splitScalar(u8, id, '/');
        while (it.next()) |part| {
            if (!isSlug(part)) return null;
            n += 1;
        }
        if (n < 2 or n > 4) return null;
        return .{ .source = .standard, .id = id };
    }
    if (std.mem.eql(u8, src, "archive") or std.mem.eql(u8, src, "ia")) {
        if (!isArchiveId(id)) return null;
        return .{ .source = .archive, .id = id };
    }
    if (std.mem.eql(u8, src, "arxiv")) {
        if (!isArxivId(id)) return null;
        return .{ .source = .arxiv, .id = id };
    }
    return null;
}

pub fn specText(a: Allocator, spec: Spec) ![]u8 {
    return std.fmt.allocPrint(a, "book:{s}/{s}", .{ @tagName(spec.source), spec.id });
}

// ---------------------------------------------------------------------------
// Where a book comes from
// ---------------------------------------------------------------------------

pub const Plan = struct {
    url: []const u8,
    ext: []const u8,
    title: []const u8,
    author: []const u8,
    /// Published by the Internet Archive.
    sha1: ?[]const u8 = null,
    size: ?u64 = null,
};

const PlanError = error{ Unavailable, Restricted, NoSuchFormat, NotFound };

fn jsonString(v: ?std.json.Value) ?[]const u8 {
    const x = v orelse return null;
    return switch (x) {
        .string => |s| s,
        .array => |arr| if (arr.items.len != 0 and arr.items[0] == .string) arr.items[0].string else null,
        else => null,
    };
}

/// "Austen, Jane, 1775-1817" → "Jane Austen".
pub fn tidyAuthor(a: Allocator, raw: []const u8) ![]const u8 {
    var parts = std.mem.splitSequence(u8, raw, ", ");
    const last = parts.next() orelse return raw;
    const first = parts.next() orelse return raw;
    if (first.len == 0 or std.ascii.isDigit(first[0])) return last;
    return std.fmt.allocPrint(a, "{s} {s}", .{ first, last });
}

/// "pride-and-prejudice" → "Pride and Prejudice".
fn slugTitle(a: Allocator, slug: []const u8) ![]u8 {
    const small = [_][]const u8{ "a", "an", "and", "as", "at", "by", "for", "in", "of", "on", "or", "the", "to", "with" };
    var out = std.ArrayList(u8).init(a);
    var it = std.mem.splitScalar(u8, slug, '-');
    var first = true;
    while (it.next()) |w| {
        if (w.len == 0) continue;
        if (!first) try out.append(' ');
        var keep_small = false;
        if (!first) for (small) |sw| {
            keep_small = keep_small or std.mem.eql(u8, w, sw);
        };
        try out.append(if (keep_small) w[0] else std.ascii.toUpper(w[0]));
        try out.appendSlice(w[1..]);
        first = false;
    }
    return out.toOwnedSlice();
}

fn hostIs(url: []const u8, host: []const u8) bool {
    const prefix = "https://";
    if (!std.mem.startsWith(u8, url, prefix)) return false;
    const rest = url[prefix.len..];
    const end = std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len;
    return std.mem.eql(u8, rest[0..end], host);
}

fn gutenbergPlan(a: Allocator, id: []const u8, format: Format) !Plan {
    // Plain text redirects to plain http from /ebooks/, so it is taken from
    // the https file cache directly.
    const fallback_url = switch (format) {
        .epub => try std.fmt.allocPrint(a, "https://www.gutenberg.org/ebooks/{s}.epub3.images", .{id}),
        .kindle => try std.fmt.allocPrint(a, "https://www.gutenberg.org/ebooks/{s}.kf8.images", .{id}),
        .txt => try std.fmt.allocPrint(a, "https://www.gutenberg.org/cache/epub/{s}/pg{s}.txt", .{ id, id }),
        .pdf => return error.NoSuchFormat,
    };
    const ext = switch (format) {
        .epub => "epub",
        .kindle => "mobi",
        .txt => "txt",
        .pdf => unreachable,
    };
    const fallback: Plan = .{ .url = fallback_url, .ext = ext, .title = try std.fmt.allocPrint(a, "Gutenberg {s}", .{id}), .author = "" };
    // The catalog only names the book; without it the file still comes from gutenberg.org.
    const body = net.fetchToString(a, try std.fmt.allocPrint(a, "https://gutendex.com/books/{s}", .{id}), 1024 * 1024, .{}) catch return fallback;
    const v = std.json.parseFromSliceLeaky(std.json.Value, a, body, .{}) catch return fallback;
    if (v != .object) return fallback;
    if (v.object.get("detail") != null) return error.NotFound;
    const title = jsonString(v.object.get("title")) orelse return fallback;
    var author: []const u8 = "";
    if (v.object.get("authors")) |au| if (au == .array and au.array.items.len != 0 and au.array.items[0] == .object) {
        if (jsonString(au.array.items[0].object.get("name"))) |n| author = try tidyAuthor(a, n);
    };
    var url: []const u8 = fallback_url;
    if (v.object.get("formats")) |f| if (f == .object) {
        var it = f.object.iterator();
        while (it.next()) |e| {
            const want = switch (format) {
                .epub => std.mem.eql(u8, e.key_ptr.*, "application/epub+zip"),
                .kindle => std.mem.eql(u8, e.key_ptr.*, "application/x-mobipocket-ebook"),
                .txt => false,
                .pdf => false,
            };
            if (want and e.value_ptr.* == .string and hostIs(e.value_ptr.string, "www.gutenberg.org")) url = e.value_ptr.string;
        }
    };
    return .{ .url = url, .ext = ext, .title = title, .author = author };
}

fn standardPlan(a: Allocator, id: []const u8, format: Format) !Plan {
    const ext = switch (format) {
        .epub => "epub",
        .kindle => "azw3",
        .txt, .pdf => return error.NoSuchFormat,
    };
    const stem = try std.mem.replaceOwned(u8, a, id, "/", "_");
    var parts = std.mem.splitScalar(u8, id, '/');
    const author = try slugTitle(a, parts.next().?);
    const title = try slugTitle(a, parts.next().?);
    return .{
        .url = try std.fmt.allocPrint(a, "https://standardebooks.org/ebooks/{s}/downloads/{s}.{s}?source=download", .{ id, stem, ext }),
        .ext = ext,
        .title = title,
        .author = author,
    };
}

fn archivePlan(a: Allocator, id: []const u8, format: Format) !Plan {
    const body = net.fetchToString(a, try std.fmt.allocPrint(a, "https://archive.org/metadata/{s}", .{id}), 32 * 1024 * 1024, .{}) catch return error.Unavailable;
    const v = std.json.parseFromSliceLeaky(std.json.Value, a, body, .{}) catch return error.Unavailable;
    if (v != .object) return error.Unavailable;
    const meta = v.object.get("metadata") orelse return error.NotFound;
    if (meta != .object) return error.NotFound;
    // Borrow-only (lending library) and hidden items are not free downloads.
    if (jsonString(meta.object.get("access-restricted-item"))) |r| if (std.mem.eql(u8, r, "true")) return error.Restricted;
    if (v.object.get("is_dark")) |d| if (d == .bool and d.bool) return error.Restricted;
    const title = jsonString(meta.object.get("title")) orelse id;
    const author = if (jsonString(meta.object.get("creator"))) |c| try tidyAuthor(a, c) else "";

    const files = v.object.get("files") orelse return error.NoSuchFormat;
    if (files != .array) return error.NoSuchFormat;
    var best: ?std.json.ObjectMap = null;
    var best_rank: u8 = 0;
    for (files.array.items) |f| {
        if (f != .object) continue;
        const name = jsonString(f.object.get("name")) orelse continue;
        if (f.object.get("private")) |p| if ((p == .string and std.mem.eql(u8, p.string, "true")) or (p == .bool and p.bool)) continue;
        const fmt = jsonString(f.object.get("format")) orelse "";
        const rank: u8 = switch (format) {
            .pdf => if (std.mem.eql(u8, fmt, "Text PDF")) 3 else if (std.ascii.endsWithIgnoreCase(name, ".pdf")) 2 else 0,
            .epub => if (std.ascii.endsWithIgnoreCase(name, ".epub")) 2 else 0,
            .txt => if (std.mem.endsWith(u8, name, "_djvu.txt")) 2 else if (std.ascii.endsWithIgnoreCase(name, ".txt")) 1 else 0,
            .kindle => if (std.ascii.endsWithIgnoreCase(name, ".mobi")) 2 else 0,
        };
        if (rank > best_rank) {
            best = f.object;
            best_rank = rank;
        }
    }
    const f = best orelse return error.NoSuchFormat;
    const name = jsonString(f.get("name")).?;
    var size: ?u64 = null;
    if (jsonString(f.get("size"))) |s| size = std.fmt.parseInt(u64, s, 10) catch null;
    const sha1 = jsonString(f.get("sha1"));
    if (sha1) |h| if (h.len != 40) return error.Unavailable;
    return .{
        .url = try std.fmt.allocPrint(a, "https://archive.org/download/{s}/{s}", .{ id, try encodePath(a, name) }),
        .ext = switch (format) {
            .pdf => "pdf",
            .epub => "epub",
            .txt => "txt",
            .kindle => "mobi",
        },
        .title = title,
        .author = author,
        .sha1 = sha1,
        .size = size,
    };
}

fn encodePath(a: Allocator, p: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(a);
    for (p) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '/' or c == '~') try out.append(c) else try out.writer().print("%{X:0>2}", .{c});
    }
    return out.toOwnedSlice();
}

fn arxivPlan(a: Allocator, id: []const u8, format: Format) !Plan {
    if (format != .pdf) return error.NoSuchFormat;
    const url = try std.fmt.allocPrint(a, "https://arxiv.org/pdf/{s}", .{id});
    const body = net.fetchToString(a, try std.fmt.allocPrint(a, "https://export.arxiv.org/api/query?id_list={s}", .{id}), 4 * 1024 * 1024, .{}) catch
        return .{ .url = url, .ext = "pdf", .title = id, .author = "" };
    const entries = try parseArxiv(a, body);
    if (entries.len == 0) return error.NotFound;
    return .{ .url = url, .ext = "pdf", .title = entries[0].title, .author = entries[0].author };
}

pub fn plan(a: Allocator, spec: Spec, format: ?Format) !Plan {
    return switch (spec.source) {
        .gutenberg => gutenbergPlan(a, spec.id, format orelse .epub),
        .standard => standardPlan(a, spec.id, format orelse .epub),
        .archive => archivePlan(a, spec.id, format orelse .pdf),
        .arxiv => arxivPlan(a, spec.id, format orelse .pdf),
    };
}

// ---------------------------------------------------------------------------
// arXiv's Atom feed
// ---------------------------------------------------------------------------

pub const Hit = struct { spec: []const u8, title: []const u8, author: []const u8, note: []const u8 = "" };

fn between(s: []const u8, open: []const u8, close: []const u8) ?[]const u8 {
    const i = std.mem.indexOf(u8, s, open) orelse return null;
    const start = i + open.len;
    const j = std.mem.indexOfPos(u8, s, start, close) orelse return null;
    return s[start..j];
}

/// XML text to plain: entities decoded, runs of whitespace made one space.
pub fn plainText(a: Allocator, s: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(a);
    var i: usize = 0;
    var space = false;
    while (i < s.len) {
        const c = s[i];
        if (c == ' ' or c == '\n' or c == '\r' or c == '\t') {
            space = out.items.len != 0;
            i += 1;
            continue;
        }
        if (space) try out.append(' ');
        space = false;
        if (c == '&') {
            const ents = [_]struct { []const u8, u8 }{ .{ "&amp;", '&' }, .{ "&lt;", '<' }, .{ "&gt;", '>' }, .{ "&quot;", '"' }, .{ "&#39;", '\'' }, .{ "&apos;", '\'' } };
            var hit = false;
            for (ents) |e| if (std.mem.startsWith(u8, s[i..], e[0])) {
                try out.append(e[1]);
                i += e[0].len;
                hit = true;
                break;
            };
            if (hit) continue;
        }
        try out.append(c);
        i += 1;
    }
    return out.toOwnedSlice();
}

pub fn parseArxiv(a: Allocator, body: []const u8) ![]Hit {
    var hits = std.ArrayList(Hit).init(a);
    var it = std.mem.splitSequence(u8, body, "<entry>");
    _ = it.next();
    while (it.next()) |entry| {
        const raw_id = between(entry, "<id>", "</id>") orelse continue;
        const abs = "arxiv.org/abs/";
        const k = std.mem.indexOf(u8, raw_id, abs) orelse continue;
        const id = std.mem.trim(u8, raw_id[k + abs.len ..], " \n");
        if (!isArxivId(id)) continue;
        const title = try plainText(a, between(entry, "<title>", "</title>") orelse id);
        var author: []const u8 = "";
        if (between(entry, "<name>", "</name>")) |n| {
            const more = std.mem.count(u8, entry, "<author>") > 1;
            author = try std.fmt.allocPrint(a, "{s}{s}", .{ try plainText(a, n), if (more) " et al." else "" });
        }
        const published = between(entry, "<published>", "</published>") orelse "";
        try hits.append(.{ .spec = try std.fmt.allocPrint(a, "book:arxiv/{s}", .{id}), .title = title, .author = author, .note = if (published.len >= 4) published[0..4] else "" });
    }
    return hits.toOwnedSlice();
}

// ---------------------------------------------------------------------------
// Checking what arrived
// ---------------------------------------------------------------------------

/// True when the first bytes of a file fit its format, so an HTML error page
/// or a different kind of file is never kept as a book.
pub fn looksLike(ext: []const u8, head: []const u8) bool {
    if (std.mem.eql(u8, ext, "pdf")) return std.mem.startsWith(u8, head, "%PDF-");
    if (std.mem.eql(u8, ext, "epub")) return std.mem.startsWith(u8, head, "PK\x03\x04") and std.mem.indexOf(u8, head[0..@min(head.len, 128)], "application/epub+zip") != null;
    if (std.mem.eql(u8, ext, "mobi") or std.mem.eql(u8, ext, "azw3")) return head.len >= 68 and std.mem.eql(u8, head[60..68], "BOOKMOBI");
    if (std.mem.eql(u8, ext, "txt")) {
        if (std.mem.indexOfScalar(u8, head, 0) != null) return false;
        const t = std.mem.trimLeft(u8, head, " \t\r\n\xef\xbb\xbf");
        return !std.ascii.startsWithIgnoreCase(t, "<!doctype") and !std.ascii.startsWithIgnoreCase(t, "<html");
    }
    return false;
}

fn sha1File(path: []const u8) ![40]u8 {
    const f = try std.fs.cwd().openFile(path, .{});
    defer f.close();
    var h = std.crypto.hash.Sha1.init(.{});
    var buf: [64 * 1024]u8 = undefined;
    while (true) {
        const n = try f.read(&buf);
        if (n == 0) break;
        h.update(buf[0..n]);
    }
    return std.fmt.bytesToHex(h.finalResult(), .lower);
}

/// "Title - Author.ext" with anything a file system might mind taken out.
pub fn fileName(a: Allocator, p: Plan) ![]u8 {
    var out = std.ArrayList(u8).init(a);
    defer out.deinit();
    const raw = if (p.author.len != 0) try std.fmt.allocPrint(a, "{s} - {s}", .{ p.title, p.author }) else try a.dupe(u8, p.title);
    defer a.free(raw);
    var space = false;
    for (raw) |c| {
        const keep = std.ascii.isAlphanumeric(c) or c >= 0x80 or std.mem.indexOfScalar(u8, " .,'()&!-_", c) != null;
        if (!keep or c == ' ') {
            space = out.items.len != 0;
            continue;
        }
        if (space) try out.append(' ');
        space = false;
        try out.append(c);
    }
    // No leading dots (hidden files), and a sane length on every system.
    var name = std.mem.trimLeft(u8, out.items, ". ");
    if (name.len > 150) {
        var cut: usize = 150;
        while (cut > 0 and (name[cut] & 0xC0) == 0x80) cut -= 1;
        name = name[0..cut];
    }
    name = std.mem.trimRight(u8, name, ". ");
    if (name.len == 0) name = "book";
    // Windows keeps these names for devices, whatever the extension.
    const reserved = [_][]const u8{ "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9" };
    for (reserved) |r| if (std.ascii.eqlIgnoreCase(name, r)) return std.fmt.allocPrint(a, "{s} (book).{s}", .{ name, p.ext });
    return std.fmt.allocPrint(a, "{s}.{s}", .{ name, p.ext });
}

// ---------------------------------------------------------------------------
// The books folder and its index
// ---------------------------------------------------------------------------

pub fn booksDir(a: Allocator) ![]u8 {
    if (platform.envOwned(a, "ABV0_BOOKS_DIR")) |d| if (d.len != 0) return d;
    return std.fs.path.join(a, &.{ try platform.homeDir(a), "Books" });
}

const index_name = ".abv0-books";

pub const Entry = struct { spec: []const u8, file: []const u8, sha256: []const u8 };

/// Lines of `spec<TAB>file<TAB>sha256`. A line that does not parse is skipped.
pub fn parseIndex(a: Allocator, text: []const u8) ![]Entry {
    var out = std.ArrayList(Entry).init(a);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var f = std.mem.splitScalar(u8, line, '\t');
        const spec = f.next() orelse continue;
        const file = f.next() orelse continue;
        const sha = f.next() orelse continue;
        if (parseSpec(spec) == null or file.len == 0 or std.mem.indexOfAny(u8, file, "/\\") != null or file[0] == '.') continue;
        try out.append(.{ .spec = spec, .file = file, .sha256 = sha });
    }
    return out.toOwnedSlice();
}

fn loadIndex(a: Allocator, dir: []const u8) ![]Entry {
    const path = try std.fs.path.join(a, &.{ dir, index_name });
    const text = std.fs.cwd().readFileAlloc(a, path, 16 * 1024 * 1024) catch return &.{};
    return parseIndex(a, text);
}

fn saveIndex(a: Allocator, dir: []const u8, entries: []const Entry) !void {
    var buf = std.ArrayList(u8).init(a);
    for (entries) |e| try buf.writer().print("{s}\t{s}\t{s}\n", .{ e.spec, e.file, e.sha256 });
    const path = try std.fs.path.join(a, &.{ dir, index_name });
    const tmp = try std.fmt.allocPrint(a, "{s}.{x}.tmp", .{ path, std.crypto.random.int(u32) });
    try std.fs.cwd().writeFile(.{ .sub_path = tmp, .data = buf.items });
    try std.fs.cwd().rename(tmp, path);
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

pub const Options = struct {
    format: ?Format = null,
    force: bool = false,
    dry_run: bool = false,
    quiet: bool = false,
};

fn planError(shown: []const u8, e: anyerror, format: ?Format) void {
    const why = switch (e) {
        error.NotFound => "not found",
        error.Restricted => "this is a borrow-only (lending library) item, not a free download",
        error.NoSuchFormat => if (format) |f| switch (f) {
            .epub => "no EPUB of this one (try --format pdf or txt)",
            .pdf => "no PDF of this one (try --format epub)",
            .txt => "no plain text of this one",
            .kindle => "no Kindle file of this one (try --format epub)",
        } else "no file in that format",
        error.Unavailable => "the source cannot be reached right now",
        else => @errorName(e),
    };
    term.err("{s}error{s}: {s}: {s}\n", .{ term.red, term.reset, shown, why });
}

/// `abv0 install book:...`
pub fn install(base: Allocator, spec: Spec, opts: Options) !u8 {
    var arena = std.heap.ArenaAllocator.init(base);
    defer arena.deinit();
    const a = arena.allocator();
    var timer = try std.time.Timer.start();
    const shown = try specText(a, spec);

    const dir = try booksDir(a);
    var entries = std.ArrayList(Entry).init(a);
    try entries.appendSlice(try loadIndex(a, dir));
    if (!opts.force and opts.format == null) for (entries.items) |e| {
        if (!std.mem.eql(u8, e.spec, shown)) continue;
        const have = try std.fs.path.join(a, &.{ dir, e.file });
        std.fs.cwd().access(have, .{}) catch continue;
        if (!opts.quiet) term.print("{s} is already downloaded\n  {s}\n", .{ shown, have });
        return 0;
    };

    const p = plan(a, spec, opts.format) catch |e| {
        planError(shown, e, opts.format);
        return 1;
    };
    const first_name = try fileName(a, p);
    var name = first_name;
    if (opts.dry_run) {
        term.print("  {s}  {s}\n  from {s}\ndry run: nothing was downloaded\n", .{ shown, name, p.url });
        return 0;
    }
    try std.fs.cwd().makePath(dir);
    // A different book with the same name keeps its file.
    var n: usize = 2;
    while (true) : (n += 1) {
        const taken = blk: {
            std.fs.cwd().access(try std.fs.path.join(a, &.{ dir, name }), .{}) catch break :blk false;
            for (entries.items) |e| if (std.mem.eql(u8, e.file, name) and std.mem.eql(u8, e.spec, shown)) break :blk false;
            break :blk true;
        };
        if (!taken) break;
        const stem = first_name[0 .. first_name.len - p.ext.len - 1];
        name = try std.fmt.allocPrint(a, "{s} ({d}).{s}", .{ stem, n, p.ext });
    }
    const dest = try std.fs.path.join(a, &.{ dir, name });
    const tmp = try std.fmt.allocPrint(a, "{s}.{x}.incomplete", .{ try std.fs.path.join(a, &.{ dir, ".abv0" }), std.crypto.random.int(u32) });
    errdefer std.fs.cwd().deleteFile(tmp) catch {};

    const got = net.downloadHashed(a, p.url, tmp, .{ .max_time_s = 3600 }) catch |e| {
        std.fs.cwd().deleteFile(tmp) catch {};
        term.err("{s}error{s}: {s}: download failed ({s})\n", .{ term.red, term.reset, shown, @errorName(e) });
        return 1;
    };
    const fail = struct {
        fn f(path: []const u8, what: []const u8, msg: []const u8) u8 {
            std.fs.cwd().deleteFile(path) catch {};
            term.err("{s}error{s}: {s}: {s}; nothing was kept\n", .{ term.red, term.reset, what, msg });
            return 1;
        }
    }.f;
    if (p.size) |want| if (got.bytes != want) return fail(tmp, shown, "the size does not match what the source lists");
    if (p.sha1) |want| {
        const have = try sha1File(tmp);
        if (!std.ascii.eqlIgnoreCase(&have, want)) return fail(tmp, shown, "the SHA-1 does not match what the Internet Archive lists");
    }
    {
        const f = try std.fs.cwd().openFile(tmp, .{});
        defer f.close();
        var head: [512]u8 = undefined;
        const len = try f.readAll(&head);
        if (!looksLike(p.ext, head[0..len])) return fail(tmp, shown, "the file is not a real book in that format (an error page or another kind of file)");
    }
    try std.fs.cwd().rename(tmp, dest);

    const sha = std.fmt.bytesToHex(got.digest, .lower);
    var kept = std.ArrayList(Entry).init(a);
    for (entries.items) |e| if (!std.mem.eql(u8, e.spec, shown) or !std.mem.eql(u8, e.file, name)) try kept.append(e);
    try kept.append(.{ .spec = shown, .file = name, .sha256 = try a.dupe(u8, &sha) });
    try saveIndex(a, dir, kept.items);

    if (!opts.quiet) {
        var buf: [32]u8 = undefined;
        const secs = @as(f64, @floatFromInt(timer.read())) / 1e9;
        term.print("{s}done{s} {s} ({s}, {s}{s}) in {d:.1}s\n  {s}\n", .{ term.green, term.reset, p.title, spec.source.label(), fmtSize(&buf, got.bytes), if (p.sha1 != null) ", SHA-1 checked" else "", secs, dest });
    }
    return 0;
}

fn fmtSize(buf: []u8, n: u64) []const u8 {
    const f: f64 = @floatFromInt(n);
    if (n >= 1 << 20) return std.fmt.bufPrint(buf, "{d:.1} MB", .{f / (1 << 20)}) catch "?";
    return std.fmt.bufPrint(buf, "{d} KB", .{(n + 1023) / 1024}) catch "?";
}

/// `abv0 uninstall book:...`: delete the files abv0 downloaded for it.
pub fn remove(base: Allocator, spec: Spec, dry_run: bool) !u8 {
    var arena = std.heap.ArenaAllocator.init(base);
    defer arena.deinit();
    const a = arena.allocator();
    const shown = try specText(a, spec);
    const dir = try booksDir(a);
    const entries = try loadIndex(a, dir);
    var kept = std.ArrayList(Entry).init(a);
    var removed: usize = 0;
    for (entries) |e| {
        if (!std.mem.eql(u8, e.spec, shown)) {
            try kept.append(e);
            continue;
        }
        const path = try std.fs.path.join(a, &.{ dir, e.file });
        if (dry_run) {
            term.print("  remove   {s}\n", .{path});
        } else {
            std.fs.cwd().deleteFile(path) catch |err| if (err != error.FileNotFound) return err;
            term.print("removed {s}\n", .{path});
        }
        removed += 1;
    }
    if (removed == 0) {
        term.err("{s} was not downloaded by abv0\n", .{shown});
        return 1;
    }
    if (!dry_run) try saveIndex(a, dir, kept.items);
    return 0;
}

/// `abv0 book list`
pub fn list(base: Allocator) !u8 {
    var arena = std.heap.ArenaAllocator.init(base);
    defer arena.deinit();
    const a = arena.allocator();
    const dir = try booksDir(a);
    const entries = try loadIndex(a, dir);
    var shown: usize = 0;
    for (entries) |e| {
        std.fs.cwd().access(try std.fs.path.join(a, &.{ dir, e.file }), .{}) catch continue;
        term.print("{s:<44} {s}\n", .{ e.spec, e.file });
        shown += 1;
    }
    term.print("{d} books in {s}\n", .{ shown, dir });
    return 0;
}

// ---------------------------------------------------------------------------
// Search: every source at once
// ---------------------------------------------------------------------------

const per_source = 8;

fn query(a: Allocator, words: []const []const u8, sep: []const u8) ![]u8 {
    var q = std.ArrayList(u8).init(a);
    for (words, 0..) |w, i| {
        if (i != 0) try q.appendSlice(sep);
        for (w) |c| {
            if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.') try q.append(c) else try q.writer().print("%{X:0>2}", .{c});
        }
    }
    return q.toOwnedSlice();
}

fn searchGutenberg(a: Allocator, words: []const []const u8) ![]Hit {
    const body = try net.fetchToString(a, try std.fmt.allocPrint(a, "https://gutendex.com/books/?search={s}", .{try query(a, words, "%20")}), 8 * 1024 * 1024, .{});
    return parseGutendex(a, body);
}

pub fn parseGutendex(a: Allocator, body: []const u8) ![]Hit {
    const v = try std.json.parseFromSliceLeaky(std.json.Value, a, body, .{});
    if (v != .object) return &.{};
    const results = v.object.get("results") orelse return &.{};
    if (results != .array) return &.{};
    var hits = std.ArrayList(Hit).init(a);
    for (results.array.items) |r| {
        if (hits.items.len == per_source) break;
        if (r != .object) continue;
        const id = r.object.get("id") orelse continue;
        if (id != .integer or id.integer <= 0) continue;
        const title = jsonString(r.object.get("title")) orelse continue;
        var author: []const u8 = "";
        if (r.object.get("authors")) |au| if (au == .array and au.array.items.len != 0 and au.array.items[0] == .object) {
            if (jsonString(au.array.items[0].object.get("name"))) |n| author = try tidyAuthor(a, n);
        };
        try hits.append(.{ .spec = try std.fmt.allocPrint(a, "book:gutenberg/{d}", .{id.integer}), .title = title, .author = author });
    }
    return hits.toOwnedSlice();
}

fn searchStandard(a: Allocator, words: []const []const u8) ![]Hit {
    const body = try net.fetchToString(a, try std.fmt.allocPrint(a, "https://standardebooks.org/ebooks?query={s}", .{try query(a, words, "+")}), 8 * 1024 * 1024, .{});
    return parseStandard(a, body);
}

pub fn parseStandard(a: Allocator, body: []const u8) ![]Hit {
    var hits = std.ArrayList(Hit).init(a);
    var rest = body;
    const marker = "href=\"/ebooks/";
    while (std.mem.indexOf(u8, rest, marker)) |i| {
        rest = rest[i + marker.len ..];
        const end = std.mem.indexOfScalar(u8, rest, '"') orelse break;
        const path = rest[0..end];
        const spec = try std.fmt.allocPrint(a, "book:standard/{s}", .{path});
        if (parseSpec(spec) == null) continue;
        var dup = false;
        for (hits.items) |h| dup = dup or std.mem.eql(u8, h.spec, spec);
        if (dup) continue;
        var parts = std.mem.splitScalar(u8, path, '/');
        const author = try slugTitle(a, parts.next().?);
        const title = try slugTitle(a, parts.next().?);
        try hits.append(.{ .spec = spec, .title = title, .author = author });
        if (hits.items.len == per_source) break;
    }
    return hits.toOwnedSlice();
}

fn searchArchive(a: Allocator, words: []const []const u8) ![]Hit {
    const url = try std.fmt.allocPrint(a, "https://archive.org/advancedsearch.php?q=title%3A%28{s}%29+AND+mediatype%3Atexts+AND+NOT+access-restricted-item%3Atrue&fl%5B%5D=identifier&fl%5B%5D=title&fl%5B%5D=creator&fl%5B%5D=year&sort%5B%5D=downloads+desc&rows={d}&output=json", .{ try query(a, words, "+"), per_source });
    const body = try net.fetchToString(a, url, 8 * 1024 * 1024, .{});
    return parseArchiveSearch(a, body);
}

pub fn parseArchiveSearch(a: Allocator, body: []const u8) ![]Hit {
    const v = try std.json.parseFromSliceLeaky(std.json.Value, a, body, .{});
    if (v != .object) return &.{};
    const resp = v.object.get("response") orelse return &.{};
    if (resp != .object) return &.{};
    const docs = resp.object.get("docs") orelse return &.{};
    if (docs != .array) return &.{};
    var hits = std.ArrayList(Hit).init(a);
    for (docs.array.items) |d| {
        if (d != .object) continue;
        const id = jsonString(d.object.get("identifier")) orelse continue;
        if (!isArchiveId(id)) continue;
        const year: []const u8 = if (d.object.get("year")) |y| switch (y) {
            .integer => |n| try std.fmt.allocPrint(a, "{d}", .{n}),
            .string => |s| s,
            else => "",
        } else "";
        try hits.append(.{
            .spec = try std.fmt.allocPrint(a, "book:archive/{s}", .{id}),
            .title = jsonString(d.object.get("title")) orelse id,
            .author = if (jsonString(d.object.get("creator"))) |c| try tidyAuthor(a, c) else "",
            .note = year,
        });
    }
    return hits.toOwnedSlice();
}

fn searchArxiv(a: Allocator, words: []const []const u8) ![]Hit {
    var q = std.ArrayList(u8).init(a);
    for (words, 0..) |w, i| {
        if (i != 0) try q.appendSlice("+AND+");
        try q.writer().print("all:{s}", .{try query(a, &.{w}, "")});
    }
    const body = try net.fetchToString(a, try std.fmt.allocPrint(a, "https://export.arxiv.org/api/query?search_query={s}&max_results={d}&sortBy=relevance", .{ q.items, per_source }), 8 * 1024 * 1024, .{});
    // A busy answer ("Rate exceeded.") is not an empty result.
    if (std.mem.indexOf(u8, body, "<feed") == null) return error.Unavailable;
    return parseArxiv(a, body);
}

const Search = struct {
    source: Source,
    words: []const []const u8,
    hits: []Hit = &.{},
    failed: bool = false,
    arena: std.heap.ArenaAllocator,

    fn run(self: *Search) void {
        const a = self.arena.allocator();
        self.hits = (switch (self.source) {
            .gutenberg => searchGutenberg(a, self.words),
            .standard => searchStandard(a, self.words),
            .archive => searchArchive(a, self.words),
            .arxiv => searchArxiv(a, self.words),
        }) catch {
            self.failed = true;
            return;
        };
    }
};

/// `abv0 book search <words>`: Project Gutenberg, Standard Ebooks, the
/// Internet Archive and arXiv, asked at the same time.
pub fn search(words: []const []const u8, only: ?Source) !u8 {
    var searches: [4]Search = undefined;
    var threads: [4]?std.Thread = .{ null, null, null, null };
    var n: usize = 0;
    for ([_]Source{ .gutenberg, .standard, .archive, .arxiv }) |s| {
        if (only != null and only.? != s) continue;
        // Each search has its own arena over the thread-safe page allocator.
        searches[n] = .{ .source = s, .words = words, .arena = std.heap.ArenaAllocator.init(std.heap.page_allocator) };
        n += 1;
    }
    defer for (searches[0..n]) |*s| s.arena.deinit();
    for (searches[0..n], 0..) |*s, i| threads[i] = std.Thread.spawn(.{}, Search.run, .{s}) catch blk: {
        s.run();
        break :blk null;
    };
    for (threads[0..n]) |t| if (t) |th| th.join();

    var total: usize = 0;
    for (searches[0..n]) |s| {
        term.print("{s}{s}{s}\n", .{ term.bold, s.source.label(), term.reset });
        if (s.failed) {
            term.print("  (cannot be reached right now)\n", .{});
            continue;
        }
        if (s.hits.len == 0) term.print("  no match\n", .{});
        for (s.hits) |h| {
            term.print("  {s:<44} {s}", .{ h.spec, h.title });
            if (h.author.len != 0) term.print(" — {s}", .{h.author});
            if (h.note.len != 0) term.print(" ({s})", .{h.note});
            term.print("\n", .{});
        }
        total += s.hits.len;
    }
    if (total != 0) term.print("install one with `abv0 install <book:...>` (--format epub|pdf|txt|kindle)\n", .{});
    return 0;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parseSpec reads every source and refuses bad ids" {
    const g = parseSpec("book:gutenberg/1342").?;
    try testing.expect(g.source == .gutenberg);
    try testing.expectEqualStrings("1342", g.id);
    try testing.expect(parseSpec("book:pg/84").?.source == .gutenberg);
    try testing.expect(parseSpec("book:standard/jane-austen/pride-and-prejudice").?.source == .standard);
    try testing.expect(parseSpec("book:standard/leo-tolstoy/anna-karenina/constance-garnett") != null);
    try testing.expect(parseSpec("book:archive/prideprejudice00aust").?.source == .archive);
    try testing.expect(parseSpec("book:arxiv/1706.03762").?.source == .arxiv);
    try testing.expect(parseSpec("book:arxiv/2401.12345v2") != null);
    try testing.expect(parseSpec("book:arxiv/hep-th/9901001") != null);

    try testing.expect(parseSpec("book:gutenberg/12a") == null);
    try testing.expect(parseSpec("book:gutenberg/") == null);
    try testing.expect(parseSpec("book:standard/jane-austen") == null);
    try testing.expect(parseSpec("book:standard/../etc") == null);
    try testing.expect(parseSpec("book:archive/../x") == null);
    try testing.expect(parseSpec("book:archive/a/b") == null);
    try testing.expect(parseSpec("book:arxiv/1706.037") == null);
    try testing.expect(parseSpec("book:oceanofpdf/x") == null);
    try testing.expect(parseSpec("gutenberg/1342") == null);
}

test "fileName keeps a readable, safe name" {
    const a = testing.allocator;
    const n1 = try fileName(a, .{ .url = "", .ext = "epub", .title = "Pride and Prejudice", .author = "Jane Austen" });
    defer a.free(n1);
    try testing.expectEqualStrings("Pride and Prejudice - Jane Austen.epub", n1);
    const n2 = try fileName(a, .{ .url = "", .ext = "pdf", .title = "../../etc/passwd: a\x00b", .author = "" });
    defer a.free(n2);
    try testing.expect(std.mem.indexOfAny(u8, n2, "/\\:\x00") == null);
    try testing.expect(n2[0] != '.');
    const n3 = try fileName(a, .{ .url = "", .ext = "txt", .title = "...", .author = "" });
    defer a.free(n3);
    try testing.expectEqualStrings("book.txt", n3);
    const n4 = try fileName(a, .{ .url = "", .ext = "txt", .title = "Nul", .author = "" });
    defer a.free(n4);
    try testing.expectEqualStrings("Nul (book).txt", n4);
}

test "tidyAuthor turns catalog names around" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings("Jane Austen", try tidyAuthor(arena.allocator(), "Austen, Jane, 1775-1817"));
    try testing.expectEqualStrings("Jane Austen", try tidyAuthor(arena.allocator(), "Austen, Jane"));
    try testing.expectEqualStrings("Plato", try tidyAuthor(arena.allocator(), "Plato"));
    try testing.expectEqualStrings("Pride and Prejudice", try slugTitle(arena.allocator(), "pride-and-prejudice"));
    try testing.expectEqualStrings("The Call of the Wild", try slugTitle(arena.allocator(), "the-call-of-the-wild"));
}

test "looksLike catches error pages and wrong files" {
    try testing.expect(looksLike("pdf", "%PDF-1.7\n..."));
    try testing.expect(!looksLike("pdf", "<!DOCTYPE html><html>"));
    try testing.expect(looksLike("epub", "PK\x03\x04\x14\x00\x00\x00\x00\x00\x17\x80Z]oa\xab,\x14\x00\x00\x00\x14\x00\x00\x00\x08\x00\x00\x00mimetypeapplication/epub+zip"));
    try testing.expect(!looksLike("epub", "PK\x03\x04 a plain zip"));
    var mobi = [_]u8{0} ** 80;
    @memcpy(mobi[60..68], "BOOKMOBI");
    try testing.expect(looksLike("mobi", &mobi));
    try testing.expect(looksLike("txt", "\xef\xbb\xbfThe Project Gutenberg eBook of Pride and Prejudice"));
    try testing.expect(!looksLike("txt", "  <html><body>Not found"));
    try testing.expect(!looksLike("exe", "MZ"));
}

test "parseArxiv reads entries" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const hits = try parseArxiv(arena.allocator(),
        \\<feed><title>q</title>
        \\<entry><id>http://arxiv.org/abs/1706.03762v7</id><title>Attention Is All
        \\  You Need</title><published>2017-06-12T17:57:34Z</published>
        \\<author><name>Ashish Vaswani</name></author><author><name>Noam Shazeer</name></author></entry>
        \\<entry><id>http://arxiv.org/abs/../../x</id><title>bad</title></entry>
        \\</feed>
    );
    try testing.expectEqual(@as(usize, 1), hits.len);
    try testing.expectEqualStrings("book:arxiv/1706.03762v7", hits[0].spec);
    try testing.expectEqualStrings("Attention Is All You Need", hits[0].title);
    try testing.expectEqualStrings("Ashish Vaswani et al.", hits[0].author);
    try testing.expectEqualStrings("2017", hits[0].note);
}

test "search parsers for Gutenberg, Standard Ebooks and the Internet Archive" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const g = try parseGutendex(a,
        \\{"count":1,"results":[{"id":1342,"title":"Pride and Prejudice","authors":[{"name":"Austen, Jane"}]},{"id":-1,"title":"x"}]}
    );
    try testing.expectEqual(@as(usize, 1), g.len);
    try testing.expectEqualStrings("book:gutenberg/1342", g[0].spec);
    try testing.expectEqualStrings("Jane Austen", g[0].author);

    const s = try parseStandard(a,
        \\<a href="/ebooks/jane-austen/emma">x</a><a href="/ebooks/jane-austen/emma">again</a>
        \\<a href="/ebooks/jane-austen">author page</a><a href="/ebooks/x/y/downloads/x_y.epub">dl</a>
        \\<a href="/ebooks/leo-tolstoy/anna-karenina/constance-garnett">t</a>
    );
    try testing.expectEqual(@as(usize, 2), s.len);
    try testing.expectEqualStrings("book:standard/jane-austen/emma", s[0].spec);
    try testing.expectEqualStrings("Emma", s[0].title);
    try testing.expectEqualStrings("Leo Tolstoy", s[1].author);

    const ia = try parseArchiveSearch(a,
        \\{"response":{"docs":[{"identifier":"prideprejudice00aust","title":"Pride and prejudice","creator":["Austen, Jane, 1775-1817"],"year":1894},{"identifier":"../bad"}]}}
    );
    try testing.expectEqual(@as(usize, 1), ia.len);
    try testing.expectEqualStrings("1894", ia[0].note);
}

test "parseIndex skips lines that could point outside the folder" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const e = try parseIndex(arena.allocator(), "book:gutenberg/1342\tPride.epub\tab\nbook:gutenberg/1\t../x\tab\nbook:gutenberg/2\t.hidden\tab\njunk\n");
    try testing.expectEqual(@as(usize, 1), e.len);
    try testing.expectEqualStrings("Pride.epub", e[0].file);
}
