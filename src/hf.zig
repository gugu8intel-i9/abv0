//! Hugging Face models and datasets: `abv0 install hf:owner/name`.
//!
//! Files go into the Hugging Face cache, in the layout the `huggingface_hub`
//! library uses (`<cache>/models--owner--name/{blobs,snapshots,refs}`), so
//! transformers, datasets, diffusers, llama.cpp and friends find them with no
//! extra setup. The cache is `$HF_HUB_CACHE`, else `$HF_HOME/hub`, else
//! `~/.cache/huggingface/hub`.
//!
//! Every file is verified: a large (LFS) file against the SHA-256 the Hub
//! publishes for it, a small one against its git blob id (SHA-1 of
//! `blob <size>\0<content>`). Nothing that fails reaches the cache. Pickle
//! files (`.bin`, `.pt`, `.pkl`, ...) can run code when loaded, so they are
//! scanned for imports of dangerous modules first.
//!
//! The revision is pinned to the commit the Hub names when the listing is read,
//! so all files come from one commit even if the repository changes meanwhile.

const std = @import("std");
const builtin = @import("builtin");
const http = @import("http.zig");
const net = @import("net.zig");
const platform = @import("platform.zig");
const safepath = @import("safepath.zig");
const term = @import("term.zig");

const Allocator = std.mem.Allocator;
const Sha1 = std.crypto.hash.Sha1;

pub const hub = "https://huggingface.co";

pub const Kind = enum {
    model,
    dataset,

    fn plural(self: Kind) []const u8 {
        return switch (self) {
            .model => "models",
            .dataset => "datasets",
        };
    }
};

pub const Spec = struct {
    kind: Kind,
    /// Empty for the few old repositories with no owner (`gpt2`).
    owner: []const u8,
    name: []const u8,
    revision: []const u8 = "main",
};

fn validPart(s: []const u8) bool {
    if (s.len == 0 or s.len > 96) return false;
    if (s[0] == '.' or s[0] == '-') return false;
    if (std.mem.indexOf(u8, s, "..") != null) return false;
    for (s) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_' and c != '.') return false;
    }
    return true;
}

fn validRevision(s: []const u8) bool {
    if (s.len == 0 or s.len > 128) return false;
    if (s[0] == '.' or s[0] == '-' or s[0] == '/') return false;
    if (std.mem.indexOf(u8, s, "..") != null) return false;
    for (s) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_' and c != '.' and c != '/') return false;
    }
    return true;
}

/// `hf:owner/name[@revision]`, `hf:datasets/owner/name[@revision]` (also
/// `hf:models/...`), or `hf:name` for an owner-less model. Null when the text
/// is not one; the parts are checked, so they are safe in URLs and paths.
pub fn parseSpec(text: []const u8) ?Spec {
    if (!std.mem.startsWith(u8, text, "hf:")) return null;
    var rest = text["hf:".len..];
    var revision: []const u8 = "main";
    if (std.mem.indexOfScalar(u8, rest, '@')) |at| {
        revision = rest[at + 1 ..];
        rest = rest[0..at];
        if (!validRevision(revision)) return null;
    }
    var kind: Kind = .model;
    if (std.mem.startsWith(u8, rest, "datasets/")) {
        kind = .dataset;
        rest = rest["datasets/".len..];
    } else if (std.mem.startsWith(u8, rest, "models/")) {
        rest = rest["models/".len..];
    }
    var owner: []const u8 = "";
    var name = rest;
    if (std.mem.indexOfScalar(u8, rest, '/')) |slash| {
        owner = rest[0..slash];
        name = rest[slash + 1 ..];
        if (!validPart(owner)) return null;
    } else if (kind == .dataset) return null;
    if (!validPart(name)) return null;
    return .{ .kind = kind, .owner = owner, .name = name, .revision = revision };
}

pub fn repoId(a: Allocator, spec: Spec) ![]u8 {
    if (spec.owner.len == 0) return a.dupe(u8, spec.name);
    return std.fmt.allocPrint(a, "{s}/{s}", .{ spec.owner, spec.name });
}

/// `hf:owner/name` or `hf:datasets/owner/name`, as typed.
pub fn display(a: Allocator, spec: Spec) ![]u8 {
    const id = try repoId(a, spec);
    return if (spec.kind == .dataset) std.fmt.allocPrint(a, "hf:datasets/{s}", .{id}) else std.fmt.allocPrint(a, "hf:{s}", .{id});
}

/// The listing of one revision, with file sizes and hashes.
pub fn apiUrl(a: Allocator, spec: Spec) ![]u8 {
    return std.fmt.allocPrint(a, hub ++ "/api/{s}/{s}/revision/{s}?blobs=true", .{ spec.kind.plural(), try repoId(a, spec), spec.revision });
}

/// The download link of one file at a commit. The path is percent-encoded
/// except for `/`.
pub fn fileUrl(a: Allocator, spec: Spec, commit: []const u8, path: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(a);
    const w = out.writer();
    try w.writeAll(hub ++ "/");
    if (spec.kind == .dataset) try w.writeAll("datasets/");
    try w.print("{s}/resolve/{s}/", .{ try repoId(a, spec), commit });
    for (path) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '/' or c == '-' or c == '_' or c == '.' or c == '~') {
            try out.append(c);
        } else try w.print("%{X:0>2}", .{c});
    }
    return out.toOwnedSlice();
}

/// `models--owner--name`, the folder `huggingface_hub` uses.
pub fn cacheFolderName(a: Allocator, spec: Spec) ![]u8 {
    if (spec.owner.len == 0) return std.fmt.allocPrint(a, "{s}--{s}", .{ spec.kind.plural(), spec.name });
    return std.fmt.allocPrint(a, "{s}--{s}--{s}", .{ spec.kind.plural(), spec.owner, spec.name });
}

// ---------------------------------------------------------------------------
// The listing
// ---------------------------------------------------------------------------

pub const File = struct {
    path: []const u8,
    size: u64,
    /// The git blob id (40 hex characters).
    blob_id: []const u8,
    /// For a large file stored with LFS, its SHA-256 (64 hex characters).
    sha256: ?[]const u8 = null,

    /// The name `huggingface_hub` gives the blob: the SHA-256 for LFS files,
    /// else the git blob id.
    pub fn etag(self: File) []const u8 {
        return self.sha256 orelse self.blob_id;
    }
};

pub const Repo = struct {
    id: []const u8,
    commit: []const u8,
    gated: bool,
    files: []File,
};

fn isHex(s: []const u8, n: usize) bool {
    if (s.len != n) return false;
    for (s) |c| {
        if (!std.ascii.isHex(c) or std.ascii.isUpper(c)) return false;
    }
    return true;
}

/// A file path from the listing that is safe to create under the snapshot.
pub fn isSafeRepoPath(p: []const u8) bool {
    if (p.len == 0 or p.len > 1024) return false;
    if (std.mem.indexOfScalar(u8, p, '\\') != null) return false;
    if (!safepath.isSafeRelPath(p)) return false;
    var it = std.mem.splitScalar(u8, p, '/');
    while (it.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return false;
        for (part) |c| {
            if (c < 0x20 or c == 0x7f or c == ':' or c == '*' or c == '?' or c == '"' or c == '<' or c == '>' or c == '|') return false;
        }
    }
    return true;
}

/// The Hub's answer for one revision. Files with an unsafe path or a
/// malformed hash are refused outright: a listing that names one is not used.
pub fn parseRepo(a: Allocator, body: []const u8) !Repo {
    const v = std.json.parseFromSliceLeaky(std.json.Value, a, body, .{}) catch return error.BadListing;
    if (v != .object) return error.BadListing;
    const o = v.object;
    if (o.get("error")) |e| {
        if (e == .string) term.err("Hugging Face says: {s}\n", .{e.string});
        return error.NotFound;
    }
    const id = (o.get("id") orelse return error.BadListing);
    const sha = (o.get("sha") orelse return error.BadListing);
    if (id != .string or sha != .string or !isHex(sha.string, 40)) return error.BadListing;
    const gated = if (o.get("gated")) |g| (g == .string or (g == .bool and g.bool)) else false;
    var files = std.ArrayList(File).init(a);
    const siblings = o.get("siblings") orelse return error.BadListing;
    if (siblings != .array) return error.BadListing;
    for (siblings.array.items) |s| {
        if (s != .object) return error.BadListing;
        const path = s.object.get("rfilename") orelse return error.BadListing;
        const blob = s.object.get("blobId") orelse return error.BadListing;
        const size = s.object.get("size") orelse return error.BadListing;
        if (path != .string or blob != .string or size != .integer or size.integer < 0) return error.BadListing;
        if (!isSafeRepoPath(path.string) or !isHex(blob.string, 40)) return error.UnsafeListing;
        var f = File{ .path = path.string, .size = @intCast(size.integer), .blob_id = blob.string };
        if (s.object.get("lfs")) |l| {
            if (l == .object) {
                if (l.object.get("sha256")) |h| {
                    if (h != .string or !isHex(h.string, 64)) return error.UnsafeListing;
                    f.sha256 = h.string;
                }
            }
        }
        try files.append(f);
    }
    return .{ .id = id.string, .commit = sha.string, .gated = gated, .files = try files.toOwnedSlice() };
}

// ---------------------------------------------------------------------------
// Which files
// ---------------------------------------------------------------------------

/// `*` matches any run of characters, `?` one. A pattern without `/` is
/// matched against the file name alone; one with `/` against the whole path.
pub fn matches(pattern: []const u8, path: []const u8) bool {
    const subject = if (std.mem.indexOfScalar(u8, pattern, '/') == null)
        path[if (std.mem.lastIndexOfScalar(u8, path, '/')) |i| i + 1 else 0..]
    else
        path;
    return glob(pattern, subject);
}

fn glob(p: []const u8, s: []const u8) bool {
    if (p.len == 0) return s.len == 0;
    if (p[0] == '*') {
        var k: usize = 0;
        while (k <= s.len) : (k += 1) {
            if (glob(p[1..], s[k..])) return true;
        }
        return false;
    }
    if (s.len == 0) return false;
    if (p[0] != '?' and std.ascii.toLower(p[0]) != std.ascii.toLower(s[0])) return false;
    return glob(p[1..], s[1..]);
}

/// The other copies of the weights a repository with `.safetensors` usually
/// also carries, left out unless asked for.
const duplicate_weights = [_][]const u8{
    "pytorch_model*.bin", "*.pt",          "*.pth",       "tf_model*.h5", "*.msgpack", "*.onnx",
    "*.onnx_data",        "*.ot",          "*.tflite",    "*.mlmodel",    "coreml/*",  "onnx/*",
    "openvino/*",         "*.mlpackage/*", "rust_model*",
};

pub const Selection = struct {
    files: []File,
    /// Weights in another format, left out because `.safetensors` exist.
    duplicates: []File,
};

/// The files to fetch. With `include` patterns, only those (minus `exclude`);
/// otherwise everything, minus duplicate weight formats unless `all`.
pub fn select(a: Allocator, files: []const File, include: []const []const u8, exclude: []const []const u8, all: bool) !Selection {
    var has_safetensors = false;
    for (files) |f| {
        if (std.mem.endsWith(u8, f.path, ".safetensors")) has_safetensors = true;
    }
    var keep = std.ArrayList(File).init(a);
    var dup = std.ArrayList(File).init(a);
    outer: for (files) |f| {
        for (exclude) |p| {
            if (matches(p, f.path)) continue :outer;
        }
        if (include.len != 0) {
            for (include) |p| {
                if (matches(p, f.path)) {
                    try keep.append(f);
                    continue :outer;
                }
            }
            continue;
        }
        if (has_safetensors and !all) {
            for (duplicate_weights) |p| {
                if (matches(p, f.path)) {
                    try dup.append(f);
                    continue :outer;
                }
            }
        }
        try keep.append(f);
    }
    return .{ .files = try keep.toOwnedSlice(), .duplicates = try dup.toOwnedSlice() };
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

/// The git blob id of a file: SHA-1 of `blob <size>\0` and its bytes.
pub fn gitBlobId(path: []const u8) ![40]u8 {
    const f = try std.fs.cwd().openFile(path, .{});
    defer f.close();
    const size = (try f.stat()).size;
    var h = Sha1.init(.{});
    var hdr: [32]u8 = undefined;
    h.update(try std.fmt.bufPrint(&hdr, "blob {d}\x00", .{size}));
    var buf: [64 * 1024]u8 = undefined;
    while (true) {
        const n = try f.read(&buf);
        if (n == 0) break;
        h.update(buf[0..n]);
    }
    return std.fmt.bytesToHex(h.finalResult(), .lower);
}

/// Files that hold Python pickles, which run code when loaded.
pub fn isPickleName(path: []const u8) bool {
    const exts = [_][]const u8{ ".bin", ".pt", ".pth", ".pkl", ".pickle", ".ckpt", ".joblib", ".dill", ".npy", ".npz" };
    for (exts) |e| {
        if (std.ascii.endsWithIgnoreCase(path, e)) return true;
    }
    return false;
}

/// Modules a model file has no reason to import; importing one is how a
/// pickle runs commands, opens connections or loads more code.
const bad_modules = [_][]const u8{
    "os",              "posix",    "nt",        "subprocess", "sys",      "socket", "shutil",  "runpy",       "webbrowser", "pty",
    "commands",        "ctypes",   "importlib", "pip",        "requests", "urllib", "httplib", "http.client", "asyncio",    "code",
    "multiprocessing", "platform", "pickle",    "marshal",    "types",
};
/// Names in `builtins` that run or load code.
const bad_builtins = [_][]const u8{ "eval", "exec", "compile", "open", "__import__", "getattr", "breakpoint", "apply", "execfile" };

fn badImport(module: []const u8, name: []const u8) bool {
    const root = module[0 .. std.mem.indexOfScalar(u8, module, '.') orelse module.len];
    for (bad_modules) |m| {
        if (std.mem.eql(u8, module, m) or std.mem.eql(u8, root, m)) return true;
    }
    if (std.mem.eql(u8, module, "builtins") or std.mem.eql(u8, module, "__builtin__") or std.mem.eql(u8, module, "__builtins__")) {
        for (bad_builtins) |b| {
            if (std.mem.eql(u8, name, b)) return true;
        }
    }
    return false;
}

pub const PickleFinding = struct { module: []const u8, name: []const u8 };

/// The first dangerous import in pickle bytes, or null. Both forms are read:
/// the text `GLOBAL` opcode (`c<module>\n<name>\n`) and the protocol 4+
/// `STACK_GLOBAL` (`\x93`) after two short strings. PyTorch `.bin`/`.pt`
/// files are zip archives that store their pickle uncompressed, so the bytes
/// of the whole file are searched.
pub fn findBadImport(bytes: []const u8) ?PickleFinding {
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        switch (bytes[i]) {
            'c' => {
                // GLOBAL: module and name, each ended by a newline.
                const m_end = std.mem.indexOfScalarPos(u8, bytes, i + 1, '\n') orelse continue;
                if (m_end - (i + 1) == 0 or m_end - (i + 1) > 64) continue;
                const n_end = std.mem.indexOfScalarPos(u8, bytes, m_end + 1, '\n') orelse continue;
                if (n_end - (m_end + 1) == 0 or n_end - (m_end + 1) > 64) continue;
                const module = bytes[i + 1 .. m_end];
                const name = bytes[m_end + 1 .. n_end];
                if (isIdent(module, true) and isIdent(name, false) and badImport(module, name)) return .{ .module = module, .name = name };
            },
            0x93 => {
                // STACK_GLOBAL: the two strings pushed before it, each a
                // SHORT_BINUNICODE (\x8c len) optionally followed by MEMOIZE (\x94).
                var j = i;
                if (j > 0 and bytes[j - 1] == 0x94) j -= 1;
                const name = shortStringBefore(bytes, j) orelse continue;
                var k = name.start;
                if (k > 0 and bytes[k - 1] == 0x94) k -= 1;
                const module = shortStringBefore(bytes, k) orelse continue;
                const m = bytes[module.start + 2 .. module.end];
                const n = bytes[name.start + 2 .. name.end];
                if (isIdent(m, true) and isIdent(n, false) and badImport(m, n)) return .{ .module = m, .name = n };
            },
            else => {},
        }
    }
    return null;
}

const Span = struct { start: usize, end: usize };

/// A SHORT_BINUNICODE (`\x8c`, one length byte, text) ending at `end`.
fn shortStringBefore(bytes: []const u8, end: usize) ?Span {
    var len: usize = 1;
    while (len <= 64 and len + 2 <= end) : (len += 1) {
        const start = end - len - 2;
        if (bytes[start] == 0x8c and bytes[start + 1] == len) return .{ .start = start, .end = end };
    }
    return null;
}

fn isIdent(s: []const u8, dotted: bool) bool {
    if (s.len == 0) return false;
    if (!std.ascii.isAlphabetic(s[0]) and s[0] != '_') return false;
    for (s) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '_' and !(dotted and c == '.')) return false;
    }
    return true;
}

/// `findBadImport` over a file, read in pieces with an overlap so an import
/// split across two reads is still seen.
pub fn scanPickleFile(a: Allocator, path: []const u8) !?PickleFinding {
    const f = try std.fs.cwd().openFile(path, .{});
    defer f.close();
    const overlap = 160;
    const buf = try a.alloc(u8, 4 * 1024 * 1024 + overlap);
    var have: usize = 0;
    while (true) {
        const n = try f.read(buf[have..]);
        if (n == 0) break;
        const end = have + n;
        if (findBadImport(buf[0..end])) |hit| return .{ .module = try a.dupe(u8, hit.module), .name = try a.dupe(u8, hit.name) };
        const keep = @min(overlap, end);
        std.mem.copyForwards(u8, buf[0..keep], buf[end - keep .. end]);
        have = keep;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Where, and who
// ---------------------------------------------------------------------------

/// The Hugging Face cache: `$HF_HUB_CACHE`, `$HF_HOME/hub`,
/// `$XDG_CACHE_HOME/huggingface/hub`, else `~/.cache/huggingface/hub`.
pub fn cacheRoot(a: Allocator) ![]u8 {
    if (platform.envOwned(a, "HF_HUB_CACHE")) |p| if (p.len != 0) return p;
    if (platform.envOwned(a, "HUGGINGFACE_HUB_CACHE")) |p| if (p.len != 0) return p;
    if (platform.envOwned(a, "HF_HOME")) |p| if (p.len != 0) return std.fs.path.join(a, &.{ p, "hub" });
    if (platform.envOwned(a, "XDG_CACHE_HOME")) |p| if (p.len != 0) return std.fs.path.join(a, &.{ p, "huggingface", "hub" });
    const home = try platform.homeDir(a);
    return std.fs.path.join(a, &.{ home, ".cache", "huggingface", "hub" });
}

fn validToken(t: []const u8) bool {
    if (t.len < 8 or t.len > 256) return false;
    for (t) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-' and c != '.') return false;
    }
    return true;
}

/// A Hugging Face access token for gated and private repositories:
/// `$HF_TOKEN`, `$HUGGING_FACE_HUB_TOKEN`, else the file `huggingface-cli
/// login` writes (`$HF_HOME/token`, else `~/.cache/huggingface/token`).
pub fn token(a: Allocator) ?[]const u8 {
    for ([_][]const u8{ "HF_TOKEN", "HUGGING_FACE_HUB_TOKEN" }) |k| {
        if (platform.envOwned(a, k)) |v| {
            const t = std.mem.trim(u8, v, " \t\r\n");
            if (validToken(t)) return t;
        }
    }
    const path = tokenPath(a) catch return null;
    const text = std.fs.cwd().readFileAlloc(a, path, 4096) catch return null;
    const t = std.mem.trim(u8, text, " \t\r\n");
    return if (validToken(t)) t else null;
}

/// Where the token is kept on this computer, the same file Hugging Face's
/// own tools read: `$HF_TOKEN_PATH`, `$HF_HOME/token`, else
/// `~/.cache/huggingface/token`.
pub fn tokenPath(a: Allocator) ![]u8 {
    if (platform.envOwned(a, "HF_TOKEN_PATH")) |p| if (p.len != 0) return p;
    if (platform.envOwned(a, "HF_HOME")) |h| if (h.len != 0) return std.fs.path.join(a, &.{ h, "token" });
    const home = try platform.homeDir(a);
    return std.fs.path.join(a, &.{ home, ".cache", "huggingface", "token" });
}

/// `HF_HUB_OFFLINE=1`: never contact Hugging Face, use only the cache.
pub fn offline(a: Allocator) bool {
    const v = platform.envOwned(a, "HF_HUB_OFFLINE") orelse return false;
    defer a.free(v);
    return isTrue(std.mem.trim(u8, v, " \t\r\n"));
}

fn isTrue(v: []const u8) bool {
    for ([_][]const u8{ "1", "true", "yes", "on", "TRUE", "True", "YES", "ON" }) |t| {
        if (std.mem.eql(u8, v, t)) return true;
    }
    return false;
}

fn authHeaders(a: Allocator) ![]const []const u8 {
    const t = token(a) orelse return &.{};
    const list = try a.alloc([]const u8, 1);
    list[0] = try std.fmt.allocPrint(a, "Authorization: Bearer {s}", .{t});
    return list;
}

// ---------------------------------------------------------------------------
// Install
// ---------------------------------------------------------------------------

pub const Options = struct {
    include: []const []const u8 = &.{},
    exclude: []const []const u8 = &.{},
    /// Also the duplicate weight formats.
    all: bool = false,
    /// Past the size guard.
    force: bool = false,
    allow_suspicious: bool = false,
    dry_run: bool = false,
    quiet: bool = false,
    jobs: usize = 4,
};

/// Downloads past this need `--include` or `--force`.
pub const size_guard: u64 = 25 * 1024 * 1024 * 1024;

pub fn fmtSize(buf: []u8, n: u64) []const u8 {
    const f: f64 = @floatFromInt(n);
    if (n >= 1 << 30) return std.fmt.bufPrint(buf, "{d:.1} GB", .{f / (1 << 30)}) catch "?";
    if (n >= 1 << 20) return std.fmt.bufPrint(buf, "{d:.1} MB", .{f / (1 << 20)}) catch "?";
    if (n >= 1 << 10) return std.fmt.bufPrint(buf, "{d:.1} KB", .{f / (1 << 10)}) catch "?";
    return std.fmt.bufPrint(buf, "{d} B", .{n}) catch "?";
}

const Job = struct {
    a: Allocator,
    spec: Spec,
    repo: *const Repo,
    file: File,
    blobs: []const u8,
    opts: *const Options,
    headers: []const []const u8,
    ok: bool = false,
    fetched: bool = false,
    message: []const u8 = "",
};

fn fetchOne(job: *Job) void {
    job.ok = fetchFile(job) catch |e| blk: {
        if (job.message.len == 0) job.message = std.fmt.allocPrint(job.a, "{s}", .{@errorName(e)}) catch "failed";
        break :blk false;
    };
}

fn fetchFile(job: *Job) !bool {
    const a = job.a;
    const f = job.file;
    const blob = try std.fs.path.join(a, &.{ job.blobs, f.etag() });
    // Already here from an earlier download (of this or another revision).
    if (std.fs.cwd().statFile(blob)) |st| {
        if (st.size == f.size) return true;
    } else |_| {}

    const tmp = try std.fmt.allocPrint(a, "{s}.{x}.incomplete", .{ blob, std.crypto.random.int(u32) });
    errdefer std.fs.cwd().deleteFile(tmp) catch {};
    const url = try fileUrl(a, job.spec, job.repo.commit, f.path);
    const got = try net.downloadHashed(a, url, tmp, .{ .headers = job.headers, .max_time_s = 6 * 3600 });
    if (got.bytes != f.size) {
        job.message = try std.fmt.allocPrint(a, "got {d} bytes, the Hub lists {d}", .{ got.bytes, f.size });
        return error.SizeMismatch;
    }
    if (f.sha256) |want| {
        const have = std.fmt.bytesToHex(got.digest, .lower);
        if (!std.mem.eql(u8, &have, want)) {
            job.message = try std.fmt.allocPrint(a, "SHA-256 {s} does not match the Hub's {s}", .{ &have, want });
            return error.ChecksumMismatch;
        }
    } else {
        const have = try gitBlobId(tmp);
        if (!std.mem.eql(u8, &have, f.blob_id)) {
            job.message = try std.fmt.allocPrint(a, "git blob id {s} does not match the Hub's {s}", .{ &have, f.blob_id });
            return error.ChecksumMismatch;
        }
    }
    if (isPickleName(f.path)) {
        if (try scanPickleFile(a, tmp)) |hit| {
            if (!job.opts.allow_suspicious) {
                job.message = try std.fmt.allocPrint(a, "pickle imports {s}.{s}, which can run code when the file is loaded (--allow-suspicious to keep it)", .{ hit.module, hit.name });
                return error.SuspiciousPickle;
            }
            term.err("{s}warning{s}: {s}: pickle imports {s}.{s}; kept (--allow-suspicious)\n", .{ term.yellow, term.reset, f.path, hit.module, hit.name });
        }
    }
    try std.fs.cwd().rename(tmp, blob);
    job.fetched = true;
    return true;
}

/// Put `path` in the snapshot: a relative link to its blob, or a copy where
/// links are not available (Windows without the right, as huggingface_hub does).
fn linkSnapshot(a: Allocator, snapshot: []const u8, blobs_rel_depth: usize, path: []const u8, etag: []const u8, blob_abs: []const u8) !void {
    const dest = try std.fs.path.join(a, &.{ snapshot, path });
    if (std.fs.path.dirname(dest)) |d| try std.fs.cwd().makePath(d);
    std.fs.cwd().deleteFile(dest) catch {};
    if (!platform.is_windows) {
        var target = std.ArrayList(u8).init(a);
        for (0..blobs_rel_depth) |_| try target.appendSlice("../");
        try target.appendSlice("blobs/");
        try target.appendSlice(etag);
        if (std.fs.cwd().symLink(target.items, dest, .{})) return else |_| {}
    }
    try std.fs.cwd().copyFile(blob_abs, std.fs.cwd(), dest, .{});
}

/// `abv0 install hf:...`. Returns the exit code.
pub fn install(base: Allocator, spec: Spec, opts: Options) !u8 {
    var arena = std.heap.ArenaAllocator.init(base);
    defer arena.deinit();
    const a = arena.allocator();
    var timer = try std.time.Timer.start();
    const shown = try display(a, spec);
    if (offline(a)) {
        if (!opts.quiet) term.print("offline (HF_HUB_OFFLINE): Hugging Face is not contacted\n", .{});
        return useCache(a, spec, opts);
    }
    const headers = try authHeaders(a);

    const body = net.fetchToString(a, try apiUrl(a, spec), 64 * 1024 * 1024, .{ .headers = headers }) catch |e| {
        // No network: what is already on this computer still works.
        if ((try cachedSnapshot(a, spec)) != null) {
            if (!opts.quiet) term.print("cannot reach Hugging Face ({s}); using the copy already on this computer\n", .{@errorName(e)});
            return useCache(a, spec, opts);
        }
        term.err("{s}error{s}: cannot read {s} from Hugging Face ({s}){s}\n", .{ term.red, term.reset, shown, @errorName(e), if (headers.len == 0) "; a private or misspelled repository looks the same as a missing one" else "" });
        return 1;
    };
    const repo = parseRepo(a, body) catch |e| {
        term.err("{s}error{s}: {s}: {s}\n", .{ term.red, term.reset, shown, switch (e) {
            error.NotFound => "not found on Hugging Face",
            error.UnsafeListing => "the listing names a file with an unsafe path or hash; refusing it",
            else => "unreadable listing",
        } });
        return 1;
    };
    if (repo.gated and headers.len == 0) {
        term.err("{s}error{s}: {s} is gated: accept its terms on huggingface.co, then run `abv0 hf login` (or set HF_TOKEN)\n", .{ term.red, term.reset, shown });
        return 1;
    }

    const sel = try select(a, repo.files, opts.include, opts.exclude, opts.all);
    if (sel.files.len == 0) {
        term.err("{s}error{s}: no file of {s} matches", .{ term.red, term.reset, shown });
        for (opts.include) |p| term.err(" {s}", .{p});
        term.err("\n", .{});
        return 1;
    }
    var total: u64 = 0;
    for (sel.files) |f| total += f.size;
    var dup_total: u64 = 0;
    for (sel.duplicates) |f| dup_total += f.size;
    var sbuf: [32]u8 = undefined;
    var dbuf: [32]u8 = undefined;

    if (!opts.quiet) {
        term.print("{s} @ {s} ({s}): {d} files, {s}", .{ shown, repo.commit[0..12], spec.revision, sel.files.len, fmtSize(&sbuf, total) });
        if (sel.duplicates.len != 0) term.print("; {d} copies in other weight formats left out ({s}, --all-files to take them)", .{ sel.duplicates.len, fmtSize(&dbuf, dup_total) });
        term.print("\n", .{});
    }
    if (total > size_guard and opts.include.len == 0 and !opts.force) {
        term.err("{s}error{s}: that is {s}. Pick files with --include (for example --include \"*Q4_K_M*\" or --include \"*.safetensors\"), or pass --force\n", .{ term.red, term.reset, fmtSize(&sbuf, total) });
        return 1;
    }
    if (opts.dry_run) {
        for (sel.files) |f| term.print("  {s}  {s}\n", .{ f.path, fmtSize(&sbuf, f.size) });
        term.print("dry run: nothing was downloaded\n", .{});
        return 0;
    }

    const root = try cacheRoot(a);
    const folder = try std.fs.path.join(a, &.{ root, try cacheFolderName(a, spec) });
    const blobs = try std.fs.path.join(a, &.{ folder, "blobs" });
    const snapshot = try std.fs.path.join(a, &.{ folder, "snapshots", repo.commit });
    try std.fs.cwd().makePath(blobs);
    try std.fs.cwd().makePath(snapshot);

    const jobs = try a.alloc(Job, sel.files.len);
    for (sel.files, 0..) |f, i| jobs[i] = .{ .a = a, .spec = spec, .repo = &repo, .file = f, .blobs = blobs, .opts = &opts, .headers = headers };
    // Several files at once; a big file is itself split over connections.
    if (opts.jobs <= 1 or jobs.len == 1) {
        for (jobs) |*j| fetchOne(j);
    } else {
        var pool: std.Thread.Pool = undefined;
        try pool.init(.{ .allocator = base, .n_jobs = @intCast(@min(opts.jobs, jobs.len)) });
        defer pool.deinit();
        var wg: std.Thread.WaitGroup = .{};
        for (jobs) |*j| pool.spawnWg(&wg, fetchOne, .{j});
        wg.wait();
    }

    var failed: usize = 0;
    var fetched: usize = 0;
    var bytes: u64 = 0;
    for (jobs) |j| {
        if (!j.ok) {
            failed += 1;
            term.err("{s}error{s}: {s}: {s}\n", .{ term.red, term.reset, j.file.path, j.message });
            continue;
        }
        if (j.fetched) {
            fetched += 1;
            bytes += j.file.size;
        }
        const depth = std.mem.count(u8, j.file.path, "/") + 2;
        const blob_abs = try std.fs.path.join(a, &.{ blobs, j.file.etag() });
        try linkSnapshot(a, snapshot, depth, j.file.path, j.file.etag(), blob_abs);
    }
    if (failed != 0) {
        term.err("{s}{d} of {d} files failed{s}; the cache keeps the verified ones, and running the same command again fetches only the rest\n", .{ term.red, failed, jobs.len, term.reset });
        return 1;
    }
    // A branch or tag name points at the commit, as huggingface_hub records it.
    if (!isHex(spec.revision, 40)) {
        const ref = try std.fs.path.join(a, &.{ folder, "refs", spec.revision });
        if (std.fs.path.dirname(ref)) |d| try std.fs.cwd().makePath(d);
        try std.fs.cwd().writeFile(.{ .sub_path = ref, .data = repo.commit });
    }
    const secs = @as(f64, @floatFromInt(timer.read())) / 1e9;
    if (!opts.quiet) {
        term.print("{s}done{s} {s}: {d} files verified ({d} downloaded, {s}) in {d:.1}s\n", .{ term.green, term.reset, shown, jobs.len, fetched, fmtSize(&sbuf, bytes), secs });
        term.print("  {s}\n", .{snapshot});
    }
    return 0;
}

/// `abv0 uninstall hf:...`: the repository's whole cache folder.
pub fn remove(base: Allocator, spec: Spec, dry_run: bool) !u8 {
    var arena = std.heap.ArenaAllocator.init(base);
    defer arena.deinit();
    const a = arena.allocator();
    const folder = try std.fs.path.join(a, &.{ try cacheRoot(a), try cacheFolderName(a, spec) });
    const shown = try display(a, spec);
    std.fs.cwd().access(folder, .{}) catch {
        term.err("{s} is not in the Hugging Face cache\n", .{shown});
        return 1;
    };
    if (dry_run) {
        term.print("  remove   {s} ({s})\n", .{ shown, folder });
        return 0;
    }
    try std.fs.cwd().deleteTree(folder);
    term.print("removed {s}\n", .{shown});
    return 0;
}

fn treeSize(a: Allocator, path: []const u8) u64 {
    var dir = std.fs.cwd().openDir(path, .{ .iterate = true }) catch return 0;
    defer dir.close();
    var w = dir.walk(a) catch return 0;
    defer w.deinit();
    var total: u64 = 0;
    while (w.next() catch null) |e| {
        if (e.kind != .file) continue;
        const st = e.dir.statFile(e.basename) catch continue;
        total += st.size;
    }
    return total;
}

/// The cache folder name back to the `hf:` name, or null.
pub fn specFromFolder(a: Allocator, folder: []const u8) !?[]u8 {
    var kind: Kind = undefined;
    var rest: []const u8 = undefined;
    if (std.mem.startsWith(u8, folder, "models--")) {
        kind = .model;
        rest = folder["models--".len..];
    } else if (std.mem.startsWith(u8, folder, "datasets--")) {
        kind = .dataset;
        rest = folder["datasets--".len..];
    } else return null;
    const id = try std.mem.replaceOwned(u8, a, rest, "--", "/");
    return if (kind == .dataset) try std.fmt.allocPrint(a, "hf:datasets/{s}", .{id}) else try std.fmt.allocPrint(a, "hf:{s}", .{id});
}

/// `abv0 hf list`: what is in the cache, abv0's or not.
pub fn listCache(base: Allocator) !u8 {
    var arena = std.heap.ArenaAllocator.init(base);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try cacheRoot(a);
    var dir = std.fs.cwd().openDir(root, .{ .iterate = true }) catch {
        term.print("the Hugging Face cache ({s}) is empty\n", .{root});
        return 0;
    };
    defer dir.close();
    var names = std.ArrayList([]const u8).init(a);
    var it = dir.iterate();
    while (try it.next()) |e| {
        if (e.kind != .directory) continue;
        if ((try specFromFolder(a, e.name)) != null) try names.append(try a.dupe(u8, e.name));
    }
    std.mem.sort([]const u8, names.items, {}, struct {
        fn lt(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.order(u8, x, y) == .lt;
        }
    }.lt);
    var total: u64 = 0;
    var buf: [32]u8 = undefined;
    for (names.items) |n| {
        const size = treeSize(a, try std.fs.path.join(a, &.{ root, n, "blobs" }));
        total += size;
        term.print("{s:<60} {s:>10}\n", .{ (try specFromFolder(a, n)).?, fmtSize(&buf, size) });
    }
    term.print("{d} repositories, {s} in {s}\n", .{ names.items.len, fmtSize(&buf, total), root });
    return 0;
}

/// `abv0 hf path hf:...`: the snapshot folder of the revision last installed.
pub fn snapshotPath(base: Allocator, spec: Spec) !u8 {
    var arena = std.heap.ArenaAllocator.init(base);
    defer arena.deinit();
    const a = arena.allocator();
    const snapshot = try cachedSnapshot(a, spec) orelse {
        term.err("{s} is not in the Hugging Face cache (install it first)\n", .{try display(a, spec)});
        return 1;
    };
    term.print("{s}\n", .{snapshot});
    return 0;
}

/// The cached snapshot folder for `spec`'s revision, or null. Reads only
/// the disk.
pub fn cachedSnapshot(a: Allocator, spec: Spec) !?[]u8 {
    const folder = try std.fs.path.join(a, &.{ try cacheRoot(a), try cacheFolderName(a, spec) });
    const commit = if (isHex(spec.revision, 40)) spec.revision else blk: {
        const ref = try std.fs.path.join(a, &.{ folder, "refs", spec.revision });
        const text = std.fs.cwd().readFileAlloc(a, ref, 256) catch return null;
        break :blk std.mem.trim(u8, text, " \r\n");
    };
    if (!isHex(commit, 40)) return null;
    const snapshot = try std.fs.path.join(a, &.{ folder, "snapshots", commit });
    std.fs.cwd().access(snapshot, .{}) catch return null;
    return snapshot;
}

/// Install with no network: the cached snapshot, if it holds the files
/// asked for (`--include`), else an error.
fn useCache(a: Allocator, spec: Spec, opts: Options) !u8 {
    const shown = try display(a, spec);
    const snapshot = try cachedSnapshot(a, spec) orelse {
        term.err("{s}error{s}: {s} is not on this computer yet; download it once with network on\n", .{ term.red, term.reset, shown });
        return 1;
    };
    var dir = try std.fs.cwd().openDir(snapshot, .{ .iterate = true });
    defer dir.close();
    var w = try dir.walk(a);
    defer w.deinit();
    var count: usize = 0;
    var missing: usize = 0;
    while (try w.next()) |e| {
        if (e.kind == .directory) continue;
        const rel = try std.mem.replaceOwned(u8, a, e.path, "\\", "/");
        if (opts.include.len != 0) {
            var hit = false;
            for (opts.include) |p| hit = hit or matches(p, rel);
            if (!hit) continue;
        }
        var skip = false;
        for (opts.exclude) |p| skip = skip or matches(p, rel);
        if (skip) continue;
        // A link whose blob is gone is a broken download.
        e.dir.access(e.basename, .{}) catch {
            missing += 1;
            continue;
        };
        count += 1;
    }
    if (count == 0 or missing != 0) {
        term.err("{s}error{s}: {s}: the copy on this computer is {s}; download it with network on\n", .{ term.red, term.reset, shown, if (count == 0) "missing those files" else "incomplete" });
        return 1;
    }
    if (opts.dry_run) {
        term.print("dry run: {d} files already on this computer\n", .{count});
        return 0;
    }
    if (!opts.quiet) {
        term.print("{s}done{s} {s}: {d} files on this computer (0 downloaded)\n", .{ term.green, term.reset, shown, count });
        term.print("  {s}\n", .{snapshot});
    }
    return 0;
}

/// `abv0 hf search <words>` / `abv0 hf search-datasets <words>`: the most
/// downloaded matches on the Hub.
pub fn search(base: Allocator, kind: Kind, words: []const []const u8) !u8 {
    var arena = std.heap.ArenaAllocator.init(base);
    defer arena.deinit();
    const a = arena.allocator();
    if (offline(a)) {
        term.err("{s}error{s}: search needs Hugging Face, and HF_HUB_OFFLINE is set\n", .{ term.red, term.reset });
        return 1;
    }
    var q = std.ArrayList(u8).init(a);
    for (words, 0..) |w, i| {
        if (i != 0) try q.appendSlice("%20");
        for (w) |c| {
            if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.') try q.append(c) else try q.writer().print("%{X:0>2}", .{c});
        }
    }
    const url = try std.fmt.allocPrint(a, hub ++ "/api/{s}?search={s}&sort=downloads&direction=-1&limit=20", .{ kind.plural(), q.items });
    const body = net.fetchToString(a, url, 8 * 1024 * 1024, .{ .headers = try authHeaders(a) }) catch |e| {
        term.err("{s}error{s}: Hugging Face search failed ({s})\n", .{ term.red, term.reset, @errorName(e) });
        return 1;
    };
    const v = std.json.parseFromSliceLeaky(std.json.Value, a, body, .{}) catch return 1;
    if (v != .array) return 1;
    for (v.array.items) |item| {
        if (item != .object) continue;
        const id = item.object.get("id") orelse continue;
        if (id != .string) continue;
        const spec_text = if (kind == .dataset) try std.fmt.allocPrint(a, "hf:datasets/{s}", .{id.string}) else try std.fmt.allocPrint(a, "hf:{s}", .{id.string});
        if (parseSpec(spec_text) == null) continue;
        const dl: u64 = if (item.object.get("downloads")) |d| (if (d == .integer and d.integer > 0) @intCast(d.integer) else 0) else 0;
        const tag = if (item.object.get("pipeline_tag")) |t| (if (t == .string) t.string else "") else "";
        term.print("{s:<60} {d:>12} downloads  {s}\n", .{ spec_text, dl, tag });
    }
    if (v.array.items.len == 0) term.print("no match\n", .{});
    return 0;
}

// ---------------------------------------------------------------------------
// Your token: login, whoami, logout
// ---------------------------------------------------------------------------

/// The token is sent only to huggingface.co: the HTTP client drops it on a
/// redirect to any other host (the file CDN), and it is never written
/// anywhere but the token file.
const Account = struct { name: []const u8, role: []const u8 };

fn whoamiRequest(a: Allocator, t: []const u8) !Account {
    const header = try std.fmt.allocPrint(a, "Authorization: Bearer {s}", .{t});
    const body = try net.fetchToString(a, hub ++ "/api/whoami-v2", 1024 * 1024, .{ .headers = &.{header} });
    return parseWhoami(a, body);
}

fn parseWhoami(a: Allocator, body: []const u8) !Account {
    const v = std.json.parseFromSliceLeaky(std.json.Value, a, body, .{}) catch return error.BadAnswer;
    if (v != .object) return error.BadAnswer;
    const name = v.object.get("name") orelse return error.BadAnswer;
    if (name != .string) return error.BadAnswer;
    var role: []const u8 = "";
    if (v.object.get("auth")) |auth| if (auth == .object) if (auth.object.get("accessToken")) |at| if (at == .object) if (at.object.get("role")) |r| if (r == .string) {
        role = r.string;
    };
    return .{ .name = name.string, .role = role };
}

/// One line from the terminal with typing hidden, or from a pipe as is.
fn readSecret(a: Allocator, prompt: []const u8) ![]u8 {
    const in = std.io.getStdIn();
    const tty = in.isTty();
    if (tty) term.err("{s}", .{prompt});
    var restore: ?if (builtin.os.tag == .windows) u32 else std.posix.termios = null;
    if (tty) {
        if (builtin.os.tag == .windows) {
            const k32 = std.os.windows.kernel32;
            var mode: u32 = 0;
            if (k32.GetConsoleMode(in.handle, &mode) != 0) {
                restore = mode;
                _ = k32.SetConsoleMode(in.handle, mode & ~@as(u32, 0x4)); // ENABLE_ECHO_INPUT
            }
        } else if (std.posix.tcgetattr(in.handle)) |orig| {
            var quiet = orig;
            quiet.lflag.ECHO = false;
            std.posix.tcsetattr(in.handle, .FLUSH, quiet) catch {};
            restore = orig;
        } else |_| {}
    }
    defer if (restore) |r| {
        if (builtin.os.tag == .windows) {
            _ = std.os.windows.kernel32.SetConsoleMode(in.handle, r);
        } else std.posix.tcsetattr(in.handle, .FLUSH, r) catch {};
        term.err("\n", .{});
    };
    const line = try in.reader().readUntilDelimiterOrEofAlloc(a, '\n', 4096) orelse return error.EndOfStream;
    return line;
}

/// Save the token where Hugging Face's own tools look, readable only by you.
fn saveToken(a: Allocator, t: []const u8) ![]u8 {
    const path = try tokenPath(a);
    if (std.fs.path.dirname(path)) |d| try std.fs.cwd().makePath(d);
    const f = try std.fs.cwd().createFile(path, .{ .truncate = true, .mode = if (builtin.os.tag == .windows) 0 else 0o600 });
    defer f.close();
    // An older file keeps its mode on create; tighten it.
    if (builtin.os.tag != .windows) try f.chmod(0o600);
    try f.writeAll(t);
    return path;
}

/// `abv0 hf login [--token <token>]`: check the token with Hugging Face and
/// keep it on this computer. With no `--token`, it is typed (hidden) or piped
/// in, so it stays out of shell history.
pub fn login(base: Allocator, given: ?[]const u8) !u8 {
    var arena = std.heap.ArenaAllocator.init(base);
    defer arena.deinit();
    const a = arena.allocator();
    const raw = given orelse (readSecret(a, "Hugging Face token (from https://huggingface.co/settings/tokens): ") catch {
        term.err("{s}error{s}: no token given\n", .{ term.red, term.reset });
        return 2;
    });
    const t = std.mem.trim(u8, raw, " \t\r\n");
    if (!validToken(t)) {
        term.err("{s}error{s}: that does not look like a Hugging Face token (they start with hf_)\n", .{ term.red, term.reset });
        return 2;
    }
    if (offline(a)) {
        term.err("{s}error{s}: HF_HUB_OFFLINE is set; the token cannot be checked, so it was not saved\n", .{ term.red, term.reset });
        return 1;
    }
    const acct = whoamiRequest(a, t) catch |e| {
        const rejected = e == error.HttpStatus and (http.last_http_status == 401 or http.last_http_status == 403);
        term.err("{s}error{s}: {s}; nothing was saved\n", .{ term.red, term.reset, if (rejected) "Hugging Face did not accept that token" else "Hugging Face did not accept that token, or cannot be reached" });
        return 1;
    };
    const path = try saveToken(a, t);
    term.print("{s}logged in{s} as {s}{s}{s}{s}\n", .{ term.green, term.reset, acct.name, if (acct.role.len != 0) " (" else "", acct.role, if (acct.role.len != 0) " token)" else "" });
    term.print("  token saved on this computer only: {s}\n", .{path});
    if (platform.envOwned(a, "HF_TOKEN") != null) term.print("  note: HF_TOKEN is set and is used instead of the saved token\n", .{});
    return 0;
}

/// `abv0 hf whoami`: which account the token belongs to, and where it lives.
pub fn whoami(base: Allocator) !u8 {
    var arena = std.heap.ArenaAllocator.init(base);
    defer arena.deinit();
    const a = arena.allocator();
    const t = token(a) orelse {
        term.print("not logged in (run `abv0 hf login`)\n", .{});
        return 1;
    };
    const from = if (platform.envOwned(a, "HF_TOKEN") != null) "HF_TOKEN" else if (platform.envOwned(a, "HUGGING_FACE_HUB_TOKEN") != null) "HUGGING_FACE_HUB_TOKEN" else try tokenPath(a);
    if (offline(a)) {
        term.print("a token is set ({s}); offline, so the account is not checked\n", .{from});
        return 0;
    }
    const acct = whoamiRequest(a, t) catch {
        term.err("{s}error{s}: the token from {s} was not accepted (or Hugging Face cannot be reached)\n", .{ term.red, term.reset, from });
        return 1;
    };
    term.print("{s}{s}{s}{s}  (token from {s})\n", .{ acct.name, if (acct.role.len != 0) ", " else "", acct.role, if (acct.role.len != 0) " token" else "", from });
    return 0;
}

/// `abv0 hf logout`: delete the saved token from this computer.
pub fn logout(base: Allocator) !u8 {
    var arena = std.heap.ArenaAllocator.init(base);
    defer arena.deinit();
    const a = arena.allocator();
    const path = try tokenPath(a);
    std.fs.cwd().deleteFile(path) catch |e| switch (e) {
        error.FileNotFound => {
            term.print("no saved token ({s})\n", .{path});
            return 0;
        },
        else => return e,
    };
    term.print("logged out: {s} is gone\n", .{path});
    if (platform.envOwned(a, "HF_TOKEN") != null or platform.envOwned(a, "HUGGING_FACE_HUB_TOKEN") != null)
        term.print("  note: a token is still set in your environment (HF_TOKEN)\n", .{});
    return 0;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parseSpec reads models, datasets, revisions and owner-less names" {
    const m = parseSpec("hf:HuggingFaceTB/SmolLM2-135M").?;
    try testing.expect(m.kind == .model);
    try testing.expectEqualStrings("HuggingFaceTB", m.owner);
    try testing.expectEqualStrings("main", m.revision);
    const d = parseSpec("hf:datasets/fka/prompts.chat@refs/pr/1").?;
    try testing.expect(d.kind == .dataset);
    try testing.expectEqualStrings("refs/pr/1", d.revision);
    try testing.expectEqualStrings("gpt2", parseSpec("hf:gpt2").?.name);
    try testing.expect(parseSpec("hf:models/a/b").?.kind == .model);
    for ([_][]const u8{ "hf:", "hf:a/../b", "hf:datasets/onlyname", "hf:a/b c", "hf:a/b@..", "gh:a/b", "hf:a/b/c", "hf:-a/b", "hf:a/b@-x" }) |bad| {
        try testing.expect(parseSpec(bad) == null);
    }
}

test "URLs and cache folder names" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const m = parseSpec("hf:o/n").?;
    try testing.expectEqualStrings("https://huggingface.co/api/models/o/n/revision/main?blobs=true", try apiUrl(a, m));
    try testing.expectEqualStrings("https://huggingface.co/o/n/resolve/abc/sub%20dir/f%2B1.bin", try fileUrl(a, m, "abc", "sub dir/f+1.bin"));
    try testing.expectEqualStrings("models--o--n", try cacheFolderName(a, m));
    const d = parseSpec("hf:datasets/o/n").?;
    try testing.expectEqualStrings("https://huggingface.co/datasets/o/n/resolve/c/x.csv", try fileUrl(a, d, "c", "x.csv"));
    try testing.expectEqualStrings("datasets--o--n", try cacheFolderName(a, d));
    try testing.expectEqualStrings("hf:datasets/o/n", (try specFromFolder(a, "datasets--o--n")).?);
    try testing.expectEqualStrings("hf:gpt2", (try specFromFolder(a, "models--gpt2")).?);
    try testing.expect((try specFromFolder(a, ".locks")) == null);
}

test "parseRepo keeps hashes and refuses unsafe paths" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const ok =
        \\{"id":"o/n","sha":"12fd25f77366fa6b3b4b768ec3050bf629380bac","gated":false,"siblings":[
        \\{"rfilename":"config.json","blobId":"36293b6099200eb8aeb55ae2c01bca2ba46d80d0","size":861},
        \\{"rfilename":"model.safetensors","blobId":"2ef707371406f95f8aa91fb03a75f22f3c568299","size":269060552,"lfs":{"sha256":"5af571cbf074e6d21a03528d2330792e532ca608f24ac70a143f6b369968ab8c","size":269060552,"pointerSize":134}}]}
    ;
    const r = try parseRepo(a, ok);
    try testing.expectEqual(@as(usize, 2), r.files.len);
    try testing.expectEqualStrings("36293b6099200eb8aeb55ae2c01bca2ba46d80d0", r.files[0].etag());
    try testing.expectEqualStrings("5af571cbf074e6d21a03528d2330792e532ca608f24ac70a143f6b369968ab8c", r.files[1].etag());
    try testing.expect(!r.gated);
    try testing.expect((try parseRepo(a, "{\"id\":\"o/n\",\"sha\":\"12fd25f77366fa6b3b4b768ec3050bf629380bac\",\"gated\":\"manual\",\"siblings\":[]}")).gated);
    for ([_][]const u8{ "../x", "/etc/passwd", "a/../../x", "C:/x", "a\\b", "a//b" }) |p| {
        const body = try std.fmt.allocPrint(a, "{{\"id\":\"o/n\",\"sha\":\"12fd25f77366fa6b3b4b768ec3050bf629380bac\",\"siblings\":[{{\"rfilename\":\"{s}\",\"blobId\":\"36293b6099200eb8aeb55ae2c01bca2ba46d80d0\",\"size\":1}}]}}", .{p});
        try testing.expectError(error.UnsafeListing, parseRepo(a, body));
    }
    try testing.expectError(error.NotFound, parseRepo(a, "{\"error\":\"Repository not found\"}"));
}

test "select: patterns, and duplicate weights left out next to safetensors" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const h = "36293b6099200eb8aeb55ae2c01bca2ba46d80d0";
    const files = [_]File{
        .{ .path = "config.json", .size = 1, .blob_id = h },
        .{ .path = "model.safetensors", .size = 10, .blob_id = h },
        .{ .path = "pytorch_model.bin", .size = 10, .blob_id = h },
        .{ .path = "onnx/model.onnx", .size = 10, .blob_id = h },
        .{ .path = "gguf/model-Q4_K_M.gguf", .size = 5, .blob_id = h },
    };
    const def = try select(a, &files, &.{}, &.{}, false);
    try testing.expectEqual(@as(usize, 3), def.files.len);
    try testing.expectEqual(@as(usize, 2), def.duplicates.len);
    try testing.expectEqual(@as(usize, 5), (try select(a, &files, &.{}, &.{}, true)).files.len);
    const q = try select(a, &files, &.{"*Q4_K_M*"}, &.{}, false);
    try testing.expectEqual(@as(usize, 1), q.files.len);
    try testing.expectEqual(@as(usize, 2), (try select(a, &files, &.{}, &.{"*.json"}, false)).files.len);
    try testing.expect(matches("onnx/*", "onnx/model.onnx"));
    try testing.expect(!matches("onnx/*", "model.onnx"));
    try testing.expect(matches("*.SafeTensors", "x/model.safetensors"));
}

test "gitBlobId matches git's" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "f", .data = "hello\n" });
    const p = try tmp.dir.realpathAlloc(testing.allocator, "f");
    defer testing.allocator.free(p);
    // `printf 'hello\n' | git hash-object --stdin`
    try testing.expectEqualStrings("ce013625030ba8dba906f756967f9e9ca394464a", &(try gitBlobId(p)));
}

test "findBadImport catches os.system in both pickle forms and leaves weights alone" {
    // Protocol 0-2: GLOBAL opcode.
    try testing.expectEqualStrings("os", findBadImport("\x80\x02cos\nsystem\nq\x00X\x02\x00\x00\x00idq\x01\x85R.").?.module);
    try testing.expectEqualStrings("eval", findBadImport("cbuiltins\neval\n(Vprint(1)\ntR.").?.name);
    // Protocol 4: STACK_GLOBAL after two SHORT_BINUNICODE, with MEMOIZE.
    const p4 = "\x80\x04\x95\x20\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x02id\x94\x85\x94R\x94.";
    try testing.expectEqualStrings("posix", findBadImport(p4).?.module);
    try testing.expectEqualStrings("subprocess", findBadImport("\x8c\x0asubprocess\x8c\x05Popen\x93").?.module);
    // What PyTorch writes: torch and collections imports are fine.
    try testing.expect(findBadImport("\x80\x02ctorch._utils\n_rebuild_tensor_v2\nq\x00ccollections\nOrderedDict\nq\x01") == null);
    try testing.expect(findBadImport("\x8c\x0ctorch._utils\x94\x8c\x12_rebuild_tensor_v2\x94\x93") == null);
    try testing.expect(findBadImport("cosmetic\nsystem\n") == null);
    try testing.expect(isPickleName("pytorch_model.bin"));
    try testing.expect(!isPickleName("model.safetensors"));
}

test "a pickle split across reads is still found" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var data = std.ArrayList(u8).init(testing.allocator);
    defer data.deinit();
    try data.appendNTimes('x', 4 * 1024 * 1024 - 5);
    try data.appendSlice("cos\nsystem\n");
    try tmp.dir.writeFile(.{ .sub_path = "p.bin", .data = data.items });
    const p = try tmp.dir.realpathAlloc(testing.allocator, "p.bin");
    defer testing.allocator.free(p);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings("system", (try scanPickleFile(arena.allocator(), p)).?.name);
}

test "parseWhoami reads the account name and token role" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const acct = try parseWhoami(arena.allocator(),
        \\{"type":"user","name":"someone","auth":{"type":"access_token","accessToken":{"displayName":"x","role":"read"}}}
    );
    try testing.expectEqualStrings("someone", acct.name);
    try testing.expectEqualStrings("read", acct.role);
    try testing.expectError(error.BadAnswer, parseWhoami(arena.allocator(), "{\"error\":\"Invalid credentials\"}"));
    try testing.expectError(error.BadAnswer, parseWhoami(arena.allocator(), "not json"));
}

test "HF_HUB_OFFLINE values" {
    try testing.expect(isTrue("1"));
    try testing.expect(isTrue("true"));
    try testing.expect(!isTrue("0"));
    try testing.expect(!isTrue(""));
}

test "validToken refuses anything that could break a header" {
    try testing.expect(validToken("hf_abcdefghijklmnopqrstuvwxyz0123"));
    try testing.expect(!validToken("hf_abc\r\nX-Evil: 1"));
    try testing.expect(!validToken("hf_ab cd ef gh"));
    try testing.expect(!validToken("short"));
}
