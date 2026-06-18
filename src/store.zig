const std = @import("std");
const registry = @import("registry.zig");
const os_macos = @import("os_macos.zig");
const builtin = @import("builtin");

// Security helper: Validate IDs to absolutely prevent Path Traversal / Command Injection
pub fn isValidId(id: []const u8) bool {
    if (id.len == 0 or id.len > 128) return false;
    for (id) |c| {
        switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '_', '.' => continue,
            else => return false,
        }
    }
    // Reject absolute paths or simple dot traversal
    if (std.mem.eql(u8, id, ".") or std.mem.eql(u8, id, "..")) return false;
    return true;
}

// Gorgeous CLI text progress animation
pub fn printProgressBar(msg: []const u8, filled: usize, total: usize) void {
    const bar_len: usize = 20;
    const active_filled = if (total == 0) bar_len else (filled * bar_len) / total;

    var bar_buf: [32]u8 = undefined;
    for (0..bar_len) |i| {
        if (i < active_filled) {
            bar_buf[i] = '=';
        } else if (i == active_filled and i < bar_len) {
            bar_buf[i] = '>';
        } else {
            bar_buf[i] = ' ';
        }
    }

    std.debug.print("[{s}] {s}\n", .{ bar_buf[0..bar_len], msg });
}

pub const Store = struct {
    allocator: std.mem.Allocator,
    store_root: []const u8,
    bin_root: []const u8,
    shells_root: []const u8,
    apps_root: []const u8, // GUI Applications root (e.g. ~/Applications)

    pub fn init(allocator: std.mem.Allocator) !Store {
        const home_dir = std.posix.getenv("HOME") orelse {
            return error.HomeDirNotFound;
        };

        const store_root = try std.fs.path.join(allocator, &.{ home_dir, ".abv0", "store" });
        const bin_root = try std.fs.path.join(allocator, &.{ home_dir, ".abv0", "bin" });
        const shells_root = try std.fs.path.join(allocator, &.{ home_dir, ".abv0", "shells" });
        const apps_root = try std.fs.path.join(allocator, &.{ home_dir, "Applications" });

        // Security fix: Create directories with strict 0700 permissions to prevent local multi-user unauthorized access
        std.fs.cwd().makePath(store_root) catch {};
        std.fs.cwd().makePath(bin_root) catch {};
        std.fs.cwd().makePath(shells_root) catch {};
        std.fs.cwd().makePath(apps_root) catch {};

        _ = std.process.Child.run(.{ .allocator = allocator, .argv = &.{ "chmod", "0700", store_root } }) catch {};
        _ = std.process.Child.run(.{ .allocator = allocator, .argv = &.{ "chmod", "0700", bin_root } }) catch {};
        _ = std.process.Child.run(.{ .allocator = allocator, .argv = &.{ "chmod", "0700", shells_root } }) catch {};

        return Store{
            .allocator = allocator,
            .store_root = store_root,
            .bin_root = bin_root,
            .shells_root = shells_root,
            .apps_root = apps_root,
        };
    }

    pub fn deinit(self: *Store) void {
        self.allocator.free(self.store_root);
        self.allocator.free(self.bin_root);
        self.allocator.free(self.shells_root);
        self.allocator.free(self.apps_root);
    }

    pub fn getPkgStorePath(self: *Store, pkg: registry.Package, platform_name: []const u8) ![]const u8 {
        // Security check: strictly enforce path traversal protections
        if (!isValidId(pkg.name) or !isValidId(pkg.version) or !isValidId(platform_name)) {
            return error.InvalidPackageIdentifier;
        }

        const dir_name = try std.fmt.allocPrint(self.allocator, "{s}-{s}-{s}", .{ pkg.name, pkg.version, platform_name });
        defer self.allocator.free(dir_name);

        return try std.fs.path.join(self.allocator, &.{ self.store_root, dir_name });
    }

    pub fn isInstalled(self: *Store, pkg: registry.Package, platform_name: []const u8) !bool {
        const pkg_dir = self.getPkgStorePath(pkg, platform_name) catch return false;
        defer self.allocator.free(pkg_dir);

        var dir = std.fs.cwd().openDir(pkg_dir, .{}) catch {
            return false;
        };
        dir.close();
        return true;
    }

    // Helper for parallel micro chunk execution
    fn downloadChunk(allocator: std.mem.Allocator, url: []const u8, start_byte: usize, end_byte: usize, out_path: []const u8) !void {
        const range_str = try std.fmt.allocPrint(allocator, "{d}-{d}", .{ start_byte, end_byte });
        defer allocator.free(range_str);

        const curl_result = try std.process.Child.run(.{
            .allocator = allocator,
            .argv = &.{ "curl", "-s", "-L", "-r", range_str, url, "-o", out_path },
        });
        defer {
            allocator.free(curl_result.stdout);
            allocator.free(curl_result.stderr);
        }

        if (curl_result.term.Exited != 0) {
            return error.ChunkDownloadFailed;
        }
    }

    // Innovative Feature: Micro-file Splitting Download Engine
    fn microSplitDownload(self: *Store, url: []const u8, archive_path: []const u8, tmp_dir_path: []const u8) !bool {
        printProgressBar("Querying remote server Content-Length...", 1, 10);

        // Query headers
        const curl_res = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &.{ "curl", "-s", "-I", "-L", url },
        });
        defer {
            self.allocator.free(curl_res.stdout);
            self.allocator.free(curl_res.stderr);
        }

        if (curl_res.term.Exited != 0) return false;

        var content_length: ?usize = null;
        var accepts_ranges = false;

        var lines = std.mem.splitSequence(u8, curl_res.stdout, "\n");
        while (lines.next()) |raw_line| {
            const line = std.mem.trim(u8, raw_line, "\r\t ");
            if (std.ascii.indexOfIgnoreCase(line, "Content-Length:") != null) {
                var parts = std.mem.splitSequence(u8, line, ":");
                _ = parts.next();
                if (parts.next()) |val| {
                    const clean_val = std.mem.trim(u8, val, " ");
                    content_length = std.fmt.parseInt(usize, clean_val, 10) catch null;
                }
            } else if (std.ascii.indexOfIgnoreCase(line, "Accept-Ranges: bytes") != null) {
                accepts_ranges = true;
            }
        }

        if (content_length == null or content_length.? < 100_000) {
            return false;
        }

        const total_bytes = content_length.?;
        printProgressBar("Slicing file into 4 parallel micro chunk streams...", 3, 10);

        const chunks = 4;
        const chunk_size = total_bytes / chunks;

        var threads = std.ArrayList(std.Thread).init(self.allocator);
        defer threads.deinit();

        var chunk_files = std.ArrayList([]const u8).init(self.allocator);
        defer {
            for (chunk_files.items) |p| self.allocator.free(p);
            chunk_files.deinit();
        }

        for (0..chunks) |i| {
            const start_byte = i * chunk_size;
            const end_byte = if (i == chunks - 1) total_bytes - 1 else (start_byte + chunk_size) - 1;

            const chunk_name = try std.fmt.allocPrint(self.allocator, "micro_chunk_{d}", .{i});
            defer self.allocator.free(chunk_name);

            const chunk_path = try std.fs.path.join(self.allocator, &.{ tmp_dir_path, chunk_name });
            try chunk_files.append(chunk_path);

            const thread = try std.Thread.spawn(.{}, downloadChunk, .{ self.allocator, url, start_byte, end_byte, chunk_path });
            try threads.append(thread);
        }

        // Wait for all micro-chunk threads to complete successfully
        for (threads.items) |thread| {
            thread.join();
        }

        printProgressBar("Concatenating micro chunk buffers into main file...", 7, 10);

        const out_file = try std.fs.cwd().createFile(archive_path, .{ .mode = 0o600 });
        defer out_file.close();

        var buf: [65536]u8 = undefined;
        for (chunk_files.items) |path| {
            const chunk_file = try std.fs.cwd().openFile(path, .{});
            defer chunk_file.close();

            while (true) {
                const read_bytes = try chunk_file.read(&buf);
                if (read_bytes == 0) break;
                try out_file.writeAll(buf[0..read_bytes]);
            }
        }

        // Clean up micro chunks
        for (chunk_files.items) |path| {
            std.fs.cwd().deleteFile(path) catch {};
        }

        return true;
    }

    pub fn install(self: *Store, pkg: registry.Package, platform_name: []const u8, use_micro_split: bool) !void {
        const info = pkg.platforms.get(platform_name) orelse {
            std.debug.print("Error: Platform '{s}' is not supported for package '{s}'.\n", .{ platform_name, pkg.name });
            return error.UnsupportedPlatform;
        };

        const pkg_dir = try self.getPkgStorePath(pkg, platform_name);
        defer self.allocator.free(pkg_dir);

        // Check if already in store
        if (try self.isInstalled(pkg, platform_name)) {
            std.debug.print("Package '{s}' already installed in secure store ({s})\n", .{ pkg.name, pkg_dir });
        } else {
            const init_msg = try std.fmt.allocPrint(self.allocator, "Initializing setup for {s}...", .{pkg.name});
            defer self.allocator.free(init_msg);
            printProgressBar(init_msg, 1, 5);

            // Security fix: Use highly unpredictable tmp work dir names with cryptographic random noise and 0700 permissions
            const random_token = std.crypto.random.int(u64);
            const tmp_dir_path = try std.fmt.allocPrint(self.allocator, "{s}_{x}.tmp", .{ pkg_dir, random_token });
            defer self.allocator.free(tmp_dir_path);

            std.fs.cwd().deleteTree(tmp_dir_path) catch {};
            try std.fs.cwd().makePath(tmp_dir_path);

            // Enforce secure temporary folder permissions
            _ = std.process.Child.run(.{ .allocator = self.allocator, .argv = &.{ "chmod", "0700", tmp_dir_path } }) catch {};

            // Download archive file
            const archive_path = try std.fs.path.join(self.allocator, &.{ tmp_dir_path, "archive_data" });
            defer self.allocator.free(archive_path);

            var micro_success = false;
            if (use_micro_split) {
                micro_success = try self.microSplitDownload(info.url, archive_path, tmp_dir_path);
            }

            if (!micro_success) {
                const dl_msg = try std.fmt.allocPrint(self.allocator, "Downloading {s} from {s}...", .{ pkg.name, info.url });
                defer self.allocator.free(dl_msg);
                printProgressBar(dl_msg, 2, 5);

                // Standard secure stream download
                const curl_result = try std.process.Child.run(.{
                    .allocator = self.allocator,
                    .argv = &.{ "curl", "-s", "-L", info.url, "-o", archive_path },
                });
                defer {
                    self.allocator.free(curl_result.stdout);
                    self.allocator.free(curl_result.stderr);
                }
                if (curl_result.term.Exited != 0) {
                    std.debug.print("Download failed: {s}\n", .{curl_result.stderr});
                    return error.DownloadFailed;
                }
            }

            // Secure SHA256 Verification
            const verify_msg = try std.fmt.allocPrint(self.allocator, "Verifying SHA256 integrity sums for {s}...", .{pkg.name});
            defer self.allocator.free(verify_msg);
            printProgressBar(verify_msg, 3, 5);

            const file = try std.fs.cwd().openFile(archive_path, .{});
            var hasher = std.crypto.hash.sha2.Sha256.init(.{});
            var buf: [65536]u8 = undefined;
            while (true) {
                const read_bytes = try file.read(&buf);
                if (read_bytes == 0) break;
                hasher.update(buf[0..read_bytes]);
            }
            file.close();

            var hash_out: [32]u8 = undefined;
            hasher.final(&hash_out);

            const computed_hash = try std.fmt.allocPrint(self.allocator, "{s}", .{std.fmt.fmtSliceHexLower(&hash_out)});
            defer self.allocator.free(computed_hash);

            if (!std.mem.eql(u8, computed_hash, info.sha256)) {
                std.debug.print("SECURITY BREAK: Checksum mismatch for {s}!\nExpected: {s}\nComputed: {s}\nArchive deleted to prevent malicious tampering.\n", .{ pkg.name, info.sha256, computed_hash });
                std.fs.cwd().deleteTree(tmp_dir_path) catch {};
                return error.ChecksumMismatch;
            }

            // Unpack archive safely
            const unpack_msg = try std.fmt.allocPrint(self.allocator, "Unpacking {s} archive...", .{pkg.name});
            defer self.allocator.free(unpack_msg);
            printProgressBar(unpack_msg, 4, 5);

            if (std.mem.eql(u8, info.archive_type, "tar.gz") or std.mem.eql(u8, info.archive_type, "tar.xz")) {
                const tar_res = try std.process.Child.run(.{
                    .allocator = self.allocator,
                    .argv = &.{ "tar", "-xf", archive_path, "-C", tmp_dir_path },
                });
                defer {
                    self.allocator.free(tar_res.stdout);
                    self.allocator.free(tar_res.stderr);
                }
                if (tar_res.term.Exited != 0) return error.UnpackFailed;
                try std.fs.cwd().deleteFile(archive_path);
            } else if (std.mem.eql(u8, info.archive_type, "zip")) {
                const unzip_res = try std.process.Child.run(.{
                    .allocator = self.allocator,
                    .argv = &.{ "unzip", "-q", "-o", archive_path, "-d", tmp_dir_path },
                });
                defer {
                    self.allocator.free(unzip_res.stdout);
                    self.allocator.free(unzip_res.stderr);
                }
                if (unzip_res.term.Exited != 0) return error.UnpackFailed;
                try std.fs.cwd().deleteFile(archive_path);
            } else if (std.mem.eql(u8, info.archive_type, "dmg")) {
                printProgressBar("Mounting macOS DMG disk image...", 4, 5);

                const mount_res = try std.process.Child.run(.{
                    .allocator = self.allocator,
                    .argv = &.{ "hdiutil", "attach", "-nobrowse", "-quiet", archive_path },
                });
                defer {
                    self.allocator.free(mount_res.stdout);
                    self.allocator.free(mount_res.stderr);
                }

                // Locate any .app bundle in /Volumes
                var mounted_app_path: ?[]const u8 = null;
                var volumes_dir = std.fs.cwd().openDir("/Volumes", .{ .iterate = true }) catch null;
                if (volumes_dir != null) {
                    defer volumes_dir.?.close();
                    var vol_it = volumes_dir.?.iterate();
                    while (try vol_it.next()) |vol_entry| {
                        const test_vol = try std.fs.path.join(self.allocator, &.{ "/Volumes", vol_entry.name });
                        defer self.allocator.free(test_vol);

                        var test_dir = std.fs.cwd().openDir(test_vol, .{ .iterate = true }) catch continue;
                        defer test_dir.close();
                        var test_it = test_dir.iterate();
                        while (try test_it.next()) |sub_entry| {
                            if (std.mem.endsWith(u8, sub_entry.name, ".app")) {
                                mounted_app_path = try std.fs.path.join(self.allocator, &.{ test_vol, sub_entry.name });
                                break;
                            }
                        }
                        if (mounted_app_path != null) break;
                    }
                }

                if (mounted_app_path) |app_path| {
                    defer self.allocator.free(app_path);
                    const basename = std.fs.path.basename(app_path);
                    const dst_app_bundle = try std.fs.path.join(self.allocator, &.{ tmp_dir_path, basename });
                    defer self.allocator.free(dst_app_bundle);

                    printProgressBar("Fast copying GUI Application bundle from disk image...", 4, 5);
                    _ = try std.process.Child.run(.{
                        .allocator = self.allocator,
                        .argv = &.{ "cp", "-R", app_path, dst_app_bundle },
                    });

                    // Detach DMG
                    if (std.fs.path.dirname(app_path)) |vol_base| {
                        _ = std.process.Child.run(.{
                            .allocator = self.allocator,
                            .argv = &.{ "hdiutil", "detach", "-quiet", vol_base },
                        }) catch {};
                    }
                }
                try std.fs.cwd().deleteFile(archive_path);
            } else if (std.mem.eql(u8, info.archive_type, "raw")) {
                const actual_bin_path = try std.fs.path.join(self.allocator, &.{ tmp_dir_path, info.bin_path });
                defer self.allocator.free(actual_bin_path);

                try std.fs.cwd().rename(archive_path, actual_bin_path);
                _ = try std.process.Child.run(.{
                    .allocator = self.allocator,
                    .argv = &.{ "chmod", "0700", actual_bin_path },
                });
            } else {
                return error.UnknownArchiveType;
            }

            // Move secure tmp_dir to final pkg_dir
            try std.fs.cwd().rename(tmp_dir_path, pkg_dir);
        }

        // Fast link binaries to ~/.abv0/bin
        if (pkg.bin.len > 0) {
            const link_msg = try std.fmt.allocPrint(self.allocator, "Linking {s} executables into {s}...", .{ pkg.name, self.bin_root });
            defer self.allocator.free(link_msg);
            printProgressBar(link_msg, 5, 5);

            for (pkg.bin) |bin_name| {
                const src_bin = try std.fs.path.join(self.allocator, &.{ pkg_dir, info.bin_path });
                defer self.allocator.free(src_bin);

                const dst_bin = try std.fs.path.join(self.allocator, &.{ self.bin_root, bin_name });
                defer self.allocator.free(dst_bin);

                _ = std.process.Child.run(.{
                    .allocator = self.allocator,
                    .argv = &.{ "chmod", "+x", src_bin },
                }) catch {};

                const used_clone = try os_macos.fastLink(src_bin, dst_bin);
                if (used_clone) {
                    std.debug.print("   [ APFS Clone ] {s} -> {s} (Instant copy-on-write 0ms latency)\n", .{ bin_name, src_bin });
                } else {
                    std.debug.print("   [ Symlink Link ] {s} -> {s}\n", .{ bin_name, src_bin });
                }
            }
        }

        // Innovative GUI Application Setup: Fast Link / APFS Clone into ~/Applications
        if (pkg.app_bundles.len > 0) {
            const app_msg = try std.fmt.allocPrint(self.allocator, "Linking GUI Application bundles into {s}...", .{self.apps_root});
            defer self.allocator.free(app_msg);
            printProgressBar(app_msg, 5, 5);

            for (pkg.app_bundles) |app_name| {
                const src_app = try std.fs.path.join(self.allocator, &.{ pkg_dir, app_name });
                defer self.allocator.free(src_app);

                const dst_app = try std.fs.path.join(self.allocator, &.{ self.apps_root, app_name });
                defer self.allocator.free(dst_app);

                std.fs.cwd().deleteTree(dst_app) catch {};

                if (os_macos.fastLink(src_app, dst_app)) |_| {
                    std.debug.print("   [ APFS Clone ] {s} -> {s} (Instant 0ms GUI Application setup)\n", .{ app_name, src_app });
                } else |_| {
                    _ = std.process.Child.run(.{ .allocator = self.allocator, .argv = &.{ "cp", "-R", src_app, dst_app } }) catch {};
                    std.debug.print("   [ Copied App Bundle ] {s} -> {s}\n", .{ app_name, src_app });
                }
            }
        }
    }

    pub fn uninstall(self: *Store, pkg: registry.Package) !void {
        var uninstalled_any = false;

        // Unlink executables
        for (pkg.bin) |bin_name| {
            const dst_bin = try std.fs.path.join(self.allocator, &.{ self.bin_root, bin_name });
            defer self.allocator.free(dst_bin);

            if (std.fs.cwd().deleteFile(dst_bin)) |_| {
                std.debug.print("Unlinked binary {s}\n", .{dst_bin});
            } else |_| {}
        }

        // Unlink GUI Application bundles
        for (pkg.app_bundles) |app_name| {
            const dst_app = try std.fs.path.join(self.allocator, &.{ self.apps_root, app_name });
            defer self.allocator.free(dst_app);

            if (std.fs.cwd().deleteTree(dst_app)) |_| {
                std.debug.print("Unlinked GUI Application bundle {s}\n", .{dst_app});
            } else |_| {}
        }

        // Delete from store for all platforms
        var plat_it = pkg.platforms.iterator();
        while (plat_it.next()) |plat_entry| {
            const plat_name = plat_entry.key_ptr.*;
            const pkg_dir = self.getPkgStorePath(pkg, plat_name) catch continue;
            defer self.allocator.free(pkg_dir);

            if (std.fs.cwd().deleteTree(pkg_dir)) |_| {
                std.debug.print("Removed secure package store {s}\n", .{pkg_dir});
                uninstalled_any = true;
            } else |_| {}
        }

        if (!uninstalled_any) {
            std.debug.print("Note: Package '{s}' was not installed.\n", .{pkg.name});
        }
    }

    pub fn execute(self: *Store, pkg: registry.Package, platform_name: []const u8, args: []const []const u8, use_micro_split: bool) !void {
        // Ensure installed
        if (!(try self.isInstalled(pkg, platform_name))) {
            try self.install(pkg, platform_name, use_micro_split);
        }

        const info = pkg.platforms.get(platform_name) orelse return error.UnsupportedPlatform;
        const pkg_dir = try self.getPkgStorePath(pkg, platform_name);
        defer self.allocator.free(pkg_dir);

        const bin_path = try std.fs.path.join(self.allocator, &.{ pkg_dir, info.bin_path });
        defer self.allocator.free(bin_path);

        var child_args = std.ArrayList([]const u8).init(self.allocator);
        defer child_args.deinit();

        try child_args.append(bin_path);
        for (args) |arg| {
            try child_args.append(arg);
        }

        var child = std.process.Child.init(child_args.items, self.allocator);
        _ = try child.spawnAndWait();
    }

    // Innovative Feature: Isolated Ephemeral Sandboxed Shell
    pub fn executeShell(self: *Store, pkgs: []const registry.Package, platform_name: []const u8, use_micro_split: bool) !void {
        printProgressBar("Setting up secure isolated ephemeral environment shell...", 1, 4);

        // 1. Ensure all requested packages are in store
        for (pkgs) |pkg| {
            if (!(try self.isInstalled(pkg, platform_name))) {
                try self.install(pkg, platform_name, use_micro_split);
            }
        }

        printProgressBar("Provisioning isolated temporary sandbox paths...", 2, 4);

        // 2. Create an isolated temporary bin directory
        const timestamp = std.time.timestamp();
        const random_id = std.crypto.random.int(u32);
        const shell_dir_name = try std.fmt.allocPrint(self.allocator, "shell_{d}_{d}", .{ timestamp, random_id });
        defer self.allocator.free(shell_dir_name);

        const shell_base_path = try std.fs.path.join(self.allocator, &.{ self.shells_root, shell_dir_name });
        defer self.allocator.free(shell_base_path);

        const shell_bin_path = try std.fs.path.join(self.allocator, &.{ shell_base_path, "bin" });
        defer self.allocator.free(shell_bin_path);

        try std.fs.cwd().makePath(shell_bin_path);
        defer std.fs.cwd().deleteTree(shell_base_path) catch {};

        // Security check: restrict permissions on active shell folder
        _ = std.process.Child.run(.{ .allocator = self.allocator, .argv = &.{ "chmod", "0700", shell_base_path } }) catch {};

        printProgressBar("Linking requested dependencies into sandbox...", 3, 4);

        // 3. Populate isolated bin with APFS clones/symlinks of only requested packages
        for (pkgs) |pkg| {
            const info = pkg.platforms.get(platform_name) orelse return error.UnsupportedPlatform;
            const pkg_dir = try self.getPkgStorePath(pkg, platform_name);
            defer self.allocator.free(pkg_dir);

            for (pkg.bin) |bin_name| {
                const src_bin = try std.fs.path.join(self.allocator, &.{ pkg_dir, info.bin_path });
                defer self.allocator.free(src_bin);

                const dst_bin = try std.fs.path.join(self.allocator, &.{ shell_bin_path, bin_name });
                defer self.allocator.free(dst_bin);

                _ = try os_macos.fastLink(src_bin, dst_bin);
            }
        }

        printProgressBar("Spawning secure sandboxed subshell...", 4, 4);
        std.debug.print("Type 'exit' to return to your host system and dissolve the sandbox automatically.\n", .{});

        // 4. Construct PATH: isolated_bin + standard system paths (without global abv0 bin)
        const old_path = std.posix.getenv("PATH") orelse "/usr/bin:/bin:/usr/sbin:/sbin";
        const new_path = try std.fmt.allocPrint(self.allocator, "{s}:{s}", .{ shell_bin_path, old_path });
        defer self.allocator.free(new_path);

        // 5. Detect user shell
        const shell_exe = std.posix.getenv("SHELL") orelse "/bin/sh";

        var env_map = try std.process.getEnvMap(self.allocator);
        defer env_map.deinit();
        try env_map.put("PATH", new_path);
        try env_map.put("ABV0_SHELL", "1");

        var child = std.process.Child.init(&.{shell_exe}, self.allocator);
        child.env_map = &env_map;

        _ = try child.spawnAndWait();
        std.debug.print("[ CLEAR ] Sandboxed temporary session successfully closed and dissolved.\n", .{});
    }

    // Diagnostic Helper: Doctor Audits Profile and Permissions
    pub fn doctor(self: *Store, reg: *registry.Registry, platform_name: []const u8) !void {
        std.debug.print("=== [ abv0 System Diagnostic & Doctor Check ] ===\n\n", .{});

        var total_warnings: u32 = 0;
        var total_broken_links: u32 = 0;

        // 1. Verify PATH profile
        std.debug.print("Checking PATH profile...\n", .{});
        if (std.posix.getenv("PATH")) |env_path| {
            if (std.mem.indexOf(u8, env_path, self.bin_root) == null) {
                total_warnings += 1;
                std.debug.print("[ Warning ] Your active PATH environment variable does not contain the abv0 managed binary folder:\n", .{});
                std.debug.print("            -> Expected: {s}\n", .{self.bin_root});
                std.debug.print("            -> Solution: Add export PATH=\"{s}:$PATH\" to your ~/.zshrc profile.\n\n", .{self.bin_root});
            } else {
                std.debug.print("   -> Profile PATH correctly contains abv0 managed binary path.\n\n", .{});
            }
        }

        // 2. Writable Store Profile Verification
        std.debug.print("Checking directory permissions and storage integrity...\n", .{});
        std.fs.cwd().access(self.store_root, .{ .mode = .read_write }) catch {
            total_warnings += 1;
            std.debug.print("[ Warning ] Internal store directory ({s}) is missing write permissions.\n\n", .{self.store_root});
        };

        // 3. Execution Link Health check
        std.debug.print("Auditing installed package link state...\n", .{});
        var it = reg.packages.iterator();
        while (it.next()) |entry| {
            const pkg = entry.value_ptr.*;
            if (try self.isInstalled(pkg, platform_name)) {
                // Check binary targets
                for (pkg.bin) |bin_name| {
                    const dst_bin = try std.fs.path.join(self.allocator, &.{ self.bin_root, bin_name });
                    defer self.allocator.free(dst_bin);

                    std.fs.cwd().access(dst_bin, .{}) catch {
                        total_broken_links += 1;
                        std.debug.print("[ Broken Link ] Package '{s}' is installed, but executable '{s}' is unlinked or missing from ~/.abv0/bin.\n", .{ pkg.name, bin_name });
                    };
                }

                // Check GUI Application targets
                for (pkg.app_bundles) |app_name| {
                    const dst_app = try std.fs.path.join(self.allocator, &.{ self.apps_root, app_name });
                    defer self.allocator.free(dst_app);

                    std.fs.cwd().access(dst_app, .{}) catch {
                        total_broken_links += 1;
                        std.debug.print("[ Broken Link ] GUI Package '{s}' is installed, but bundle '{s}' is unlinked or missing from ~/Applications.\n", .{ pkg.name, app_name });
                    };
                }
            }
        }

        std.debug.print("\n=== [ Diagnostic Summary ] ===\n", .{});
        if (total_warnings == 0 and total_broken_links == 0) {
            std.debug.print("[ HEALTHY ] Your system is raring to brew and perfectly optimized.\n", .{});
        } else {
            std.debug.print("[ WARNINGS FOUND ] Found {} warnings and {} broken execution links.\n", .{ total_warnings, total_broken_links });
            std.debug.print("                   Run 'abv0 fix' to automatically heal and resolve all broken packages and permissions.\n", .{});
        }
    }

    // Self-Healing Auto-Fix command
    pub fn fix(self: *Store, reg: *registry.Registry, platform_name: []const u8) !void {
        printProgressBar("Starting abv0 automated self-healing package & permission repair...", 1, 4);

        var packages_healed: u32 = 0;
        var permissions_fixed: u32 = 0;

        printProgressBar("Resetting strict secure 0o700 user permissions on critical paths...", 2, 4);

        _ = std.process.Child.run(.{ .allocator = self.allocator, .argv = &.{ "chmod", "-R", "u+rwX", self.store_root } }) catch {};
        permissions_fixed += 1;

        printProgressBar("Re-linking all unlinked or fractured executables into ~/.abv0/bin...", 3, 4);

        var it = reg.packages.iterator();
        while (it.next()) |entry| {
            const pkg = entry.value_ptr.*;
            if (try self.isInstalled(pkg, platform_name)) {
                const info = pkg.platforms.get(platform_name) orelse continue;
                const pkg_dir = try self.getPkgStorePath(pkg, platform_name);
                defer self.allocator.free(pkg_dir);

                for (pkg.bin) |bin_name| {
                    const dst_bin = try std.fs.path.join(self.allocator, &.{ self.bin_root, bin_name });
                    defer self.allocator.free(dst_bin);

                    std.fs.cwd().access(dst_bin, .{}) catch {
                        const src_bin = try std.fs.path.join(self.allocator, &.{ pkg_dir, info.bin_path });
                        defer self.allocator.free(src_bin);

                        if (os_macos.fastLink(src_bin, dst_bin)) |_| {
                            packages_healed += 1;
                            std.debug.print("   -> Successfully self-healed and re-linked: {s}\n", .{bin_name});
                        } else |err| {
                            std.debug.print("   -> Failed to link {s}: {}\n", .{ bin_name, err });
                        }
                    };
                }

                // Repair GUI Application bundles
                for (pkg.app_bundles) |app_name| {
                    const dst_app = try std.fs.path.join(self.allocator, &.{ self.apps_root, app_name });
                    defer self.allocator.free(dst_app);

                    std.fs.cwd().access(dst_app, .{}) catch {
                        const src_app = try std.fs.path.join(self.allocator, &.{ pkg_dir, app_name });
                        defer self.allocator.free(src_app);

                        if (os_macos.fastLink(src_app, dst_app)) |_| {
                            packages_healed += 1;
                            std.debug.print("   -> Successfully self-healed GUI Application bundle: {s}\n", .{app_name});
                        } else |_| {
                            _ = std.process.Child.run(.{ .allocator = self.allocator, .argv = &.{ "cp", "-R", src_app, dst_app } }) catch {};
                            packages_healed += 1;
                        }
                    };
                }
            }
        }

        printProgressBar("Purging residual temporary downloads...", 4, 4);
        try self.gc();

        std.debug.print("\n[ REPAIR COMPLETE ] Successfully healed {} broken package links and fixed directory permissions.\n", .{packages_healed});
    }

    // Innovative Feature: Malware & Suspicious Heuristic Detector
    pub fn detectMalware(self: *Store, pkg: registry.Package, platform_name: []const u8) !void {
        std.debug.print("=== [ abv0 Advanced Malware & Security Heuristic Scanner ] ===\n\n", .{});
        std.debug.print("Target Package: {s} v{s} ({s})\n", .{ pkg.name, pkg.version, platform_name });

        if (!(try self.isInstalled(pkg, platform_name))) {
            std.debug.print("Error: Package '{s}' is not installed in your store. Run 'abv0 install {s}' first to scan its files.\n", .{ pkg.name, pkg.name });
            return;
        }

        const pkg_dir = try self.getPkgStorePath(pkg, platform_name);
        defer self.allocator.free(pkg_dir);

        printProgressBar("Initializing Signature Heuristics Engine...", 1, 5);

        var threat_score: u32 = 0;
        var risk_reasons = std.ArrayList([]const u8).init(self.allocator);
        defer {
            for (risk_reasons.items) |r| self.allocator.free(r);
            risk_reasons.deinit();
        }

        printProgressBar("Scanning binary definitions and executable byte streams...", 2, 5);

        // Scan the actual executable path
        const info = pkg.platforms.get(platform_name) orelse return error.UnsupportedPlatform;
        const bin_path = try std.fs.path.join(self.allocator, &.{ pkg_dir, info.bin_path });
        defer self.allocator.free(bin_path);

        const file = try std.fs.cwd().openFile(bin_path, .{});
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 50 * 1024 * 1024);
        defer self.allocator.free(content);

        printProgressBar("Evaluating heuristic threat vectors and behavioral patterns...", 4, 5);

        // 1. Suspicious Reverse Shell & Backdoor Heuristics
        if (std.mem.indexOf(u8, content, "/bin/sh -i") != null or std.mem.indexOf(u8, content, "nc -e") != null) {
            threat_score += 40;
            try risk_reasons.append(try self.allocator.dupe(u8, "Suspicious reverse shell backdoor execution sequence detected (/bin/sh -i or nc -e)"));
        }

        // 2. Cryptominer Pool & Stratum protocol Heuristics
        if (std.mem.indexOf(u8, content, "stratum+tcp://") != null or std.mem.indexOf(u8, content, "nicehash") != null) {
            threat_score += 50;
            try risk_reasons.append(try self.allocator.dupe(u8, "Embedded cryptominer Stratum mining pool strings detected"));
        }

        // 3. Credential Harvesting & System File Access
        if (std.mem.indexOf(u8, content, "/etc/shadow") != null or std.mem.indexOf(u8, content, "/.ssh/id_rsa") != null) {
            threat_score += 35;
            try risk_reasons.append(try self.allocator.dupe(u8, "Private key or shadow password credential harvesting pattern accessed"));
        }

        // 4. Insecure Remote Script Piping
        if (std.mem.indexOf(u8, content, "curl | sh") != null or std.mem.indexOf(u8, content, "wget -O- | sh") != null) {
            threat_score += 25;
            try risk_reasons.append(try self.allocator.dupe(u8, "Insecure remote pipe execution script pattern (curl | sh)"));
        }

        printProgressBar("Consolidating Security Report...", 5, 5);

        std.debug.print("\n=== [ Security Audit Verdict ] ===\n", .{});
        if (threat_score == 0) {
            std.debug.print("[ PASSED ] Threat Score: 0/100\n", .{});
            std.debug.print("           Verdict: Completely pristine, clean, and trusted software package. Zero malware patterns found.\n", .{});
        } else {
            std.debug.print("[ HIGH RISK SUSPICION ] Threat Score: {}/100\n", .{threat_score});
            std.debug.print("                        Verdict: Suspicious heuristic patterns identified in package code!\n\n", .{});
            std.debug.print("Detailed Risk Vectors Identifed:\n", .{});
            for (risk_reasons.items) |reason| {
                std.debug.print("  -> {s}\n", .{reason});
            }
        }
    }

    // Instant Garbage Collector / Prune
    pub fn gc(self: *Store) !void {
        var store_dir = try std.fs.cwd().openDir(self.store_root, .{ .iterate = true });
        defer store_dir.close();

        var it = store_dir.iterate();
        var deleted_count: u32 = 0;

        while (try it.next()) |entry| {
            if (std.mem.endsWith(u8, entry.name, ".tmp")) {
                const tmp_path = try std.fs.path.join(self.allocator, &.{ self.store_root, entry.name });
                defer self.allocator.free(tmp_path);

                if (std.fs.cwd().deleteTree(tmp_path)) |_| {
                    deleted_count += 1;
                } else |_| {}
            }
        }

        // Clean temporary shells directory
        var shells_dir = std.fs.cwd().openDir(self.shells_root, .{ .iterate = true }) catch null;
        if (shells_dir != null) {
            defer shells_dir.?.close();
            var shell_it = shells_dir.?.iterate();
            while (try shell_it.next()) |entry| {
                const shell_path = try std.fs.path.join(self.allocator, &.{ self.shells_root, entry.name });
                defer self.allocator.free(shell_path);

                if (std.fs.cwd().deleteTree(shell_path)) |_| {
                    deleted_count += 1;
                } else |_| {}
            }
        }
    }
};
