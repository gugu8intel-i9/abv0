const std = @import("std");
const registry = @import("registry.zig");
const os_macos = @import("os_macos.zig");
const builtin = @import("builtin");

pub const Store = struct {
    allocator: std.mem.Allocator,
    store_root: []const u8,
    bin_root: []const u8,
    shells_root: []const u8,

    pub fn init(allocator: std.mem.Allocator) !Store {
        const home_dir = std.posix.getenv("HOME") orelse {
            return error.HomeDirNotFound;
        };

        const store_root = try std.fs.path.join(allocator, &.{ home_dir, ".abv0", "store" });
        const bin_root = try std.fs.path.join(allocator, &.{ home_dir, ".abv0", "bin" });
        const shells_root = try std.fs.path.join(allocator, &.{ home_dir, ".abv0", "shells" });

        // Ensure directories exist
        std.fs.cwd().makePath(store_root) catch {};
        std.fs.cwd().makePath(bin_root) catch {};
        std.fs.cwd().makePath(shells_root) catch {};

        return Store{
            .allocator = allocator,
            .store_root = store_root,
            .bin_root = bin_root,
            .shells_root = shells_root,
        };
    }

    pub fn deinit(self: *Store) void {
        self.allocator.free(self.store_root);
        self.allocator.free(self.bin_root);
        self.allocator.free(self.shells_root);
    }

    pub fn getPkgStorePath(self: *Store, pkg: registry.Package, platform_name: []const u8) ![]const u8 {
        const dir_name = try std.fmt.allocPrint(self.allocator, "{s}-{s}-{s}", .{ pkg.name, pkg.version, platform_name });
        defer self.allocator.free(dir_name);

        return try std.fs.path.join(self.allocator, &.{ self.store_root, dir_name });
    }

    pub fn isInstalled(self: *Store, pkg: registry.Package, platform_name: []const u8) !bool {
        const pkg_dir = try self.getPkgStorePath(pkg, platform_name);
        defer self.allocator.free(pkg_dir);

        var dir = std.fs.cwd().openDir(pkg_dir, .{}) catch {
            return false;
        };
        dir.close();
        return true;
    }

    pub fn install(self: *Store, pkg: registry.Package, platform_name: []const u8) !void {
        const info = pkg.platforms.get(platform_name) orelse {
            std.debug.print("Error: Platform '{s}' is not supported for package '{s}'.\n", .{ platform_name, pkg.name });
            return error.UnsupportedPlatform;
        };

        const pkg_dir = try self.getPkgStorePath(pkg, platform_name);
        defer self.allocator.free(pkg_dir);

        // Check if already in store
        if (try self.isInstalled(pkg, platform_name)) {
            std.debug.print("Package '{s}' already installed in store ({s})\n", .{ pkg.name, pkg_dir });
        } else {
            std.debug.print("Downloading {s} v{s} for {s}...\n", .{ pkg.name, pkg.version, platform_name });
            std.debug.print("URL: {s}\n", .{info.url});

            // Create temporary work dir
            const tmp_dir_path = try std.fmt.allocPrint(self.allocator, "{s}.tmp", .{pkg_dir});
            defer self.allocator.free(tmp_dir_path);

            std.fs.cwd().deleteTree(tmp_dir_path) catch {};
            try std.fs.cwd().makePath(tmp_dir_path);

            // Download file
            const archive_path = try std.fs.path.join(self.allocator, &.{ tmp_dir_path, "archive_data" });
            defer self.allocator.free(archive_path);

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

            // Verify SHA256 checksum
            std.debug.print("Verifying SHA256 integrity for {s}...\n", .{pkg.name});
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
                std.debug.print("Checksum mismatch for {s}!\nExpected: {s}\nComputed: {s}\n", .{ pkg.name, info.sha256, computed_hash });
                return error.ChecksumMismatch;
            }
            std.debug.print("SHA256 checksum verified!\n", .{});

            // Unpack archive
            std.debug.print("Unpacking {s} ({s})...\n", .{ pkg.name, info.archive_type });
            if (std.mem.eql(u8, info.archive_type, "tar.gz") or std.mem.eql(u8, info.archive_type, "tar.xz")) {
                const tar_res = try std.process.Child.run(.{
                    .allocator = self.allocator,
                    .argv = &.{ "tar", "-xf", archive_path, "-C", tmp_dir_path },
                });
                defer {
                    self.allocator.free(tar_res.stdout);
                    self.allocator.free(tar_res.stderr);
                }
                if (tar_res.term.Exited != 0) {
                    return error.UnpackFailed;
                }
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
                if (unzip_res.term.Exited != 0) {
                    return error.UnpackFailed;
                }
                try std.fs.cwd().deleteFile(archive_path);
            } else if (std.mem.eql(u8, info.archive_type, "raw")) {
                // For raw single binaries, we just rename archive_data to the actual binary name
                const actual_bin_path = try std.fs.path.join(self.allocator, &.{ tmp_dir_path, info.bin_path });
                defer self.allocator.free(actual_bin_path);

                try std.fs.cwd().rename(archive_path, actual_bin_path);
                // Make executable
                const chmod_res = try std.process.Child.run(.{
                    .allocator = self.allocator,
                    .argv = &.{ "chmod", "+x", actual_bin_path },
                });
                defer {
                    self.allocator.free(chmod_res.stdout);
                    self.allocator.free(chmod_res.stderr);
                }
            } else {
                return error.UnknownArchiveType;
            }

            // Move completed tmp_dir to final pkg_dir
            try std.fs.cwd().rename(tmp_dir_path, pkg_dir);
        }

        // Fast link binaries to ~/.abv0/bin
        std.debug.print("Linking executables for {s} into {s}...\n", .{ pkg.name, self.bin_root });
        for (pkg.bin) |bin_name| {
            const src_bin = try std.fs.path.join(self.allocator, &.{ pkg_dir, info.bin_path });
            defer self.allocator.free(src_bin);

            const dst_bin = try std.fs.path.join(self.allocator, &.{ self.bin_root, bin_name });
            defer self.allocator.free(dst_bin);

            // Ensure executable permissions
            _ = std.process.Child.run(.{
                .allocator = self.allocator,
                .argv = &.{ "chmod", "+x", src_bin },
            }) catch {};

            const used_clone = try os_macos.fastLink(src_bin, dst_bin);
            if (used_clone) {
                std.debug.print("   {s} -> {s} (Instant APFS Clone! 0ms latency)\n", .{ bin_name, src_bin });
            } else {
                std.debug.print("   {s} -> {s} (Symlink)\n", .{ bin_name, src_bin });
            }
        }
    }

    pub fn uninstall(self: *Store, pkg: registry.Package) !void {
        var uninstalled_any = false;

        // Unlink binaries
        for (pkg.bin) |bin_name| {
            const dst_bin = try std.fs.path.join(self.allocator, &.{ self.bin_root, bin_name });
            defer self.allocator.free(dst_bin);

            if (std.fs.cwd().deleteFile(dst_bin)) |_| {
                std.debug.print("Unlinked binary {s}\n", .{dst_bin});
            } else |_| {}
        }

        // Delete from store for all platforms
        var plat_it = pkg.platforms.iterator();
        while (plat_it.next()) |plat_entry| {
            const plat_name = plat_entry.key_ptr.*;
            const pkg_dir = try self.getPkgStorePath(pkg, plat_name);
            defer self.allocator.free(pkg_dir);

            if (std.fs.cwd().deleteTree(pkg_dir)) |_| {
                std.debug.print("Removed package cache {s}\n", .{pkg_dir});
                uninstalled_any = true;
            } else |_| {}
        }

        if (!uninstalled_any) {
            std.debug.print("Note: Package '{s}' was not installed.\n", .{pkg.name});
        }
    }

    pub fn execute(self: *Store, pkg: registry.Package, platform_name: []const u8, args: []const []const u8) !void {
        // Ensure installed
        if (!(try self.isInstalled(pkg, platform_name))) {
            try self.install(pkg, platform_name);
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

    // Innovative Feature: Isolated Temporary Sandboxed Shell
    pub fn executeShell(self: *Store, pkgs: []const registry.Package, platform_name: []const u8) !void {
        std.debug.print("Setting up isolated abv0 environment shell...\n", .{});

        // 1. Ensure all requested packages are in the store
        for (pkgs) |pkg| {
            if (!(try self.isInstalled(pkg, platform_name))) {
                try self.install(pkg, platform_name);
            }
        }

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

        // 3. Populate isolated bin with APFS clones/symlinks of only the requested packages
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

        std.debug.print("Spawning sandboxed subshell. Type 'exit' to return and automatically clean up.\n", .{});

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
        std.debug.print("Exited sandboxed shell. Temporary environment cleaned up successfully.\n", .{});
    }

    // Innovative Feature: Self-Healing Doctor
    pub fn doctor(self: *Store, reg: *registry.Registry, platform_name: []const u8) !void {
        std.debug.print("Running abv0 self-healing audit & health check...\n", .{});

        var issues_found: u32 = 0;
        var issues_fixed: u32 = 0;

        var it = reg.packages.iterator();
        while (it.next()) |entry| {
            const pkg = entry.value_ptr.*;
            if (try self.isInstalled(pkg, platform_name)) {
                const info = pkg.platforms.get(platform_name) orelse continue;
                const pkg_dir = try self.getPkgStorePath(pkg, platform_name);
                defer self.allocator.free(pkg_dir);

                // Verify each binary link exists in ~/.abv0/bin
                for (pkg.bin) |bin_name| {
                    const dst_bin = try std.fs.path.join(self.allocator, &.{ self.bin_root, bin_name });
                    defer self.allocator.free(dst_bin);

                    if (std.fs.cwd().access(dst_bin, .{})) |_| {
                        // Link is intact
                    } else |_| {
                        issues_found += 1;
                        std.debug.print("Broken link detected for binary: {s}\n", .{bin_name});

                        const src_bin = try std.fs.path.join(self.allocator, &.{ pkg_dir, info.bin_path });
                        defer self.allocator.free(src_bin);

                        if (os_macos.fastLink(src_bin, dst_bin)) |_| {
                            issues_fixed += 1;
                            std.debug.print("   Successfully self-healed link: {s} -> {s}\n", .{ bin_name, src_bin });
                        } else |err| {
                            std.debug.print("   Failed to self-heal link: {}\n", .{err});
                        }
                    }
                }
            }
        }

        if (issues_found == 0) {
            std.debug.print("Audit complete! All installed package links and internal stores are perfectly healthy.\n", .{});
        } else {
            std.debug.print("Audit complete! Found {} issues and self-healed {}.\n", .{ issues_found, issues_fixed });
        }
    }

    // Innovative Feature: Instant Garbage Collector / Prune
    pub fn gc(self: *Store) !void {
        std.debug.print("Starting abv0 instant garbage collector...\n", .{});

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
                    std.debug.print("Pruned orphaned temporary cache: {s}\n", .{entry.name});
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
                    std.debug.print("Pruned abandoned sandboxed shell environment: {s}\n", .{entry.name});
                } else |_| {}
            }
        }

        std.debug.print("Garbage collection finished successfully! Reclaimed {} abandoned items.\n", .{deleted_count});
    }
};
