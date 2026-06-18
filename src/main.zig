const std = @import("std");
const registry = @import("registry.zig");
const store = @import("store.zig");
const builtin = @import("builtin");

const ANSI_RESET = "\x1b[0m";
const ANSI_BOLD = "\x1b[1m";
const ANSI_GREEN = "\x1b[32m";
const ANSI_CYAN = "\x1b[36m";
const ANSI_YELLOW = "\x1b[33m";
const ANSI_RED = "\x1b[31m";
const ANSI_MAGENTA = "\x1b[35m";

fn getDefaultPlatform() []const u8 {
    if (builtin.target.os.tag == .macos) {
        if (builtin.target.cpu.arch == .aarch64) {
            return "aarch64-macos";
        } else {
            return "x86_64-macos";
        }
    } else if (builtin.target.os.tag == .linux) {
        return "x86_64-linux";
    }
    return "x86_64-linux"; // Sandbox fallback
}

fn indexOfIgnoreCase(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len > haystack.len) return null;
    var i: usize = 0;
    while (i <= haystack.len - needle.len) : (i += 1) {
        var match = true;
        for (needle, 0..) |n_char, j| {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(n_char)) {
                match = false;
                break;
            }
        }
        if (match) return i;
    }
    return null;
}

pub fn printUsage() void {
    std.debug.print(ANSI_CYAN ++ ANSI_BOLD ++ "abv0" ++ ANSI_RESET ++ " - The Faster, Innovative Homebrew Alternative built in Zig\n\n", .{});
    std.debug.print(ANSI_BOLD ++ "USAGE:\n" ++ ANSI_RESET, .{});
    std.debug.print("  abv0 <command> [options] [arguments]\n\n", .{});
    std.debug.print(ANSI_BOLD ++ "COMMANDS:\n" ++ ANSI_RESET, .{});
    std.debug.print("  " ++ ANSI_GREEN ++ "install" ++ ANSI_RESET ++ " <pkg>       Install and instantly APFS-link a package\n", .{});
    std.debug.print("  " ++ ANSI_RED ++ "uninstall" ++ ANSI_RESET ++ " <pkg>     Remove an installed package and its links\n", .{});
    std.debug.print("  " ++ ANSI_YELLOW ++ "run" ++ ANSI_RESET ++ " <pkg> [args...] Run a package executable instantly (auto-installs if missing)\n", .{});
    std.debug.print("  " ++ ANSI_MAGENTA ++ "search" ++ ANSI_RESET ++ " <query>      Search the lightning-fast abv0 registry\n", .{});
    std.debug.print("  " ++ ANSI_CYAN ++ "list" ++ ANSI_RESET ++ "               List all packages available in the registry\n", .{});
    std.debug.print("  " ++ ANSI_GREEN ++ "info" ++ ANSI_RESET ++ " <pkg>          Show detailed package metadata and binary hashes\n\n", .{});
    std.debug.print(ANSI_BOLD ++ "OPTIONS:\n" ++ ANSI_RESET, .{});
    std.debug.print("  --platform <name>  Override target platform (e.g. x86_64-macos, aarch64-macos, x86_64-linux)\n", .{});
    std.debug.print("  --help, -h         Display this help message\n\n", .{});
    std.debug.print(ANSI_BOLD ++ "MAC-SPECIFIC INNOVATION:\n" ++ ANSI_RESET, .{});
    std.debug.print("  On macOS, abv0 bypasses traditional, fragile symlinking and file copying by invoking\n", .{});
    std.debug.print("  APFS " ++ ANSI_YELLOW ++ "clonefile(2)" ++ ANSI_RESET ++ " for 0ms microsecond-level package setups and zero extra disk storage.\n", .{});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const base_allocator = gpa.allocator();

    var arena = std.heap.ArenaAllocator.init(base_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var args_it = try std.process.argsWithAllocator(allocator);
    defer args_it.deinit();

    _ = args_it.next(); // skip exe name

    var command: ?[]const u8 = null;
    var target_pkg: ?[]const u8 = null;
    var override_platform: ?[]const u8 = null;
    var run_args = std.ArrayList([]const u8).init(allocator);

    while (args_it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            return;
        } else if (std.mem.eql(u8, arg, "--platform")) {
            override_platform = args_it.next();
        } else if (command == null) {
            command = arg;
        } else if (target_pkg == null) {
            target_pkg = arg;
        } else {
            try run_args.append(arg);
        }
    }

    if (command == null) {
        printUsage();
        return;
    }

    const platform = override_platform orelse getDefaultPlatform();

    // Start precision timer
    var timer = try std.time.Timer.start();

    // Init Registry & Store
    var reg = registry.Registry.init(allocator);
    defer reg.deinit();

    // In a real deployment, index.json might be installed in /opt/abv0/index.json or ~/.abv0/registry.json
    // For development and testing, we find it relative to current working directory or executable
    reg.loadFromFile("packages/index.json") catch |err| {
        std.debug.print("Error: Failed to load package registry: {}\n", .{err});
        return;
    };

    var pkg_store = try store.Store.init(allocator);
    defer pkg_store.deinit();

    const cmd = command.?;
    if (std.mem.eql(u8, cmd, "list")) {
        std.debug.print(ANSI_CYAN ++ ANSI_BOLD ++ "Available Packages in abv0 Registry:\n\n" ++ ANSI_RESET, .{});
        var it = reg.packages.iterator();
        while (it.next()) |entry| {
            const pkg = entry.value_ptr.*;
            std.debug.print("  " ++ ANSI_GREEN ++ ANSI_BOLD ++ "{s}" ++ ANSI_RESET ++ " v{s}\n    {s}\n\n", .{ pkg.name, pkg.version, pkg.description });
        }
    } else if (std.mem.eql(u8, cmd, "search")) {
        if (target_pkg == null) {
            std.debug.print("Error: Please provide a search query. Example: abv0 search json\n", .{});
            return;
        }
        const query = target_pkg.?;
        std.debug.print(ANSI_CYAN ++ ANSI_BOLD ++ "Search results for '{s}':\n\n" ++ ANSI_RESET, .{query});

        var found = false;
        var it = reg.packages.iterator();
        while (it.next()) |entry| {
            const pkg = entry.value_ptr.*;
            const name_match = indexOfIgnoreCase(pkg.name, query) != null;
            const desc_match = indexOfIgnoreCase(pkg.description, query) != null;

            if (name_match or desc_match) {
                found = true;
                std.debug.print("  " ++ ANSI_GREEN ++ ANSI_BOLD ++ "{s}" ++ ANSI_RESET ++ " v{s}\n    {s}\n\n", .{ pkg.name, pkg.version, pkg.description });
            }
        }
        if (!found) {
            std.debug.print("  No packages found matching your query.\n", .{});
        }
    } else if (std.mem.eql(u8, cmd, "info")) {
        if (target_pkg == null) {
            std.debug.print("Error: Please provide a package name. Example: abv0 info jq\n", .{});
            return;
        }
        const pkg_name = target_pkg.?;
        const pkg = reg.packages.get(pkg_name) orelse {
            std.debug.print("Error: Package '{s}' not found in registry.\n", .{pkg_name});
            return;
        };

        std.debug.print(ANSI_CYAN ++ ANSI_BOLD ++ "Information for {s}:\n" ++ ANSI_RESET, .{pkg.name});
        std.debug.print("  " ++ ANSI_BOLD ++ "Version:" ++ ANSI_RESET ++ "     {s}\n", .{pkg.version});
        std.debug.print("  " ++ ANSI_BOLD ++ "Description:" ++ ANSI_RESET ++ " {s}\n", .{pkg.description});
        std.debug.print("  " ++ ANSI_BOLD ++ "Homepage:" ++ ANSI_RESET ++ "    {s}\n", .{pkg.homepage});
        std.debug.print("  " ++ ANSI_BOLD ++ "License:" ++ ANSI_RESET ++ "     {s}\n", .{pkg.license});
        std.debug.print("  " ++ ANSI_BOLD ++ "Binaries:" ++ ANSI_RESET ++ "    ", .{});
        for (pkg.bin) |b| {
            std.debug.print("{s} ", .{b});
        }
        std.debug.print("\n\n  " ++ ANSI_BOLD ++ "Supported Platforms & SHA256 Hashes:\n" ++ ANSI_RESET, .{});

        var plat_it = pkg.platforms.iterator();
        while (plat_it.next()) |plat_entry| {
            const plat = plat_entry.key_ptr.*;
            const info = plat_entry.value_ptr.*;
            std.debug.print("    " ++ ANSI_YELLOW ++ "{s}" ++ ANSI_RESET ++ "\n", .{plat});
            std.debug.print("      Archive:  {s}\n", .{info.archive_type});
            std.debug.print("      Checksum: {s}\n", .{info.sha256});
            std.debug.print("      URL:      {s}\n\n", .{info.url});
        }
    } else if (std.mem.eql(u8, cmd, "install")) {
        if (target_pkg == null) {
            std.debug.print("Error: Please provide a package name. Example: abv0 install jq\n", .{});
            return;
        }
        const pkg_name = target_pkg.?;
        const pkg = reg.packages.get(pkg_name) orelse {
            std.debug.print("Error: Package '{s}' not found in registry.\n", .{pkg_name});
            return;
        };

        try pkg_store.install(pkg, platform);

        const elapsed_ns = timer.read();
        const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;
        std.debug.print(ANSI_GREEN ++ ANSI_BOLD ++ "\nSuccessfully setup {s} v{s} in {d:.2}ms!\n" ++ ANSI_RESET, .{ pkg.name, pkg.version, elapsed_ms });
        std.debug.print("Note: Make sure to add {s} to your PATH!\n", .{pkg_store.bin_root});
    } else if (std.mem.eql(u8, cmd, "uninstall")) {
        if (target_pkg == null) {
            std.debug.print("Error: Please provide a package name. Example: abv0 uninstall jq\n", .{});
            return;
        }
        const pkg_name = target_pkg.?;
        const pkg = reg.packages.get(pkg_name) orelse {
            std.debug.print("Error: Package '{s}' not found in registry.\n", .{pkg_name});
            return;
        };

        try pkg_store.uninstall(pkg);
        const elapsed_ns = timer.read();
        const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;
        std.debug.print(ANSI_GREEN ++ ANSI_BOLD ++ "\nSuccessfully uninstalled {s} in {d:.2}ms!\n" ++ ANSI_RESET, .{ pkg.name, elapsed_ms });
    } else if (std.mem.eql(u8, cmd, "run")) {
        if (target_pkg == null) {
            std.debug.print("Error: Please provide a package name to run. Example: abv0 run jq -- --version\n", .{});
            return;
        }
        const pkg_name = target_pkg.?;
        const pkg = reg.packages.get(pkg_name) orelse {
            std.debug.print("Error: Package '{s}' not found in registry.\n", .{pkg_name});
            return;
        };

        var actual_run_args = run_args.items;
        if (actual_run_args.len > 0 and std.mem.eql(u8, actual_run_args[0], "--")) {
            actual_run_args = actual_run_args[1..];
        }

        try pkg_store.execute(pkg, platform, actual_run_args);
    } else {
        std.debug.print("Error: Unknown command: {s}\n\n", .{cmd});
        printUsage();
    }
}
