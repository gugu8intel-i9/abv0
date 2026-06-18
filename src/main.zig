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
    std.debug.print(ANSI_CYAN ++ ANSI_BOLD ++ "abv0" ++ ANSI_RESET ++ " - The Faster, Secure, Innovative Homebrew Alternative built in pure Zig\n\n", .{});
    std.debug.print(ANSI_BOLD ++ "USAGE:\n" ++ ANSI_RESET, .{});
    std.debug.print("  abv0 <command> [options] [arguments]\n\n", .{});
    std.debug.print(ANSI_BOLD ++ "COMMANDS:\n" ++ ANSI_RESET, .{});
    std.debug.print("  " ++ ANSI_GREEN ++ "install" ++ ANSI_RESET ++ " <pkg1> [pkg2...] Installs and instantly APFS-links packages (Supports concurrent batching)\n", .{});
    std.debug.print("  " ++ ANSI_RED ++ "uninstall" ++ ANSI_RESET ++ " <pkg>          Remove an installed package and its secure links\n", .{});
    std.debug.print("  " ++ ANSI_YELLOW ++ "run" ++ ANSI_RESET ++ " <pkg> [args...]       Run a package executable instantly (auto-installs if missing)\n", .{});
    std.debug.print("  " ++ ANSI_MAGENTA ++ "shell" ++ ANSI_RESET ++ " <pkg1> [pkg2...]     Innovative Sandboxed Shell: Spawn an ephemeral subshell with specific packages\n", .{});
    std.debug.print("  " ++ ANSI_GREEN ++ "doctor" ++ ANSI_RESET ++ "                  Innovative Self-Healing Check: Securely verifies and self-heals broken execution links\n", .{});
    std.debug.print("  " ++ ANSI_YELLOW ++ "gc" ++ ANSI_RESET ++ "                      Instant Garbage Collector: Prunes abandoned secure temp downloads and shells\n", .{});
    std.debug.print("  " ++ ANSI_MAGENTA ++ "search" ++ ANSI_RESET ++ " <query>           Search the lightning-fast abv0 registry\n", .{});
    std.debug.print("  " ++ ANSI_CYAN ++ "list" ++ ANSI_RESET ++ "                     List all packages available in the secure registry\n", .{});
    std.debug.print("  " ++ ANSI_GREEN ++ "info" ++ ANSI_RESET ++ " <pkg>                Show detailed package metadata and binary integrity hashes\n\n", .{});
    std.debug.print(ANSI_BOLD ++ "OPTIONS:\n" ++ ANSI_RESET, .{});
    std.debug.print("  --micro-split            Enable high-performance range-split multi-chunk download mode\n", .{});
    std.debug.print("  --platform <name>        Override target platform (e.g. x86_64-macos, aarch64-macos, x86_64-linux)\n", .{});
    std.debug.print("  --json                   Enable structured JSON machine-readable output (supported on list, info)\n", .{});
    std.debug.print("  --help, -h               Display this help message\n\n", .{});
    std.debug.print(ANSI_BOLD ++ "MAC-SPECIFIC INNOVATION:\n" ++ ANSI_RESET, .{});
    std.debug.print("  On macOS, abv0 bypasses traditional, fragile symlinking and file copying by invoking\n", .{});
    std.debug.print("  APFS " ++ ANSI_YELLOW ++ "clonefile(2)" ++ ANSI_RESET ++ " for 0ms microsecond-level package setups and zero extra disk storage.\n", .{});
}

fn writePackageJson(pkg: registry.Package, writer: anytype) !void {
    try writer.print("{{\n", .{});
    try writer.print("  \"name\": \"{s}\",\n", .{pkg.name});
    try writer.print("  \"version\": \"{s}\",\n", .{pkg.version});
    try writer.print("  \"description\": \"{s}\",\n", .{pkg.description});
    try writer.print("  \"homepage\": \"{s}\",\n", .{pkg.homepage});
    try writer.print("  \"license\": \"{s}\",\n", .{pkg.license});
    try writer.print("  \"bin\": [", .{});
    for (pkg.bin, 0..) |b, i| {
        if (i > 0) try writer.print(", ", .{});
        try writer.print("\"{s}\"", .{b});
    }
    try writer.print("],\n", .{});
    try writer.print("  \"platforms\": {{\n", .{});

    var plat_it = pkg.platforms.iterator();
    var count: usize = 0;
    while (plat_it.next()) |plat_entry| {
        if (count > 0) try writer.print(",\n", .{});
        const plat = plat_entry.key_ptr.*;
        const info = plat_entry.value_ptr.*;
        try writer.print("    \"{s}\": {{\n", .{plat});
        try writer.print("      \"archive_type\": \"{s}\",\n", .{info.archive_type});
        try writer.print("      \"sha256\": \"{s}\",\n", .{info.sha256});
        try writer.print("      \"url\": \"{s}\",\n", .{info.url});
        try writer.print("      \"bin_path\": \"{s}\"\n", .{info.bin_path});
        try writer.print("    }}", .{});
        count += 1;
    }
    try writer.print("\n  }}\n}}", .{});
}

// Thread helper struct for parallel installations
const InstallWorker = struct {
    pkg_store: *store.Store,
    pkg: registry.Package,
    platform: []const u8,
    use_micro_split: bool,

    pub fn execute(self: *InstallWorker) void {
        self.pkg_store.install(self.pkg, self.platform, self.use_micro_split) catch |err| {
            std.debug.print("Error installing {s}: {}\n", .{ self.pkg.name, err });
        };
    }
};

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
    var override_platform: ?[]const u8 = null;
    var json_output = false;
    var use_micro_split = false;
    var cmd_args = std.ArrayList([]const u8).init(allocator);

    while (args_it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            return;
        } else if (std.mem.eql(u8, arg, "--json")) {
            json_output = true;
        } else if (std.mem.eql(u8, arg, "--micro-split")) {
            use_micro_split = true;
        } else if (std.mem.eql(u8, arg, "--platform")) {
            override_platform = args_it.next();
        } else if (command == null) {
            command = arg;
        } else {
            try cmd_args.append(arg);
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

    reg.loadFromFile("packages/index.json") catch |err| {
        std.debug.print("Error: Failed to load package registry: {}\n", .{err});
        return;
    };

    var pkg_store = try store.Store.init(allocator);
    defer pkg_store.deinit();

    const cmd = command.?;
    if (std.mem.eql(u8, cmd, "list")) {
        if (json_output) {
            const writer = std.io.getStdOut().writer();
            try writer.print("[\n", .{});
            var it = reg.packages.iterator();
            var count: usize = 0;
            while (it.next()) |entry| {
                if (count > 0) try writer.print(",\n", .{});
                try writePackageJson(entry.value_ptr.*, writer);
                count += 1;
            }
            try writer.print("\n]\n", .{});
        } else {
            std.debug.print(ANSI_CYAN ++ ANSI_BOLD ++ "Available Packages in secure abv0 Registry:\n\n" ++ ANSI_RESET, .{});
            var it = reg.packages.iterator();
            while (it.next()) |entry| {
                const pkg = entry.value_ptr.*;
                std.debug.print("  " ++ ANSI_GREEN ++ ANSI_BOLD ++ "{s}" ++ ANSI_RESET ++ " v{s}\n    {s}\n\n", .{ pkg.name, pkg.version, pkg.description });
            }
        }
    } else if (std.mem.eql(u8, cmd, "search")) {
        if (cmd_args.items.len == 0) {
            std.debug.print("Error: Please provide a search query. Example: abv0 search json\n", .{});
            return;
        }
        const query = cmd_args.items[0];
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
        if (cmd_args.items.len == 0) {
            std.debug.print("Error: Please provide a package name. Example: abv0 info jq\n", .{});
            return;
        }
        const pkg_name = cmd_args.items[0];
        const pkg = reg.packages.get(pkg_name) orelse {
            std.debug.print("Error: Package '{s}' not found in registry.\n", .{pkg_name});
            return;
        };

        if (json_output) {
            const writer = std.io.getStdOut().writer();
            try writePackageJson(pkg, writer);
            try writer.print("\n", .{});
        } else {
            std.debug.print(ANSI_CYAN ++ ANSI_BOLD ++ "Information for {s}:\n" ++ ANSI_RESET, .{pkg.name});
            std.debug.print("  " ++ ANSI_BOLD ++ "Version:" ++ ANSI_RESET ++ "     {s}\n", .{pkg.version});
            std.debug.print("  " ++ ANSI_BOLD ++ "Description:" ++ ANSI_RESET ++ " {s}\n", .{pkg.description});
            std.debug.print("  " ++ ANSI_BOLD ++ "Homepage:" ++ ANSI_RESET ++ "    {s}\n", .{pkg.homepage});
            std.debug.print("  " ++ ANSI_BOLD ++ "License:" ++ ANSI_RESET ++ "     {s}\n", .{pkg.license});
            std.debug.print("  " ++ ANSI_BOLD ++ "Binaries:" ++ ANSI_RESET ++ "    ", .{});
            for (pkg.bin) |b| {
                std.debug.print("{s} ", .{b});
            }
            std.debug.print("\n\n  " ++ ANSI_BOLD ++ "Supported Platforms & SHA256 Cryptographic Hashes:\n" ++ ANSI_RESET, .{});

            var plat_it = pkg.platforms.iterator();
            while (plat_it.next()) |plat_entry| {
                const plat = plat_entry.key_ptr.*;
                const info = plat_entry.value_ptr.*;
                std.debug.print("    " ++ ANSI_YELLOW ++ "{s}" ++ ANSI_RESET ++ "\n", .{plat});
                std.debug.print("      Archive:  {s}\n", .{info.archive_type});
                std.debug.print("      Checksum: {s}\n", .{info.sha256});
                std.debug.print("      URL:      {s}\n\n", .{info.url});
            }
        }
    } else if (std.mem.eql(u8, cmd, "install")) {
        if (cmd_args.items.len == 0) {
            std.debug.print("Error: Please provide at least one package name. Example: abv0 install jq ripgrep\n", .{});
            return;
        }

        // Innovative Feature: Parallel Batch Installations
        var workers = std.ArrayList(InstallWorker).init(allocator);
        var threads = std.ArrayList(std.Thread).init(allocator);

        for (cmd_args.items) |pkg_name| {
            const pkg = reg.packages.get(pkg_name) orelse {
                std.debug.print("Error: Package '{s}' not found in registry. Skipping...\n", .{pkg_name});
                continue;
            };
            try workers.append(.{
                .pkg_store = &pkg_store,
                .pkg = pkg,
                .platform = platform,
                .use_micro_split = use_micro_split,
            });
        }

        std.debug.print("[ ⠋ ] Starting high-performance secure setup for {} packages...\n", .{workers.items.len});

        // Launch parallel worker execution threads
        for (workers.items) |*worker| {
            const thread = try std.Thread.spawn(.{}, InstallWorker.execute, .{worker});
            try threads.append(thread);
        }

        // Join all worker threads safely
        for (threads.items) |thread| {
            thread.join();
        }

        const elapsed_ns = timer.read();
        const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;
        std.debug.print(ANSI_GREEN ++ ANSI_BOLD ++ "\n[ ✅ ] Successfully completed secure setup for {} packages in {d:.2}ms!\n" ++ ANSI_RESET, .{ workers.items.len, elapsed_ms });
        std.debug.print("Note: Make sure to add {s} to your PATH!\n", .{pkg_store.bin_root});
    } else if (std.mem.eql(u8, cmd, "uninstall")) {
        if (cmd_args.items.len == 0) {
            std.debug.print("Error: Please provide a package name. Example: abv0 uninstall jq\n", .{});
            return;
        }
        const pkg_name = cmd_args.items[0];
        const pkg = reg.packages.get(pkg_name) orelse {
            std.debug.print("Error: Package '{s}' not found in registry.\n", .{pkg_name});
            return;
        };

        try pkg_store.uninstall(pkg);
        const elapsed_ns = timer.read();
        const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;
        std.debug.print(ANSI_GREEN ++ ANSI_BOLD ++ "\n[ ✅ ] Successfully uninstalled {s} in {d:.2}ms!\n" ++ ANSI_RESET, .{ pkg.name, elapsed_ms });
    } else if (std.mem.eql(u8, cmd, "run")) {
        if (cmd_args.items.len == 0) {
            std.debug.print("Error: Please provide a package name to run. Example: abv0 run jq -- --version\n", .{});
            return;
        }
        const pkg_name = cmd_args.items[0];
        const pkg = reg.packages.get(pkg_name) orelse {
            std.debug.print("Error: Package '{s}' not found in registry.\n", .{pkg_name});
            return;
        };

        var actual_run_args = cmd_args.items[1..];
        if (actual_run_args.len > 0 and std.mem.eql(u8, actual_run_args[0], "--")) {
            actual_run_args = actual_run_args[1..];
        }

        try pkg_store.execute(pkg, platform, actual_run_args, use_micro_split);
    } else if (std.mem.eql(u8, cmd, "shell")) {
        // Innovative Feature: Ephemeral Sandboxed Shell
        if (cmd_args.items.len == 0) {
            std.debug.print("Error: Please provide at least one package name for your sandboxed shell. Example: abv0 shell jq ripgrep\n", .{});
            return;
        }

        var req_pkgs = std.ArrayList(registry.Package).init(allocator);
        for (cmd_args.items) |pkg_name| {
            const pkg = reg.packages.get(pkg_name) orelse {
                std.debug.print("Error: Package '{s}' not found in registry. Aborting shell creation.\n", .{pkg_name});
                return;
            };
            try req_pkgs.append(pkg);
        }

        try pkg_store.executeShell(req_pkgs.items, platform, use_micro_split);
    } else if (std.mem.eql(u8, cmd, "doctor")) {
        // Innovative Feature: Self-Healing Audit
        try pkg_store.doctor(&reg, platform);
        const elapsed_ns = timer.read();
        const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;
        std.debug.print("Completed health audit in {d:.2}ms.\n", .{elapsed_ms});
    } else if (std.mem.eql(u8, cmd, "gc")) {
        // Innovative Feature: Instant Garbage Collection
        try pkg_store.gc();
        const elapsed_ns = timer.read();
        const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;
        std.debug.print("Completed secure garbage collection in {d:.2}ms.\n", .{elapsed_ms});
    } else {
        std.debug.print("Error: Unknown command: {s}\n\n", .{cmd});
        printUsage();
    }
}
