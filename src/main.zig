//! abv0 command-line interface.

const std = @import("std");
const builtin = @import("builtin");

const registry = @import("registry.zig");
const store = @import("store.zig");
const platform = @import("platform.zig");
const safepath = @import("safepath.zig");
const term = @import("term.zig");
const net = @import("net.zig");
const abvindex = @import("abvindex.zig");
const archive = @import("archive.zig");
const bloom = @import("bloom.zig");
const wal = @import("wal.zig");

pub const version = "2.0.0";

const registry_url = "https://raw.githubusercontent.com/gugu8intel-i9/abv0/main/packages/index.json";
const issues_url = "https://github.com/gugu8intel-i9/abv0/issues/new";

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

const Args = struct {
    command: ?[]const u8 = null,
    rest: std.ArrayList([]const u8),

    platform_name: ?[]const u8 = null,
    file: ?[]const u8 = null,
    jobs: ?usize = null,

    json: bool = false,
    force: bool = false,
    micro_split: bool = false,
    allow_unverified: bool = false,
    no_color: bool = false,
    want_help: bool = false,
    want_version: bool = false,
    report_bug: bool = false,
    report_malware: bool = false,

    fn deinit(self: *Args) void {
        self.rest.deinit();
    }
};

const ParseError = error{ MissingOptionValue, UnknownOption, OutOfMemory };

fn parseArgs(allocator: std.mem.Allocator, argv: []const []const u8) ParseError!Args {
    var args = Args{ .rest = std.ArrayList([]const u8).init(allocator) };
    errdefer args.deinit();

    var i: usize = 0;
    var after_ddash = false;

    while (i < argv.len) : (i += 1) {
        const arg = argv[i];

        if (after_ddash) {
            try args.rest.append(arg);
            continue;
        }
        if (std.mem.eql(u8, arg, "--")) {
            after_ddash = true;
            continue;
        }

        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            args.want_help = true;
        } else if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-V")) {
            args.want_version = true;
        } else if (std.mem.eql(u8, arg, "--json")) {
            args.json = true;
        } else if (std.mem.eql(u8, arg, "--force")) {
            args.force = true;
        } else if (std.mem.eql(u8, arg, "--micro-split")) {
            args.micro_split = true;
        } else if (std.mem.eql(u8, arg, "--allow-unverified")) {
            args.allow_unverified = true;
        } else if (std.mem.eql(u8, arg, "--no-color")) {
            args.no_color = true;
        } else if (std.mem.eql(u8, arg, "--bug")) {
            args.report_bug = true;
        } else if (std.mem.eql(u8, arg, "--malware")) {
            args.report_malware = true;
        } else if (std.mem.eql(u8, arg, "--platform")) {
            // The original called args_it.next() with no null check, so a
            // trailing `--platform` silently produced a null platform.
            i += 1;
            if (i >= argv.len) return error.MissingOptionValue;
            args.platform_name = argv[i];
        } else if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--file")) {
            i += 1;
            if (i >= argv.len) return error.MissingOptionValue;
            args.file = argv[i];
        } else if (std.mem.eql(u8, arg, "-j") or std.mem.eql(u8, arg, "--jobs")) {
            i += 1;
            if (i >= argv.len) return error.MissingOptionValue;
            args.jobs = std.fmt.parseInt(usize, argv[i], 10) catch return error.MissingOptionValue;
        } else if (arg.len > 1 and arg[0] == '-' and !std.mem.eql(u8, arg, "-")) {
            return error.UnknownOption;
        } else if (args.command == null) {
            args.command = arg;
        } else {
            try args.rest.append(arg);
        }
    }
    return args;
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

fn printUsage() void {
    term.print(
        \\{s}{s}abv0{s} {s} - a fast, verifying package manager in Zig
        \\
        \\{s}USAGE{s}
        \\  abv0 <command> [options] [arguments]
        \\
        \\{s}PACKAGES{s}
        \\  install <pkg>...     Install packages (verified, in parallel)
        \\  uninstall <pkg>      Remove a package and its links
        \\  upgrade [pkg]...     Upgrade outdated packages
        \\  outdated             List packages with a newer version available
        \\  list                 List registry packages
        \\  search <query>       Search the registry
        \\  info <pkg>           Show package metadata
        \\
        \\{s}EXECUTION{s}
        \\  run <pkg> [-- args]  Run a package executable
        \\  shell <pkg>...       Ephemeral subshell with only those packages
        \\
        \\{s}MANIFESTS{s}
        \\  bundle [install]     Install from a Brewfile
        \\  bundle dump          Export installed packages to a Brewfile
        \\  update               Refresh the registry index
        \\  sync                 Recompile the local index and SQL export
        \\
        \\{s}MAINTENANCE{s}
        \\  doctor               Diagnose PATH, permissions and links
        \\  fix                  Repair broken links and permissions
        \\  detect <pkg>         Scan an installed package for malware patterns
        \\  benchmark            Measure local store and index performance
        \\  gc                   Remove temporary files and stale sandboxes
        \\  reset                Uninstall everything
        \\  report [--bug]       Open a prefilled GitHub issue
        \\
        \\{s}OPTIONS{s}
        \\  --platform <tag>     Target platform (default: {s})
        \\  -f, --file <path>    Manifest path for bundle commands
        \\  -j, --jobs <n>       Parallel install workers
        \\  --allow-unverified   Permit installs without a verified checksum
        \\  --micro-split        Parallel ranged download for large assets
        \\  --force              Overwrite output files and replace conflicting bin links
        \\  --json               Machine-readable output (list, info, outdated)
        \\  --no-color           Disable colour
        \\  -h, --help           This message
        \\  -V, --version        Version
        \\
    , .{
        term.bold,   term.cyan, term.reset, version,
        term.bold,   term.reset,
        term.bold,   term.reset,
        term.bold,   term.reset,
        term.bold,   term.reset,
        term.bold,   term.reset,
        term.bold,   term.reset,
        platform.defaultPlatformTag(),
    });
}

// ---------------------------------------------------------------------------
// Registry acquisition
// ---------------------------------------------------------------------------

fn registryPaths(a: std.mem.Allocator, st: *const store.Store) ![2][]u8 {
    const json = try std.fs.path.join(a, &.{ st.registry_root, "index.json" });
    const idx = try std.fs.path.join(a, &.{ st.registry_root, "index.abv" });
    return .{ json, idx };
}

/// Seed the user registry from the repository copy (development checkout) or
/// by downloading it.
/// Materialise the registry manifest, atomically.
///
/// This used to write `index.json` in place. Two `abv0` processes started at
/// once on a fresh machine would then both create it, and whichever one read
/// the file while the other was still writing got a truncated document and
/// reported `MalformedManifest`. Downloading to a unique temporary name,
/// validating it, and renaming into place makes the publish step atomic: a
/// reader sees either no file or a complete, parseable one.
fn ensureRegistryFile(a: std.mem.Allocator, json_path: []const u8) !void {
    if (std.fs.cwd().access(json_path, .{})) |_| return else |_| {}

    const tmp_path = try std.fmt.allocPrint(a, "{s}.{x}.tmp", .{ json_path, std.crypto.random.int(u64) });
    defer a.free(tmp_path);
    errdefer std.fs.cwd().deleteFile(tmp_path) catch {};

    if (std.fs.cwd().access("packages/index.json", .{})) |_| {
        try std.fs.cwd().copyFile("packages/index.json", std.fs.cwd(), tmp_path, .{});
    } else |_| {
        term.print("fetching registry index...\n", .{});
        try net.download(a, registry_url, tmp_path, .{});
    }

    // Never publish something the parser would reject: a corrupt download must
    // not become the registry every later command reads.
    var probe = try registry.loadFromJsonFile(a, tmp_path, null);
    probe.deinit();

    try std.fs.cwd().rename(tmp_path, json_path);
}

fn loadRegistry(a: std.mem.Allocator, st: *const store.Store) !registry.Registry {
    const paths = try registryPaths(a, st);
    defer a.free(paths[0]);
    defer a.free(paths[1]);

    ensureRegistryFile(a, paths[0]) catch |e| {
        term.err("{s}error{s}: no package registry available: {s}\n", .{ term.red, term.reset, @errorName(e) });
        return e;
    };

    return abvindex.loadCached(a, paths[0], paths[1]) catch |e| {
        term.err("{s}error{s}: could not load registry: {s}\n", .{ term.red, term.reset, @errorName(e) });
        return e;
    };
}

// ---------------------------------------------------------------------------
// Parallel install
// ---------------------------------------------------------------------------

const Batch = struct {
    st: *store.Store,
    reg: *const registry.Registry,
    names: []const []const u8,
    platform_name: []const u8,
    opts: store.InstallOptions,
    next: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    failures: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

    fn worker(self: *Batch) void {
        while (true) {
            const i = self.next.fetchAdd(1, .monotonic);
            if (i >= self.names.len) return;
            const name = self.names[i];

            var arena = std.heap.ArenaAllocator.init(self.st.allocator);
            defer arena.deinit();

            if (store.Store.resolveRequest(self.reg, name)) |pkg| {
                self.st.install(pkg, self.platform_name, self.opts) catch |e| {
                    if (!store.alreadyDiagnosed(e)) {
                        term.err("{s}error{s}: {s}: {s}\n", .{ term.red, term.reset, name, @errorName(e) });
                    }
                    _ = self.failures.fetchAdd(1, .monotonic);
                };
            } else {
                _ = self.st.installDynamic(arena.allocator(), name, self.platform_name, self.opts) catch |e| {
                    if (!store.alreadyDiagnosed(e)) {
                        term.err("{s}error{s}: {s}: {s}\n", .{ term.red, term.reset, name, @errorName(e) });
                    }
                    _ = self.failures.fetchAdd(1, .monotonic);
                };
            }
        }
    }
};

fn runBatch(a: std.mem.Allocator, batch: *Batch, requested_jobs: ?usize) !usize {
    const cpus = std.Thread.getCpuCount() catch 2;
    // The original spawned one OS thread per package with no bound, so a
    // 50-entry Brewfile created 50 threads all contending for bandwidth.
    const jobs = @max(1, @min(requested_jobs orelse cpus, @min(batch.names.len, 8)));

    const threads = try a.alloc(std.Thread, jobs);
    defer a.free(threads);

    for (threads) |*t| t.* = try std.Thread.spawn(.{}, Batch.worker, .{batch});
    for (threads) |t| t.join();

    return batch.failures.load(.monotonic);
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

fn writePackageJson(w: anytype, pkg: registry.Package) !void {
    try w.writeAll("{");
    try w.print("\"name\":\"{s}\",", .{pkg.name});
    try w.print("\"version\":\"{s}\",", .{pkg.version});
    try w.writeAll("\"description\":");
    try std.json.encodeJsonString(pkg.description, .{}, w);
    try w.writeAll(",\"homepage\":");
    try std.json.encodeJsonString(pkg.homepage, .{}, w);
    try w.print(",\"license\":\"{s}\",\"bin\":[", .{pkg.license});
    for (pkg.bin, 0..) |b, i| {
        if (i > 0) try w.writeAll(",");
        try w.print("\"{s}\"", .{b});
    }
    try w.writeAll("],\"platforms\":{");
    for (pkg.platforms, 0..) |p, i| {
        if (i > 0) try w.writeAll(",");
        try w.print("\"{s}\":{{\"archive_type\":\"{s}\",\"sha256\":\"{s}\",\"bin_path\":\"{s}\",\"url\":", .{
            p.name, p.archive_type, p.sha256, p.bin_path,
        });
        try std.json.encodeJsonString(p.url, .{}, w);
        try w.writeAll("}");
    }
    try w.writeAll("}}");
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main() u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    // Install workers allocate concurrently. The original handed them a plain
    // ArenaAllocator, which is not thread-safe.
    var thread_safe = std.heap.ThreadSafeAllocator{ .child_allocator = gpa.allocator() };
    const base = thread_safe.allocator();

    var arena_state = std.heap.ArenaAllocator.init(base);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const code = run(base, a) catch |e| {
        // Only fall back to the bare error name when nothing more useful has
        // already been printed, so failures are reported exactly once.
        if (!term.anythingReported()) {
            term.err("{s}error{s}: {s}\n", .{ term.red, term.reset, @errorName(e) });
        }
        term.flush();
        return 1;
    };
    term.flush();
    return code;
}

fn run(base: std.mem.Allocator, a: std.mem.Allocator) !u8 {
    const argv = try std.process.argsAlloc(a);
    const rest_argv = if (argv.len > 1) argv[1..] else &[_][]const u8{};

    var args = parseArgs(a, rest_argv) catch |e| {
        term.init(false);
        switch (e) {
            error.MissingOptionValue => term.err("error: option requires a value\n", .{}),
            error.UnknownOption => term.err("error: unknown option\n", .{}),
            else => return e,
        }
        return 2;
    };
    defer args.deinit();

    term.init(args.no_color);

    if (args.want_version) {
        term.print("abv0 {s} ({s})\n", .{ version, platform.defaultPlatformTag() });
        return 0;
    }
    // Help must not touch the filesystem at all.
    if (args.want_help or args.command == null) {
        printUsage();
        return 0;
    }

    const cmd = args.command.?;
    if (std.mem.eql(u8, cmd, "help")) {
        printUsage();
        return 0;
    }
    // `abv0 version` is as natural as `abv0 --version`; accept both.
    if (std.mem.eql(u8, cmd, "version")) {
        term.print("abv0 {s} ({s})\n", .{ version, platform.defaultPlatformTag() });
        return 0;
    }

    const platform_name = args.platform_name orelse platform.defaultPlatformTag();
    if (!platform.isKnownPlatformTag(platform_name)) {
        term.err("{s}error{s}: unknown platform '{s}'\n", .{ term.red, term.reset, platform_name });
        return 2;
    }

    const opts = store.InstallOptions{
        .micro_split = args.micro_split,
        .allow_unverified = args.allow_unverified,
        .force = args.force,
    };

    var timer = try std.time.Timer.start();

    var st = try store.Store.init(base);
    defer st.deinit();

    // ---- commands that need no registry ----
    if (std.mem.eql(u8, cmd, "gc")) {
        const n = try st.gc(a);
        term.print("reclaimed {d} items in {d:.2}ms\n", .{ n, ms(timer.read()) });
        return 0;
    }
    if (std.mem.eql(u8, cmd, "update")) {
        return cmdUpdate(a, &st);
    }
    if (std.mem.eql(u8, cmd, "report")) {
        return cmdReport(a, &args, platform_name);
    }

    var reg = try loadRegistry(base, &st);
    defer reg.deinit();

    if (std.mem.eql(u8, cmd, "list")) return cmdList(&reg, args.json);
    if (std.mem.eql(u8, cmd, "search")) return cmdSearch(&reg, args.rest.items);
    if (std.mem.eql(u8, cmd, "info")) return cmdInfo(&reg, args.rest.items, args.json);
    if (std.mem.eql(u8, cmd, "install")) return cmdInstall(a, &st, &reg, &args, platform_name, opts, &timer);
    if (std.mem.eql(u8, cmd, "uninstall")) return cmdUninstall(a, &st, &reg, args.rest.items);
    if (std.mem.eql(u8, cmd, "outdated")) return cmdOutdated(a, &st, &reg, platform_name, args.json);
    if (std.mem.eql(u8, cmd, "upgrade")) return cmdUpgrade(a, &st, &reg, args.rest.items, platform_name, opts);
    if (std.mem.eql(u8, cmd, "run")) return cmdRun(a, &st, &reg, args.rest.items, platform_name, opts);
    if (std.mem.eql(u8, cmd, "shell")) return cmdShell(a, &st, &reg, args.rest.items, platform_name, opts);
    if (std.mem.eql(u8, cmd, "bundle")) return cmdBundle(a, &st, &reg, &args, platform_name, opts);
    if (std.mem.eql(u8, cmd, "doctor")) {
        const h = try st.doctor(a, &reg, platform_name);
        term.print("\n{d} warnings, {d} broken links ({d:.2}ms)\n", .{ h.warnings, h.broken_links, ms(timer.read()) });
        return if (h.warnings + h.broken_links == 0) 0 else 1;
    }
    if (std.mem.eql(u8, cmd, "fix")) {
        const n = try st.fix(a, &reg, platform_name);
        term.print("repaired {d} packages in {d:.2}ms\n", .{ n, ms(timer.read()) });
        return 0;
    }
    if (std.mem.eql(u8, cmd, "detect")) return cmdDetect(a, &st, &reg, args.rest.items, platform_name);
    if (std.mem.eql(u8, cmd, "reset")) {
        const n = try st.resetAll(a, &reg, platform_name);
        term.print("uninstalled {d} packages; store reset\n", .{n});
        return 0;
    }
    if (std.mem.eql(u8, cmd, "sync") or std.mem.eql(u8, cmd, "hybrid-sync")) {
        try st.exportRegistry(a, &reg);
        term.print("\nsynchronised in {d:.2}ms\n", .{ms(timer.read())});
        return 0;
    }
    if (std.mem.eql(u8, cmd, "benchmark")) return cmdBenchmark(a, &st, &reg, platform_name);

    term.err("{s}error{s}: unknown command '{s}' (try `abv0 help`)\n", .{ term.red, term.reset, cmd });
    return 2;
}

fn ms(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / 1_000_000.0;
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

fn cmdList(reg: *const registry.Registry, json: bool) !u8 {
    if (json) {
        const w = term.writer();
        try w.writeAll("[");
        for (reg.packages, 0..) |pkg, i| {
            if (i > 0) try w.writeAll(",");
            try writePackageJson(w, pkg);
        }
        try w.writeAll("]\n");
        return 0;
    }
    for (reg.packages) |pkg| {
        term.print("{s}{s}{s} {s}{s}{s}\n    {s}\n", .{
            term.bold, pkg.name, term.reset, term.dim, pkg.version, term.reset, pkg.description,
        });
    }
    term.print("\n{d} packages\n", .{reg.count()});
    return 0;
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    return std.ascii.indexOfIgnoreCase(haystack, needle) != null;
}

fn cmdSearch(reg: *const registry.Registry, rest: []const []const u8) !u8 {
    if (rest.len == 0) {
        term.err("usage: abv0 search <query>\n", .{});
        return 2;
    }
    const q = rest[0];
    var found: usize = 0;
    for (reg.packages) |pkg| {
        if (containsIgnoreCase(pkg.name, q) or containsIgnoreCase(pkg.description, q)) {
            found += 1;
            term.print("{s}{s}{s} {s}{s}{s}\n    {s}\n", .{
                term.bold, pkg.name, term.reset, term.dim, pkg.version, term.reset, pkg.description,
            });
        }
    }
    if (found == 0) {
        term.print("no packages match '{s}'\n", .{q});
        return 1;
    }
    return 0;
}

fn cmdInfo(reg: *const registry.Registry, rest: []const []const u8, json: bool) !u8 {
    if (rest.len == 0) {
        term.err("usage: abv0 info <pkg>\n", .{});
        return 2;
    }
    const pkg = store.Store.resolveRequest(reg, rest[0]) orelse {
        term.err("{s}error{s}: '{s}' not found\n", .{ term.red, term.reset, rest[0] });
        return 1;
    };
    if (json) {
        const w = term.writer();
        try writePackageJson(w, pkg);
        try w.writeAll("\n");
        return 0;
    }

    term.print("{s}{s}{s} {s}\n", .{ term.bold, pkg.name, term.reset, pkg.version });
    if (pkg.description.len > 0) term.print("  {s}\n", .{pkg.description});
    if (pkg.homepage.len > 0) term.print("  {s}\n", .{pkg.homepage});
    term.print("  license: {s}\n", .{pkg.license});
    if (pkg.bin.len > 0) {
        term.print("  binaries:", .{});
        for (pkg.bin) |b| term.print(" {s}", .{b});
        term.print("\n", .{});
    }
    if (pkg.deps.len > 0) {
        term.print("  depends on:", .{});
        for (pkg.deps) |d| term.print(" {s}", .{d});
        term.print("\n", .{});
    }
    term.print("\n  platforms:\n", .{});
    for (pkg.platforms) |p| {
        const pinned = p.checksumIsPinned();
        const colour = if (pinned) term.green else term.yellow;
        const state = if (pinned) "verified" else "UNVERIFIED";
        term.print("    {s:<16} {s:<8} {s}{s}{s}\n", .{ p.name, p.archive_type, colour, state, term.reset });
        term.print("      {s}\n", .{p.url});
        term.print("      sha256 {s}\n", .{if (p.sha256.len > 0) p.sha256 else "(none)"});
    }
    return 0;
}

fn cmdInstall(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: *const registry.Registry,
    args: *Args,
    platform_name: []const u8,
    opts: store.InstallOptions,
    timer: *std.time.Timer,
) !u8 {
    if (args.rest.items.len == 0) {
        term.err("usage: abv0 install <pkg>...\n", .{});
        return 2;
    }

    // Pull in declared dependencies where the registry knows about them.
    var names = std.ArrayList([]const u8).init(a);
    defer names.deinit();

    if (registry.resolveOrder(a, reg, args.rest.items)) |ordered| {
        defer a.free(ordered);
        for (ordered) |p| try names.append(p.name);
    } else |_| {
        try names.appendSlice(args.rest.items);
    }

    var batch = Batch{
        .st = st,
        .reg = reg,
        .names = names.items,
        .platform_name = platform_name,
        .opts = opts,
    };
    const failures = try runBatch(a, &batch, args.jobs);

    const elapsed = ms(timer.read());
    if (failures == 0) {
        term.print("\n{s}done{s} {d} packages in {d:.2}ms\n", .{ term.green, term.reset, names.items.len, elapsed });
        return 0;
    }
    term.print("\n{s}{d} of {d} packages failed{s} ({d:.2}ms)\n", .{ term.red, failures, names.items.len, term.reset, elapsed });
    return 1;
}

fn cmdUninstall(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: *const registry.Registry,
    rest: []const []const u8,
) !u8 {
    if (rest.len == 0) {
        term.err("usage: abv0 uninstall <pkg>\n", .{});
        return 2;
    }
    var failed: u8 = 0;
    for (rest) |name| {
        const pkg = store.Store.resolveRequest(reg, name) orelse {
            term.err("{s}error{s}: '{s}' not found in registry\n", .{ term.red, term.reset, name });
            failed = 1;
            continue;
        };
        if (try st.uninstall(a, pkg)) {
            term.print("removed {s}\n", .{pkg.name});
        } else {
            term.print("{s} was not installed\n", .{pkg.name});
        }
    }
    return failed;
}

fn cmdOutdated(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: *const registry.Registry,
    platform_name: []const u8,
    json: bool,
) !u8 {
    const list = try st.getOutdated(a, reg, platform_name);
    defer a.free(list);

    if (json) {
        const w = term.writer();
        try w.writeAll("[");
        for (list, 0..) |e, i| {
            if (i > 0) try w.writeAll(",");
            try w.print("{{\"name\":\"{s}\",\"installed\":\"{s}\",\"available\":\"{s}\"}}", .{
                e.pkg.name, e.installed, e.pkg.version,
            });
        }
        try w.writeAll("]\n");
        return 0;
    }

    if (list.len == 0) {
        term.print("everything is up to date\n", .{});
        return 0;
    }
    for (list) |e| {
        term.print("{s}{s}{s}  {s} {s}->{s} {s}{s}{s}\n", .{
            term.bold, e.pkg.name,  term.reset,
            e.installed, term.dim,  term.reset,
            term.green, e.pkg.version, term.reset,
        });
    }
    term.print("\n{d} outdated; run `abv0 upgrade`\n", .{list.len});
    return 0;
}

fn cmdUpgrade(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: *const registry.Registry,
    rest: []const []const u8,
    platform_name: []const u8,
    opts: store.InstallOptions,
) !u8 {
    var targets = std.ArrayList(registry.Package).init(a);
    defer targets.deinit();

    if (rest.len == 0) {
        const list = try st.getOutdated(a, reg, platform_name);
        defer a.free(list);
        for (list) |e| try targets.append(e.pkg);
    } else {
        for (rest) |name| {
            if (store.Store.resolveRequest(reg, name)) |p| {
                try targets.append(p);
            } else {
                term.err("{s}warning{s}: '{s}' not in registry\n", .{ term.yellow, term.reset, name });
            }
        }
    }

    if (targets.items.len == 0) {
        term.print("nothing to upgrade\n", .{});
        return 0;
    }

    var failures: u8 = 0;
    for (targets.items) |pkg| {
        // Remove the old tree so the new version is genuinely fetched.
        _ = st.uninstall(a, pkg) catch false;
        st.install(pkg, platform_name, opts) catch |e| {
            term.err("{s}error{s}: {s}: {s}\n", .{ term.red, term.reset, pkg.name, @errorName(e) });
            failures = 1;
        };
    }
    return failures;
}

fn cmdRun(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: *const registry.Registry,
    rest: []const []const u8,
    platform_name: []const u8,
    opts: store.InstallOptions,
) !u8 {
    if (rest.len == 0) {
        term.err("usage: abv0 run <pkg> [-- args...]\n", .{});
        return 2;
    }
    return st.runPackage(a, reg, rest[0], rest[1..], platform_name, opts);
}

fn cmdShell(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: *const registry.Registry,
    rest: []const []const u8,
    platform_name: []const u8,
    opts: store.InstallOptions,
) !u8 {
    if (rest.len == 0) {
        term.err("usage: abv0 shell <pkg>...\n", .{});
        return 2;
    }
    return st.spawnShell(a, reg, rest, platform_name, opts);
}

fn cmdBundle(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: *const registry.Registry,
    args: *Args,
    platform_name: []const u8,
    opts: store.InstallOptions,
) !u8 {
    const sub = if (args.rest.items.len > 0) args.rest.items[0] else "install";
    const path = args.file orelse "Brewfile";

    if (std.mem.eql(u8, sub, "install")) {
        try st.bundleInstall(a, reg, path, platform_name, opts);
        return 0;
    }
    if (std.mem.eql(u8, sub, "dump")) {
        try st.bundleDump(a, reg, path, args.force, platform_name);
        return 0;
    }
    term.err("usage: abv0 bundle [install|dump] [-f <path>]\n", .{});
    return 2;
}

fn cmdDetect(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: *const registry.Registry,
    rest: []const []const u8,
    platform_name: []const u8,
) !u8 {
    if (rest.len == 0) {
        term.err("usage: abv0 detect <pkg>\n", .{});
        return 2;
    }
    const pkg = store.Store.resolveRequest(reg, rest[0]) orelse {
        term.err("{s}error{s}: '{s}' not found\n", .{ term.red, term.reset, rest[0] });
        return 1;
    };
    if (!st.isInstalled(pkg, platform_name)) {
        term.err("{s}error{s}: '{s}' is not installed\n", .{ term.red, term.reset, pkg.name });
        return 1;
    }

    const bin = try st.resolveBinary(a, pkg, platform_name);
    defer a.free(bin);

    var threat = try store.Store.scanFile(a, bin);
    defer threat.deinit();

    term.print("scanned {s}\n\n", .{bin});
    if (threat.score == 0) {
        term.print("{s}clean{s}  threat score 0/100\n", .{ term.green, term.reset });
        return 0;
    }
    term.print("{s}suspicious{s}  threat score {d}/100\n", .{ term.red, term.reset, threat.score });
    for (threat.reasons.items) |r| term.print("  - {s}\n", .{r});
    return 1;
}

fn cmdUpdate(a: std.mem.Allocator, st: *store.Store) !u8 {
    // The original `update` ran:
    //     sh -c "curl -sL https://.../install.sh | sh"
    // i.e. it downloaded and executed an arbitrary remote script every time.
    // `update` now refreshes the registry index and nothing else.
    const paths = try registryPaths(a, st);
    defer a.free(paths[0]);
    defer a.free(paths[1]);

    const tmp = try std.fmt.allocPrint(a, "{s}.{x}.tmp", .{ paths[0], std.crypto.random.int(u32) });
    defer a.free(tmp);

    term.print("fetching {s}\n", .{registry_url});
    net.download(a, registry_url, tmp, .{}) catch |e| {
        term.err("{s}error{s}: update failed: {s}\n", .{ term.red, term.reset, @errorName(e) });
        return 1;
    };
    defer std.fs.cwd().deleteFile(tmp) catch {};

    // Validate before replacing the working registry.
    var probe = registry.loadFromJsonFile(a, tmp, null) catch |e| {
        term.err("{s}error{s}: downloaded registry is invalid ({s}); keeping the existing one\n", .{ term.red, term.reset, @errorName(e) });
        return 1;
    };
    const n = probe.count();
    probe.deinit();

    try std.fs.cwd().rename(tmp, paths[0]);

    const stamp = try abvindex.Stamp.ofFile(paths[0]);
    var reg = try registry.loadFromJsonFile(a, paths[0], null);
    defer reg.deinit();
    abvindex.build(a, &reg, paths[1], stamp) catch {};

    term.print("{s}updated{s} {d} packages\n", .{ term.green, term.reset, n });
    return 0;
}

fn cmdReport(a: std.mem.Allocator, args: *Args, platform_name: []const u8) !u8 {
    const subject = if (args.rest.items.len > 0) args.rest.items[0] else "unspecified";

    const title = if (args.report_malware)
        try std.fmt.allocPrint(a, "[security] suspicious behaviour in '{s}'", .{subject})
    else if (args.report_bug)
        try std.fmt.allocPrint(a, "[bug] {s}", .{subject})
    else
        try std.fmt.allocPrint(a, "[report] {s}", .{subject});
    defer a.free(title);

    const body = try std.fmt.allocPrint(a,
        \\### abv0 report
        \\
        \\- abv0 version: {s}
        \\- platform: {s}
        \\- subject: {s}
        \\
        \\#### What happened
        \\
        \\
    , .{ version, platform_name, subject });
    defer a.free(body);

    const enc_title = try net.urlEncode(a, title);
    defer a.free(enc_title);
    const enc_body = try net.urlEncode(a, body);
    defer a.free(enc_body);

    const url = try std.fmt.allocPrint(a, "{s}?title={s}&body={s}", .{ issues_url, enc_title, enc_body });
    defer a.free(url);

    term.print("opening:\n{s}\n", .{url});
    term.flush();
    platform.openBrowser(a, url);
    return 0;
}

fn cmdBenchmark(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: *const registry.Registry,
    platform_name: []const u8,
) !u8 {
    _ = platform_name;
    term.print("{s}abv0 benchmark{s}  ({d} packages)\n\n", .{ term.bold, term.reset, reg.count() });

    var t = try std.time.Timer.start();

    // 1. Registry lookups.
    const lookups: usize = 100_000;
    var hits: usize = 0;
    var i: usize = 0;
    while (i < lookups) : (i += 1) {
        const name = reg.packages[i % reg.packages.len].name;
        if (reg.get(name) != null) hits += 1;
    }
    const lookup_ns = t.lap();

    // 2. Binary index build + mmap load.
    const paths = try registryPaths(a, st);
    defer a.free(paths[0]);
    defer a.free(paths[1]);

    const stamp = abvindex.Stamp.ofFile(paths[0]) catch abvindex.Stamp{ .size = 0, .mtime_ns = 0 };
    try abvindex.build(a, reg, paths[1], stamp);
    const build_ns = t.lap();

    var loaded = try abvindex.load(a, paths[1], stamp);
    loaded.deinit();
    const load_ns = t.lap();

    // 3. Link throughput.
    const scratch = try std.fs.path.join(a, &.{ st.store_root, "bench.tmp" });
    defer a.free(scratch);
    try platform.makeSecureDir(scratch);
    defer std.fs.cwd().deleteTree(scratch) catch {};

    const src = try std.fs.path.join(a, &.{ scratch, "src" });
    defer a.free(src);
    {
        const f = try std.fs.cwd().createFile(src, .{ .mode = platform.mode_exec });
        defer f.close();
        try f.writeAll("benchmark payload\n");
    }

    const links: usize = 500;
    var kind: platform.LinkKind = .copied;
    i = 0;
    _ = t.lap();
    while (i < links) : (i += 1) {
        const dst = try std.fmt.allocPrint(a, "{s}/dst.{d}", .{ scratch, i });
        defer a.free(dst);
        kind = try platform.fastLink(src, dst);
    }
    const link_ns = t.lap();

    // 4. Hashing throughput.
    const blob = try std.fs.path.join(a, &.{ scratch, "blob" });
    defer a.free(blob);
    const blob_size = 8 * 1024 * 1024;
    {
        const f = try std.fs.cwd().createFile(blob, .{});
        defer f.close();
        const chunk = try a.alloc(u8, 64 * 1024);
        defer a.free(chunk);
        @memset(chunk, 0xAB);
        var written: usize = 0;
        while (written < blob_size) : (written += chunk.len) try f.writeAll(chunk);
    }
    _ = t.lap();
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    {
        const f = try std.fs.cwd().openFile(blob, .{});
        defer f.close();
        var buf: [64 * 1024]u8 = undefined;
        while (true) {
            const n = try f.read(&buf);
            if (n == 0) break;
            hasher.update(buf[0..n]);
        }
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    const hash_ns = t.lap();

    term.print("  registry lookup     {d:>10} ops  {d:>8.3} ms  {d:>9.1} ns/op\n", .{ lookups, ms(lookup_ns), @as(f64, @floatFromInt(lookup_ns)) / @as(f64, @floatFromInt(lookups)) });
    term.print("  index build         {d:>10} pkgs {d:>8.3} ms\n", .{ reg.count(), ms(build_ns) });
    term.print("  index mmap load     {d:>10} pkgs {d:>8.3} ms\n", .{ reg.count(), ms(load_ns) });
    term.print("  fastLink ({s:<10}) {d:>8} ops  {d:>8.3} ms  {d:>9.1} us/op\n", .{ kind.label(), links, ms(link_ns), ms(link_ns) * 1000.0 / @as(f64, @floatFromInt(links)) });
    term.print("  sha256              {d:>10} MiB  {d:>8.3} ms  {d:>9.1} MiB/s\n", .{ blob_size / (1024 * 1024), ms(hash_ns), @as(f64, @floatFromInt(blob_size)) / (1024.0 * 1024.0) / (ms(hash_ns) / 1000.0) });

    return 0;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parseArgs handles commands, flags and separators" {
    var a = try parseArgs(testing.allocator, &.{ "install", "jq", "ripgrep", "--platform", "x86_64-linux" });
    defer a.deinit();
    try testing.expectEqualStrings("install", a.command.?);
    try testing.expectEqual(@as(usize, 2), a.rest.items.len);
    try testing.expectEqualStrings("x86_64-linux", a.platform_name.?);
}

test "parseArgs errors on a missing option value instead of silently continuing" {
    try testing.expectError(error.MissingOptionValue, parseArgs(testing.allocator, &.{ "install", "jq", "--platform" }));
    try testing.expectError(error.MissingOptionValue, parseArgs(testing.allocator, &.{ "bundle", "-f" }));
}

test "parseArgs rejects unknown options" {
    try testing.expectError(error.UnknownOption, parseArgs(testing.allocator, &.{ "install", "--definitely-not-a-flag" }));
}

test "parseArgs passes everything after -- through untouched" {
    var a = try parseArgs(testing.allocator, &.{ "run", "jq", "--", "-n", "1+1" });
    defer a.deinit();
    try testing.expectEqualStrings("run", a.command.?);
    try testing.expectEqual(@as(usize, 3), a.rest.items.len);
    try testing.expectEqualStrings("jq", a.rest.items[0]);
    // `-n` must reach jq, not be parsed by abv0.
    try testing.expectEqualStrings("-n", a.rest.items[1]);
}

test "parseArgs recognises help and version early" {
    var h = try parseArgs(testing.allocator, &.{"--help"});
    defer h.deinit();
    try testing.expect(h.want_help);

    var v = try parseArgs(testing.allocator, &.{"-V"});
    defer v.deinit();
    try testing.expect(v.want_version);
}

test "writePackageJson escapes strings" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();

    try writePackageJson(buf.writer(), .{
        .name = "x",
        .version = "1.0",
        .description = "has \"quotes\" and \\ backslash",
        .bin = &.{"x"},
    });

    // Must remain parseable.
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, buf.items, .{});
    defer parsed.deinit();
    try testing.expectEqualStrings("x", parsed.value.object.get("name").?.string);
    try testing.expectEqualStrings("has \"quotes\" and \\ backslash", parsed.value.object.get("description").?.string);
}

comptime {
    // Ensure every module's tests are discovered by `zig build test`.
    _ = @import("safepath.zig");
    _ = @import("term.zig");
    _ = @import("platform.zig");
    _ = @import("bloom.zig");
    _ = @import("wal.zig");
    _ = @import("archive.zig");
    _ = @import("registry.zig");
    _ = @import("abvindex.zig");
    _ = @import("net.zig");
    _ = @import("store.zig");
}
