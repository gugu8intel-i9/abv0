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
const sign = @import("sign.zig");

pub const version = "2.0.0";

const registry_url = "https://raw.githubusercontent.com/gugu8intel-i9/abv0/main/packages/index.json";
const registry_sig_url = registry_url ++ ".sig";
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
    /// Load this manifest instead of the installed registry (`--registry`).
    registry_path: ?[]const u8 = null,

    json: bool = false,
    force: bool = false,
    micro_split: bool = false,
    allow_unverified: bool = false,
    allow_unsigned_manifest: bool = false,
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
        } else if (std.mem.eql(u8, arg, "--allow-unsigned-manifest")) {
            args.allow_unsigned_manifest = true;
        } else if (std.mem.eql(u8, arg, "--registry")) {
            i += 1;
            if (i >= argv.len) return error.MissingOptionValue;
            args.registry_path = argv[i];
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
        \\  --registry <path>    Use this manifest (its <path>.sig must verify)
        \\  --allow-unsigned-manifest  Skip manifest signature and replay checks (UNSAFE)
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

// The manifest is trusted only after its detached signature (`<url>.sig`)
// verifies. The signature check comes before anything else reads the content.
//
// Replay protection: the manifest's top-level `updated_at` must not be older
// than the last one this machine accepted, remembered in
// `<registry dir>/last-updated-at`. Without this an attacker could serve an
// old, correctly signed manifest that still lists a vulnerable version.

const max_manifest_bytes = 16 * 1024 * 1024;
const max_sig_bytes = 4 * 1024;
const stored_updated_at_name = "last-updated-at";

const manifest_error = error{
    ManifestSignatureInvalid,
    ManifestReplay,
    MissingUpdatedAt,
    InvalidUpdatedAt,
};

fn warnUnsignedManifest() void {
    term.err(
        "{s}{s}WARNING{s}: --allow-unsigned-manifest: the registry signature is NOT checked and " ++
            "replay protection is off. Whatever the registry serves will be trusted.\n",
        .{ term.bold, term.red, term.reset },
    );
}

/// Pure replay test. Both values must be in the same fixed ISO-8601 UTC form
/// (validUpdatedAt enforces the character set), so lexical order is time order.
/// Equal is accepted: re-fetching the same manifest is not a replay.
fn isReplay(candidate: []const u8, stored: ?[]const u8) bool {
    const s = stored orelse return false;
    return std.mem.order(u8, candidate, s) == .lt;
}

/// Shape check for `updated_at`: `YYYY-...` made only of the characters an
/// ISO-8601 timestamp uses. Rejecting anything else keeps control bytes out of
/// the terminal and out of the stored file, and keeps the comparison meaningful.
fn validUpdatedAt(s: []const u8) bool {
    if (s.len < 10 or s.len > 64) return false;
    for (s[0..4]) |c| if (!std.ascii.isDigit(c)) return false;
    if (s[4] != '-') return false;
    for (s) |c| switch (c) {
        '0'...'9', 'T', 'Z', ':', '.', '+', '-' => {},
        else => return false,
    };
    return true;
}

/// Top-level `updated_at` of a manifest's bytes. The returned slice aliases
/// `a`'s allocation for the parse, so the caller keeps `a` alive while using it.
fn manifestUpdatedAt(a: std.mem.Allocator, bytes: []const u8) manifest_error![]const u8 {
    const root = std.json.parseFromSliceLeaky(std.json.Value, a, bytes, .{}) catch return error.MissingUpdatedAt;
    const obj = switch (root) {
        .object => |o| o,
        else => return error.MissingUpdatedAt,
    };
    const v = obj.get("updated_at") orelse return error.MissingUpdatedAt;
    const s = switch (v) {
        .string => |str| str,
        else => return error.MissingUpdatedAt,
    };
    if (!validUpdatedAt(s)) return error.InvalidUpdatedAt;
    return s;
}

/// Verify a staged manifest against its staged signature. Returns the
/// manifest's `updated_at`, or null when `--allow-unsigned-manifest` skipped
/// every check. Prints a specific diagnostic for each failure.
/// The returned slice is allocated from `a`; scratch memory for the file
/// contents is released before returning.
fn vetManifest(
    a: std.mem.Allocator,
    manifest_path: []const u8,
    sig_path: []const u8,
    allow_unsigned: bool,
) !?[]const u8 {
    if (allow_unsigned) {
        warnUnsignedManifest();
        return null;
    }

    var scratch = std.heap.ArenaAllocator.init(a);
    defer scratch.deinit();
    const s = scratch.allocator();

    const bytes = std.fs.cwd().readFileAlloc(s, manifest_path, max_manifest_bytes) catch |e| {
        term.err("{s}error{s}: cannot read manifest: {s}\n", .{ term.red, term.reset, @errorName(e) });
        return e;
    };
    const sig = std.fs.cwd().readFileAlloc(s, sig_path, max_sig_bytes) catch |e| {
        term.err("{s}error{s}: cannot read manifest signature: {s}\n", .{ term.red, term.reset, @errorName(e) });
        return e;
    };

    sign.verify(bytes, sig) catch |e| {
        term.err(
            "{s}error{s}: manifest signature check failed \xe2\x80\x94 refusing to use it ({s})\n",
            .{ term.red, term.reset, @errorName(e) },
        );
        return error.ManifestSignatureInvalid;
    };

    const updated_at = manifestUpdatedAt(s, bytes) catch |e| {
        term.err("{s}error{s}: signed manifest has no valid updated_at ({s}); refusing it\n", .{ term.red, term.reset, @errorName(e) });
        return e;
    };
    return try a.dupe(u8, updated_at);
}

fn readStoredUpdatedAt(a: std.mem.Allocator, st: *const store.Store) !?[]const u8 {
    const p = try std.fs.path.join(a, &.{ st.registry_root, stored_updated_at_name });
    defer a.free(p);
    const raw = std.fs.cwd().readFileAlloc(a, p, 256) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return e,
    };
    const t = std.mem.trim(u8, raw, " \t\r\n");
    if (!validUpdatedAt(t)) return null;
    return t;
}

/// Refuse a manifest older than the one already accepted.
fn checkReplay(a: std.mem.Allocator, st: *const store.Store, candidate: []const u8) !void {
    const stored = try readStoredUpdatedAt(a, st);
    if (isReplay(candidate, stored)) {
        term.err(
            "{s}error{s}: manifest is older than the one already installed \xe2\x80\x94 possible replay ({s} < {s})\n",
            .{ term.red, term.reset, candidate, stored.? },
        );
        return error.ManifestReplay;
    }
}

/// Record an accepted `updated_at`, atomically. Called after the manifest is
/// in place, so a crash in between leaves the stored value older, never newer.
fn storeUpdatedAt(a: std.mem.Allocator, st: *const store.Store, value: []const u8) !void {
    const p = try std.fs.path.join(a, &.{ st.registry_root, stored_updated_at_name });
    defer a.free(p);
    const tmp = try std.fmt.allocPrint(a, "{s}.{x}.tmp", .{ p, std.crypto.random.int(u32) });
    defer a.free(tmp);
    errdefer std.fs.cwd().deleteFile(tmp) catch {};

    const f = try std.fs.cwd().createFile(tmp, .{ .mode = platform.mode_private });
    {
        defer f.close();
        try f.writeAll(value);
        try f.writeAll("\n");
    }
    try std.fs.cwd().rename(tmp, p);
}

/// Download the manifest and its signature to staging names. Nothing is
/// published here.
fn fetchManifestPair(a: std.mem.Allocator, manifest_tmp: []const u8, sig_tmp: []const u8) !void {
    net.download(a, registry_url, manifest_tmp, .{}) catch |e| {
        term.err("{s}error{s}: could not download registry manifest: {s}\n", .{ term.red, term.reset, @errorName(e) });
        return e;
    };
    net.download(a, registry_sig_url, sig_tmp, .{}) catch |e| {
        term.err("{s}error{s}: could not download manifest signature: {s}\n", .{ term.red, term.reset, @errorName(e) });
        return e;
    };
}

/// Materialise the registry manifest, atomically, if it is not present yet.
///
/// The manifest is always downloaded: a file in the current directory is never
/// used. Download to unique temporary names, verify, validate, and rename into
/// place, so a reader sees either no file or a complete, verified one.
///
/// Returns the registry it parsed while validating, so the caller does not parse
/// the same bytes again. Returns null when a manifest was already in place.
fn ensureRegistryFile(base: std.mem.Allocator, st: *const store.Store, json_path: []const u8, allow_unsigned: bool) !?registry.Registry {
    if (std.fs.cwd().access(json_path, .{})) |_| return null else |_| {}

    // Scratch for paths and the verified manifest. The caller's allocator is
    // long-lived (it is the GPA in `main`), so nothing is left in it.
    var scratch = std.heap.ArenaAllocator.init(base);
    defer scratch.deinit();
    const a = scratch.allocator();

    const tag = std.crypto.random.int(u64);
    const tmp_path = try std.fmt.allocPrint(a, "{s}.{x}.tmp", .{ json_path, tag });
    defer a.free(tmp_path);
    const sig_path = try std.fmt.allocPrint(a, "{s}.sig", .{tmp_path});
    defer a.free(sig_path);
    defer std.fs.cwd().deleteFile(tmp_path) catch {};
    defer std.fs.cwd().deleteFile(sig_path) catch {};

    term.print("fetching registry index...\n", .{});
    try fetchManifestPair(a, tmp_path, sig_path);

    const updated_at = try vetManifest(a, tmp_path, sig_path, allow_unsigned);
    if (updated_at) |u| try checkReplay(a, st, u);

    // Never publish something the parser would reject: a corrupt download must
    // not become the registry every later command reads. The parse is kept
    // (not freed) because it is the registry the caller wants. It lives in
    // `base`, not the scratch arena, so it outlives this function.
    var fresh = try registry.loadFromJsonFile(base, tmp_path, null);
    errdefer fresh.deinit();

    try std.fs.cwd().rename(tmp_path, json_path);
    if (updated_at) |u| try storeUpdatedAt(a, st, u);
    return fresh;
}

fn loadRegistry(a: std.mem.Allocator, st: *const store.Store, allow_unsigned: bool) !registry.Registry {
    const paths = try registryPaths(a, st);
    defer a.free(paths[0]);
    defer a.free(paths[1]);

    const fresh = ensureRegistryFile(a, st, paths[0], allow_unsigned) catch |e| {
        term.err("{s}error{s}: no package registry available: {s}\n", .{ term.red, term.reset, @errorName(e) });
        return e;
    };
    if (fresh) |parsed| {
        // Just downloaded and already parsed: build the index from that
        // registry rather than parsing the same file again.
        var reg = parsed;
        const stamp = try abvindex.Stamp.ofFile(paths[0]);
        abvindex.build(a, &reg, paths[1], stamp) catch {};
        return reg;
    }

    return abvindex.loadCached(a, paths[0], paths[1]) catch |e| {
        term.err("{s}error{s}: could not load registry: {s}\n", .{ term.red, term.reset, @errorName(e) });
        return e;
    };
}

/// `--registry <path>`: an explicit local manifest. It is signature-checked
/// against `<path>.sig` like any other. It does not touch the installed
/// registry or its replay state, and it skips the binary index cache so it
/// cannot be confused with the installed one.
fn loadExplicitRegistry(base: std.mem.Allocator, path: []const u8, allow_unsigned: bool) !registry.Registry {
    var scratch = std.heap.ArenaAllocator.init(base);
    defer scratch.deinit();
    const a = scratch.allocator();

    const sig_path = try std.fmt.allocPrint(a, "{s}.sig", .{path});

    _ = vetManifest(a, path, sig_path, allow_unsigned) catch |e| {
        term.err("{s}error{s}: registry '{s}' was not loaded: {s}\n", .{ term.red, term.reset, path, @errorName(e) });
        return e;
    };
    // The loaded registry outlives the scratch arena, so it uses `base`.
    return registry.loadFromJsonFile(base, path, null) catch |e| {
        term.err("{s}error{s}: could not load registry '{s}': {s}\n", .{ term.red, term.reset, path, @errorName(e) });
        return e;
    };
}

// ---------------------------------------------------------------------------
// Dependency-ordered parallel install
// ---------------------------------------------------------------------------

/// Wave number for each package. `pkgs` must list every dependency before its
/// dependents, as `registry.resolveOrder` returns them. A package's wave is one
/// more than the highest wave of its dependencies that are in `pkgs`, so it runs
/// after everything it depends on, and packages in one wave are independent.
/// Dependencies outside `pkgs` are not waited for.
fn levelize(a: std.mem.Allocator, pkgs: []const registry.Package) ![]usize {
    var index = std.StringHashMap(usize).init(a);
    defer index.deinit();
    for (pkgs, 0..) |pkg, i| try index.put(pkg.name, i);

    const levels = try a.alloc(usize, pkgs.len);
    errdefer a.free(levels);
    @memset(levels, 0);

    for (pkgs, 0..) |pkg, i| {
        for (pkg.deps) |dep| {
            const j = index.get(dep) orelse continue;
            if (j >= i) return error.NotDependencyOrdered;
            levels[i] = @max(levels[i], levels[j] + 1);
        }
    }
    return levels;
}

/// What to install, dependencies first: `names[i]` runs in wave `levels[i]`.
const Plan = struct {
    names: []const []const u8,
    levels: []const usize,
};

/// Plan the installation of `roots` and what they depend on. Names the registry
/// does not know go last, in a wave of their own. If the registry graph cannot
/// be ordered (a cycle, or an unknown dependency), everything goes in one wave.
fn planInstall(a: std.mem.Allocator, reg: *const registry.Registry, roots: []const []const u8) !Plan {
    var known = std.ArrayList([]const u8).init(a);
    defer known.deinit();
    var unknown = std.ArrayList([]const u8).init(a);
    defer unknown.deinit();
    var seen = std.StringHashMap(void).init(a);
    defer seen.deinit();

    for (roots) |root| {
        if (store.Store.resolveRequest(reg, root)) |pkg| {
            if (try seen.fetchPut(pkg.name, {}) == null) try known.append(pkg.name);
        } else {
            if (try seen.fetchPut(root, {}) == null) try unknown.append(root);
        }
    }

    var names = std.ArrayList([]const u8).init(a);
    errdefer names.deinit();
    var levels = std.ArrayList(usize).init(a);
    errdefer levels.deinit();

    if (known.items.len > 0) {
        if (registry.resolveOrder(a, reg, known.items)) |ordered| {
            defer a.free(ordered);
            const wave = try levelize(a, ordered);
            defer a.free(wave);
            for (ordered, wave) |pkg, lv| {
                try names.append(pkg.name);
                try levels.append(lv);
            }
        } else |err| switch (err) {
            error.OutOfMemory => return err,
            else => {
                term.err("{s}warning{s}: no dependency order ({s}); installing without one\n", .{ term.yellow, term.reset, @errorName(err) });
                for (known.items) |name| {
                    try names.append(name);
                    try levels.append(0);
                }
            },
        }
    }

    const after_known: usize = if (levels.items.len == 0) 0 else std.mem.max(usize, levels.items) + 1;
    for (unknown.items) |name| {
        try names.append(name);
        try levels.append(after_known);
    }

    return .{ .names = try names.toOwnedSlice(), .levels = try levels.toOwnedSlice() };
}

fn reportInstallError(name: []const u8, e: anyerror) void {
    if (!store.alreadyDiagnosed(e)) {
        term.err("{s}error{s}: {}: {s}\n", .{ term.red, term.reset, safe(name), @errorName(e) });
    }
}

/// One install pool shared by every wave of one command.
const Batch = struct {
    st: *store.Store,
    reg: *const registry.Registry,
    names: []const []const u8,
    /// Indices into `names` that make up the wave being run.
    slots: []const usize,
    /// `ok[i]` is set once `names[i]` is installed. Each index is written by
    /// exactly one worker, and the main thread reads it after the join.
    ok: []bool,
    platform_name: []const u8,
    opts: store.InstallOptions,
    next: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

    fn worker(self: *Batch) void {
        // Per-worker arena for each job's temporary memory. It is backed by
        // page_allocator, so it never takes the shared thread-safe allocator's
        // lock. Each job's allocations are released by reset when it finishes.
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();

        while (true) {
            const slot = self.next.fetchAdd(1, .monotonic);
            if (slot >= self.slots.len) return;
            const i = self.slots[slot];
            self.ok[i] = self.installOne(arena.allocator(), self.names[i]);
            _ = arena.reset(.retain_capacity);
        }
    }

    fn installOne(self: *Batch, scratch: std.mem.Allocator, name: []const u8) bool {
        if (store.Store.resolveRequest(self.reg, name)) |pkg| {
            self.st.install(pkg, self.platform_name, self.opts) catch |e| {
                reportInstallError(name, e);
                return false;
            };
            return true;
        }
        _ = self.st.installDynamic(scratch, name, self.platform_name, self.opts) catch |e| {
            reportInstallError(name, e);
            return false;
        };
        return true;
    }
};

/// Run one wave on a pool of at most `min(requested or CPUs, wave size, 8)`
/// threads. Returns once every package in the wave has finished.
fn runWave(batch: *Batch, requested_jobs: ?usize) void {
    const cpus = std.Thread.getCpuCount() catch 2;
    // The original spawned one OS thread per package with no bound, so a
    // 50-entry Brewfile created 50 threads all contending for bandwidth.
    const jobs = @max(1, @min(requested_jobs orelse cpus, @min(batch.slots.len, 8)));

    var threads: [8]std.Thread = undefined;
    var spawned: usize = 0;
    // Join whatever started, even if a later spawn failed.
    defer for (threads[0..spawned]) |t| t.join();
    while (spawned < jobs) : (spawned += 1) {
        threads[spawned] = std.Thread.spawn(.{}, Batch.worker, .{batch}) catch break;
    }
    // If no thread could be started, the calling thread does the work itself.
    if (spawned == 0) batch.worker();
}

/// The first dependency of `names[i]` that sits in an earlier wave and did not
/// install. A package is never started while one of its dependencies is missing.
fn failedDependency(
    reg: *const registry.Registry,
    names: []const []const u8,
    levels: []const usize,
    ok: []const bool,
    i: usize,
) ?[]const u8 {
    const pkg = store.Store.resolveRequest(reg, names[i]) orelse return null;
    for (pkg.deps) |dep| {
        for (names, levels, ok) |name, lv, done| {
            if (lv < levels[i] and !done and std.mem.eql(u8, name, dep)) return dep;
        }
    }
    return null;
}

/// Install `names` one wave at a time. Every package in a wave runs on the pool
/// before the next wave starts, so nothing begins before its dependencies have
/// finished. A package whose dependency failed is skipped. Sets `ok[i]` for each
/// name that is installed, and returns how many names were not.
fn installWaves(
    a: std.mem.Allocator,
    st: *store.Store,
    reg: *const registry.Registry,
    names: []const []const u8,
    levels: []const usize,
    ok: []bool,
    platform_name: []const u8,
    opts: store.InstallOptions,
    requested_jobs: ?usize,
) !usize {
    std.debug.assert(levels.len == names.len and ok.len == names.len);
    @memset(ok, false);
    if (names.len == 0) return 0;

    const last_wave = std.mem.max(usize, levels);
    for (0..last_wave + 1) |wave_no| {
        var slots = std.ArrayList(usize).init(a);
        defer slots.deinit();

        for (levels, 0..) |lv, i| {
            if (lv != wave_no) continue;
            if (failedDependency(reg, names, levels, ok, i)) |dep| {
                term.err("{s}skipped{s} {}: dependency {} did not install\n", .{ term.yellow, term.reset, safe(names[i]), safe(dep) });
                continue;
            }
            try slots.append(i);
        }
        if (slots.items.len == 0) continue;

        var batch = Batch{
            .st = st,
            .reg = reg,
            .names = names,
            .slots = slots.items,
            .ok = ok,
            .platform_name = platform_name,
            .opts = opts,
        };
        runWave(&batch, requested_jobs);
    }

    var failures: usize = 0;
    for (ok) |done| {
        if (!done) failures += 1;
    }
    return failures;
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

/// Terminal-safe view of manifest text. Manifest strings come from a remote
/// index and may carry escape sequences that move the cursor, rewrite earlier
/// lines or retitle the window. Every control byte (0x00-0x1f, which includes
/// ESC and tab/newline, and 0x7f) prints as '?'. Use with `{}`. Pads on the
/// right when a width is given, like `{s:<16}`.
const Safe = struct {
    text: []const u8,

    pub fn format(
        self: Safe,
        comptime fmt_str: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt_str;
        for (self.text) |c| try writer.writeByte(if (c < 0x20 or c == 0x7f) '?' else c);
        if (options.width) |w| {
            if (w > self.text.len) try writer.writeByteNTimes(' ', w - self.text.len);
        }
    }
};

fn safe(text: []const u8) Safe {
    return .{ .text = text };
}

/// Every JSON string value goes through the standard encoder, so quotes,
/// backslashes and control bytes can never break out of the document.
fn writeJsonString(w: anytype, s: []const u8) !void {
    try std.json.encodeJsonString(s, .{}, w);
}

fn writePackageJson(w: anytype, pkg: registry.Package) !void {
    try w.writeAll("{\"name\":");
    try writeJsonString(w, pkg.name);
    try w.writeAll(",\"version\":");
    try writeJsonString(w, pkg.version);
    try w.writeAll(",\"description\":");
    try writeJsonString(w, pkg.description);
    try w.writeAll(",\"homepage\":");
    try writeJsonString(w, pkg.homepage);
    try w.writeAll(",\"license\":");
    try writeJsonString(w, pkg.license);
    try w.writeAll(",\"bin\":[");
    for (pkg.bin, 0..) |b, i| {
        if (i > 0) try w.writeAll(",");
        try writeJsonString(w, b);
    }
    try w.writeAll("],\"platforms\":{");
    for (pkg.platforms, 0..) |p, i| {
        if (i > 0) try w.writeAll(",");
        try writeJsonString(w, p.name);
        try w.writeAll(":{\"archive_type\":");
        try writeJsonString(w, p.archive_type);
        try w.writeAll(",\"sha256\":");
        try writeJsonString(w, p.sha256);
        try w.writeAll(",\"bin_path\":");
        try writeJsonString(w, p.bin_path);
        try w.writeAll(",\"url\":");
        try writeJsonString(w, p.url);
        try w.writeAll("}");
    }
    try w.writeAll("}}");
}

fn writeOutdatedJson(w: anytype, name: []const u8, installed: []const u8, available: []const u8) !void {
    try w.writeAll("{\"name\":");
    try writeJsonString(w, name);
    try w.writeAll(",\"installed\":");
    try writeJsonString(w, installed);
    try w.writeAll(",\"available\":");
    try writeJsonString(w, available);
    try w.writeAll("}");
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
        return cmdUpdate(a, &st, args.allow_unsigned_manifest);
    }
    if (std.mem.eql(u8, cmd, "report")) {
        return cmdReport(a, &args, platform_name);
    }

    var reg = if (args.registry_path) |p|
        try loadExplicitRegistry(base, p, args.allow_unsigned_manifest)
    else
        try loadRegistry(base, &st, args.allow_unsigned_manifest);
    defer reg.deinit();

    if (std.mem.eql(u8, cmd, "list")) return cmdList(&reg, args.json);
    if (std.mem.eql(u8, cmd, "search")) return cmdSearch(&reg, args.rest.items);
    if (std.mem.eql(u8, cmd, "info")) return cmdInfo(&reg, args.rest.items, args.json);
    if (std.mem.eql(u8, cmd, "install")) return cmdInstall(a, &st, &reg, &args, platform_name, opts, &timer);
    if (std.mem.eql(u8, cmd, "uninstall")) return cmdUninstall(a, &st, &reg, args.rest.items);
    if (std.mem.eql(u8, cmd, "outdated")) return cmdOutdated(a, &st, &reg, platform_name, args.json);
    if (std.mem.eql(u8, cmd, "upgrade")) return cmdUpgrade(a, &st, &reg, args.rest.items, platform_name, opts, args.jobs);
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
        term.print("{s}{}{s} {s}{}{s}\n    {}\n", .{
            term.bold, safe(pkg.name), term.reset, term.dim, safe(pkg.version), term.reset, safe(pkg.description),
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
            term.print("{s}{}{s} {s}{}{s}\n    {}\n", .{
                term.bold, safe(pkg.name), term.reset, term.dim, safe(pkg.version), term.reset, safe(pkg.description),
            });
        }
    }
    if (found == 0) {
        term.print("no packages match '{}'\n", .{safe(q)});
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

    term.print("{s}{}{s} {}\n", .{ term.bold, safe(pkg.name), term.reset, safe(pkg.version) });
    if (pkg.description.len > 0) term.print("  {}\n", .{safe(pkg.description)});
    if (pkg.homepage.len > 0) term.print("  {}\n", .{safe(pkg.homepage)});
    term.print("  license: {}\n", .{safe(pkg.license)});
    if (pkg.bin.len > 0) {
        term.print("  binaries:", .{});
        for (pkg.bin) |b| term.print(" {}", .{safe(b)});
        term.print("\n", .{});
    }
    if (pkg.deps.len > 0) {
        term.print("  depends on:", .{});
        for (pkg.deps) |d| term.print(" {}", .{safe(d)});
        term.print("\n", .{});
    }
    term.print("\n  platforms:\n", .{});
    for (pkg.platforms) |p| {
        const pinned = p.checksumIsPinned();
        const colour = if (pinned) term.green else term.yellow;
        const state = if (pinned) "verified" else "UNVERIFIED";
        term.print("    {:<16} {:<8} {s}{s}{s}\n", .{ safe(p.name), safe(p.archive_type), colour, state, term.reset });
        term.print("      {}\n", .{safe(p.url)});
        term.print("      sha256 {}\n", .{safe(if (p.sha256.len > 0) p.sha256 else "(none)")});
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

    // Dependencies come along, and always install before what needs them.
    const plan = try planInstall(a, reg, args.rest.items);
    defer a.free(plan.names);
    defer a.free(plan.levels);

    const ok = try a.alloc(bool, plan.names.len);
    defer a.free(ok);
    const failures = try installWaves(a, st, reg, plan.names, plan.levels, ok, platform_name, opts, args.jobs);

    const elapsed = ms(timer.read());
    if (failures == 0) {
        term.print("\n{s}done{s} {d} packages in {d:.2}ms\n", .{ term.green, term.reset, plan.names.len, elapsed });
        return 0;
    }
    term.print("\n{s}{d} of {d} packages failed{s} ({d:.2}ms)\n", .{ term.red, failures, plan.names.len, term.reset, elapsed });
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
            term.err("{s}error{s}: '{}' not found in registry\n", .{ term.red, term.reset, safe(name) });
            failed = 1;
            continue;
        };
        if (try st.uninstall(a, pkg)) {
            term.print("removed {}\n", .{safe(pkg.name)});
        } else {
            term.print("{} was not installed\n", .{safe(pkg.name)});
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
            try writeOutdatedJson(w, e.pkg.name, e.installed, e.pkg.version);
        }
        try w.writeAll("]\n");
        return 0;
    }

    if (list.len == 0) {
        term.print("everything is up to date\n", .{});
        return 0;
    }
    for (list) |e| {
        term.print("{s}{}{s}  {} {s}->{s} {s}{}{s}\n", .{
            term.bold, safe(e.pkg.name), term.reset,
            safe(e.installed), term.dim, term.reset,
            term.green, safe(e.pkg.version), term.reset,
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
    jobs: ?usize,
) !u8 {
    var targets = std.ArrayList(registry.Package).init(a);
    defer targets.deinit();

    if (rest.len == 0) {
        const list = try st.getOutdated(a, reg, platform_name);
        defer a.free(list);
        for (list) |e| try targets.append(e.pkg);
    } else {
        var unknown: usize = 0;
        for (rest) |name| {
            if (store.Store.resolveRequest(reg, name)) |p| {
                try targets.append(p);
            } else {
                unknown += 1;
                term.err("{s}warning{s}: '{}' not in registry\n", .{ term.yellow, term.reset, safe(name) });
            }
        }
        // Asking only for names that do not exist is a failed request.
        if (unknown == rest.len) return 1;
    }

    if (targets.items.len == 0) {
        term.print("nothing to upgrade\n", .{});
        return 0;
    }

    // Only the requested packages are upgraded, so their dependencies are
    // dropped from the plan. What remains keeps dependency order among itself.
    var roots = std.ArrayList([]const u8).init(a);
    defer roots.deinit();
    var wanted = std.StringHashMap(void).init(a);
    defer wanted.deinit();
    for (targets.items) |pkg| {
        try roots.append(pkg.name);
        try wanted.put(pkg.name, {});
    }

    const plan = try planInstall(a, reg, roots.items);
    defer a.free(plan.names);
    defer a.free(plan.levels);
    var names = std.ArrayList([]const u8).init(a);
    defer names.deinit();
    var levels = std.ArrayList(usize).init(a);
    defer levels.deinit();
    for (plan.names, plan.levels) |name, lv| {
        if (!wanted.contains(name)) continue;
        try names.append(name);
        try levels.append(lv);
    }

    // Install the new version first; each version has its own store
    // directory, so the old one stays usable until the new one is in place.
    // Only a successful install lets the older versions go, so a failed
    // download leaves the package exactly as it was.
    const ok = try a.alloc(bool, names.items.len);
    defer a.free(ok);
    const failures = try installWaves(a, st, reg, names.items, levels.items, ok, platform_name, opts, jobs);

    for (names.items, ok) |name, done| {
        if (!done) continue;
        const pkg = store.Store.resolveRequest(reg, name) orelse continue;
        _ = try st.pruneOtherVersions(a, pkg.name, pkg.version, platform_name);
    }
    return if (failures == 0) 0 else 1;
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
        const requested = try store.Store.bundleInstall(a, reg, path);
        if (requested.len == 0) {
            term.print("no installable entries in {s}\n", .{path});
            return 0;
        }
        const plan = try planInstall(a, reg, requested);
        defer a.free(plan.names);
        defer a.free(plan.levels);

        term.print("installing {d} packages from {s}\n\n", .{ plan.names.len, path });
        const ok = try a.alloc(bool, plan.names.len);
        defer a.free(ok);
        // A package that fails is reported and the rest still run, as before.
        _ = try installWaves(a, st, reg, plan.names, plan.levels, ok, platform_name, opts, args.jobs);
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

fn cmdUpdate(a: std.mem.Allocator, st: *store.Store, allow_unsigned: bool) !u8 {
    // The original `update` ran:
    //     sh -c "curl -sL https://.../install.sh | sh"
    // i.e. it downloaded and executed an arbitrary remote script every time.
    // `update` now refreshes the registry index and nothing else.
    const paths = try registryPaths(a, st);
    defer a.free(paths[0]);
    defer a.free(paths[1]);

    const tag = std.crypto.random.int(u32);
    const tmp = try std.fmt.allocPrint(a, "{s}.{x}.tmp", .{ paths[0], tag });
    defer a.free(tmp);
    const tmp_sig = try std.fmt.allocPrint(a, "{s}.sig", .{tmp});
    defer a.free(tmp_sig);
    defer std.fs.cwd().deleteFile(tmp) catch {};
    defer std.fs.cwd().deleteFile(tmp_sig) catch {};

    term.print("fetching {s}\n", .{registry_url});
    fetchManifestPair(a, tmp, tmp_sig) catch return 1;

    // Nothing below may touch the working registry until the signature and
    // the replay check both pass.
    const updated_at = vetManifest(a, tmp, tmp_sig, allow_unsigned) catch return 1;
    if (updated_at) |u| checkReplay(a, st, u) catch return 1;

    // Validate before replacing the working registry. This one parse is also
    // the registry the index is built from, so the file is parsed only once.
    var reg = registry.loadFromJsonFile(a, tmp, null) catch |e| {
        term.err("{s}error{s}: downloaded registry is invalid ({s}); keeping the existing one\n", .{ term.red, term.reset, @errorName(e) });
        return 1;
    };
    defer reg.deinit();
    const n = reg.count();

    try std.fs.cwd().rename(tmp, paths[0]);
    if (updated_at) |u| try storeUpdatedAt(a, st, u);

    const stamp = try abvindex.Stamp.ofFile(paths[0]);
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

test "JSON output escapes quotes, newlines and ESC in every string field" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();

    const nasty = "q\"uote\\ new\nline\x1b[2J";
    try writePackageJson(buf.writer(), .{
        .name = nasty,
        .version = nasty,
        .description = nasty,
        .homepage = nasty,
        .license = nasty,
        .bin = &.{nasty},
        .platforms = &.{.{
            .name = nasty,
            .url = nasty,
            .sha256 = nasty,
            .archive_type = nasty,
            .bin_path = nasty,
        }},
    });

    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, buf.items, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try testing.expectEqualStrings(nasty, obj.get("name").?.string);
    try testing.expectEqualStrings(nasty, obj.get("version").?.string);
    try testing.expectEqualStrings(nasty, obj.get("description").?.string);
    try testing.expectEqualStrings(nasty, obj.get("homepage").?.string);
    try testing.expectEqualStrings(nasty, obj.get("license").?.string);
    try testing.expectEqualStrings(nasty, obj.get("bin").?.array.items[0].string);
    const plat = obj.get("platforms").?.object.get(nasty).?.object;
    try testing.expectEqualStrings(nasty, plat.get("archive_type").?.string);
    try testing.expectEqualStrings(nasty, plat.get("sha256").?.string);
    try testing.expectEqualStrings(nasty, plat.get("bin_path").?.string);
    try testing.expectEqualStrings(nasty, plat.get("url").?.string);
}

test "outdated JSON escapes its fields" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try writeOutdatedJson(buf.writer(), "a\"b", "1\n", "2\x1b");

    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, buf.items, .{});
    defer parsed.deinit();
    try testing.expectEqualStrings("a\"b", parsed.value.object.get("name").?.string);
    try testing.expectEqualStrings("1\n", parsed.value.object.get("installed").?.string);
    try testing.expectEqualStrings("2\x1b", parsed.value.object.get("available").?.string);
}

test "terminal output replaces every control byte with '?'" {
    const out = try std.fmt.allocPrint(testing.allocator, "{}", .{safe("a\x1b[31mb\n\t\x7fc")});
    defer testing.allocator.free(out);
    try testing.expectEqualStrings("a?[31mb???c", out);
    // Printable text, including multi-byte UTF-8, passes through untouched.
    const plain = try std.fmt.allocPrint(testing.allocator, "{}", .{safe("jq 1.7 \xc3\xa9")});
    defer testing.allocator.free(plain);
    try testing.expectEqualStrings("jq 1.7 \xc3\xa9", plain);
}

test "terminal output keeps width padding" {
    const out = try std.fmt.allocPrint(testing.allocator, "[{:<6}]", .{safe("ab\x1b")});
    defer testing.allocator.free(out);
    try testing.expectEqualStrings("[ab?   ]", out);
}

test "replay check refuses older manifests and accepts equal or newer" {
    const old = "2026-06-18T00:00:00Z";
    const new = "2026-06-19T00:00:00Z";
    try testing.expect(isReplay(old, new));
    try testing.expect(!isReplay(new, old));
    try testing.expect(!isReplay(old, old));
    try testing.expect(!isReplay(old, null));
}

test "updated_at must look like an ISO-8601 timestamp" {
    try testing.expect(validUpdatedAt("2026-06-18T00:00:00Z"));
    try testing.expect(validUpdatedAt("2026-06-18T10:20:30.5+02:00"));
    try testing.expect(!validUpdatedAt("2026-06-18\n"));
    try testing.expect(!validUpdatedAt("yesterday"));
    try testing.expect(!validUpdatedAt("2026-06-18T00:00:00Z\x1b[2J"));
}

test "manifestUpdatedAt reads the top-level field only" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const ok = try manifestUpdatedAt(a, "{\"packages\":{\"x\":{\"updated_at\":\"1999-01-01\"}},\"updated_at\":\"2026-06-18T00:00:00Z\"}");
    try testing.expectEqualStrings("2026-06-18T00:00:00Z", ok);
    try testing.expectError(error.MissingUpdatedAt, manifestUpdatedAt(a, "{\"packages\":{}}"));
    try testing.expectError(error.MissingUpdatedAt, manifestUpdatedAt(a, "[1,2]"));
    try testing.expectError(error.InvalidUpdatedAt, manifestUpdatedAt(a, "{\"updated_at\":\"bad\\nvalue\"}"));
}

test "levelize puts a dependency chain in successive waves and independent packages in the first" {
    // a <- b <- c, and d is independent: waves are [a, d], [b], [c].
    const pkgs = [_]registry.Package{
        .{ .name = "a" },
        .{ .name = "b", .deps = &.{"a"} },
        .{ .name = "c", .deps = &.{"b"} },
        .{ .name = "d" },
    };
    const levels = try levelize(testing.allocator, &pkgs);
    defer testing.allocator.free(levels);
    try testing.expectEqualSlices(usize, &.{ 0, 1, 2, 0 }, levels);
}

test "levelize waits for the deepest of several dependencies" {
    // c needs a and b; d needs c; e needs only a.
    const pkgs = [_]registry.Package{
        .{ .name = "a" },
        .{ .name = "b" },
        .{ .name = "c", .deps = &.{ "a", "b" } },
        .{ .name = "d", .deps = &.{"c"} },
        .{ .name = "e", .deps = &.{"a"} },
    };
    const levels = try levelize(testing.allocator, &pkgs);
    defer testing.allocator.free(levels);
    try testing.expectEqualSlices(usize, &.{ 0, 0, 1, 2, 1 }, levels);
}

test "levelize ignores dependencies outside the list" {
    const pkgs = [_]registry.Package{
        .{ .name = "app", .deps = &.{"not-in-this-plan"} },
    };
    const levels = try levelize(testing.allocator, &pkgs);
    defer testing.allocator.free(levels);
    try testing.expectEqualSlices(usize, &.{0}, levels);
}

test "levelize refuses a list where a dependency comes after its dependent" {
    const pkgs = [_]registry.Package{
        .{ .name = "b", .deps = &.{"a"} },
        .{ .name = "a" },
    };
    try testing.expectError(error.NotDependencyOrdered, levelize(testing.allocator, &pkgs));
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
