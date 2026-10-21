//! Package model and manifest loading.
//!
//! Changes from the original:
//!   * No `.?` unwrapping. Every field access on parsed JSON is checked, so a
//!     truncated or hostile `index.json` produces an error instead of a panic.
//!     This matters because the file is fetched over the network on first run.
//!   * Manifest values that become filesystem paths are validated at load time.
//!   * Packages are stored sorted in a flat slice and found by binary search,
//!     which is faster than a StringHashMap at this size, gives deterministic
//!     output ordering, and is the layout the binary index needs.
//!   * `platforms` is a small sorted slice rather than a hash map.
//!   * Strings are allocated exactly once (previously the JSON DOM was kept
//!     *and* every string was duped out of it).

const std = @import("std");
const safepath = @import("safepath.zig");
const platform_mod = @import("platform.zig");
const bloom = @import("bloom.zig");
const net = @import("net.zig");

pub const sha256_skip = "SKIP";

/// Executable names abv0 must never expose on PATH. Installing a package that
/// ships one of these would shadow the shell, the privilege tools, or abv0
/// itself the next time a user runs them.
const reserved_bin_names = [_][]const u8{
    "abv0", "sudo",  "su",     "doas",   "ssh",        "sh",   "bash", "zsh", "fish",
    "env",  "login", "passwd", "pkexec", "powershell", "pwsh", "cmd",
};

/// True when `name` is one of the reserved executable names. The comparison
/// ignores case, and a trailing `.exe` is ignored too, so `SUDO.exe` and
/// `abv0.exe` are reserved as well.
pub fn isReservedBinName(name: []const u8) bool {
    var base = name;
    if (base.len > 4 and std.ascii.eqlIgnoreCase(base[base.len - 4 ..], ".exe")) {
        base = base[0 .. base.len - 4];
    }
    for (reserved_bin_names) |reserved| {
        if (std.ascii.eqlIgnoreCase(base, reserved)) return true;
    }
    return false;
}

/// A manifest URL is only usable over https. Prevents a manifest pointing at
/// file:// or a plaintext http mirror that an on-path attacker can rewrite.
/// Shares the downloader's check, so a URL is never admitted here and then
/// refused at download time.
pub const isSafeUrl = net.isSafeUrl;

/// A single executable name: a valid id that is not reserved.
pub fn isUsableBinName(name: []const u8) bool {
    return safepath.isValidId(name) and !isReservedBinName(name);
}

/// Checks applied to one platform entry. Shared by the JSON loader and the
/// binary index loader so both admit exactly the same platforms.
pub fn isUsablePlatform(name: []const u8, url: []const u8, bin_path: []const u8) bool {
    if (!safepath.isValidId(name)) return false;
    if (!isSafeUrl(url)) return false;
    if (bin_path.len != 0 and !safepath.isSafeRelPath(bin_path)) return false;
    return true;
}

/// Package-level checks shared by the JSON loader and the binary index loader.
pub fn isUsablePackage(pkg: Package) bool {
    if (!safepath.isValidId(pkg.name)) return false;
    if (!safepath.isValidId(pkg.version)) return false;
    for (pkg.bin) |b| {
        if (!isUsableBinName(b)) return false;
    }
    for (pkg.app_bundles) |a| {
        if (!safepath.isSafeRelPath(a)) return false;
    }
    for (pkg.deps) |d| {
        if (!safepath.isValidId(d)) return false;
    }
    return true;
}

pub const PlatformInfo = struct {
    name: []const u8 = "",
    url: []const u8 = "",
    sha256: []const u8 = "",
    archive_type: []const u8 = "",
    bin_path: []const u8 = "",

    /// A manifest may legitimately decline to pin a hash for a rolling asset,
    /// but it has to say so explicitly.
    pub fn checksumIsPinned(self: PlatformInfo) bool {
        return !std.mem.eql(u8, self.sha256, sha256_skip) and self.sha256.len == 64;
    }
};

pub const Package = struct {
    name: []const u8 = "",
    version: []const u8 = "",
    description: []const u8 = "",
    homepage: []const u8 = "",
    license: []const u8 = "",
    bin: []const []const u8 = &.{},
    app_bundles: []const []const u8 = &.{},
    deps: []const []const u8 = &.{},
    platforms: []const PlatformInfo = &.{},

    pub fn platform(self: Package, name: []const u8) ?PlatformInfo {
        for (self.platforms) |p| {
            if (std.mem.eql(u8, p.name, name)) return p;
        }
        return null;
    }

    /// The executable name to expose on PATH. `abv0 run ripgrep` must resolve
    /// to `rg`; the original looked for a binary literally named `ripgrep`.
    pub fn primaryBin(self: Package) ?[]const u8 {
        if (self.bin.len == 0) return null;
        return self.bin[0];
    }

    pub fn providesBin(self: Package, name: []const u8) bool {
        for (self.bin) |b| {
            if (std.mem.eql(u8, b, name)) return true;
        }
        return false;
    }
};

fn lessThanByName(_: void, a: Package, b: Package) bool {
    return std.mem.order(u8, a.name, b.name) == .lt;
}

fn orderByName(_: void, key: []const u8, mid: Package) std.math.Order {
    return std.mem.order(u8, key, mid.name);
}

pub const Registry = struct {
    allocator: std.mem.Allocator,
    /// Backing storage when the registry came from JSON.
    arena: ?*std.heap.ArenaAllocator = null,
    /// Backing storage when the registry came from the binary index.
    mapped: ?platform_mod.MappedFile = null,
    /// Sorted by name.
    packages: []Package = &.{},
    /// How many manifest entries were rejected during load.
    rejected: usize = 0,

    pub fn deinit(self: *Registry) void {
        if (self.arena) |a| {
            a.deinit();
            self.allocator.destroy(a);
            self.arena = null;
        }
        if (self.mapped) |*m| {
            m.deinit();
            self.mapped = null;
        }
        self.packages = &.{};
    }

    pub fn count(self: *const Registry) usize {
        return self.packages.len;
    }

    pub fn get(self: *const Registry, name: []const u8) ?Package {
        const idx = std.sort.binarySearch(Package, name, self.packages, {}, orderByName) orelse return null;
        return self.packages[idx];
    }

    /// Find whichever package ships an executable called `bin_name`.
    pub fn findByBin(self: *const Registry, bin_name: []const u8) ?Package {
        for (self.packages) |p| {
            if (p.providesBin(bin_name)) return p;
        }
        return null;
    }

    /// Build an empty registry that owns an arena, for tests and for the
    /// index loader.
    pub fn initArena(allocator: std.mem.Allocator) !Registry {
        const arena = try allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        return .{ .allocator = allocator, .arena = arena };
    }
};

// ---------------------------------------------------------------------------
// JSON loading
// ---------------------------------------------------------------------------

fn objGet(obj: std.json.ObjectMap, key: []const u8) ?std.json.Value {
    return obj.get(key);
}

fn getString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

fn getStringOr(obj: std.json.ObjectMap, key: []const u8, default: []const u8) []const u8 {
    return getString(obj, key) orelse default;
}

fn getStringArray(
    allocator: std.mem.Allocator,
    obj: std.json.ObjectMap,
    key: []const u8,
) ![]const []const u8 {
    const v = obj.get(key) orelse return &.{};
    const arr = switch (v) {
        .array => |a| a,
        else => return &.{},
    };
    var list = try std.ArrayList([]const u8).initCapacity(allocator, arr.items.len);
    for (arr.items) |item| {
        switch (item) {
            .string => |s| try list.append(s),
            else => {},
        }
    }
    return list.toOwnedSlice();
}

pub const LoadDiagnostics = struct {
    rejected_packages: usize = 0,
    first_error: ?[]const u8 = null,
};

/// Parse an `index.json`. Invalid individual packages are skipped rather than
/// failing the whole load, so one bad manifest entry cannot brick the CLI.
pub fn loadFromJsonFile(
    allocator: std.mem.Allocator,
    path: []const u8,
    diags: ?*LoadDiagnostics,
) !Registry {
    var reg = try Registry.initArena(allocator);
    errdefer reg.deinit();
    const arena = reg.arena.?.allocator();

    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const content = try file.readToEndAlloc(arena, 16 * 1024 * 1024);
    if (content.len == 0) return error.EmptyManifest;

    // Leaky parse into our arena: string values alias `content`, which the
    // arena also owns, so nothing is copied twice.
    const root_value = std.json.parseFromSliceLeaky(std.json.Value, arena, content, .{}) catch {
        return error.MalformedManifest;
    };

    const root = switch (root_value) {
        .object => |o| o,
        else => return error.MalformedManifest,
    };

    const packages_value = root.get("packages") orelse return error.MissingPackagesKey;
    const packages_obj = switch (packages_value) {
        .object => |o| o,
        else => return error.MalformedManifest,
    };

    var list = try std.ArrayList(Package).initCapacity(arena, packages_obj.count());
    var rejected: usize = 0;

    // Names already admitted. See admitUnique.
    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();

    var it = packages_obj.iterator();
    while (it.next()) |entry| {
        const key = entry.key_ptr.*;
        const pkg_obj = switch (entry.value_ptr.*) {
            .object => |o| o,
            else => {
                rejected += 1;
                continue;
            },
        };

        const pkg = parsePackage(arena, key, pkg_obj) catch {
            rejected += 1;
            if (diags) |d| {
                if (d.first_error == null) d.first_error = key;
            }
            continue;
        };

        const admitted = try admitUnique(&seen, pkg);
        if (!admitted) {
            rejected += 1;
            if (diags) |d| {
                if (d.first_error == null) d.first_error = key;
            }
            continue;
        }
        try list.append(pkg);
    }

    const pkgs = try list.toOwnedSlice();
    std.mem.sort(Package, pkgs, {}, lessThanByName);

    reg.packages = pkgs;
    reg.rejected = rejected;
    if (diags) |d| d.rejected_packages = rejected;
    return reg;
}

/// Records `pkg.name` in `seen`. Returns false, leaving `seen` unchanged, when
/// the name was already admitted. The first package to claim a name wins, so
/// a later duplicate can never shadow it.
pub fn admitUnique(seen: *std.StringHashMap(void), pkg: Package) !bool {
    if (seen.contains(pkg.name)) return false;
    try seen.put(pkg.name, {});
    return true;
}

fn parsePackage(
    arena: std.mem.Allocator,
    key: []const u8,
    obj: std.json.ObjectMap,
) !Package {
    const name = getStringOr(obj, "name", key);
    if (!safepath.isValidId(name)) return error.InvalidPackageName;
    // The key is what `index.json` says the package is called. A body that
    // claims a different name is either a mistake or an attempt to impersonate.
    if (!std.mem.eql(u8, name, key)) return error.NameKeyMismatch;

    const version = getStringOr(obj, "version", "0.0.0");
    if (!safepath.isValidId(version)) return error.InvalidPackageVersion;

    const platforms_value = obj.get("platforms") orelse return error.MissingPlatforms;
    const platforms_obj = switch (platforms_value) {
        .object => |o| o,
        else => return error.MalformedPlatforms,
    };

    var plats = try std.ArrayList(PlatformInfo).initCapacity(arena, platforms_obj.count());
    var pit = platforms_obj.iterator();
    while (pit.next()) |pentry| {
        const plat_name = pentry.key_ptr.*;
        if (!safepath.isValidId(plat_name)) continue;

        const pobj = switch (pentry.value_ptr.*) {
            .object => |o| o,
            else => continue,
        };

        const url = getStringOr(pobj, "url", "");
        // Only https; see isSafeUrl. Unusable platforms are skipped, not fatal.
        const bin_path = getStringOr(pobj, "bin_path", "");
        // THE v1.5.0 FIX THAT WAS NEVER ACTUALLY APPLIED.
        if (!isUsablePlatform(plat_name, url, bin_path)) continue;

        const archive_type = getStringOr(pobj, "archive_type", "raw");
        const sha256 = getStringOr(pobj, "sha256", "");

        try plats.append(.{
            .name = plat_name,
            .url = url,
            .sha256 = sha256,
            .archive_type = archive_type,
            .bin_path = bin_path,
        });
    }
    if (plats.items.len == 0) return error.NoUsablePlatforms;

    const bin = try getStringArray(arena, obj, "bin");
    for (bin) |b| {
        // Reserved names (shells, privilege tools, abv0 itself) are refused
        // here so they can never reach PATH through a manifest.
        if (!isUsableBinName(b)) return error.InvalidBinaryName;
    }

    const app_bundles = try getStringArray(arena, obj, "app_bundles");
    for (app_bundles) |a| {
        if (!safepath.isSafeRelPath(a)) return error.InvalidAppBundleName;
    }

    const deps = try getStringArray(arena, obj, "deps");
    for (deps) |d| {
        if (!safepath.isValidId(d)) return error.InvalidDependencyName;
    }

    return .{
        .name = name,
        .version = version,
        .description = getStringOr(obj, "description", ""),
        .homepage = getStringOr(obj, "homepage", ""),
        .license = getStringOr(obj, "license", ""),
        .bin = bin,
        .app_bundles = app_bundles,
        .deps = deps,
        .platforms = try plats.toOwnedSlice(),
    };
}

// ---------------------------------------------------------------------------
// Dependency resolution
// ---------------------------------------------------------------------------

/// Deepest dependency chain `resolveOrder` will follow. Real trees are a few
/// levels deep; the limit exists so a hostile manifest cannot exhaust the stack.
pub const max_dependency_depth = 64;

pub const ResolveError = error{
    DependencyCycle,
    DependencyTooDeep,
    UnknownDependency,
    OutOfMemory,
};

/// Topologically order `roots` and their transitive `deps` so dependencies are
/// installed first.
///
/// The Bloom filter is a cheap negative cache on the recursion stack: most
/// `mightContain` calls answer "definitely not on the stack" without touching
/// the exact set. Because Bloom filters admit false positives, a hit is always
/// confirmed against `on_stack` before a cycle is declared.
pub fn resolveOrder(
    allocator: std.mem.Allocator,
    reg: *const Registry,
    roots: []const []const u8,
) ResolveError![]Package {
    var ordered = std.ArrayList(Package).init(allocator);
    errdefer ordered.deinit();

    var done = std.StringHashMap(void).init(allocator);
    defer done.deinit();
    var on_stack = std.StringHashMap(void).init(allocator);
    defer on_stack.deinit();

    var filter = bloom.Default.init();

    for (roots) |root| {
        try visit(reg, root, 0, &ordered, &done, &on_stack, &filter);
    }
    return ordered.toOwnedSlice();
}

fn visit(
    reg: *const Registry,
    name: []const u8,
    depth: usize,
    ordered: *std.ArrayList(Package),
    done: *std.StringHashMap(void),
    on_stack: *std.StringHashMap(void),
    filter: *bloom.Default,
) ResolveError!void {
    if (done.contains(name)) return;

    // Each level of recursion costs a stack frame. A chain longer than the
    // limit is refused instead of being followed to exhaustion.
    if (depth >= max_dependency_depth) return error.DependencyTooDeep;

    // Fast path: the filter says this name was never pushed, so it cannot be
    // on the stack and we skip the hash lookup entirely.
    if (filter.mightContain(name) and on_stack.contains(name)) {
        return error.DependencyCycle;
    }

    const pkg = reg.get(name) orelse return error.UnknownDependency;

    try on_stack.put(name, {});
    filter.insert(name);

    for (pkg.deps) |dep| {
        try visit(reg, dep, depth + 1, ordered, done, on_stack, filter);
    }

    _ = on_stack.remove(name);
    try done.put(name, {});
    try ordered.append(pkg);
}

// ---------------------------------------------------------------------------
// Version comparison (for `outdated`)
// ---------------------------------------------------------------------------

/// Compare dotted numeric versions, falling back to lexicographic for
/// non-numeric components. `1.10.0` correctly sorts above `1.9.0`.
pub fn compareVersions(a: []const u8, b: []const u8) std.math.Order {
    var ita = std.mem.splitAny(u8, a, ".-+");
    var itb = std.mem.splitAny(u8, b, ".-+");

    while (true) {
        const ca = ita.next();
        const cb = itb.next();
        if (ca == null and cb == null) return .eq;
        const sa = ca orelse return .lt;
        const sb = cb orelse return .gt;

        const na = std.fmt.parseInt(u64, sa, 10) catch null;
        const nb = std.fmt.parseInt(u64, sb, 10) catch null;

        if (na != null and nb != null) {
            if (na.? < nb.?) return .lt;
            if (na.? > nb.?) return .gt;
        } else {
            const ord = std.mem.order(u8, sa, sb);
            if (ord != .eq) return ord;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn writeTempJson(tmp: *std.testing.TmpDir, name: []const u8, body: []const u8) ![]u8 {
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    const p = try std.fs.path.join(testing.allocator, &.{ root, name });
    const f = try std.fs.cwd().createFile(p, .{});
    defer f.close();
    try f.writeAll(body);
    return p;
}

test "loads a well-formed manifest and sorts packages" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try writeTempJson(&tmp, "index.json",
        \\{"packages":{
        \\ "zig":{"name":"zig","version":"0.13.0","description":"lang","homepage":"","license":"MIT",
        \\        "bin":["zig"],"platforms":{"x86_64-linux":{"url":"https://example.com/z.tar.xz",
        \\        "sha256":"SKIP","archive_type":"tar.xz","bin_path":"zig"}}},
        \\ "jq":{"name":"jq","version":"1.7.1","description":"json","homepage":"","license":"MIT",
        \\       "bin":["jq"],"platforms":{"x86_64-linux":{"url":"https://example.com/jq",
        \\       "sha256":"SKIP","archive_type":"raw","bin_path":"jq"}}}
        \\}}
    );
    defer testing.allocator.free(p);

    var reg = try loadFromJsonFile(testing.allocator, p, null);
    defer reg.deinit();

    try testing.expectEqual(@as(usize, 2), reg.count());
    // Sorted, so output ordering is deterministic (it used to be hash order).
    try testing.expectEqualStrings("jq", reg.packages[0].name);
    try testing.expectEqualStrings("zig", reg.packages[1].name);

    const jq = reg.get("jq").?;
    try testing.expectEqualStrings("1.7.1", jq.version);
    try testing.expect(reg.get("nonexistent") == null);
    try testing.expectEqualStrings("jq", jq.platform("x86_64-linux").?.bin_path);
}

test "malformed manifests error instead of panicking" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // Previously every one of these hit a `.?` unwrap and aborted the process.
    const cases = [_][]const u8{
        "{}",
        "{\"packages\": 42}",
        "not json at all",
        "{\"packages\":{\"a\":{\"name\":\"a\"}}}",
        "",
    };
    for (cases, 0..) |body, i| {
        var buf: [32]u8 = undefined;
        const fname = try std.fmt.bufPrint(&buf, "bad{d}.json", .{i});
        const p = try writeTempJson(&tmp, fname, body);
        defer testing.allocator.free(p);

        if (loadFromJsonFile(testing.allocator, p, null)) |*r| {
            var reg = r.*;
            defer reg.deinit();
            // Structurally valid but semantically empty is acceptable...
            try testing.expectEqual(@as(usize, 0), reg.count());
        } else |_| {
            // ...and an outright error is acceptable. A panic is not.
        }
    }
}

test "hostile manifest fields are rejected at load time" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try writeTempJson(&tmp, "evil.json",
        \\{"packages":{
        \\ "traversal":{"name":"traversal","version":"1.0","bin":["x"],
        \\   "platforms":{"x86_64-linux":{"url":"https://e.com/x","sha256":"SKIP",
        \\   "archive_type":"raw","bin_path":"../../../../.ssh/authorized_keys"}}},
        \\ "plainhttp":{"name":"plainhttp","version":"1.0","bin":["y"],
        \\   "platforms":{"x86_64-linux":{"url":"http://e.com/y","sha256":"SKIP",
        \\   "archive_type":"raw","bin_path":"y"}}},
        \\ "fileurl":{"name":"fileurl","version":"1.0","bin":["z"],
        \\   "platforms":{"x86_64-linux":{"url":"file:///etc/passwd","sha256":"SKIP",
        \\   "archive_type":"raw","bin_path":"z"}}},
        \\ "good":{"name":"good","version":"1.0","bin":["g"],
        \\   "platforms":{"x86_64-linux":{"url":"https://e.com/g","sha256":"SKIP",
        \\   "archive_type":"raw","bin_path":"g"}}}
        \\}}
    );
    defer testing.allocator.free(p);

    var reg = try loadFromJsonFile(testing.allocator, p, null);
    defer reg.deinit();

    try testing.expect(reg.get("traversal") == null);
    try testing.expect(reg.get("plainhttp") == null);
    try testing.expect(reg.get("fileurl") == null);
    try testing.expect(reg.get("good") != null);
    try testing.expectEqual(@as(usize, 3), reg.rejected);
}

test "checksumIsPinned distinguishes real hashes from SKIP" {
    const pinned = PlatformInfo{ .sha256 = "a" ** 64 };
    const skipped = PlatformInfo{ .sha256 = "SKIP" };
    const junk = PlatformInfo{ .sha256 = "abc" };
    try testing.expect(pinned.checksumIsPinned());
    try testing.expect(!skipped.checksumIsPinned());
    try testing.expect(!junk.checksumIsPinned());
}

test "compareVersions orders numerically, not lexicographically" {
    try testing.expectEqual(std.math.Order.lt, compareVersions("1.9.0", "1.10.0"));
    try testing.expectEqual(std.math.Order.gt, compareVersions("2.0.0", "1.99.99"));
    try testing.expectEqual(std.math.Order.eq, compareVersions("1.7.1", "1.7.1"));
    try testing.expectEqual(std.math.Order.lt, compareVersions("1.7", "1.7.1"));
    try testing.expectEqual(std.math.Order.gt, compareVersions("14.1.0", "9.9.9"));
}

fn testRegistry(arena: std.mem.Allocator, specs: []const struct { []const u8, []const []const u8 }) !Registry {
    var reg = Registry{ .allocator = testing.allocator };
    var list = std.ArrayList(Package).init(arena);
    for (specs) |s| {
        try list.append(.{ .name = s[0], .version = "1.0", .deps = s[1] });
    }
    const pkgs = try list.toOwnedSlice();
    std.mem.sort(Package, pkgs, {}, lessThanByName);
    reg.packages = pkgs;
    return reg;
}

test "resolveOrder installs dependencies before dependents" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var reg = try testRegistry(arena, &.{
        .{ "app", &.{ "lib", "tool" } },
        .{ "lib", &.{"base"} },
        .{ "tool", &.{"base"} },
        .{ "base", &.{} },
    });

    const order = try resolveOrder(testing.allocator, &reg, &.{"app"});
    defer testing.allocator.free(order);

    try testing.expectEqual(@as(usize, 4), order.len);
    try testing.expectEqualStrings("base", order[0].name);
    try testing.expectEqualStrings("app", order[3].name);

    // base appears exactly once despite two dependents.
    var base_count: usize = 0;
    for (order) |p| {
        if (std.mem.eql(u8, p.name, "base")) base_count += 1;
    }
    try testing.expectEqual(@as(usize, 1), base_count);
}

test "resolveOrder detects a dependency cycle instead of recursing forever" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var reg = try testRegistry(arena, &.{
        .{ "a", &.{"b"} },
        .{ "b", &.{"c"} },
        .{ "c", &.{"a"} },
    });

    try testing.expectError(error.DependencyCycle, resolveOrder(testing.allocator, &reg, &.{"a"}));
}

test "resolveOrder reports an unknown dependency" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var reg = try testRegistry(arena, &.{.{ "a", &.{"ghost"} }});
    try testing.expectError(error.UnknownDependency, resolveOrder(testing.allocator, &reg, &.{"a"}));
}

test "findByBin maps an executable back to its package" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var list = std.ArrayList(Package).init(arena);
    try list.append(.{ .name = "ripgrep", .version = "14.1.0", .bin = &.{"rg"} });
    const pkgs = try list.toOwnedSlice();
    var reg = Registry{ .allocator = testing.allocator, .packages = pkgs };

    try testing.expectEqualStrings("ripgrep", reg.findByBin("rg").?.name);
    try testing.expectEqualStrings("rg", reg.get("ripgrep").?.primaryBin().?);
}

test "a package whose name duplicates an admitted name is rejected" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A parsed JSON object cannot hold one key twice, so the admitted-name
    // set is what stops two entries claiming the same name.
    var seen = std.StringHashMap(void).init(testing.allocator);
    defer seen.deinit();

    const first = Package{ .name = "jq", .version = "1.7.1" };
    const second = Package{ .name = try arena.dupe(u8, "jq"), .version = "9.9.9" };
    try testing.expect(try admitUnique(&seen, first));
    try testing.expect(!(try admitUnique(&seen, second)));
    try testing.expect(try admitUnique(&seen, .{ .name = "rg", .version = "14.1.0" }));
}

test "a name that differs from its JSON key is rejected" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try writeTempJson(&tmp, "mismatch.json",
        \\{"packages":{
        \\ "jq":{"name":"ripgrep","version":"1.0","bin":["rg"],
        \\   "platforms":{"x86_64-linux":{"url":"https://e.com/x","sha256":"SKIP","archive_type":"raw","bin_path":"x"}}},
        \\ "good":{"name":"good","version":"1.0","bin":["g"],
        \\   "platforms":{"x86_64-linux":{"url":"https://e.com/g","sha256":"SKIP","archive_type":"raw","bin_path":"g"}}}
        \\}}
    );
    defer testing.allocator.free(p);

    var reg = try loadFromJsonFile(testing.allocator, p, null);
    defer reg.deinit();

    try testing.expect(reg.get("ripgrep") == null);
    try testing.expect(reg.get("jq") == null);
    try testing.expect(reg.get("good") != null);
    try testing.expectEqual(@as(usize, 1), reg.rejected);
}

test "reserved binary names are refused case-insensitively, with or without .exe" {
    try testing.expect(isReservedBinName("abv0"));
    try testing.expect(isReservedBinName("abv0.exe"));
    try testing.expect(isReservedBinName("SUDO.exe"));
    try testing.expect(isReservedBinName("Bash"));
    try testing.expect(isReservedBinName("pwsh.EXE"));
    try testing.expect(!isReservedBinName("rg"));
    try testing.expect(!isReservedBinName("sudoers"));
    try testing.expect(!isReservedBinName("sudo.exe.bak"));
    try testing.expect(!isReservedBinName(".exe"));
}

test "packages shipping a reserved binary name are rejected" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try writeTempJson(&tmp, "reserved.json",
        \\{"packages":{
        \\ "evil1":{"name":"evil1","version":"1.0","bin":["abv0"],
        \\   "platforms":{"x86_64-linux":{"url":"https://e.com/a","sha256":"SKIP","archive_type":"raw","bin_path":"a"}}},
        \\ "evil2":{"name":"evil2","version":"1.0","bin":["rg","SUDO.exe"],
        \\   "platforms":{"x86_64-linux":{"url":"https://e.com/b","sha256":"SKIP","archive_type":"raw","bin_path":"b"}}},
        \\ "ripgrep":{"name":"ripgrep","version":"14.1.0","bin":["rg"],
        \\   "platforms":{"x86_64-linux":{"url":"https://e.com/c","sha256":"SKIP","archive_type":"raw","bin_path":"c"}}}
        \\}}
    );
    defer testing.allocator.free(p);

    var reg = try loadFromJsonFile(testing.allocator, p, null);
    defer reg.deinit();

    try testing.expect(reg.get("evil1") == null);
    try testing.expect(reg.get("evil2") == null);
    try testing.expect(reg.findByBin("abv0") == null);
    try testing.expect(reg.get("ripgrep") != null);
    try testing.expectEqual(@as(usize, 2), reg.rejected);
}

/// Builds `count` packages p000 -> p001 -> ... where each depends on the next.
fn chainRegistry(arena: std.mem.Allocator, count: usize) !Registry {
    var list = std.ArrayList(Package).init(arena);
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const name = try std.fmt.allocPrint(arena, "p{d:0>3}", .{i});
        const deps: []const []const u8 = if (i + 1 < count)
            try arena.dupe([]const u8, &.{try std.fmt.allocPrint(arena, "p{d:0>3}", .{i + 1})})
        else
            &.{};
        try list.append(.{ .name = name, .version = "1.0", .deps = deps });
    }
    const pkgs = try list.toOwnedSlice();
    std.mem.sort(Package, pkgs, {}, lessThanByName);
    return Registry{ .allocator = testing.allocator, .packages = pkgs };
}

test "a dependency chain deeper than the limit errors instead of crashing" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var reg = try chainRegistry(arena_state.allocator(), 100);
    try testing.expectError(error.DependencyTooDeep, resolveOrder(testing.allocator, &reg, &.{"p000"}));
}

test "resolveOrder still accepts a chain just inside the depth limit" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const count = max_dependency_depth;
    var reg = try chainRegistry(arena_state.allocator(), count);
    const order = try resolveOrder(testing.allocator, &reg, &.{"p000"});
    defer testing.allocator.free(order);
    try testing.expectEqual(count, order.len);
}
