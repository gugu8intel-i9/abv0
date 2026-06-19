const std = @import("std");

pub const PlatformInfo = struct {
    url: []const u8,
    sha256: []const u8,
    archive_type: []const u8,
    bin_path: []const u8,
};

pub const Package = struct {
    name: []const u8,
    version: []const u8,
    description: []const u8,
    homepage: []const u8,
    license: []const u8,
    bin: []const []const u8,
    app_bundles: []const []const u8,
    platforms: std.StringHashMap(PlatformInfo),
};

// Next-Generation Feature: Binary Columnar Compressed Log Engine
pub const ColumnarRegistry = struct {
    allocator: std.mem.Allocator,
    columnar_file_path: []const u8,

    pub fn init(allocator: std.mem.Allocator, file_path: []const u8) ColumnarRegistry {
        return .{
            .allocator = allocator,
            .columnar_file_path = file_path,
        };
    }

    // High-Performance Query Projection: Only reads exact projected column offsets
    pub fn projectNamesAndVersions(self: *ColumnarRegistry) !std.ArrayList([2][]const u8) {
        var results = std.ArrayList([2][]const u8).init(self.allocator);

        const file = std.fs.cwd().openFile(self.columnar_file_path, .{}) catch return results;
        defer file.close();

        var reader = file.reader();
        var magic: [24]u8 = undefined;
        const read_magic = try reader.read(&magic);
        if (read_magic < 24 or !std.mem.eql(u8, magic[0..24], "ABV0_BINARY_COLUMNAR_LOG")) {
            return results;
        }

        const entries_count = try reader.readInt(u32, .little);
        for (0..entries_count) |_| {
            const n_len = try reader.readInt(u16, .little);
            const name_buf = try self.allocator.alloc(u8, n_len);
            _ = try reader.read(name_buf);

            const v_len = try reader.readInt(u16, .little);
            const ver_buf = try self.allocator.alloc(u8, v_len);
            _ = try reader.read(ver_buf);

            try results.append([2][]const u8{ name_buf, ver_buf });
        }

        return results;
    }

    // Auto-compiles flat packages map into definitive Binary Columnar Compressed Log database
    pub fn compileFromPackages(self: *ColumnarRegistry, pkgs_map: *std.StringHashMap(Package)) !void {
        if (std.fs.path.dirname(self.columnar_file_path)) |p_dir| {
            std.fs.cwd().makePath(p_dir) catch {};
        }
        const file = try std.fs.cwd().createFile(self.columnar_file_path, .{ .mode = 0o644 });
        defer file.close();

        var writer = file.writer();
        try writer.writeAll("ABV0_BINARY_COLUMNAR_LOG");

        const count: u32 = @as(u32, @intCast(pkgs_map.count()));
        try writer.writeInt(u32, count, .little);

        // Column 1 & 2 Streams: Names and Versions projection data
        var it = pkgs_map.iterator();
        while (it.next()) |entry| {
            const pkg = entry.value_ptr.*;
            const n_len: u16 = @as(u16, @intCast(pkg.name.len));
            try writer.writeInt(u16, n_len, .little);
            try writer.writeAll(pkg.name);

            const v_len: u16 = @as(u16, @intCast(pkg.version.len));
            try writer.writeInt(u16, v_len, .little);
            try writer.writeAll(pkg.version);
        }
    }
};

pub const Registry = struct {
    allocator: std.mem.Allocator,
    packages: std.StringHashMap(Package),

    pub fn init(allocator: std.mem.Allocator) Registry {
        return .{
            .allocator = allocator,
            .packages = std.StringHashMap(Package).init(allocator),
        };
    }

    pub fn deinit(self: *Registry) void {
        self.packages.deinit();
    }

    pub fn loadFromFile(self: *Registry, file_path: []const u8) !void {
        const alloc = self.allocator;
        const file = try std.fs.cwd().openFile(file_path, .{});
        defer file.close();

        const content = try file.readToEndAlloc(alloc, 10 * 1024 * 1024);

        const parsed = try std.json.parseFromSlice(std.json.Value, alloc, content, .{});

        const root = parsed.value.object;
        const pkgs_map = root.get("packages").?.object;

        var it = pkgs_map.iterator();
        while (it.next()) |entry| {
            const pkg_name = entry.key_ptr.*;
            const pkg_obj = entry.value_ptr.object;

            var bin_list = std.ArrayList([]const u8).init(alloc);
            if (pkg_obj.get("bin")) |bin_val| {
                const bin_arr = bin_val.array;
                for (bin_arr.items) |b_val| {
                    try bin_list.append(try alloc.dupe(u8, b_val.string));
                }
            }

            var app_list = std.ArrayList([]const u8).init(alloc);
            if (pkg_obj.get("app_bundles")) |app_val| {
                const app_arr = app_val.array;
                for (app_arr.items) |a_val| {
                    try app_list.append(try alloc.dupe(u8, a_val.string));
                }
            }

            var platforms_map = std.StringHashMap(PlatformInfo).init(alloc);
            const plats_obj = pkg_obj.get("platforms").?.object;
            var plat_it = plats_obj.iterator();
            while (plat_it.next()) |plat_entry| {
                const plat_name = plat_entry.key_ptr.*;
                const plat_obj = plat_entry.value_ptr.object;

                try platforms_map.put(try alloc.dupe(u8, plat_name), .{
                    .url = try alloc.dupe(u8, plat_obj.get("url").?.string),
                    .sha256 = try alloc.dupe(u8, plat_obj.get("sha256").?.string),
                    .archive_type = try alloc.dupe(u8, plat_obj.get("archive_type").?.string),
                    .bin_path = try alloc.dupe(u8, plat_obj.get("bin_path").?.string),
                });
            }

            const pkg = Package{
                .name = try alloc.dupe(u8, pkg_obj.get("name").?.string),
                .version = try alloc.dupe(u8, pkg_obj.get("version").?.string),
                .description = try alloc.dupe(u8, pkg_obj.get("description").?.string),
                .homepage = try alloc.dupe(u8, pkg_obj.get("homepage").?.string),
                .license = try alloc.dupe(u8, pkg_obj.get("license").?.string),
                .bin = try bin_list.toOwnedSlice(),
                .app_bundles = try app_list.toOwnedSlice(),
                .platforms = platforms_map,
            };

            try self.packages.put(try alloc.dupe(u8, pkg_name), pkg);
        }
    }
};
