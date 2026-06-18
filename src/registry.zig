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
    platforms: std.StringHashMap(PlatformInfo),
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
            const bin_arr = pkg_obj.get("bin").?.array;
            for (bin_arr.items) |bin_val| {
                try bin_list.append(try alloc.dupe(u8, bin_val.string));
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
                .platforms = platforms_map,
            };

            try self.packages.put(try alloc.dupe(u8, pkg_name), pkg);
        }
    }
};
