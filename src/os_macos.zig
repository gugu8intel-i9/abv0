const std = @import("std");
const builtin = @import("builtin");

// APFS clonefile flag: CLONE_NOFOLLOW (0x0001) - don't follow symlinks
const CLONE_NOFOLLOW: u32 = 0x0001;

pub extern "c" fn clonefile(src: [*:0]const u8, dst: [*:0]const u8, flags: u32) i32;

pub fn fastLink(src_path: []const u8, dst_path: []const u8) !bool {
    if (builtin.target.os.tag == .macos) {
        // We need null-terminated strings for clonefile
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const alloc = arena.allocator();

        const src_z = try alloc.dupeZ(u8, src_path);
        const dst_z = try alloc.dupeZ(u8, dst_path);

        const ret = clonefile(src_z, dst_z, CLONE_NOFOLLOW);
        if (ret == 0) {
            return true; // Successfully used high-performance APFS clonefile!
        }
    }

    // Fallback to standard symlink if clonefile failed or not on macOS
    std.posix.symlink(src_path, dst_path) catch |err| {
        if (err == error.PathAlreadyExists) {
            try std.posix.unlink(dst_path);
            try std.posix.symlink(src_path, dst_path);
        } else {
            return err;
        }
    };

    return false; // Used symlink fallback
}
