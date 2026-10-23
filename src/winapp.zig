//! Windows GUI apps: Start Menu shortcuts for portable programs.
//!
//! A Windows app in the catalog is a portable build (a .zip or .7z that runs
//! where it is unpacked, with no installer). It is unpacked into the store like
//! any package, and a shortcut to its program is put in
//! `%APPDATA%\Microsoft\Windows\Start Menu\Programs\abv0`, which makes it show
//! up in Start and in Windows search. Uninstalling deletes the shortcut.
//!
//! The package's `app_bundles` list names the program: `KeePassXC.exe`, or
//! `Display Name=file.exe` when the shortcut should be called something other
//! than the file. macOS ignores these entries, as Windows ignores `Name.app`.
//!
//! On Windows the shortcut is made by the Shell itself (the ShellLink COM
//! object that Explorer uses), so its target is stored the way every Windows
//! component reads it. `shortcutBytes` writes the Shell Link format directly
//! ([MS-SHLLINK], target as a LinkInfo local path); it is the fallback when COM
//! is unavailable and what the tests check on other systems.

const std = @import("std");
const builtin = @import("builtin");

pub const Entry = struct {
    /// Shortcut name, without `.lnk`.
    display: []const u8,
    /// The program's file name, `Name.exe`.
    exe: []const u8,
};

/// Split an `app_bundles` entry meant for Windows. Null for anything else
/// (a macOS `Name.app`, or a name abv0 must not use).
pub fn parseEntry(raw: []const u8) ?Entry {
    const eq = std.mem.indexOfScalar(u8, raw, '=');
    const exe = if (eq) |i| raw[i + 1 ..] else raw;
    if (!isSafeExeName(exe)) return null;
    const display = if (eq) |i| raw[0..i] else exe[0 .. exe.len - 4];
    if (!isSafeDisplayName(display)) return null;
    return .{ .display = display, .exe = exe };
}

/// One plain `*.exe` file name: no directory part, drive, or reserved character.
pub fn isSafeExeName(name: []const u8) bool {
    if (name.len <= 4 or name.len > 128) return false;
    if (!std.ascii.endsWithIgnoreCase(name, ".exe")) return false;
    return isPlainName(name);
}

/// A shortcut name Windows accepts as a file name, and that cannot climb out
/// of the abv0 Start Menu folder.
pub fn isSafeDisplayName(name: []const u8) bool {
    if (name.len == 0 or name.len > 100) return false;
    if (name[0] == ' ' or name[name.len - 1] == ' ' or name[name.len - 1] == '.') return false;
    if (!isPlainName(name)) return false;
    // Device names stay devices whatever the extension.
    const stem = if (std.mem.indexOfScalar(u8, name, '.')) |i| name[0..i] else name;
    const reserved = [_][]const u8{ "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9" };
    for (reserved) |r| {
        if (std.ascii.eqlIgnoreCase(stem, r)) return false;
    }
    return true;
}

fn isPlainName(name: []const u8) bool {
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return false;
    for (name) |c| {
        if (c < 0x20 or c == 0x7f) return false;
        switch (c) {
            '<', '>', ':', '"', '/', '\\', '|', '?', '*', '=' => return false,
            else => {},
        }
    }
    return true;
}

/// `<display>.lnk`, owned by `a`.
pub fn shortcutFileName(a: std.mem.Allocator, e: Entry) ![]u8 {
    return std.fmt.allocPrint(a, "{s}.lnk", .{e.display});
}

/// A shortcut file name abv0 recorded and may delete: a safe display name
/// followed by `.lnk`.
pub fn isSafeShortcutName(name: []const u8) bool {
    if (name.len <= 4 or !std.mem.endsWith(u8, name, ".lnk")) return false;
    return isSafeDisplayName(name[0 .. name.len - 4]);
}

// ---------------------------------------------------------------------------
// Shell Link writer
// ---------------------------------------------------------------------------

const header_size = 0x4c;
const link_clsid = [16]u8{ 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 };

const has_link_info: u32 = 0x02;
const has_working_dir: u32 = 0x10;
const has_icon_location: u32 = 0x40;
const is_unicode: u32 = 0x80;

const file_attribute_archive: u32 = 0x20;
const sw_shownormal: u32 = 1;
const drive_fixed: u32 = 3;

fn put32(w: anytype, v: u32) !void {
    try w.writeInt(u32, v, .little);
}

fn utf16(a: std.mem.Allocator, s: []const u8) ![]u16 {
    return std.unicode.utf8ToUtf16LeAlloc(a, s);
}

/// The bytes of a shortcut that starts `target` (an absolute path) in
/// `work_dir`, using the program's own first icon. Owned by `a`.
pub fn shortcutBytes(a: std.mem.Allocator, target: []const u8, work_dir: []const u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const aa = arena.allocator();

    const target_w = try utf16(aa, target);
    const dir_w = try utf16(aa, work_dir);

    // LinkInfo, with the Unicode path fields (header size 0x24). The ANSI
    // path is required by the format; non-ASCII characters there become '?',
    // and Windows reads the Unicode copy.
    var info = std.ArrayList(u8).init(aa);
    const iw = info.writer();
    const info_header: u32 = 0x24;
    const volume_id_size: u32 = 0x11; // 16 bytes of fields + an empty label
    const local_base_off: u32 = info_header + volume_id_size;
    const ansi_len: u32 = @intCast(target.len + 1);
    const suffix_off: u32 = local_base_off + ansi_len;
    const base_w_off: u32 = suffix_off + 1;
    const suffix_w_off: u32 = base_w_off + @as(u32, @intCast((target_w.len + 1) * 2));
    const info_size: u32 = suffix_w_off + 2;

    try put32(iw, info_size);
    try put32(iw, info_header);
    try put32(iw, 0x1); // VolumeIDAndLocalBasePath
    try put32(iw, info_header); // VolumeIDOffset
    try put32(iw, local_base_off);
    try put32(iw, 0); // CommonNetworkRelativeLinkOffset
    try put32(iw, suffix_off);
    try put32(iw, base_w_off);
    try put32(iw, suffix_w_off);
    // VolumeID
    try put32(iw, volume_id_size);
    try put32(iw, drive_fixed);
    try put32(iw, 0); // serial number
    try put32(iw, 0x10); // VolumeLabelOffset
    try iw.writeByte(0); // empty label
    // LocalBasePath (ANSI), CommonPathSuffix (empty)
    for (target) |c| try iw.writeByte(if (c < 0x80) c else '?');
    try iw.writeByte(0);
    try iw.writeByte(0);
    // LocalBasePathUnicode, CommonPathSuffixUnicode (empty)
    for (target_w) |u| try iw.writeInt(u16, u, .little);
    try iw.writeInt(u16, 0, .little);
    try iw.writeInt(u16, 0, .little);
    std.debug.assert(info.items.len == info_size);

    var out = std.ArrayList(u8).init(a);
    errdefer out.deinit();
    const w = out.writer();
    // ShellLinkHeader
    try put32(w, header_size);
    try w.writeAll(&link_clsid);
    try put32(w, has_link_info | has_working_dir | has_icon_location | is_unicode);
    try put32(w, file_attribute_archive);
    try w.writeByteNTimes(0, 24); // creation, access, write times
    try put32(w, 0); // file size
    try put32(w, 0); // icon index
    try put32(w, sw_shownormal);
    try w.writeInt(u16, 0, .little); // hot key
    try w.writeByteNTimes(0, 10); // reserved
    std.debug.assert(out.items.len == header_size);

    try w.writeAll(info.items);

    // StringData: working directory, then icon location.
    for ([_][]const u16{ dir_w, target_w }) |s| {
        try w.writeInt(u16, @intCast(s.len), .little);
        for (s) |u| try w.writeInt(u16, u, .little);
    }
    // ExtraData: terminal block only.
    try put32(w, 0);
    return out.toOwnedSlice();
}

/// Write the shortcut at `lnk_path`, replacing it. On Windows through the
/// Shell (see `comShortcut`), falling back to `writeShortcutFile`.
pub fn writeShortcut(a: std.mem.Allocator, lnk_path: []const u8, target: []const u8, work_dir: []const u8) !void {
    if (builtin.os.tag == .windows) {
        if (comShortcut(a, lnk_path, target, work_dir)) |_| return else |_| {}
    }
    return writeShortcutFile(a, lnk_path, target, work_dir);
}

/// Write `shortcutBytes` at `lnk_path` through a temporary file, so a reader
/// never sees half a shortcut.
pub fn writeShortcutFile(a: std.mem.Allocator, lnk_path: []const u8, target: []const u8, work_dir: []const u8) !void {
    const bytes = try shortcutBytes(a, target, work_dir);
    defer a.free(bytes);
    const tmp = try std.fmt.allocPrint(a, "{s}.tmp", .{lnk_path});
    defer a.free(tmp);
    try std.fs.cwd().writeFile(.{ .sub_path = tmp, .data = bytes });
    std.fs.cwd().rename(tmp, lnk_path) catch |e| {
        std.fs.cwd().deleteFile(tmp) catch {};
        return e;
    };
}

// ---------------------------------------------------------------------------
// The Shell's own shortcut writer (Windows)
// ---------------------------------------------------------------------------

const win = std.os.windows;

const clsid_shell_link = win.GUID.parse("{00021401-0000-0000-C000-000000000046}");
const iid_ishell_link_w = win.GUID.parse("{000214F9-0000-0000-C000-000000000046}");
const iid_ipersist_file = win.GUID.parse("{0000010B-0000-0000-C000-000000000046}");

/// A COM interface pointer: the first word is its method table.
const ComObject = extern struct { vtbl: [*]const *const anyopaque };

const ole32 = struct {
    extern "ole32" fn CoInitializeEx(reserved: ?*anyopaque, flags: u32) callconv(win.WINAPI) win.HRESULT;
    extern "ole32" fn CoUninitialize() callconv(win.WINAPI) void;
    extern "ole32" fn CoCreateInstance(clsid: *const win.GUID, outer: ?*anyopaque, ctx: u32, iid: *const win.GUID, out: *?*ComObject) callconv(win.WINAPI) win.HRESULT;
};

// Method slots. IUnknown: QueryInterface 0, AddRef 1, Release 2.
// IShellLinkW then: GetPath 3, GetIDList 4, SetIDList 5, GetDescription 6,
// SetDescription 7, GetWorkingDirectory 8, SetWorkingDirectory 9, GetArguments 10,
// SetArguments 11, GetHotkey 12, SetHotkey 13, GetShowCmd 14, SetShowCmd 15,
// GetIconLocation 16, SetIconLocation 17, SetRelativePath 18, Resolve 19, SetPath 20.
// IPersistFile: GetClassID 3, IsDirty 4, Load 5, Save 6.
const QueryInterface = *const fn (*ComObject, *const win.GUID, *?*ComObject) callconv(win.WINAPI) win.HRESULT;
const Release = *const fn (*ComObject) callconv(win.WINAPI) u32;
const SetString = *const fn (*ComObject, [*:0]const u16) callconv(win.WINAPI) win.HRESULT;
const SetIcon = *const fn (*ComObject, [*:0]const u16, c_int) callconv(win.WINAPI) win.HRESULT;
const SetShowCmd = *const fn (*ComObject, c_int) callconv(win.WINAPI) win.HRESULT;
const Save = *const fn (*ComObject, [*:0]const u16, win.BOOL) callconv(win.WINAPI) win.HRESULT;

fn method(comptime F: type, obj: *ComObject, slot: usize) F {
    return @ptrCast(@alignCast(obj.vtbl[slot]));
}

fn check(hr: win.HRESULT) !void {
    if (hr < 0) return error.ComCallFailed;
}

/// Make the shortcut with the Shell's ShellLink object, as Explorer does.
fn comShortcut(a: std.mem.Allocator, lnk_path: []const u8, target: []const u8, work_dir: []const u8) !void {
    if (builtin.os.tag != .windows) return error.Unsupported;
    const lnk_w = try std.unicode.utf8ToUtf16LeAllocZ(a, lnk_path);
    defer a.free(lnk_w);
    const target_w = try std.unicode.utf8ToUtf16LeAllocZ(a, target);
    defer a.free(target_w);
    const dir_w = try std.unicode.utf8ToUtf16LeAllocZ(a, work_dir);
    defer a.free(dir_w);

    const COINIT_APARTMENTTHREADED = 0x2;
    const CLSCTX_INPROC_SERVER = 0x1;
    // S_OK or S_FALSE: this call owns an initialization and must undo it.
    // RPC_E_CHANGED_MODE: the thread already uses COM, which works too.
    const init = ole32.CoInitializeEx(null, COINIT_APARTMENTTHREADED);
    defer if (init == 0 or init == 1) ole32.CoUninitialize();

    var link_opt: ?*ComObject = null;
    try check(ole32.CoCreateInstance(&clsid_shell_link, null, CLSCTX_INPROC_SERVER, &iid_ishell_link_w, &link_opt));
    const link = link_opt orelse return error.ComCallFailed;
    defer _ = method(Release, link, 2)(link);

    try check(method(SetString, link, 20)(link, target_w));
    try check(method(SetString, link, 9)(link, dir_w));
    try check(method(SetIcon, link, 17)(link, target_w, 0));
    try check(method(SetShowCmd, link, 15)(link, 1)); // SW_SHOWNORMAL

    var file_opt: ?*ComObject = null;
    try check(method(QueryInterface, link, 0)(link, &iid_ipersist_file, &file_opt));
    const file = file_opt orelse return error.ComCallFailed;
    defer _ = method(Release, file, 2)(file);
    try check(method(Save, file, 6)(file, lnk_w, win.TRUE));
}

/// Where the program `exe` sits under `root`: the shallowest regular file with
/// that name, compared without case as Windows does. Symlinks are not followed.
/// Relative to `root`, with the native separator; owned by `a`.
pub fn findProgram(a: std.mem.Allocator, root: []const u8, exe: []const u8) !?[]u8 {
    var dir = try std.fs.cwd().openDir(root, .{ .iterate = true, .no_follow = true });
    defer dir.close();
    var walker = try dir.walk(a);
    defer walker.deinit();
    var best: ?[]u8 = null;
    var best_depth: usize = std.math.maxInt(usize);
    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.ascii.eqlIgnoreCase(entry.basename, exe)) continue;
        const depth = std.mem.count(u8, entry.path, std.fs.path.sep_str);
        if (depth < best_depth or (depth == best_depth and std.mem.order(u8, entry.path, best.?) == .lt)) {
            if (best) |b| a.free(b);
            best = try a.dupe(u8, entry.path);
            best_depth = depth;
        }
    }
    return best;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parseEntry reads Windows entries and ignores Mac bundles" {
    const plain = parseEntry("KeePassXC.exe").?;
    try testing.expectEqualStrings("KeePassXC", plain.display);
    try testing.expectEqualStrings("KeePassXC.exe", plain.exe);
    const named = parseEntry("Godot Engine=Godot_v4.3-stable_win64.exe").?;
    try testing.expectEqualStrings("Godot Engine", named.display);
    try testing.expectEqualStrings("Godot_v4.3-stable_win64.exe", named.exe);

    try testing.expect(parseEntry("Rectangle.app") == null);
    try testing.expect(parseEntry("..\\evil.exe") == null);
    try testing.expect(parseEntry("C:evil.exe") == null);
    try testing.expect(parseEntry("dir/evil.exe") == null);
    try testing.expect(parseEntry("..=x.exe") == null);
    try testing.expect(parseEntry("CON=x.exe") == null);
    try testing.expect(parseEntry("a\\b=x.exe") == null);
    try testing.expect(parseEntry(".exe") == null);
    try testing.expect(isSafeShortcutName("KeePassXC.lnk"));
    try testing.expect(!isSafeShortcutName("..\\x.lnk"));
    try testing.expect(!isSafeShortcutName("x.app"));
}

fn readU32(b: []const u8, at: usize) u32 {
    return std.mem.readInt(u32, b[at..][0..4], .little);
}

fn readUtf16Z(a: std.mem.Allocator, b: []const u8, at: usize) ![]u8 {
    var units = std.ArrayList(u16).init(a);
    defer units.deinit();
    var i = at;
    while (true) : (i += 2) {
        const u = std.mem.readInt(u16, b[i..][0..2], .little);
        if (u == 0) break;
        try units.append(u);
    }
    return std.unicode.utf16LeToUtf8Alloc(a, units.items);
}

test "shortcutBytes lays out a Shell Link that points at the program" {
    const a = testing.allocator;
    const target = "C:\\Users\\Zoë\\.abv0\\store\\keepassxc@2.7.9@x86_64-windows\\KeePassXC\\KeePassXC.exe";
    const dir = "C:\\Users\\Zoë\\.abv0\\store\\keepassxc@2.7.9@x86_64-windows\\KeePassXC";
    const b = try shortcutBytes(a, target, dir);
    defer a.free(b);

    try testing.expectEqual(@as(u32, 0x4c), readU32(b, 0));
    try testing.expectEqualSlices(u8, &link_clsid, b[4..20]);
    const flags = readU32(b, 20);
    try testing.expect(flags & has_link_info != 0 and flags & is_unicode != 0);
    try testing.expect(flags & 0x1 == 0); // no ID list: LinkInfo carries the target

    // LinkInfo follows the header directly.
    const li = header_size;
    const li_size = readU32(b, li);
    try testing.expectEqual(@as(u32, 0x24), readU32(b, li + 4));
    try testing.expectEqual(@as(u32, 1), readU32(b, li + 8));
    const base_w = readU32(b, li + 0x1c);
    const got = try readUtf16Z(a, b, li + base_w);
    defer a.free(got);
    try testing.expectEqualStrings(target, got);
    // The ANSI copy has the same length, with '?' for the non-ASCII letter.
    const ansi_at = li + readU32(b, li + 0x10);
    const ansi = std.mem.sliceTo(b[ansi_at..], 0);
    try testing.expect(std.mem.indexOfScalar(u8, ansi, '?') != null);

    // StringData: working dir then icon, length-prefixed UTF-16.
    var at: usize = li + @as(usize, li_size);
    const dlen = std.mem.readInt(u16, b[at..][0..2], .little);
    const dir_w = try std.unicode.utf8ToUtf16LeAlloc(a, dir);
    defer a.free(dir_w);
    try testing.expectEqual(dir_w.len, dlen);
    at += 2 + @as(usize, dlen) * 2;
    const ilen = std.mem.readInt(u16, b[at..][0..2], .little);
    at += 2 + @as(usize, ilen) * 2;
    try testing.expectEqual(@as(u32, 0), readU32(b, at));
    try testing.expectEqual(b.len, at + 4);
}

test "findProgram picks the shallowest match, ignoring case" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.makePath("app/deep/er");
    try tmp.dir.writeFile(.{ .sub_path = "app/deep/er/Tool.exe", .data = "MZ" });
    try tmp.dir.writeFile(.{ .sub_path = "app/deep/TOOL.EXE", .data = "MZ" });
    try tmp.dir.writeFile(.{ .sub_path = "app/readme.txt", .data = "" });
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    const got = (try findProgram(testing.allocator, root, "tool.exe")).?;
    defer testing.allocator.free(got);
    const want = try std.fs.path.join(testing.allocator, &.{ "app", "deep", "TOOL.EXE" });
    defer testing.allocator.free(want);
    try testing.expectEqualStrings(want, got);
    try testing.expect((try findProgram(testing.allocator, root, "missing.exe")) == null);
}
