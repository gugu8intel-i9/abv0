//! Offline signing tool for the package manifest.
//!
//!   sign-manifest keygen <secret-key-out> <public-key-out>
//!   sign-manifest sign <secret-key-file> <manifest.json>
//!   sign-manifest verify <public-key-file> <manifest.json>
//!
//! Keys are hex text: the 64-byte Ed25519 secret key is 128 hex characters and
//! the 32-byte public key is 64. A signature is written beside the manifest as
//! `<manifest.json>.sig` (128 hex characters and a newline). The verifier in
//! src/sign.zig reads exactly that format.

const std = @import("std");
const builtin = @import("builtin");

const Ed25519 = std.crypto.sign.Ed25519;

const usage =
    \\usage:
    \\  sign-manifest keygen <secret-key-out> <public-key-out>
    \\  sign-manifest sign <secret-key-file> <manifest.json>
    \\  sign-manifest verify <public-key-file> <manifest.json>
    \\
;

/// A manifest can be large; key and signature files are tiny.
const max_manifest_bytes = 64 * 1024 * 1024;
const max_key_file_bytes = 4096;

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    const argv = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, argv);

    if (argv.len < 2) {
        std.io.getStdErr().writeAll(usage) catch {};
        std.process.exit(2);
    }
    const cmd = argv[1];
    const args = argv[2..];

    if (std.mem.eql(u8, cmd, "keygen") and args.len == 2) {
        try keygen(args[0], args[1]);
    } else if (std.mem.eql(u8, cmd, "sign") and args.len == 2) {
        try sign(gpa, args[0], args[1]);
    } else if (std.mem.eql(u8, cmd, "verify") and args.len == 2) {
        try verify(gpa, args[0], args[1]);
    } else {
        std.io.getStdErr().writeAll(usage) catch {};
        std.process.exit(2);
    }
}

/// Print a one-line error and exit with status 1.
fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("sign-manifest: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

/// Write a fresh key pair. Both files must not exist; the secret key is created
/// mode 0600 so other local users cannot read it.
fn keygen(secret_path: []const u8, public_path: []const u8) !void {
    refuseIfExists(secret_path);
    refuseIfExists(public_path);

    const kp = try Ed25519.KeyPair.create(null);
    const secret_hex = std.fmt.bytesToHex(kp.secret_key.toBytes(), .lower);
    const public_hex = std.fmt.bytesToHex(kp.public_key.toBytes(), .lower);

    const secret_mode: std.fs.File.Mode = if (builtin.os.tag == .windows) 0 else 0o600;
    const secret_file = createNewFile(secret_path, secret_mode);
    defer secret_file.close();
    try secret_file.writer().print("{s}\n", .{secret_hex[0..]});

    const public_file = createNewFile(public_path, std.fs.File.default_mode);
    defer public_file.close();
    try public_file.writer().print("{s}\n", .{public_hex[0..]});

    std.io.getStdOut().writer().print("wrote secret key to {s} and public key to {s}\n", .{ secret_path, public_path }) catch {};
}

/// Sign the raw bytes of `manifest_path` and write `<manifest_path>.sig`.
fn sign(gpa: std.mem.Allocator, key_path: []const u8, manifest_path: []const u8) !void {
    const secret = try readHexKey(gpa, key_path, Ed25519.SecretKey.encoded_length);
    const sk = Ed25519.SecretKey.fromBytes(secret) catch
        fail("{s} is not a valid Ed25519 secret key", .{key_path});
    const kp = Ed25519.KeyPair.fromSecretKey(sk) catch
        fail("{s} is not a valid Ed25519 secret key", .{key_path});

    const manifest = readFileOrFail(gpa, manifest_path, max_manifest_bytes);
    defer gpa.free(manifest);

    const sig = try kp.sign(manifest, null);
    const sig_hex = std.fmt.bytesToHex(sig.toBytes(), .lower);

    const sig_path = try std.fmt.allocPrint(gpa, "{s}.sig", .{manifest_path});
    defer gpa.free(sig_path);

    var line: [2 * Ed25519.Signature.encoded_length + 1]u8 = undefined;
    @memcpy(line[0 .. line.len - 1], sig_hex[0..]);
    line[line.len - 1] = '\n';
    try std.fs.cwd().writeFile(.{ .sub_path = sig_path, .data = &line });

    std.io.getStdOut().writer().print("wrote {s}\n", .{sig_path}) catch {};
}

/// Check `<manifest_path>.sig` against `public_path`. Exits 1 on any mismatch.
fn verify(gpa: std.mem.Allocator, public_path: []const u8, manifest_path: []const u8) !void {
    const pk_bytes = try readHexKey(gpa, public_path, Ed25519.PublicKey.encoded_length);
    const public_key = Ed25519.PublicKey.fromBytes(pk_bytes) catch
        fail("{s} is not a valid Ed25519 public key", .{public_path});

    const manifest = readFileOrFail(gpa, manifest_path, max_manifest_bytes);
    defer gpa.free(manifest);

    const sig_path = try std.fmt.allocPrint(gpa, "{s}.sig", .{manifest_path});
    defer gpa.free(sig_path);
    const sig_text = readFileOrFail(gpa, sig_path, max_key_file_bytes);
    defer gpa.free(sig_text);

    const sig_hex = std.mem.trimRight(u8, sig_text, " \t\r\n");
    if (sig_hex.len != 2 * Ed25519.Signature.encoded_length)
        fail("{s} is not a {d}-character hex signature", .{ sig_path, 2 * Ed25519.Signature.encoded_length });
    var sig_bytes: [Ed25519.Signature.encoded_length]u8 = undefined;
    _ = std.fmt.hexToBytes(&sig_bytes, sig_hex) catch
        fail("{s} is not a hex signature", .{sig_path});

    Ed25519.Signature.fromBytes(sig_bytes).verify(manifest, public_key) catch
        fail("signature does NOT match {s}", .{manifest_path});

    std.io.getStdOut().writer().print("OK: {s} is signed by {s}\n", .{ manifest_path, public_path }) catch {};
}

/// Read a key file holding `len` bytes as hex (surrounding whitespace allowed).
fn readHexKey(gpa: std.mem.Allocator, path: []const u8, comptime len: usize) ![len]u8 {
    const raw = readFileOrFail(gpa, path, max_key_file_bytes);
    defer gpa.free(raw);

    const text = std.mem.trim(u8, raw, " \t\r\n");
    // hexToBytes accepts short input, so the length has to be checked here.
    if (text.len != 2 * len) fail("{s} must contain {d} hex characters", .{ path, 2 * len });

    var out: [len]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch fail("{s} contains non-hex characters", .{path});
    return out;
}

fn readFileOrFail(gpa: std.mem.Allocator, path: []const u8, max_bytes: usize) []u8 {
    return std.fs.cwd().readFileAlloc(gpa, path, max_bytes) catch |err|
        fail("cannot read {s}: {s}", .{ path, @errorName(err) });
}

fn refuseIfExists(path: []const u8) void {
    if (std.fs.cwd().access(path, .{})) |_| {
        fail("refusing to overwrite existing file {s}", .{path});
    } else |_| {}
}

/// Create a file that must not already exist (exclusive create closes the race
/// window that refuseIfExists() leaves open).
fn createNewFile(path: []const u8, mode: std.fs.File.Mode) std.fs.File {
    return std.fs.cwd().createFile(path, .{ .exclusive = true, .mode = mode }) catch |err| switch (err) {
        error.PathAlreadyExists => fail("refusing to overwrite existing file {s}", .{path}),
        else => fail("cannot create {s}: {s}", .{ path, @errorName(err) }),
    };
}
