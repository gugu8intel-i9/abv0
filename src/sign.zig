//! Ed25519 verification of the package manifest.
//!
//! The registry index is fetched over the network, so before it is trusted a
//! detached signature (packages/index.json.sig) is checked against a public key
//! compiled into the binary. Signing happens offline in tools/sign-manifest.zig.

const std = @import("std");
const build_options = @import("build_options");

const Ed25519 = std.crypto.sign.Ed25519;

pub const Error = error{ MalformedSignature, BadSignature };

/// Public key bytes compiled in from build option `manifest_pubkey` (64 hex chars).
pub const public_key: [32]u8 = blk: {
    // A malformed key is a build error, never a runtime surprise.
    const hex = build_options.manifest_pubkey;
    if (hex.len != 64) @compileError("manifest_pubkey must be 64 hex characters");
    var key: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&key, hex) catch
        @compileError("manifest_pubkey contains non-hex characters");
    break :blk key;
};

/// Verify `sig_text` (128 hex chars, optional trailing whitespace/newline) is an
/// Ed25519 signature over `msg` by `public_key`.
pub fn verify(msg: []const u8, sig_text: []const u8) Error!void {
    return verifyWith(public_key, msg, sig_text);
}

/// Same, against an explicit key (used by tests and by verify()).
pub fn verifyWith(key: [32]u8, msg: []const u8, sig_text: []const u8) Error!void {
    // Editors and `echo` add a trailing newline; nothing else is tolerated.
    const hex = std.mem.trimRight(u8, sig_text, " \t\r\n");
    if (hex.len != 2 * Ed25519.Signature.encoded_length) return error.MalformedSignature;

    var sig_bytes: [Ed25519.Signature.encoded_length]u8 = undefined;
    _ = std.fmt.hexToBytes(&sig_bytes, hex) catch return error.MalformedSignature;

    // An unusable key cannot vouch for anything, so it is reported as a bad signature.
    const pk = Ed25519.PublicKey.fromBytes(key) catch return error.BadSignature;
    Ed25519.Signature.fromBytes(sig_bytes).verify(msg, pk) catch return error.BadSignature;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "verifyWith accepts a signature made by the same key" {
    const kp = try Ed25519.KeyPair.create([_]u8{7} ** 32);
    const msg = "{\"packages\":{}}";
    const sig = try kp.sign(msg, null);
    const hex = std.fmt.bytesToHex(sig.toBytes(), .lower);
    try verifyWith(kp.public_key.toBytes(), msg, &hex);
}

test "verifyWith rejects a tampered message" {
    const kp = try Ed25519.KeyPair.create([_]u8{7} ** 32);
    const msg = "manifest body";
    const sig = try kp.sign(msg, null);
    const hex = std.fmt.bytesToHex(sig.toBytes(), .lower);

    var tampered = msg.*;
    tampered[0] ^= 0x01;
    try std.testing.expectError(error.BadSignature, verifyWith(kp.public_key.toBytes(), &tampered, &hex));
}

test "verify rejects a signature from a different key" {
    const kp = try Ed25519.KeyPair.create([_]u8{7} ** 32);
    const other = try Ed25519.KeyPair.create([_]u8{9} ** 32);
    const msg = "manifest body";
    const sig = try kp.sign(msg, null);
    const hex = std.fmt.bytesToHex(sig.toBytes(), .lower);

    try std.testing.expectError(error.BadSignature, verifyWith(other.public_key.toBytes(), msg, &hex));
    // The compiled-in key is not the test key either.
    try std.testing.expectError(error.BadSignature, verify(msg, &hex));
}

test "verifyWith rejects non-hex and wrong-length signatures" {
    const kp = try Ed25519.KeyPair.create([_]u8{7} ** 32);
    const pk = kp.public_key.toBytes();
    const msg = "manifest body";

    try std.testing.expectError(error.MalformedSignature, verifyWith(pk, msg, "z" ** 128));
    try std.testing.expectError(error.MalformedSignature, verifyWith(pk, msg, "ab" ** 63));
    try std.testing.expectError(error.MalformedSignature, verifyWith(pk, msg, "ab" ** 65));
    try std.testing.expectError(error.MalformedSignature, verifyWith(pk, msg, ""));
}

test "verifyWith accepts a trailing newline" {
    const kp = try Ed25519.KeyPair.create([_]u8{7} ** 32);
    const msg = "manifest body";
    const sig = try kp.sign(msg, null);
    const hex = std.fmt.bytesToHex(sig.toBytes(), .lower);

    const with_newline = try std.fmt.allocPrint(std.testing.allocator, "{s}\n", .{hex[0..]});
    defer std.testing.allocator.free(with_newline);
    try verifyWith(kp.public_key.toBytes(), msg, with_newline);
}
