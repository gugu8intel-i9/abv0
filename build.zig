const std = @import("std");

/// Every artifact we publish. The Linux builds link musl statically so a single
/// file runs on any distribution regardless of its glibc version; the previous
/// release binary was a dynamically linked *debug* build, which is both slower
/// and tied to the machine it happened to be compiled on.
const ReleaseTarget = struct {
    name: []const u8,
    query: std.Target.Query,
};

const release_targets = [_]ReleaseTarget{
    .{
        .name = "abv0-linux-x86_64",
        .query = .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .musl },
    },
    .{
        .name = "abv0-linux-aarch64",
        .query = .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .musl },
    },
    .{
        .name = "abv0-darwin-x86_64",
        .query = .{
            .cpu_arch = .x86_64,
            .os_tag = .macos,
            // High Sierra 10.13 and newer.
            .os_version_min = .{ .semver = .{ .major = 10, .minor = 13, .patch = 0 } },
        },
    },
    .{
        .name = "abv0-darwin-arm64",
        .query = .{
            .cpu_arch = .aarch64,
            .os_tag = .macos,
            // Big Sur 11.0 is the first macOS with Apple Silicon support.
            .os_version_min = .{ .semver = .{ .major = 11, .minor = 0, .patch = 0 } },
        },
    },
    .{
        .name = "abv0-windows-x86_64.exe",
        .query = .{ .cpu_arch = .x86_64, .os_tag = .windows },
    },
    .{
        .name = "abv0-windows-aarch64.exe",
        .query = .{ .cpu_arch = .aarch64, .os_tag = .windows },
    },
};

/// Public key that trusts packages/index.json.sig, relative to the build root.
/// Overridable with -Dmanifest-pubkey=<hex> (for example to test a release key).
const default_pubkey_path = "keys/manifest.pub";

/// Resolve the manifest public key as 64 hex characters, failing the build early
/// if it is malformed so no step can silently embed a bad key.
fn manifestPubkey(b: *std.Build) []const u8 {
    const hex = if (b.option(
        []const u8,
        "manifest-pubkey",
        "Ed25519 public key (64 hex chars) that trusts the package manifest",
    )) |override|
        std.mem.trim(u8, override, " \t\r\n")
    else blk: {
        const raw = b.build_root.handle.readFileAlloc(b.allocator, default_pubkey_path, 1024) catch |err| {
            std.debug.panic(
                "cannot read {s}: {s} (create it with `zig build sign-tool` and sign-manifest keygen, or pass -Dmanifest-pubkey=<hex>)",
                .{ default_pubkey_path, @errorName(err) },
            );
        };
        break :blk std.mem.trim(u8, raw, " \t\r\n");
    };

    var key: [32]u8 = undefined;
    if (hex.len != 64) std.debug.panic("manifest public key must be 64 hex characters, got {d}", .{hex.len});
    _ = std.fmt.hexToBytes(&key, hex) catch
        std.debug.panic("manifest public key contains non-hex characters", .{});
    return hex;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Compile-time configuration for src/sign.zig, exposed as `@import("build_options")`.
    const options = b.addOptions();
    options.addOption([]const u8, "manifest_pubkey", manifestPubkey(b));
    const build_options_mod = options.createModule();

    // ---- main executable ---------------------------------------------------
    const exe = b.addExecutable(.{
        .name = "abv0",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe.root_module.addImport("build_options", build_options_mod);
    b.installArtifact(exe);

    // ---- run ---------------------------------------------------------------
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    b.step("run", "Run the abv0 CLI").dependOn(&run_cmd.step);

    // ---- tests -------------------------------------------------------------
    // main.zig pulls in every module with `comptime _ = @import(...)`, so this
    // one test binary covers the whole codebase.
    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    unit_tests.root_module.addImport("build_options", build_options_mod);
    const run_unit_tests = b.addRunArtifact(unit_tests);

    // sign.zig is not reachable from main.zig yet, so it gets its own test binary.
    const sign_tests = b.addTest(.{
        .root_source_file = b.path("src/sign.zig"),
        .target = target,
        .optimize = optimize,
    });
    sign_tests.root_module.addImport("build_options", build_options_mod);
    const run_sign_tests = b.addRunArtifact(sign_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
    test_step.dependOn(&run_sign_tests.step);

    // ---- manifest signing tool ---------------------------------------------
    // Standalone: keygen, sign and verify never touch the embedded key.
    const sign_tool = b.addExecutable(.{
        .name = "sign-manifest",
        .root_source_file = b.path("tools/sign-manifest.zig"),
        .target = target,
        .optimize = optimize,
    });
    const install_sign_tool = b.addInstallArtifact(sign_tool, .{});
    b.step("sign-tool", "Install the sign-manifest CLI (keygen, sign, verify)").dependOn(&install_sign_tool.step);

    // ---- compile check for every supported platform ------------------------
    // Catches Windows-only and macOS-only compile errors without needing those
    // machines. `std.posix.getenv`, `std.fs.File.Mode` and `std.posix.mmap` all
    // behave differently there.
    const check_step = b.step("check", "Type-check against Linux, macOS and Windows");
    for (release_targets) |rt| {
        const chk = b.addExecutable(.{
            .name = b.fmt("check-{s}", .{rt.name}),
            .root_source_file = b.path("src/main.zig"),
            .target = b.resolveTargetQuery(rt.query),
            .optimize = .Debug,
        });
        chk.root_module.addImport("build_options", build_options_mod);
        check_step.dependOn(&chk.step);
    }

    // ---- release artifacts -------------------------------------------------
    const release_step = b.step("release", "Build stripped ReleaseFast binaries into release/");
    for (release_targets) |rt| {
        const rel = b.addExecutable(.{
            .name = rt.name,
            .root_source_file = b.path("src/main.zig"),
            .target = b.resolveTargetQuery(rt.query),
            .optimize = .ReleaseFast,
            .strip = true,
        });
        rel.root_module.addImport("build_options", build_options_mod);
        const install = b.addInstallArtifact(rel, .{
            .dest_dir = .{ .override = .{ .custom = "../release" } },
            .dest_sub_path = rt.name,
        });
        release_step.dependOn(&install.step);
    }

    // ---- macOS-only convenience step (kept for backwards compatibility) ----
    const macos_step = b.step("macos", "Build release binaries for macOS (Intel and Apple Silicon)");
    macos_step.dependOn(release_step);
}
