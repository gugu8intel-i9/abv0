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

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ---- main executable ---------------------------------------------------
    const exe = b.addExecutable(.{
        .name = "abv0",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
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
    const run_unit_tests = b.addRunArtifact(unit_tests);
    b.step("test", "Run unit tests").dependOn(&run_unit_tests.step);

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
