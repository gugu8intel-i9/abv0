const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Main executable
    const exe = b.addExecutable(.{
        .name = "abv0",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(exe);

    // Run step
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the abv0 CLI");
    run_step.dependOn(&run_cmd.step);

    // Unit tests
    const exe_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);

    // Cross-compilation targets for macOS (Intel & ARM)
    const macos_x86_target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .macos,
        // Highly compatible older macOS target (High Sierra 10.13)
        .os_version_min = .{ .semver = .{ .major = 10, .minor = 13, .patch = 0 } },
    });
    const macos_x86_exe = b.addExecutable(.{
        .name = "abv0-x86_64-macos",
        .root_source_file = b.path("src/main.zig"),
        .target = macos_x86_target,
        .optimize = .ReleaseFast, // High performance
    });
    const install_macos_x86 = b.addInstallArtifact(macos_x86_exe, .{});

    const macos_arm_target = b.resolveTargetQuery(.{
        .cpu_arch = .aarch64,
        .os_tag = .macos,
        // macOS Big Sur 11.0 is the first macOS with Apple Silicon support
        .os_version_min = .{ .semver = .{ .major = 11, .minor = 0, .patch = 0 } },
    });
    const macos_arm_exe = b.addExecutable(.{
        .name = "abv0-aarch64-macos",
        .root_source_file = b.path("src/main.zig"),
        .target = macos_arm_target,
        .optimize = .ReleaseFast, // High performance
    });
    const install_macos_arm = b.addInstallArtifact(macos_arm_exe, .{});

    const macos_step = b.step("macos", "Build release binaries for macOS (Intel and Apple Silicon)");
    macos_step.dependOn(&install_macos_x86.step);
    macos_step.dependOn(&install_macos_arm.step);
}
