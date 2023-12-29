const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "stryke",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    exe.addModule("uuid", b.dependency("uuid", .{}).module("uuid6"));
    exe.linkLibC();
    exe.linkLibCpp();
    exe.linkSystemLibrary("libcrypto");
    exe.linkSystemLibrary("cryptopp");

    b.installArtifact(exe);

    // RUN STEP
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
    // TEST STEP
    const unit_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    unit_tests.addModule("uuid", b.dependency("uuid", .{}).module("uuid6"));
    unit_tests.linkLibC();
    unit_tests.linkSystemLibrary("libcrypto");

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
