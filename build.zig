const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardOptimizeOption(.{});

    const known_folder_module = b.addModule("known_folder", .{
        .source_file = .{ .path = "src/known_folder.zig" },
    });

    const exe = b.addExecutable(.{
        .name = "knownfolder",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = mode,
    });
    b.installArtifact(exe);

    const test_filter = b.option([]const u8, "test-filter", "Skip tests that do not match filter");
    const tests = b.addTest(.{
        .root_source_file = .{ .path = "src/known_folder.zig" },
        .target = target,
        .optimize = mode,
        .filter = test_filter,
    });
    const run_tests = b.addRunArtifact(tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_tests.step);

    const shknownfolder = b.addExecutable(.{
        .name = "shknownfolder",
        .root_source_file = .{ .path = "tools/shknownfolder.zig" },
        .target = target,
        .optimize = mode,
    });
    shknownfolder.addModule("known_folder", known_folder_module);
    const install_shknownfolder = b.addInstallArtifact(shknownfolder, .{});

    const spawnempty = b.addExecutable(.{
        .name = "spawnempty",
        .root_source_file = .{ .path = "tools/spawnempty.zig" },
        .target = target,
        .optimize = mode,
    });
    const install_spawnempty = b.addInstallArtifact(spawnempty, .{});

    const tools_step = b.step("tools", "Build and install tools");
    tools_step.dependOn(&install_shknownfolder.step);
    tools_step.dependOn(&install_spawnempty.step);
}
