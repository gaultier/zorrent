const Builder = @import("std").build.Builder;
const std = @import("std");

pub fn build(b: *Builder) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable("zorrent", "zorrent-client.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.addPackage(.{
        .name = "zorrent",
        .path = "src/main.zig",
        .dependencies = &[_]std.build.Pkg{.{
            .name = "zig-bencode",
            .path = "zig-bencode/src/main.zig",
        }},
    });
    exe.setOutputDir("zig-cache");
    exe.linkLibC();
    exe.linkSystemLibrary("curl");
    exe.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // const test_step = b.step("test", "Run library tests");
    // test_step.dependOn(&main_tests.step);
}
