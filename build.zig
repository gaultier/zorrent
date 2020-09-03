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

    const test_step = b.step("test", "Run all the tests");
    var torrent_file_test = b.addTest("src/torrent_file.zig");
    torrent_file_test.setBuildMode(mode);
    torrent_file_test.addPackagePath("zig-bencode", "zig-bencode/src/main.zig");
    test_step.dependOn(&torrent_file_test.step);

    var pieces_test = b.addTest("src/pieces.zig");
    pieces_test.setBuildMode(mode);
    test_step.dependOn(&pieces_test.step);

    var peer_test = b.addTest("src/peer.zig");
    peer_test.setBuildMode(mode);
    test_step.dependOn(&peer_test.step);
}
