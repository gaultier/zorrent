const zorrent = @import("zorrent");
const std = @import("std");

pub const io_mode = .evented;
pub const log_level: std.log.Level = .debug;

pub fn log(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    const green = "\x1b[32m";
    const red = "\x1b[31m";
    const grey = "\x1b[37m";
    const reset = "\x1b[0m";

    const scope_prefix = "[" ++ switch (level) {
        .info, .notice => green,
        .debug => grey,
        else => red,
    } ++ @tagName(scope) ++ "][";

    const prefix = scope_prefix ++ @tagName(level) ++ "] ";

    // Print the message to stderr, silently ignoring any errors
    const held = std.debug.getStderrMutex().acquire();
    defer held.release();
    const stderr = std.io.getStdErr().writer();
    nosuspend stderr.print(prefix ++ format ++ "\x1b[0m\n", args) catch return;
}

pub fn main() anyerror!void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = &arena.allocator;

    var args = try std.process.argsAlloc(allocator);
    const arg = if (args.len == 2) args[1] else return error.MissingCliArgument;

    var torrent_file = try zorrent.TorrentFile.parse(arg, allocator);

    var peers: []zorrent.Peer = undefined;
    while (true) {
        peers = try torrent_file.getPeers(allocator);
        if (peers.len > 0) break;

        std.time.sleep(1 * std.time.ns_per_s);
    }
    defer allocator.destroy(&peers);

    var frames = std.ArrayList(@Frame(zorrent.Peer.handle)).init(allocator);
    defer frames.deinit();
    try frames.ensureCapacity(peers.len);

    var download_file = try zorrent.openMmapFile(torrent_file.path, torrent_file.total_len);
    defer download_file.deinit();

    var pieces = try zorrent.Pieces.init(torrent_file.total_len, allocator);
    defer pieces.deinit();

    for (peers) |*peer| {
        frames.addOneAssumeCapacity().* = async peer.handle(torrent_file, download_file.data, &pieces);
    }

    for (frames.items) |*frame, i| {
        _ = await frame catch |err| {
            const peer = peers[i];
            std.log.err(.zorrent_client, "{}\t{}", .{ peer.address, err });
        };
    }
}
