const zorrent = @import("zorrent");
const std = @import("std");

pub const io_mode = .evented;
pub const log_level: std.log.Level = .info;

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
    var peers = try torrent_file.getPeers(allocator);
    defer allocator.destroy(&peers);

    if (peers.len == 0) return error.NoPeersAvailable; // TODO: sleep & retry

    var frames = std.ArrayList(@Frame(zorrent.Peer.handle)).init(allocator);
    defer frames.deinit();
    try frames.ensureCapacity(peers.len);

    var download_file = try torrent_file.openMmapFile();
    defer download_file.deinit();

    var pieces = try zorrent.Pieces.init(torrent_file.total_len, allocator);

    for (peers) |*peer| {
        frames.addOneAssumeCapacity().* = async peer.handle(torrent_file, download_file.data, &pieces);
    }

    for (frames.items) |*frame| {
        _ = try await frame;
    }
}
