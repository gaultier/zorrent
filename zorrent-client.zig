const zorrent = @import("zorrent");
const std = @import("std");
pub const io_mode = .evented;

pub fn main() anyerror!void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    const allocator = &arena.allocator;

    var args = try std.process.argsAlloc(allocator);
    const arg = if (args.len == 2) args[1] else return error.MissingCliArgument;

    var torrent_file = try zorrent.TorrentFile.parse(arg, allocator);
    var peers = try torrent_file.getPeers(allocator);
    defer allocator.destroy(&peers);

    var frames = std.ArrayList(@Frame(zorrent.Peer.handle)).init(allocator);
    defer frames.deinit();
    try frames.ensureCapacity(peers.len);

    for (peers) |*peer| {
        frames.addOneAssumeCapacity().* = async peer.handle(&torrent_file);
    }
    for (frames.items) |*frame| {
        _ = try await frame;
    }
}
