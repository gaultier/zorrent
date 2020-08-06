const zorrent = @import("zorrent");
const std = @import("std");
pub const io_mode = .evented;

pub fn main() anyerror!void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = &arena.allocator;

    var args = try std.process.argsAlloc(allocator);
    const arg = if (args.len == 2) args[1] else return error.MissingCliArgument;

    var torrent_file = try zorrent.TorrentFile.parse(arg, allocator);
    var peers = try torrent_file.getPeers(allocator);
    std.debug.warn("Peers len: {}\n", .{peers.len});
    defer allocator.destroy(&peers);

    var frames = std.ArrayList(@Frame(zorrent.Peer.handle)).init(allocator);
    defer frames.deinit();
    try frames.ensureCapacity(peers.len);

    var download_file = try torrent_file.openMmapFile();
    defer download_file.deinit();

    var file_mutex = std.Mutex.init();
    defer file_mutex.deinit();

    for (peers) |*peer| {
        frames.addOneAssumeCapacity().* = async peer.handle(torrent_file, download_file.data, &file_mutex);
    }

    for (frames.items) |*frame| {
        _ = try await frame;
    }
}
