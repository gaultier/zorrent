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

    var connectFrames = std.ArrayList(@Frame(zorrent.Peer.connect)).init(allocator);
    defer connectFrames.deinit();
    try connectFrames.ensureCapacity(peers.len);

    for (peers) |*peer| {
        std.debug.warn("Connecting to peer {}\n", .{peer.address});
        connectFrames.addOneAssumeCapacity().* = async peer.connect();
    }

    for (connectFrames.items) |*frame, i| {
        var socket = await frame catch |err| {
            switch (err) {
                error.ConnectionTimedOut => continue,
                else => return err,
            }
        };

        std.debug.warn("Connected to peer {}\n", .{peers[i].address});
    }

    //         var handshakeFrame = async peer.handshake();

    //         await handshakeFrame catch |err| {
    //             switch (err) {
    //                 error.ConnectionTimedOut => continue,
    //                 error.WrongHandshake => continue,
    //                 else => return err,
    //             }
    //         };

    //         std.debug.warn("Handshaked peer {}\n", .{peer.address});
    //     }
}
