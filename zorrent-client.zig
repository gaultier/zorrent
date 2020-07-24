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

    // Connect
    {
        var frames = std.ArrayList(@Frame(zorrent.Peer.connect)).init(allocator);
        defer frames.deinit();
        try frames.ensureCapacity(peers.len);
        for (peers) |*peer| {
            std.debug.warn("Connecting to peer {}\n", .{peer.address});
            frames.addOneAssumeCapacity().* = async peer.connect();
        }

        for (peers) |*peer, i| {
            var socket = await frames.items[i] catch |err| {
                switch (err) {
                    error.ConnectionTimedOut, error.ConnectionRefused => {
                        std.debug.warn("Peer {} failed\n", .{peer.address});
                        peer.deinit();
                        continue;
                    },
                    else => return err,
                }
            };

            std.debug.warn("Connected to peer {}\n", .{peer.address});
        }
    }

    // Handshake
    {
        var frames = std.ArrayList(@Frame(zorrent.Peer.handshake)).init(allocator);
        defer frames.deinit();
        try frames.ensureCapacity(peers.len);
        for (peers) |*peer| {
            if (peer.state == zorrent.PeerState.Connected) {
                std.debug.warn("Handshaking peer {}\n", .{peer.address});
                frames.addOneAssumeCapacity().* = async peer.handshake();
            }
        }

        for (peers) |*peer, i| {
            if (peer.state == zorrent.PeerState.Connected) {
                await frames.items[i] catch |err| {
                    switch (err) {
                        error.ConnectionTimedOut => {
                            std.debug.warn("Peer {} failed\n", .{peer.address});
                            continue;
                        },
                        error.WrongHandshake => {
                            std.debug.warn("Peer {} sent a wrong handshake\n", .{peer.address});
                            peer.deinit();
                            continue;
                        },
                        else => return err,
                    }
                };

                std.debug.warn("Connected to peer {}\n", .{peer.address});
            }
        }
    }
}
