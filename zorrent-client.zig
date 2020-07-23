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

    for (peers) |*peer| {
        std.debug.warn("Connecting to peer {}", .{peer.address});
        defer peer.deinit();

        peer.connect() catch |err| {
            switch (err) {
                error.ConnectionTimedOut => continue,
                else => return err,
            }
        };
        std.debug.warn("Connected to peer {}", .{peer.address});

        peer.handshake() catch |err| {
            switch (err) {
                error.ConnectionTimedOut => continue,
                error.WrongHandshake => continue,
                else => return err,
            }
        };

        std.debug.warn("Handshaked peer {}", .{peer.address});
    }
}
