const std = @import("std");
const c = @cImport(@cInclude("curl/curl.h"));
const bencode = @import("zig-bencode");

const torrent_file = @import("torrent_file.zig");
const peer_mod = @import("peer.zig");
const pieces_mod = @import("pieces.zig");
pub const tracker = @import("tracker.zig");
pub const utils = @import("utils.zig");

pub const TorrentFile = torrent_file.TorrentFile;
pub const Peer = peer_mod.Peer;

pub const Pieces = pieces_mod.Pieces;

pub fn run(torrent_file_path: []const u8, allocator: *std.mem.Allocator) !void {
    var torrent_file_content = try std.fs.cwd().readFileAlloc(allocator, torrent_file_path, 10_000_000);
    defer allocator.free(torrent_file_content);

    var file = try TorrentFile.parse(torrent_file_path, torrent_file_content, allocator);
    defer file.deinit();

    var peers = try tracker.getPeers(file.announce_urls, file.info_hash, file.total_len, allocator);
    defer allocator.free(peers);

    var frames = std.ArrayList(@Frame(Peer.handle)).init(allocator);
    defer frames.deinit();
    try frames.ensureCapacity(peers.len);

    var pieces = try Pieces.init(file.total_len, file.piece_len, file.file_paths, file.pieces[0..], file.file_sizes, allocator);
    const pieces_len: usize = utils.divCeil(usize, file.total_len, file.piece_len);
    defer pieces.deinit();

    var trackers = std.ArrayList(tracker.Tracker).init(allocator);
    defer trackers.deinit();
    try trackers.ensureCapacity(file.announce_urls.len);

    for (file.announce_urls) |url| {
        trackers.addOneAssumeCapacity().* = tracker.Tracker{ .url = url, .last_updated_unix_timestamp = std.atomic.Int(i64).init(std.time.timestamp()) };
    }

    for (peers) |*peer| {
        frames.addOneAssumeCapacity().* = async peer.handle(file, pieces.file_buffer, &pieces, trackers.items);
    }

    for (frames.items) |*frame, i| {
        _ = await frame catch |err| {
            const peer = peers[i];
            std.log.err("{}\t{}", .{ peer.address, err });
        };
    }
}
