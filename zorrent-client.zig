const zorrent = @import("zorrent");
const std = @import("std");

pub const io_mode = .evented;
pub const log_level: std.log.Level = .err;

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
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = &gpa.allocator;

    var args = try std.process.argsAlloc(allocator);
    const torrent_file_path = if (args.len == 2) args[1] else {
        try std.io.getStdOut().outStream().writeAll("zorrent <torrent file>\n");
        return;
    };

    var torrent_file_content = try std.fs.cwd().readFileAlloc(allocator, torrent_file_path, 10_000_000);
    defer allocator.free(torrent_file_content);

    var torrent_file = try zorrent.TorrentFile.parse(torrent_file_path, torrent_file_content, allocator);
    defer torrent_file.deinit();

    var peers: []zorrent.Peer = undefined;
    while (true) {
        peers = try torrent_file.getPeers(allocator);
        if (peers.len > 0) break;

        std.time.sleep(3 * std.time.ns_per_s);
    }
    defer allocator.free(peers);

    var frames = std.ArrayList(@Frame(zorrent.Peer.handle)).init(allocator);
    defer frames.deinit();
    try frames.ensureCapacity(peers.len);

    var pieces = try zorrent.Pieces.init(torrent_file.total_len, torrent_file.piece_len, torrent_file.file_paths, torrent_file.pieces[0..], torrent_file.file_sizes, allocator);
    const pieces_len: usize = zorrent.utils.divCeil(usize, torrent_file.total_len, torrent_file.piece_len);
    defer pieces.deinit();

    for (peers) |*peer| {
        frames.addOneAssumeCapacity().* = async peer.handle(torrent_file, pieces.file_buffers, &pieces);
    }

    for (frames.items) |*frame, i| {
        _ = await frame catch |err| {
            const peer = peers[i];
            std.log.err("{}\t{}", .{ peer.address, err });
        };
    }
}
