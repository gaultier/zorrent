const std = @import("std");
const c = @cImport(@cInclude("curl/curl.h"));
const bencode = @import("zig-bencode");

const torrent_file = @import("torrent_file.zig");
const peer_mod = @import("peer.zig");
const pieces_mod = @import("pieces.zig");

pub const TorrentFile = torrent_file.TorrentFile;
pub const Peer = peer_mod.Peer;

pub const Pieces = pieces_mod.Pieces;

pub fn openMmapFile(path: []const u8, file_len: usize) !DownloadFile {
    const fd = try std.os.open(path, std.os.O_CREAT | std.os.O_RDWR, 438);
    try std.os.ftruncate(fd, file_len);

    var data = try std.os.mmap(
        null,
        file_len,
        std.os.PROT_READ | std.os.PROT_WRITE,
        std.os.MAP_FILE | std.os.MAP_SHARED,
        fd,
        0,
    );

    return DownloadFile{ .fd = fd, .data = data };
}

pub const DownloadFile = struct {
    fd: c_int,
    data: []align(std.mem.page_size) u8,

    pub fn deinit(self: *DownloadFile) void {
        defer std.os.munmap(self.data);
        defer std.os.close(self.fd);
    }
};
