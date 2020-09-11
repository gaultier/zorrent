const std = @import("std");

pub fn main() anyerror!void {
    var torrent_file_content = try std.fs.cwd().readFileAlloc(std.testing.allocator, "../zig-bencode/input/wizard_oz.torrent", 30_000);
    defer std.testing.allocator.free(torrent_file_content);
}
