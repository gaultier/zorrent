const std = @import("std");
const bencode = @import("zig-bencode");

pub const TorrentFile = struct {
    allocator: *std.mem.Allocator,
    announce_urls: [][]const u8,
    total_len: usize,
    info_hash: [20]u8,
    pieces: []const u8,
    piece_len: usize,
    file_paths: [][]const u8,
    file_sizes: []const usize,

    pub fn deinit(self: *TorrentFile) void {
        for (self.announce_urls) |url| self.allocator.free(url);
        self.allocator.free(self.announce_urls);

        self.allocator.free(self.pieces);

        for (self.file_paths) |fp| self.allocator.free(fp);
        self.allocator.free(self.file_paths);

        self.allocator.free(self.file_sizes);
    }

    pub fn parse(path: []const u8, content: []const u8, allocator: *std.mem.Allocator) !TorrentFile {
        // TODO: decide if we copy the memory from the ValueTree, or if we keep a reference to it
        var value = try bencode.ValueTree.parse(content, allocator);
        defer value.deinit();

        if (!bencode.isMap(value.root)) return error.InvalidField;

        var owned_announce_urls = std.ArrayList([]const u8).init(allocator);
        errdefer {
            for (owned_announce_urls.items) |url| allocator.free(url);
            owned_announce_urls.deinit();
        }

        if (bencode.mapLookup(value.root.Map, "announce")) |field| {
            if (!bencode.isString(field.*)) return error.InvalidField;

            const real_url = field.*.String;

            if (real_url.len >= 7 and std.mem.eql(u8, real_url[0..7], "http://")) {
                try owned_announce_urls.append(try allocator.dupe(u8, field.String));
            }
        }

        if (bencode.mapLookup(value.root.Map, "announce-list")) |field| {
            if (!bencode.isArray(field.*)) return error.InvalidField;

            const urls = field.Array.items;
            for (urls) |url| {
                const real_url = url.Array.items;

                if (real_url.len == 1) {
                    const real_real_url = real_url[0].String;
                    if (real_real_url.len >= 7 and std.mem.eql(u8, real_real_url[0..7], "http://")) {
                        try owned_announce_urls.append(try allocator.dupe(u8, real_real_url));
                    }
                }
            }
        }

        const field_info = bencode.mapLookup(value.root.Map, "info") orelse return error.FieldNotFound;
        if (!bencode.isMap(field_info.*)) return error.InvalidField;

        const pieces_field = bencode.mapLookup(field_info.Map, "pieces") orelse return error.FieldNotFound;
        if (!bencode.isString(pieces_field.*)) return error.InvalidField;
        const pieces = pieces_field.String;

        var owned_pieces = std.ArrayList(u8).init(allocator);
        errdefer owned_pieces.deinit();
        try owned_pieces.appendSlice(pieces);

        const piece_len_field = (bencode.mapLookup(field_info.Map, "piece length") orelse return error.FieldNotFound);
        if (!bencode.isInteger(piece_len_field.*)) return error.InvalidField;
        const piece_len = piece_len_field.Integer;

        var file_paths = std.ArrayList([]const u8).init(allocator);
        defer file_paths.deinit();

        var file_sizes = std.ArrayList(usize).init(allocator);
        defer file_sizes.deinit();

        if (bencode.mapLookup(field_info.Map, "name")) |field| {
            if (!bencode.isString(field.*)) return error.InvalidField;

            const basename = std.fs.path.basename(field.String);
            if (std.mem.eql(u8, basename, "..") or !std.mem.eql(u8, basename, field.String)) return error.InvalidFilePath;

            try file_paths.append(try allocator.dupe(u8, basename));
        }

        var total_len: usize = 0;
        if (bencode.mapLookup(field_info.Map, "length")) |field| {
            if (!bencode.isInteger(field.*)) return error.InvalidField;

            const len = field.Integer;
            if (len <= 0) return error.InvalidField;
            total_len = @intCast(usize, len);
            try file_sizes.append(@intCast(usize, len));
        }

        if (bencode.mapLookup(field_info.Map, "files")) |field| {
            if (!bencode.isArray(field.*)) return error.InvalidField;

            if (field.Array.items.len > 0) {
                for (field.Array.items) |file_field| {
                    if (!bencode.isMap(file_field)) return error.InvalidField;
                    var files = file_field.Map;

                    const file_path_field = (bencode.mapLookup(files, "path") orelse return error.FieldNotFound);
                    if (!bencode.isArray(file_path_field.*)) return error.InvalidField;
                    const file_path_field_real = file_path_field.Array.items[0];

                    if (!bencode.isString(file_path_field_real)) return error.InvalidField;
                    const p = file_path_field_real.String;

                    const basename = std.fs.path.basename(p);
                    if (std.mem.eql(u8, basename, "..") or !std.mem.eql(u8, basename, p)) return error.InvalidFilePath;

                    try file_paths.append(try allocator.dupe(u8, basename));

                    const total_len_field = bencode.mapLookup(files, "length") orelse return error.FieldNotFound;
                    if (!bencode.isInteger(total_len_field.*)) return error.InvalidField;

                    const len = total_len_field.Integer;
                    if (len <= 0) return error.InvalidField;

                    try file_sizes.append(@intCast(usize, len));

                    total_len += @intCast(usize, len);
                }
            }
        }

        var field_info_bencoded = std.ArrayList(u8).init(allocator);
        defer field_info_bencoded.deinit();
        try field_info.stringifyValue(field_info_bencoded.writer());

        var hash: [20]u8 = undefined;
        std.crypto.hash.Sha1.hash(field_info_bencoded.items, hash[0..], std.crypto.hash.Sha1.Options{});

        if (total_len == 0) return error.MissingField;

        return TorrentFile{
            .allocator = allocator,
            .announce_urls = owned_announce_urls.toOwnedSlice(),
            .total_len = @intCast(usize, total_len),
            .info_hash = hash,
            .piece_len = @intCast(usize, piece_len),
            .pieces = owned_pieces.toOwnedSlice(),
            .file_paths = file_paths.toOwnedSlice(),
            .file_sizes = file_sizes.toOwnedSlice(),
        };
    }
};

test "parse torrent file with file name outside of current directory" {
    std.testing.expectError(error.InvalidFilePath, TorrentFile.parse("", "d8:announce14:http://foo.com4:infod12:piece lengthi1e6:pieces1:04:name2:..ee", std.testing.allocator));
    std.testing.expectError(error.InvalidFilePath, TorrentFile.parse("", "d8:announce14:http://foo.com4:infod12:piece lengthi1e6:pieces1:04:name4:./..ee", std.testing.allocator));
    std.testing.expectError(error.InvalidFilePath, TorrentFile.parse("", "d8:announce14:http://foo.com4:infod12:piece lengthi1e6:pieces1:04:name1:/ee", std.testing.allocator));
    std.testing.expectError(error.InvalidFilePath, TorrentFile.parse("", "d8:announce14:http://foo.com4:infod12:piece lengthi1e6:pieces1:04:name6:foo/..ee", std.testing.allocator));
}

test "parse torrent file" {
    var torrent_file_content = try std.fs.cwd().readFileAlloc(std.testing.allocator, "../zig-bencode/input/OpenBSD_6.6_alpha_install66.iso-2019-10-16-1254.torrent", 30_000);
    defer std.testing.allocator.free(torrent_file_content);

    var torrent_file = try TorrentFile.parse("../zig-bencode/input/OpenBSD_6.6_alpha_install66.iso-2019-10-16-1254.torrent", torrent_file_content, std.testing.allocator);
    std.testing.expectEqual(@as(usize, 273358848), torrent_file.total_len);

    defer torrent_file.deinit();
}

test "parse torrent with multiple files" {
    var torrent_file = try TorrentFile.parse("", "d8:announce14:http://foo.com4:infod12:piece lengthi1e6:pieces1:04:name3:foo5:filesld6:lengthi20e4:pathl8:test.pdfeeeee", std.testing.allocator);
    std.testing.expectEqual(@as(usize, 20), torrent_file.total_len);

    defer torrent_file.deinit();
}

test "parse real torrent with multiple files" {
    var torrent_file_content = try std.fs.cwd().readFileAlloc(std.testing.allocator, "zig-bencode/input/wizard_oz.torrent", 30_000);
    defer std.testing.allocator.free(torrent_file_content);

    var torrent_file = try TorrentFile.parse("zig-bencode/input/wizard_oz.torrent", torrent_file_content, std.testing.allocator);
    std.testing.expectEqual(@as(usize, 8621319 + 46758 + 2357), torrent_file.total_len);
    std.testing.expectEqual(@as(usize, 3), torrent_file.file_sizes.len);
    std.testing.expectEqual(@as(usize, 4), torrent_file.file_paths.len);

    defer torrent_file.deinit();
}
