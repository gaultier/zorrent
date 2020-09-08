const std = @import("std");
const bencode = @import("zig-bencode");

const peer_mod = @import("peer.zig");
const Peer = peer_mod.Peer;

pub const TorrentFile = struct {
    allocator: *std.mem.Allocator,
    announce_urls: [][]const u8,
    total_len: usize,
    hash_info: [20]u8,
    downloadedBytesCount: usize,
    uploadedBytesCount: usize,
    leftBytesCount: usize,
    pieces: []const u8,
    piece_len: usize,
    file_paths: [][]const u8,

    pub fn deinit(self: *TorrentFile) void {
        for (self.announce_urls) |url| self.allocator.free(url);
        self.allocator.free(self.announce_urls);

        self.allocator.free(self.pieces);

        for (self.file_paths) |fp| self.allocator.free(fp);
        self.allocator.free(self.file_paths);
    }

    pub fn parse(path: []const u8, content: []const u8, allocator: *std.mem.Allocator) !TorrentFile {
        // TODO: decide if we copy the memory from the ValueTree, or if we keep a reference to it
        var value = try bencode.ValueTree.parse(content, allocator);
        defer value.deinit();

        if (!bencode.isObject(value.root)) return error.InvalidField;

        var owned_announce_urls = std.ArrayList([]const u8).init(allocator);
        errdefer {
            for (owned_announce_urls.items) |url| allocator.free(url);
            owned_announce_urls.deinit();
        }

        if (bencode.mapLookup(&value.root.Object, "announce")) |field| {
            if (!bencode.isString(field.*)) return error.InvalidField;

            const real_url = field.*.String;

            if (real_url.len >= 7 and std.mem.eql(u8, real_url[0..7], "http://")) {
                try owned_announce_urls.append(try allocator.dupe(u8, field.String));
            }
        }

        if (bencode.mapLookup(&value.root.Object, "announce-list")) |field| {
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

        const field_info = bencode.mapLookup(&value.root.Object, "info") orelse return error.FieldNotFound;
        if (!bencode.isObject(field_info.*)) return error.InvalidField;

        const pieces_field = bencode.mapLookup(&field_info.Object, "pieces") orelse return error.FieldNotFound;
        if (!bencode.isString(pieces_field.*)) return error.InvalidField;
        const pieces = pieces_field.String;

        var owned_pieces = std.ArrayList(u8).init(allocator);
        errdefer owned_pieces.deinit();
        try owned_pieces.appendSlice(pieces);

        const piece_len_field = (bencode.mapLookup(&field_info.Object, "piece length") orelse return error.FieldNotFound);
        if (!bencode.isInteger(piece_len_field.*)) return error.InvalidField;
        const piece_len = piece_len_field.Integer;

        var file_paths = std.ArrayList([]const u8).init(allocator);
        defer file_paths.deinit();

        if (bencode.mapLookup(&field_info.Object, "name")) |field| {
            if (!bencode.isString(field.*)) return error.InvalidField;

            const basename = std.fs.path.basename(field.String);
            if (basename.len == 0 or std.mem.eql(u8, basename, "..")) return error.InvalidFilePath;

            try file_paths.append(try allocator.dupe(u8, basename));
        }

        var total_len: isize = 0;
        if (bencode.mapLookup(&field_info.Object, "length")) |field| {
            if (!bencode.isInteger(field.*)) return error.InvalidField;
            total_len += field.Integer;
        }

        if (bencode.mapLookup(&field_info.Object, "files")) |field| {
            if (!bencode.isArray(field.*)) return error.InvalidField;

            if (field.Array.items.len > 0) {
                var file_field = field.Array.items[0];
                if (!bencode.isObject(file_field)) return error.InvalidField;
                var files = file_field.Object;

                const file_path_field = (bencode.mapLookup(&files, "path") orelse return error.FieldNotFound);
                if (!bencode.isArray(file_path_field.*)) return error.InvalidField;
                const file_path_field_real = file_path_field.Array.items[0];

                if (!bencode.isString(file_path_field_real)) return error.InvalidField;
                const p = file_path_field_real.String;

                const basename = std.fs.path.basename(p);
                if (basename.len == 0 or std.mem.eql(u8, basename, "..")) return error.InvalidFilePath;

                try file_paths.append(try allocator.dupe(u8, basename));

                const total_len_field = bencode.mapLookup(&files, "length") orelse return error.FieldNotFound;
                if (!bencode.isInteger(total_len_field.*)) return error.InvalidField;
                total_len += total_len_field.Integer;
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
            .hash_info = hash,
            .uploadedBytesCount = 0,
            .downloadedBytesCount = 0,
            .leftBytesCount = @intCast(usize, total_len),
            .piece_len = @intCast(usize, piece_len),
            .pieces = owned_pieces.toOwnedSlice(),
            .file_paths = file_paths.toOwnedSlice(),
        };
    }

    fn buildAnnounceUrl(self: TorrentFile, url: []const u8, allocator: *std.mem.Allocator) ![]const u8 {
        var query = std.ArrayList(u8).init(allocator);
        defer query.deinit();

        try query.appendSlice(url);
        try query.appendSlice("?info_hash=");

        for (self.hash_info) |byte| {
            try std.fmt.format(query.writer(), "%{X:0<2}", .{byte});
        }

        const peer_id: [20]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19 };

        try query.appendSlice("&peer_id=");
        for (peer_id) |byte| {
            try std.fmt.format(query.writer(), "%{X:0<2}", .{byte});
        }

        const port: u16 = 6881; // TODO: listen on that port
        try std.fmt.format(query.writer(), "&port={}", .{port});

        try std.fmt.format(query.writer(), "&uploaded={}", .{self.uploadedBytesCount});

        const downloaded = 0;
        try std.fmt.format(query.writer(), "&downloaded={}", .{self.downloadedBytesCount});

        try std.fmt.format(query.writer(), "&left={}", .{self.leftBytesCount});

        try std.fmt.format(query.writer(), "&event={}", .{"started"}); // FIXME

        // libcurl expects a null terminated string
        try query.append(0);

        return query.toOwnedSlice();
    }

    fn queryAnnounceUrl(self: TorrentFile, url: []const u8, allocator: *std.mem.Allocator) !bencode.ValueTree {
        var queryUrl = try self.buildAnnounceUrl(url, allocator);
        defer allocator.free(queryUrl);

        const host = "lobste.rs";
        const endpoint = "/recent";

        std.debug.warn("Querying {}{}\n", .{ host, endpoint });
        var connection = try std.net.tcpConnectToHost(allocator, host, 80);
        std.debug.warn("Connected to {}\n", .{host});
        defer connection.close();

        try std.fmt.format(connection.writer(), "GET {} HTTP/1.1\r\nHost: {}\r\n\r\n", .{ endpoint, host });

        var response: [1 << 14]u8 = undefined;
        const len = try connection.readAll(response[0..]);
        std.debug.warn("response={}\n", .{response[0..len]});

        var tracker_response = try bencode.ValueTree.parse(response[0..len], allocator);
        return tracker_response;
    }

    fn addUniquePeer(peers: *std.ArrayList(Peer), peer: Peer) !bool {
        for (peers.items) |p| {
            if (p.address.eql(peer.address)) {
                return false;
            }
        }

        try peers.append(peer);
        return true;
    }

    fn addPeersFromTracker(self: TorrentFile, url: []const u8, peers: *std.ArrayList(Peer), allocator: *std.mem.Allocator) !void {
        std.log.notice("Tracker {}: trying to contact...", .{url});
        var tracker_response = try self.queryAnnounceUrl(url, allocator);
        std.log.notice("Tracker {} replied successfuly", .{url});

        var dict_field = tracker_response.root;
        if (!bencode.isObject(dict_field)) return error.InvalidField;
        var dict = dict_field.Object;

        if (bencode.mapLookup(&dict, "failure reason")) |failure_field| {
            if (!bencode.isString(failure_field.*)) return error.InvalidField;

            std.log.warn("Tracker {}: {}", .{ url, failure_field.String });
            return error.TrackerFailure;
        }

        const peers_field = if (bencode.mapLookup(&dict, "peers")) |peers_field| peers_field.* else return error.EmptyPeers;

        switch (peers_field) {
            .String => |peers_compact| {
                if (peers_compact.len == 0) return error.EmptyPeers;
                if (peers_compact.len % 6 != 0) return error.InvalidPeerFormat;

                var i: usize = 0;

                while (i < peers_compact.len) {
                    const ip = [4]u8{
                        peers_compact[i],
                        peers_compact[i + 1],
                        peers_compact[i + 2],
                        peers_compact[i + 3],
                    };

                    const peer_port_s = [2]u8{ peers_compact[i + 4], peers_compact[i + 5] };
                    const peer_port = std.mem.readIntBig(u16, &peer_port_s);

                    const address = std.net.Address.initIp4(ip, peer_port);

                    const peer = try Peer.init(address, allocator);

                    if (try addUniquePeer(peers, peer)) {
                        std.log.notice("Tracker {}: new peer {} total_peers_count={}", .{ url, address, peers.items.len });
                    }

                    i += 6;
                }
            },
            .Array => |*peers_list| {
                for (peers_list.items) |*peer_field| {
                    // TODO: parse peer_id?
                    const ip = if (bencode.mapLookup(&peer_field.Object, "ip")) |ip_field| brk: {
                        if (!bencode.isString(ip_field.*)) return error.InvalidField;
                        break :brk ip_field.String;
                    } else continue;

                    const port = if (bencode.mapLookup(&peer_field.Object, "port")) |port_field| brk: {
                        if (!bencode.isInteger(port_field.*)) return error.InvalidField;
                        break :brk port_field.Integer;
                    } else continue;

                    const address = try std.net.Address.parseIp(ip, @intCast(u16, port));

                    const peer = try Peer.init(address, allocator);
                    if (try addUniquePeer(peers, peer)) {
                        std.log.notice("Tracker {}: new peer {}", .{ url, address });
                    }
                }
            },
            else => return error.InvalidPeerFormat,
        }
    }

    pub fn getPeers(self: TorrentFile, allocator: *std.mem.Allocator) ![]Peer {
        var peers = std.ArrayList(Peer).init(allocator);
        defer peers.deinit();

        const local_address = std.net.Address.initIp4([4]u8{ 0, 0, 0, 0 }, 6881);
        try peers.append(try Peer.init(local_address, allocator)); // FIXME

        // TODO: contact in parallel each tracker, hard with libcurl?
        for (self.announce_urls) |url| {
            self.addPeersFromTracker(url, &peers, allocator) catch |err| {
                std.log.warn("Tracker {}: {}", .{ url, err });
                continue;
            };
        }

        return peers.toOwnedSlice();
    }
};

fn writeCallback(p_contents: *c_void, size: usize, nmemb: usize, p_user_data: *std.ArrayList(u8)) usize {
    const contents = @ptrCast([*c]const u8, p_contents);
    p_user_data.*.appendSlice(contents[0..nmemb]) catch {
        std.process.exit(1);
    };
    return size * nmemb;
}

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

test "parse torrent file with multiple files" {
    var torrent_file = try TorrentFile.parse("", "d8:announce14:http://foo.com4:infod12:piece lengthi1e6:pieces1:04:name3:foo5:filesld6:lengthi20e4:pathl8:test.pdfeeeee", std.testing.allocator);
    std.testing.expectEqual(@as(usize, 20), torrent_file.total_len);

    defer torrent_file.deinit();
}
