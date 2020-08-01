const std = @import("std");
const c = @cImport(@cInclude("curl/curl.h"));
const bencode = @import("zig-bencode");

fn writeCallback(p_contents: *c_void, size: usize, nmemb: usize, p_user_data: *std.ArrayList(u8)) usize {
    const contents = @ptrCast([*c]const u8, p_contents);
    p_user_data.*.appendSlice(contents[0..nmemb]) catch {
        std.process.exit(1);
    };
    return size * nmemb;
}

pub fn hexDump(bytes: []const u8) void {
    for (bytes) |b| {
        std.debug.warn("{X:0<2} ", .{b});
    }
    std.debug.warn("\n", .{});
}

pub const MessageId = enum(u8) {
    Choke = 0,
    Unchoke = 1,
    Interested = 2,
    Uninterested = 3,
    Have = 4,
    Bitfield = 5,
    Request = 6,
    Piece = 7,
    Cancel = 8,
};

pub const Message = union(MessageId) {
    Choke: void,
    Unchoke: void,
    Interested: void,
    Uninterested: void,
    Bitfield: []const u8,
    Have: u32,
    Request: [3]u32,
    Cancel: [3]u32,
    Piece: [3]u32,
};

pub const PeerState = enum {
    Unknown,
    Connected,
    SentHandshake,
    Handshaked,
    ReadyToReceivePieces,
    Down,
};

fn isHandshake(buffer: []const u8) bool {
    return (buffer.len >= 19 and std.mem.eql(u8, "\x13BitTorrent protocol", buffer[0..20]));
}

pub const Peer = struct {
    address: std.net.Address,
    state: PeerState,
    socket: ?std.fs.File,

    pub fn connect(self: *Peer) !void {
        self.socket = try std.net.tcpConnectToAddress(self.address);
    }

    pub fn deinit(self: *Peer) void {
        if (self.socket) |socket| {
            socket.close();
        }
    }

    pub fn sendHandshake(self: *Peer, hash_info: [20]u8) !void {
        const handshake_payload = "\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00";
        try self.socket.?.writeAll(handshake_payload);
        try self.socket.?.writeAll(hash_info[0..]);
    }

    pub fn sendInterested(self: *Peer) !void {
        var msg: [5]u8 = undefined;

        std.mem.writeIntBig(u32, @ptrCast(*[4]u8, &msg), 1);
        std.mem.writeIntBig(u8, @ptrCast(*[1]u8, &msg[4]), @enumToInt(MessageId.Interested));
        try self.socket.?.writeAll(msg[0..]);
    }

    pub fn sendChoke(self: *Peer) !void {
        var msg: [5]u8 = undefined;

        std.mem.writeIntBig(u32, @ptrCast(*[4]u8, &msg), 1);
        std.mem.writeIntBig(u8, @ptrCast(*[1]u8, &msg[4]), @enumToInt(MessageId.Choke));
        try self.socket.?.writeAll(msg[0..]);
    }

    // pub fn sendPeerId(self: *Peer) !void {
    //     const remote_peer_id = "\x00" ** 20;
    //     try self.socket.?.writeAll(remote_peer_id[0..]);
    // }

    pub fn read(self: *Peer, response: *[1 << 14]u8) !usize {
        const len = self.socket.?.read(response.*[0..]) catch |err| {
            // defer self.deinit();
            switch (err) {
                error.ConnectionResetByPeer => {
                    return 0;
                },
                else => return err,
            }
        };
        return len;
    }

    pub fn requestPiece(self: *Peer, piece_index: u32) !void {
        const length: u32 = 1 << 14;
        const begin = 0; //piece_index * length;

        var payload: [17]u8 = undefined;
        const payload_len = 1 + 3 * 4;
        std.mem.writeIntBig(u32, @ptrCast(*[4]u8, &payload), payload_len);

        const tag: u8 = @enumToInt(MessageId.Request);
        std.mem.writeIntBig(u8, @ptrCast(*[1]u8, &payload[4]), tag);
        std.mem.writeIntBig(u32, @ptrCast(*[4]u8, &payload[5]), piece_index);
        std.mem.writeIntBig(u32, @ptrCast(*[4]u8, &payload[9]), begin);
        std.mem.writeIntBig(u32, @ptrCast(*[4]u8, &payload[13]), length);

        std.debug.warn("{}\tRequest piece #{}\n", .{ self.address, piece_index });
        // hexDump(payload[0..]);
        try self.socket.?.writeAll(payload[0..]);
        std.debug.warn("{}\tRequested piece #{}\n", .{ self.address, piece_index });
    }

    pub fn parseMessage(self: *Peer, payload: []const u8, allocator: *std.mem.Allocator) ![]Message {
        if (payload.len < 5) return error.MalformedMessage;

        // std.debug.warn("{}\tParsing message: ", .{self.address});
        // hexDump(payload);

        var parse_len = payload.len;

        var messages = std.ArrayList(Message).init(allocator);
        defer messages.deinit();

        while (parse_len > 0) {
            const len = std.mem.readIntSliceBig(u32, payload[0..4]);
            std.debug.warn("{}\tparse_len={} payload.len={} len={}\n", .{ self.address, parse_len, payload.len, len });
            parse_len -= (4 + len);
            const itag = std.mem.readIntSliceBig(u8, payload[4..5]);
            if (itag > @enumToInt(MessageId.Cancel)) return error.MalformedMessage;

            const tag = @intToEnum(MessageId, itag);

            if (payload.len < 4 + len) return error.MalformedMessage;

            const message: Message = switch (tag) {
                .Choke => Message.Choke,
                .Unchoke => Message.Unchoke,
                .Interested => Message.Interested,
                .Uninterested => Message.Uninterested,
                .Have => Message{ .Have = std.mem.readIntSliceBig(u32, payload[4..]) },
                .Bitfield => Message{ .Bitfield = payload[4..] },
                .Request => Message{
                    .Request = [3]u32{
                        std.mem.readIntSliceBig(u32, payload[4..]),
                        std.mem.readIntSliceBig(u32, payload[8..]),
                        std.mem.readIntSliceBig(u32, payload[12..]),
                    },
                },
                .Piece => Message{
                    .Piece = [3]u32{
                        std.mem.readIntSliceBig(u32, payload[4..]),
                        std.mem.readIntSliceBig(u32, payload[8..]),
                        std.mem.readIntSliceBig(u32, payload[12..]),
                    },
                },
                .Cancel => Message{
                    .Cancel = [3]u32{
                        std.mem.readIntSliceBig(u32, payload[4..]),
                        std.mem.readIntSliceBig(u32, payload[8..]),
                        std.mem.readIntSliceBig(u32, payload[12..]),
                    },
                },
            };
            try messages.append(message);
        }

        return messages.toOwnedSlice();
    }

    pub fn handle(self: *Peer, torrent_file: TorrentFile, allocator: *std.mem.Allocator) !void {
        std.debug.warn("{}\tConnecting\n", .{self.address});
        self.connect() catch |err| {
            switch (err) {
                error.ConnectionTimedOut, error.ConnectionRefused => {
                    std.debug.warn("{}\tFailed ({})\n", .{ self.address, err });
                    // self.deinit();
                    return;
                },
                else => return err,
            }
        };
        std.debug.warn("{}\tConnected\n", .{self.address});

        std.debug.warn("{}\tHandshaking\n", .{self.address});
        try self.sendHandshake(torrent_file.hash_info);

        var response = try allocator.create([1 << 14]u8);
        defer allocator.destroy(response);

        var len: usize = 0;
        while (!isHandshake(response[0..len])) {
            len = try self.read(response);
            std.debug.warn("{}\tNot-handshake message: ", .{self.address});
            hexDump(response[0..len]);

            std.time.sleep(1_000_000_000);
        }
        std.debug.warn("{}\tHandshaked\n", .{self.address});
        // try self.sendPeerId();
        try self.sendInterested();
        try self.sendChoke();

        var piece_index: u32 = 0x410;
        // try std.crypto.randomBytes(@ptrCast(*[4]u8, &piece_index));
        try self.requestPiece(piece_index);

        // const pieces_len: usize = torrent_file.pieces.len / 20;
        while (true) {
            // if (piece_index == 0) {
            //     try self.requestPiece(piece_index);
            //     piece_index += 1;
            // } else {
            len = try self.read(response);
            if (len > 0) {
                const msgs = self.parseMessage(response[0..len], allocator) catch |err| {
                    std.debug.warn("{}\tError parsing message: {}\n", .{ self.address, err });
                    return err;
                };
                defer allocator.destroy(&msgs);

                for (msgs) |msg| {
                    std.debug.warn("{}\tMessage: {}\n", .{ self.address, msg });
                }
            } else {
                std.debug.warn("{}\t.\n", .{self.address});
                std.time.sleep(1_000_000_000);
            }
            // }
        }
    }
};

pub const TorrentFile = struct {
    announce: []const u8,
    lengthBytesCount: usize,
    hash_info: [20]u8,
    downloadedBytesCount: usize,
    uploadedBytesCount: usize,
    leftBytesCount: usize,
    pieces: []const u8,
    piece_len: usize,

    pub fn parse(path: []const u8, allocator: *std.mem.Allocator) !TorrentFile {
        var file = try std.fs.cwd().openFile(path, std.fs.File.OpenFlags{ .read = true });
        defer file.close();

        const content = try file.readAllAlloc(allocator, (try file.stat()).size, std.math.maxInt(usize));

        var value = try bencode.ValueTree.parse(content, allocator);
        defer value.deinit();

        const announce = (bencode.mapLookup(&value.root.Object, "announce") orelse return error.FieldNotFound).String;

        const field_info = bencode.mapLookup(&value.root.Object, "info") orelse return error.FieldNotFound;
        const pieces = (bencode.mapLookup(&field_info.Object, "pieces") orelse return error.FieldNotFound).String;
        const piece_len = (bencode.mapLookup(&field_info.Object, "piece length") orelse return error.FieldNotFound).Integer;

        const length = (bencode.mapLookup(&field_info.Object, "length") orelse return error.FieldNotFound).Integer;

        var field_info_bencoded = std.ArrayList(u8).init(allocator);
        defer field_info_bencoded.deinit();
        try field_info.stringifyValue(field_info_bencoded.writer());

        var hash: [20]u8 = undefined;
        std.crypto.Sha1.hash(field_info_bencoded.items, hash[0..]);

        return TorrentFile{
            .announce = announce,
            .lengthBytesCount = @intCast(usize, length),
            .hash_info = hash,
            .uploadedBytesCount = 0,
            .downloadedBytesCount = 0,
            .leftBytesCount = @intCast(usize, length),
            .piece_len = @intCast(usize, piece_len),
            .pieces = pieces,
        };
    }

    fn buildAnnounceUrl(self: TorrentFile, allocator: *std.mem.Allocator) ![]const u8 {
        var query = std.ArrayList(u8).init(allocator);
        defer query.deinit();

        try query.appendSlice("OpenBSD.somedomain.net:6969/announce?info_hash=");

        for (self.hash_info) |byte| {
            try std.fmt.format(query.writer(), "%{X:0<2}", .{byte});
        }

        var peer_id: [20]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19 };
        // try std.crypto.randomBytes(peer_id[0..]);

        try query.appendSlice("&peer_id=");
        for (peer_id) |byte| {
            try std.fmt.format(query.writer(), "%{X:0<2}", .{byte});
        }

        const port: u16 = 6881;
        try std.fmt.format(query.writer(), "&port={}", .{port});

        try std.fmt.format(query.writer(), "&uploaded={}", .{self.uploadedBytesCount});

        const downloaded = 0;
        try std.fmt.format(query.writer(), "&downloaded={}", .{self.downloadedBytesCount});

        try std.fmt.format(query.writer(), "&left={}", .{self.leftBytesCount});

        try std.fmt.format(query.writer(), "&event={}", .{"started"}); // FIXME

        try query.append(0);

        return query.toOwnedSlice();
    }

    fn queryAnnounceUrl(self: TorrentFile, allocator: *std.mem.Allocator) !bencode.ValueTree {
        var queryUrl = try self.buildAnnounceUrl(allocator);
        defer allocator.destroy(&queryUrl);

        std.debug.warn("queryUrl=`{}`\n", .{queryUrl}); // TODO: rm

        var curl_res: c.CURLcode = undefined;
        curl_res = c.curl_global_init(c.CURL_GLOBAL_ALL);
        if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
            _ = c.printf("curl_global_init() failed: %s\n", c.curl_easy_strerror(curl_res));
            return error.CurlInitFailed;
        }
        defer c.curl_global_cleanup();

        var curl: ?*c.CURL = null;
        var headers: [*c]c.curl_slist = null;

        curl = c.curl_easy_init() orelse {
            _ = c.printf("curl_easy_init() failed: %s\n", c.curl_easy_strerror(curl_res));
            return error.CurlInitFailed;
        };
        defer c.curl_easy_cleanup(curl);

        // url
        curl_res = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_URL, @ptrCast([*:0]const u8, queryUrl));
        if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
            _ = c.printf("curl_easy_setopt() failed: %s\n", c.curl_easy_strerror(curl_res));
            return error.CurlSetOptFailed;
        }

        curl_res = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_WRITEFUNCTION, writeCallback);
        if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
            _ = c.printf("curl_easy_setopt() failed: %s\n", c.curl_easy_strerror(curl_res));
            return error.CurlSetOptFailed;
        }

        var res_body = std.ArrayList(u8).init(allocator);
        curl_res = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_WRITEDATA, &res_body);
        if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
            _ = c.printf("curl_easy_setopt() failed: %s\n", c.curl_easy_strerror(curl_res));
            return error.CurlSetOptFailed;
        }

        // perform the call
        curl_res = c.curl_easy_perform(curl);
        if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
            _ = c.printf("curl_easy_perform() failed: %s\n", c.curl_easy_strerror(curl_res));
            return error.CurlPerform;
        }

        var tracker_response = try bencode.ValueTree.parse(res_body.items[0..], allocator);
        return tracker_response;
    }

    pub fn getPeers(self: TorrentFile, allocator: *std.mem.Allocator) ![]Peer {
        const tracker_response = try self.queryAnnounceUrl(allocator);
        var dict = tracker_response.root.Object;
        // TODO: support non compact format i.e. a list of strings
        const peers_compact = bencode.mapLookup(&dict, "peers").?.String;

        std.debug.assert(peers_compact.len % 6 == 0);

        var i: usize = 0;
        var peers = std.ArrayList(Peer).init(allocator);
        defer peers.deinit();

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

            try peers.append(Peer{ .address = address, .state = PeerState.Unknown, .socket = null });

            i += 6;
        }

        std.debug.assert(peers.items.len > 0);

        return peers.toOwnedSlice();
    }
};
