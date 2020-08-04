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

const MessageRequest = struct { index: u32, begin: u32, length: u32 };
const MessagePiece = struct { index: u32, begin: u32, data: []const u8 };
const MessageCancel = struct { index: u32, begin: u32, length: u32 };

pub const Message = union(MessageId) {
    Choke: void,
    Unchoke: void,
    Interested: void,
    Uninterested: void,
    Bitfield: []const u8,
    Have: u32,
    Request: MessageRequest,
    Cancel: MessageCancel,
    Piece: MessagePiece,
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
    recv_buffer: std.ArrayList(u8),
    allocator: *std.mem.Allocator,

    pub fn connect(self: *Peer) !void {
        self.socket = try std.net.tcpConnectToAddress(self.address);
    }

    pub fn deinit(self: *Peer) void {
        if (self.socket) |socket| {
            socket.close();
        }
        self.recv_buffer.deinit();
    }

    pub fn sendHandshake(self: *Peer, hash_info: [20]u8) !void {
        const handshake_payload = "\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00";
        try self.socket.?.writeAll(handshake_payload);
        try self.socket.?.writeAll(hash_info[0..]);
        try self.sendPeerId();
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

    pub fn sendPeerId(self: *Peer) !void {
        const remote_peer_id = "\x00" ** 20;
        try self.socket.?.writeAll(remote_peer_id[0..]);
    }

    pub fn read(self: *Peer, n: usize) !usize {
        var payload: [1 << 14]u8 = undefined;
        std.debug.assert(n <= (1 << 14));

        const len = self.socket.?.read(payload[0..n]) catch |err| {
            std.debug.warn("{}\t{}\n", .{ self.address, err });
            switch (err) {
                error.ConnectionResetByPeer => {
                    return 0;
                },
                else => return err,
            }
        };

        try self.recv_buffer.appendSlice(payload[0..len]);

        return len;
    }

    pub fn requestFullPiece(self: *Peer, piece_index: u32, piece_len: u32) !void {
        var begin: u32 = 0;
        while (begin < piece_len) {
            try self.requestFragmentOfPiece(piece_index, begin);
            begin += 1 << 16;
        }
    }

    pub fn requestFragmentOfPiece(self: *Peer, piece_index: u32, piece_begin: u32) !void {
        const payload_len = 1 + 3 * 4;
        var payload: [4 + payload_len]u8 = undefined;
        std.mem.writeIntBig(u32, @ptrCast(*[4]u8, &payload), payload_len);

        const tag: u8 = @enumToInt(MessageId.Request);
        std.mem.writeIntBig(u8, @ptrCast(*[1]u8, &payload[4]), tag);
        std.mem.writeIntBig(u32, @ptrCast(*[4]u8, &payload[5]), piece_index);
        std.mem.writeIntBig(u32, @ptrCast(*[4]u8, &payload[9]), piece_begin);
        const piece_len: u32 = 1 << 14;
        std.mem.writeIntBig(u32, @ptrCast(*[4]u8, &payload[13]), piece_len);

        std.debug.warn("{}\tRequest piece #{}_{}\n", .{ self.address, piece_index, piece_begin });
        try self.socket.?.writeAll(payload[0..]);
        std.debug.warn("{}\tRequested piece #{}_{}\n", .{ self.address, piece_index, piece_begin });
    }

    pub fn parseMessage(self: *Peer) !?Message {
        var recv_buffer: [1 << 15]u8 = undefined;

        var read_len = try self.socket.?.readAll(recv_buffer[0..4]);
        if (read_len == 0) return null;

        const announced_len = std.mem.readIntSliceBig(u32, recv_buffer[0..4]);
        if (announced_len > (1 << 14 + 9)) return error.AnnouncedLengthTooBig;

        _ = try self.socket.?.readAll(recv_buffer[4 .. announced_len + 4]);

        const itag = std.mem.readIntSliceBig(u8, recv_buffer[4..5]);
        if (itag > @enumToInt(MessageId.Cancel)) return error.MalformedMessage;

        const tag = @intToEnum(MessageId, itag);

        return switch (tag) {
            .Choke => Message.Choke,
            .Unchoke => Message.Unchoke,
            .Interested => Message.Interested,
            .Uninterested => Message.Uninterested,
            .Have => Message{ .Have = std.mem.readIntSliceBig(u32, recv_buffer[5..9]) },
            .Bitfield => Message{ .Bitfield = recv_buffer[5..] }, // FIXME:segfault
            .Request => Message{
                .Request = MessageRequest{
                    .index = std.mem.readIntSliceBig(u32, recv_buffer[5..9]),
                    .begin = std.mem.readIntSliceBig(u32, recv_buffer[9..13]),
                    .length = std.mem.readIntSliceBig(u32, recv_buffer[13..17]),
                },
            },
            .Piece => blk: {
                var data = std.ArrayList(u8).init(self.allocator);
                try data.appendSlice(recv_buffer[13 .. 4 + announced_len]);
                defer data.deinit();

                std.debug.warn("{}\tpiece #{} announced_len={} data_len={}\n", .{ self.address, std.mem.readIntSliceBig(u32, recv_buffer[5..9]), announced_len, data.items.len });

                break :blk Message{
                    .Piece = MessagePiece{
                        .index = std.mem.readIntSliceBig(u32, recv_buffer[5..9]),
                        .begin = std.mem.readIntSliceBig(u32, recv_buffer[9..13]),
                        .data = data.toOwnedSlice(),
                    },
                };
            },
            .Cancel => Message{
                .Cancel = MessageCancel{
                    .index = std.mem.readIntSliceBig(u32, recv_buffer[5..9]),
                    .begin = std.mem.readIntSliceBig(u32, recv_buffer[9..13]),
                    .length = std.mem.readIntSliceBig(u32, recv_buffer[13..17]),
                },
            },
        };
    }

    pub fn handle(self: *Peer, torrent_file: TorrentFile, file_buffer: []align(std.mem.page_size) u8, file_mutex: *std.Mutex) !void {
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

        var len: usize = 0;
        while (!isHandshake(self.recv_buffer.items[0..])) {
            len = try self.read(500);
            if (len > 0) {
                std.debug.warn("{}\tNot-handshake message: ", .{self.address});
                hexDump(self.recv_buffer.items[0..]);
            }
            std.time.sleep(1_000_000_000);
        }
        std.debug.warn("{}\tHandshaked\n", .{self.address});

        // Ignore message before handshake
        try self.recv_buffer.resize(0);

        try self.sendInterested();
        try self.sendChoke();

        var piece_index: u32 = 0;
        // try std.crypto.randomBytes(@ptrCast(*[4]u8, &piece_index));

        const pieces_len: usize = torrent_file.pieces.len / 20;
        while (true) {
            if (piece_index < pieces_len) {
                try self.requestFullPiece(piece_index, @intCast(u32, torrent_file.piece_len));
                piece_index += 1;
            }
            const message = self.parseMessage() catch |err| {
                std.debug.warn("{}\tError parsing message: {}\n", .{ self.address, err });
                return err;
            };

            if (message) |msg| {
                std.debug.warn("{}\tMessage: {}\n", .{ self.address, @tagName(msg) });

                switch (msg) {
                    Message.Piece => |piece| {
                        const n = piece.data.len;
                        const start = piece.index * (1 << 14) + piece.begin; // FIXME
                        std.debug.warn("{}\tWriting piece to disk: start={} begin={} len={} total_len={}\n", .{ self.address, start, piece.begin, n, file_buffer.len });
                        while (true) {
                            if (file_mutex.tryAcquire()) |lock| {
                                defer lock.release();
                                std.mem.copy(u8, file_buffer[0..], piece.data[0..]);
                                break;
                            }
                        }
                        // const expected_hash = torrent_file.pieces[piece.index * 20 .. (piece.index + 1) * 20];
                        // var actual_hash: [20]u8 = undefined;
                        // std.crypto.Sha1.hash(piece.data[0..], actual_hash[0..]);
                        // const matching_hash = std.mem.eql(u8, actual_hash[0..20], expected_hash[0..20]);

                        // std.debug.warn("{}\tpiece #{} data_len={} actual_hash=", .{
                        //     self.address,
                        //     piece.index,
                        //     piece.data.len,
                        // });
                        // hexDump(actual_hash[0..20]);
                        // std.debug.warn("{}\tpiece #{} expected_hash=", .{ self.address, piece.index });
                        // hexDump(expected_hash[0..20]);
                        // std.debug.warn("{}\tpiece #{} matching_hash={}\n", .{
                        //     self.address,
                        //     piece.index,
                        //     matching_hash,
                        // });
                    },
                    else => {},
                }
            }
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
    path: []const u8,

    pub fn parse(path: []const u8, allocator: *std.mem.Allocator) !TorrentFile {
        // TODO: decide if we copy the memory from the ValueTree, or if we keep a reference to it
        var file = try std.fs.cwd().openFile(path, std.fs.File.OpenFlags{ .read = true });
        defer file.close();

        const content = try file.readAllAlloc(allocator, (try file.stat()).size, std.math.maxInt(usize));

        var value = try bencode.ValueTree.parse(content, allocator);
        defer value.deinit();

        const announce = (bencode.mapLookup(&value.root.Object, "announce") orelse return error.FieldNotFound).String;

        const field_info = bencode.mapLookup(&value.root.Object, "info") orelse return error.FieldNotFound;
        const pieces = (bencode.mapLookup(&field_info.Object, "pieces") orelse return error.FieldNotFound).String;
        var owned_pieces = std.ArrayList(u8).init(allocator);
        try owned_pieces.appendSlice(pieces);

        const piece_len = (bencode.mapLookup(&field_info.Object, "piece length") orelse return error.FieldNotFound).Integer;

        const length = (bencode.mapLookup(&field_info.Object, "length") orelse return error.FieldNotFound).Integer;

        var file_path: ?[]const u8 = null;
        var info_name_field: ?*bencode.Value = bencode.mapLookup(&field_info.Object, "name");
        if (info_name_field) |field| {
            file_path = field.String;
        }

        // FIXME
        if (file_path == null) {
            if (bencode.mapLookup(&field_info.Object, "files")) |field| {
                if (field.Array.items.len > 0) file_path = field.Array.items[0].String;
            }
        }

        var owned_file_path = std.ArrayList(u8).init(allocator);
        try owned_file_path.appendSlice(file_path.?);

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
            .pieces = owned_pieces.toOwnedSlice(),
            .path = owned_file_path.toOwnedSlice(),
        };
    }

    fn buildAnnounceUrl(self: TorrentFile, allocator: *std.mem.Allocator) ![]const u8 {
        var query = std.ArrayList(u8).init(allocator);
        defer query.deinit();

        try query.appendSlice(self.announce);
        try query.appendSlice("?info_hash=");

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

            var recv_buffer = std.ArrayList(u8).init(allocator);
            try recv_buffer.ensureCapacity(1 << 16);

            try peers.append(Peer{ .address = address, .state = PeerState.Unknown, .socket = null, .recv_buffer = recv_buffer, .allocator = allocator });

            i += 6;
        }

        std.debug.assert(peers.items.len > 0);

        return peers.toOwnedSlice();
    }

    pub fn openMmapFile(self: *TorrentFile) ![]align(std.mem.page_size) u8 {
        std.debug.warn("path={} lengthBytesCount={}\n", .{ self.path, self.lengthBytesCount });
        const fd = try std.os.open(self.path, std.os.O_CREAT | std.os.O_RDWR, 438);
        try std.os.ftruncate(fd, self.lengthBytesCount);
        // FIXME
        // defer std.os.close(fd);
        return try std.os.mmap(
            null,
            self.lengthBytesCount,
            std.os.PROT_READ | std.os.PROT_WRITE,
            std.os.MAP_FILE | std.os.MAP_PRIVATE,
            fd,
            0,
        );
    }
};
