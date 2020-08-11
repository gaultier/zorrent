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

pub const PieceStatus = enum(u2) {
    DontHave,
    Requesting,
    Have,
};

pub const Pieces = struct {
    seed: u64,
    prng: std.rand.DefaultPrng,
    remaining_file_offsets: std.ArrayList(usize),
    allocator: *std.mem.Allocator,
    piece_acquire_mutex: std.Mutex, // FIXME: remove, use atomic stack?

    pub fn init(file_len: usize, allocator: *std.mem.Allocator) !Pieces {
        var buf: [8]u8 = undefined;
        try std.crypto.randomBytes(buf[0..]);
        const seed = std.mem.readIntLittle(u64, buf[0..8]);

        var remaining_file_offsets = std.ArrayList(usize).init(allocator);
        try remaining_file_offsets.ensureCapacity(std.math.max(1, file_len / block_len));

        var i: usize = 0;
        while (i < file_len) : (i += block_len) {
            remaining_file_offsets.addOneAssumeCapacity().* = i;
        }
        std.debug.warn("remaining_file_offsets len: {}\n", .{remaining_file_offsets.items.len});

        return Pieces{ .seed = seed, .remaining_file_offsets = remaining_file_offsets, .allocator = allocator, .prng = std.rand.DefaultPrng.init(seed), .piece_acquire_mutex = std.Mutex.init() };
    }

    pub fn deinit(self: *Pieces) void {
        self.piece_acquire_mutex.deinit();
        self.remaining_file_offsets.deinit();
    }

    pub fn acquireFileOffset(self: *Pieces) ?usize {
        var trial: u32 = 0;
        while (trial < 20) : (trial += 1) {
            if (self.piece_acquire_mutex.tryAcquire()) |lock| {
                defer lock.release();
                if (self.remaining_file_offsets.items.len == 0) return null;

                const i = self.prng.random.uintLessThan(usize, self.remaining_file_offsets.items.len);
                const file_offset = self.remaining_file_offsets.items[i];
                _ = self.remaining_file_offsets.swapRemove(i);
                return file_offset;
            }
            std.time.sleep(1_000);
        }
        return null;
    }

    // FIXME: finished iff all pieces arrived (and hash is ok)
    pub fn isFinished(self: *Pieces) bool {
        var trial: u32 = 0;
        while (trial < 20) : (trial += 1) {
            if (self.piece_acquire_mutex.tryAcquire()) |lock| {
                defer lock.release();
                return (self.remaining_file_offsets.items.len == 0);
            }
            std.time.sleep(1_000);
        }
        return false;
    }

    pub fn releaseFileOffset(self: *Pieces, file_offset: usize) void {
        while (true) {
            if (self.piece_acquire_mutex.tryAcquire()) |lock| {
                defer lock.release();

                self.remaining_file_offsets.appendAssumeCapacity(file_offset);
            }
        }
    }
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

pub const handshake_len: usize = 1 + 19 + 8 + 20 + 20;
pub const block_len: usize = 1 << 14;

fn isHandshake(buffer: []const u8) bool {
    return (buffer.len == handshake_len and std.mem.eql(u8, "\x13BitTorrent protocol", buffer[0..20]));
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
        const peer_id: [20]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19 };
        try self.socket.?.writeAll(peer_id[0..]);
    }

    pub fn read(self: *Peer, n: usize) !usize {
        var payload: [block_len]u8 = undefined;
        std.debug.assert(n <= (block_len));

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

    //     pub fn requestFullPiece(self: *Peer, piece_index: u32, piece_len: u32) !void {
    //         var begin: u32 = 0;
    //         while (begin < piece_len) {
    //             try self.requestFragmentOfPiece(piece_index, begin);
    //             begin += 1 << 16;
    //         }
    //     }

    pub fn requestBlock(self: *Peer, piece_index: u32, file_offset: usize, piece_len: u32) !void {
        const payload_len = 1 + 3 * 4;
        var payload: [4 + payload_len]u8 = undefined;
        std.mem.writeIntBig(u32, @ptrCast(*[4]u8, &payload), payload_len);

        const tag: u8 = @enumToInt(MessageId.Request);
        std.mem.writeIntBig(u8, @ptrCast(*[1]u8, &payload[4]), tag);
        std.mem.writeIntBig(u32, @ptrCast(*[4]u8, &payload[5]), piece_index);
        const begin: u32 = @intCast(u32, file_offset - @as(usize, piece_index) * @as(usize, piece_len));
        std.mem.writeIntBig(u32, @ptrCast(*[4]u8, &payload[9]), begin);
        std.mem.writeIntBig(u32, @ptrCast(*[4]u8, &payload[13]), block_len);

        std.debug.warn("{}\tRequest piece #{}_{}\n", .{ self.address, piece_index, begin });
        try self.socket.?.writeAll(payload[0..]);
        std.debug.warn("{}\tRequested piece #{}_{}\n", .{ self.address, piece_index, begin });
    }

    pub fn parseMessage(self: *Peer) !?Message {
        defer self.recv_buffer.shrinkRetainingCapacity(0);
        try self.recv_buffer.appendSlice(&[_]u8{ 0, 0, 0, 0 });

        var read_len = try self.socket.?.readAll(self.recv_buffer.items[0..4]);
        if (read_len == 0) return null;

        const announced_len = std.mem.readIntSliceBig(u32, self.recv_buffer.items[0..4]);
        if (announced_len == 0) return null; // Heartbeat

        if (announced_len > (block_len + 9)) {
            std.debug.warn("{}\tInvalid announced_len: {}\n", .{ self.address, announced_len });
            return error.InvalidAnnouncedLength;
        }

        try self.recv_buffer.resize(announced_len);

        _ = try self.socket.?.readAll(self.recv_buffer.items[0..announced_len]);

        const itag = std.mem.readIntSliceBig(u8, self.recv_buffer.items[0..1]);
        if (itag > @enumToInt(MessageId.Cancel)) return error.MalformedMessage;

        const tag = @intToEnum(MessageId, itag);

        return switch (tag) {
            .Choke => Message.Choke,
            .Unchoke => Message.Unchoke,
            .Interested => Message.Interested,
            .Uninterested => Message.Uninterested,
            .Have => Message{ .Have = std.mem.readIntSliceBig(u32, self.recv_buffer.items[1..5]) },
            .Bitfield => Message{ .Bitfield = try self.allocator.dupe(u8, self.recv_buffer.items[1..announced_len]) },
            .Request => Message{
                .Request = MessageRequest{
                    .index = std.mem.readIntSliceBig(u32, self.recv_buffer.items[1..5]),
                    .begin = std.mem.readIntSliceBig(u32, self.recv_buffer.items[5..9]),
                    .length = std.mem.readIntSliceBig(u32, self.recv_buffer.items[9..13]),
                },
            },
            .Piece => blk: {
                var data = std.ArrayList(u8).init(self.allocator);
                try data.appendSlice(self.recv_buffer.items[9..announced_len]);
                defer data.deinit();

                std.debug.warn("{}\tpiece #{} announced_len={} data_len={}\n", .{ self.address, std.mem.readIntSliceBig(u32, self.recv_buffer.items[5..9]), announced_len, data.items.len });

                break :blk Message{
                    .Piece = MessagePiece{
                        .index = std.mem.readIntSliceBig(u32, self.recv_buffer.items[1..5]),
                        .begin = std.mem.readIntSliceBig(u32, self.recv_buffer.items[5..9]),
                        .data = data.toOwnedSlice(),
                    },
                };
            },
            .Cancel => Message{
                .Cancel = MessageCancel{
                    .index = std.mem.readIntSliceBig(u32, self.recv_buffer.items[1..5]),
                    .begin = std.mem.readIntSliceBig(u32, self.recv_buffer.items[5..9]),
                    .length = std.mem.readIntSliceBig(u32, self.recv_buffer.items[9..13]),
                },
            },
        };
    }

    pub fn handle(self: *Peer, torrent_file: TorrentFile, file_buffer: []align(std.mem.page_size) u8, pieces: *Pieces) !void {
        std.debug.warn("{}\tConnecting\n", .{self.address});
        self.connect() catch |err| {
            switch (err) {
                error.ConnectionTimedOut, error.ConnectionRefused => {
                    std.debug.warn("{}\tFailed ({})\n", .{ self.address, err });
                    return;
                },
                else => return err,
            }
        };
        std.debug.warn("{}\tConnected\n", .{self.address});

        std.debug.warn("{}\tHandshaking\n", .{self.address});
        try self.sendHandshake(torrent_file.hash_info);

        var len: usize = try self.read(handshake_len);
        while (true) {
            if (len >= handshake_len and isHandshake(self.recv_buffer.items[0..handshake_len])) break;

            self.recv_buffer.shrinkRetainingCapacity(0);
            std.time.sleep(1_000_000_000);
            len = try self.read(handshake_len);
        }
        self.recv_buffer.shrinkRetainingCapacity(0);
        std.debug.warn("{}\tHandshaked\n", .{self.address});

        try self.sendInterested();
        try self.sendChoke();

        const pieces_len: usize = torrent_file.pieces.len / 20;
        const blocks_per_piece: usize = torrent_file.piece_len / block_len;
        var choked = true;
        var requests_in_flight: usize = 0;

        while (true) {
            if (pieces.isFinished()) {
                std.debug.warn("{}\tFinished\n", .{self.address});
                return;
            }
            const file_offset = pieces.acquireFileOffset();

            const piece_index: u32 = @intCast(u32, file_offset.? / (pieces_len * block_len));
            std.debug.warn("{}\tfile_offset={} piece_index={} piece_len={} pieces_len={}\n", .{ self.address, file_offset.?, piece_index, torrent_file.piece_len, pieces_len });

            // if (!choked and piece_index < pieces_len) {
            if (requests_in_flight < 20 and piece_index < pieces_len) {
                try self.requestBlock(piece_index, file_offset.?, @intCast(u32, torrent_file.piece_len));
                requests_in_flight += 1;
            }

            const message = self.parseMessage() catch |err| {
                std.debug.warn("{}\tError parsing message: {}\n", .{ self.address, err });
                pieces.releaseFileOffset(file_offset.?);
                return err;
            };

            if (message) |msg| {
                std.debug.warn("{}\tMessage: {}\n", .{ self.address, @tagName(msg) });

                switch (msg) {
                    Message.Unchoke => choked = false,
                    Message.Choke => choked = true,
                    Message.Bitfield => |bitfield| {
                        defer bitfield.deinit();
                        std.debug.warn("{}\tbitfield: ", .{self.address});
                        hexDump(bitfield);
                    },
                    Message.Piece => |piece| {
                        const n = piece.data.len;
                        const start = piece.index * torrent_file.piece_len + piece.begin;

                        // Malformed piece, skip
                        if (piece.index != piece_index or (start + n > file_buffer.len)) {
                            std.debug.warn("{}\tMalformed piece: {}\n", .{ self.address, piece });
                            pieces.releaseFileOffset(file_offset.?);
                            continue;
                        }
                        requests_in_flight -= 1;

                        std.debug.warn("{}\tWriting piece to disk: start={} begin={} len={} total_len={}\n", .{ self.address, start, piece.begin, n, file_buffer.len });
                        std.mem.copy(u8, file_buffer[file_offset.?..], piece.data[0..]);
                        // TODO: check hashes

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
            } else {
                std.time.sleep(500_000_000);
            }
        }
    }
};

pub const DownloadFile = struct {
    fd: c_int,
    data: []align(std.mem.page_size) u8,

    pub fn deinit(self: *DownloadFile) void {
        defer std.os.munmap(self.data);
        defer std.os.close(self.fd);
    }
};

pub const TorrentFile = struct {
    announce_urls: [][]const u8,
    length_bytes_count: usize,
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

        var owned_announce_urls = std.ArrayList([]const u8).init(allocator);
        if (bencode.mapLookup(&value.root.Object, "announce")) |field| {
            const real_url = field.String;
            if (real_url.len >= 7 and std.mem.eql(u8, real_url[0..7], "http://")) {
                try owned_announce_urls.append(try allocator.dupe(u8, field.String));
            }
        }

        if (bencode.mapLookup(&value.root.Object, "announce-list")) |field| {
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
        const pieces = (bencode.mapLookup(&field_info.Object, "pieces") orelse return error.FieldNotFound).String;
        var owned_pieces = std.ArrayList(u8).init(allocator);
        try owned_pieces.appendSlice(pieces);

        const piece_len = (bencode.mapLookup(&field_info.Object, "piece length") orelse return error.FieldNotFound).Integer;

        var file_path: ?[]const u8 = null;
        var file_length: ?isize = null;
        if (bencode.mapLookup(&field_info.Object, "name")) |field| {
            file_path = field.String;
        }
        if (bencode.mapLookup(&field_info.Object, "length")) |field| {
            file_length = field.Integer;
        }

        if (bencode.mapLookup(&field_info.Object, "files")) |field| {
            // FIXME: multi file download
            if (field.Array.items.len > 0) {
                var file_field = field.Array.items[0].Object;
                file_path = (bencode.mapLookup(&file_field, "path") orelse return error.FieldNotFound).Array.items[0].String;
                file_length = (bencode.mapLookup(&file_field, "length") orelse return error.FieldNotFound).Integer;
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
            .announce_urls = owned_announce_urls.toOwnedSlice(),
            .length_bytes_count = @intCast(usize, file_length.?),
            .hash_info = hash,
            .uploadedBytesCount = 0,
            .downloadedBytesCount = 0,
            .leftBytesCount = @intCast(usize, file_length.?),
            .piece_len = @intCast(usize, piece_len),
            .pieces = owned_pieces.toOwnedSlice(),
            .path = owned_file_path.toOwnedSlice(),
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

        try query.append(0);

        return query.toOwnedSlice();
    }

    fn queryAnnounceUrl(self: TorrentFile, url: []const u8, allocator: *std.mem.Allocator) !bencode.ValueTree {
        var queryUrl = try self.buildAnnounceUrl(url, allocator);
        defer allocator.destroy(&queryUrl);

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

        const timeout_seconds: usize = 10;
        curl_res = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_TIMEOUT, timeout_seconds);
        if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
            _ = c.printf("curl_easy_setopt() failed: %s\n", c.curl_easy_strerror(curl_res));
            return error.CurlSetOptFailed;
        }

        const follow_redirect_enabled: usize = 1;
        curl_res = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_FOLLOWLOCATION, follow_redirect_enabled);
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
        std.debug.warn("Tracker {}: trying to contact...\n", .{url});
        var tracker_response = try self.queryAnnounceUrl(url, allocator);
        std.debug.warn("Tracker {} replied successfuly\n", .{url});

        var dict = tracker_response.root.Object;

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

                    var recv_buffer = std.ArrayList(u8).init(allocator);
                    try recv_buffer.ensureCapacity(1 << 16);

                    const peer = Peer{ .address = address, .state = PeerState.Unknown, .socket = null, .recv_buffer = recv_buffer, .allocator = allocator };
                    if (try addUniquePeer(peers, peer)) {
                        std.debug.warn("Tracker {}: new peer {} total_peers_count={}\n", .{ url, address, peers.items.len });
                    }

                    i += 6;
                }
            },
            .Array => |*peers_list| {
                for (peers_list.items) |*peer_field| {
                    // TODO: parse peer_id?
                    const ip = if (bencode.mapLookup(&peer_field.Object, "ip")) |ip_field| ip_field.String else continue;
                    const port = if (bencode.mapLookup(&peer_field.Object, "port")) |port_field| port_field.Integer else continue;
                    std.debug.warn("Tracker {}: ip={} port={}\n", .{ url, ip, port });
                    const address = try std.net.Address.parseIp(ip, @intCast(u16, port));

                    var recv_buffer = std.ArrayList(u8).init(allocator);
                    try recv_buffer.ensureCapacity(1 << 16);
                    const peer = Peer{ .address = address, .state = PeerState.Unknown, .socket = null, .recv_buffer = recv_buffer, .allocator = allocator };
                    if (try addUniquePeer(peers, peer)) {
                        std.debug.warn("Tracker {}: new peer {} total_peers_count={}\n", .{ url, address, peers.items.len });
                    }
                }
            },
            else => return error.InvalidPeerFormat,
        }
    }

    pub fn getPeers(self: TorrentFile, allocator: *std.mem.Allocator) ![]Peer {
        var peers = std.ArrayList(Peer).init(allocator);
        defer peers.deinit();

        // TODO: contact in parallel each tracker, hard with libcurl?
        for (self.announce_urls) |url| {
            self.addPeersFromTracker(url, &peers, allocator) catch |err| {
                std.debug.warn("Tracker {}: {}\n", .{ url, err });
                continue;
            };
        }

        return peers.toOwnedSlice();
    }

    pub fn openMmapFile(self: *TorrentFile) !DownloadFile {
        const fd = try std.os.open(self.path, std.os.O_CREAT | std.os.O_RDWR, 438);
        try std.os.ftruncate(fd, self.length_bytes_count);

        var data = try std.os.mmap(
            null,
            self.length_bytes_count,
            std.os.PROT_READ | std.os.PROT_WRITE,
            std.os.MAP_FILE | std.os.MAP_PRIVATE,
            fd,
            0,
        );

        return DownloadFile{ .fd = fd, .data = data };
    }
};
