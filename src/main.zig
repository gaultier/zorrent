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
    prng: std.rand.DefaultPrng,
    want_blocks_bitfield: std.ArrayList(u8),
    allocator: *std.mem.Allocator,
    piece_acquire_mutex: std.Mutex,
    initial_want_block_count: usize,
    have_block_count: std.atomic.Int(usize),
    want_block_count: std.atomic.Int(usize),

    pub fn init(file_len: usize, allocator: *std.mem.Allocator) !Pieces {
        var buf: [8]u8 = undefined;
        try std.crypto.randomBytes(buf[0..]);
        const seed = std.mem.readIntLittle(u64, buf[0..8]);

        var want_blocks_bitfield = std.ArrayList(u8).init(allocator);
        // Div ceil
        const initial_want_block_count: usize = 1 + ((file_len - 1) / block_len);
        // Div ceil
        try want_blocks_bitfield.appendNTimes(0xff, 1 + ((initial_want_block_count - 1) / 8));

        return Pieces{
            .want_blocks_bitfield = want_blocks_bitfield,
            .allocator = allocator,
            .prng = std.rand.DefaultPrng.init(seed),
            .piece_acquire_mutex = std.Mutex{},
            .have_block_count = std.atomic.Int(usize).init(0),
            .want_block_count = std.atomic.Int(usize).init(initial_want_block_count),
            .initial_want_block_count = initial_want_block_count,
        };
    }

    pub fn deinit(self: *Pieces) void {
        self.piece_acquire_mutex.deinit();
        self.want_blocks_bitfield.deinit();
    }

    pub fn acquireFileOffset(self: *Pieces, remote_have_file_offsets_bitfield: []const u8) ?usize {
        std.debug.assert(!self.isFinished());

        var trial: u32 = 0;
        while (trial < 20) : (trial += 1) {
            if (self.piece_acquire_mutex.tryAcquire()) |lock| {
                defer lock.release();
                std.debug.warn("want={X} | have={X}\n", .{ self.want_blocks_bitfield.items, remote_have_file_offsets_bitfield });

                for (self.want_blocks_bitfield.items) |*want, i| {
                    if (want.* == 0) continue;
                    const remote = self.want_blocks_bitfield.items[i];
                    if ((want.* & remote) == 0) continue;

                    const bit: u3 = @intCast(u3, @ctz(u8, want.* & remote));
                    const file_offset = block_len * i * 8 + block_len * bit;
                    // Clear bit
                    want.* &= std.mem.nativeToBig(u8, ~(@as(u8, 1) << bit));

                    _ = self.want_block_count.decr();

                    std.log.debug(.zorrent_lib, "acquireFileOffset: overlap={} bit={} i={} file_offset={}", .{ want.* & remote, bit, i, file_offset });
                    return file_offset;
                }
            }
            std.time.sleep(1_000);
        }
        return null;
    }

    pub fn commitFileOffset(self: *Pieces, file_offset: usize) void {
        _ = self.have_block_count.incr();
    }

    // TODO: check hash
    pub fn isFinished(self: *Pieces) bool {
        return self.initial_want_block_count == self.have_block_count.get();
    }

    pub fn releaseFileOffset(self: *Pieces, file_offset: usize) void {
        while (true) {
            if (self.piece_acquire_mutex.tryAcquire()) |lock| {
                defer lock.release();

                const i: usize = file_offset / block_len;
                const bit: u3 = @intCast(u3, i % 8);
                // Set bit to 1
                self.want_blocks_bitfield.items[i] |= std.mem.nativeToBig(u8, @as(u8, 1) << bit);
                _ = self.want_block_count.incr();
            }
        }
    }

    pub fn displayStats(self: *Pieces) void {
        const have: usize = self.have_block_count.get();
        const want: usize = self.want_block_count.get();
        const total: usize = want + have;

        std.debug.assert(total == self.initial_want_block_count);

        std.log.info(.zorrent_lib, "[Have/Remaining/Total/Size/Total size: {}/{}/{}/{Bi:.2}/{Bi:.2}] {d:.2}%", .{ have, want, total, have * block_len, self.initial_want_block_count * block_len, @intToFloat(f32, have) / @intToFloat(f32, total) * 100.0 });
        return;
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

pub const handshake_len: usize = 1 + 19 + 8 + 20 + 20;
pub const block_len: usize = 1 << 14;

fn isHandshake(buffer: []const u8) bool {
    return (buffer.len == handshake_len and std.mem.eql(u8, "\x13BitTorrent protocol", buffer[0..20]));
}

fn isPieceHashValid(piece: usize, piece_data: []const u8, hashes: []const u8) bool {
    const expected_hash = hashes[piece * 20 .. (piece + 1) * 20];
    var actual_hash: [20]u8 = undefined;
    std.crypto.Sha1.hash(piece_data[0..], actual_hash[0..]);
    const identical = std.mem.eql(u8, actual_hash[0..20], expected_hash[0..20]);

    std.log.debug(.zorrent_lib, "isPieceHashValid: piece={} actual_hash={X} expected_hash={X} matching_hash={}", .{ piece, actual_hash, expected_hash, identical });
    return identical;
}

pub const Peer = struct {
    address: std.net.Address,
    socket: ?std.fs.File,
    recv_buffer: std.ArrayList(u8),
    allocator: *std.mem.Allocator,

    pub fn init(address: std.net.Address, allocator: *std.mem.Allocator) !Peer {
        var recv_buffer = std.ArrayList(u8).init(allocator);
        try recv_buffer.ensureCapacity(1 << 16);
        return Peer{ .address = address, .socket = null, .recv_buffer = recv_buffer, .allocator = allocator };
    }

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

        std.log.notice(.zorrent_lib, "{}\tInterested", .{self.address});
    }

    pub fn sendChoke(self: *Peer) !void {
        var msg: [5]u8 = undefined;

        std.mem.writeIntBig(u32, @ptrCast(*[4]u8, &msg), 1);
        std.mem.writeIntBig(u8, @ptrCast(*[1]u8, &msg[4]), @enumToInt(MessageId.Choke));
        try self.socket.?.writeAll(msg[0..]);

        std.log.notice(.zorrent_lib, "{}\tChoke", .{self.address});
    }

    pub fn sendPeerId(self: *Peer) !void {
        const peer_id: [20]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19 };
        try self.socket.?.writeAll(peer_id[0..]);
    }

    pub fn read(self: *Peer, n: usize) !usize {
        var payload: [block_len]u8 = undefined;
        std.debug.assert(n <= (block_len));

        const len = self.socket.?.read(payload[0..n]) catch |err| {
            std.log.err(.zorrent_lib, "{}\t{}", .{ self.address, err });
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

    pub fn requestBlock(self: *Peer, file_offset: usize, piece_len: u32, total_len: usize) !void {
        const piece: u32 = @intCast(u32, file_offset / piece_len);
        const begin: u32 = @intCast(u32, file_offset - @as(usize, piece) * @as(usize, piece_len));
        const len = @intCast(u32, std.math.min(block_len, total_len - (piece * piece_len + begin)));

        const payload_len = 1 + 3 * 4;
        var payload: [4 + payload_len]u8 = undefined;
        std.mem.writeIntBig(u32, @ptrCast(*[4]u8, &payload), payload_len);

        const tag: u8 = @enumToInt(MessageId.Request);
        std.mem.writeIntBig(u8, @ptrCast(*[1]u8, &payload[4]), tag);
        std.mem.writeIntBig(u32, @ptrCast(*[4]u8, &payload[5]), piece);
        std.mem.writeIntBig(u32, @ptrCast(*[4]u8, &payload[9]), begin);
        std.mem.writeIntBig(u32, @ptrCast(*[4]u8, &payload[13]), len);

        try self.socket.?.writeAll(payload[0..]);
        std.log.debug(.zorrent_lib, "{}\tRequest piece: index={} begin={} file_offset={} piece_len={} block_len={}", .{ self.address, piece, begin, file_offset, piece_len, len });
    }

    pub fn parseMessage(self: *Peer) !?Message {
        defer self.recv_buffer.shrinkRetainingCapacity(0);
        try self.recv_buffer.appendSlice(&[_]u8{ 0, 0, 0, 0 });

        var read_len = try self.socket.?.readAll(self.recv_buffer.items[0..4]);
        if (read_len == 0) return null;

        const announced_len = std.mem.readIntSliceBig(u32, self.recv_buffer.items[0..4]);
        if (announced_len == 0) {
            std.log.notice(.zorrent_lib, "{}\tHeartbeat", .{self.address});
            return null;
        }

        if (announced_len > (block_len + 9)) {
            std.log.err(.zorrent_lib, "{}\tInvalid announced_len: {}", .{ self.address, announced_len });
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
            .Bitfield => Message{ .Bitfield = try self.allocator.dupe(u8, self.recv_buffer.items[1..]) },
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
        std.log.notice(.zorrent_lib, "{}\tConnecting", .{self.address});
        self.connect() catch |err| {
            switch (err) {
                error.ConnectionTimedOut, error.ConnectionRefused => {
                    std.log.err(.zorrent_lib, "{}\tFailed ({})", .{ self.address, err });
                    return;
                },
                else => return err,
            }
        };
        std.log.notice(.zorrent_lib, "{}\tConnected", .{self.address});

        std.log.notice(.zorrent_lib, "{}\tHandshaking", .{self.address});
        try self.sendHandshake(torrent_file.hash_info);

        var len: usize = try self.read(handshake_len);
        while (true) {
            if (len >= handshake_len and isHandshake(self.recv_buffer.items[0..handshake_len])) break;

            self.recv_buffer.shrinkRetainingCapacity(0);
            std.time.sleep(1_000_000_000);
            len = try self.read(handshake_len);
        }
        self.recv_buffer.shrinkRetainingCapacity(0);
        std.log.notice(.zorrent_lib, "{}\tHandshaked", .{self.address});

        try self.sendInterested();
        try self.sendChoke();

        const pieces_len: usize = torrent_file.pieces.len / 20;
        const blocks_per_piece: usize = torrent_file.piece_len / block_len;
        var choked = true;
        var file_offset_opt: ?usize = null;

        var remote_have_pieces_bitfield = std.ArrayList(u8).init(self.allocator);
        const initial_want_block_count: usize = torrent_file.total_len / block_len;
        // TODO: deal with padding bytes?
        try remote_have_pieces_bitfield.appendNTimes(0, pieces.initial_want_block_count);
        defer remote_have_pieces_bitfield.deinit();

        var remote_have_file_offsets_bitfield = std.ArrayList(u8).init(self.allocator);
        try remote_have_file_offsets_bitfield.appendNTimes(0, pieces.want_blocks_bitfield.items.len);
        defer remote_have_file_offsets_bitfield.deinit();

        errdefer if (file_offset_opt) |file_offset| {
            std.log.debug(.zorrent_lib, "{}\tAn error happened, releasing file_offset={} want_file_offsets_capacity={} want_file_offsets_len={}", .{ self.address, file_offset, pieces.want_blocks_bitfield.capacity, pieces.want_blocks_bitfield.items.len });

            pieces.releaseFileOffset(file_offset);
        };

        while (true) {
            if (pieces.isFinished()) {
                var piece: usize = 0;
                while (piece < (pieces_len - 3)) : (piece += 1) {
                    const begin: usize = piece * torrent_file.piece_len;
                    const expected_len: usize = torrent_file.piece_len;
                    std.debug.warn("piece={} begin={} expected_len={}\n", .{ piece, begin, expected_len });

                    if (!isPieceHashValid(piece, file_buffer[begin .. begin + expected_len], torrent_file.pieces)) {
                        std.log.warn(.zorrent_lib, "invalid piece={}", .{piece});
                    }
                }
                if (!isPieceHashValid(piece, file_buffer[piece * torrent_file.piece_len ..], torrent_file.pieces)) {
                    std.log.warn(.zorrent_lib, "invalid piece={}", .{piece});
                }

                std.log.notice(.zorrent_lib, "{}\tFinished", .{self.address});
                return;
            }

            const message = self.parseMessage() catch |err| {
                std.log.err(.zorrent_lib, "{}\tError parsing message: {}", .{ self.address, err });
                return err;
            };
            if (message) |msg| {
                std.log.debug(.zorrent_lib, "{}\tMessage: {}", .{ self.address, @tagName(msg) });

                switch (msg) {
                    Message.Unchoke => choked = false,
                    Message.Choke => choked = true,
                    Message.Have => |piece| {
                        const byte_index: u32 = piece / 8;
                        if (byte_index >= remote_have_pieces_bitfield.items.len) {
                            std.log.crit(.zorrent_lib, "{}\tInvalid Have piece index: got {}, expected < {}", .{ self.address, piece, pieces_len });
                            return error.InvalidMessage;
                        }

                        std.log.debug(.zorrent_lib, "{}\tHave: piece={} byte_index={} remote_have_pieces_bitfield[]={}", .{ self.address, piece, byte_index, remote_have_pieces_bitfield.items[byte_index] });
                        remote_have_pieces_bitfield.items[byte_index] |= std.math.pow(u8, 2, @intCast(u8, (piece % 8)));
                        try markFileOffsetAsHaveFromPiece(&remote_have_file_offsets_bitfield, piece, torrent_file.piece_len, torrent_file.total_len);
                        std.log.debug(.zorrent_lib, "{}\tHave: piece={} byte_index={} remote_have_pieces_bitfield[]={}", .{ self.address, piece, byte_index, remote_have_pieces_bitfield.items[byte_index] });
                    },
                    Message.Bitfield => |bitfield| {
                        if (bitfield.len > remote_have_pieces_bitfield.items.len) {
                            std.log.crit(.zorrent_lib, "{}\tInvalid Bitfield length: got {}, expected {}", .{ self.address, bitfield.len, remote_have_pieces_bitfield.items.len });
                            return error.InvalidMessage;
                        }

                        std.log.debug(.zorrent_lib, "{}\tBitfield: len={} have={X}", .{ self.address, bitfield.len, bitfield });

                        for (bitfield) |have, i| {
                            try markPiecesAsHaveFromBitfield(&remote_have_file_offsets_bitfield, &remote_have_pieces_bitfield, torrent_file.piece_len, have, i, torrent_file.total_len);
                        }
                        defer self.allocator.free(bitfield);
                    },
                    Message.Piece => |piece| {
                        if (file_offset_opt == null) continue;

                        const file_offset: usize = file_offset_opt.?;

                        const expected_piece: u32 = @intCast(u32, file_offset / torrent_file.piece_len);
                        const expected_begin: u32 = @intCast(u32, file_offset - @as(usize, expected_piece) * @as(usize, torrent_file.piece_len));
                        const expected_len: usize = @intCast(u32, std.math.min(block_len, torrent_file.total_len - (expected_piece * torrent_file.piece_len + expected_begin)));
                        const actual_piece: usize = piece.index;
                        const actual_begin: usize = piece.begin;
                        const actual_len: usize = piece.data.len;
                        const actual_file_offset: usize = piece.index * torrent_file.piece_len + piece.begin;

                        // Malformed piece, skip
                        if (actual_piece != expected_piece or actual_file_offset != file_offset or actual_len != expected_len or actual_begin != expected_begin) {
                            std.log.err(.zorrent_lib, "{}\tMalformed block: index={} begin={} expected_piece={} requested_file_offset={}", .{
                                self.address,   piece.index, piece.begin,
                                expected_piece, file_offset,
                            });
                            return error.MalformedMessage;
                        }

                        std.log.debug(.zorrent_lib, "{}\tWriting block to disk: file_offset={} begin={} len={} total_len={}", .{ self.address, file_offset, piece.begin, actual_len, file_buffer.len });
                        std.mem.copy(u8, file_buffer[file_offset .. file_offset + expected_len], piece.data[0..]);
                        pieces.commitFileOffset(file_offset);
                        file_offset_opt = null;

                        pieces.displayStats();
                    },
                    else => {},
                }
            } else {
                std.time.sleep(500_000_000);
            }

            if (file_offset_opt == null and !choked and !pieces.isFinished()) {
                file_offset_opt = pieces.acquireFileOffset(remote_have_file_offsets_bitfield.items[0..]);
                if (file_offset_opt == null) {
                    std.time.sleep(100_000_000);
                    continue;
                }
                try self.requestBlock(file_offset_opt.?, @intCast(u32, torrent_file.piece_len), torrent_file.total_len);
            }
        }
    }
};

fn markFileOffsetAsHaveFromPiece(remote_have_file_offsets_bitfield: *std.ArrayList(u8), piece: u32, piece_len: usize, total_len: usize) !void {
    var file_offset: usize = piece * piece_len;

    const size = std.math.min(total_len, (piece + 1) * piece_len);
    while (file_offset < size) : (file_offset += block_len) {
        std.debug.assert(file_offset < total_len);
        const block: usize = file_offset / block_len;
        const bit: u3 = @intCast(u3, block % 8);

        std.log.debug(.zorrent_lib, "markFileOffsetAsHaveFromPiece: piece={} file_offset={} block={} bit={}", .{ piece, file_offset, block, bit });
        remote_have_file_offsets_bitfield.items[block / 8] |= @as(u8, 1) << bit;
    }
}

fn markPiecesAsHaveFromBitfield(remote_have_file_offsets_bitfield: *std.ArrayList(u8), remote_have_pieces_bitfield: *std.ArrayList(u8), piece_len: usize, have_bitfield: u8, have_bitfield_index: usize, total_len: usize) !void {
    remote_have_pieces_bitfield.items[have_bitfield_index] |= have_bitfield;

    var j: u8 = 0;
    while (j < 8) : (j += 1) {
        const k: u3 = @as(u3, 7) - @intCast(u3, j);
        const shift: u3 = @as(u3, k);
        const piece: u32 = @intCast(u32, have_bitfield_index) * 8 + j;
        const has_piece_mask = (have_bitfield & (@as(u8, 1) << shift));

        if (has_piece_mask == 0) continue;

        try markFileOffsetAsHaveFromPiece(remote_have_file_offsets_bitfield, piece, piece_len, total_len);
    }
}

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
    total_len: usize,
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
            .total_len = @intCast(usize, file_length.?),
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
            const err_msg: []const u8 = std.mem.spanZ(c.curl_easy_strerror(curl_res));
            std.log.emerg(.zorrent_lib, "libcurl initialization failed: {}", .{err_msg});
            return error.CurlInitFailed;
        }
        defer c.curl_global_cleanup();

        var curl: ?*c.CURL = null;
        var headers: [*c]c.curl_slist = null;

        curl = c.curl_easy_init() orelse {
            const err_msg: []const u8 = std.mem.spanZ(c.curl_easy_strerror(curl_res));
            std.log.emerg(.zorrent_lib, "libcurl initialization failed: {}", .{err_msg});
            return error.CurlInitFailed;
        };
        defer c.curl_easy_cleanup(curl);

        // url
        curl_res = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_URL, @ptrCast([*:0]const u8, queryUrl));
        if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
            const err_msg: []const u8 = std.mem.spanZ(c.curl_easy_strerror(curl_res));
            std.log.emerg(.zorrent_lib, "libcurl initialization failed: {}", .{err_msg});
            return error.CurlSetOptFailed;
        }

        curl_res = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_WRITEFUNCTION, writeCallback);
        if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
            const err_msg: []const u8 = std.mem.spanZ(c.curl_easy_strerror(curl_res));
            std.log.emerg(.zorrent_lib, "libcurl initialization failed: {}", .{err_msg});
            return error.CurlSetOptFailed;
        }

        const timeout_seconds: usize = 10;
        curl_res = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_TIMEOUT, timeout_seconds);
        if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
            const err_msg: []const u8 = std.mem.spanZ(c.curl_easy_strerror(curl_res));
            std.log.emerg(.zorrent_lib, "libcurl initialization failed: {}", .{err_msg});
            return error.CurlSetOptFailed;
        }

        const follow_redirect_enabled: usize = 1;
        curl_res = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_FOLLOWLOCATION, follow_redirect_enabled);
        if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
            const err_msg: []const u8 = std.mem.spanZ(c.curl_easy_strerror(curl_res));
            std.log.emerg(.zorrent_lib, "libcurl initialization failed: {}", .{err_msg});
            return error.CurlSetOptFailed;
        }

        var res_body = std.ArrayList(u8).init(allocator);
        curl_res = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_WRITEDATA, &res_body);
        if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
            const err_msg: []const u8 = std.mem.spanZ(c.curl_easy_strerror(curl_res));
            std.log.emerg(.zorrent_lib, "libcurl initialization failed: {}", .{err_msg});
            return error.CurlSetOptFailed;
        }

        // perform the call
        curl_res = c.curl_easy_perform(curl);
        if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
            const err_msg: []const u8 = std.mem.spanZ(c.curl_easy_strerror(curl_res));
            std.log.emerg(.zorrent_lib, "libcurl initialization failed: {}", .{err_msg});
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
        std.log.notice(.zorrent_lib, "Tracker {}: trying to contact...", .{url});
        var tracker_response = try self.queryAnnounceUrl(url, allocator);
        std.log.notice(.zorrent_lib, "Tracker {} replied successfuly", .{url});

        var dict = tracker_response.root.Object;

        if (bencode.mapLookup(&dict, "failure reason")) |failure_field| {
            std.log.warn(.zorrent_lib, "Tracker {}: {}", .{ url, failure_field.String });
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
                        std.log.notice(.zorrent_lib, "Tracker {}: new peer {} total_peers_count={}", .{ url, address, peers.items.len });
                    }

                    i += 6;
                }
            },
            .Array => |*peers_list| {
                for (peers_list.items) |*peer_field| {
                    // TODO: parse peer_id?
                    const ip = if (bencode.mapLookup(&peer_field.Object, "ip")) |ip_field| ip_field.String else continue;
                    const port = if (bencode.mapLookup(&peer_field.Object, "port")) |port_field| port_field.Integer else continue;
                    const address = try std.net.Address.parseIp(ip, @intCast(u16, port));

                    const peer = try Peer.init(address, allocator);
                    if (try addUniquePeer(peers, peer)) {
                        std.log.notice(.zorrent_lib, "Tracker {}: new peer {}", .{ url, address });
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
                std.log.warn(.zorrent_lib, "Tracker {}: {}", .{ url, err });
                continue;
            };
        }

        return peers.toOwnedSlice();
    }

    pub fn openMmapFile(self: *TorrentFile) !DownloadFile {
        const fd = try std.os.open(self.path, std.os.O_CREAT | std.os.O_RDWR, 438);
        try std.os.ftruncate(fd, self.total_len);

        var data = try std.os.mmap(
            null,
            self.total_len,
            std.os.PROT_READ | std.os.PROT_WRITE,
            std.os.MAP_FILE | std.os.MAP_SHARED,
            fd,
            0,
        );

        return DownloadFile{ .fd = fd, .data = data };
    }
};
