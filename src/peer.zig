const std = @import("std");

const torrent_file_mod = @import("torrent_file.zig");
const TorrentFile = torrent_file_mod.TorrentFile;

const pieces_mod = @import("pieces.zig");
const Pieces = pieces_mod.Pieces;

const utils = @import("utils.zig");

const handshake_len: usize = 1 + 19 + 8 + 20 + 20;
const block_len = pieces_mod.block_len;

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

fn checkPiecesValid(pieces_len: usize, piece_len: usize, file_buffer: []const u8, hashes: []const u8, want_blocks_bitfield: []u8, want_block_count: *std.atomic.Int(usize)) bool {
    // TODO: parallelize
    var all_valid = true;
    var piece: usize = 0;
    while (piece < pieces_len - 1) : (piece += 1) {
        const begin: usize = piece * piece_len;
        const expected_len: usize = piece_len;

        if (!isPieceHashValid(piece, file_buffer[begin..std.math.min(file_buffer.len, begin + expected_len)], hashes)) {
            all_valid = false;
            std.log.warn(.zorrent_lib, "Invalid piece={}", .{piece});

            markFileOffsetsFromPiece(want_blocks_bitfield, @intCast(u32, piece), pieces_len, file_buffer.len);
            _ = want_block_count.incr();

            // TODO: re-fetch piece
        } else {
            std.log.info(.zorrent_lib, "Piece {}/{} valid", .{ piece + 1, pieces_len });
        }
    }

    return all_valid;
}

fn markFileOffsetsFromPiece(bitfield: []u8, piece: u32, piece_len: usize, total_len: usize) void {
    var file_offset: usize = piece * piece_len;

    const size = std.math.min(total_len, (piece + 1) * piece_len);
    while (file_offset < size) : (file_offset += block_len) {
        std.debug.assert(file_offset < total_len);
        const block: usize = file_offset / block_len;
        const bit: u3 = @intCast(u3, block % 8);

        std.log.debug(.zorrent_lib, "markFileOffsetsFromPiece: piece={} file_offset={} block={} bit={}", .{ piece, file_offset, block, bit });
        bitfield[block / 8] |= @as(u8, 1) << bit;
    }
}

fn markPiecesAsHaveFromBitfield(remote_have_file_offsets_bitfield: []u8, piece_len: usize, have_bitfield: u8, have_bitfield_index: usize, total_len: usize) void {
    var j: u8 = 0;
    while (j < 8) : (j += 1) {
        const k: u3 = @as(u3, 7) - @intCast(u3, j);
        const shift: u3 = @as(u3, k);
        const piece: u32 = @intCast(u32, have_bitfield_index) * 8 + j;
        const has_piece_mask = (have_bitfield & (@as(u8, 1) << shift));

        if (has_piece_mask == 0) continue;

        markFileOffsetsFromPiece(remote_have_file_offsets_bitfield, piece, piece_len, total_len);
    }
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
        std.debug.assert(file_offset < total_len);
        const piece: u32 = @intCast(u32, file_offset / piece_len);
        const begin: u32 = @intCast(u32, file_offset - @as(usize, piece) * @as(usize, piece_len));
        std.debug.assert(begin < piece_len);

        std.log.debug(.zorrent_lib, "requestBlock: piece={} file_offset={}", .{ piece, file_offset });
        const len = @intCast(u32, std.math.min(block_len, total_len - (piece * piece_len + begin)));
        std.debug.assert(len <= block_len);
        std.debug.assert(begin + len <= piece_len);

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

    fn waitForHandshake(self: *Peer, torrent_file: TorrentFile) !void {
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

        try self.waitForHandshake(torrent_file);
        try self.sendInterested();
        try self.sendChoke();

        const pieces_len: usize = utils.divCeil(usize, torrent_file.total_len, torrent_file.piece_len);
        const blocks_per_piece: usize = utils.divCeil(usize, torrent_file.piece_len, block_len);
        var choked = true;
        var file_offset_opt: ?usize = null;
        std.log.debug(.zorrent_lib, "stats: total_len={} block_len={} piece_len={}, pieces_count={} blocks_per_piece={} blocks_count={}", .{ torrent_file.total_len, block_len, torrent_file.piece_len, pieces_len, torrent_file.piece_len / block_len, pieces.initial_want_block_count });

        var remote_have_file_offsets_bitfield = std.ArrayList(u8).init(self.allocator);
        try remote_have_file_offsets_bitfield.appendNTimes(0, pieces.want_blocks_bitfield.len);
        defer remote_have_file_offsets_bitfield.deinit();

        errdefer if (file_offset_opt) |file_offset| {
            std.log.debug(.zorrent_lib, "{}\tAn error happened, releasing file_offset={} want_file_offsets_len={}", .{ self.address, file_offset, pieces.want_blocks_bitfield.len });

            pieces.releaseFileOffset(file_offset);
        };

        while (true) {
            if (pieces.isFinished()) {
                if (checkPiecesValid(pieces_len, torrent_file.piece_len, file_buffer, torrent_file.pieces, pieces.want_blocks_bitfield, &pieces.want_block_count)) {
                    std.log.notice(.zorrent_lib, "{}\tFinished", .{self.address});
                    return;
                } else continue;
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
                        if (byte_index > pieces_len) {
                            std.log.crit(.zorrent_lib, "{}\tInvalid Have piece index: got {}, expected < {}", .{ self.address, piece, pieces_len });
                            return error.InvalidMessage;
                        }

                        std.log.debug(.zorrent_lib, "{}\tHave: piece={} byte_index={}", .{ self.address, piece, byte_index });
                        markFileOffsetsFromPiece(remote_have_file_offsets_bitfield.items, piece, torrent_file.piece_len, torrent_file.total_len);
                        std.log.debug(.zorrent_lib, "{}\tHave: piece={} byte_index={}", .{ self.address, piece, byte_index });
                    },
                    Message.Bitfield => |bitfield| {
                        if (bitfield.len > pieces_len) {
                            std.log.crit(.zorrent_lib, "{}\tInvalid Bitfield length: got {}, expected {}", .{ self.address, bitfield.len, pieces_len });
                            return error.InvalidMessage;
                        }

                        std.log.debug(.zorrent_lib, "{}\tBitfield: len={} have={X}", .{ self.address, bitfield.len, bitfield });

                        for (bitfield) |have, i| {
                            markPiecesAsHaveFromBitfield(remote_have_file_offsets_bitfield.items, torrent_file.piece_len, have, i, torrent_file.total_len);
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
