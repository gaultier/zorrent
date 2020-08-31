const std = @import("std");
const utils = @import("utils.zig");
const testing = std.testing;

pub const block_len: usize = 1 << 14;

const file_name = ".zorrent_state";

pub fn setAllBlocksForPiece(bitfield: []u8, piece: u32, piece_len: usize, total_len: usize) void {
    const blocks_in_piece = piece_len / block_len;
    var block = piece * blocks_in_piece;
    while (block * block_len < (piece + 1) * piece_len and block * block_len < total_len) : (block += 1) {
        utils.bitArraySet(bitfield, block);
    }
}

pub fn markPiecesAsHaveFromBitfield(remote_have_file_offsets_bitfield: []u8, piece_len: usize, have_bitfield: u8, have_bitfield_index: usize, total_len: usize) void {
    var j: u8 = 0;
    while (j < 8) : (j += 1) {
        const k: u3 = @as(u3, 7) - @intCast(u3, j);
        const shift: u3 = @as(u3, k);
        const piece: u32 = @intCast(u32, have_bitfield_index) * 8 + j;
        const has_piece_mask = (have_bitfield & (@as(u8, 1) << shift));

        if (has_piece_mask == 0) continue;

        setAllBlocksForPiece(remote_have_file_offsets_bitfield, piece, piece_len, total_len);
    }
}

pub const Pieces = struct {
    have_blocks_bitfield: []u8,
    pieces_valid: []u8,
    allocator: *std.mem.Allocator,
    piece_acquire_mutex: std.Mutex,
    initial_want_block_count: usize,
    total_len: usize,
    piece_len: usize,
    valid_block_count: std.atomic.Int(usize),
    pieces_valid_mutex: std.Mutex,

    pub fn init(total_len: usize, piece_len: usize, allocator: *std.mem.Allocator) !Pieces {
        const initial_want_block_count: usize = utils.divCeil(usize, total_len, block_len);
        const blocks_bitfield_len = utils.divCeil(usize, initial_want_block_count, 8);

        var pieces_valid = std.ArrayList(u8).init(allocator);
        errdefer pieces_valid.deinit();
        const pieces_count = utils.divCeil(usize, total_len, piece_len);
        try pieces_valid.appendNTimes(0, utils.divCeil(usize, pieces_count, 8));

        var have_blocks_bitfield = std.ArrayList(u8).init(allocator);
        defer have_blocks_bitfield.deinit();
        try have_blocks_bitfield.appendNTimes(0, blocks_bitfield_len);

        return Pieces{
            .have_blocks_bitfield = have_blocks_bitfield.toOwnedSlice(),
            .allocator = allocator,
            .piece_acquire_mutex = std.Mutex{},
            .initial_want_block_count = initial_want_block_count,
            .total_len = total_len,
            .piece_len = piece_len,
            .pieces_valid = pieces_valid.toOwnedSlice(),
            .valid_block_count = std.atomic.Int(usize).init(0),
            .pieces_valid_mutex = std.Mutex{},
        };
    }

    pub fn deinit(self: *Pieces) void {
        self.allocator.free(self.have_blocks_bitfield);
        self.allocator.free(self.pieces_valid);
    }

    pub fn acquireFileOffset(self: *Pieces, remote_have_file_offsets_bitfield: []const u8) ?usize {
        while (true) {
            if (self.piece_acquire_mutex.tryAcquire()) |lock| {
                defer lock.release();

                var block: usize = 0;
                while (block < self.initial_want_block_count) : (block += 1) {
                    if (!utils.bitArrayIsSet(self.have_blocks_bitfield[0..], block) and utils.bitArrayIsSet(remote_have_file_offsets_bitfield[0..], block)) {
                        return block * block_len;
                    }
                }
                return null;
            }
        }
    }

    pub fn commitFileOffset(self: *Pieces, file_offset: usize, file_buffer: []const u8, hashes: []const u8) void {
        std.debug.assert(file_offset < self.total_len);

        while (true) {
            if (self.pieces_valid_mutex.tryAcquire()) |lock| {
                defer lock.release();

                utils.bitArraySet(self.have_blocks_bitfield, file_offset / block_len);

                self.checkPieceValidForBlock(file_offset / block_len, file_buffer, hashes);
                return;
            }
        }
    }

    pub fn displayStats(self: *Pieces) void {
        const valid = self.valid_block_count.get();
        const total = self.initial_want_block_count;
        const percent: f64 = @intToFloat(f64, valid) / @intToFloat(f64, total) * 100.0;

        std.log.info(.zorrent_lib, "[Blocks Valid/Total/Have Size/Total size: {}/{}/{Bi:.2}/{Bi:.2}] {d:.2}%", .{ valid, total, valid * block_len, self.initial_want_block_count * block_len, percent });
        return;
    }

    fn isPieceHashValid(piece: usize, piece_data: []const u8, hashes: []const u8) bool {
        const expected_hash = hashes[piece * 20 .. (piece + 1) * 20];
        var actual_hash: [20]u8 = undefined;
        std.crypto.Sha1.hash(piece_data[0..], actual_hash[0..]);
        const identical = std.mem.eql(u8, actual_hash[0..20], expected_hash[0..20]);

        std.log.debug(.zorrent_lib, "isPieceHashValid: piece={} actual_hash={X} expected_hash={X} matching_hash={}", .{ piece, actual_hash, expected_hash, identical });
        return identical;
    }

    fn checkPieceValidForBlock(self: *Pieces, file_offset: usize, file_buffer: []const u8, hashes: []const u8) void {
        std.debug.assert(file_offset < self.total_len);

        std.log.debug(.zorrent_lib, "Checking piece validity for block {}", .{file_offset / block_len});

        const piece: u32 = @intCast(u32, file_offset / self.piece_len);
        const begin: u32 = @intCast(u32, file_offset - @as(usize, piece) * @as(usize, self.piece_len));
        std.debug.assert(begin < self.piece_len);

        // Check cache
        if (utils.bitArrayIsSet(self.pieces_valid[0..], piece)) return;

        // Check if we have all blocks for piece
        const real_len: usize = std.math.min(self.total_len - begin, self.piece_len);
        {
            const blocks_in_piece = self.piece_len / block_len;
            var block = piece * blocks_in_piece;
            while (block * block_len < (piece + 1) * self.piece_len and block * block_len < self.total_len) : (block += 1) {
                if (!utils.bitArrayIsSet(self.have_blocks_bitfield[0..], block)) return;
            }
        }

        const valid = isPieceHashValid(piece, file_buffer[begin .. begin + real_len], hashes);

        if (valid) {
            std.log.info(.zorrent_lib, "Piece valid: {}", .{piece});

            const blocks_count = utils.divCeil(usize, real_len, block_len);
            const val = self.valid_block_count.fetchAdd(blocks_count);
            std.debug.assert(val <= self.initial_want_block_count);

            utils.bitArraySet(self.pieces_valid, piece);
        } else {
            std.log.warn(.zorrent_lib, "Piece invalid: {}", .{piece});
            utils.bitArrayClear(self.pieces_valid, piece);
            // TODO: clear all blocks from piece in 'have_blocks_bitfield'
        }
        return;
    }

    pub fn checkPiecesValid(self: *Pieces, file_buffer: []const u8, hashes: []const u8) void {
        const pieces_count: usize = utils.divCeil(usize, self.total_len, self.piece_len);

        while (true) {
            if (self.pieces_valid_mutex.tryAcquire()) |lock| {
                defer lock.release();
                // TODO: parallelize

                var piece: usize = 0;
                while (piece < pieces_count) : (piece += 1) {
                    const begin: usize = piece * self.piece_len;
                    const expected_len: usize = self.piece_len;
                    const real_len: usize = if (piece == pieces_count - 1) file_buffer.len - begin else self.piece_len;
                    std.debug.assert(real_len <= self.piece_len);

                    if (utils.bitArrayIsSet(self.pieces_valid[0..], piece)) continue;

                    if (!isPieceHashValid(piece, file_buffer[begin .. begin + real_len], hashes)) {
                        std.log.warn(.zorrent_lib, "Invalid hash: piece={} [Valid blocks/total={}/{}]", .{ piece, self.valid_block_count.get(), self.initial_want_block_count });
                    } else {
                        const blocks_count = utils.divCeil(usize, real_len, block_len);
                        const valid = self.valid_block_count.fetchAdd(blocks_count);
                        std.debug.assert(valid <= self.initial_want_block_count);

                        utils.bitArraySet(self.pieces_valid[0..], piece);
                        std.log.info(.zorrent_lib, "Valid hash: piece={} [Valid blocks/total={}/{}]", .{ piece + 1, self.valid_block_count.get(), self.initial_want_block_count });
                    }
                }

                return;
            }
        }
    }
};

test "setAllBlocksForPiece" {
    var blocks_bitfield = [3]u8{ 0b1010_0000, 0b0000_0001, 0 };
    const piece_len = 2 * block_len;
    const total_len = 18 * block_len + 5;

    setAllBlocksForPiece(blocks_bitfield[0..], 3, piece_len, total_len);
    std.testing.expectEqual(@as(u8, 0b1110_0000), blocks_bitfield[0]);
    std.testing.expectEqual(@as(u8, 0b0000_0001), blocks_bitfield[1]);
    std.testing.expectEqual(@as(u8, 0), blocks_bitfield[2]);

    setAllBlocksForPiece(blocks_bitfield[0..], 9, piece_len, total_len);
    std.testing.expectEqual(@as(u8, 0b1110_0000), blocks_bitfield[0]);
    std.testing.expectEqual(@as(u8, 0b0000_0001), blocks_bitfield[1]);
    std.testing.expectEqual(@as(u8, 0b0000_0100), blocks_bitfield[2]);
}

test "markPiecesAsHaveFromBitfield" {
    var blocks_bitfield = [3]u8{ 0, 0, 0 };
    const piece_len = 2 * block_len;
    const total_len = 18 * block_len + 5;

    markPiecesAsHaveFromBitfield(blocks_bitfield[0..], piece_len, 0b1000_0000, 0, total_len);
    std.testing.expectEqual(@as(u8, 0b0000_0011), blocks_bitfield[0]);
    std.testing.expectEqual(@as(u8, 0), blocks_bitfield[1]);
    std.testing.expectEqual(@as(u8, 0), blocks_bitfield[2]);

    markPiecesAsHaveFromBitfield(blocks_bitfield[0..], piece_len, 0b1111_1111, 0, total_len);
    std.testing.expectEqual(@as(u8, 0b1111_1111), blocks_bitfield[0]);
    std.testing.expectEqual(@as(u8, 0b1111_1111), blocks_bitfield[1]);
    std.testing.expectEqual(@as(u8, 0), blocks_bitfield[2]);

    markPiecesAsHaveFromBitfield(blocks_bitfield[0..], piece_len, 0b1111_1111, 1, total_len);
    std.testing.expectEqual(@as(u8, 0b1111_1111), blocks_bitfield[0]);
    std.testing.expectEqual(@as(u8, 0b1111_1111), blocks_bitfield[1]);
    std.testing.expectEqual(@as(u8, 0b0000_0111), blocks_bitfield[2]);
}

test "init" {
    const total_len = 18 * block_len + 5;
    var pieces = try Pieces.init(total_len, 2 * block_len, testing.allocator);
    defer pieces.deinit();

    testing.expectEqual(@as(usize, 3), pieces.have_blocks_bitfield.len);
    testing.expectEqual(@as(usize, 0), pieces.have_blocks_bitfield[0]);
    testing.expectEqual(@as(usize, 0), pieces.have_blocks_bitfield[1]);
    testing.expectEqual(@as(usize, 0), pieces.have_blocks_bitfield[2]);

    testing.expectEqual(@as(usize, 2), pieces.pieces_valid.len);
    testing.expectEqual(@as(usize, 0), pieces.pieces_valid[0]);
    testing.expectEqual(@as(usize, 0), pieces.pieces_valid[1]);

    testing.expectEqual(@as(usize, total_len), pieces.total_len);
    testing.expectEqual(@as(usize, 2 * block_len), pieces.piece_len);

    testing.expectEqual(@as(usize, 0), pieces.valid_block_count.get());
}

test "acquireFileOffset" {
    const total_len = 18 * block_len + 5;
    var pieces = try Pieces.init(total_len, 2 * block_len, testing.allocator);
    defer pieces.deinit();

    var remote_have_blocks_bitfield = std.ArrayList(u8).init(testing.allocator);
    defer remote_have_blocks_bitfield.deinit();
    const initial_remote_have_block_count: usize = utils.divCeil(usize, total_len, block_len);
    try remote_have_blocks_bitfield.appendNTimes(0, utils.divCeil(usize, initial_remote_have_block_count, 8));

    testing.expectEqual(@as(?usize, null), pieces.acquireFileOffset(remote_have_blocks_bitfield.items[0..]));

    remote_have_blocks_bitfield.items[0] = 0b0001_0001;
    testing.expectEqual(@as(?usize, 0 * block_len), pieces.acquireFileOffset(remote_have_blocks_bitfield.items[0..]));

    utils.bitArraySet(pieces.have_blocks_bitfield, 0);
    utils.bitArraySet(pieces.have_blocks_bitfield, 1);
    testing.expectEqual(@as(?usize, 4 * block_len), pieces.acquireFileOffset(remote_have_blocks_bitfield.items[0..]));
}

test "commitFileOffset" {
    const total_len = 18 * block_len + 5;
    const piece_len = 2 * block_len;
    var pieces = try Pieces.init(total_len, piece_len, testing.allocator);
    defer pieces.deinit();

    var remote_have_blocks_bitfield = std.ArrayList(u8).init(testing.allocator);
    defer remote_have_blocks_bitfield.deinit();
    const initial_remote_have_block_count: usize = utils.divCeil(usize, total_len, block_len);
    try remote_have_blocks_bitfield.appendNTimes(0, utils.divCeil(usize, initial_remote_have_block_count, 8));

    remote_have_blocks_bitfield.items[0] = 0b0000_0001;
    testing.expectEqual(@as(?usize, 0 * block_len), pieces.acquireFileOffset(remote_have_blocks_bitfield.items[0..]));

    var file_buffer: [10 * piece_len]u8 = undefined;
    for (file_buffer) |*f| f.* = 9;

    const hash = [20]u8{ 0xE6, 0x4E, 0xA4, 0x9D, 0xEF, 0x87, 0x53, 0x70, 0x83, 0xFA, 0x06, 0xE0, 0xD9, 0x6F, 0x4F, 0xAD, 0x00, 0x65, 0x0D, 0x11 };
    const hash_rest = [20 * 9]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const hashes: [20 * 10]u8 = hash ++ hash_rest;

    // We only have one block, not the whole first piece, so no hash check can be done
    {
        pieces.commitFileOffset(0 * block_len, file_buffer[0..], hashes[0..]);

        testing.expectEqual(true, utils.bitArrayIsSet(pieces.have_blocks_bitfield, 0));
        testing.expectEqual(false, utils.bitArrayIsSet(pieces.have_blocks_bitfield, 1));

        testing.expectEqual(false, utils.bitArrayIsSet(pieces.pieces_valid, 0));
        testing.expectEqual(false, utils.bitArrayIsSet(pieces.pieces_valid, 1));
        testing.expectEqual(false, utils.bitArrayIsSet(pieces.pieces_valid, 2));
        testing.expectEqual(false, utils.bitArrayIsSet(pieces.pieces_valid, 3));
        testing.expectEqual(false, utils.bitArrayIsSet(pieces.pieces_valid, 4));
        testing.expectEqual(false, utils.bitArrayIsSet(pieces.pieces_valid, 5));
        testing.expectEqual(false, utils.bitArrayIsSet(pieces.pieces_valid, 6));
        testing.expectEqual(false, utils.bitArrayIsSet(pieces.pieces_valid, 7));
        testing.expectEqual(false, utils.bitArrayIsSet(pieces.pieces_valid, 8));
        testing.expectEqual(false, utils.bitArrayIsSet(pieces.pieces_valid, 9));
    }

    // We now have the full piece
    {
        pieces.commitFileOffset(1 * block_len, file_buffer[0..], hashes[0..]);
        testing.expectEqual(true, utils.bitArrayIsSet(pieces.have_blocks_bitfield, 0));
        testing.expectEqual(true, utils.bitArrayIsSet(pieces.have_blocks_bitfield, 1));

        testing.expectEqual(true, utils.bitArrayIsSet(pieces.pieces_valid, 0));
        testing.expectEqual(false, utils.bitArrayIsSet(pieces.pieces_valid, 1));
        testing.expectEqual(false, utils.bitArrayIsSet(pieces.pieces_valid, 2));
        testing.expectEqual(false, utils.bitArrayIsSet(pieces.pieces_valid, 3));
        testing.expectEqual(false, utils.bitArrayIsSet(pieces.pieces_valid, 4));
        testing.expectEqual(false, utils.bitArrayIsSet(pieces.pieces_valid, 5));
        testing.expectEqual(false, utils.bitArrayIsSet(pieces.pieces_valid, 6));
        testing.expectEqual(false, utils.bitArrayIsSet(pieces.pieces_valid, 7));
        testing.expectEqual(false, utils.bitArrayIsSet(pieces.pieces_valid, 8));
        testing.expectEqual(false, utils.bitArrayIsSet(pieces.pieces_valid, 9));
    }
}

test "recover state from file" {
    {
        const total_len = 18 * block_len + 5;
        const piece_len = 2 * block_len;
        var pieces = try Pieces.init(total_len, piece_len, testing.allocator);
        defer pieces.deinit();

        testing.expectEqual(@as(usize, 3), pieces.have_blocks_bitfield.len);
        testing.expectEqual(@as(usize, 0), pieces.have_blocks_bitfield[0]);
        testing.expectEqual(@as(usize, 0), pieces.have_blocks_bitfield[1]);
        testing.expectEqual(@as(usize, 0), pieces.have_blocks_bitfield[2]);

        testing.expectEqual(@as(usize, 2), pieces.pieces_valid.len);
        testing.expectEqual(@as(usize, 0), pieces.pieces_valid[0]);
        testing.expectEqual(@as(usize, 0), pieces.pieces_valid[1]);

        testing.expectEqual(@as(usize, total_len), pieces.total_len);
        testing.expectEqual(@as(usize, 2 * block_len), pieces.piece_len);

        testing.expectEqual(@as(usize, 0), pieces.valid_block_count.get());

        var remote_have_blocks_bitfield = std.ArrayList(u8).init(testing.allocator);
        defer remote_have_blocks_bitfield.deinit();
        const initial_remote_have_block_count: usize = utils.divCeil(usize, total_len, block_len);
        try remote_have_blocks_bitfield.appendNTimes(0, utils.divCeil(usize, initial_remote_have_block_count, 8));

        var file_buffer: [10 * piece_len]u8 = undefined;
        for (file_buffer) |*f| f.* = 9;

        const hash = [20]u8{ 0xE6, 0x4E, 0xA4, 0x9D, 0xEF, 0x87, 0x53, 0x70, 0x83, 0xFA, 0x06, 0xE0, 0xD9, 0x6F, 0x4F, 0xAD, 0x00, 0x65, 0x0D, 0x11 };

        const hash_rest = [20 * 9]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        const hashes: [20 * 10]u8 = hash ++ hash_rest;

        pieces.checkPiecesValid(file_buffer[0..], hashes[0..]);
        testing.expectEqual(@as(usize, 2), pieces.valid_block_count.get());
        // pieces.commitFileOffset(pieces.acquireFileOffset(remote_have_blocks_bitfield.items).?, file_buffer[0..], hashes[0..]);
    }

    // {
    //     var pieces = try Pieces.init(131_073, 16 * block_len, testing.allocator);
    //     defer pieces.deinit();

    //     testing.expectEqual(@as(usize, 2), pieces.want_blocks_bitfield.len);
    //     testing.expectEqual(@as(usize, 0b1111_1110), pieces.want_blocks_bitfield[0]);
    //     testing.expectEqual(@as(usize, 0b1000_0000), pieces.want_blocks_bitfield[1]);
    //     testing.expectEqual(@as(usize, 8), pieces.want_block_count.get());

    //     var remote_have_blocks_bitfield = std.ArrayList(u8).init(testing.allocator);
    //     defer remote_have_blocks_bitfield.deinit();
    //     const initial_remote_have_block_count: usize = utils.divCeil(usize, 131_073, block_len);
    //     try remote_have_blocks_bitfield.appendNTimes(0, utils.divCeil(usize, initial_remote_have_block_count, 8));

    //     testing.expectEqual(@as(?usize, null), pieces.acquireFileOffset(remote_have_blocks_bitfield.items[0..]));

    //     remote_have_blocks_bitfield.items[0] = 0b0000_0001;
    //     testing.expectEqual(@as(?usize, null), pieces.acquireFileOffset(remote_have_blocks_bitfield.items[0..]));
    // }
}
