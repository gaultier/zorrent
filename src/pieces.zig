const std = @import("std");
const utils = @import("utils.zig");
const testing = std.testing;

pub const block_len: usize = 1 << 14;

const file_name = ".zorrent_state";

pub fn markFileOffsetsFromPiece(bitfield: []u8, piece: u32, piece_len: usize, total_len: usize) void {
    const size = std.math.min(total_len, (piece + 1) * piece_len);

    var file_offset: usize = piece * piece_len;
    while (file_offset < size) : (file_offset += block_len) {
        std.debug.assert(file_offset < total_len);
        const block: usize = file_offset / block_len;
        const bit: u3 = @intCast(u3, block % 8);

        std.log.debug(.zorrent_lib, "markFileOffsetsFromPiece: piece={} file_offset={} block={} bit={}", .{ piece, file_offset, block, bit });
        bitfield[block / 8] |= @as(u8, 1) << bit;
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

        markFileOffsetsFromPiece(remote_have_file_offsets_bitfield, piece, piece_len, total_len);
    }
}

pub const Pieces = struct {
    have_blocks_bitfield: []u8,
    pieces_valid: []u8,
    allocator: *std.mem.Allocator,
    piece_acquire_mutex: std.Mutex,
    initial_want_block_count: usize,
    have_block_count: std.atomic.Int(usize),
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

        var pieces = Pieces{
            .have_blocks_bitfield = have_blocks_bitfield.toOwnedSlice(),
            .allocator = allocator,
            .piece_acquire_mutex = std.Mutex{},
            .have_block_count = std.atomic.Int(usize).init(initial_want_block_count),
            .initial_want_block_count = initial_want_block_count,
            .total_len = total_len,
            .piece_len = piece_len,
            .pieces_valid = pieces_valid.toOwnedSlice(),
            .valid_block_count = std.atomic.Int(usize).init(0),
            .pieces_valid_mutex = std.Mutex{},
        };

        return pieces;
    }

    pub fn deinit(self: *Pieces) void {
        self.allocator.free(self.have_blocks_bitfield);
        self.allocator.free(self.pieces_valid);
    }

    pub fn acquireFileOffset(self: *Pieces, remote_have_file_offsets_bitfield: []const u8) ?usize {
        var trial: u32 = 0;
        while (trial < 20) : (trial += 1) {
            if (self.piece_acquire_mutex.tryAcquire()) |lock| {
                defer lock.release();

                var block: usize = 0;
                while (block < self.initial_want_block_count) : (block += 1) {
                    if (!utils.bitArrayIsSet(self.have_blocks_bitfield[0..], block) and utils.bitArrayIsSet(remote_have_file_offsets_bitfield[0..], block)) {
                        utils.bitArrayClear(self.have_blocks_bitfield[0..], block);
                        return block * block_len;
                    }
                }
                return null;
            }
        }
        return null;
    }

    pub fn commitFileOffset(self: *Pieces, file_offset: usize, file_buffer: []const u8, hashes: []const u8) void {
        std.debug.assert(file_offset < self.total_len);
        // const have = self.have_block_count.incr();
        // std.debug.assert(have <= self.initial_want_block_count);

        self.checkPieceValidForBlock(file_offset / block_len, file_buffer, hashes);
    }

    pub fn releaseFileOffset(self: *Pieces, file_offset: usize) void {
        std.debug.assert(file_offset < self.total_len);

        while (true) {
            if (self.piece_acquire_mutex.tryAcquire()) |lock| {
                defer lock.release();

                utils.bitArraySet(self.have_blocks_bitfield[0..], file_offset / block_len);
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

        while (true) {
            if (self.pieces_valid_mutex.tryAcquire()) |lock| {
                defer lock.release();
                const piece: u32 = @intCast(u32, file_offset / self.piece_len);
                const begin: u32 = @intCast(u32, file_offset - @as(usize, piece) * @as(usize, self.piece_len));
                std.debug.assert(begin < self.piece_len);

                // Check cache
                if (utils.bitArrayIsSet(self.pieces_valid[0..], piece)) return;

                // Check if we have all blocks for piece
                const real_len: usize = std.math.min(self.total_len - begin, self.piece_len);
                {
                    var block = piece * self.piece_len / block_len;
                    const blocks = std.math.min(self.initial_want_block_count - block, (self.piece_len / block_len));
                    while (block < blocks) : (block += 1) {
                        if (!utils.bitArrayIsSet(self.have_blocks_bitfield[0..], block)) return;
                    }
                }

                const valid = isPieceHashValid(piece, file_buffer[begin .. begin + real_len], hashes);

                if (valid) {
                    // const val = self.valid_block_count.incr();
                    // std.debug.assert(val <= self.initial_want_block_count);
                    utils.bitArraySet(self.pieces_valid, piece);
                } else {
                    utils.bitArrayClear(self.pieces_valid, piece);
                }
                return;
            }
        }
    }

    pub fn checkPiecesValid(self: *Pieces, pieces_len: usize, file_buffer: []const u8, hashes: []const u8) void {
        while (true) {
            if (self.pieces_valid_mutex.tryAcquire()) |lock| {
                defer lock.release();
                // TODO: parallelize

                var piece: usize = 0;
                while (piece < pieces_len) : (piece += 1) {
                    const begin: usize = piece * self.piece_len;
                    const expected_len: usize = self.piece_len;
                    const real_len: usize = if (piece == pieces_len - 1) file_buffer.len - begin else self.piece_len;
                    std.debug.assert(real_len <= self.piece_len);

                    if (utils.bitArrayIsSet(self.pieces_valid[0..], piece)) continue;

                    if (!isPieceHashValid(piece, file_buffer[begin .. begin + real_len], hashes)) {
                        std.log.warn(.zorrent_lib, "Invalid hash: piece={} [Valid blocks/total={}/{}]", .{ piece, self.valid_block_count.get(), self.initial_want_block_count });

                        // markFileOffsetsFromPiece(self.want_blocks_bitfield, @intCast(u32, piece), self.piece_len, file_buffer.len);
                        const blocks_count = utils.divCeil(usize, real_len, block_len);

                        // var j: usize = 0;
                        // while (j < blocks_count) : (j += 1) {
                        // const have = self.have_block_count.decr();
                        // std.debug.assert(have <= self.initial_want_block_count);
                        // }
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

// test "init" {
//     var pieces = try Pieces.init(131_073, 16 * block_len, testing.allocator);
//     defer pieces.deinit();

//     testing.expectEqual(@as(usize, 9), pieces.want_block_count.get());
//     testing.expectEqual(@as(usize, 0), pieces.have_block_count.get());
//     testing.expectEqual(@as(usize, 131_073), pieces.total_len);

//     testing.expectEqual(@as(usize, 2), pieces.want_blocks_bitfield.len);
//     testing.expectEqual(@as(usize, 0xff), pieces.want_blocks_bitfield[0]);
//     testing.expectEqual(@as(usize, 0b1000_0000), pieces.want_blocks_bitfield[1]);
// }

// test "acquireFileOffset" {
//     var pieces = try Pieces.init(131_073, 16 * block_len, testing.allocator);
//     defer pieces.deinit();

//     var remote_have_blocks_bitfield = std.ArrayList(u8).init(testing.allocator);
//     defer remote_have_blocks_bitfield.deinit();
//     const initial_remote_have_block_count: usize = utils.divCeil(usize, 131_073, block_len);
//     try remote_have_blocks_bitfield.appendNTimes(0, utils.divCeil(usize, initial_remote_have_block_count, 8));

//     testing.expectEqual(@as(?usize, null), pieces.acquireFileOffset(remote_have_blocks_bitfield.items[0..]));

//     remote_have_blocks_bitfield.items[0] = 0b0001_0001;
//     testing.expectEqual(@as(?usize, 3 * block_len), pieces.acquireFileOffset(remote_have_blocks_bitfield.items[0..]));

//     testing.expectEqual(@as(u8, 0b1110_1111), pieces.want_blocks_bitfield[0]);
//     testing.expectEqual(@as(usize, 8), pieces.want_block_count.get());
//     testing.expectEqual(@as(usize, 0), pieces.have_block_count.get());
// }

// test "commitFileOffset" {
//     var pieces = try Pieces.init(131_073, 16 * block_len, testing.allocator);
//     defer pieces.deinit();

//     var remote_have_blocks_bitfield = std.ArrayList(u8).init(testing.allocator);
//     defer remote_have_blocks_bitfield.deinit();
//     const initial_remote_have_block_count: usize = utils.divCeil(usize, 131_073, block_len);
//     try remote_have_blocks_bitfield.appendNTimes(0, utils.divCeil(usize, initial_remote_have_block_count, 8));

//     remote_have_blocks_bitfield.items[0] = 0b0000_0001;
//     testing.expectEqual(@as(?usize, 7 * block_len), pieces.acquireFileOffset(remote_have_blocks_bitfield.items[0..]));

//     pieces.commitFileOffset(0);
//     testing.expectEqual(@as(usize, 1), pieces.have_block_count.get());
// }

// test "releaseFileOffset" {
//     var pieces = try Pieces.init(131_073, 16 * block_len, testing.allocator);
//     defer pieces.deinit();

//     var remote_have_blocks_bitfield = std.ArrayList(u8).init(testing.allocator);
//     defer remote_have_blocks_bitfield.deinit();
//     const initial_remote_have_block_count: usize = utils.divCeil(usize, 131_073, block_len);
//     try remote_have_blocks_bitfield.appendNTimes(0, utils.divCeil(usize, initial_remote_have_block_count, 8));

//     remote_have_blocks_bitfield.items[0] = 0b0000_0001;
//     testing.expectEqual(@as(?usize, 7 * block_len), pieces.acquireFileOffset(remote_have_blocks_bitfield.items[0..]));

//     pieces.releaseFileOffset(0);
//     testing.expectEqual(@as(u8, 0b1111_1111), pieces.want_blocks_bitfield[0]);
//     testing.expectEqual(@as(usize, 9), pieces.want_block_count.get());
//     testing.expectEqual(@as(usize, 0), pieces.have_block_count.get());
// }

// test "isFinished" {
//     var pieces = try Pieces.init(131_073, 16 * block_len, testing.allocator);
//     defer pieces.deinit();

//     var remote_have_blocks_bitfield = std.ArrayList(u8).init(testing.allocator);
//     defer remote_have_blocks_bitfield.deinit();
//     const initial_remote_have_block_count: usize = utils.divCeil(usize, 131_073, block_len);
//     try remote_have_blocks_bitfield.appendNTimes(0xff, utils.divCeil(usize, initial_remote_have_block_count, 8));

//     var block: usize = 0;
//     while (block < 9) : (block += 1) {
//         testing.expectEqual(false, pieces.isFinished());
//         pieces.commitFileOffset(pieces.acquireFileOffset(remote_have_blocks_bitfield.items).?);
//     }
//     testing.expectEqual(true, pieces.isFinished());
//     testing.expectEqual(@as(usize, 0), pieces.want_block_count.get());
//     testing.expectEqual(@as(usize, 9), pieces.have_block_count.get());
// }

// test "recover state from file" {
//     {
//         var pieces = try Pieces.init(131_073, 16 * block_len, testing.allocator);
//         defer pieces.deinit();
//         testing.expectEqual(@as(usize, 2), pieces.want_blocks_bitfield.len);
//         testing.expectEqual(@as(usize, 0b1111_1111), pieces.want_blocks_bitfield[0]);
//         testing.expectEqual(@as(usize, 0b1000_0000), pieces.want_blocks_bitfield[1]);
//         testing.expectEqual(@as(usize, 9), pieces.want_block_count.get());
//         testing.expectEqual(@as(usize, 0), pieces.have_block_count.get());

//         pieces.want_blocks_bitfield[0] = 0b1111_1110;
//         pieces.want_block_count.set(8);
//         pieces.have_block_count.set(1);
//     }

//     {
//         var pieces = try Pieces.init(131_073, 16 * block_len, testing.allocator);
//         defer pieces.deinit();

//         testing.expectEqual(@as(usize, 2), pieces.want_blocks_bitfield.len);
//         testing.expectEqual(@as(usize, 0b1111_1110), pieces.want_blocks_bitfield[0]);
//         testing.expectEqual(@as(usize, 0b1000_0000), pieces.want_blocks_bitfield[1]);
//         testing.expectEqual(@as(usize, 8), pieces.want_block_count.get());
//         testing.expectEqual(@as(usize, 1), pieces.have_block_count.get());

//         var remote_have_blocks_bitfield = std.ArrayList(u8).init(testing.allocator);
//         defer remote_have_blocks_bitfield.deinit();
//         const initial_remote_have_block_count: usize = utils.divCeil(usize, 131_073, block_len);
//         try remote_have_blocks_bitfield.appendNTimes(0, utils.divCeil(usize, initial_remote_have_block_count, 8));

//         testing.expectEqual(@as(?usize, null), pieces.acquireFileOffset(remote_have_blocks_bitfield.items[0..]));

//         remote_have_blocks_bitfield.items[0] = 0b0000_0001;
//         testing.expectEqual(@as(?usize, null), pieces.acquireFileOffset(remote_have_blocks_bitfield.items[0..]));
//     }
// }
