const std = @import("std");
const utils = @import("utils.zig");
const testing = std.testing;

pub const block_len: usize = 1 << 14;

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
    want_blocks_bitfield: []u8,
    pieces_valid: []u8,
    allocator: *std.mem.Allocator,
    piece_acquire_mutex: std.Mutex,
    initial_want_block_count: usize,
    have_block_count: std.atomic.Int(usize),
    want_block_count: std.atomic.Int(usize),
    total_len: usize,
    piece_len: usize,

    pub fn init(total_len: usize, piece_len: usize, allocator: *std.mem.Allocator) !Pieces {
        var want_blocks_bitfield = std.ArrayList(u8).init(allocator);
        const initial_want_block_count: usize = utils.divCeil(usize, total_len, block_len);
        try want_blocks_bitfield.appendNTimes(0xff, utils.divCeil(usize, initial_want_block_count, 8));

        var pieces_valid = std.ArrayList(u8).init(allocator);
        const pieces_count = utils.divCeil(usize, total_len, piece_len);
        try pieces_valid.appendNTimes(0, utils.divCeil(usize, pieces_count, 8));

        return Pieces{
            .want_blocks_bitfield = want_blocks_bitfield.toOwnedSlice(),
            .allocator = allocator,
            .piece_acquire_mutex = std.Mutex{},
            .have_block_count = std.atomic.Int(usize).init(0),
            .want_block_count = std.atomic.Int(usize).init(initial_want_block_count),
            .initial_want_block_count = initial_want_block_count,
            .total_len = total_len,
            .piece_len = piece_len,
            .pieces_valid = pieces_valid.toOwnedSlice(),
        };
    }

    pub fn deinit(self: *Pieces) void {
        self.allocator.free(self.want_blocks_bitfield);
        self.allocator.free(self.pieces_valid);
    }

    pub fn acquireFileOffset(self: *Pieces, remote_have_file_offsets_bitfield: []const u8) ?usize {
        std.debug.assert(!self.isFinished());

        var trial: u32 = 0;
        while (trial < 20) : (trial += 1) {
            if (self.piece_acquire_mutex.tryAcquire()) |lock| {
                defer lock.release();

                for (self.want_blocks_bitfield) |*want, i| {
                    if (want.* == 0) continue;
                    const remote = remote_have_file_offsets_bitfield[i];
                    if ((want.* & remote) == 0) continue;

                    const bit: u3 = @intCast(u3, @ctz(u8, want.* & remote));
                    const block = i * 8 + bit;
                    std.debug.assert(block < self.initial_want_block_count);

                    const file_offset = block_len * block;
                    std.debug.assert(file_offset < self.total_len);

                    // Clear bit
                    want.* &= std.mem.nativeToBig(u8, ~(@as(u8, 1) << bit));

                    _ = self.want_block_count.decr();

                    std.log.debug(.zorrent_lib, "acquireFileOffset: overlap={} bit={} i={} file_offset={}", .{ want.* & remote, bit, i, file_offset });
                    return file_offset;
                }
                break;
            }
        }
        return null;
    }

    pub fn commitFileOffset(self: *Pieces, file_offset: usize) void {
        std.debug.assert(file_offset < self.total_len);
        const count = self.have_block_count.incr();
        std.debug.assert(count <= self.initial_want_block_count);
    }

    pub fn isFinished(self: *Pieces) bool {
        return self.initial_want_block_count == self.have_block_count.get();
    }

    pub fn releaseFileOffset(self: *Pieces, file_offset: usize) void {
        std.debug.assert(file_offset < self.total_len);

        while (true) {
            if (self.piece_acquire_mutex.tryAcquire()) |lock| {
                defer lock.release();

                const i: usize = file_offset / block_len / 8;
                const bit: u3 = @intCast(u3, i % 8);
                // Set bit to 1
                self.want_blocks_bitfield[i] |= std.mem.nativeToBig(u8, @as(u8, 1) << bit);
                _ = self.want_block_count.incr();
                return;
            }
        }
    }

    pub fn displayStats(self: *Pieces) void {
        const have: usize = self.have_block_count.get();
        const want: usize = self.want_block_count.get();
        std.debug.assert(want <= self.initial_want_block_count);

        const total: usize = want + have;
        const percent: f64 = @intToFloat(f64, have) / @intToFloat(f64, total) * 100.0;

        std.log.info(.zorrent_lib, "[Blocks Have/Remaining/Total/Have Size/Total size: {}/{}/{}/{Bi:.2}/{Bi:.2}] {d:.2}%", .{ have, want, total, have * block_len, self.initial_want_block_count * block_len, percent });
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

    pub fn checkPiecesValid(self: *Pieces, pieces_len: usize, file_buffer: []const u8, hashes: []const u8) bool {
        // TODO: parallelize
        var all_valid = true;
        var piece: usize = 0;
        while (piece < pieces_len) : (piece += 1) {
            const begin: usize = piece * self.piece_len;
            const expected_len: usize = self.piece_len;
            const bit: u3 = @intCast(u3, piece % 8);
            const is_piece_valid = (self.pieces_valid[piece / 8] & (@as(u8, 1) << bit)) != 0;
            if (is_piece_valid) continue;

            if (!isPieceHashValid(piece, file_buffer[begin..std.math.min(file_buffer.len, begin + expected_len)], hashes)) {
                all_valid = false;
                std.log.warn(.zorrent_lib, "Invalid piece={}", .{piece});

                markFileOffsetsFromPiece(self.want_blocks_bitfield, @intCast(u32, piece), pieces_len, file_buffer.len);
                _ = self.want_block_count.incr();

                // TODO: re-fetch piece
            } else {
                self.pieces_valid[piece / 8] |= @as(u8, 1) << bit;
                std.log.info(.zorrent_lib, "Piece {}/{} valid", .{ piece + 1, pieces_len });
            }
        }

        return all_valid;
    }
};

test "init" {
    var pieces = try Pieces.init(131_073, testing.allocator);
    defer pieces.deinit();

    testing.expectEqual(@as(usize, 9), pieces.want_block_count.get());
    testing.expectEqual(@as(usize, 0), pieces.have_block_count.get());
    testing.expectEqual(@as(usize, 131_073), pieces.total_len);

    testing.expectEqual(@as(usize, 2), pieces.want_blocks_bitfield.len);
    testing.expectEqual(@as(usize, 0xff), pieces.want_blocks_bitfield[0]);
    testing.expectEqual(@as(usize, 0xff), pieces.want_blocks_bitfield[1]);
}

test "acquireFileOffset" {
    var pieces = try Pieces.init(131_073, testing.allocator);
    defer pieces.deinit();

    var remote_have_blocks_bitfield = std.ArrayList(u8).init(testing.allocator);
    defer remote_have_blocks_bitfield.deinit();
    const initial_remote_have_block_count: usize = utils.divCeil(usize, 131_073, block_len);
    try remote_have_blocks_bitfield.appendNTimes(0, utils.divCeil(usize, initial_remote_have_block_count, 8));

    testing.expectEqual(@as(?usize, null), pieces.acquireFileOffset(remote_have_blocks_bitfield.items[0..]));

    remote_have_blocks_bitfield.items[0] = 0b0000_0001;
    testing.expectEqual(@as(?usize, 0), pieces.acquireFileOffset(remote_have_blocks_bitfield.items[0..]));

    testing.expectEqual(@as(u8, 0b1111_1110), pieces.want_blocks_bitfield[0]);
    testing.expectEqual(@as(usize, 8), pieces.want_block_count.get());
    testing.expectEqual(@as(usize, 0), pieces.have_block_count.get());
}

test "commitFileOffset" {
    var pieces = try Pieces.init(131_073, testing.allocator);
    defer pieces.deinit();

    var remote_have_blocks_bitfield = std.ArrayList(u8).init(testing.allocator);
    defer remote_have_blocks_bitfield.deinit();
    const initial_remote_have_block_count: usize = utils.divCeil(usize, 131_073, block_len);
    try remote_have_blocks_bitfield.appendNTimes(0, utils.divCeil(usize, initial_remote_have_block_count, 8));

    remote_have_blocks_bitfield.items[0] = 0b0000_0001;
    testing.expectEqual(@as(?usize, 0), pieces.acquireFileOffset(remote_have_blocks_bitfield.items[0..]));

    pieces.commitFileOffset(0);
    testing.expectEqual(@as(usize, 1), pieces.have_block_count.get());
}

test "commitFileOffset" {
    var pieces = try Pieces.init(131_073, testing.allocator);
    defer pieces.deinit();

    var remote_have_blocks_bitfield = std.ArrayList(u8).init(testing.allocator);
    defer remote_have_blocks_bitfield.deinit();
    const initial_remote_have_block_count: usize = utils.divCeil(usize, 131_073, block_len);
    try remote_have_blocks_bitfield.appendNTimes(0, utils.divCeil(usize, initial_remote_have_block_count, 8));

    remote_have_blocks_bitfield.items[0] = 0b0000_0001;
    testing.expectEqual(@as(?usize, 0), pieces.acquireFileOffset(remote_have_blocks_bitfield.items[0..]));

    pieces.releaseFileOffset(0);
    testing.expectEqual(@as(u8, 0b1111_1111), pieces.want_blocks_bitfield[0]);
    testing.expectEqual(@as(usize, 9), pieces.want_block_count.get());
    testing.expectEqual(@as(usize, 0), pieces.have_block_count.get());
}

test "isFinished" {
    var pieces = try Pieces.init(131_073, testing.allocator);
    defer pieces.deinit();

    var remote_have_blocks_bitfield = std.ArrayList(u8).init(testing.allocator);
    defer remote_have_blocks_bitfield.deinit();
    const initial_remote_have_block_count: usize = utils.divCeil(usize, 131_073, block_len);
    try remote_have_blocks_bitfield.appendNTimes(0xff, utils.divCeil(usize, initial_remote_have_block_count, 8));

    var block: usize = 0;
    while (block < 9) : (block += 1) {
        testing.expectEqual(false, pieces.isFinished());
        pieces.commitFileOffset(pieces.acquireFileOffset(remote_have_blocks_bitfield.items).?);
    }
    testing.expectEqual(true, pieces.isFinished());
    testing.expectEqual(@as(usize, 0), pieces.want_block_count.get());
    testing.expectEqual(@as(usize, 9), pieces.have_block_count.get());
}
