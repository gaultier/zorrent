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
    block_count: usize,
    total_len: usize,
    piece_len: usize,
    blocks_per_piece: usize,
    pieces_count: usize,
    valid_block_count: std.atomic.Int(usize),
    pieces_valid_mutex: std.Mutex,
    file_buffer: []u8,
    file: std.fs.File,

    pub fn init(total_len: usize, piece_len: usize, file_path: []const u8, hashes: []const u8, allocator: *std.mem.Allocator) !Pieces {
        const block_count: usize = utils.divCeil(usize, total_len, block_len);
        const blocks_bitfield_len = utils.divCeil(usize, block_count, 8);

        var pieces_valid = std.ArrayList(u8).init(allocator);
        errdefer pieces_valid.deinit();
        const pieces_count = utils.divCeil(usize, total_len, piece_len);
        try pieces_valid.appendNTimes(0, utils.divCeil(usize, pieces_count, 8));

        var have_blocks_bitfield = std.ArrayList(u8).init(allocator);
        defer have_blocks_bitfield.deinit();
        try have_blocks_bitfield.appendNTimes(0, blocks_bitfield_len);

        var file_exists = true;
        const file: std.fs.File = std.fs.cwd().openFile(file_path, .{ .write = true }) catch |err| fs_catch: {
            switch (err) {
                std.fs.File.OpenError.FileNotFound => {
                    file_exists = false;
                    break :fs_catch try std.fs.cwd().createFile(file_path, .{ .read = true });
                },
                else => return err, // TODO: Maybe we can recover in some way?
            }
        };
        try std.os.ftruncate(file.handle, total_len);

        var file_buffer: []u8 = if (file_exists) file_buf: {
            break :file_buf try file.inStream().readAllAlloc(allocator, total_len);
        } else file_buf: {
            var file_buffer = std.ArrayList(u8).init(allocator);
            defer file_buffer.deinit();
            try file_buffer.appendNTimes(0, total_len);
            break :file_buf file_buffer.toOwnedSlice();
        };
        std.debug.assert(file_buffer.len == total_len);

        var pieces = Pieces{
            .have_blocks_bitfield = have_blocks_bitfield.toOwnedSlice(),
            .allocator = allocator,
            .piece_acquire_mutex = std.Mutex{},
            .block_count = block_count,
            .total_len = total_len,
            .piece_len = piece_len,
            .blocks_per_piece = piece_len / block_len,
            .pieces_count = pieces_count,
            .pieces_valid = pieces_valid.toOwnedSlice(),
            .valid_block_count = std.atomic.Int(usize).init(0),
            .pieces_valid_mutex = std.Mutex{},
            .file = file,
            .file_buffer = file_buffer,
        };

        if (file_exists) {
            _ = try pieces.checkPiecesValid(pieces.file_buffer, hashes);
        }

        return pieces;
    }

    pub fn deinit(self: *Pieces) void {
        self.allocator.free(self.have_blocks_bitfield);
        self.allocator.free(self.pieces_valid);
        self.allocator.free(self.file_buffer);
        self.file.close();
    }

    pub fn isFinished(self: *Pieces) bool {
        return self.valid_block_count.get() == self.block_count;
    }

    pub fn tryAcquireFileOffset(self: *Pieces, remote_have_file_offsets_bitfield: []const u8) ?usize {
        while (true) {
            if (self.piece_acquire_mutex.tryAcquire()) |lock| {
                defer lock.release();

                var block: usize = 0;
                while (block < self.block_count) : (block += 1) {
                    if (!utils.bitArrayIsSet(self.have_blocks_bitfield[0..], block) and utils.bitArrayIsSet(remote_have_file_offsets_bitfield[0..], block)) {
                        return block * block_len;
                    }
                }
                return null;
            }
        }
    }

    pub fn commitFileOffset(self: *Pieces, file_offset: usize, data: []const u8, hashes: []const u8) !void {
        std.debug.assert(file_offset < self.total_len);

        while (true) {
            if (self.pieces_valid_mutex.tryAcquire()) |lock| {
                defer lock.release();

                const block = file_offset / block_len;
                // If another peer has already provided this block
                if (utils.bitArrayIsSet(self.have_blocks_bitfield, block)) return;

                std.mem.copy(u8, self.file_buffer[file_offset .. file_offset + data.len], data);
                try self.file.seekTo(file_offset);
                _ = try self.file.writeAll(data);
                try self.file.seekTo(0);

                utils.bitArraySet(self.have_blocks_bitfield, block);

                self.checkPieceValidForBlock(block, self.file_buffer, hashes);
                return;
            }
        }
    }

    pub fn displayStats(self: *Pieces) void {
        const valid = self.valid_block_count.get();
        const total = self.block_count;
        const percent: f64 = @intToFloat(f64, valid) / @intToFloat(f64, total) * 100.0;

        std.log.info("[Blocks Valid/Total/Have Size/Total size: {}/{}/{Bi:.2}/{Bi:.2}] {d:.2}%", .{ valid, total, std.math.min(self.total_len, valid * block_len), self.total_len, percent });
        return;
    }

    fn isPieceHashValid(piece: usize, piece_data: []const u8, hashes: []const u8) bool {
        const expected_hash = hashes[piece * 20 .. (piece + 1) * 20];
        var actual_hash: [20]u8 = undefined;
        std.crypto.hash.Sha1.hash(piece_data[0..], actual_hash[0..], std.crypto.hash.Sha1.Options{});
        const identical = std.mem.eql(u8, actual_hash[0..20], expected_hash[0..20]);

        std.log.debug("isPieceHashValid: piece={} actual_hash={X} expected_hash={X} matching_hash={}", .{ piece, actual_hash, expected_hash, identical });
        return identical;
    }

    fn checkPieceValidForBlock(self: *Pieces, block: usize, file_buffer: []const u8, hashes: []const u8) void {
        std.debug.assert(block < self.block_count);

        const file_offset: usize = block * block_len;
        const piece: u32 = @intCast(u32, file_offset / self.piece_len);
        const file_offset_piece_begin: usize = piece * self.piece_len;
        std.debug.assert(file_offset_piece_begin < self.total_len);

        // Check cache
        if (utils.bitArrayIsSet(self.pieces_valid[0..], piece)) return;

        // Check if we have all blocks for piece
        const real_len: usize = std.math.min(self.total_len - file_offset_piece_begin, self.piece_len);
        {
            var block_i = piece * self.blocks_per_piece;
            while (block_i * block_len < (piece + 1) * self.piece_len and block_i * block_len < self.total_len) : (block_i += 1) {
                if (!utils.bitArrayIsSet(self.have_blocks_bitfield[0..], block_i)) return;
            }
        }

        const valid = isPieceHashValid(piece, file_buffer[file_offset_piece_begin .. file_offset_piece_begin + real_len], hashes);

        if (valid) {
            std.log.info("Piece valid: {}", .{piece});

            const blocks_count = utils.divCeil(usize, real_len, block_len);
            const val = self.valid_block_count.fetchAdd(blocks_count);
            std.debug.assert(val <= self.block_count);

            utils.bitArraySet(self.pieces_valid, piece);
        } else {
            std.log.warn("Piece invalid: {}", .{piece});
            utils.bitArrayClear(self.pieces_valid, piece);

            var block_i = piece * self.blocks_per_piece;
            while (block_i * block_len < (piece + 1) * self.piece_len and block_i * block_len < self.total_len) : (block_i += 1) {
                utils.bitArrayClear(self.have_blocks_bitfield[0..], block_i);
            }
        }
        return;
    }

    fn checkPieceValid(arg: usize) void {}

    pub fn checkPiecesValid(self: *Pieces, file_buffer: []const u8, hashes: []const u8) !void {
        const pieces_count: usize = utils.divCeil(usize, self.total_len, self.piece_len);

        const cpus = std.Thread.cpuCount() catch 4;
        var workers = std.ArrayList(*std.Thread).init(self.allocator);
        defer workers.deinit();

        for (workers.items) |*w, i| {
            const work_len = if (i == workers.items.len - 1) self.pieces_count - self.pieces_count / workers.items.len else self.pieces_count / workers.items.len;
            w.* = try std.Thread.spawn(work_len, checkPieceValid);
        }

        for (workers.items) |w| {
            w.wait();
        }

        while (true) {
            if (self.pieces_valid_mutex.tryAcquire()) |lock| {
                defer lock.release();
                // TODO: parallelize

                var piece: usize = 0;
                while (piece < pieces_count) : (piece += 1) {
                    const begin: usize = piece * self.piece_len;
                    const expected_len: usize = self.piece_len;
                    const real_len: usize = std.math.min(file_buffer.len - begin, self.piece_len);
                    std.debug.assert(real_len <= self.piece_len);

                    if (utils.bitArrayIsSet(self.pieces_valid[0..], piece)) continue;

                    const valid = self.valid_block_count.get();
                    const percent_valid = @intToFloat(f64, valid * 100) / @intToFloat(f64, self.block_count);
                    if (!isPieceHashValid(piece, file_buffer[begin .. begin + real_len], hashes)) {
                        std.log.warn("Invalid hash: piece={}/{} [Valid blocks/Total/%={}/{}/{d:.2}%]", .{ piece, self.pieces_count, valid, self.block_count, percent_valid });
                    } else {
                        const blocks_count = utils.divCeil(usize, real_len, block_len);
                        const val = self.valid_block_count.fetchAdd(blocks_count);
                        std.debug.assert(val <= self.block_count);

                        utils.bitArraySet(self.pieces_valid[0..], piece);
                        std.log.info("Valid hash: piece={}/{} [Valid blocks/Total/%={}/{}/{d:.2}%]", .{ piece, self.pieces_count, valid, self.block_count, percent_valid });
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

test "init without an existing file" {
    std.os.unlink("foo") catch {};
    defer std.os.unlink("foo") catch {};

    const total_len = 18 * block_len + 5;
    var pieces = try Pieces.init(total_len, 2 * block_len, "foo", &[0]u8{}, testing.allocator);
    defer pieces.deinit();

    testing.expectEqual(@as(usize, total_len), pieces.file_buffer.len);

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

test "tryAcquireFileOffset" {
    std.os.unlink("foo") catch {};
    defer std.os.unlink("foo") catch {};

    const total_len = 18 * block_len + 5;
    var pieces = try Pieces.init(total_len, 2 * block_len, "foo", &[0]u8{}, testing.allocator);
    defer pieces.deinit();

    var remote_have_blocks_bitfield = std.ArrayList(u8).init(testing.allocator);
    defer remote_have_blocks_bitfield.deinit();
    const initial_remote_have_block_count: usize = utils.divCeil(usize, total_len, block_len);
    try remote_have_blocks_bitfield.appendNTimes(0, utils.divCeil(usize, initial_remote_have_block_count, 8));

    testing.expectEqual(@as(?usize, null), pieces.tryAcquireFileOffset(remote_have_blocks_bitfield.items[0..]));

    remote_have_blocks_bitfield.items[0] = 0b0001_0001;
    testing.expectEqual(@as(?usize, 0 * block_len), pieces.tryAcquireFileOffset(remote_have_blocks_bitfield.items[0..]));

    utils.bitArraySet(pieces.have_blocks_bitfield, 0);
    utils.bitArraySet(pieces.have_blocks_bitfield, 1);
    testing.expectEqual(@as(?usize, 4 * block_len), pieces.tryAcquireFileOffset(remote_have_blocks_bitfield.items[0..]));
}

test "tryAcquireFileOffset at 100% completion" {
    std.os.unlink("foo") catch {};
    defer std.os.unlink("foo") catch {};

    const total_len = 18 * block_len + 5;
    var pieces = try Pieces.init(total_len, 2 * block_len, "foo", &[0]u8{}, testing.allocator);
    defer pieces.deinit();

    std.mem.set(u8, pieces.have_blocks_bitfield[0..], 0xff);
    std.mem.set(u8, pieces.pieces_valid[0..], 0xff);
    pieces.valid_block_count.set(10);

    var remote_have_blocks_bitfield = std.ArrayList(u8).init(testing.allocator);
    defer remote_have_blocks_bitfield.deinit();
    const initial_remote_have_block_count: usize = utils.divCeil(usize, total_len, block_len);
    try remote_have_blocks_bitfield.appendNTimes(0xff, utils.divCeil(usize, initial_remote_have_block_count, 8));

    testing.expectEqual(@as(?usize, null), pieces.tryAcquireFileOffset(remote_have_blocks_bitfield.items[0..]));
}

test "commitFileOffset" {
    std.os.unlink("foo") catch {};
    defer std.os.unlink("foo") catch {};

    const total_len = 18 * block_len + 5;
    const piece_len = 2 * block_len;
    var pieces = try Pieces.init(total_len, piece_len, "foo", &[0]u8{}, testing.allocator);
    defer pieces.deinit();

    var remote_have_blocks_bitfield = std.ArrayList(u8).init(testing.allocator);
    defer remote_have_blocks_bitfield.deinit();
    const initial_remote_have_block_count: usize = utils.divCeil(usize, total_len, block_len);
    try remote_have_blocks_bitfield.appendNTimes(0, utils.divCeil(usize, initial_remote_have_block_count, 8));

    remote_have_blocks_bitfield.items[0] = 0b0000_0001;
    testing.expectEqual(@as(?usize, 0 * block_len), pieces.tryAcquireFileOffset(remote_have_blocks_bitfield.items[0..]));

    var data: [piece_len]u8 = undefined;
    for (data) |*v, i| v.* = @intCast(u8, i % 8);

    const hash = [20]u8{ 0xF1, 0x20, 0xBA, 0xD5, 0xAA, 0x2F, 0xC4, 0x86, 0x34, 0x9B, 0xEF, 0xED, 0x84, 0x4F, 0x37, 0x4C, 0x57, 0xEB, 0xE7, 0xD8 };
    const hash_rest = [20 * 9]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const hashes: [20 * 10]u8 = hash ++ hash_rest;

    // We only have one block, not the whole first piece, so no hash check can be done
    {
        try pieces.commitFileOffset(0 * block_len, data[0..], hashes[0..]);

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

        std.testing.expectEqual(true, std.mem.eql(u8, data[0..block_len], pieces.file_buffer[0..block_len]));

        const disk_data = try pieces.file.readAllAlloc(std.testing.allocator, total_len, total_len);
        defer std.testing.allocator.free(disk_data);
        std.testing.expectEqual(true, std.mem.eql(u8, data[0..block_len], disk_data[0..block_len]));
    }

    // We now have the full piece
    {
        try pieces.commitFileOffset(1 * block_len, data[0..], hashes[0..]);
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

        std.testing.expectEqual(true, std.mem.eql(u8, data[0 .. 2 * block_len], pieces.file_buffer[0 .. 2 * block_len]));

        const disk_data = try pieces.file.readAllAlloc(std.testing.allocator, total_len, total_len);
        defer std.testing.allocator.free(disk_data);
        std.testing.expectEqual(true, std.mem.eql(u8, data[0 .. 2 * block_len], disk_data[0 .. 2 * block_len]));

        testing.expectEqual(true, Pieces.isPieceHashValid(0, disk_data[0..piece_len], hashes[0..]));
        testing.expectEqual(false, Pieces.isPieceHashValid(1, disk_data[piece_len .. 2 * piece_len], hashes[0..]));
    }
}

test "recover state from file" {
    std.os.unlink("foo") catch {};
    defer std.os.unlink("foo") catch {};

    {
        const total_len = 18 * block_len + 5;
        const piece_len = 2 * block_len;
        const hash = [20]u8{ 0xE6, 0x4E, 0xA4, 0x9D, 0xEF, 0x87, 0x53, 0x70, 0x83, 0xFA, 0x06, 0xE0, 0xD9, 0x6F, 0x4F, 0xAD, 0x00, 0x65, 0x0D, 0x11 };

        const hash_rest = [20 * 9]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        const hashes: [20 * 10]u8 = hash ++ hash_rest;

        var pieces = try Pieces.init(total_len, piece_len, "foo", hashes[0..], testing.allocator);
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

        try pieces.checkPiecesValid(file_buffer[0..], hashes[0..]);
        testing.expectEqual(@as(usize, 2), pieces.valid_block_count.get());
        // pieces.commitFileOffset(pieces.tryAcquireFileOffset(remote_have_blocks_bitfield.items).?, file_buffer[0..], hashes[0..]);
    }

    // {
    //     var pieces = try Pieces.init(131_073, 16 * block_len, testing.allocator);
    //     defer pieces.deinit();

    //     testing.expectEqual(@as(usize, 2), pieces.blocks_bitfield.len);
    //     testing.expectEqual(@as(usize, 0b1111_1110), pieces.blocks_bitfield[0]);
    //     testing.expectEqual(@as(usize, 0b1000_0000), pieces.blocks_bitfield[1]);
    //     testing.expectEqual(@as(usize, 8), pieces.block_count.get());

    //     var remote_have_blocks_bitfield = std.ArrayList(u8).init(testing.allocator);
    //     defer remote_have_blocks_bitfield.deinit();
    //     const initial_remote_have_block_count: usize = utils.divCeil(usize, 131_073, block_len);
    //     try remote_have_blocks_bitfield.appendNTimes(0, utils.divCeil(usize, initial_remote_have_block_count, 8));

    //     testing.expectEqual(@as(?usize, null), pieces.tryAcquireFileOffset(remote_have_blocks_bitfield.items[0..]));

    //     remote_have_blocks_bitfield.items[0] = 0b0000_0001;
    //     testing.expectEqual(@as(?usize, null), pieces.tryAcquireFileOffset(remote_have_blocks_bitfield.items[0..]));
    // }
}
