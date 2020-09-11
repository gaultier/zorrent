const std = @import("std");
const utils = @import("utils.zig");
const testing = std.testing;

pub const block_len: usize = 1 << 14;

const file_name = ".zorrent_state";

pub fn setAllBlocksForPiece(bitfield: []u8, piece: u32, piece_len: usize, total_len: usize) void {
    const blocks_in_piece = utils.divCeil(usize, piece_len, block_len);
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

const CheckHashWork = struct {
    pieces: *Pieces,
    file_buffer: []const u8,
    hashes: []const u8,
    piece_start: usize,
    pieces_count: usize,

    fn checkPieceValid(work: *CheckHashWork) void {
        var piece: usize = work.piece_start;
        const piece_end = std.math.min(piece + work.pieces_count, work.pieces.pieces_count);

        std.log.debug("Worker #{}: piece_start={} pieces_count={} piece_end={}", .{ work.piece_start / work.pieces_count, work.piece_start, work.pieces_count, piece_end });

        while (piece < piece_end) : (piece += 1) {
            const begin: usize = piece * work.pieces.piece_len;
            const expected_len: usize = work.pieces.piece_len;
            const real_len: usize = std.math.min(work.file_buffer.len - begin, work.pieces.piece_len);
            std.debug.assert(real_len <= work.pieces.piece_len);

            if (utils.bitArrayIsSet(work.pieces.pieces_valid[0..], piece)) continue;

            if (!Pieces.isPieceHashValid(piece, work.file_buffer[begin .. begin + real_len], work.hashes)) {
                const valid = work.pieces.valid_piece_count.get();
                const percent_valid = @intToFloat(f64, valid * 100) / @intToFloat(f64, work.pieces.pieces_count);

                std.log.warn("Invalid hash: piece={} [Valid pieces/Total Blocks/Total % {}/{} {}/{} {d:.2}%]", .{ piece, valid / work.pieces.blocks_per_piece, work.pieces.pieces_count, valid, work.pieces.block_count, percent_valid });
            } else {
                const blocks_count = utils.divCeil(usize, real_len, block_len);
                const val = work.pieces.valid_piece_count.incr();
                std.debug.assert(val <= work.pieces.pieces_count);

                utils.bitArraySet(work.pieces.pieces_valid[0..], piece);

                work.pieces.displayStats();
            }
        }
    }
};

pub const Pieces = struct {
    have_blocks_bitfield: []u8,
    inflight_blocks_bitfield: []u8,
    pieces_valid: []u8,
    allocator: *std.mem.Allocator,
    piece_acquire_mutex: std.Mutex,
    block_count: usize,
    total_len: usize,
    piece_len: usize,
    blocks_per_piece: usize,
    pieces_count: usize,
    valid_piece_count: std.atomic.Int(usize),
    pieces_valid_mutex: std.Mutex,
    file_buffer: []u8,
    files: []std.fs.File,
    file_paths: []const []const u8,
    file_sizes: []const usize,

    pub fn init(total_len: usize, piece_len: usize, file_paths: []const []const u8, hashes: []const u8, file_sizes: []const usize, allocator: *std.mem.Allocator) !Pieces {
        const block_count: usize = utils.divCeil(usize, total_len, block_len);
        const blocks_bitfield_len = utils.divCeil(usize, block_count, 8);

        var pieces_valid = std.ArrayList(u8).init(allocator);
        errdefer pieces_valid.deinit();
        const pieces_count = utils.divCeil(usize, total_len, piece_len);
        try pieces_valid.appendNTimes(0, utils.divCeil(usize, pieces_count, 8));

        var have_blocks_bitfield = std.ArrayList(u8).init(allocator);
        defer have_blocks_bitfield.deinit();
        try have_blocks_bitfield.appendNTimes(0, blocks_bitfield_len);

        var inflight_blocks_bitfield = std.ArrayList(u8).init(allocator);
        defer inflight_blocks_bitfield.deinit();
        try inflight_blocks_bitfield.appendNTimes(0, blocks_bitfield_len);

        if (file_paths.len == 0) return error.NoFiles;
        if (file_paths.len > 1) return error.UnsupportedExtension;

        var files = std.ArrayList(std.fs.File).init(allocator);
        defer files.deinit();
        try files.ensureCapacity(file_paths.len);

        var file_buffer = std.ArrayList(u8).init(allocator);
        defer file_buffer.deinit();
        try file_buffer.ensureCapacity(total_len);

        for (file_paths) |fp, i| {
            var file_exists = true;

            const file: std.fs.File = std.fs.cwd().openFile(fp, .{ .write = true }) catch |err| fs_catch: {
                switch (err) {
                    std.fs.File.OpenError.FileNotFound => {
                        file_exists = false;
                        break :fs_catch try std.fs.cwd().createFile(fp, .{ .read = true });
                    },
                    else => return err, // TODO: Maybe we can recover in some way?
                }
            };
            const len = file_sizes[i];
            try std.os.ftruncate(file.handle, len);

            files.addOneAssumeCapacity().* = file;

            var buf: []u8 = if (file_exists) file_buf: {
                break :file_buf try file.inStream().readAllAlloc(allocator, total_len);
            } else file_buf: {
                var buf = std.ArrayList(u8).init(allocator);
                defer buf.deinit();
                try buf.appendNTimes(0, total_len);
                break :file_buf buf.toOwnedSlice();
            };
            file_buffer.appendSliceAssumeCapacity(buf);
        }
        std.debug.assert(file_buffer.items.len == total_len);

        var pieces = Pieces{
            .have_blocks_bitfield = have_blocks_bitfield.toOwnedSlice(),
            .inflight_blocks_bitfield = inflight_blocks_bitfield.toOwnedSlice(),
            .allocator = allocator,
            .piece_acquire_mutex = std.Mutex{},
            .block_count = block_count,
            .total_len = total_len,
            .piece_len = piece_len,
            .blocks_per_piece = utils.divCeil(usize, piece_len, block_len),
            .pieces_count = pieces_count,
            .pieces_valid = pieces_valid.toOwnedSlice(),
            .valid_piece_count = std.atomic.Int(usize).init(0),
            .pieces_valid_mutex = std.Mutex{},
            .files = files.toOwnedSlice(),
            .file_buffer = file_buffer.toOwnedSlice(),
            .file_paths = file_paths,
            .file_sizes = file_sizes,
        };

        // if (file_exists) {
        _ = try pieces.checkPiecesValid(pieces.file_buffer, pieces.file_sizes, hashes);
        // }

        return pieces;
    }

    pub fn deinit(self: *Pieces) void {
        self.allocator.free(self.have_blocks_bitfield);
        self.allocator.free(self.inflight_blocks_bitfield);
        self.allocator.free(self.pieces_valid);
        self.allocator.free(self.file_buffer);
        self.file.close();
    }

    pub fn isFinished(self: *Pieces) bool {
        return self.valid_piece_count.get() == self.pieces_count;
    }

    pub fn tryAcquireFileOffset(self: *Pieces, remote_have_file_offsets_bitfield: []const u8) ?usize {
        while (true) {
            if (self.piece_acquire_mutex.tryAcquire()) |lock| {
                defer lock.release();

                var block: usize = 0;
                while (block < self.block_count) : (block += 1) {
                    const piece = block / self.blocks_per_piece;
                    if (!utils.bitArrayIsSet(self.inflight_blocks_bitfield, block) and !utils.bitArrayIsSet(self.pieces_valid, piece) and !utils.bitArrayIsSet(self.have_blocks_bitfield[0..], block) and utils.bitArrayIsSet(remote_have_file_offsets_bitfield[0..], block)) {
                        utils.bitArraySet(self.inflight_blocks_bitfield, block);
                        return block * block_len;
                    }
                }
                return null;
            }
        }
    }
    pub fn releaseFileOffset(self: *Pieces, file_offset: usize) void {
        std.debug.assert(file_offset < self.total_len);

        std.log.debug("releaseFileOffset: file_offset={}", .{file_offset});

        while (true) {
            if (self.pieces_valid_mutex.tryAcquire()) |lock| {
                defer lock.release();

                const block = file_offset / block_len;

                utils.bitArraySet(self.inflight_blocks_bitfield, block);
                return;
            }
        }
    }

    pub fn commitFileOffset(self: *Pieces, file_offset: usize, data: []const u8, hashes: []const u8) !void {
        std.debug.assert(file_offset < self.total_len);

        while (true) {
            if (self.pieces_valid_mutex.tryAcquire()) |lock| {
                defer lock.release();

                const block = file_offset / block_len;

                utils.bitArrayClear(self.inflight_blocks_bitfield, block);

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
        const valid = self.valid_piece_count.get();
        const total = self.pieces_count;
        const percent: f64 = @intToFloat(f64, valid) / @intToFloat(f64, total) * 100.0;

        const held = std.debug.getStderrMutex().acquire();
        defer held.release();
        const stderr = std.io.getStdErr().writer();
        nosuspend stderr.print("\x1b[1A\x1b[2K{} [{}/{} {Bi:.2}/{Bi:.2}] {d:.2}%\n", .{ self.file_paths[0], valid, total, std.math.min(self.total_len, valid * self.piece_len), self.total_len, percent }) catch return;
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
            const val = self.valid_piece_count.incr();
            std.debug.assert(val <= self.pieces_count);

            utils.bitArraySet(self.pieces_valid, piece);

            var block_i = piece * self.blocks_per_piece;
            while (block_i * block_len < (piece + 1) * self.piece_len and block_i * block_len < self.total_len) : (block_i += 1) {
                utils.bitArraySet(self.have_blocks_bitfield[0..], block_i);
            }
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

    fn checkPiecesValid(self: *Pieces, file_buffer: []const u8, file_sizes: []const usize, hashes: []const u8) !void {
        // Print one newline to avoid erasing the command line invocation
        std.io.getStdErr().writeAll("\n") catch {};

        const cpus = std.Thread.cpuCount() catch 4;

        var work = std.ArrayList(CheckHashWork).init(self.allocator);
        try work.ensureCapacity(cpus);
        defer work.deinit();

        var workers = std.ArrayList(*std.Thread).init(self.allocator);
        try workers.ensureCapacity(cpus);
        defer workers.deinit();

        {
            var w: usize = 0;
            while (w < cpus) : (w += 1) {
                const pieces_count = utils.divCeil(usize, self.pieces_count, cpus);
                const piece_begin = w * pieces_count;

                work.addOneAssumeCapacity().* = CheckHashWork{
                    .pieces = self,
                    .file_buffer = file_buffer,
                    .hashes = hashes,
                    .piece_start = piece_begin,
                    .pieces_count = pieces_count,
                };
                workers.addOneAssumeCapacity().* = try std.Thread.spawn(&work.items[w], CheckHashWork.checkPieceValid);
            }
        }

        for (workers.items) |w| {
            w.wait();
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
    const file_path = "foo";
    const file_paths = [1][]const u8{file_path[0..]};
    var pieces = try Pieces.init(total_len, 2 * block_len, file_paths[0..], &[0]u8{}, testing.allocator);
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

    testing.expectEqual(@as(usize, 0), pieces.valid_piece_count.get());
}

test "tryAcquireFileOffset" {
    std.os.unlink("foo") catch {};
    defer std.os.unlink("foo") catch {};

    const total_len = 18 * block_len + 5;
    const file_path = "foo";
    const file_paths = [1][]const u8{file_path[0..]};
    var pieces = try Pieces.init(total_len, 2 * block_len, file_paths[0..], &[0]u8{}, testing.allocator);
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
    const file_path = "foo";
    const file_paths = [1][]const u8{file_path[0..]};
    var pieces = try Pieces.init(total_len, 2 * block_len, file_paths[0..], &[0]u8{}, testing.allocator);
    defer pieces.deinit();

    std.mem.set(u8, pieces.have_blocks_bitfield[0..], 0xff);
    std.mem.set(u8, pieces.pieces_valid[0..], 0xff);
    pieces.valid_piece_count.set(5);

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
    const file_path = "foo";
    const file_paths = [1][]const u8{file_path[0..]};
    var pieces = try Pieces.init(total_len, piece_len, file_paths[0..], &[0]u8{}, testing.allocator);
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

        const file_path = "foo";
        const file_paths = [1][]const u8{file_path[0..]};
        var pieces = try Pieces.init(total_len, piece_len, file_paths[0..], hashes[0..], testing.allocator);
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

        testing.expectEqual(@as(usize, 0), pieces.valid_piece_count.get());

        var remote_have_blocks_bitfield = std.ArrayList(u8).init(testing.allocator);
        defer remote_have_blocks_bitfield.deinit();
        const initial_remote_have_block_count: usize = utils.divCeil(usize, total_len, block_len);
        try remote_have_blocks_bitfield.appendNTimes(0, utils.divCeil(usize, initial_remote_have_block_count, 8));

        var file_buffer: [10 * piece_len]u8 = undefined;
        for (file_buffer) |*f| f.* = 9;

        try pieces.checkPiecesValid(file_buffer[0..], hashes[0..]);
        testing.expectEqual(@as(usize, 1), pieces.valid_piece_count.get());
    }
}
