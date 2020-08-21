const std = @import("std");

pub const block_len: usize = 1 << 14;

pub const Pieces = struct {
    prng: std.rand.DefaultPrng,
    want_blocks_bitfield: std.ArrayList(u8),
    allocator: *std.mem.Allocator,
    piece_acquire_mutex: std.Mutex,
    initial_want_block_count: usize,
    have_block_count: std.atomic.Int(usize),
    want_block_count: std.atomic.Int(usize),
    total_len: usize,

    pub fn init(total_len: usize, allocator: *std.mem.Allocator) !Pieces {
        var buf: [8]u8 = undefined;
        try std.crypto.randomBytes(buf[0..]);
        const seed = std.mem.readIntLittle(u64, buf[0..8]);

        var want_blocks_bitfield = std.ArrayList(u8).init(allocator);
        // Div ceil
        const initial_want_block_count: usize = 1 + ((total_len - 1) / block_len);
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
            .total_len = total_len,
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
                std.log.debug(.zorrent_lib, "want={X} | have={X}\n", .{ self.want_blocks_bitfield.items, remote_have_file_offsets_bitfield });

                for (self.want_blocks_bitfield.items) |*want, i| {
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
            }
            std.time.sleep(1_000);
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
                self.want_blocks_bitfield.items[i] |= std.mem.nativeToBig(u8, @as(u8, 1) << bit);
                _ = self.want_block_count.incr();
            }
        }
    }

    pub fn displayStats(self: *Pieces) void {
        const have: usize = self.have_block_count.get();
        const want: usize = self.want_block_count.get();
        const total: usize = want + have;

        std.log.info(.zorrent_lib, "[Have/Remaining/Total/Size/Total size: {}/{}/{}/{Bi:.2}/{Bi:.2}] {d:.2}%", .{ have, want, total, have * block_len, self.initial_want_block_count * block_len, @intToFloat(f32, have) / @intToFloat(f32, total) * 100.0 });
        return;
    }
};
