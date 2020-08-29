const std = @import("std");

pub fn divCeil(comptime T: type, numerator: T, denumerator: T) T {
    return 1 + (numerator - 1) / denumerator;
}

pub fn openMmapFile(path: []const u8, file_len: usize) !MmapFile {
    const fd = try std.os.open(path, std.os.O_CREAT | std.os.O_RDWR, 438);
    try std.os.ftruncate(fd, file_len);

    var data = try std.os.mmap(
        null,
        file_len,
        std.os.PROT_READ | std.os.PROT_WRITE,
        std.os.MAP_FILE | std.os.MAP_SHARED,
        fd,
        0,
    );
    std.debug.assert(data.len == file_len);

    return MmapFile{ .fd = fd, .data = data };
}

pub const MmapFile = struct {
    fd: c_int,
    data: []align(std.mem.page_size) u8,

    pub fn deinit(self: *MmapFile) void {
        defer std.os.munmap(self.data);
        defer std.os.close(self.fd);
    }
};
