const std = @import("std");
const bencode = @import("zig-bencode");

pub fn main() anyerror!void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = &arena.allocator;

    var value = bencode.ValueTree.parse("li20ee", allocator) catch |err| {
        try std.io.getStdErr().writer().print("Error parsing: {}\n", .{err});
        return;
    };
    defer {
        value.deinit();
    }

    std.debug.warn("decoded: {}\n", .{value});
}
