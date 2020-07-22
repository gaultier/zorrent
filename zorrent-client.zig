const zorrent = @import("zorrent");
const std = @import("std");

pub fn main() anyerror!void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    const allocator = &arena.allocator;

    var args = try std.process.argsAlloc(allocator);
    const arg = if (args.len == 2) args[1] else return error.MissingCliArgument;

    var value_tree = try zorrent.parseFile(arg, allocator);
    defer value_tree.deinit();
}
