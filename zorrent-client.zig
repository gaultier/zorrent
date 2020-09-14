const zorrent = @import("zorrent");
const std = @import("std");

pub const io_mode = .evented;
pub const log_level: std.log.Level = .err;

pub fn log(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    const green = "\x1b[32m";
    const red = "\x1b[31m";
    const grey = "\x1b[37m";
    const reset = "\x1b[0m";

    const scope_prefix = "[" ++ switch (level) {
        .info, .notice => green,
        .debug => grey,
        else => red,
    } ++ @tagName(scope) ++ "][";

    const prefix = scope_prefix ++ @tagName(level) ++ "] ";

    // Print the message to stderr, silently ignoring any errors
    const held = std.debug.getStderrMutex().acquire();
    defer held.release();
    const stderr = std.io.getStdErr().writer();
    nosuspend stderr.print(prefix ++ format ++ "\x1b[0m\n", args) catch return;
}

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = &gpa.allocator;

    var args = try std.process.argsAlloc(allocator);
    const torrent_file_path = if (args.len == 2) args[1] else {
        try std.io.getStdOut().outStream().writeAll("zorrent <torrent file>\n");
        return;
    };

    try zorrent.run(torrent_file_path, allocator);
}
