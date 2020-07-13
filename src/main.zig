const std = @import("std");
const bencode = @import("zig-bencode");

fn outputUnicodeEscape(
    codepoint: u21,
    out_stream: var,
) !void {
    if (codepoint <= 0xFFFF) {
        // If the character is in the Basic Multilingual Plane (U+0000 through U+FFFF),
        // then it may be represented as a six-character sequence: a reverse solidus, followed
        // by the lowercase letter u, followed by four hexadecimal digits that encode the character's code point.
        try out_stream.writeAll("\\u");
        try std.fmt.formatIntValue(codepoint, "x", std.fmt.FormatOptions{ .width = 4, .fill = '0' }, out_stream);
    } else {
        std.debug.assert(codepoint <= 0x10FFFF);
        // To escape an extended character that is not in the Basic Multilingual Plane,
        // the character is represented as a 12-character sequence, encoding the UTF-16 surrogate pair.
        const high = @intCast(u16, (codepoint - 0x10000) >> 10) + 0xD800;
        const low = @intCast(u16, codepoint & 0x3FF) + 0xDC00;
        try out_stream.writeAll("\\u");
        try std.fmt.formatIntValue(high, "x", std.fmt.FormatOptions{ .width = 4, .fill = '0' }, out_stream);
        try out_stream.writeAll("\\u");
        try std.fmt.formatIntValue(low, "x", std.fmt.FormatOptions{ .width = 4, .fill = '0' }, out_stream);
    }
}

fn dump(value: bencode.Value, indent: usize) anyerror!void {
    var out_stream = std.io.getStdOut().writer();

    switch (value) {
        .Integer => |n| {
            try out_stream.print("{}", .{n});
        },
        .String => |s| {
            var i: usize = 0;

            try out_stream.print("\"", .{});
            if (std.unicode.utf8ValidateSlice(s)) {
                while (i < s.len) : (i += 1) {
                    switch (s[i]) {
                        // normal ascii character
                        0x20...0x21, 0x23...0x2E, 0x30...0x5B, 0x5D...0x7F => |c| try out_stream.writeByte(c),
                        // only 2 characters that *must* be escaped
                        '\\' => try out_stream.writeAll("\\\\"),
                        '\"' => try out_stream.writeAll("\\\""),
                        // solidus is optional to escape
                        '/' => {
                            try out_stream.writeByte('/');
                        },
                        // control characters with short escapes
                        // TODO: option to switch between unicode and 'short' forms?
                        0x8 => try out_stream.writeAll("\\b"),
                        0xC => try out_stream.writeAll("\\f"),
                        '\n' => try out_stream.writeAll("\\n"),
                        '\r' => try out_stream.writeAll("\\r"),
                        '\t' => try out_stream.writeAll("\\t"),
                        else => {
                            const ulen = std.unicode.utf8ByteSequenceLength(s[i]) catch unreachable;
                            // control characters (only things left with 1 byte length) should always be printed as unicode escapes
                            if (ulen == 1) {
                                const codepoint = std.unicode.utf8Decode(s[i .. i + ulen]) catch unreachable;
                                try outputUnicodeEscape(codepoint, out_stream);
                            } else {
                                try out_stream.writeAll(s[i .. i + ulen]);
                            }
                            i += ulen - 1;
                        },
                    }
                }
            } else {
                for (s) |c| {
                    try out_stream.print("\\x{X}", .{c});
                }
            }
            try out_stream.print("\"", .{});
        },
        .Array => |arr| {
            for (arr.items) |v| {
                try out_stream.print("\n", .{});
                try out_stream.writeByteNTimes(' ', indent);
                try out_stream.print("- ", .{});
                try dump(v, indent + 2);
            }
        },
        .Object => |obj| {
            var it = obj.iterator();
            while (it.next()) |kv| {
                try out_stream.print("\n", .{});
                try out_stream.writeByteNTimes(' ', indent);
                try out_stream.print("\"{}\": ", .{kv.key});
                try dump(kv.value, indent + 2);
            }
        },
    }
}

pub fn main() anyerror!void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = &arena.allocator;

    var args = try std.process.argsAlloc(allocator);
    const arg = if (args.len == 2) args[1] else return error.MissingCliArgument;

    var file = try std.fs.cwd().openFile(arg, std.fs.File.OpenFlags{ .read = true });
    defer file.close();

    const content = try file.readAllAlloc(allocator, (try file.stat()).size, std.math.maxInt(usize));

    var value = bencode.ValueTree.parse(content, allocator) catch |err| {
        try std.io.getStdErr().writer().print("Error parsing: {}\n", .{err});
        return;
    };
    defer value.deinit();

    const url = bencode.mapLookup(&value.root.Object, "announce") orelse {
        try std.io.getStdErr().writer().print("Error getting field `announce`: not found\n", .{});
        return;
    };

    const field_info = bencode.mapLookup(&value.root.Object, "info") orelse {
        try std.io.getStdErr().writer().print("Error getting field `info`: not found\n", .{});
        return;
    };

    const length = bencode.mapLookup(&field_info.Object, "length") orelse {
        try std.io.getStdErr().writer().print("Error getting field `info.length`: not found\n", .{});
        return;
    };

    var field_info_bencoded = std.ArrayList(u8).init(allocator);
    try field_info.stringifyValue(field_info_bencoded.writer());
    std.debug.warn("`{}`\n", .{field_info_bencoded.items});

    var hash: [20]u8 = undefined;
    std.crypto.Sha1.hash(field_info_bencoded.items, hash[0..]);

    var query = std.ArrayList(u8).init(allocator);
    try query.appendSlice("?info_hash=");

    for (hash) |byte| {
        try std.fmt.format(query.writer(), "%{X:0<2}", .{byte});
    }

    var peer_id: [20]u8 = undefined;
    try std.crypto.randomBytes(peer_id[0..]);

    try query.appendSlice("&peer_id=");
    for (peer_id) |byte| {
        try std.fmt.format(query.writer(), "%{X:0<2}", .{byte});
    }

    const port: u16 = 6881;
    try std.fmt.format(query.writer(), "&port={}", .{port});

    const uploaded = 0;
    try std.fmt.format(query.writer(), "&uploaded={}", .{uploaded});

    const downloaded = 0;
    try std.fmt.format(query.writer(), "&downloaded={}", .{downloaded});

    const left = length.Integer - downloaded; // FIXME
    try std.fmt.format(query.writer(), "&left={}", .{left});

    try std.fmt.format(query.writer(), "&event={}", .{"started"}); // FIXME

    std.debug.warn("query=`{}`", .{query.items});
    var socket = try std.net.tcpConnectToHost(allocator, "bttracker.debian.org", 6969);
    defer socket.close();
    try std.fmt.format(socket.writer(), "GET /announce{}\n\n", .{query});
    var response: [900]u8 = undefined;
    const res = try socket.read(response[0..]);

    std.debug.warn("res={} response=`{}`\n", .{ res, response });
}
