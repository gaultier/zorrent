const std = @import("std");
const c = @cImport(@cInclude("curl/curl.h"));
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

fn dump(value: *bencode.Value, indent: usize) anyerror!void {
    var out_stream = std.io.getStdOut().writer();

    switch (value.*) {
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
                        0x20...0x21, 0x23...0x2E, 0x30...0x5B, 0x5D...0x7F => |ch| try out_stream.writeByte(ch),
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
                for (s) |ch| {
                    try out_stream.print("\\x{X}", .{ch});
                }
            }
            try out_stream.print("\"", .{});
        },
        .Array => |arr| {
            for (arr.items) |*v| {
                try out_stream.print("\n", .{});
                try out_stream.writeByteNTimes(' ', indent);
                try out_stream.print("- ", .{});
                try dump(v, indent + 2);
            }
        },
        .Object => |*obj| {
            var node = obj.first();
            while (node) |it| {
                const entry = bencode.mapGetEntry(it);
                try out_stream.print("\n", .{});
                try out_stream.writeByteNTimes(' ', indent);
                try out_stream.print("\"{}\": ", .{entry.key});
                try dump(&entry.value, indent + 2);

                node = it.next();
            }
        },
    }
}

fn writeCallback(p_contents: *c_void, size: usize, nmemb: usize, p_user_data: *std.ArrayList(u8)) usize {
    const contents = @ptrCast([*c]const u8, p_contents);
    p_user_data.*.appendSlice(contents[0..nmemb]) catch {
        std.process.exit(1);
    };
    return size * nmemb;
}

pub fn main() anyerror!void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
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

    var hash: [20]u8 = undefined;
    std.crypto.Sha1.hash(field_info_bencoded.items, hash[0..]);

    var query = std.ArrayList(u8).init(allocator);
    try query.appendSlice("OpenBSD.somedomain.net:6969/announce?info_hash=");

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

    std.debug.warn("{}", .{query.items});

    _ = c.curl_global_init(c.CURL_GLOBAL_ALL);

    var curl: ?*c.CURL = null;
    var curl_res: c.CURLcode = undefined;
    var headers: [*c]c.curl_slist = null;

    curl = c.curl_easy_init() orelse {
        _ = c.printf("curl_easy_init() failed: %s\n", c.curl_easy_strerror(curl_res));
        return;
    };
    defer c.curl_easy_cleanup(curl);
    defer c.curl_global_cleanup();

    // url
    _ = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_URL, @ptrCast([*:0]const u8, query.items[0..]));

    _ = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_WRITEFUNCTION, writeCallback);

    var res_body = std.ArrayList(u8).init(allocator);
    _ = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_WRITEDATA, &res_body);

    // perform the call
    curl_res = c.curl_easy_perform(curl);
    if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
        _ = c.printf("curl_easy_perform() failed: %s\n", c.curl_easy_strerror(curl_res));
        return;
    }

    std.debug.warn("Res body: {}", .{res_body.items});

    var value_decoded = try bencode.ValueTree.parse(res_body.items[0..], allocator);
    try dump(&value_decoded.root, 0);

    var dict = value_decoded.root.Object;
    // TODO: support non compact format i.e. a list of strings
    const peers = bencode.mapLookup(&dict, "peers").?.String;

    std.debug.assert(peers.len % 6 == 0);

    var i: usize = 0;
    var peer_addresses = std.ArrayList(std.net.Address).init(allocator);

    while (i < peers.len) {
        const peer_port_s = [2]u8{ peers[i + 4], peers[i + 5] };
        const peer_port = std.mem.readIntBig(u16, &peer_port_s);

        const ip = [4]u8{
            peers[i],
            peers[i + 1],
            peers[i + 2],
            peers[i + 3],
        };
        const address = std.net.Address.initIp4(ip, peer_port);

        std.debug.warn("address: {}\n", .{address});
        try peer_addresses.append(address);

        i += 6;
    }

    std.debug.assert(peer_addresses.items.len > 0);
    var socket = try std.net.tcpConnectToAddress(peer_addresses.items[1]);
    defer socket.close();

    const handshake = "\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00";
    try socket.writeAll(handshake);
    try socket.writeAll(hash[0..]);
    const remote_peer_id = "\x00" ** 20;
    try socket.writeAll(remote_peer_id[0..]);

    try socket.writeAll(&[_]u8{0x2}); // interested

    var response: [300]u8 = undefined;
    const res = try socket.read(response[0..]);

    std.debug.warn("res={} response=`{}`\n", .{ res, response });
}
