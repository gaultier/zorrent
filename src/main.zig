const std = @import("std");
const c = @cImport(@cInclude("curl/curl.h"));
const bencode = @import("zig-bencode");

fn writeCallback(p_contents: *c_void, size: usize, nmemb: usize, p_user_data: *std.ArrayList(u8)) usize {
    const contents = @ptrCast([*c]const u8, p_contents);
    p_user_data.*.appendSlice(contents[0..nmemb]) catch {
        std.process.exit(1);
    };
    return size * nmemb;
}

pub fn hexDump(bytes: []const u8) void {
    for (bytes) |b| {
        std.debug.warn("{X:0<2} ", .{b});
    }
    std.debug.warn("\n", .{});
}

pub const TorrentFile = struct {
    announce: []const u8,
    lengthBytesCount: usize,
    hash_info: [20]u8,
    downloadedBytesCount: usize,
    uploadedBytesCount: usize,
    leftBytesCount: usize,

    pub fn parse(path: []const u8, allocator: *std.mem.Allocator) !TorrentFile {
        var file = try std.fs.cwd().openFile(path, std.fs.File.OpenFlags{ .read = true });
        defer file.close();

        const content = try file.readAllAlloc(allocator, (try file.stat()).size, std.math.maxInt(usize));

        var value = try bencode.ValueTree.parse(content, allocator);
        defer value.deinit();

        const announce = (bencode.mapLookup(&value.root.Object, "announce") orelse return error.FieldNotFound).String;

        const field_info = bencode.mapLookup(&value.root.Object, "info") orelse return error.FieldNotFound;

        const length = (bencode.mapLookup(&field_info.Object, "length") orelse return error.FieldNotFound).Integer;

        var field_info_bencoded = std.ArrayList(u8).init(allocator);
        defer field_info_bencoded.deinit();
        try field_info.stringifyValue(field_info_bencoded.writer());

        var hash: [20]u8 = undefined;
        std.crypto.Sha1.hash(field_info_bencoded.items, hash[0..]);

        return TorrentFile{
            .announce = announce,
            .lengthBytesCount = @intCast(usize, length),
            .hash_info = hash,
            .uploadedBytesCount = 0,
            .downloadedBytesCount = 0,
            .leftBytesCount = @intCast(usize, length),
        };
    }

    fn buildAnnounceUrl(self: TorrentFile, allocator: *std.mem.Allocator) ![]const u8 {
        var query = std.ArrayList(u8).init(allocator);
        defer query.deinit();

        try query.appendSlice("OpenBSD.somedomain.net:6969/announce?info_hash=");

        for (self.hash_info) |byte| {
            try std.fmt.format(query.writer(), "%{X:0<2}", .{byte});
        }

        var peer_id: [20]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19 };
        // try std.crypto.randomBytes(peer_id[0..]);

        try query.appendSlice("&peer_id=");
        for (peer_id) |byte| {
            try std.fmt.format(query.writer(), "%{X:0<2}", .{byte});
        }

        const port: u16 = 6881;
        try std.fmt.format(query.writer(), "&port={}", .{port});

        try std.fmt.format(query.writer(), "&uploaded={}", .{self.uploadedBytesCount});

        const downloaded = 0;
        try std.fmt.format(query.writer(), "&downloaded={}", .{self.downloadedBytesCount});

        try std.fmt.format(query.writer(), "&left={}", .{self.leftBytesCount});

        try std.fmt.format(query.writer(), "&event={}", .{"started"}); // FIXME

        try query.append(0);

        return query.toOwnedSlice();
    }

    pub fn queryAnnounceUrl(self: TorrentFile, allocator: *std.mem.Allocator) !bencode.ValueTree {
        var queryUrl = try self.buildAnnounceUrl(allocator);
        defer allocator.destroy(&queryUrl);

        std.debug.warn("queryUrl=`{}`\n", .{queryUrl});

        _ = c.curl_global_init(c.CURL_GLOBAL_ALL);
        defer c.curl_global_cleanup();

        var curl: ?*c.CURL = null;
        var curl_res: c.CURLcode = undefined;
        var headers: [*c]c.curl_slist = null;

        curl = c.curl_easy_init() orelse {
            _ = c.printf("curl_easy_init() failed: %s\n", c.curl_easy_strerror(curl_res));
            return error.CurlInitFailed;
        };
        defer c.curl_easy_cleanup(curl);

        // url
        _ = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_URL, @ptrCast([*:0]const u8, queryUrl));

        _ = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_WRITEFUNCTION, writeCallback);

        var res_body = std.ArrayList(u8).init(allocator);
        _ = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_WRITEDATA, &res_body);

        // perform the call
        curl_res = c.curl_easy_perform(curl);
        if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
            _ = c.printf("curl_easy_perform() failed: %s\n", c.curl_easy_strerror(curl_res));
            return error.CurlPerform;
        }

        std.debug.warn("Res body: {}", .{res_body.items});

        var value_decoded = try bencode.ValueTree.parse(res_body.items[0..], allocator);
        try bencode.dump(&value_decoded.root, 0);
        return value_decoded;
    }
};

fn main() anyerror!void {
    var dict = value_decoded.root.Object;
    // TODO: support non compact format i.e. a list of strings
    const peers = bencode.mapLookup(&dict, "peers").?.String;

    std.debug.assert(peers.len % 6 == 0);

    var i: usize = 0;
    var peer_addresses = std.ArrayList(std.net.Address).init(allocator);

    while (i < peers.len) {
        const ip = [4]u8{
            peers[i],
            peers[i + 1],
            peers[i + 2],
            peers[i + 3],
        };

        const peer_port_s = [2]u8{ peers[i + 4], peers[i + 5] };
        const peer_port = std.mem.readIntBig(u16, &peer_port_s);

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

    var response: [1 << 14]u8 = undefined;
    var res = try socket.read(response[0..]);

    std.debug.warn("res={} response=", .{res});
    hexDump(response[0..res]);

    if (res >= 19 and std.mem.eql(u8, "\x13BitTorrent protocol", response[0..20])) {
        std.debug.warn("Got handshake ok\n", .{});
    } else {
        std.debug.warn("Got no handshake\n", .{});
    }

    const remote_peer_id = "\x00" ** 20;
    try socket.writeAll(remote_peer_id[0..]);

    try socket.writeAll(&[_]u8{ 0, 0, 0, 1, 1 }); // unchoke
    try socket.writeAll(&[_]u8{ 0, 0, 0, 1, 2 }); // interested
    res = try socket.read(response[0..]);

    try socket.writeAll(&[_]u8{
        0,    0, 0, 0xd,
        0x6,  0, 0, 0,
        0,    0, 0, 0,
        0,    0, 0, 0,
        0x40,
    }); // request first piece

    // Unchoke
    res = try socket.read(response[0..]);
    std.debug.warn("res={} response=", .{res});
    hexDump(response[0..res]);

    // Piece 0
    res = try socket.read(response[0..]);
    std.debug.warn("res={} response=", .{res});
    hexDump(response[0..res]);

    res = try socket.read(response[0..]);
    std.debug.warn("res={} response=", .{res});
    hexDump(response[0..res]);

    res = try socket.read(response[0..]);
    std.debug.warn("res={} response=", .{res});
    hexDump(response[0..res]);
}
