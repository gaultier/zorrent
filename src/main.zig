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

pub const PeerState = enum {
    Unknown,
    Connected,
    Handshaked,
    Down,
};

fn isHandshake(buffer: []const u8) bool {
    return (buffer.len >= 19 and std.mem.eql(u8, "\x13BitTorrent protocol", buffer[0..20]));
}

pub const Peer = struct {
    address: std.net.Address,
    state: PeerState,
    socket: ?std.fs.File,

    pub fn connect(self: *Peer) !void {
        self.socket = try std.net.tcpConnectToAddress(self.address);
        self.state = PeerState.Connected;
    }

    pub fn deinit(self: *Peer) void {
        if (self.socket) |socket| {
            socket.close();
        }
        self.state = PeerState.Down;
    }

    pub fn sendHandshake(self: *Peer, hash_info: [20]u8) !void {
        std.debug.assert(self.state == PeerState.Connected);

        const handshake_payload = "\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00";
        try self.socket.?.writeAll(handshake_payload);
        try self.socket.?.writeAll(hash_info[0..]);
    }

    pub fn handle(self: *Peer, hash_info: [20]u8) !void {
        std.debug.assert(self.state == PeerState.Unknown);

        std.debug.warn("{}\tConnecting\n", .{self.address});
        self.connect() catch |err| {
            switch (err) {
                error.ConnectionTimedOut, error.ConnectionRefused => {
                    std.debug.warn("{}\tFailed ({})\n", .{ self.address, err });
                    self.deinit();
                    return;
                },
                else => return err,
            }
        };

        std.debug.warn("{}\tConnected\n", .{self.address});
        try self.sendHandshake(hash_info);
        std.debug.warn("{}\tHandshaking\n", .{self.address});

        while (true) {
            var response: [1 << 14]u8 = undefined;
            var res = try self.socket.?.readAll(response[0..]);
            if (res == 0) return;

            if (isHandshake(response[0..res])) {
                self.state = PeerState.Handshaked;
                std.debug.warn("{}\tHandshaked\n", .{self.address});
            } else {
                std.debug.warn("{}\tUnknown message: ", .{self.address});
                hexDump(response[0..res]);
            }
        }
    }
};

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

    fn queryAnnounceUrl(self: TorrentFile, allocator: *std.mem.Allocator) !bencode.ValueTree {
        var queryUrl = try self.buildAnnounceUrl(allocator);
        defer allocator.destroy(&queryUrl);

        std.debug.warn("queryUrl=`{}`\n", .{queryUrl}); // TODO: rm

        var curl_res: c.CURLcode = undefined;
        curl_res = c.curl_global_init(c.CURL_GLOBAL_ALL);
        if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
            _ = c.printf("curl_global_init() failed: %s\n", c.curl_easy_strerror(curl_res));
            return error.CurlInitFailed;
        }
        defer c.curl_global_cleanup();

        var curl: ?*c.CURL = null;
        var headers: [*c]c.curl_slist = null;

        curl = c.curl_easy_init() orelse {
            _ = c.printf("curl_easy_init() failed: %s\n", c.curl_easy_strerror(curl_res));
            return error.CurlInitFailed;
        };
        defer c.curl_easy_cleanup(curl);

        // url
        curl_res = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_URL, @ptrCast([*:0]const u8, queryUrl));
        if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
            _ = c.printf("curl_easy_setopt() failed: %s\n", c.curl_easy_strerror(curl_res));
            return error.CurlSetOptFailed;
        }

        curl_res = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_WRITEFUNCTION, writeCallback);
        if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
            _ = c.printf("curl_easy_setopt() failed: %s\n", c.curl_easy_strerror(curl_res));
            return error.CurlSetOptFailed;
        }

        var res_body = std.ArrayList(u8).init(allocator);
        curl_res = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_WRITEDATA, &res_body);
        if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
            _ = c.printf("curl_easy_setopt() failed: %s\n", c.curl_easy_strerror(curl_res));
            return error.CurlSetOptFailed;
        }

        // perform the call
        curl_res = c.curl_easy_perform(curl);
        if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
            _ = c.printf("curl_easy_perform() failed: %s\n", c.curl_easy_strerror(curl_res));
            return error.CurlPerform;
        }

        var tracker_response = try bencode.ValueTree.parse(res_body.items[0..], allocator);
        return tracker_response;
    }

    pub fn getPeers(self: TorrentFile, allocator: *std.mem.Allocator) ![]Peer {
        const tracker_response = try self.queryAnnounceUrl(allocator);
        var dict = tracker_response.root.Object;
        // TODO: support non compact format i.e. a list of strings
        const peers_compact = bencode.mapLookup(&dict, "peers").?.String;

        std.debug.assert(peers_compact.len % 6 == 0);

        var i: usize = 0;
        var peers = std.ArrayList(Peer).init(allocator);
        defer peers.deinit();

        while (i < peers_compact.len) {
            const ip = [4]u8{
                peers_compact[i],
                peers_compact[i + 1],
                peers_compact[i + 2],
                peers_compact[i + 3],
            };

            const peer_port_s = [2]u8{ peers_compact[i + 4], peers_compact[i + 5] };
            const peer_port = std.mem.readIntBig(u16, &peer_port_s);

            const address = std.net.Address.initIp4(ip, peer_port);

            try peers.append(Peer{ .address = address, .state = PeerState.Unknown, .socket = null });

            i += 6;
        }

        std.debug.assert(peers.items.len > 0);

        return peers.toOwnedSlice();
    }
};

fn main() anyerror!void {
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
