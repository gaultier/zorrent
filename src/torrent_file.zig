const std = @import("std");
const c = @cImport(@cInclude("curl/curl.h"));
const bencode = @import("zig-bencode");

const peer_mod = @import("peer.zig");
const Peer = peer_mod.Peer;

pub const TorrentFile = struct {
    announce_urls: [][]const u8,
    total_len: usize,
    hash_info: [20]u8,
    downloadedBytesCount: usize,
    uploadedBytesCount: usize,
    leftBytesCount: usize,
    pieces: []const u8,
    piece_len: usize,
    path: []const u8,

    pub fn parse(path: []const u8, allocator: *std.mem.Allocator) !TorrentFile {
        // TODO: decide if we copy the memory from the ValueTree, or if we keep a reference to it
        var file = try std.fs.cwd().openFile(path, std.fs.File.OpenFlags{ .read = true });
        defer file.close();

        const content = try file.readAllAlloc(allocator, (try file.stat()).size, std.math.maxInt(usize));

        var value = try bencode.ValueTree.parse(content, allocator);
        defer value.deinit();

        var owned_announce_urls = std.ArrayList([]const u8).init(allocator);
        if (bencode.mapLookup(&value.root.Object, "announce")) |field| {
            const real_url = field.String;
            if (real_url.len >= 7 and std.mem.eql(u8, real_url[0..7], "http://")) {
                try owned_announce_urls.append(try allocator.dupe(u8, field.String));
            }
        }

        if (bencode.mapLookup(&value.root.Object, "announce-list")) |field| {
            const urls = field.Array.items;
            for (urls) |url| {
                const real_url = url.Array.items;

                if (real_url.len == 1) {
                    const real_real_url = real_url[0].String;
                    if (real_real_url.len >= 7 and std.mem.eql(u8, real_real_url[0..7], "http://")) {
                        try owned_announce_urls.append(try allocator.dupe(u8, real_real_url));
                    }
                }
            }
        }

        const field_info = bencode.mapLookup(&value.root.Object, "info") orelse return error.FieldNotFound;
        const pieces = (bencode.mapLookup(&field_info.Object, "pieces") orelse return error.FieldNotFound).String;
        var owned_pieces = std.ArrayList(u8).init(allocator);
        try owned_pieces.appendSlice(pieces);

        const piece_len = (bencode.mapLookup(&field_info.Object, "piece length") orelse return error.FieldNotFound).Integer;

        var file_path: ?[]const u8 = null;
        var total_len: ?isize = null;
        if (bencode.mapLookup(&field_info.Object, "name")) |field| {
            file_path = field.String;
        }
        if (bencode.mapLookup(&field_info.Object, "length")) |field| {
            total_len = field.Integer;
        }

        if (bencode.mapLookup(&field_info.Object, "files")) |field| {
            // FIXME: multi file download
            if (field.Array.items.len > 0) {
                var file_field = field.Array.items[0].Object;
                file_path = (bencode.mapLookup(&file_field, "path") orelse return error.FieldNotFound).Array.items[0].String;
                total_len = (bencode.mapLookup(&file_field, "length") orelse return error.FieldNotFound).Integer;
            }
        }

        var owned_file_path = std.ArrayList(u8).init(allocator);
        try owned_file_path.appendSlice(file_path.?);

        var field_info_bencoded = std.ArrayList(u8).init(allocator);
        defer field_info_bencoded.deinit();
        try field_info.stringifyValue(field_info_bencoded.writer());

        var hash: [20]u8 = undefined;
        std.crypto.Sha1.hash(field_info_bencoded.items, hash[0..]);

        return TorrentFile{
            .announce_urls = owned_announce_urls.toOwnedSlice(),
            .total_len = @intCast(usize, total_len.?),
            .hash_info = hash,
            .uploadedBytesCount = 0,
            .downloadedBytesCount = 0,
            .leftBytesCount = @intCast(usize, total_len.?),
            .piece_len = @intCast(usize, piece_len),
            .pieces = owned_pieces.toOwnedSlice(),
            .path = owned_file_path.toOwnedSlice(),
        };
    }

    fn buildAnnounceUrl(self: TorrentFile, url: []const u8, allocator: *std.mem.Allocator) ![]const u8 {
        var query = std.ArrayList(u8).init(allocator);
        defer query.deinit();

        try query.appendSlice(url);
        try query.appendSlice("?info_hash=");

        for (self.hash_info) |byte| {
            try std.fmt.format(query.writer(), "%{X:0<2}", .{byte});
        }

        const peer_id: [20]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19 };

        try query.appendSlice("&peer_id=");
        for (peer_id) |byte| {
            try std.fmt.format(query.writer(), "%{X:0<2}", .{byte});
        }

        const port: u16 = 6881; // TODO: listen on that port
        try std.fmt.format(query.writer(), "&port={}", .{port});

        try std.fmt.format(query.writer(), "&uploaded={}", .{self.uploadedBytesCount});

        const downloaded = 0;
        try std.fmt.format(query.writer(), "&downloaded={}", .{self.downloadedBytesCount});

        try std.fmt.format(query.writer(), "&left={}", .{self.leftBytesCount});

        try std.fmt.format(query.writer(), "&event={}", .{"started"}); // FIXME

        try query.append(0);

        return query.toOwnedSlice();
    }

    fn queryAnnounceUrl(self: TorrentFile, url: []const u8, allocator: *std.mem.Allocator) !bencode.ValueTree {
        var queryUrl = try self.buildAnnounceUrl(url, allocator);
        defer allocator.destroy(&queryUrl);

        var curl_res: c.CURLcode = undefined;
        curl_res = c.curl_global_init(c.CURL_GLOBAL_ALL);
        if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
            const err_msg: []const u8 = std.mem.spanZ(c.curl_easy_strerror(curl_res));
            std.log.emerg(.zorrent_lib, "libcurl initialization failed: {}", .{err_msg});
            return error.CurlInitFailed;
        }
        defer c.curl_global_cleanup();

        var curl: ?*c.CURL = null;
        var headers: [*c]c.curl_slist = null;

        curl = c.curl_easy_init() orelse {
            const err_msg: []const u8 = std.mem.spanZ(c.curl_easy_strerror(curl_res));
            std.log.emerg(.zorrent_lib, "libcurl initialization failed: {}", .{err_msg});
            return error.CurlInitFailed;
        };
        defer c.curl_easy_cleanup(curl);

        // url
        curl_res = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_URL, @ptrCast([*:0]const u8, queryUrl));
        if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
            const err_msg: []const u8 = std.mem.spanZ(c.curl_easy_strerror(curl_res));
            std.log.emerg(.zorrent_lib, "libcurl initialization failed: {}", .{err_msg});
            return error.CurlSetOptFailed;
        }

        curl_res = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_WRITEFUNCTION, writeCallback);
        if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
            const err_msg: []const u8 = std.mem.spanZ(c.curl_easy_strerror(curl_res));
            std.log.emerg(.zorrent_lib, "libcurl initialization failed: {}", .{err_msg});
            return error.CurlSetOptFailed;
        }

        const timeout_seconds: usize = 10;
        curl_res = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_TIMEOUT, timeout_seconds);
        if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
            const err_msg: []const u8 = std.mem.spanZ(c.curl_easy_strerror(curl_res));
            std.log.emerg(.zorrent_lib, "libcurl initialization failed: {}", .{err_msg});
            return error.CurlSetOptFailed;
        }

        const follow_redirect_enabled: usize = 1;
        curl_res = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_FOLLOWLOCATION, follow_redirect_enabled);
        if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
            const err_msg: []const u8 = std.mem.spanZ(c.curl_easy_strerror(curl_res));
            std.log.emerg(.zorrent_lib, "libcurl initialization failed: {}", .{err_msg});
            return error.CurlSetOptFailed;
        }

        var res_body = std.ArrayList(u8).init(allocator);
        curl_res = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_WRITEDATA, &res_body);
        if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
            const err_msg: []const u8 = std.mem.spanZ(c.curl_easy_strerror(curl_res));
            std.log.emerg(.zorrent_lib, "libcurl initialization failed: {}", .{err_msg});
            return error.CurlSetOptFailed;
        }

        // perform the call
        curl_res = c.curl_easy_perform(curl);
        if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
            const err_msg: []const u8 = std.mem.spanZ(c.curl_easy_strerror(curl_res));
            std.log.emerg(.zorrent_lib, "libcurl initialization failed: {}", .{err_msg});
            return error.CurlPerform;
        }

        var tracker_response = try bencode.ValueTree.parse(res_body.items[0..], allocator);
        return tracker_response;
    }

    fn addUniquePeer(peers: *std.ArrayList(Peer), peer: Peer) !bool {
        for (peers.items) |p| {
            if (p.address.eql(peer.address)) {
                return false;
            }
        }

        try peers.append(peer);
        return true;
    }

    fn addPeersFromTracker(self: TorrentFile, url: []const u8, peers: *std.ArrayList(Peer), allocator: *std.mem.Allocator) !void {
        std.log.notice(.zorrent_lib, "Tracker {}: trying to contact...", .{url});
        var tracker_response = try self.queryAnnounceUrl(url, allocator);
        std.log.notice(.zorrent_lib, "Tracker {} replied successfuly", .{url});

        var dict = tracker_response.root.Object;

        if (bencode.mapLookup(&dict, "failure reason")) |failure_field| {
            std.log.warn(.zorrent_lib, "Tracker {}: {}", .{ url, failure_field.String });
            return error.TrackerFailure;
        }

        const peers_field = if (bencode.mapLookup(&dict, "peers")) |peers_field| peers_field.* else return error.EmptyPeers;

        switch (peers_field) {
            .String => |peers_compact| {
                if (peers_compact.len == 0) return error.EmptyPeers;
                if (peers_compact.len % 6 != 0) return error.InvalidPeerFormat;

                var i: usize = 0;

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

                    const peer = try Peer.init(address, allocator);

                    if (try addUniquePeer(peers, peer)) {
                        std.log.notice(.zorrent_lib, "Tracker {}: new peer {} total_peers_count={}", .{ url, address, peers.items.len });
                    }

                    i += 6;
                }
            },
            .Array => |*peers_list| {
                for (peers_list.items) |*peer_field| {
                    // TODO: parse peer_id?
                    const ip = if (bencode.mapLookup(&peer_field.Object, "ip")) |ip_field| ip_field.String else continue;
                    const port = if (bencode.mapLookup(&peer_field.Object, "port")) |port_field| port_field.Integer else continue;
                    const address = try std.net.Address.parseIp(ip, @intCast(u16, port));

                    const peer = try Peer.init(address, allocator);
                    if (try addUniquePeer(peers, peer)) {
                        std.log.notice(.zorrent_lib, "Tracker {}: new peer {}", .{ url, address });
                    }
                }
            },
            else => return error.InvalidPeerFormat,
        }
    }

    pub fn getPeers(self: TorrentFile, allocator: *std.mem.Allocator) ![]Peer {
        var peers = std.ArrayList(Peer).init(allocator);
        defer peers.deinit();

        const local_address = std.net.Address.initIp4([4]u8{ 0, 0, 0, 0 }, 6881);
        try peers.append(try Peer.init(local_address, allocator)); // FIXME

        // TODO: contact in parallel each tracker, hard with libcurl?
        for (self.announce_urls) |url| {
            self.addPeersFromTracker(url, &peers, allocator) catch |err| {
                std.log.warn(.zorrent_lib, "Tracker {}: {}", .{ url, err });
                continue;
            };
        }

        return peers.toOwnedSlice();
    }
};

fn writeCallback(p_contents: *c_void, size: usize, nmemb: usize, p_user_data: *std.ArrayList(u8)) usize {
    const contents = @ptrCast([*c]const u8, p_contents);
    p_user_data.*.appendSlice(contents[0..nmemb]) catch {
        std.process.exit(1);
    };
    return size * nmemb;
}
