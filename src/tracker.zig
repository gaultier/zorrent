const c = @cImport(@cInclude("curl/curl.h"));
const std = @import("std");
const bencode = @import("zig-bencode");

const Peer = @import("peer.zig").Peer;

pub const Event = enum {
    Started,
    Completed,
    Stopped,

    pub fn to_string(self: Event) []const u8 {
        return switch (self) {
            .Started => "started",
            .Completed => "completed",
            .Stopped => "stopped",
        };
    }
};

pub const Query = struct {
    info_hash: [20]u8,
    peer_id: [20]u8,
    port: u16,
    uploaded: usize,
    downloaded: usize,
    left: usize,
    event: Event,
};

pub fn getPeers(announce_urls: []const []const u8, query: Query, allocator: *std.mem.Allocator) ![]Peer {
    var peers = std.ArrayList(Peer).init(allocator);
    defer peers.deinit();

    const local_address = std.net.Address.initIp4([4]u8{ 0, 0, 0, 0 }, 6881);
    try peers.append(try Peer.init(local_address, allocator)); // FIXME

    // TODO: contact in parallel each tracker, hard with libcurl?

    for (announce_urls) |url| {
        addPeersFromTracker(url, &peers, query, allocator) catch |err| {
            std.log.warn("Tracker {}: {}", .{ url, err });
            continue;
        };
    }

    return peers.toOwnedSlice();
}

fn addPeersFromTracker(url: []const u8, peers: *std.ArrayList(Peer), query: Query, allocator: *std.mem.Allocator) !void {
    std.log.notice("Tracker {}: trying to contact...", .{url});
    var tracker_response = try queryAnnounceUrl(url, query, allocator);
    std.log.notice("Tracker {} replied successfuly", .{url});

    var dict_field = tracker_response.root;
    if (!bencode.isObject(dict_field)) return error.InvalidField;
    var dict = dict_field.Object;

    if (bencode.mapLookup(&dict, "failure reason")) |failure_field| {
        if (!bencode.isString(failure_field.*)) return error.InvalidField;

        std.log.warn("Tracker {}: {}", .{ url, failure_field.String });
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
                    std.log.notice("Tracker {}: new peer {} total_peers_count={}", .{ url, address, peers.items.len });
                }

                i += 6;
            }
        },
        .Array => |*peers_list| {
            for (peers_list.items) |*peer_field| {
                // TODO: parse peer_id?
                const ip = if (bencode.mapLookup(&peer_field.Object, "ip")) |ip_field| brk: {
                    if (!bencode.isString(ip_field.*)) return error.InvalidField;
                    break :brk ip_field.String;
                } else continue;

                const port = if (bencode.mapLookup(&peer_field.Object, "port")) |port_field| brk: {
                    if (!bencode.isInteger(port_field.*)) return error.InvalidField;
                    break :brk port_field.Integer;
                } else continue;

                const address = try std.net.Address.parseIp(ip, @intCast(u16, port));

                const peer = try Peer.init(address, allocator);
                if (try addUniquePeer(peers, peer)) {
                    std.log.notice("Tracker {}: new peer {}", .{ url, address });
                }
            }
        },
        else => return error.InvalidPeerFormat,
    }
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

fn queryAnnounceUrl(url: []const u8, query: Query, allocator: *std.mem.Allocator) !bencode.ValueTree {
    var queryUrl = try buildAnnounceUrl(url, query, allocator);
    defer allocator.free(queryUrl);

    var curl_res: c.CURLcode = undefined;
    curl_res = c.curl_global_init(c.CURL_GLOBAL_ALL);
    if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
        const err_msg: []const u8 = std.mem.spanZ(c.curl_easy_strerror(curl_res));
        std.log.emerg("libcurl initialization failed: {}", .{err_msg});
        return error.CurlInitFailed;
    }
    defer c.curl_global_cleanup();

    var curl: ?*c.CURL = null;
    var headers: [*c]c.curl_slist = null;

    curl = c.curl_easy_init() orelse {
        const err_msg: []const u8 = std.mem.spanZ(c.curl_easy_strerror(curl_res));
        std.log.emerg("libcurl initialization failed: {}", .{err_msg});
        return error.CurlInitFailed;
    };
    defer c.curl_easy_cleanup(curl);

    // url
    curl_res = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_URL, @ptrCast([*:0]const u8, queryUrl));
    if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
        const err_msg: []const u8 = std.mem.spanZ(c.curl_easy_strerror(curl_res));
        std.log.emerg("libcurl initialization failed: {}", .{err_msg});
        return error.CurlSetOptFailed;
    }

    curl_res = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_WRITEFUNCTION, writeCallback);
    if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
        const err_msg: []const u8 = std.mem.spanZ(c.curl_easy_strerror(curl_res));
        std.log.emerg("libcurl initialization failed: {}", .{err_msg});
        return error.CurlSetOptFailed;
    }

    const timeout_seconds: usize = 10;
    curl_res = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_TIMEOUT, timeout_seconds);
    if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
        const err_msg: []const u8 = std.mem.spanZ(c.curl_easy_strerror(curl_res));
        std.log.emerg("libcurl initialization failed: {}", .{err_msg});
        return error.CurlSetOptFailed;
    }

    const follow_redirect_enabled: usize = 1;
    curl_res = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_FOLLOWLOCATION, follow_redirect_enabled);
    if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
        const err_msg: []const u8 = std.mem.spanZ(c.curl_easy_strerror(curl_res));
        std.log.emerg("libcurl initialization failed: {}", .{err_msg});
        return error.CurlSetOptFailed;
    }

    var res_body = std.ArrayList(u8).init(allocator);
    curl_res = c.curl_easy_setopt(curl, c.CURLoption.CURLOPT_WRITEDATA, &res_body);
    if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
        const err_msg: []const u8 = std.mem.spanZ(c.curl_easy_strerror(curl_res));
        std.log.emerg("libcurl initialization failed: {}", .{err_msg});
        return error.CurlSetOptFailed;
    }

    // perform the call
    curl_res = c.curl_easy_perform(curl);
    if (@enumToInt(curl_res) != @bitCast(c_uint, c.CURLE_OK)) {
        const err_msg: []const u8 = std.mem.spanZ(c.curl_easy_strerror(curl_res));
        std.log.emerg("libcurl curl_easy_perform failed: {}", .{err_msg});
        return error.CurlPerform;
    }

    var tracker_response = try bencode.ValueTree.parse(res_body.items[0..], allocator);
    return tracker_response;
}

fn buildAnnounceUrl(url: []const u8, query: Query, allocator: *std.mem.Allocator) ![]const u8 {
    var query_string = std.ArrayList(u8).init(allocator);
    defer query_string.deinit();

    try query_string.appendSlice(url);
    try query_string.appendSlice("?info_hash=");

    for (query.info_hash) |byte| {
        try std.fmt.format(query_string.writer(), "%{X:0<2}", .{byte});
    }

    // const peer_id: [20]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19 };

    try query_string.appendSlice("&peer_id=");
    for (query.peer_id) |byte| {
        try std.fmt.format(query_string.writer(), "%{X:0<2}", .{byte});
    }

    // const port: u16 = 6881; // TODO: listen on that port
    try std.fmt.format(query_string.writer(), "&port={}", .{query.port});

    try std.fmt.format(query_string.writer(), "&uploaded={}", .{query.uploaded});

    try std.fmt.format(query_string.writer(), "&downloaded={}", .{query.downloaded});

    try std.fmt.format(query_string.writer(), "&left={}", .{query.left});

    try std.fmt.format(query_string.writer(), "&event={}", .{query.event.to_string()});

    // libcurl expects a null terminated string
    try query_string.append(0);

    return query_string.toOwnedSlice();
}

fn writeCallback(p_contents: *c_void, size: usize, nmemb: usize, p_user_data: *std.ArrayList(u8)) usize {
    const contents = @ptrCast([*c]const u8, p_contents);
    p_user_data.*.appendSlice(contents[0..nmemb]) catch {
        std.process.exit(1);
    };
    return size * nmemb;
}
