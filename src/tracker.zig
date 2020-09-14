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
