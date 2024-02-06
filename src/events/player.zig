const Connection = @import("../network/netlib.zig").Connection;
const UUID = @import("../data/uuid.zig").UUID;
const Player = @import("../player/player.zig").Player;

pub const PlayerPreLoginEvent = struct {
    connection: *Connection,
    name: []const u8,
    uuid: UUID,
};

pub const PlayerLoginEvent = struct {
    player: Player,
    canceled: bool,
};
