const network = @import("../network/network.zig");
const netlib = @import("../network/netlib.zig");
const packets = @import("../network/packets.zig");

pub const PacketRecieveEvent = struct {
    /// The connection sending the packet
    connection: *netlib.Connection,
    /// The packet recieved from the connection
    packet: packets.Packet,
    /// Whether the server should process the packet
    /// normally or should just ignore
    canceled: bool = false,
};

pub const PacketSendEvent = struct {
    /// The connection to send the packet to
    connection: *netlib.Connection,
    /// The packet to potentially send to the connection
    packet: packets.Packet,
    /// Whether the packet should actually be sent
    canceled: bool = false,
};

pub const ConnectionAcceptEvent = struct {
    /// The connection to accept
    connection: *netlib.Connection,
    /// Whether the connection should be immediately
    /// closed or if it should be processed
    canceled: bool = false,
};

pub const PlayerPingEvent = struct {
    /// The connection sending the ping packet
    connection: *netlib.Connection,
    /// The timestamp sent to the server
    payload: i64,
    /// The amount of time (in ticks) to wait
    /// before sending the response
    delay: usize = 0,
};

pub const ServerListPingEvent = struct {
    /// The connection sending the request
    connection: *netlib.Connection,
    /// The response that should be sent the player
    /// Automatically populated with the default values
    /// specified by the global config or by the
    /// connection config
    response: packets.StatusResponse,
    canceled: bool = false,
};

/// WARNING: This should just be used for monitoring
/// Actually canceling the tick can have unintended consiquences
pub const ServerTickEvent = struct {
    /// The server that is ticking
    server: network.Server,
    /// Whether the server should skip processing this tick
    canceled: bool = false,
};
