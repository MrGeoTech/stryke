const std = @import("std");

pub const Config = struct {
    /// The address to bind the server to
    bind_address: []const u8 = "0.0.0.0",
    /// The port to bind the server to
    port: u16 = 25565,
    /// Whether the server should respond to server pings
    /// If disabled, the server will appear offline in the
    /// server list but will accept new connections
    enable_status: bool = true,
    /// The default max players to display to the players
    /// on a server ping.
    /// 0 will use forced_max_players
    /// -1 will resolve to players_online + 1
    display_max_players: isize = 20,
    /// The "true" max players that will not allow more
    /// players to join if over this amount.
    /// -1 will disable
    forced_max_players: isize = 20,
    /// The default description to send on a server ping
    default_description: []const u8 = "A Stryke Server!",
    /// Whether the server should send a preview of
    /// the online players when pinged
    should_preview_players: bool = false,
    /// If the user should be validated with mojang
    online_mode: bool = false,
    /// Whether the server should force use of secure chat
    /// Disabled if online mode is false
    enforce_secure_chat: bool = false,
    /// Wheter the server should force clients to provide
    /// a Mojang-signed public key
    /// Disabled if online mode is false
    enforce_secure_profile: bool = false,
    /// Whether the server should preview player chats
    previews_chats: bool = false,
    /// The default gamemode that should be given to
    /// a player who joins for the first time
    /// TODO: Change to enum
    default_gamemode: []const u8 = "survival",
    /// The seed used for world generation
    world_seed: u64 = 0,
    /// The name of the default world
    world_name: []const u8 = "world",
    /// Whether command blocks should be interactable
    command_blocks_enabled: bool = false,
    /// Whether players should be able to attack other players
    pvp_enabled: bool = true,
    /// Whether structures should be generated when generating worlds
    structures_enabled: bool = true,
    /// Adjusts the amount of mobs allowed and
    /// if the players is allowed to respawn
    /// TODO: Change to enum
    difficulty: []const u8 = "normal",
    /// If a packet is larger than this in bytes, it will be compressed
    /// 0 compresses all packets
    /// -1 disables compression
    network_compression_threshold: i32 = 0,
    /// The URI of the servers resource pack
    resource_pack_uri: ?[]const u8 = null,
    /// UUID of the resource pack for the clients to easily
    /// identify the pack with clients
    /// Required by stryke if you are using a resource pack
    resource_pack_uuid: ?[]const u8 = null,
    /// Whether to force the use of the resource pack
    /// Doesn't matter if resource_pack_url is not set
    require_resource_pack: bool = false,
};

const ConfigError = error{
    InvalidFormat,
};

/// Loads a server config from the specified file
pub fn loadFromFile(allocator: std.mem.Allocator, path: []const u8) !Config {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer {
        arena.reset(.free_all);
        arena.deinit();
    }

    const contents = try std.fs.cwd().readFileAlloc(arena.allocator(), path, 1024 * 1024);

    return try std.json.parseFromSliceLeaky(Config, arena.allocator(), contents, .{ .duplicate_field_behavior = .use_first, .ignore_unknown_fields = true });
}

/// Saves the server config to the specified file
pub fn saveToFile(allocator: std.mem.Allocator, config: Config, path: []const u8) !void {
    const as_string = std.json.stringifyAlloc(allocator, config, .{ .whitespace = .indent_tab });
    defer allocator.free(as_string);

    try std.fs.cwd().writeFile(path, as_string);
}

/// Loads a stryke server config from a vanila
/// minecraft server.properties file
/// TODO: Implement
pub fn loadFromVanila(allocator: std.mem.Allocator, path: []const u8) !Config {
    const contents = try std.fs.cwd().readFileAlloc(allocator, path, 1024 * 1024);
    const lines = std.mem.splitScalar(u8, contents, '\n');

    while (lines.next()) |line| {
        if (line[0] == '#') continue;
    }
}
