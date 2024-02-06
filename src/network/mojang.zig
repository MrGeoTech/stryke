const std = @import("std");
const https = @import("https.zig");

const SESSION_SERVER = "sessionserver.mojang.com";
const SESSION_SERVER_PORT = "443";
const SESSION_SERVER_QUERY = "username={s}&serverId={s}{s}";
const SESSION_SERVER_REQUEST = "GET /session/minecraft/hasJoined?{s} HTTP/1.1\r\nHost: sessionserver.mojang.com\r\nUser-Agent: Stryke 1.0.0\r\nConnection: close\r\n\r\n";

pub const AuthResponse = struct {
    arena: std.heap.ArenaAllocator,
    id: []u8,
    name: []u8,
    skin_texture: []u8,
    skin_signature: []u8,
};

const ResponseStruct = struct {
    const Property = struct {
        name: []const u8,
        value: []const u8,
        signature: []const u8,
    };

    id: []const u8,
    name: []const u8,
    properties: []const Property,
};

/// Checks mojang servers for client authentication
/// Memory is owned by returned arena
pub fn auth(allocator: std.mem.Allocator, username: []const u8, hash_hex: []const u8, ip: ?[]const u8) !AuthResponse {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer {
        _ = arena.reset(.free_all);
        arena.deinit();
    }

    std.debug.print("0", .{});

    const ip_request = if (ip) |i| try std.fmt.allocPrint(arena.allocator(), "&ip={s}", .{i}) else "";
    const query = try std.Uri.escapeQuery(
        arena.allocator(),
        try std.fmt.allocPrint(
            arena.allocator(),
            SESSION_SERVER_QUERY,
            .{ username, hash_hex, ip_request },
        ),
    );

    const request = try std.fmt.allocPrint(arena.allocator(), SESSION_SERVER_REQUEST, .{query});

    const body = try https.getResponse(arena.allocator(), SESSION_SERVER, request) orelse return error.NoContentResponse;

    std.debug.print("{s}", .{body});

    const response = try std.json.parseFromSliceLeaky(ResponseStruct, arena.allocator(), body, .{});

    std.debug.print("3", .{});

    var return_arena = std.heap.ArenaAllocator.init(allocator);

    var auth_response = AuthResponse{
        .arena = return_arena,
        .id = try return_arena.allocator().alloc(u8, response.id.len),
        .name = try return_arena.allocator().alloc(u8, response.name.len),
        .skin_texture = try return_arena.allocator().alloc(u8, response.properties[0].value.len),
        .skin_signature = try return_arena.allocator().alloc(u8, response.properties[0].signature.len),
    };

    @memcpy(auth_response.id[0..], response.id[0..]);
    @memcpy(auth_response.name[0..], response.name[0..]);
    @memcpy(auth_response.skin_texture[0..], response.properties[0].value[0..]);
    @memcpy(auth_response.skin_signature[0..], response.properties[0].signature[0..]);

    return auth_response;
}

test "auth" {
    std.testing.refAllDecls(https);

    var response = try auth(std.testing.allocator, "MrGeoTech", "eakjlnbvle;lkvasd", null);
    _ = response.arena.reset(.free_all);
    response.arena.deinit();
}
