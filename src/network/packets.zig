const std = @import("std");
const openssl = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/sha.h");
});

const chat = @import("../chat/chat.zig");
const identifier = @import("../data/indentifier.zig");
const net = @import("./netlib.zig");
const crypto = @import("../crypto/crypto.zig");
const mojang = @import("mojang.zig");
const player = @import("../player/player.zig");
const events = @import("../events/events.zig");

const UUID = @import("../data/uuid.zig").UUID;

pub const ConnectionState = enum(usize) {
    HANDSHAKE = 0,
    STATUS = 1,
    LOGIN = 2,
    PLAY = 3,
};

pub const PacketType = enum {
    HANDSHAKE,
    STATUS_RESPONSE,
    PING_RESPONSE_STATUS,
    STATUS_REQUEST,
    PING_REQUEST_STATUS,
    DISCONNECT_LOGIN,
    ENCRYPTION_REQUEST,
    LOGIN_SUCCESS,
    SET_COMPRESSION,
    LOGIN_PLUGIN_REQUEST,
    LOGIN_START,
    ENCRYPTION_RESPONSE,
    LOGIN_PLUGIN_RESPONSE,
    LOGIN_ACKNOWLEDGED,
};

pub const Packet = union(PacketType) {
    HANDSHAKE: Handshake,
    // STATUS
    STATUS_RESPONSE: StatusResponse,
    PING_RESPONSE_STATUS: PingResponse_Status,
    STATUS_REQUEST: StatusRequest,
    PING_REQUEST_STATUS: PingRequest_Status,
    // LOGIN
    DISCONNECT_LOGIN: Disconnect_Login,
    ENCRYPTION_REQUEST: EncryptionRequest,
    LOGIN_SUCCESS: LoginSuccess,
    SET_COMPRESSION: SetCompression,
    LOGIN_PLUGIN_REQUEST: LoginPluginRequest,
    LOGIN_START: LoginStart,
    ENCRYPTION_RESPONSE: EncryptionResponse,
    LOGIN_PLUGIN_RESPONSE: LoginPluginResponse,
    LOGIN_ACKNOWLEDGED: LoginAcknowledged,

    pub fn print(self: Packet, comptime level: std.log.Level) void {
        std.log.debug("Print packet", .{});

        const runtime_type = @tagName(@as(PacketType, self));
        const log_func = @field(std.log, level.asText());

        inline for (std.meta.fields(@TypeOf(self))) |union_field| {
            std.log.debug("Trying packet type: {s}. Comparing to: {s}.", .{ union_field.name, runtime_type });
            if (std.mem.eql(u8, union_field.name, runtime_type)) {
                std.log.debug("Found packet type! Printing...", .{});

                const field = @field(self, union_field.name);
                inline for (std.meta.fields(union_field.type)) |data_field| {
                    const value = @field(field, data_field.name);
                    switch (@typeInfo(data_field.type)) {
                        .Array => log_func("{s} -> {s}", .{ data_field.name, value }),
                        else => log_func("{s} -> {any}", .{ data_field.name, value }),
                    }
                }

                return;
            }
        }
    }
};

pub const PacketError = error{
    InvalidPacketId,
};

// READING PACKETS

pub fn readPacket(connection: *net.Connection, allocator: std.mem.Allocator) !Packet {
    const packet_id = try connection.readVarInt(allocator);

    std.log.debug("Packet id: {x}", .{packet_id});

    var packet_out: Packet = try switch (connection.state) {
        ConnectionState.HANDSHAKE => readHandshakePacket(connection, packet_id, allocator),
        ConnectionState.STATUS => readStatusPacket(connection, packet_id, allocator),
        ConnectionState.LOGIN => readLoginPacket(connection, packet_id, allocator),
        ConnectionState.PLAY => readPlayPacket(connection, packet_id, allocator),
    };

    var event = events.network.PacketRecieveEvent{
        .connection = connection,
        .packet = packet_out,
    };
    try events.disbatch(events.Event.fromType(&event));

    return packet_out;
}

fn readHandshakePacket(connection: *net.Connection, packet_id: i32, allocator: std.mem.Allocator) !Packet {
    if (packet_id != 0x00) return PacketError.InvalidPacketId;
    return Packet{ .HANDSHAKE = Handshake{
        .protocol_version = @intCast(try connection.readVarInt(allocator)),
        .server_address = try connection.readString(255, allocator),
        .server_port = try connection.readUShort(allocator),
        .next_state = try std.meta.intToEnum(Handshake.NextState, try connection.readVarInt(allocator)),
    } };
}

fn readStatusPacket(connection: *net.Connection, packet_id: i32, allocator: std.mem.Allocator) !Packet {
    return switch (packet_id) {
        0x00 => Packet{ .STATUS_REQUEST = StatusRequest{} },
        0x01 => Packet{ .PING_REQUEST_STATUS = PingRequest_Status{
            .payload = try connection.readLong(allocator),
        } },
        else => error.InvalidPacketId,
    };
}

fn readLoginPacket(connection: *net.Connection, packet_id: i32, allocator: std.mem.Allocator) !Packet {
    return switch (packet_id) {
        0x00 => Packet{ .LOGIN_START = .{
            .name = try connection.readString(16, allocator),
            .uuid = try connection.readUUID(allocator),
        } },
        0x01 => Packet{ .ENCRYPTION_RESPONSE = .{
            .shared_secret = try connection.readArray(@intCast(try connection.readVarInt(allocator)), u8, allocator),
            .verify_token = try connection.readArray(@intCast(try connection.readVarInt(allocator)), u8, allocator),
        } },
        else => error.InvalidPacketId,
    };
}

fn readPlayPacket(connection: *net.Connection, packet_id: i32, allocator: std.mem.Allocator) !Packet {
    _ = allocator;
    _ = packet_id;
    _ = connection;
    unreachable;
}

// WRITING PACKETS

pub fn writePacket(connection: *net.Connection, packet: Packet) !void {
    std.log.debug("Writing {s} packet...", .{@tagName(packet)});

    var event = events.network.PacketSendEvent{
        .packet = packet,
        .connection = connection,
        .canceled = false,
    };
    try events.disbatch(events.Event.fromType(&event));
    if (event.canceled) return;

    switch (packet) {
        .STATUS_RESPONSE => {
            try connection.writeVarInt(0x00);

            const string = try std.json.stringifyAlloc(connection.allocator, packet.STATUS_RESPONSE.data, .{ .emit_null_optional_fields = false });
            defer connection.allocator.free(string);

            std.debug.print("{s}\n", .{string});

            try connection.writeString(string, null);
            try connection.flush();
        },
        .PING_RESPONSE_STATUS => {
            try connection.writeVarInt(0x01);
            try connection.writeLong(0);
            try connection.flush();
        },
        .ENCRYPTION_REQUEST => {
            try connection.writeVarInt(0x01);
            try connection.writeString(packet.ENCRYPTION_REQUEST.server_id, 20);
            try connection.writeVarInt(@intCast(packet.ENCRYPTION_REQUEST.public_key.len));
            try connection.writeArray(packet.ENCRYPTION_REQUEST.public_key);
            try connection.writeVarInt(@intCast(packet.ENCRYPTION_REQUEST.verify_token.len));
            try connection.writeArray(packet.ENCRYPTION_REQUEST.verify_token);
            try connection.flush();
        },
        .LOGIN_SUCCESS => {
            try connection.writeVarInt(0x02);
            try connection.writeUUID(packet.LOGIN_SUCCESS.uuid);
            try connection.writeString(packet.LOGIN_SUCCESS.username, 16);
            if (packet.LOGIN_SUCCESS.properties) |properties| {
                try connection.writeVarInt(@bitCast(@as(u32, @truncate(properties.len))));
                for (properties) |property| {
                    try connection.writeString(property.name, null);
                    try connection.writeString(property.value, null);
                    try connection.writeBool(property.is_signed);
                    if (property.is_signed) try connection.writeString(property.signature.?, null);
                }
            } else {
                try connection.writeVarInt(0);
            }
            try connection.flush();
        },
        .SET_COMPRESSION => {
            try connection.writeVarInt(0x03);
            try connection.writeVarInt(packet.SET_COMPRESSION.threshold);
            try connection.flush();
        },
        else => @panic("Unimplemented!"),
    }
    std.log.debug("Done writing!", .{});
}

// HANDLING PACKETS

pub fn handlePacket(self: *net.Connection, packet: Packet) !bool {
    std.log.debug("Handling packet...", .{});
    switch (packet) {
        .HANDSHAKE => {
            const handshake = packet.HANDSHAKE;
            // TODO Handle incorrect protocol version
            self.state = handshake.next_state.toState();
        },
        .STATUS_REQUEST => {
            const response = Packet{ .STATUS_RESPONSE = .{ .data = .{
                .version = .{
                    .name = "1.20.2",
                    .protocol = 764,
                },
                .players = .{
                    .max = 100,
                    .online = 0,
                    .sample = &[0]StatusResponse.StatusResponseData.Players.Sample{},
                },
                .description = .{
                    .text = "Hello Minecraft!",
                },
                .favicon = null,
                .enforces_secure_chat = false,
                .previews_chat = false,
            } } };

            try writePacket(self, response);
        },
        .PING_REQUEST_STATUS => {
            const response = Packet{ .PING_RESPONSE_STATUS = .{
                .payload = packet.PING_REQUEST_STATUS.payload,
            } };

            try writePacket(self, response);
            return true;
        },
        .LOGIN_START => {
            const login_packet = packet.LOGIN_START;

            self.player = try player.Player.init(self.allocator, login_packet.name, null, login_packet.uuid);

            if (self.config.online_mode) {
                @panic("Unimplemented!");
                //try writePacket(
                //    self,
                //    Packet{ .LOGIN_SUCCESS = .{
                //        .uuid = self.player.?.uuid,
                //        .username = self.player.?.name,
                //        .properties = [0]LoginSuccess.Property,
                //    } },
                //);
                //// Compression and login success will be sent after recieving response
                //return true;
            }

            // Set compression threshold
            if (self.config.network_compression_threshold >= 0) {
                try writePacket(
                    self,
                    Packet{ .SET_COMPRESSION = .{
                        .threshold = self.config.network_compression_threshold,
                    } },
                );
                self.compressed = true;
            }

            try writePacket(
                self,
                Packet{ .LOGIN_SUCCESS = .{
                    .uuid = self.player.?.uuid.*,
                    .username = self.player.?.name,
                    .properties = null,
                } },
            );
        },
        .ENCRYPTION_RESPONSE => {
            @panic("Unimplemented!");
            //const enc_res = packet.ENCRYPTION_RESPONSE;

            //if (enc_res.verify_token.len > 162 or enc_res.shared_secret.len > 162)
            //    return error.EncryptionResponseTooLong;

            //// Shared Secret
            //var shared_secret: [162]u8 = undefined;
            //var secret_length = try self.server.rsa.decrypt(&shared_secret, enc_res.shared_secret);
            //if (secret_length != 16) return error.InvalidSecretLength;
            //// Verify Token
            //var verify_token: [162]u8 = undefined;
            //var verify_length = try self.server.rsa.decrypt(&verify_token, enc_res.verify_token);
            //if (verify_length != 4) return error.InvalidVerifyLength;

            //var verify_token_int: u32 = std.mem.bytesAsValue(u32, verify_token[0..4]).*;
            //if (verify_token_int != self.verify_token) return error.MismatchingVerifyToken;

            //self.cipher = try crypto.CFB8Cipher.init(shared_secret[0..16].*);

            //// Mojang authentication
            //var public_key: [162]u8 = undefined;
            //@memcpy(public_key[0..], self.server.rsa.public[0..]);
            //var hash: [20]u8 = undefined;
            //var context: openssl.SHA_CTX = undefined;

            //_ = openssl.SHA1_Init(&context);
            //_ = openssl.SHA1_Update(&context, &shared_secret, 0);
            //_ = openssl.SHA1_Update(&context, &shared_secret, shared_secret.len);
            //_ = openssl.SHA1_Update(&context, &public_key, public_key.len);
            //_ = openssl.SHA1_Final(&hash, &context);

            //var hash_hex = try crypto.hexdigest(hash);
            //std.debug.print("{s}\n", .{hash_hex});
            //_ = try mojang.auth(self.allocator, self.player.?.name, hash_hex, null);
        },
        else => @panic("Not implemented!"),
    }

    return false;
}

// --- HANDSHAKING ---

pub const Handshake = struct {
    pub const NextState = enum(usize) {
        STATUS = 1,
        LOGIN = 2,

        pub fn toState(self: *const NextState) ConnectionState {
            return switch (self.*) {
                .STATUS => .STATUS,
                .LOGIN => .LOGIN,
            };
        }
    };

    protocol_version: usize,
    server_address: []const u8,
    server_port: u16,
    next_state: NextState,
};

// --- STATUS ---
// CLIENTBOUND

pub const StatusResponse = struct {
    pub const StatusResponseData = struct {
        pub const Version = struct {
            name: []const u8,
            protocol: usize,
        };
        pub const Players = struct {
            pub const Sample = struct {
                name: []const u8,
                id: []const u8,
            };

            max: usize,
            online: usize,
            sample: ?[]const Sample,
        };

        version: Version,
        players: Players,
        description: chat.Chat,
        favicon: ?[]const u8,
        enforces_secure_chat: bool,
        previews_chat: bool,
    };

    data: StatusResponseData,
};

const PingResponse_Status = struct {
    payload: i64,
};

// SERVERBOUND

const StatusRequest = struct {};

const PingRequest_Status = struct {
    payload: i64,
};

// --- LOGIN ---
// CLIENTBOUND

const Disconnect_Login = struct {
    reason: chat.Chat,
};

const EncryptionRequest = struct {
    server_id: []const u8,
    public_key: []const u8,
    verify_token: []const u8,
};

const LoginSuccess = struct {
    const Property = struct {
        name: []const u8,
        value: []const u8,
        is_signed: bool,
        signature: ?[]const u8,
    };

    uuid: UUID,
    username: []const u8,
    properties: ?[]const Property,
};

const SetCompression = struct {
    threshold: i32,
};

const LoginPluginRequest = struct {
    message_id: i32,
    channel: identifier.Identifier,
    data: []const u8,
};

// SERVERBOUND

const LoginStart = struct {
    name: []const u8,
    uuid: UUID,
};

const EncryptionResponse = struct {
    shared_secret: []const u8,
    verify_token: []const u8,
};

const LoginPluginResponse = struct {
    message_id: i32,
    successful: bool,
    data: []const u8,
};

const LoginAcknowledged = struct {};

// --- CONFIGURATION ---
// Clientbound

const ConfigurationPluginMessage = struct {
    channel: identifier.Identifier,
    data: []const u8,
};

const Disconnect_Configuration = struct {
    reason: chat.TextContent,
};
