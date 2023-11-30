const std = @import("std");
const net = @import("./netlib.zig");

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
};

pub const Packet = union(PacketType) {
    HANDSHAKE: Handshake,
    STATUS_RESPONSE: StatusResponse,
    PING_RESPONSE_STATUS: PingResponse_Status,
    STATUS_REQUEST: StatusRequest,
    PING_REQUEST_STATUS: PingRequest_Status,

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

    switch (connection.state) {
        ConnectionState.HANDSHAKE => {
            if (packet_id != 0x00) return PacketError.InvalidPacketId;
            return Packet{ .HANDSHAKE = Handshake{
                .protocol_version = @intCast(try connection.readVarInt(allocator)),
                .server_address = try connection.readString(255, allocator),
                .server_port = try connection.readUShort(allocator),
                .next_state = try std.meta.intToEnum(Handshake.NextState, try connection.readVarInt(allocator)),
            } };
        },
        ConnectionState.STATUS => return readStatusPacket(connection, packet_id, allocator),
        ConnectionState.LOGIN => return readLoginPacket(connection, packet_id, allocator),
        ConnectionState.PLAY => return readPlayPacket(connection, packet_id, allocator),
    }
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
    _ = allocator;
    _ = packet_id;
    _ = connection;
    unreachable;
}

fn readPlayPacket(connection: *net.Connection, packet_id: i32, allocator: std.mem.Allocator) !Packet {
    _ = allocator;
    _ = packet_id;
    _ = connection;
    unreachable;
}

// WRITING PACKETS

pub fn writePacket(connection: *net.Connection, packet: Packet) !void {
    std.log.debug("Writing packet...", .{});
    switch (packet) {
        .STATUS_RESPONSE => {
            try connection.writeVarInt(0x00);

            const string = try std.json.stringifyAlloc(connection.allocator, packet.STATUS_RESPONSE.data, .{});
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
        else => @panic("Not implemented!"),
    }

    return false;
}

// HANDSHAKING

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
    server_address: [255]u8,
    server_port: u16,
    next_state: NextState,
};

// STATUS
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
        pub const Description = struct {
            text: []const u8,
        };

        version: Version,
        players: Players,
        description: Description,
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

// LOGIN
// CLIENTBOUND

// PLAY
