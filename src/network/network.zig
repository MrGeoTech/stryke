const std = @import("std");
const net = std.net;
const os = std.os;
const netlib = @import("netlib.zig");
const builtin = @import("builtin");
const network = @import("network");
const packets = @import("./packets.zig");

const StreamServer = netlib.StreamServer;
const Connection = netlib.Connection;

const INVALID_SOCKET = switch (builtin.os.tag) {
    .windows => os.windows.ws2_32.INVALID_SOCKET,
    .linux, .macos, .tvos, .watchos, .ios => -1,
};

pub const Server = struct {
    stream: StreamServer,
    connections: std.ArrayList(Connection),
    connection_mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator) Server {
        std.log.debug("Creating new sever!", .{});
        return Server{
            .stream = StreamServer.init(.{ .reuse_address = true, .force_nonblocking = true }),
            .connections = std.ArrayList(Connection).init(allocator),
            .connection_mutex = std.Thread.Mutex{},
        };
    }

    pub fn deinit(self: *Server) void {
        std.log.debug("Closing server!", .{});
        self.connection_mutex.unlock();
        self.connection_mutex.lock();
        for (self.connections.items) |connection| {
            connection.deinit();
        }
        self.connections.deinit();
        self.connection_mutex.unlock();

        self.stream.deinit();
    }

    pub fn start(self: *Server, address: net.Address) !void {
        try self.stream.listen(address);
    }

    fn acceptNewConnections(self: *Server) !void {
        std.log.debug("Trying to accept new connections...", .{});
        while (true) {
            var new_connection = self.stream.accept(self.connections.allocator) catch |err| switch (err) {
                error.WouldBlock => break,
                else => return err,
            };
            std.log.debug("New connection accpeted!", .{});

            self.connection_mutex.lock();
            try self.connections.append(new_connection.stream);
            self.connection_mutex.unlock();
        }
    }

    pub fn tick(self: *Server) !void {
        std.log.debug("Server tick!", .{});
        try self.acceptNewConnections();

        self.connection_mutex.lock();
        for (self.connections.items, 0..) |const_connection, i| {
            var connection = const_connection;
            var arena = std.heap.ArenaAllocator.init(connection.allocator);
            defer {
                _ = arena.reset(.free_all);
                arena.deinit();
            }

            while (true) {
                if (connection.readVarInt(arena.allocator())) |packet_len| {
                    // TODO: Read packet
                    std.log.debug("Reading packet of len: {}", .{packet_len});
                    var packet = try packets.readPacket(@constCast(&connection), arena.allocator());
                    packet.print(.debug);
                    if (try packets.handlePacket(@constCast(&connection), packet)) {
                        std.log.debug("Closing connection!", .{});
                        connection.deinit();
                        _ = self.connections.orderedRemove(i);
                        break;
                    }
                    std.log.debug("Done handling packet!", .{});
                    // Handle error case
                } else |err| {
                    switch (err) {
                        error.WouldBlock => break,
                        else => return err,
                    }
                }
            }
        }
        self.connection_mutex.unlock();
    }
};
