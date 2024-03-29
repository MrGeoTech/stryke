const std = @import("std");
const os = std.os;
const net = std.net;

const builtin = @import("builtin");

const network = @import("network.zig");
const packets = @import("packets.zig");
const chat = @import("../chat/chat.zig");
const identifier = @import("../data/indentifier.zig");
const crypto = @import("../crypto/crypto.zig");
const player = @import("../player/player.zig");

const nativeToBig = std.mem.nativeToBig;
const bigToNative = std.mem.bigToNative;

const Config = @import("../config.zig").Config;
const UUID = @import("../data/uuid.zig").UUID;

const MAX_PACKET_SIZE: comptime_int = 2097151;

pub const Connection = struct {
    // Underlying socket descriptor.
    // Note that on some platforms this may not be interchangeable with a
    // regular files descriptor.
    handle: os.socket_t,
    server: *network.Server,
    allocator: std.mem.Allocator,
    state: packets.ConnectionState,
    buffer: std.RingBuffer,
    config: Config,
    verify_token: u32,
    cipher: ?crypto.CFB8Cipher = null,
    player: ?player.Player = null,
    compressed: bool = false,

    pub fn init(handle: os.socket_t, allocator: std.mem.Allocator, state: packets.ConnectionState, server: *network.Server) !Connection {
        return Connection{
            .handle = handle,
            .server = server,
            .allocator = allocator,
            .state = state,
            .buffer = try std.RingBuffer.init(allocator, MAX_PACKET_SIZE),
            .config = server.config,
            .verify_token = std.crypto.random.int(u32),
        };
    }

    pub fn deinit(self: *const Connection) void {
        self.close();
        @constCast(self).buffer.deinit(self.allocator);
    }

    /// Disconnects the minecraft client gracefully
    /// Should be called instead of close
    pub fn disconnect(self: *Connection, reason: ?chat.Chat) !void {
        switch (self.state) {
            .PLAY => {},
            .LOGIN => {
                const packet = packets.Packet{ .DISCONNECT_LOGIN = .{ .reason = reason orelse chat.Chat{ .text = "Unspecified reason!" } } };
                packets.writePacket(self, packet);
            },
            else => {},
        }
        self.close();
    }

    /// Forcefully closes socket
    fn close(self: Connection) void {
        os.closeSocket(self.handle);
    }

    pub const ReadError = os.ReadError;
    pub const WriteError = os.WriteError;

    pub const Reader = std.io.Reader(Connection, ReadError, read);
    pub const Writer = std.io.Writer(Connection, WriteError, write);

    pub fn reader(self: Connection) Reader {
        return .{ .context = self };
    }

    pub fn writer(self: Connection) Writer {
        return .{ .context = self };
    }

    pub fn read(self: Connection, buffer: []u8) ReadError!usize {
        if (builtin.os.tag == .windows) {
            return os.windows.ReadFile(self.handle, buffer, null, std.io.default_mode);
        }

        if (std.io.is_async) {
            return std.event.Loop.instance.?.read(self.handle, buffer, false);
        } else {
            return os.read(self.handle, buffer);
        }
    }

    pub fn readv(s: Connection, iovecs: []const os.iovec) ReadError!usize {
        if (builtin.os.tag == .windows) {
            // TODO improve this to use ReadFileScatter

            if (iovecs.len == 0) return @as(usize, 0);
            const first = iovecs[0];
            return os.windows.ReadFile(s.handle, first.iov_base[0..first.iov_len], null, std.io.default_mode);
        }

        return os.readv(s.handle, iovecs);
    }

    /// Returns the number of bytes read. If the number read is smaller than
    /// `buffer.len`, it means the stream reached the end. Reaching the end of
    /// a stream is not an error condition.
    pub fn readAll(s: Connection, buffer: []u8) ReadError!usize {
        return readAtLeast(s, buffer, buffer.len);
    }

    /// Returns the number of bytes read, calling the underlying read function
    /// the minimal number of times until the buffer has at least `len` bytes
    /// filled. If the number read is less than `len` it means the stream
    /// reached the end. Reaching the end of the stream is not an error
    /// condition.
    pub fn readAtLeast(s: Connection, buffer: []u8, len: usize) ReadError!usize {
        std.debug.assert(len <= buffer.len);
        var index: usize = 0;
        while (index < len) {
            const amt = try s.read(buffer[index..]);
            if (amt == 0) break;
            index += amt;
        }
        return index;
    }

    pub fn writeBuffered(self: *Connection, data: []const u8) !void {
        std.log.debug("Writing {d} bytes to buffer...", .{data.len});
        for (data) |byte| {
            try self.buffer.write(byte);
            if (self.buffer.isFull()) try self.flush();
        }
    }

    pub fn flush(self: *Connection) !void {
        std.log.debug("Flushing {d} bytes...", .{self.buffer.len()});
        if (self.buffer.isEmpty()) return;
        if (self.compressed and self.buffer.len() > self.config.network_compression_threshold) return self.flushCompressed();
        // Adding packet length to the beginning of buffer
        var temp_buffer = try std.RingBuffer.init(self.allocator, 5 + self.buffer.len());
        defer temp_buffer.deinit(self.allocator);

        try writeVarIntBuffer(@constCast(&temp_buffer), @intCast(@as(u32, @truncate(self.buffer.len()))));

        while (self.buffer.read()) |byte| {
            try temp_buffer.write(byte);
        }
        // Converting from RingBuffer to a slice
        var data = temp_buffer.data[temp_buffer.read_index..temp_buffer.write_index];

        std.log.debug("Flushed!", .{});
        try self.writeAll(data);
    }

    fn flushCompressed(self: *Connection) !void {
        // Converting from RingBuffer to a slice
        var data = try self.allocator.alloc(u8, self.buffer.len());
        defer self.allocator.free(data);

        var i: usize = 0;
        while (self.buffer.read()) |byte| {
            data[i] = byte;
            i += 1;
        }

        // Compressing the data
        var compressed = std.ArrayList(u8).init(self.allocator);
        defer compressed.deinit();
        var compression_stream = try std.compress.zlib.compressStream(self.allocator, compressed.writer(), .{});
        defer compression_stream.deinit();

        _ = try compression_stream.write(data);
        try compression_stream.finish();

        // Adding varints to front
        var ring = try std.RingBuffer.init(self.allocator, 10);
        defer ring.deinit(self.allocator);

        try writeVarIntBuffer(&ring, @intCast(@as(u32, @truncate(data.len))));
        const packet_length = ring.len() + compressed.items.len;
        // Reset ring buffer
        ring.read_index = 0;
        ring.write_index = 0;

        try writeVarIntBuffer(&ring, @intCast(@as(u32, @truncate(packet_length))));
        try writeVarIntBuffer(&ring, @intCast(@as(u32, @truncate(data.len))));

        try compressed.insertSlice(0, ring.data[0..ring.len()]);

        std.log.debug("Flushed compressed!", .{});
        try self.writeAll(compressed.items);
    }

    /// TODO in evented I/O mode, this implementation incorrectly uses the event loop's
    /// file system thread instead of non-blocking. It needs to be reworked to properly
    /// use non-blocking I/O.
    pub fn write(self: Connection, buffer: []const u8) WriteError!usize {
        if (builtin.os.tag == .windows) {
            return os.windows.WriteFile(self.handle, buffer, null, std.io.default_mode);
        }

        if (std.io.is_async) {
            return std.event.Loop.instance.?.write(self.handle, buffer, false);
        } else {
            return os.write(self.handle, buffer);
        }
    }

    pub fn writeAll(self: Connection, bytes: []const u8) WriteError!void {
        var index: usize = 0;
        while (index < bytes.len) {
            index += try self.write(bytes[index..]);
        }
    }

    /// See https://github.com/ziglang/zig/issues/7699
    /// See equivalent function: `std.fs.File.writev`.
    pub fn writev(self: Connection, iovecs: []const os.iovec_const) WriteError!usize {
        if (std.io.is_async) {
            // TODO improve to actually take advantage of writev syscall, if available.

            if (iovecs.len == 0) return 0;
            const first_buffer = iovecs[0].iov_base[0..iovecs[0].iov_len];
            try self.write(first_buffer);
            return first_buffer.len;
        } else {
            return os.writev(self.handle, iovecs);
        }
    }

    /// The `iovecs` parameter is mutable because this function needs to mutate the fields in
    /// order to handle partial writes from the underlying OS layer.
    /// See https://github.com/ziglang/zig/issues/7699
    /// See equivalent function: `std.fs.File.writevAll`.
    pub fn writevAll(self: Connection, iovecs: []os.iovec_const) WriteError!void {
        if (iovecs.len == 0) return;

        var i: usize = 0;
        while (true) {
            var amt = try self.writev(iovecs[i..]);
            while (amt >= iovecs[i].iov_len) {
                amt -= iovecs[i].iov_len;
                i += 1;
                if (i >= iovecs.len) return;
            }
            iovecs[i].iov_base += amt;
            iovecs[i].iov_len -= amt;
        }
    }

    pub inline fn readBytes(self: *const Connection, size: usize, allocator: std.mem.Allocator) ![]const u8 {
        var buffer = try allocator.alloc(u8, size);
        _ = try self.readAtLeast(buffer, size);
        return buffer;
    }

    pub inline fn writeBytes(self: *const Connection, bytes: []const u8) !void {
        _ = try @constCast(self).writeBuffered(bytes);
    }

    pub inline fn readBool(self: *const Connection, allocator: std.mem.Allocator) !bool {
        return try self.readUByte(allocator) == 0x01;
    }

    pub inline fn writeBool(self: *const Connection, value: bool) !void {
        try self.writeUByte(@intFromBool(value));
    }

    pub inline fn readByte(self: *const Connection, allocator: std.mem.Allocator) !i8 {
        return @bitCast(try self.readUByte(allocator));
    }

    pub inline fn writeByte(self: *const Connection, value: i8) !void {
        try self.writeUByte(@bitCast(value));
    }

    pub inline fn readUByte(self: *const Connection, allocator: std.mem.Allocator) !u8 {
        return bigToNative(u8, (try self.readBytes(1, allocator))[0]);
    }

    pub inline fn writeUByte(self: *const Connection, value: u8) !void {
        try self.writeBytes(&[1]u8{value});
    }

    pub inline fn readShort(self: *const Connection, allocator: std.mem.Allocator) !i16 {
        return @bitCast(try self.readUShort(allocator));
    }

    pub inline fn writeShort(self: *const Connection, value: i16) !void {
        try self.writeUShort(@bitCast(value));
    }

    pub inline fn readUShort(self: *const Connection, allocator: std.mem.Allocator) !u16 {
        return bigToNative(u16, std.mem.bytesToValue(u16, (try self.readBytes(2, allocator))[0..2]));
    }

    pub inline fn writeUShort(self: *const Connection, value: u16) !void {
        try self.writeBytes(&std.mem.toBytes(value));
    }

    pub inline fn readInt(self: *const Connection, allocator: std.mem.Allocator) !i32 {
        return bigToNative(i32, std.mem.bytesToValue(i32, (try self.readBytes(4, allocator))[0..4]));
    }

    pub inline fn writeInt(self: *const Connection, value: i32) !void {
        try self.writeBytes(&std.mem.toBytes(@as(u32, @bitCast(value))));
    }

    pub inline fn readLong(self: *const Connection, allocator: std.mem.Allocator) !i64 {
        return bigToNative(i64, std.mem.bytesToValue(i64, (try self.readBytes(8, allocator))[0..8]));
    }

    pub inline fn writeLong(self: *const Connection, value: i64) !void {
        try self.writeBytes(&std.mem.toBytes(@as(u64, @bitCast(value))));
    }

    pub inline fn readFloat(self: *const Connection, allocator: std.mem.Allocator) !f32 {
        return @bitCast(try self.readInt(allocator));
    }

    pub inline fn writeFloat(self: *const Connection, value: f32) !void {
        self.writeInt(@bitCast(value));
    }

    pub inline fn readDouble(self: *const Connection, allocator: std.mem.Allocator) !f64 {
        return @bitCast(self.readLong(allocator));
    }

    pub inline fn writeDouble(self: *const Connection, value: f64) !void {
        return self.writeLong(@bitCast(value));
    }

    /// Returns are utf-8 encoded string. Enforces the max length
    pub inline fn readString(self: *const Connection, comptime max_len: ?comptime_int, allocator: std.mem.Allocator) ![]const u8 {
        const max_len_val = if (max_len) |len| len else 32767;
        const size: usize = @intCast(try self.readVarInt(allocator));

        if (size > max_len_val * 4 + 3) return error.StringTooLong;

        var bytes = try self.readBytes(@intCast(size), allocator);
        if (try std.unicode.utf8CountCodepoints(bytes) > max_len_val) return error.StringTooLong;

        return bytes;
    }

    /// Writes a utf-8 encoded string ensuring that it meets the size constraints before sending
    pub inline fn writeString(self: *const Connection, value: []const u8, comptime max_len: ?comptime_int) !void {
        const max_len_val = if (max_len) |len| len else 32767;
        if (try std.unicode.utf8CountCodepoints(value) > max_len_val) return error.StringTooLong;

        try self.writeVarInt(@intCast(value.len));
        try self.writeBytes(value);
    }

    pub inline fn readChat(self: *const Connection, allocator: std.mem.Allocator) !chat.Chat {
        const json = try self.readString(262144, allocator);
        defer allocator.free(json);
        return chat.Chat.fromJsonLeaky(json, allocator);
    }

    pub inline fn writeChat(self: *const Connection, value: chat.Chat) !void {
        const json = value.toJson(self.allocator);
        defer self.allocator.free(json);
        try self.writeString(json, 262144);
    }

    pub inline fn readIdentifier(self: *const Connection, allocator: std.mem.Allocator) !identifier.Identifier {
        const string = try self.readString(null, allocator);
        return try identifier.Identifier.fromString(string);
    }

    pub inline fn writeIdentifier(self: *const Connection, value: identifier.Identifier) !void {
        try self.writeString(value.toString(), null);
    }

    const SEGMENT_BITS: u8 = 0x7f;
    const CONTINUE_BIT: u8 = 0x80;

    pub inline fn readVarInt(self: *const Connection, allocator: std.mem.Allocator) !i32 {
        std.log.debug("Reading int...", .{});
        var value: u32 = 0;
        var position: u5 = 0;
        var current_byte: u8 = undefined;

        while (true) {
            current_byte = try self.readUByte(allocator);
            value |= @as(u32, current_byte & SEGMENT_BITS) << position;

            if (current_byte & CONTINUE_BIT == 0) break;

            const tuple = @addWithOverflow(position, 7);
            if (tuple[1] == 1) return error.VarNumberTooLong;
            position = tuple[0];
        }

        return @bitCast(value);
    }

    pub inline fn writeVarInt(self: *const Connection, value: i32) !void {
        std.log.debug("Writing varint: {d}", .{value});
        try writeVarIntBuffer(@constCast(&self.buffer), value);
    }

    pub inline fn writeVarIntBuffer(buffer: *std.RingBuffer, value: i32) !void {
        var uvalue: u32 = @bitCast(value);

        while (uvalue & ~@as(u32, SEGMENT_BITS) != 0) {
            try buffer.write((@as(u8, @truncate(uvalue)) & SEGMENT_BITS) | CONTINUE_BIT);

            uvalue >>= 7;
        }

        try buffer.write(@truncate(uvalue));
    }

    pub inline fn readVarLong(self: *const Connection, allocator: std.mem.Allocator) !i64 {
        var value: u64 = 0;
        var position: u6 = 0;
        var current_byte: u8 = undefined;

        while (true) {
            current_byte = try self.readUByte(allocator);
            value |= @as(u64, current_byte & SEGMENT_BITS) << position;

            if (current_byte & CONTINUE_BIT == 0) break;

            const tuple = @addWithOverflow(position, 7);
            if (tuple[1] == 1) return error.VarNumberTooLong;
            position = tuple[0];
        }

        return @bitCast(value);
    }

    pub inline fn writeVarLong(self: *const Connection, value: i64) !void {
        var uvalue: u64 = @bitCast(value);

        while (uvalue & ~@as(u64, SEGMENT_BITS) != 0) {
            try self.writeUByte((@as(u8, @truncate(uvalue)) & SEGMENT_BITS) | CONTINUE_BIT);

            uvalue >>= 7;
        }

        try self.writeUByte(@truncate(uvalue));
    }

    pub inline fn readEntityMetadata() void {
        @panic("TODO: Identifier not implemented yet");
    }

    pub inline fn writeEntityMetadata() void {
        @panic("TODO: Identifier not implemented yet");
    }

    pub inline fn readSlot() void {
        @panic("TODO: Identifier not implemented yet");
    }

    pub inline fn writeSlot() void {
        @panic("TODO: Identifier not implemented yet");
    }

    pub inline fn readNBT() void {
        @panic("TODO: Identifier not implemented yet");
    }

    pub inline fn writeNBT() void {
        @panic("TODO: Identifier not implemented yet");
    }

    pub inline fn readPosition() void {
        @panic("TODO: Identifier not implemented yet");
    }

    pub inline fn writePosition() void {
        @panic("TODO: Identifier not implemented yet");
    }

    pub inline fn readAngle() void {
        @panic("TODO: Identifier not implemented yet");
    }

    pub inline fn writeAngle() void {
        @panic("TODO: Identifier not implemented yet");
    }

    pub inline fn readUUID(self: *const Connection, allocator: std.mem.Allocator) !UUID {
        const upper: u64 = @bitCast(try self.readLong(allocator));
        const lower: u64 = @bitCast(try self.readLong(allocator));
        const combined: u128 = @as(u128, upper) << 64 | lower;
        return UUID{ .bytes = std.mem.asBytes(&combined).* };
    }

    pub inline fn writeUUID(self: *const Connection, value: UUID) !void {
        const as_int: u128 = std.mem.bytesToValue(u128, &value.bytes);
        const upper: u64 = @truncate(as_int >> 64);
        const lower: u64 = @truncate(as_int);
        try self.writeLong(@bitCast(upper));
        try self.writeLong(@bitCast(lower));
    }

    pub inline fn readArray(self: *const Connection, byte_size: usize, comptime T: type, allocator: std.mem.Allocator) ![]const T {
        return std.mem.bytesAsSlice(T, (try self.readBytes(byte_size, allocator))[0..byte_size]);
    }

    pub inline fn writeArray(self: *const Connection, array: anytype) !void {
        try self.writeBytes(std.mem.sliceAsBytes(array));
    }

    pub inline fn readEnum() void {
        @panic("TODO: Identifier not implemented yet");
    }

    pub inline fn writeEnum() void {
        @panic("TODO: Identifier not implemented yet");
    }
};

pub const StreamServer = struct {
    /// Copied from `Options` on `init`.
    kernel_backlog: u31,
    reuse_address: bool,
    reuse_port: bool,
    force_nonblocking: bool,

    /// `undefined` until `listen` returns successfully.
    listen_address: net.Address,

    sockfd: ?os.socket_t,

    pub const Options = struct {
        /// How many connections the kernel will accept on the application's behalf.
        /// If more than this many connections pool in the kernel, clients will start
        /// seeing "Connection refused".
        kernel_backlog: u31 = 128,

        /// Enable SO.REUSEADDR on the socket.
        reuse_address: bool = false,

        /// Enable SO.REUSEPORT on the socket.
        reuse_port: bool = false,

        /// Force non-blocking mode.
        force_nonblocking: bool = false,
    };

    /// After this call succeeds, resources have been acquired and must
    /// be released with `deinit`.
    pub fn init(options: Options) StreamServer {
        return StreamServer{
            .sockfd = null,
            .kernel_backlog = options.kernel_backlog,
            .reuse_address = options.reuse_address,
            .reuse_port = options.reuse_port,
            .force_nonblocking = options.force_nonblocking,
            .listen_address = undefined,
        };
    }

    /// Release all resources. The `StreamServer` memory becomes `undefined`.
    pub fn deinit(self: *StreamServer) void {
        self.close();
        self.* = undefined;
    }

    pub fn listen(self: *StreamServer, address: net.Address) !void {
        const nonblock = if (std.io.is_async) os.SOCK.NONBLOCK else 0;
        const sock_flags = os.SOCK.STREAM | os.SOCK.CLOEXEC | nonblock;
        var use_sock_flags: u32 = sock_flags;
        if (self.force_nonblocking) use_sock_flags |= os.SOCK.NONBLOCK;
        const proto = if (address.any.family == os.AF.UNIX) @as(u32, 0) else os.IPPROTO.TCP;

        const sockfd = try os.socket(address.any.family, use_sock_flags, proto);
        self.sockfd = sockfd;
        errdefer {
            os.closeSocket(sockfd);
            self.sockfd = null;
        }

        if (self.reuse_address) {
            try os.setsockopt(
                sockfd,
                os.SOL.SOCKET,
                os.SO.REUSEADDR,
                &std.mem.toBytes(@as(c_int, 1)),
            );
        }
        if (@hasDecl(os.SO, "REUSEPORT") and self.reuse_port) {
            try os.setsockopt(
                sockfd,
                os.SOL.SOCKET,
                os.SO.REUSEPORT,
                &std.mem.toBytes(@as(c_int, 1)),
            );
        }

        var socklen = address.getOsSockLen();
        try os.bind(sockfd, &address.any, socklen);
        try os.listen(sockfd, self.kernel_backlog);
        try os.getsockname(sockfd, &self.listen_address.any, &socklen);
    }

    /// Stop listening. It is still necessary to call `deinit` after stopping listening.
    /// Calling `deinit` will automatically call `close`. It is safe to call `close` when
    /// not listening.
    pub fn close(self: *StreamServer) void {
        if (self.sockfd) |fd| {
            os.closeSocket(fd);
            self.sockfd = null;
            self.listen_address = undefined;
        }
    }

    pub const AcceptError = error{
        ConnectionAborted,

        /// The per-process limit on the number of open file descriptors has been reached.
        ProcessFdQuotaExceeded,

        /// The system-wide limit on the total number of open files has been reached.
        SystemFdQuotaExceeded,

        /// Not enough free memory. This often means that the memory allocation
        /// is limited by the socket buffer limits, not by the system memory.
        SystemResources,

        /// Socket is not listening for new connections.
        SocketNotListening,

        ProtocolFailure,

        /// Socket is in non-blocking mode and there is no connection to accept.
        WouldBlock,

        /// Firewall rules forbid connection.
        BlockedByFirewall,

        FileDescriptorNotASocket,

        ConnectionResetByPeer,

        NetworkSubsystemFailed,

        OperationNotSupported,
    } || os.UnexpectedError;

    pub const NewConnection = struct {
        stream: Connection,
        address: net.Address,
    };

    /// If this function succeeds, the returned `NewConnection` is a caller-managed resource.
    pub fn accept(self: *StreamServer, allocator: std.mem.Allocator, server: *network.Server) !NewConnection {
        var accepted_addr: net.Address = undefined;
        var adr_len: os.socklen_t = @sizeOf(net.Address);
        const accept_result = blk: {
            if (std.io.is_async) {
                const loop = std.event.Loop.instance orelse return error.UnexpectedError;
                break :blk loop.accept(self.sockfd.?, &accepted_addr.any, &adr_len, os.SOCK.CLOEXEC);
            } else {
                break :blk os.accept(self.sockfd.?, &accepted_addr.any, &adr_len, os.SOCK.CLOEXEC);
            }
        };

        if (accept_result) |fd| {
            return NewConnection{
                .stream = try Connection.init(fd, allocator, .HANDSHAKE, server),
                .address = accepted_addr,
            };
        } else |err| {
            return err;
        }
    }
};
