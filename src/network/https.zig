const std = @import("std");
const openssl = @cImport({
    @cInclude("openssl/ssl.h");
});

const HTTPSError = error{
    SSLCannotSetFd,
    SSLCannotConnect,
    SSLCannotWrite,
    NoHeaderEnd,
};

pub fn getResponse(allocator: std.mem.Allocator, server: []const u8, request: []const u8) !?[]const u8 {
    var host = try std.net.tcpConnectToHost(allocator, server, 443);
    defer host.close();

    var ctx = openssl.SSL_CTX_new(openssl.SSLv23_client_method());
    defer openssl.SSL_CTX_free(ctx);

    var ssl = openssl.SSL_new(ctx);
    defer openssl.SSL_free(ssl);

    openssl.SSL_set_connect_state(ssl);
    if (openssl.SSL_set_fd(ssl, host.handle) != 1) return HTTPSError.SSLCannotSetFd;

    if (openssl.SSL_connect(ssl) != 1) return HTTPSError.SSLCannotConnect;

    var r: usize = 0;
    var written: usize = 0;
    while (written < request.len) : (written += r) {
        r = @intCast(openssl.SSL_write(ssl, request[written..].ptr, @intCast(request[written..].len)));
        if (r <= 0) return HTTPSError.SSLCannotWrite;
    }

    var buffer = try allocator.alloc(u8, 4096);
    var read: usize = 0;
    r = 1;
    while (r > 0) : (read += r) {
        r = @intCast(openssl.SSL_read(ssl, buffer[read..].ptr, @intCast(buffer[read..].len)));
        if (r + read >= buffer.len) buffer = try allocator.realloc(buffer, buffer.len + 4096);
    }

    std.debug.print("{s}\n{s}\n", .{ request, buffer[0..read] });

    const body_index = (std.mem.indexOf(u8, buffer[0..read], "\r\n\r\n") orelse return HTTPSError.NoHeaderEnd) + 4;

    if (body_index == read) {
        allocator.free(buffer);
        return null;
    }

    std.mem.copyForwards(u8, buffer[0 .. read - body_index], buffer[body_index..read]);
    buffer = try allocator.realloc(buffer, read - body_index);

    return buffer;
}

test "getResponse" {
    const response = try getResponse(
        std.testing.allocator,
        "sessionserver.mojang.com",
        "GET /session/minecraft/hasJoined?username=MrGeoTech&serverId=jkafkljasn HTTP/1.1\r\nHost: sessionserver.mojang.com\r\nUser-Agent: Stryke 1.0.0\r\nConnection: close\r\n\r\n",
    ) orelse return;
    std.debug.print("{?s}", .{response});
    std.testing.allocator.free(response);
}
