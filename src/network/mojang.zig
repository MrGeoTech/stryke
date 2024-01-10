const std = @import("std");
const openssl = @cImport({
    @cInclude("openssl/bio.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/x509v3.h");
});

const SESSION_SERVER = "google.com";
const SESSION_SERVER_PORT = "443";
const SESSION_SERVER_REQUEST = "/{s}{s}{s}";

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

    var ip_request = if (ip) |i| try std.fmt.allocPrint(arena.allocator(), "&ip={s}", .{i}) else "";
    var request = try std.fmt.allocPrint(arena.allocator(), SESSION_SERVER_REQUEST, .{ username, hash_hex, ip_request });

    const body = try getMojangAuth(arena.allocator(), request);

    const response = try std.json.parseFromSliceLeaky(ResponseStruct, arena.allocator(), body, .{});

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

/// Sends request to mojang servers and gets response
/// Not super strict on memory freeing so recommend using an ArenaAllocator
pub fn getMojangAuth(allocator: std.mem.Allocator, request: []const u8) ![]const u8 {
    comptime {
        if (openssl.OPENSSL_VERSION_NUMBER < 0x10100000)
            @compileError("Invalid OpenSSL version! Make sure you are using version 1.1.1 or higher!");
    }
    var ctx = openssl.SSL_CTX_new(openssl.TLS_client_method());
    if (openssl.SSL_CTX_set_min_proto_version(ctx, openssl.TLS1_2_VERSION) != 1) return error.OpenSSL_SetDefaultVerifyPaths;

    if (openssl.SSL_CTX_set_default_verify_paths(ctx) != 1) return error.OpenSSL_SetDefaultVerifyPaths;

    var bio = openssl.BIO_new_connect((SESSION_SERVER ++ ":" ++ SESSION_SERVER_PORT)) orelse unreachable;
    if (openssl.BIO_do_connect(bio) <= 0) return error.OpenSSL_BioDoConnect;

    var ssl_bio = openssl.BIO_new_ssl(ctx, 1) orelse unreachable;
    _ = openssl.BIO_push(bio, ssl_bio);

    if (openssl.SSL_set_tlsext_host_name(try getSSL(ssl_bio), SESSION_SERVER) != 1) return error.OpenSSL_SetTLSHostName;
    if (openssl.SSL_set1_host(try getSSL(ssl_bio), SESSION_SERVER) != 1) return error.OpenSSL_Set1Host;
    // TLS handshake
    var t = openssl.BIO_do_handshake(ssl_bio);
    std.debug.print("{d}\n", .{t});
    if (t <= 0) return error.OpenSSLTLSHandshake;
    try verifyCertificate(try getSSL(ssl_bio), SESSION_SERVER);

    try sendHttpRequest(allocator, ssl_bio, request, SESSION_SERVER);
    return readHttpResponse(allocator, ssl_bio);
}

/// Gets the inner ssl from a bio
fn getSSL(bio: *openssl.BIO) !*openssl.SSL {
    var ssl: ?*openssl.SSL = null;
    _ = openssl.BIO_get_ssl(bio, &ssl);
    return if (ssl) |s| s else return error.OpenSSL_BioGetSSL;
}

/// Used to verify a TLS certificate before sending any data
fn verifyCertificate(ssl: *openssl.SSL, expected_hostname: []const u8) !void {
    // Verify certificate (age, trusted..)
    var err = openssl.SSL_get_verify_result(ssl);
    var cert = openssl.SSL_get_peer_certificate(ssl);
    std.log.err("Subject: {s}", .{openssl.X509_NAME_oneline(openssl.X509_get_subject_name(cert), null, 0)});
    if (err != openssl.X509_V_OK) {
        const message = openssl.X509_verify_cert_error_string(err);
        std.log.err("Certificate verification error: {s} ({d})", .{ message, err });
        return error.CertificateInvalid;
    }
    // Make sure certificate exists
    if (cert == null) {
        std.log.err("No certificate was presented by the server!", .{});
    }
    // Make sure hostname matches
    if (openssl.X509_check_host(cert, expected_hostname.ptr, expected_hostname.len, 0, null) != 1) {
        std.log.err("Certificate verification error: Hostname mismatch", .{});
        return error.CertificateHostnameMismatch;
    }
}

fn sendHttpRequest(allocator: std.mem.Allocator, bio: *openssl.BIO, line: []const u8, host: []const u8) !void {
    var request = try std.fmt.allocPrint(allocator, "GET {s} HTTP/1.1\r\nHost: {s}\r\nUser-Agent: Stryke\r\nConnection: close\r\n\r\n", .{ line, host });
    defer allocator.free(request);

    std.log.err("Request {s}", .{request});

    if (openssl.BIO_write(bio, request.ptr, @intCast(request.len)) != request.len) return error.OpenSSL_BioWrite;
    if (openssl.BIO_flush(bio) != 1) return error.OpenSSL_BioFlush;
}

fn readHttpResponse(allocator: std.mem.Allocator, bio: *openssl.BIO) ![]const u8 {
    var headers = std.ArrayList(u8).init(allocator);
    defer headers.deinit();

    try headers.appendSlice(try readSomeData(bio));
    var end_of_headers = std.mem.indexOf(u8, headers.items, "\r\n\r\n");

    var file = try std.fs.cwd().createFile("temp.txt", .{});
    defer file.close();

    while (end_of_headers == null) {
        std.log.err("Headers: {s} ({?d})", .{ headers.items, end_of_headers });
        _ = try file.write(headers.items);
        try headers.appendSlice(try readSomeData(bio));
        end_of_headers = std.mem.indexOf(u8, headers.items, "\r\n\r\n");
    }

    var body = std.ArrayList(u8).init(allocator);
    defer body.deinit();
    try body.appendSlice(headers.items[end_of_headers.? + 4 ..]);
    headers.shrinkAndFree(end_of_headers.?);

    var content_length = try getContentLength(headers);
    while (body.items.len < content_length) {
        try body.appendSlice(try readSomeData(bio));
    }

    var body_copy = try allocator.alloc(u8, body.items.len);
    @memcpy(body_copy, body.items);
    return body_copy;
}

fn readSomeData(bio: *openssl.BIO) ![]u8 {
    var buffer: [1024]u8 = undefined;
    var len = openssl.BIO_read(bio, &buffer, buffer.len);
    if (len < 0) {
        return error.OpenSSL_BioRead;
    } else if (len > 0) {
        return buffer[0..@intCast(len)];
    } else if (openssl.BIO_should_retry(bio) == 1) {
        return readSomeData(bio);
    } else {
        return error.BIOReadEmpty;
    }
}

fn getContentLength(headers: std.ArrayList(u8)) !usize {
    var split_headers = try splitHeaders(headers);
    defer split_headers.deinit();
    for (split_headers.items) |line| {
        if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
            var header_name = line[0..colon];
            if (std.mem.eql(u8, header_name, "Content-Length")) {
                return std.fmt.parseInt(usize, line[colon + 1 ..], 10);
            }
        }
    }
    return 0;
}

fn splitHeaders(headers: std.ArrayList(u8)) !std.ArrayList([]u8) {
    var lines = std.ArrayList([]u8).init(headers.allocator);
    var start: usize = 0;
    while (std.mem.indexOfPos(u8, headers.items, start, "\r\n")) |end| {
        try lines.append(headers.items[start..end]);
        start = end + 2;
    }
    return lines;
}

test "auth" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) @panic("Leaks Detected!");

    var response = try auth(gpa.allocator(), "MrGeoTech", "eakjlnbvle;lkvasd", null);
    _ = response.arena.reset(.free_all);
    response.arena.deinit();
}
