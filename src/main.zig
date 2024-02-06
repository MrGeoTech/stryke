const std = @import("std");
const network = @import("network/network.zig");
const crypto = @import("crypto/crypto.zig");
const mojang = @import("network/mojang.zig");
const events = @import("events/events.zig");

pub const std_options = struct {
    pub const log_level = .debug;
    pub const logFn = log;
};

pub var log_lock = std.Thread.Mutex{};

pub fn main() !void {
    //const my_logger = std.log.scoped(.my_logger);

    var allocator = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = allocator.deinit();

    const config = @import("config.zig").Config{};

    var server = try network.Server.init(allocator.allocator(), config);
    try server.start();
    defer server.deinit();

    while (true) {
        try server.tick();
        std.time.sleep(1 * std.time.ns_per_s / 2);
    }
}

pub fn log(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    const scope_prefix = "(" ++ @tagName(scope) ++ "): ";
    const prefix = "[" ++ comptime level.asText() ++ "] " ++ scope_prefix;

    log_lock.lock();
    defer log_lock.unlock();

    std.io.getStdOut().writer().print(prefix ++ format ++ "\n", args) catch return;
}

test "run all tests" {
    std.testing.refAllDeclsRecursive(network);
    std.testing.refAllDeclsRecursive(events);
}
