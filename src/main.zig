const std = @import("std");
const network = @import("network/network.zig");

pub const std_options = struct {
    pub const log_level = .info;
    pub const logFn = log;
};

pub var log_lock = std.Thread.Mutex{};

pub fn main() !void {
    //const my_logger = std.log.scoped(.my_logger);

    var allocator = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = allocator.deinit();

    var server = network.Server.init(allocator.allocator());
    try server.start(try std.net.Address.parseIp("127.0.0.1", 25565));
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
    std.testing.refAllDecls(network);
}
