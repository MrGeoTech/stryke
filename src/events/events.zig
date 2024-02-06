const std = @import("std");

pub const network = @import("network.zig");
pub const player = @import("player.zig");

/// A wrapper around any class that can be passed to listeners
pub const Event = struct {
    event_type: []const u8,
    event_data: []u8,

    pub fn fromType(value: anytype) Event {
        return switch (@typeInfo(@TypeOf(value))) {
            .Pointer => Event{ .event_type = @typeName(@TypeOf(value.*)), .event_data = @constCast(std.mem.asBytes(value)) },
            else => @compileError("Must pass pointer to Event.fromType!"),
        };
    }

    pub fn asType(self: Event, comptime T: type) *align(1) T {
        return std.mem.bytesAsValue(T, self.event_data[0..@sizeOf(T)]);
    }
};

pub const ListenerPriority = enum(usize) {
    LOWEST = 0,
    LOW = 250,
    MEDIUM = 500,
    HIGH = 750,
    HIGHEST = 1000,

    pub fn int(self: ListenerPriority) usize {
        return @intFromEnum(self);
    }
};

pub const Listener = struct {
    event_type: []const u8,
    /// The higher the number, the more priority
    /// Should almost always use ListenerPriority
    /// instead of a interger literal
    /// If multiple of the same priority listeners
    /// are registered, the ones previously register
    /// have priority
    listener_priority: usize,
    callback: *const fn (event: Event) ?anyerror,
};

var listeners: std.ArrayList(Listener) = undefined;

pub fn init(allocator: std.mem.Allocator) void {
    listeners = std.ArrayList(Listener).init(allocator);
}

pub fn deinit() void {
    listeners.deinit();
}

/// Does an ordered insertion into the array
pub fn register(listener: Listener) !void {
    var i: usize = 0;
    while (i < listeners.items.len and listeners.items[i].listener_priority <= listener.listener_priority) : (i += 1) {}
    try listeners.insert(i, listener);
}

/// Triggers all listeners in order
pub fn disbatch(event: Event) !void {
    var ordered = std.ArrayList(*const Listener).init(listeners.allocator);
    defer ordered.deinit();

    for (listeners.items) |listener| {
        if (std.mem.eql(u8, listener.event_type, event.event_type))
            try ordered.append(&listener);
    }

    var i: usize = ordered.items.len;
    while (i > 0) : (i -= 1) {
        if (ordered.items[i - 1].callback(event)) |err| return err;
    }
}

test "this" {
    init(std.testing.allocator);
    defer deinit();

    try register(Listener{ .event_type = "usize", .listener_priority = ListenerPriority.LOW.int(), .callback = testPrint });
    try register(Listener{ .event_type = "usize", .listener_priority = ListenerPriority.LOW.int(), .callback = testPrint });
    try disbatch(Event.fromType(@as(usize, 0)));
}

fn testPrint(event: Event) ?anyerror {
    var int_ptr = event.asType(usize);
    std.debug.print("Test {d} ", .{int_ptr.*});
    int_ptr.* += 1;
    return null;
}
