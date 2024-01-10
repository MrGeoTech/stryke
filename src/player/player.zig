const std = @import("std");
const UUID = @import("uuid");

pub const Player = struct {
    arena: std.heap.ArenaAllocator,
    name: []const u8,
    display_name: []const u8,
    uuid: *UUID,

    pub fn init(child_allocator: std.mem.Allocator, name: []const u8, display_name: ?[]const u8, uuid: UUID) !Player {
        var arena = std.heap.ArenaAllocator.init(child_allocator);
        var _name = try arena.allocator().dupe(u8, name);
        var _display_name = if (display_name) |dn| try arena.allocator().dupe(u8, dn) else _name;
        var _uuid = try arena.allocator().create(UUID);
        @memcpy(&_uuid.bytes, &uuid.bytes);

        return Player{
            .arena = arena,
            .name = _name,
            .display_name = _display_name,
            .uuid = _uuid,
        };
    }
};
