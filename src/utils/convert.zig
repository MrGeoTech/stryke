const std = @import("std");

pub fn stringTo(comptime T: type, value: []const u8) !T {
    switch (@typeInfo(T)) {
        .Int => return std.fmt.parseInt(T, value, 10),
        .Float => return std.fmt.parseFloat(T, value),
    }
}
