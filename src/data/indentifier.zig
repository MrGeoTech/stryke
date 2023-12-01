const std = @import("std");
const eql = std.mem.eql;
const expect = std.testing.expect;

pub const Identifier = struct {
    namespace: []const u8,
    value: []const u8,

    pub const EMPTY = Identifier{
        .namespace = undefined,
        .value = undefined,
    };

    const IdentifierError = error{
        InvalidNamespace,
        InvalidValue,
    };

    pub fn fromString(string: []const u8) !Identifier {
        if (string.len == 0) return EMPTY;

        var split_index: usize = 0;
        var iterator = std.unicode.Utf8Iterator{ .bytes = string, .i = 0 };

        while (iterator.nextCodepoint()) |codepoint| {
            if (codepoint == ':') break;
            split_index += 1;
        }

        const namespace: []const u8 = if (split_index != string.len) string[0..split_index] else "minecraft";
        const value: []const u8 = if (split_index != string.len) string[split_index + 1 ..] else string;

        if (!isValidNamespace(namespace)) return IdentifierError.InvalidNamespace;
        if (!isValidValue(value)) return IdentifierError.InvalidValue;

        return Identifier{
            .namespace = namespace,
            .value = value,
        };
    }

    /// Returns identifier as one string.
    pub fn toString(self: Identifier) ![]const u8 {
        var string: [32767]u8 = undefined;

        @memcpy(string[0..self.namespace.len], self.namespace);
        string[self.namespace.len] = ':';
        @memcpy(string[self.namespace.len + 1 .. self.namespace.len + 1 + self.value.len], self.value);

        return string[0 .. self.namespace.len + 1 + self.value.len];
    }

    pub fn isValidNamespace(namespace: []const u8) bool {
        for (namespace) |char| {
            // [a-z0-9.-_]
            if (!((char >= '0' and char <= '9') or
                (char >= 'a' and char <= 'z') or
                char == '.' or
                char == '_' or
                char == '-')) return false;
        }
        return true;
    }

    pub fn isValidValue(value: []const u8) bool {
        for (value) |char| {
            // [a-z0-9.-_/]
            if (!((char >= '0' and char <= '9') or
                (char >= 'a' and char <= 'z') or
                char == '.' or
                char == '_' or
                char == '-' or
                char == '/')) return false;
        }
        return true;
    }

    pub fn isEqual(self: Identifier, other: Identifier) bool {
        return eql(u8, self.namespace, other.namespace) and eql(u8, self.value, self.value);
    }

    test "fromString" {
        const correct = Identifier{ .namespace = "minecraft", .value = "thing" };
        try expect(correct.isEqual(try Identifier.fromString("minecraft:thing")));
        try expect(correct.isEqual(try Identifier.fromString("thing")));
        try expect(!correct.isEqual(try Identifier.fromString(":thing")));
        try expect(!correct.isEqual(try Identifier.fromString("thing:minecraft")));
        try expect(!correct.isEqual(try Identifier.fromString("")));
    }

    test "toString" {
        const identifier = Identifier{ .namespace = "minecraft", .value = "thing" };
        const string = try identifier.toString();

        try expect(eql(u8, string, "minecraft:thing"));
    }

    test "isValidNamespace" {
        try expect(isValidNamespace("abcdefghijklmnopqrstuvwxyz"));
        try expect(isValidNamespace("minecraft"));
        try expect(isValidNamespace("minecraft_test"));
        try expect(isValidNamespace("minecraft-test"));
        try expect(isValidNamespace("minecraft.test"));
        try expect(isValidNamespace("minecraft0123456789"));
        try expect(!isValidNamespace("minecraft="));
        try expect(!isValidNamespace("minecraft+"));
        try expect(!isValidNamespace("minecraft()"));
        try expect(!isValidNamespace("minecraft/test"));
    }

    test "isValidValue" {
        try expect(isValidValue("abcdefghijklmnopqrstuvwxyz"));
        try expect(isValidValue("minecraft"));
        try expect(isValidValue("minecraft_test"));
        try expect(isValidValue("minecraft-test"));
        try expect(isValidValue("minecraft.test"));
        try expect(isValidValue("minecraft0123456789"));
        try expect(isValidValue("minecraft/test"));
        try expect(!isValidValue("minecraft="));
        try expect(!isValidValue("minecraft+"));
        try expect(!isValidValue("minecraft()"));
    }
};

test "Identifier" {
    std.testing.refAllDecls(Identifier);
}
