const std = @import("std");

pub const Component = union(enum) {
    text: TextContent,
    translatable: TranslatableContent,
    keybind: KeybindContent,
    score: ScoreContent,
    selector: SelectorContent,
    nbt: NBTContent,

    pub fn toJson(self: Component, allocator: std.mem.Allocator) error{OutOfMemory}![]const u8 {
        return switch (self) {
            .text => {
                const style = try std.json.stringifyAlloc(allocator, self.text.style, .{ .emit_null_optional_fields = false });
                defer allocator.free(style);

                const extras = try formatComponentArray("extra", self.text.extra, allocator);
                defer allocator.free(extras);

                try std.fmt.allocPrint(allocator, "{{\"text\":\"{s}\"{s}{s}{s}}}", .{
                    self.text.text,
                    if (style.len > 2) "," else "",
                    style[1 .. style.len - 1],
                    extras,
                });
            },
            .translatable => {
                const style = try std.json.stringifyAlloc(allocator, self.translatable.style, .{ .emit_null_optional_fields = false });
                defer allocator.free(style);

                const extras = try formatComponentArray("extra", self.translatable.extra, allocator);
                defer allocator.free(extras);

                const with = try formatComponentArray("with", self.translatable.with, allocator);
                defer allocator.free(with);

                try std.fmt.allocPrint(allocator, "{{\"translate\":\"{s}\"{s}{s}{s}{s}}}", .{
                    self.translatable.translate,
                    with,
                    if (style.len > 2) "," else "",
                    style[1 .. style.len - 1],
                    extras,
                });
            },
            .keybind => {
                const style = try std.json.stringifyAlloc(allocator, self.keybind.style, .{ .emit_null_optional_fields = false });
                defer allocator.free(style);

                const extras = try formatComponentArray("extra", self.keybind.extra, allocator);
                defer allocator.free(extras);

                try std.fmt.allocPrint(allocator, "{{\"keybind\":\"{s}\"{s}{s}{s}}}", .{
                    self.keybind.keybind.toString(),
                    if (style.len > 2) "," else "",
                    style[1 .. style.len - 1],
                    extras,
                });
            },
            .score => {
                const style = try std.json.stringifyAlloc(allocator, self.score.style, .{ .emit_null_optional_fields = false });
                defer allocator.free(style);

                const extras = try formatComponentArray("extra", self.score.extra, allocator);
                defer allocator.free(extras);

                const score = try std.json.stringifyAlloc(allocator, self.score.score, .{ .emit_null_optional_fields = false });
                defer allocator.free(score);

                try std.fmt.allocPrint(allocator, "{{\"score\":\"{s}\"{s}{s}{s}}}", .{
                    score,
                    if (style.len > 2) "," else "",
                    style[1 .. style.len - 1],
                    extras,
                });
            },
            .selector => {
                const style = try std.json.stringifyAlloc(allocator, self.selector.style, .{ .emit_null_optional_fields = false });
                defer allocator.free(style);

                const extras = try formatComponentArray("extra", self.selector.extra, allocator);
                defer allocator.free(extras);

                const separator = try std.json.stringifyAlloc(allocator, self.selector.separator, .{ .emit_null_optional_fields = false });
                defer allocator.free(extras);

                try std.fmt.allocPrint(allocator, "{{\"translate\":\"{s}\"{s}{s}{s}{s}{s}}}", .{
                    self.selector.selector,
                    if (separator.len > 2) ",\"separator\":" else "",
                    separator,
                    if (style.len > 2) "," else "",
                    style[1 .. style.len - 1],
                    extras,
                });
            },
            .nbt => {
                const style = try std.json.stringifyAlloc(allocator, self.nbt.style, .{ .emit_null_optional_fields = false });
                defer allocator.free(style);

                const extras = try formatComponentArray("extra", self.nbt.extra, allocator);
                defer allocator.free(extras);

                const separator = try std.json.stringifyAlloc(allocator, self.selector.separator, .{ .emit_null_optional_fields = false });
                defer allocator.free(extras);

                try std.fmt.allocPrint(allocator, "{{\"translate\":\"{s}\"{s}{s}{s}{s}{s}}}", .{
                    self.selector.selector,
                    if (separator.len > 2) ",\"separator\":" else "",
                    separator,
                    if (style.len > 2) "," else "",
                    style[1 .. style.len - 1],
                    extras,
                });
            },
        };
    }

    fn formatComponentArray(comptime name: []const u8, array: std.ArrayList(Component), allocator: std.mem.Allocator) ![]const u8 {
        if (array.items.len == 0) return allocator.alloc(u8, 0);

        var string: []u8 = try allocator.alloc(u8, 10);
        @memcpy(string, ",\"" ++ name ++ "\":[");

        for (array.items) |item| {
            const json = try item.toJson(allocator);
            defer allocator.free(json);
            string = try allocator.realloc(string, string.len + json.len + 1);
            @memcpy(string[string.len - 1 - json.len .. string.len - 1], json);
            string[string.len - 1] = ',';
        }

        string[string.len - 1] = ']';

        return string;
    }

    test "toJson" {
        var chat = Component{ .text = TextContent{
            .text = "Hello World",
            .extra = std.ArrayList(Component).init(std.testing.allocator),
            .style = .{
                .color = try colorFromName("red"),
            },
        } };
        std.log.err("{s}", .{try chat.toJson(std.testing.allocator)});
    }

    test "formatComponentArray" {
        var extras = std.ArrayList(Component).init(std.testing.allocator);
        defer extras.deinit();

        var string = try formatComponentArray("extra", extras, std.testing.allocator);
        try std.testing.expectEqualStrings("", string);
        std.testing.allocator.free(string);

        try extras.append(Component{ .text = TextContent{
            .text = "Hello World!",
            .extra = std.ArrayList(Component).init(std.testing.allocator),
        } });

        string = try formatComponentArray("extra", extras, std.testing.allocator);
        try std.testing.expectEqualStrings(",\"extra\":[{\"text\":\"Hello World!\"}]", string);
        std.testing.allocator.free(string);

        try extras.append(Component{ .text = TextContent{
            .text = "Hello World!",
            .extra = std.ArrayList(Component).init(std.testing.allocator),
        } });

        string = try formatComponentArray("extra", extras, std.testing.allocator);
        try std.testing.expectEqualStrings(",\"extra\":[{\"text\":\"Hello World!\"},{\"text\":\"Hello World!\"}]", string);
        std.testing.allocator.free(string);
    }
};

pub const TextContent = struct {
    text: []const u8,
    extra: std.ArrayList(Component),
    style: StylingOptions = .{},
};

pub const TranslatableContent = struct {
    translate: []const u8,
    with: std.ArrayList(Component),
    extra: std.ArrayList(Component),
    style: StylingOptions = .{},
};

pub const KeybindContent = struct {
    keybind: Keybind,
    extra: std.ArrayList(Component),
    style: StylingOptions = .{},
};

pub const ScoreContent = struct {
    score: Score,
    extra: std.ArrayList(Component),
    style: StylingOptions = .{},
};

pub const SelectorContent = struct {
    selector: []const u8,
    separator: ?*Component = null,
    extra: std.ArrayList(Component),
    style: StylingOptions = .{},
};

pub const NBTContent = struct {
    nbt: []const u8,
    interpret: ?bool = null,
    separator: ?*Component = null,
    block: []const u8,
    entity: []const u8,
    storage: []const u8,
};

pub const StylingOptions = struct {
    color: ?[]const u8 = null,

    bold: ?bool = null,
    italic: ?bool = null,
    underlined: ?bool = null,
    strikethrough: ?bool = null,
    obfuscated: ?bool = null,

    font: ?[]const u8 = null,

    insertion: ?[]const u8 = null,

    click_event: ?ClickEvent = null,
    hover_event: ?HoverEvent = null,
};

pub const ClickEvent = struct {
    pub const Action = enum([]const u8) {
        OPEN_URL = "open_url",
        RUN_COMMAND = "run_command",
        SUGGEST_COMMAND = "suggest_command",
        CHANGE_PAGE = "change_page",
        COPY_TO_CLIPBOARD = "copy_to_clipboard",
    };

    const ClickEventError = error{
        IllegalValue,
        ValueTooBig,
    };

    action: []const u8,
    value: []const u8,

    /// Sets the action and value while ensuring that the value is allowed for the action type
    pub fn set(self: *ClickEvent, action: Action, value: anytype) ClickEventError!void {
        switch (action) {
            .OPEN_URL, .RUN_COMMAND, .SUGGEST_COMMAND, .COPY_TO_CLIPBOARD => {
                switch (@typeInfo(@TypeOf(value))) {
                    .SLICE, .ARRAY, .POINTER => self.value = value,
                    else => return ClickEventError.IllegalValue,
                }
            },
            .CHANGE_PAGE => {
                switch (@typeInfo(@TypeOf(value))) {
                    .Int => {
                        if (value > 100) return ClickEventError.ValueTooBig;
                        self.value = &[3]u8{ 0, 0, 0 };
                        var writter = std.io.bufferedWriter(@constCast(self.value));
                        std.fmt.formatInt(value, 10, .lower, .{}, writter);
                    },
                    else => return ClickEventError.IllegalValue,
                }
            },
        }
    }
};

pub const HoverEvent = struct {
    pub const Action = enum([]const u8) {
        SHOW_TEXT = "show_text",
        SHOW_ITEM = "show_item",
        SHOW_ENTITY = "show_entity",
    };

    const HoverEventError = error{
        IllegalValue,
    };

    action: []const u8,
    contents: []const u8,

    /// Sets the action and value while ensuring that the value is allowed for the action type
    pub fn set(self: *HoverEvent, action: Action, value: anytype) HoverEventError!void {
        switch (action) {
            .SHOW_TEXT => {
                switch (@typeInfo(@TypeOf(value))) {
                    .SLICE, .ARRAY, .POINTER => self.value = value,
                    else => return HoverEventError.IllegalValue,
                }
            },
            else => @panic("Not implemented!"),
        }
    }
};

pub const Score = struct {
    name: []const u8,
    objective: []const u8,
};

pub const Keybind = enum {
    attack,
    use,
    forward,
    left,
    back,
    right,
    jump,
    sneak,
    sprint,
    drop,
    inventory,
    chat,
    playerlist,
    pick_item,
    command,
    social_interactions,
    screenshot,
    toggle_perspective,
    smooth_camera,
    fullscreen,
    spectator_outlines,
    swap_offhand,
    save_toolbar_activator,
    load_toolbar_activator,
    advancements,

    /// Converts a keybind enum into a string while fixing
    /// the case and format to be sent to the client
    pub fn toString(self: Keybind) []const u8 {
        return switch (self) {
            .pick_item => "pickItem",
            .social_interactions => "socialInteractions",
            .toggle_perspective => "togglePerspective",
            .smooth_camera => "smoothCamera",
            .spectator_outlines => "spectatorOutlines",
            .swap_offhand => "swapOffhand",
            .save_toolbar_activator => "saveToolbarActivator",
            .load_toolbar_activator => "loadToolbarActivator",
            else => @tagName(self),
        };
    }

    test "toString" {
        try std.testing.expectEqualStrings("attack", toString(Keybind.attack));
        try std.testing.expectEqualStrings("use", toString(Keybind.use));
        try std.testing.expectEqualStrings("forward", toString(Keybind.forward));
        try std.testing.expectEqualStrings("left", toString(Keybind.left));
        try std.testing.expectEqualStrings("back", toString(Keybind.back));
        try std.testing.expectEqualStrings("right", toString(Keybind.right));
        try std.testing.expectEqualStrings("jump", toString(Keybind.jump));
        try std.testing.expectEqualStrings("sneak", toString(Keybind.sneak));
        try std.testing.expectEqualStrings("sprint", toString(Keybind.sprint));
        try std.testing.expectEqualStrings("drop", toString(Keybind.drop));
        try std.testing.expectEqualStrings("inventory", toString(Keybind.inventory));
        try std.testing.expectEqualStrings("chat", toString(Keybind.chat));
        try std.testing.expectEqualStrings("playerlist", toString(Keybind.playerlist));
        try std.testing.expectEqualStrings("pickItem", toString(Keybind.pick_item));
        try std.testing.expectEqualStrings("command", toString(Keybind.command));
        try std.testing.expectEqualStrings("socialInteractions", toString(Keybind.social_interactions));
        try std.testing.expectEqualStrings("screenshot", toString(Keybind.screenshot));
        try std.testing.expectEqualStrings("togglePerspective", toString(Keybind.toggle_perspective));
        try std.testing.expectEqualStrings("smoothCamera", toString(Keybind.smooth_camera));
        try std.testing.expectEqualStrings("fullscreen", toString(Keybind.fullscreen));
        try std.testing.expectEqualStrings("spectatorOutlines", toString(Keybind.spectator_outlines));
        try std.testing.expectEqualStrings("swapOffhand", toString(Keybind.swap_offhand));
        try std.testing.expectEqualStrings("saveToolbarActivator", toString(Keybind.save_toolbar_activator));
        try std.testing.expectEqualStrings("loadToolbarActivator", toString(Keybind.load_toolbar_activator));
        try std.testing.expectEqualStrings("advancements", toString(Keybind.advancements));
    }
};

/// Just a thin wrapper around bufPrint to ensure
/// there won't be any runtime errors converting
pub fn colorFromInt(color: u24) [7]u8 {
    var buf: [7]u8 = undefined;
    _ = std.fmt.bufPrint(buf[0..], "#{X:6}", .{color}) catch unreachable;
    return buf;
}

/// Converts a color name to a color code to be sent to the server
/// Technically, the color name could be just sent to the server
/// but for ease of development, the color value should always be
/// a RGB hex color code
/// Case insensitive
pub fn colorFromName(color_raw: []const u8) error{InvalidName}![]const u8 {
    if (color_raw.len > 16) return error.InvalidName;
    // Convert to lowercase to be case insensitive
    var color_copy: [16]u8 = undefined;
    var color: []u8 = color_copy[0..color_raw.len];

    @memcpy(color_copy[0..color_raw.len], color_raw[0..color_raw.len]);

    for (color, 0..) |char, i| {
        color[i] = std.ascii.toLower(char);
    }
    // Return the right color
    if (std.mem.eql(u8, color, "black")) {
        return "#000000";
    } else if (std.mem.eql(u8, color, "dark_blue")) {
        return "#0000AA";
    } else if (std.mem.eql(u8, color, "dark_green")) {
        return "#00AA00";
    } else if (std.mem.eql(u8, color, "dark_aqua")) {
        return "#00AAAA";
    } else if (std.mem.eql(u8, color, "dark_red")) {
        return "#AA0000";
    } else if (std.mem.eql(u8, color, "dark_purple")) {
        return "#AA00AA";
    } else if (std.mem.eql(u8, color, "gold")) {
        return "#FFAA00";
    } else if (std.mem.eql(u8, color, "gray")) {
        return "#AAAAAA";
    } else if (std.mem.eql(u8, color, "dark_gray")) {
        return "#555555";
    } else if (std.mem.eql(u8, color, "blue")) {
        return "#5555FF";
    } else if (std.mem.eql(u8, color, "green")) {
        return "#55FF55";
    } else if (std.mem.eql(u8, color, "aqua")) {
        return "#55FFFF";
    } else if (std.mem.eql(u8, color, "red")) {
        return "#FF5555";
    } else if (std.mem.eql(u8, color, "light_purple")) {
        return "#FF55FF";
    } else if (std.mem.eql(u8, color, "yellow")) {
        return "#FFFF55";
    } else if (std.mem.eql(u8, color, "white")) {
        return "#FFFFFF";
    }
    return error.InvalidName;
}

/// Converts a legacy color code to its corresponding RGB values
/// Case insensitive
pub fn colorFromCode(code: u8) error{InvalidCode}![]const u8 {
    return switch (code) {
        '0' => "#000000",
        '1' => "#0000AA",
        '2' => "#00AA00",
        '3' => "#00AAAA",
        '4' => "#AA0000",
        '5' => "#AA00AA",
        '6' => "#FFAA00",
        '7' => "#AAAAAA",
        '8' => "#555555",
        '9' => "#5555FF",
        'A', 'a' => "#55FF55",
        'B', 'b' => "#55FFFF",
        'C', 'c' => "#FF5555",
        'D', 'd' => "#FF55FF",
        'E', 'e' => "#FFFF55",
        'F', 'f' => "#FFFFFF",
        else => error.InvalidCode,
    };
}

test "colorFromInt" {
    var string = colorFromInt(0x111111);
    try std.testing.expectEqualStrings("#111111", &string);
}

test "colorFromName" {
    var string = try colorFromName("red");
    try std.testing.expectEqualStrings("#FF5555", string);
}

test "colorFromCode" {
    var string = try colorFromCode('f');
    try std.testing.expectEqualStrings("#FFFFFF", string);
}

test "refAll" {
    std.testing.refAllDecls(Component);
    std.testing.refAllDecls(Keybind);
}
