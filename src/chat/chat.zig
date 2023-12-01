const std = @import("std");

pub const Chat = struct {
    bold: ?bool,
    italic: ?bool,
    underlined: ?bool,
    strikethrough: ?bool,
    obfuscated: ?bool,
    font: ?[]const u8,
    color: ?[]const u8,
    insertion: ?[]const u8,
    click_event: ?ClickEvent,
    hover_event: ?HoverEvent,
    extra: ?[]Chat,

    /// Converts chat to a json string. Caller owns memory
    pub fn toJson(self: *Chat, allocator: std.mem.Allocator) ![]const u8 {
        return std.json.stringifyAlloc(allocator, self.*, .{ .emit_null_optional_fields = false });
    }

    /// Parses chat using a safer but more computationally intense parsing method
    /// Caller owns the object
    pub fn fromJson(json: []const u8, allocator: std.mem.Allocator) !Chat {
        return std.json.parseFromSlice(Chat, allocator, json, .{ .ignore_unknown_fields = true, .duplicate_field_behavior = .use_first });
    }

    /// Parses chat using leaky parsing. Only 'std.heap.ArenaAllocator' should be used here.
    /// Caller owns the object
    pub fn fromJsonLeaky(json: []const u8, allocator: std.mem.Allocator) !Chat {
        return std.json.parseFromSliceLeaky(Chat, allocator, json, .{ .ignore_unknown_fields = true, .duplicate_field_behavior = .use_first });
    }
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
