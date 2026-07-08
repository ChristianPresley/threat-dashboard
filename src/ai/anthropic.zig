//! Anthropic Messages API encode/decode. The conversation is stored as raw
//! JSON `content` fragments (a string or a block array), echoed back
//! verbatim on the next request — so tool_use blocks and any future block
//! types round-trip without being modeled in Zig.

const std = @import("std");
const Allocator = std.mem.Allocator;
const tools = @import("tools.zig");
const mcp = @import("mcp.zig");

pub const Role = enum { user, assistant };

/// One conversation turn. `content_json` is a raw JSON value (a `"string"`
/// or a `[...]` block array), owned by the caller.
pub const Turn = struct {
    role: Role,
    content_json: []u8,
};

pub const StopReason = enum { end_turn, tool_use, max_tokens, other };

pub const ToolUse = struct {
    id: []const u8,
    name: []const u8,
    /// Re-serialized `input` object.
    input_json: []const u8,
};

/// Owns the parsed response document; slices in `text`/`tool_uses` point
/// into allocations tracked by the arena. Call `deinit` when done.
pub const Response = struct {
    arena: std.heap.ArenaAllocator,
    stop_reason: StopReason,
    /// Concatenated text blocks.
    text: []const u8,
    /// Raw `content` array JSON — echo this back as the assistant turn.
    content_json: []const u8,
    tool_uses: []const ToolUse,
    input_tokens: u64 = 0,
    output_tokens: u64 = 0,
    /// Set when the API returned an error envelope instead of a message.
    api_error: ?[]const u8 = null,

    pub fn deinit(self: *Response) void {
        self.arena.deinit();
    }
};

pub const BuildArgs = struct {
    model: []const u8,
    max_tokens: u32 = 4096,
    system: []const u8,
    turns: []const Turn,
    /// MCP tools discovered at runtime (may be empty).
    mcp_tools: []const mcp.ToolDef = &.{},
};

/// Serialize a Messages API request body into `w`.
pub fn buildRequest(w: *std.Io.Writer, a: BuildArgs) !void {
    try w.writeAll("{\"model\":");
    try jstr(w, a.model);
    try w.print(",\"max_tokens\":{d},\"system\":", .{a.max_tokens});
    try jstr(w, a.system);

    // Tools: native + MCP (prefixed ti_ so the worker can route them).
    try w.writeAll(",\"tools\":[");
    for (tools.native_tools, 0..) |tool, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"name\":");
        try jstr(w, tool.name);
        try w.writeAll(",\"description\":");
        try jstr(w, tool.description);
        try w.writeAll(",\"input_schema\":");
        try w.writeAll(tool.input_schema); // already valid JSON
        try w.writeByte('}');
    }
    for (a.mcp_tools) |mt| {
        // Skip names too long to prefix — advertising them unprefixed would
        // mis-route the call back through the native-tool path.
        var nb: [64]u8 = undefined;
        const prefixed = std.fmt.bufPrint(&nb, "ti_{s}", .{mt.name}) catch {
            std.log.scoped(.ai).warn("MCP tool name too long, skipping: {s}", .{mt.name});
            continue;
        };
        try w.writeAll(",{\"name\":");
        try jstr(w, prefixed);
        try w.writeAll(",\"description\":");
        try jstr(w, mt.description);
        try w.writeAll(",\"input_schema\":");
        try w.writeAll(mt.input_schema);
        try w.writeByte('}');
    }
    try w.writeByte(']');

    // Messages.
    try w.writeAll(",\"messages\":[");
    for (a.turns, 0..) |turn, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"role\":");
        try jstr(w, @tagName(turn.role));
        try w.writeAll(",\"content\":");
        try w.writeAll(turn.content_json); // raw JSON value
        try w.writeByte('}');
    }
    try w.writeAll("]}");
}

/// Parse a Messages API response body (or error envelope).
pub fn parseResponse(gpa: Allocator, body: []const u8) !Response {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const aa = arena.allocator();

    const doc = try std.json.parseFromSliceLeaky(std.json.Value, aa, body, .{});
    if (doc != .object) return error.MalformedResponse;
    const root = doc.object;

    // Error envelope: {"type":"error","error":{"type":..,"message":..}}
    if (root.get("type")) |ty| {
        if (ty == .string and std.mem.eql(u8, ty.string, "error")) {
            var msg: []const u8 = "unknown API error";
            if (root.get("error")) |e| {
                if (e == .object) {
                    if (e.object.get("message")) |m| {
                        if (m == .string) msg = m.string;
                    }
                }
            }
            return .{
                .arena = arena,
                .stop_reason = .other,
                .text = "",
                .content_json = "[]",
                .tool_uses = &.{},
                .api_error = try aa.dupe(u8, msg),
            };
        }
    }

    const stop_reason: StopReason = blk: {
        const sr = root.get("stop_reason") orelse break :blk .other;
        if (sr != .string) break :blk .other;
        if (std.mem.eql(u8, sr.string, "end_turn")) break :blk .end_turn;
        if (std.mem.eql(u8, sr.string, "tool_use")) break :blk .tool_use;
        if (std.mem.eql(u8, sr.string, "max_tokens")) break :blk .max_tokens;
        break :blk .other;
    };

    var in_tok: u64 = 0;
    var out_tok: u64 = 0;
    if (root.get("usage")) |u| {
        if (u == .object) {
            if (u.object.get("input_tokens")) |v| {
                if (v == .integer) in_tok = @intCast(@max(v.integer, 0));
            }
            if (u.object.get("output_tokens")) |v| {
                if (v == .integer) out_tok = @intCast(@max(v.integer, 0));
            }
        }
    }

    // Walk content blocks: collect text + tool_use.
    var text_buf: std.Io.Writer.Allocating = .init(aa);
    var tus: std.ArrayList(ToolUse) = .empty;
    const content = root.get("content") orelse std.json.Value{ .array = std.json.Array.init(aa) };
    if (content == .array) {
        for (content.array.items) |blk| {
            if (blk != .object) continue;
            const bt = blk.object.get("type") orelse continue;
            if (bt != .string) continue;
            if (std.mem.eql(u8, bt.string, "text")) {
                if (blk.object.get("text")) |txt| {
                    if (txt == .string) try text_buf.writer.writeAll(txt.string);
                }
            } else if (std.mem.eql(u8, bt.string, "tool_use")) {
                const id = strOf(blk.object.get("id")) orelse "";
                const name = strOf(blk.object.get("name")) orelse "";
                const input_val = blk.object.get("input") orelse std.json.Value{ .null = {} };
                const input_json = try std.json.Stringify.valueAlloc(aa, input_val, .{});
                try tus.append(aa, .{
                    .id = try aa.dupe(u8, id),
                    .name = try aa.dupe(u8, name),
                    .input_json = input_json,
                });
            }
        }
    }

    // Re-serialize the content array for verbatim echo.
    const content_json = try std.json.Stringify.valueAlloc(aa, content, .{});

    return .{
        .arena = arena,
        .stop_reason = stop_reason,
        .text = try text_buf.toOwnedSlice(),
        .content_json = content_json,
        .tool_uses = try tus.toOwnedSlice(aa),
        .input_tokens = in_tok,
        .output_tokens = out_tok,
    };
}

fn strOf(v: ?std.json.Value) ?[]const u8 {
    const val = v orelse return null;
    return switch (val) {
        .string => |s| s,
        else => null,
    };
}

/// Build a user turn's content array carrying tool_result blocks.
/// `results` are pre-formatted {id, content, is_error}.
pub const ToolResult = struct {
    id: []const u8,
    content: []const u8,
    is_error: bool,
};

pub fn buildToolResultsContent(gpa: Allocator, results: []const ToolResult) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(gpa);
    errdefer aw.deinit();
    const w = &aw.writer;
    try w.writeByte('[');
    for (results, 0..) |r, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"type\":\"tool_result\",\"tool_use_id\":");
        try jstr(w, r.id);
        try w.writeAll(",\"content\":");
        try jstr(w, r.content);
        if (r.is_error) try w.writeAll(",\"is_error\":true");
        try w.writeByte('}');
    }
    try w.writeByte(']');
    return aw.toOwnedSlice();
}

/// Build a user turn's content array carrying one text block (+ optional
/// attached-context text block).
pub fn buildUserContent(gpa: Allocator, text: []const u8, context: ?[]const u8) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(gpa);
    errdefer aw.deinit();
    const w = &aw.writer;
    try w.writeAll("[{\"type\":\"text\",\"text\":");
    try jstr(w, text);
    try w.writeByte('}');
    if (context) |ctx| {
        try w.writeAll(",{\"type\":\"text\",\"text\":");
        try jstr(w, ctx);
        try w.writeByte('}');
    }
    try w.writeByte(']');
    return aw.toOwnedSlice();
}

fn jstr(w: *std.Io.Writer, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        '\t' => try w.writeAll("\\t"),
        else => if (c < 0x20) try w.print("\\u{x:0>4}", .{c}) else try w.writeByte(c),
    };
    try w.writeByte('"');
}

// ── Tests ────────────────────────────────────────────────────────────────

test "build request round-trips through json" {
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    const user = try buildUserContent(std.testing.allocator, "hello", null);
    defer std.testing.allocator.free(user);
    const turns = [_]Turn{.{ .role = .user, .content_json = user }};
    try buildRequest(&aw.writer, .{ .model = "claude-sonnet-5", .system = "sys", .turns = &turns });
    const body = aw.written();
    try std.testing.expect(std.json.validate(std.testing.allocator, body) catch false);
}

test "parse response: text + tool_use" {
    const body =
        \\{"stop_reason":"tool_use","usage":{"input_tokens":10,"output_tokens":5},"content":[{"type":"text","text":"Let me look."},{"type":"tool_use","id":"tu_1","name":"get_iocs","input":{"type":"ip"}}]}
    ;
    var r = try parseResponse(std.testing.allocator, body);
    defer r.deinit();
    try std.testing.expectEqual(StopReason.tool_use, r.stop_reason);
    try std.testing.expectEqualStrings("Let me look.", r.text);
    try std.testing.expectEqual(@as(usize, 1), r.tool_uses.len);
    try std.testing.expectEqualStrings("get_iocs", r.tool_uses[0].name);
    try std.testing.expectEqual(@as(u64, 5), r.output_tokens);
}

test "parse response: error envelope" {
    const body =
        \\{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}
    ;
    var r = try parseResponse(std.testing.allocator, body);
    defer r.deinit();
    try std.testing.expect(r.api_error != null);
    try std.testing.expectEqualStrings("invalid x-api-key", r.api_error.?);
}

test "tool results content is valid json" {
    const results = [_]ToolResult{
        .{ .id = "tu_1", .content = "{\"ok\":true}", .is_error = false },
        .{ .id = "tu_2", .content = "boom", .is_error = true },
    };
    const out = try buildToolResultsContent(std.testing.allocator, &results);
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.json.validate(std.testing.allocator, out) catch false);
}
