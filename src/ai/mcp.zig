//! MCP stdio client: spawns `threatintel-mcp --transport stdio` as a child
//! process and speaks JSON-RPC 2.0 over newline-delimited stdin/stdout
//! (the MCP stdio framing). Lives on the worker thread only. Spawn failure
//! degrades gracefully — the assistant keeps working with native tools.
//!
//! The frame parser (parseRpcResult) is pure and fixture-tested; the live
//! process plumbing is exercised manually.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const ToolDef = struct {
    name: []const u8, // owned
    description: []const u8, // owned
    input_schema: []const u8, // owned raw JSON
};

pub const CallResult = struct {
    /// Concatenated text content of the result (or the error message).
    text: []const u8, // owned by caller's allocator
    is_error: bool,
};

/// Parsed JSON-RPC response: either a `result` object or an `error`.
pub const RpcResult = struct {
    arena: std.heap.ArenaAllocator,
    id: i64,
    /// The `result` value re-serialized, or null when this frame is an error.
    result_json: ?[]const u8,
    err_message: ?[]const u8,

    pub fn deinit(self: *RpcResult) void {
        self.arena.deinit();
    }
};

/// Parse one JSON-RPC 2.0 response line. Pure — no I/O.
pub fn parseRpcResult(gpa: Allocator, line: []const u8) !RpcResult {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const aa = arena.allocator();

    const v = try std.json.parseFromSliceLeaky(std.json.Value, aa, line, .{});
    if (v != .object) return error.MalformedRpc;
    const root = v.object;

    var id: i64 = 0;
    if (root.get("id")) |idv| {
        if (idv == .integer) id = idv.integer;
    }

    if (root.get("error")) |e| {
        var msg: []const u8 = "rpc error";
        if (e == .object) {
            if (e.object.get("message")) |m| {
                if (m == .string) msg = m.string;
            }
        }
        return .{ .arena = arena, .id = id, .result_json = null, .err_message = try aa.dupe(u8, msg) };
    }

    const result = root.get("result") orelse std.json.Value{ .null = {} };
    const result_json = try std.json.Stringify.valueAlloc(aa, result, .{});
    return .{ .arena = arena, .id = id, .result_json = result_json, .err_message = null };
}

/// Extract tool definitions from a `tools/list` result payload.
pub fn parseToolList(gpa: Allocator, result_json: []const u8, out: *std.ArrayList(ToolDef)) !void {
    var doc = try std.json.parseFromSlice(std.json.Value, gpa, result_json, .{});
    defer doc.deinit();
    if (doc.value != .object) return;
    const tools_v = doc.value.object.get("tools") orelse return;
    if (tools_v != .array) return;
    for (tools_v.array.items) |tv| {
        if (tv != .object) continue;
        const name = strOf(tv.object.get("name")) orelse continue;
        const desc = strOf(tv.object.get("description")) orelse "";
        const schema: []u8 = if (tv.object.get("inputSchema")) |sv|
            try std.json.Stringify.valueAlloc(gpa, sv, .{})
        else
            try gpa.dupe(u8, "{\"type\":\"object\"}");
        try out.append(gpa, .{
            .name = try gpa.dupe(u8, name),
            .description = try gpa.dupe(u8, desc),
            .input_schema = schema,
        });
    }
}

/// Extract concatenated text from a `tools/call` result payload
/// (result.content[] with {type:"text", text:...}); honors result.isError.
pub fn parseCallResult(gpa: Allocator, result_json: []const u8) !CallResult {
    var doc = try std.json.parseFromSlice(std.json.Value, gpa, result_json, .{});
    defer doc.deinit();
    var aw: std.Io.Writer.Allocating = .init(gpa);
    errdefer aw.deinit();
    var is_error = false;
    if (doc.value == .object) {
        if (doc.value.object.get("isError")) |ie| {
            if (ie == .bool) is_error = ie.bool;
        }
        if (doc.value.object.get("content")) |c| {
            if (c == .array) {
                for (c.array.items) |blk| {
                    if (blk != .object) continue;
                    if (strOf(blk.object.get("type"))) |bt| {
                        if (std.mem.eql(u8, bt, "text")) {
                            if (strOf(blk.object.get("text"))) |txt| try aw.writer.writeAll(txt);
                        }
                    }
                }
            }
        }
    }
    return .{ .text = try aw.toOwnedSlice(), .is_error = is_error };
}

fn strOf(v: ?std.json.Value) ?[]const u8 {
    const val = v orelse return null;
    return switch (val) {
        .string => |s| s,
        else => null,
    };
}

// ── Live client (worker thread) ──────────────────────────────────────────

pub const Client = struct {
    io: std.Io,
    gpa: Allocator,
    child: std.process.Child,
    in_file: std.Io.File,
    out_file: std.Io.File,
    in_buf: [4096]u8 = undefined,
    out_buf: [1 << 16]u8 = undefined,
    next_id: i64 = 1,
    tools: std.ArrayList(ToolDef) = .empty,

    /// Spawn the MCP server. argv[0] is the console script; env is inherited
    /// (so VT_API_KEY / URLSCAN_API_KEY flow through). Returns an error on
    /// spawn failure — the caller degrades to native-only.
    pub fn spawn(gpa: Allocator, io: std.Io, argv: []const []const u8) !Client {
        const child = try std.process.spawn(io, .{
            .argv = argv,
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .ignore,
            .create_no_window = true,
        });
        return .{
            .io = io,
            .gpa = gpa,
            .child = child,
            .in_file = child.stdin.?,
            .out_file = child.stdout.?,
        };
    }

    pub fn deinit(self: *Client) void {
        for (self.tools.items) |t| {
            self.gpa.free(t.name);
            self.gpa.free(t.description);
            self.gpa.free(t.input_schema);
        }
        self.tools.deinit(self.gpa);
        // Close stdin (EOF), then reap.
        self.in_file.close(self.io);
        _ = self.child.wait(self.io) catch {};
    }

    fn writeLine(self: *Client, json: []const u8) !void {
        var fw = self.in_file.writer(self.io, &self.in_buf);
        try fw.interface.writeAll(json);
        try fw.interface.writeByte('\n');
        try fw.interface.flush();
    }

    /// Read response lines until one matches `id` (skipping notifications).
    fn readResult(self: *Client, id: i64) !RpcResult {
        var fr = self.out_file.reader(self.io, &self.out_buf);
        var attempts: u32 = 0;
        while (attempts < 64) : (attempts += 1) {
            const line = (try fr.interface.takeDelimiter('\n')) orelse return error.McpClosed;
            if (line.len == 0) continue;
            var res = try parseRpcResult(self.gpa, line);
            if (res.id == id) return res;
            res.deinit(); // a notification or stale frame
        }
        return error.McpNoResponse;
    }

    fn rpc(self: *Client, method: []const u8, params_json: []const u8) !RpcResult {
        const id = self.next_id;
        self.next_id += 1;
        var aw: std.Io.Writer.Allocating = .init(self.gpa);
        defer aw.deinit();
        try aw.writer.print("{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"{s}\",\"params\":{s}}}", .{ id, method, params_json });
        try self.writeLine(aw.written());
        return self.readResult(id);
    }

    fn notify(self: *Client, method: []const u8, params_json: []const u8) !void {
        var aw: std.Io.Writer.Allocating = .init(self.gpa);
        defer aw.deinit();
        try aw.writer.print("{{\"jsonrpc\":\"2.0\",\"method\":\"{s}\",\"params\":{s}}}", .{ method, params_json });
        try self.writeLine(aw.written());
    }

    /// initialize handshake + notifications/initialized + tools/list.
    pub fn handshake(self: *Client) !void {
        var init_res = try self.rpc("initialize",
            \\{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"threat-dashboard","version":"1.0"}}
        );
        init_res.deinit();
        try self.notify("notifications/initialized", "{}");

        var list_res = try self.rpc("tools/list", "{}");
        defer list_res.deinit();
        if (list_res.result_json) |rj| try parseToolList(self.gpa, rj, &self.tools);
    }

    /// Call a tool by (unprefixed) name with a raw JSON arguments object.
    pub fn callTool(self: *Client, gpa: Allocator, name: []const u8, args_json: []const u8) !CallResult {
        var aw: std.Io.Writer.Allocating = .init(self.gpa);
        defer aw.deinit();
        try aw.writer.writeAll("{\"name\":");
        try jstr(&aw.writer, name);
        try aw.writer.writeAll(",\"arguments\":");
        try aw.writer.writeAll(if (args_json.len > 0) args_json else "{}");
        try aw.writer.writeByte('}');

        var res = try self.rpc("tools/call", aw.written());
        defer res.deinit();
        if (res.err_message) |em| {
            return .{ .text = try gpa.dupe(u8, em), .is_error = true };
        }
        return parseCallResult(gpa, res.result_json orelse "{}");
    }
};

fn jstr(w: *std.Io.Writer, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        else => try w.writeByte(c),
    };
    try w.writeByte('"');
}

// ── Tests (pure frame parsing) ───────────────────────────────────────────

test "parse rpc result + tools/list" {
    const line =
        \\{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"lookup_domain","description":"VT domain","inputSchema":{"type":"object","properties":{"domain":{"type":"string"}}}}]}}
    ;
    var res = try parseRpcResult(std.testing.allocator, line);
    defer res.deinit();
    try std.testing.expectEqual(@as(i64, 2), res.id);
    try std.testing.expect(res.result_json != null);

    var tools: std.ArrayList(ToolDef) = .empty;
    defer {
        for (tools.items) |t| {
            std.testing.allocator.free(t.name);
            std.testing.allocator.free(t.description);
            std.testing.allocator.free(t.input_schema);
        }
        tools.deinit(std.testing.allocator);
    }
    try parseToolList(std.testing.allocator, res.result_json.?, &tools);
    try std.testing.expectEqual(@as(usize, 1), tools.items.len);
    try std.testing.expectEqualStrings("lookup_domain", tools.items[0].name);
}

test "parse rpc error frame" {
    const line =
        \\{"jsonrpc":"2.0","id":3,"error":{"code":-32602,"message":"invalid params"}}
    ;
    var res = try parseRpcResult(std.testing.allocator, line);
    defer res.deinit();
    try std.testing.expect(res.err_message != null);
    try std.testing.expectEqualStrings("invalid params", res.err_message.?);
}

test "parse tools/call result (defanged text passes through)" {
    const result_json =
        \\{"content":[{"type":"text","text":"verdict: malicious hxxps://evil[.]com"}],"isError":false}
    ;
    const cr = try parseCallResult(std.testing.allocator, result_json);
    defer std.testing.allocator.free(cr.text);
    try std.testing.expect(!cr.is_error);
    try std.testing.expect(std.mem.indexOf(u8, cr.text, "evil[.]com") != null);
}
