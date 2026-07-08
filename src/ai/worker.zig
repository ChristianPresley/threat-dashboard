//! AI worker thread: owns all network I/O (Anthropic + MCP child) and runs
//! the agentic tool-use loop. The render thread talks to it ONLY through
//! two mutex-guarded channels drained/filled once per frame — ImGui and the
//! Store are never touched off-thread (the events.zig reaper contract).
//!
//! Lazily spawned on the first user message, so --selftest / --validate /
//! CI never create a thread or open a socket.
//!
//! Sync uses std.Io.Mutex + polling (this std's Condition has no timed
//! wait); a background thread polling at 20 ms is plenty for chat latency.

const std = @import("std");
const Allocator = std.mem.Allocator;
const net = @import("net");
const anthropic = @import("anthropic.zig");
const mcp = @import("mcp.zig");

const POLL_MS = 20;

fn sleepMs(io: std.Io, ms: i64) void {
    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(ms), .awake) catch {};
}

pub const McpState = enum { off, starting, ready, failed };

/// Render thread → worker.
pub const UiToWorker = union(enum) {
    user_message: struct { text: []u8, context: ?[]u8 },
    tool_reply: struct { id: u32, json: []u8, is_error: bool },
    cancel,
    shutdown,
};

/// Worker → render thread. The render thread takes ownership of any slices.
pub const WorkerToUi = union(enum) {
    status: []u8,
    assistant_text: []u8,
    tool_call: struct { name: []u8, input_preview: []u8 },
    tool_done: struct { name: []u8, result_preview: []u8, is_error: bool },
    tool_query: struct { id: u32, name: []u8, input_json: []u8 },
    turn_done: struct { input_tokens: u64, output_tokens: u64 },
    mcp_state: McpState,
    err: []u8,
    idle,
};

pub fn Channel(comptime T: type) type {
    return struct {
        const Self = @This();
        mutex: std.Io.Mutex = .init,
        items: std.ArrayList(T) = .empty,

        pub fn push(self: *Self, io: std.Io, gpa: Allocator, item: T) !void {
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            try self.items.append(gpa, item);
        }

        pub fn drainInto(self: *Self, io: std.Io, gpa: Allocator, out: *std.ArrayList(T)) void {
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            for (self.items.items) |it| out.append(gpa, it) catch {};
            self.items.clearRetainingCapacity();
        }

        pub fn tryPop(self: *Self, io: std.Io) ?T {
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            if (self.items.items.len == 0) return null;
            return self.items.orderedRemove(0);
        }

        pub fn deinitFree(self: *Self, gpa: Allocator, comptime freeFn: fn (Allocator, T) void) void {
            for (self.items.items) |it| freeFn(gpa, it);
            self.items.deinit(gpa);
        }
    };
}

pub const Config = struct {
    api_key: []const u8,
    model: []const u8,
    mcp_argv: []const []const u8,
    system_prompt: []const u8,
};

pub const Worker = struct {
    gpa: Allocator,
    io: std.Io,
    cfg: Config,
    thread: ?std.Thread = null,
    inbox: Channel(UiToWorker) = .{},
    outbox: Channel(WorkerToUi) = .{},
    cancel_flag: std.atomic.Value(bool) = .init(false),
    started: bool = false,

    // Worker-thread-only:
    http: ?net.Client = null,
    mcp_client: ?mcp.Client = null,
    convo: std.ArrayList(anthropic.Turn) = .empty,
    next_query_id: u32 = 1,

    const MAX_ITERS = 8;
    const HTTP_MAX_BODY = 2 * 1024 * 1024;
    const TOOL_REPLY_TIMEOUT_MS = 10_000;

    pub fn create(gpa: Allocator, io: std.Io, cfg: Config) !*Worker {
        const w = try gpa.create(Worker);
        w.* = .{ .gpa = gpa, .io = io, .cfg = cfg };
        return w;
    }

    pub fn ensureStarted(self: *Worker) void {
        if (self.started) return;
        self.started = true;
        self.thread = std.Thread.spawn(.{}, threadMain, .{self}) catch |err| {
            self.pushErr("failed to start AI worker: {s}", .{@errorName(err)});
            self.started = false;
            return;
        };
    }

    pub fn shutdown(self: *Worker) void {
        if (self.thread) |th| {
            self.cancel_flag.store(true, .seq_cst);
            self.inbox.push(self.io, self.gpa, .shutdown) catch {};
            th.join();
        }
        self.freeQueues();
        self.gpa.destroy(self);
    }

    fn freeQueues(self: *Worker) void {
        self.inbox.deinitFree(self.gpa, freeInbox);
        self.outbox.deinitFree(self.gpa, freeOutbox);
        for (self.convo.items) |t| self.gpa.free(t.content_json);
        self.convo.deinit(self.gpa);
    }

    // ── Render-thread producers/consumers ─────────────────────────────────

    pub fn send(self: *Worker, text: []const u8, context: ?[]const u8) void {
        self.ensureStarted();
        if (!self.started) return;
        const t = self.gpa.dupe(u8, text) catch return;
        const c = if (context) |ctx| (self.gpa.dupe(u8, ctx) catch null) else null;
        self.cancel_flag.store(false, .seq_cst);
        self.inbox.push(self.io, self.gpa, .{ .user_message = .{ .text = t, .context = c } }) catch {};
    }

    pub fn cancel(self: *Worker) void {
        self.cancel_flag.store(true, .seq_cst);
        self.inbox.push(self.io, self.gpa, .cancel) catch {};
    }

    pub fn replyToolQuery(self: *Worker, id: u32, json: []const u8, is_error: bool) void {
        const j = self.gpa.dupe(u8, json) catch return;
        self.inbox.push(self.io, self.gpa, .{ .tool_reply = .{ .id = id, .json = j, .is_error = is_error } }) catch {};
    }

    /// Drain the outbox into `out` (render thread, once per frame).
    pub fn drain(self: *Worker, out: *std.ArrayList(WorkerToUi)) void {
        self.outbox.drainInto(self.io, self.gpa, out);
    }

    // ── Worker thread ─────────────────────────────────────────────────────

    fn threadMain(self: *Worker) void {
        self.http = net.Client.init(self.gpa, self.io);
        defer if (self.http) |*h| h.deinit();

        self.pushOut(.{ .mcp_state = .starting });
        if (mcp.Client.spawn(self.gpa, self.io, self.cfg.mcp_argv)) |client| {
            self.mcp_client = client;
            if (self.mcp_client.?.handshake()) {
                self.pushOut(.{ .mcp_state = .ready });
            } else |_| {
                self.pushOut(.{ .mcp_state = .failed });
                self.mcp_client.?.deinit();
                self.mcp_client = null;
            }
        } else |_| {
            self.pushOut(.{ .mcp_state = .failed });
        }
        defer if (self.mcp_client) |*m| m.deinit();

        while (true) {
            const msg = self.inbox.tryPop(self.io) orelse {
                sleepMs(self.io, POLL_MS);
                continue;
            };
            switch (msg) {
                .shutdown => return,
                .cancel => {},
                .tool_reply => |tr| self.gpa.free(tr.json),
                .user_message => |um| {
                    self.handleUserMessage(um.text, um.context);
                    self.gpa.free(um.text);
                    if (um.context) |c| self.gpa.free(c);
                },
            }
        }
    }

    fn handleUserMessage(self: *Worker, text: []const u8, context: ?[]const u8) void {
        const user_content = anthropic.buildUserContent(self.gpa, text, context) catch return;
        self.convo.append(self.gpa, .{ .role = .user, .content_json = user_content }) catch return;

        var iter: u32 = 0;
        while (iter < MAX_ITERS) : (iter += 1) {
            if (self.cancel_flag.load(.seq_cst)) {
                self.pushStatus("cancelled");
                break;
            }
            self.pushStatus("thinking");

            const body = self.buildBody() catch {
                self.pushErr("failed to encode request", .{});
                break;
            };
            defer self.gpa.free(body);

            const headers = [_]net.Header{
                .{ .name = "x-api-key", .value = self.cfg.api_key },
                .{ .name = "anthropic-version", .value = "2023-06-01" },
            };
            const resp = self.http.?.postJson(self.gpa, "https://api.anthropic.com/v1/messages", &headers, body, HTTP_MAX_BODY) catch |err| {
                self.pushErr("request failed: {s}", .{@errorName(err)});
                break;
            };
            defer self.gpa.free(resp.body);

            var parsed = anthropic.parseResponse(self.gpa, resp.body) catch {
                self.pushErr("could not parse API response (HTTP {d})", .{resp.status});
                break;
            };
            defer parsed.deinit();

            if (parsed.api_error) |ae| {
                self.pushErr("API error: {s}", .{ae});
                break;
            }

            if (parsed.text.len > 0) {
                if (self.gpa.dupe(u8, parsed.text)) |dup| {
                    self.pushOut(.{ .assistant_text = dup });
                } else |_| {}
            }

            const assistant_content = self.gpa.dupe(u8, parsed.content_json) catch break;
            self.convo.append(self.gpa, .{ .role = .assistant, .content_json = assistant_content }) catch {
                self.gpa.free(assistant_content);
                break;
            };

            if (parsed.stop_reason != .tool_use or parsed.tool_uses.len == 0) {
                self.pushOut(.{ .turn_done = .{ .input_tokens = parsed.input_tokens, .output_tokens = parsed.output_tokens } });
                break;
            }

            var results: std.ArrayList(anthropic.ToolResult) = .empty;
            defer {
                for (results.items) |r| self.gpa.free(@constCast(r.content));
                results.deinit(self.gpa);
            }
            for (parsed.tool_uses) |tu| {
                const tt = self.dispatchTool(tu.name, tu.input_json) catch |err| blk: {
                    const m = std.fmt.allocPrint(self.gpa, "tool error: {s}", .{@errorName(err)}) catch continue;
                    break :blk ToolText{ .text = m, .is_error = true };
                };
                results.append(self.gpa, .{ .id = tu.id, .content = tt.text, .is_error = tt.is_error }) catch {
                    self.gpa.free(tt.text);
                    continue;
                };
            }

            const tr_content = anthropic.buildToolResultsContent(self.gpa, results.items) catch break;
            self.convo.append(self.gpa, .{ .role = .user, .content_json = tr_content }) catch {
                self.gpa.free(tr_content);
                break;
            };
        }
        self.pushOut(.idle);
    }

    const ToolText = struct { text: []u8, is_error: bool };

    fn dispatchTool(self: *Worker, name: []const u8, input_json: []const u8) !ToolText {
        {
            const nm = self.gpa.dupe(u8, name) catch return error.OutOfMemory;
            const pv = self.gpa.dupe(u8, if (input_json.len > 160) input_json[0..160] else input_json) catch {
                self.gpa.free(nm);
                return error.OutOfMemory;
            };
            self.pushOut(.{ .tool_call = .{ .name = nm, .input_preview = pv } });
        }
        var status_buf: [96]u8 = undefined;
        self.pushStatus(std.fmt.bufPrint(&status_buf, "calling {s}", .{name}) catch "calling tool");

        if (std.mem.startsWith(u8, name, "ti_")) {
            const bare = name[3..];
            if (self.mcp_client) |*m| {
                const cr = m.callTool(self.gpa, bare, input_json) catch |err| {
                    const msg = try std.fmt.allocPrint(self.gpa, "MCP call failed: {s}", .{@errorName(err)});
                    self.emitToolDone(name, msg, true);
                    return .{ .text = msg, .is_error = true };
                };
                self.emitToolDone(name, cr.text, cr.is_error);
                return .{ .text = @constCast(cr.text), .is_error = cr.is_error };
            }
            const msg = try self.gpa.dupe(u8, "threat-intel server unavailable (native tools only)");
            self.emitToolDone(name, msg, true);
            return .{ .text = msg, .is_error = true };
        }

        // Native tool → round-trip to the render thread for Store access.
        const qid = self.next_query_id;
        self.next_query_id += 1;
        self.pushOut(.{ .tool_query = .{
            .id = qid,
            .name = self.gpa.dupe(u8, name) catch return error.OutOfMemory,
            .input_json = self.gpa.dupe(u8, input_json) catch return error.OutOfMemory,
        } });

        var waited: i64 = 0;
        while (waited < TOOL_REPLY_TIMEOUT_MS) : (waited += POLL_MS) {
            if (self.cancel_flag.load(.seq_cst)) break;
            const m = self.inbox.tryPop(self.io) orelse {
                sleepMs(self.io, POLL_MS);
                continue;
            };
            switch (m) {
                .tool_reply => |tr| {
                    if (tr.id == qid) {
                        self.emitToolDone(name, tr.json, tr.is_error);
                        return .{ .text = tr.json, .is_error = tr.is_error };
                    }
                    self.gpa.free(tr.json);
                },
                .cancel => break,
                .shutdown => {
                    self.inbox.push(self.io, self.gpa, .shutdown) catch {};
                    break;
                },
                .user_message => |um| {
                    self.gpa.free(um.text);
                    if (um.context) |c| self.gpa.free(c);
                },
            }
        }
        const msg = try self.gpa.dupe(u8, "tool timed out");
        self.emitToolDone(name, msg, true);
        return .{ .text = msg, .is_error = true };
    }

    fn emitToolDone(self: *Worker, name: []const u8, result: []const u8, is_error: bool) void {
        const nm = self.gpa.dupe(u8, name) catch return;
        const pv = self.gpa.dupe(u8, if (result.len > 2048) result[0..2048] else result) catch {
            self.gpa.free(nm);
            return;
        };
        self.pushOut(.{ .tool_done = .{ .name = nm, .result_preview = pv, .is_error = is_error } });
    }

    fn buildBody(self: *Worker) ![]u8 {
        var aw: std.Io.Writer.Allocating = .init(self.gpa);
        errdefer aw.deinit();
        const mcp_tools: []const mcp.ToolDef = if (self.mcp_client) |*m| m.tools.items else &.{};
        try anthropic.buildRequest(&aw.writer, .{
            .model = self.cfg.model,
            .max_tokens = 4096,
            .system = self.cfg.system_prompt,
            .turns = self.convo.items,
            .mcp_tools = mcp_tools,
        });
        return aw.toOwnedSlice();
    }

    fn pushOut(self: *Worker, ev: WorkerToUi) void {
        self.outbox.push(self.io, self.gpa, ev) catch {};
    }

    fn pushStatus(self: *Worker, s: []const u8) void {
        const d = self.gpa.dupe(u8, s) catch return;
        self.pushOut(.{ .status = d });
    }

    fn pushErr(self: *Worker, comptime fmt: []const u8, args: anytype) void {
        const d = std.fmt.allocPrint(self.gpa, fmt, args) catch return;
        self.pushOut(.{ .err = d });
    }
};

pub fn freeInbox(gpa: Allocator, m: UiToWorker) void {
    switch (m) {
        .user_message => |um| {
            gpa.free(um.text);
            if (um.context) |c| gpa.free(c);
        },
        .tool_reply => |tr| gpa.free(tr.json),
        .cancel, .shutdown => {},
    }
}

pub fn freeOutbox(gpa: Allocator, m: WorkerToUi) void {
    switch (m) {
        .status, .assistant_text, .err => |s| gpa.free(s),
        .tool_call => |tc| {
            gpa.free(tc.name);
            gpa.free(tc.input_preview);
        },
        .tool_done => |td| {
            gpa.free(td.name);
            gpa.free(td.result_preview);
        },
        .tool_query => |tq| {
            gpa.free(tq.name);
            gpa.free(tq.input_json);
        },
        .turn_done, .mcp_state, .idle => {},
    }
}
