//! AI · AI Assistant: a Claude chat panel with read-only dashboard tools
//! and (when configured) threatintel-mcp tools. Renders a config-needed
//! state when ANTHROPIC_API_KEY is unset — which is what --validate / CI
//! exercise, since they run without a key.

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

fn mcpColor(state: anytype) [4]f32 {
    const t = ui.theme.default;
    return switch (state) {
        .ready => t.sev.ok,
        .starting => t.sev.warn,
        .failed => t.sev.crit,
        .off => t.text.lo,
    };
}

pub fn render(d: *Dashboard) void {
    const t = ui.theme.default;
    const a = &d.assistant;

    // ── Config-needed state ──────────────────────────────────────────────
    if ((!a.cfg.configured() or a.worker == null) and !a.tour_demo) {
        zgui.textColored(t.sev.warn, "{s} AI assistant not configured", .{ui.fonts.fa.circle_info});
        zgui.spacing();
        zgui.textWrapped("Set the ANTHROPIC_API_KEY environment variable and restart the app to enable the assistant.", .{});
        zgui.spacing();
        zgui.textColored(t.text.lo, "Optional environment variables:", .{});
        zgui.bulletText("TD_AI_MODEL \u{2014} model id (default claude-sonnet-5)", .{});
        zgui.bulletText("TD_MCP_CMD \u{2014} threat-intel MCP command (default: threatintel-mcp --transport stdio)", .{});
        zgui.bulletText("VT_API_KEY / URLSCAN_API_KEY \u{2014} inherited by the MCP server for live enrichment", .{});
        zgui.spacing();
        zgui.textColored(t.text.lo, "The assistant has read-only access to dashboard data; threat-intel results are treated as untrusted and shown defanged.", .{});
        return;
    }

    // ── Header: model · MCP LED · tokens · Stop ──────────────────────────
    zgui.textColored(t.text.lo, "{s}", .{a.cfg.model});
    zgui.sameLine(.{ .spacing = 12 });
    zgui.textColored(mcpColor(a.mcp_state), "{s}", .{ui.fonts.fa.circle});
    zgui.sameLine(.{ .spacing = 4 });
    zgui.textColored(t.text.lo, "intel", .{});
    if (zgui.isItemHovered(.{})) {
        if (zgui.beginTooltip()) {
            zgui.text("threatintel-mcp: {s}", .{@tagName(a.mcp_state)});
            zgui.endTooltip();
        }
    }
    if (a.last_out_tokens > 0) {
        zgui.sameLine(.{ .spacing = 12 });
        zgui.textColored(t.text.lo, "{d} in / {d} out tok", .{ a.last_in_tokens, a.last_out_tokens });
    }
    if (a.busy) {
        zgui.sameLine(.{ .spacing = 12 });
        var sb: [24]u8 = undefined;
        const dots = (@as(usize, @intFromFloat(d.wall_clock_s * 2)) % 4);
        const el = std.fmt.bufPrintZ(&sb, "{s}{s}", .{ a.statusSlice(), (".....")[0..dots] }) catch "thinking";
        zgui.textColored(t.sev.warn, "{s}", .{el});
        zgui.sameLine(.{ .spacing = 10 });
        if (zgui.smallButton("Stop##ai")) {
            if (a.worker) |w| w.cancel();
        }
    }
    zgui.separator();

    // ── Transcript ───────────────────────────────────────────────────────
    const avail = zgui.getContentRegionAvail();
    // Transcript leaves room for chips + a 60px input + the hint line;
    // undersizing this clips the hint against the panel edge.
    const input_h: f32 = 118;
    zgui.pushStyleColor4f(.{ .idx = .child_bg, .c = t.bg.sunken });
    if (zgui.beginChild("##ai_transcript", .{ .w = avail[0], .h = @max(80, avail[1] - input_h) })) {
        if (a.transcript.items.len == 0) {
            zgui.textColored(t.text.lo, "Ask about alerts, hunt across telemetry, review rules, or enrich an indicator.", .{});
            zgui.textColored(t.text.lo, "Threat-intel results are untrusted external data; the assistant is read-only.", .{});
        }
        for (a.transcript.items, 0..) |*it, i| {
            renderItem(d, it, i);
        }
        if (a.scroll_to_bottom) {
            a.scroll_to_bottom = false;
            zgui.setScrollHereY(.{ .center_y_ratio = 1.0 });
        }
    }
    zgui.endChild();
    zgui.popStyleColor(.{ .count = 1 });

    // ── Context chips ────────────────────────────────────────────────────
    var chips = false;
    if (d.alq_sel) |aid| {
        var lb: [40]u8 = undefined;
        const lbl = std.fmt.bufPrintZ(&lb, "+ alert #{d}##aiattA", .{aid}) catch "+ alert";
        if (dash.filterChip(lbl, a.attach_alert, t.identity.triage)) a.attach_alert = !a.attach_alert;
        chips = true;
    }
    if (d.enr_sel) |iid| {
        if (chips) zgui.sameLine(.{ .spacing = 6 });
        var lb: [40]u8 = undefined;
        const lbl = std.fmt.bufPrintZ(&lb, "+ IOC #{d}##aiattI", .{iid}) catch "+ IOC";
        if (dash.filterChip(lbl, a.attach_ioc, t.identity.intel)) a.attach_ioc = !a.attach_ioc;
        chips = true;
    }

    // ── Input ────────────────────────────────────────────────────────────
    const submitted = zgui.inputTextMultiline("##ai_input", .{
        .buf = &a.input_buf,
        .w = avail[0] - 60,
        .h = 60,
        .flags = .{ .enter_returns_true = true, .ctrl_enter_for_new_line = true },
    });
    zgui.sameLine(.{ .spacing = 6 });
    const send_clicked = zgui.button("Send##ai", .{ .w = 52, .h = 60 });
    zgui.textColored(t.text.lo, "Enter sends \u{00B7} Ctrl+Enter newline", .{});

    if ((submitted or send_clicked) and !a.busy) {
        const text = std.mem.sliceTo(&a.input_buf, 0);
        const trimmed = std.mem.trim(u8, text, " \t\r\n");
        if (trimmed.len > 0) {
            d.assistantSend(trimmed);
            @memset(&a.input_buf, 0);
        }
    }
}

fn renderItem(d: *Dashboard, it: *dash.ChatItem, idx: usize) void {
    const t = ui.theme.default;
    _ = d;
    switch (it.kind) {
        .user => {
            zgui.textColored(t.accent, "you", .{});
            zgui.textWrapped("{s}", .{it.text});
        },
        .assistant => {
            zgui.textColored(t.identity.intel, "claude", .{});
            zgui.textWrapped("{s}", .{it.text});
        },
        .tool_call => {
            // Collapsible "called <tool>" card; the ##id keeps ImGui's label
            // unique WITHOUT leaking into the visible text.
            var hb: [80]u8 = undefined;
            const head = std.fmt.bufPrintZ(&hb, "called {s}##aitc{d}", .{ it.metaSlice(), idx }) catch "called tool";
            if (it.expanded) zgui.setNextItemOpen(.{ .is_open = true, .cond = .once });
            zgui.pushStyleColor4f(.{ .idx = .text, .c = t.text.lo });
            const open = zgui.treeNode(head);
            zgui.popStyleColor(.{ .count = 1 });
            if (open) {
                zgui.pushTextWrapPos(0);
                zgui.textColored(t.text.mid, "{s}", .{it.text});
                zgui.popTextWrapPos();
                zgui.treePop();
            }
        },
        .tool_result => {
            const col = if (it.is_error) t.sev.crit else t.text.mid;
            var hb: [80]u8 = undefined;
            const head = std.fmt.bufPrintZ(&hb, "result: {s}##aitr{d}", .{ it.metaSlice(), idx }) catch "result";
            zgui.pushStyleColor4f(.{ .idx = .text, .c = if (it.is_error) t.sev.crit else t.text.lo });
            const open = zgui.treeNode(head);
            zgui.popStyleColor(.{ .count = 1 });
            if (open) {
                zgui.pushTextWrapPos(0);
                zgui.textColored(col, "{s}", .{it.text});
                zgui.popTextWrapPos();
                zgui.treePop();
            }
        },
        .err => {
            zgui.textColored(t.sev.crit, "{s} {s}", .{ ui.fonts.fa.triangle_exclamation, it.text });
        },
    }
    zgui.spacing();
}
