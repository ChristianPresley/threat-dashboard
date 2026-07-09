//! ALQ · Alert Queue: the triage table. Severity/status chips + text
//! filter, keyboard row selection (↑↓), actions on the selected alert
//! (A = ack, F = false-positive, C = assign to selected case), and a
//! detail pane for the selection.

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const domain = @import("domain");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

const MAX_ROWS = 4096;

pub fn render(d: *Dashboard) void {
    const t = ui.theme.active;
    const s = &d.store;

    // ── Filter bar ───────────────────────────────────────────────────────
    zgui.textColored(t.text.lo, "sev:", .{});
    const sev_names = [_][:0]const u8{ "info", "low", "med", "high", "crit" };
    inline for (sev_names, 0..) |nm, i| {
        zgui.sameLine(.{ .spacing = 4 });
        if (dash.filterChip(nm ++ "##alqsev", d.alq_sev_show[i], dash.sevColor(@enumFromInt(i)))) {
            d.alq_sev_show[i] = !d.alq_sev_show[i];
        }
    }
    zgui.sameLine(.{ .spacing = 14 });
    if (dash.filterChip("show closed##alq", d.alq_show_closed, t.accent)) {
        d.alq_show_closed = !d.alq_show_closed;
    }
    zgui.sameLine(.{ .spacing = 14 });
    if (d.alq_focus_filter and zgui.isWindowFocused(.{ .root_window = true, .child_windows = true })) {
        d.alq_focus_filter = false;
        zgui.setKeyboardFocusHere(0);
    }
    zgui.setNextItemWidth(180);
    _ = zgui.inputTextWithHint("##alq_filter", .{ .hint = "filter (Ctrl+F)", .buf = &d.alq_filter_buf });
    if (d.alq_technique_filter) |tid| {
        const tech = domain.attack.get(tid);
        zgui.sameLine(.{ .spacing = 10 });
        zgui.textColored(t.amber, "technique {s}", .{tech.id});
        zgui.sameLine(.{ .spacing = 4 });
        if (zgui.smallButton("\u{00D7}##alqtech")) d.alq_technique_filter = null;
    }

    // ── Collect visible rows (newest first) ──────────────────────────────
    const filter = std.mem.sliceTo(&d.alq_filter_buf, 0);
    var rows: [MAX_ROWS]u32 = undefined; // indices into alerts.items
    var m: usize = 0;
    {
        var i: usize = s.alerts.items.len;
        while (i > 0 and m < rows.len) {
            i -= 1;
            const a = &s.alerts.items[i];
            if (!d.alq_sev_show[@intFromEnum(a.severity)]) continue;
            if (!d.alq_show_closed and !a.status.isOpen()) continue;
            if (d.alq_technique_filter) |tid| {
                if (a.technique == null or a.technique.? != tid) continue;
            }
            if (filter.len > 0 and
                std.ascii.indexOfIgnoreCase(a.title.slice(), filter) == null and
                std.ascii.indexOfIgnoreCase(a.entity.slice(), filter) == null) continue;
            rows[m] = @intCast(i);
            m += 1;
        }
    }

    zgui.sameLine(.{ .spacing = 14 });
    zgui.textColored(t.text.lo, "{d} shown", .{m});

    if (m == 0) {
        zgui.spacing();
        zgui.textColored(t.text.lo, "No alerts match the filters.", .{});
        return;
    }

    // Selected row position (for keyboard nav).
    var sel_pos: ?usize = null;
    if (d.alq_sel) |sid| {
        for (rows[0..m], 0..) |ri, p| {
            if (s.alerts.items[ri].id == sid) {
                sel_pos = p;
                break;
            }
        }
    }

    // ── Keyboard: ↑↓ selection, A/F/C actions (window focused, no text) ──
    const win_focused = zgui.isWindowFocused(.{ .root_window = true, .child_windows = true });
    if (win_focused and !zgui.io.getWantTextInput()) {
        if (zgui.isKeyPressed(.down_arrow, true)) {
            const p = if (sel_pos) |p| @min(p + 1, m - 1) else 0;
            d.alq_sel = s.alerts.items[rows[p]].id;
            sel_pos = p;
        }
        if (zgui.isKeyPressed(.up_arrow, true)) {
            const p = if (sel_pos) |p| p -| 1 else 0;
            d.alq_sel = s.alerts.items[rows[p]].id;
            sel_pos = p;
        }
        if (d.alq_sel) |sid| {
            if (zgui.isKeyPressed(.a, false) or zgui.isKeyPressed(.enter, false)) ackAlert(d, sid);
            if (zgui.isKeyPressed(.f, false)) markFp(d, sid);
            if (zgui.isKeyPressed(.c, false)) assignToCase(d, sid);
        }
    }

    // ── Table + detail split ─────────────────────────────────────────────
    const avail = zgui.getContentRegionAvail();
    // Detail grows with the linked-event list (one selectable per event).
    const detail_h: f32 = if (d.alq_sel) |sid| blk: {
        const ev_n: f32 = if (s.alertById(sid)) |a| @floatFromInt(a.event_count) else 1;
        break :blk 110 + @max(0, ev_n - 1) * 18;
    } else 0;
    const table_h = @max(80, avail[1] - detail_h);

    const flags = zgui.TableFlags{
        .resizable = true,
        .borders = .{ .inner_h = true },
        .scroll_y = true,
        .row_bg = false,
    };
    if (zgui.beginTable("##alq_table", .{ .column = 7, .flags = flags, .outer_size = .{ avail[0], table_h } })) {
        zgui.tableSetupColumn("Time", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 72 });
        zgui.tableSetupColumn("Sev", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 48 });
        zgui.tableSetupColumn("Status", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 70 });
        zgui.tableSetupColumn("Title", .{ .flags = .{ .width_stretch = true } });
        zgui.tableSetupColumn("Entity", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 170 });
        zgui.tableSetupColumn("Rule", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 62 });
        zgui.tableSetupColumn("Case", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 48 });
        zgui.tableSetupScrollFreeze(0, 1);
        zgui.tableHeadersRow();

        var clipper = zgui.ListClipper.init();
        clipper.begin(@intCast(m), null);
        defer clipper.end();
        while (clipper.step()) {
            var row: i32 = clipper.DisplayStart;
            while (row < clipper.DisplayEnd) : (row += 1) {
                const ri: usize = @intCast(row);
                if (ri >= m) break;
                const a = &s.alerts.items[rows[ri]];
                zgui.tableNextRow(.{});
                const selected = d.alq_sel != null and d.alq_sel.? == a.id;
                if (selected) {
                    zgui.tableSetBgColor(.{ .target = .row_bg0, .color = zgui.colorConvertFloat4ToU32(t.bg.selected) });
                }
                const dim = !a.status.isOpen();
                const text_col = if (dim) t.text.lo else t.text.hi;

                _ = zgui.tableNextColumn();
                var cb: [16]u8 = undefined;
                // Row-spanning selectable in the first column.
                var slbl: [24]u8 = undefined;
                const sl = std.fmt.bufPrintZ(&slbl, "##alqrow{d}", .{a.id}) catch "##r";
                const cur = zgui.getCursorPosX();
                if (zgui.selectable(sl, .{ .selected = selected, .flags = .{ .span_all_columns = true, .allow_overlap = true } })) {
                    d.alq_sel = a.id;
                }
                zgui.sameLine(.{});
                zgui.setCursorPosX(cur);
                zgui.textColored(t.text.lo, "{s}", .{ui.fmt.ts(&cb, @divFloor(a.ts_ms, 1000))});

                _ = zgui.tableNextColumn();
                zgui.textColored(dash.sevColor(a.severity), "{s}", .{a.severity.label()});
                _ = zgui.tableNextColumn();
                zgui.textColored(if (a.status == .new) t.accent else text_col, "{s}", .{a.status.label()});
                _ = zgui.tableNextColumn();
                zgui.textUnformattedColored(text_col, a.title.slice());
                _ = zgui.tableNextColumn();
                zgui.textUnformattedColored(text_col, a.entity.slice());
                _ = zgui.tableNextColumn();
                if (a.rule < s.rules.items.len) {
                    // Click through to the rule in RUL.
                    const r = &s.rules.items[a.rule];
                    var rb: [32]u8 = undefined;
                    const rl = std.fmt.bufPrintZ(&rb, "{s}##alqrule{d}", .{ r.code.slice(), a.id }) catch @as([:0]const u8, "rule");
                    zgui.pushStyleColor4f(.{ .idx = .text, .c = t.text.mid });
                    if (zgui.selectable(rl, .{})) {
                        d.rul_sel = r.id;
                        d.focusPanel(dash.PANEL_RUL);
                    }
                    zgui.popStyleColor(.{ .count = 1 });
                }
                _ = zgui.tableNextColumn();
                if (a.case_id) |cid| {
                    // Click through to the case in CAS.
                    var casb: [24]u8 = undefined;
                    const casl = std.fmt.bufPrintZ(&casb, "#{d}##alqcase{d}", .{ cid, a.id }) catch @as([:0]const u8, "case");
                    zgui.pushStyleColor4f(.{ .idx = .text, .c = t.accent });
                    if (zgui.selectable(casl, .{})) {
                        d.cas_sel = cid;
                        d.focusPanel(dash.PANEL_CAS);
                    }
                    zgui.popStyleColor(.{ .count = 1 });
                } else {
                    zgui.textColored(t.text.lo, "\u{2014}", .{});
                }
            }
        }
        zgui.endTable();
    }

    // ── Detail pane ──────────────────────────────────────────────────────
    if (d.alq_sel) |sid| {
        if (s.alertById(sid)) |a| {
            zgui.separator();
            zgui.textColored(dash.sevColor(a.severity), "{s}", .{a.severity.label()});
            zgui.sameLine(.{ .spacing = 8 });
            zgui.textUnformatted(a.title.slice());
            zgui.sameLine(.{ .spacing = 12 });
            zgui.textColored(t.text.mid, "{s}", .{a.entity.slice()});
            if (a.technique) |tid| {
                const tech = domain.attack.get(tid);
                zgui.sameLine(.{ .spacing = 12 });
                zgui.textColored(t.accent, "{s} {s}", .{ tech.id, tech.name });
            }

            if (a.assignee.len > 0) {
                zgui.sameLine(.{ .spacing = 12 });
                zgui.textColored(t.text.lo, "assignee: {s}", .{a.assignee.slice()});
            }

            // Linked events — each clicks through to EVT.
            for (a.event_ids[0..a.event_count]) |eid| {
                const e = s.eventById(eid) orelse continue;
                var eb: [200]u8 = undefined;
                const el = std.fmt.bufPrintZ(&eb, "{s}  {s}##alqev{d}", .{ e.process.slice(), e.cmdline.slice(), eid }) catch continue;
                zgui.pushStyleColor4f(.{ .idx = .text, .c = t.text.mid });
                if (zgui.selectable(el, .{})) {
                    d.evt_sel = eid;
                    d.focusPanel(dash.PANEL_EVT);
                }
                zgui.popStyleColor(.{ .count = 1 });
            }

            // Lifecycle actions match the alert's state: open alerts close
            // (ack/FP/resolve/suppress), closed alerts reopen.
            if (a.status.isOpen()) {
                if (a.status == .new) {
                    if (zgui.smallButton("Ack (A)")) ackAlert(d, sid);
                    zgui.sameLine(.{ .spacing = 6 });
                }
                if (zgui.smallButton("False+ (F)")) markFp(d, sid);
                zgui.sameLine(.{ .spacing = 6 });
                if (zgui.smallButton("Resolve")) {
                    _ = s.setAlertStatus(sid, .resolved, dash.unixNowMs());
                    ui.events.post(.ok, "alerts", "alert #{d} resolved", .{sid});
                }
                zgui.sameLine(.{ .spacing = 6 });
                if (zgui.smallButton("Suppress")) {
                    _ = s.setAlertStatus(sid, .suppressed, dash.unixNowMs());
                    ui.events.post(.info, "alerts", "alert #{d} suppressed", .{sid});
                }
            } else {
                if (zgui.smallButton("Reopen")) {
                    _ = s.setAlertStatus(sid, .new, dash.unixNowMs());
                    ui.events.post(.info, "alerts", "alert #{d} reopened", .{sid});
                }
            }
            zgui.sameLine(.{ .spacing = 12 });
            // Case assignment combo.
            var preview_buf: [48]u8 = undefined;
            const preview = if (d.alq_assign_case) |cid| blk: {
                const c = s.caseById(cid) orelse break :blk @as([:0]const u8, "pick case\u{2026}");
                break :blk std.fmt.bufPrintZ(&preview_buf, "#{d} {s}", .{ c.id, c.title.slice() }) catch "case";
            } else "pick case\u{2026}";
            zgui.setNextItemWidth(230);
            if (zgui.beginCombo("##alq_case", .{ .preview_value = preview })) {
                for (s.cases.items) |*c| {
                    if (c.status == .closed) continue;
                    var ib: [80]u8 = undefined;
                    const il = std.fmt.bufPrintZ(&ib, "#{d} {s}##case{d}", .{ c.id, c.title.slice(), c.id }) catch continue;
                    if (zgui.selectable(il, .{ .selected = d.alq_assign_case == c.id })) {
                        d.alq_assign_case = c.id;
                    }
                }
                zgui.endCombo();
            }
            zgui.sameLine(.{ .spacing = 6 });
            if (zgui.smallButton("Assign (C)")) assignToCase(d, sid);
        }
    }
}

fn ackAlert(d: *Dashboard, id: u32) void {
    if (d.store.setAlertStatus(id, .acked, dash.unixNowMs())) {
        ui.events.post(.ok, "alerts", "alert #{d} acked", .{id});
    }
}

fn markFp(d: *Dashboard, id: u32) void {
    if (d.store.setAlertStatus(id, .false_positive, dash.unixNowMs())) {
        // Tuning feedback: count it on the rule (through the Store so it
        // persists to PG and lands in the audit trail).
        if (d.store.alertById(id)) |a| _ = d.store.bumpRuleFp(a.rule);
        ui.events.post(.info, "alerts", "alert #{d} marked false-positive", .{id});
    }
}

fn assignToCase(d: *Dashboard, id: u32) void {
    const cid = d.alq_assign_case orelse {
        ui.events.post(.warn, "alerts", "pick a case first (detail pane combo)", .{});
        return;
    };
    if (d.store.assignAlertToCase(id, cid, dash.unixNowMs())) {
        ui.events.post(.ok, "alerts", "alert #{d} \u{2192} case #{d}", .{ id, cid });
    }
}
