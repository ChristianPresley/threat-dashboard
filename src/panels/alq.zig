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
    const t = ui.theme.default;
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
    _ = zgui.inputTextWithHint("##alq_filter", .{ .hint = "filter title/entity (Ctrl+F)", .buf = &d.alq_filter_buf });

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
    const detail_h: f32 = if (d.alq_sel != null) 110 else 0;
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
                zgui.textColored(t.text.lo, "{s}", .{ui.fmt.clock(&cb, @divFloor(a.ts_ms, 1000))});

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
                    zgui.textUnformattedColored(t.text.mid, s.rules.items[a.rule].code.slice());
                }
                _ = zgui.tableNextColumn();
                if (a.case_id) |cid| {
                    zgui.textColored(t.accent, "#{d}", .{cid});
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

            // First linked event's command line — investigation context.
            if (a.event_count > 0) {
                if (s.eventById(a.event_ids[0])) |e| {
                    dash.textWrappedColored(t.text.mid, "{s}  {s}", .{ e.process.slice(), e.cmdline.slice() });
                }
            }

            if (zgui.smallButton("Ack (A)")) ackAlert(d, sid);
            zgui.sameLine(.{ .spacing = 6 });
            if (zgui.smallButton("False+ (F)")) markFp(d, sid);
            zgui.sameLine(.{ .spacing = 6 });
            if (zgui.smallButton("Resolve")) {
                _ = s.setAlertStatus(sid, .resolved);
                ui.events.post(.ok, "alerts", "alert #{d} resolved", .{sid});
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
    if (d.store.setAlertStatus(id, .acked)) {
        ui.events.post(.ok, "alerts", "alert #{d} acked", .{id});
    }
}

fn markFp(d: *Dashboard, id: u32) void {
    if (d.store.setAlertStatus(id, .false_positive)) {
        // Tuning feedback: count it on the rule.
        if (d.store.alertById(id)) |a| {
            if (a.rule < d.store.rules.items.len) d.store.rules.items[a.rule].fp_7d += 1;
        }
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
