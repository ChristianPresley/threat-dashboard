//! CAS · Cases: incident tracking. Case table + detail for the selection
//! (linked alerts, status transitions behind a T1 dwell, notes).

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const domain = @import("domain");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

var status_dwell: ui.confirm.Dwell = .{};
var pending_status: ?domain.CaseStatus = null;

fn caseStatusColor(st: domain.CaseStatus) [4]f32 {
    const t = ui.theme.default.sev;
    return switch (st) {
        .open => t.info,
        .active => t.warn,
        .contained => t.serious,
        .eradicated => t.ok,
        .closed => ui.theme.default.text.lo,
    };
}

pub fn render(d: *Dashboard) void {
    const t = ui.theme.default;
    const s = &d.store;

    const avail = zgui.getContentRegionAvail();
    const detail_h: f32 = if (d.cas_sel != null) @max(150, avail[1] * 0.42) else 0;
    const table_h = @max(80, avail[1] - detail_h);

    const flags = zgui.TableFlags{ .resizable = true, .borders = .{ .inner_h = true }, .scroll_y = true };
    if (zgui.beginTable("##cas_table", .{ .column = 6, .flags = flags, .outer_size = .{ avail[0], table_h } })) {
        zgui.tableSetupColumn("#", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 30 });
        zgui.tableSetupColumn("Sev", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 46 });
        zgui.tableSetupColumn("Status", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 88 });
        zgui.tableSetupColumn("Title", .{ .flags = .{ .width_stretch = true } });
        zgui.tableSetupColumn("Assignee", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 84 });
        zgui.tableSetupColumn("Updated", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 70 });
        zgui.tableSetupScrollFreeze(0, 1);
        zgui.tableHeadersRow();

        for (s.cases.items) |*c| {
            zgui.tableNextRow(.{});
            const selected = d.cas_sel != null and d.cas_sel.? == c.id;
            if (selected) {
                zgui.tableSetBgColor(.{ .target = .row_bg0, .color = zgui.colorConvertFloat4ToU32(t.bg.selected) });
            }
            const dim = c.status == .closed;

            _ = zgui.tableNextColumn();
            var slbl: [20]u8 = undefined;
            const sl = std.fmt.bufPrintZ(&slbl, "##casrow{d}", .{c.id}) catch "##c";
            const cur = zgui.getCursorPosX();
            if (zgui.selectable(sl, .{ .selected = selected, .flags = .{ .span_all_columns = true, .allow_overlap = true } })) {
                d.cas_sel = c.id;
                pending_status = null;
                status_dwell.reset();
            }
            zgui.sameLine(.{});
            zgui.setCursorPosX(cur);
            zgui.textColored(t.text.lo, "{d}", .{c.id});

            _ = zgui.tableNextColumn();
            zgui.textColored(dash.sevColor(c.severity), "{s}", .{c.severity.label()});
            _ = zgui.tableNextColumn();
            zgui.textColored(caseStatusColor(c.status), "{s}", .{c.status.label()});
            _ = zgui.tableNextColumn();
            zgui.textUnformattedColored(if (dim) t.text.lo else t.text.hi, c.title.slice());
            _ = zgui.tableNextColumn();
            zgui.textUnformattedColored(t.text.mid, if (c.assignee.len > 0) c.assignee.slice() else "\u{2014}");
            _ = zgui.tableNextColumn();
            var ab: [16]u8 = undefined;
            const age_s = @divFloor(dash.unixNowMs() - c.updated_ms, 1000);
            zgui.textColored(t.text.lo, "{s}", .{ui.fmt.age(&ab, age_s)});
        }
        zgui.endTable();
    }

    // ── Detail ───────────────────────────────────────────────────────────
    const sel = d.cas_sel orelse return;
    const c = s.caseById(sel) orelse {
        d.cas_sel = null;
        return;
    };

    zgui.separator();
    zgui.pushFont(ui.fonts.mono_medium, ui.fonts.size.title);
    zgui.textUnformatted(c.title.slice());
    zgui.popFont();
    zgui.sameLine(.{ .spacing = 10 });
    zgui.textColored(caseStatusColor(c.status), "{s}", .{c.status.label()});
    zgui.sameLine(.{ .spacing = 10 });
    zgui.textColored(t.text.mid, "assignee: {s}", .{if (c.assignee.len > 0) c.assignee.slice() else "\u{2014}"});

    // Status transition with T1 dwell: pick target, confirm arms, fire.
    {
        const transitions = [_]domain.CaseStatus{ .open, .active, .contained, .eradicated, .closed };
        zgui.textColored(t.text.lo, "set status:", .{});
        inline for (transitions, 0..) |st, sti| {
            zgui.sameLine(.{ .spacing = 4 });
            const on = pending_status != null and pending_status.? == st;
            var chip_buf: [32]u8 = undefined;
            const chip = std.fmt.bufPrintZ(&chip_buf, "{s}##casst{d}", .{ st.label(), sti }) catch "st";
            if (dash.filterChip(chip, on or c.status == st, caseStatusColor(st))) {
                if (c.status != st) {
                    pending_status = st;
                    status_dwell.arm();
                }
            }
        }
        if (pending_status) |st| {
            if (st != c.status) {
                zgui.sameLine(.{ .spacing = 12 });
                const ready = status_dwell.ready(ui.confirm.DWELL_T1_MS);
                if (ready) {
                    var bb: [48]u8 = undefined;
                    const bl = std.fmt.bufPrintZ(&bb, "Confirm \u{2192} {s}##casconf", .{st.label()}) catch "Confirm";
                    if (zgui.smallButton(bl)) {
                        _ = s.setCaseStatus(c.id, st, dash.unixNowMs());
                        ui.events.post(.ok, "cases", "case #{d} \u{2192} {s}", .{ c.id, st.label() });
                        pending_status = null;
                        status_dwell.reset();
                    }
                } else {
                    zgui.textColored(t.text.lo, "confirm in {d:.1}s\u{2026}", .{status_dwell.remainingSecs(ui.confirm.DWELL_T1_MS)});
                }
            }
        }
    }

    // Linked alerts.
    zgui.spacing();
    zgui.textColored(t.text.mid, "linked alerts ({d}):", .{c.alert_count});
    for (c.alert_ids[0..c.alert_count]) |aid| {
        const a = s.alertById(aid) orelse continue;
        zgui.textColored(dash.sevColor(a.severity), "  {s}", .{a.severity.label()});
        zgui.sameLine(.{ .spacing = 8 });
        var lb: [140]u8 = undefined;
        const ll = std.fmt.bufPrintZ(&lb, "{s} \u{00B7} {s}##casal{d}", .{ a.title.slice(), a.entity.slice(), aid }) catch continue;
        if (zgui.selectable(ll, .{})) {
            d.alq_sel = aid;
            d.focusPanel(dash.PANEL_ALQ);
        }
    }

    // Notes (read-only view of the mock notes; live editing is a later phase).
    zgui.spacing();
    zgui.textColored(t.text.mid, "notes:", .{});
    dash.textWrappedColored(t.text.hi, "{s}", .{c.notes.slice()});
}
