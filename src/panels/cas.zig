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

/// Seed the meta editor's buffers from a case and enter edit mode.
fn startMetaEdit(d: *Dashboard, c: *const domain.Case) void {
    @memset(&d.cas_title_buf, 0);
    const tn = @min(c.title.len, d.cas_title_buf.len - 1);
    @memcpy(d.cas_title_buf[0..tn], c.title.slice()[0..tn]);
    @memset(&d.cas_assignee_buf, 0);
    const an = @min(c.assignee.len, d.cas_assignee_buf.len - 1);
    @memcpy(d.cas_assignee_buf[0..an], c.assignee.slice()[0..an]);
    d.cas_meta_sev = c.severity;
    d.cas_meta_edit = c.id;
}

fn caseStatusColor(st: domain.CaseStatus) [4]f32 {
    const t = ui.theme.active.sev;
    return switch (st) {
        .open => t.info,
        .active => t.warn,
        .contained => t.serious,
        .eradicated => t.ok,
        .closed => ui.theme.active.text.lo,
    };
}

pub fn render(d: *Dashboard) void {
    const t = ui.theme.active;
    const s = &d.store;

    // ── Header: counts + case creation ───────────────────────────────────
    zgui.textColored(t.text.lo, "{d} cases \u{00B7} {d} open", .{ s.cases.items.len, s.openCaseCount() });
    zgui.sameLine(.{ .spacing = 12 });
    if (zgui.smallButton("+ new case##cas")) {
        const now = dash.unixNowMs();
        if (s.addCase(.{
            .id = 0,
            .title = domain.FixedStr(96).from("Untitled case"),
            .severity = .medium,
            .status = .open,
            .assignee = domain.FixedStr(24).from("cpresley"),
            .opened_ms = now,
            .updated_ms = now,
        })) |cid| {
            d.cas_sel = cid;
            // Drop straight into the meta editor so it gets a real title.
            startMetaEdit(d, s.caseById(cid).?);
            ui.events.post(.ok, "cases", "case #{d} opened", .{cid});
        }
    }

    // ── Keyboard: ↑↓ row selection, Enter toggles detail, Esc disarms ───
    {
        const n = s.cases.items.len;
        var sel_pos: ?usize = null;
        if (d.cas_sel) |sid| {
            for (s.cases.items, 0..) |*c, p| {
                if (c.id == sid) {
                    sel_pos = p;
                    break;
                }
            }
        }
        const win_focused = zgui.isWindowFocused(.{ .root_window = true, .child_windows = true });
        if (win_focused and !zgui.io.getWantTextInput() and n > 0) {
            if (zgui.isKeyPressed(.down_arrow, true)) {
                const p = if (sel_pos) |p| @min(p + 1, n - 1) else 0;
                d.cas_sel = s.cases.items[p].id;
            }
            if (zgui.isKeyPressed(.up_arrow, true)) {
                const p = if (sel_pos) |p| p -| 1 else 0;
                d.cas_sel = s.cases.items[p].id;
            }
            if (zgui.isKeyPressed(.enter, false)) {
                d.cas_sel = if (d.cas_sel != null) null else s.cases.items[0].id;
            }
            // Esc disarms a pending status confirm (never confirms).
            if (zgui.isKeyPressed(.escape, false) and pending_status != null) {
                pending_status = null;
                status_dwell.reset();
            }
        }
    }

    const avail = zgui.getContentRegionAvail();
    const detail_h: f32 = if (d.cas_sel != null) @max(150, avail[1] * 0.42) else 0;
    const table_h = @max(80, avail[1] - detail_h);

    // Width-planned columns: Title is the payload; in narrow docks drop
    // Assignee, then Updated, then Status rather than crushing the Title.
    const cols = [_]ui.table.Col{
        .{ .name = "#", .w = 30 },
        .{ .name = "Sev", .w = 46 },
        .{ .name = "Status", .w = 88, .prio = 1 },
        .{ .name = "Title" },
        .{ .name = "Assignee", .w = 84, .prio = 3 },
        .{ .name = "Updated", .w = 70, .prio = 2 },
    };
    const pl = ui.table.plan(&cols, avail[0], 150);
    const flags = zgui.TableFlags{ .resizable = true, .no_saved_settings = true, .borders = .{ .inner_h = true }, .scroll_y = true };
    if (zgui.beginTable("##cas_table", .{ .column = pl.count, .flags = flags, .outer_size = .{ avail[0], table_h } })) {
        ui.table.setup(&cols, &pl);
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
            if (pl.on(2)) {
                _ = zgui.tableNextColumn();
                zgui.textColored(caseStatusColor(c.status), "{s}", .{c.status.label()});
            }
            _ = zgui.tableNextColumn();
            zgui.textUnformattedColored(if (dim) t.text.lo else t.text.hi, c.title.slice());
            if (pl.on(4)) {
                _ = zgui.tableNextColumn();
                zgui.textUnformattedColored(t.text.mid, if (c.assignee.len > 0) c.assignee.slice() else "\u{2014}");
            }
            if (pl.on(5)) {
                _ = zgui.tableNextColumn();
                var ab: [16]u8 = undefined;
                const age_s = @divFloor(dash.unixNowMs() - c.updated_ms, 1000);
                zgui.textColored(t.text.lo, "{s}", .{ui.fmt.age(&ab, age_s)});
            }
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
    if (d.cas_meta_edit != null and d.cas_meta_edit.? == c.id) {
        // ── Meta editor: title / severity / assignee ─────────────────────
        zgui.setNextItemWidth(280);
        _ = zgui.inputTextWithHint("##cas_title", .{ .hint = "case title", .buf = &d.cas_title_buf });
        zgui.sameLine(.{ .spacing = 8 });
        zgui.setNextItemWidth(90);
        if (zgui.beginCombo("##cas_sev", .{ .preview_value = d.cas_meta_sev.label() })) {
            const sevs = [_]domain.Severity{ .info, .low, .medium, .high, .critical };
            inline for (sevs, 0..) |sv, svi| {
                var ib: [24]u8 = undefined;
                const il = std.fmt.bufPrintZ(&ib, "{s}##cassev{d}", .{ sv.label(), svi }) catch "sev";
                if (zgui.selectable(il, .{ .selected = d.cas_meta_sev == sv })) d.cas_meta_sev = sv;
            }
            zgui.endCombo();
        }
        zgui.sameLine(.{ .spacing = 8 });
        zgui.setNextItemWidth(110);
        _ = zgui.inputTextWithHint("##cas_assignee", .{ .hint = "assignee", .buf = &d.cas_assignee_buf });
        zgui.sameLine(.{ .spacing = 8 });
        if (zgui.smallButton("Save##casmeta")) {
            const title = std.mem.sliceTo(&d.cas_title_buf, 0);
            _ = s.updateCaseMeta(c.id, if (title.len > 0) title else "Untitled case", d.cas_meta_sev, std.mem.sliceTo(&d.cas_assignee_buf, 0), dash.unixNowMs());
            ui.events.post(.ok, "cases", "case #{d} updated", .{c.id});
            d.cas_meta_edit = null;
        }
        zgui.sameLine(.{ .spacing = 6 });
        if (zgui.smallButton("Cancel##casmeta")) d.cas_meta_edit = null;
    } else {
        zgui.pushFont(ui.fonts.mono_medium, ui.fonts.size.title);
        zgui.textUnformatted(c.title.slice());
        zgui.popFont();
        zgui.sameLine(.{ .spacing = 10 });
        zgui.textColored(caseStatusColor(c.status), "{s}", .{c.status.label()});
        zgui.sameLine(.{ .spacing = 10 });
        zgui.textColored(t.text.mid, "assignee: {s}", .{if (c.assignee.len > 0) c.assignee.slice() else "\u{2014}"});
        zgui.sameLine(.{ .spacing = 10 });
        var ob: [16]u8 = undefined;
        zgui.textColored(t.text.lo, "opened {s} ago", .{ui.fmt.age(&ob, @divFloor(dash.unixNowMs() - c.opened_ms, 1000))});
        zgui.sameLine(.{ .spacing = 10 });
        if (zgui.smallButton("Edit##casmeta")) startMetaEdit(d, c);
    }

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

    // Linked alerts: click opens in ALQ; ✕ unlinks (through the Store so
    // the detach persists and audits).
    zgui.spacing();
    zgui.textColored(t.text.mid, "linked alerts ({d}):", .{c.alert_count});
    var unlink: ?u32 = null;
    for (c.alert_ids[0..c.alert_count]) |aid| {
        const a = s.alertById(aid) orelse continue;
        var xb: [24]u8 = undefined;
        const xl = std.fmt.bufPrintZ(&xb, "{s}##casunl{d}", .{ ui.fonts.fa.xmark, aid }) catch "x";
        if (zgui.smallButton(xl)) unlink = aid;
        if (zgui.isItemHovered(.{})) {
            if (zgui.beginTooltip()) {
                zgui.textColored(t.text.mid, "remove alert #{d} from this case", .{aid});
                zgui.endTooltip();
            }
        }
        zgui.sameLine(.{ .spacing = 8 });
        zgui.textColored(dash.sevColor(a.severity), "{s}", .{a.severity.label()});
        zgui.sameLine(.{ .spacing = 8 });
        var lb: [140]u8 = undefined;
        const ll = std.fmt.bufPrintZ(&lb, "{s} \u{00B7} {s}##casal{d}", .{ a.title.slice(), a.entity.slice(), aid }) catch continue;
        if (zgui.selectable(ll, .{})) {
            d.alq_sel = aid;
            d.focusPanel(dash.PANEL_ALQ);
        }
    }
    if (unlink) |aid| {
        if (s.unassignAlertFromCase(aid, dash.unixNowMs())) {
            ui.events.post(.info, "cases", "alert #{d} removed from case #{d}", .{ aid, c.id });
        }
    }

    // Notes: read view + in-place editing (persisted through the Store
    // write hook, so a PG backend stays in sync).
    zgui.spacing();
    zgui.textColored(t.text.mid, "notes:", .{});
    if (d.cas_notes_edit != null and d.cas_notes_edit.? == c.id) {
        const w = zgui.getContentRegionAvail()[0];
        _ = zgui.inputTextMultiline("##cas_notes_edit", .{ .buf = &d.cas_notes_buf, .w = w, .h = 74 });
        if (zgui.smallButton("Save##casnotes")) {
            _ = s.setCaseNotes(c.id, std.mem.sliceTo(&d.cas_notes_buf, 0), dash.unixNowMs());
            ui.events.post(.ok, "cases", "case #{d} notes updated", .{c.id});
            d.cas_notes_edit = null;
        }
        zgui.sameLine(.{ .spacing = 6 });
        if (zgui.smallButton("Cancel##casnotes")) d.cas_notes_edit = null;
    } else {
        dash.textWrappedColored(t.text.hi, "{s}", .{c.notes.slice()});
        if (zgui.smallButton("Edit notes##casnotes")) {
            @memset(&d.cas_notes_buf, 0);
            const n = @min(c.notes.len, d.cas_notes_buf.len - 1);
            @memcpy(d.cas_notes_buf[0..n], c.notes.slice()[0..n]);
            d.cas_notes_edit = c.id;
        }
    }
}
