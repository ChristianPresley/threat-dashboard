//! RUL · Detection Rules: rules table (status/severity/technique/fires/FP%),
//! enable/disable toggle behind a T1 dwell for enabled→disabled, and a
//! detail pane with the query text. Honors the ATK technique filter.

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const domain = @import("domain");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

var disable_dwell: ui.confirm.Dwell = .{};
var disable_pending: ?u16 = null;

fn ruleStatusColor(st: domain.RuleStatus) [4]f32 {
    const t = ui.theme.default;
    return switch (st) {
        .enabled => t.sev.ok,
        .testing => t.sev.warn,
        .disabled => t.text.lo,
    };
}

pub fn render(d: *Dashboard) void {
    const t = ui.theme.default;
    const s = &d.store;

    // ── Filter bar ───────────────────────────────────────────────────────
    if (d.rul_focus_filter and zgui.isWindowFocused(.{ .root_window = true, .child_windows = true })) {
        d.rul_focus_filter = false;
        zgui.setKeyboardFocusHere(0);
    }
    zgui.setNextItemWidth(200);
    _ = zgui.inputTextWithHint("##rul_filter", .{ .hint = "filter (Ctrl+F)", .buf = &d.rul_filter_buf });
    if (d.rul_technique_filter) |tid| {
        const tech = domain.attack.get(tid);
        zgui.sameLine(.{ .spacing = 10 });
        zgui.textColored(t.amber, "technique {s}", .{tech.id});
        zgui.sameLine(.{ .spacing = 4 });
        if (zgui.smallButton("\u{00D7}##rultech")) d.rul_technique_filter = null;
    }

    const filter = std.mem.sliceTo(&d.rul_filter_buf, 0);

    // ── Visible rows (indices into rules.items) ─────────────────────────
    var rows: [512]u16 = undefined;
    var m: usize = 0;
    for (s.rules.items, 0..) |*r, i| {
        if (m >= rows.len) break;
        if (filter.len > 0 and
            std.ascii.indexOfIgnoreCase(r.name.slice(), filter) == null and
            std.ascii.indexOfIgnoreCase(r.code.slice(), filter) == null) continue;
        if (d.rul_technique_filter) |tid| {
            if (r.technique != tid) continue;
        }
        rows[m] = @intCast(i);
        m += 1;
    }

    // ── Keyboard: ↑↓ row selection, Enter toggles the detail pane ───────
    {
        var sel_pos: ?usize = null;
        if (d.rul_sel) |sid| {
            for (rows[0..m], 0..) |ri, p| {
                if (s.rules.items[ri].id == sid) {
                    sel_pos = p;
                    break;
                }
            }
        }
        const win_focused = zgui.isWindowFocused(.{ .root_window = true, .child_windows = true });
        if (win_focused and !zgui.io.getWantTextInput() and m > 0) {
            if (zgui.isKeyPressed(.down_arrow, true)) {
                const p = if (sel_pos) |p| @min(p + 1, m - 1) else 0;
                d.rul_sel = s.rules.items[rows[p]].id;
            }
            if (zgui.isKeyPressed(.up_arrow, true)) {
                const p = if (sel_pos) |p| p -| 1 else 0;
                d.rul_sel = s.rules.items[rows[p]].id;
            }
            if (zgui.isKeyPressed(.enter, false)) {
                d.rul_sel = if (d.rul_sel != null) null else s.rules.items[rows[0]].id;
            }
            // Esc disarms a pending disable confirm (never confirms).
            if (zgui.isKeyPressed(.escape, false) and disable_pending != null) {
                disable_pending = null;
                disable_dwell.reset();
            }
        }
    }

    const avail = zgui.getContentRegionAvail();
    const detail_h: f32 = if (d.rul_sel != null) 120 else 0;
    const table_h = @max(80, avail[1] - detail_h);

    const flags = zgui.TableFlags{ .resizable = true, .borders = .{ .inner_h = true }, .scroll_y = true, .sortable = false };
    if (zgui.beginTable("##rul_table", .{ .column = 7, .flags = flags, .outer_size = .{ avail[0], table_h } })) {
        zgui.tableSetupColumn("Code", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 62 });
        zgui.tableSetupColumn("Status", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 74 });
        zgui.tableSetupColumn("Sev", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 46 });
        zgui.tableSetupColumn("Name", .{ .flags = .{ .width_stretch = true } });
        zgui.tableSetupColumn("Technique", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 84 });
        zgui.tableSetupColumn("Fires 7d", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 64 });
        zgui.tableSetupColumn("FP%", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 48 });
        zgui.tableSetupScrollFreeze(0, 1);
        zgui.tableHeadersRow();

        for (rows[0..m]) |ri| {
            const r = &s.rules.items[ri];
            zgui.tableNextRow(.{});
            const selected = d.rul_sel != null and d.rul_sel.? == r.id;
            if (selected) {
                zgui.tableSetBgColor(.{ .target = .row_bg0, .color = zgui.colorConvertFloat4ToU32(t.bg.selected) });
            }

            _ = zgui.tableNextColumn();
            var slbl: [20]u8 = undefined;
            const sl = std.fmt.bufPrintZ(&slbl, "##rulrow{d}", .{r.id}) catch "##r";
            const cur = zgui.getCursorPosX();
            if (zgui.selectable(sl, .{ .selected = selected, .flags = .{ .span_all_columns = true, .allow_overlap = true } })) {
                d.rul_sel = r.id;
            }
            zgui.sameLine(.{});
            zgui.setCursorPosX(cur);
            zgui.textUnformattedColored(t.accent, r.code.slice());

            _ = zgui.tableNextColumn();
            zgui.textColored(ruleStatusColor(r.status), "{s}", .{r.status.label()});
            _ = zgui.tableNextColumn();
            zgui.textColored(dash.sevColor(r.severity), "{s}", .{r.severity.label()});
            _ = zgui.tableNextColumn();
            zgui.textUnformattedColored(if (r.status == .disabled) t.text.lo else t.text.hi, r.name.slice());
            _ = zgui.tableNextColumn();
            zgui.textColored(t.text.mid, "{s}", .{domain.attack.get(r.technique).id});
            _ = zgui.tableNextColumn();
            zgui.textColored(t.text.mid, "{d}", .{r.fires_7d});
            _ = zgui.tableNextColumn();
            const fp = r.fpRate() * 100;
            zgui.textColored(if (fp > 50) t.sev.warn else t.text.mid, "{d:.0}", .{fp});
        }
        zgui.endTable();
    }

    // ── Detail ───────────────────────────────────────────────────────────
    const sel = d.rul_sel orelse return;
    const r = s.ruleById(sel) orelse return;

    zgui.separator();
    zgui.textUnformattedColored(t.accent, r.code.slice());
    zgui.sameLine(.{ .spacing = 8 });
    zgui.textUnformatted(r.name.slice());
    zgui.sameLine(.{ .spacing = 10 });
    const tech = domain.attack.get(r.technique);
    zgui.textColored(t.text.mid, "{s} {s} \u{00B7} {s}", .{ tech.id, tech.name, tech.tactic.label() });
    zgui.sameLine(.{ .spacing = 10 });
    zgui.textColored(t.text.lo, "author {s}", .{if (r.author.len > 0) r.author.slice() else "\u{2014}"});

    // Query text in a sunken well.
    zgui.pushStyleColor4f(.{ .idx = .child_bg, .c = t.bg.sunken });
    if (zgui.beginChild("##rul_query", .{ .h = 42 })) {
        dash.textWrappedColored(t.text.hi, "{s}", .{r.query.slice()});
    }
    zgui.endChild();
    zgui.popStyleColor(.{ .count = 1 });

    // Status controls. Disabling an ENABLED rule needs the dwell (coverage
    // gap risk); enabling / testing is instant.
    if (r.status != .enabled) {
        if (zgui.smallButton("Enable##rul")) {
            _ = s.setRuleStatus(r.id, .enabled);
            ui.events.post(.ok, "rules", "{s} enabled", .{r.code.slice()});
        }
        zgui.sameLine(.{ .spacing = 6 });
    }
    if (r.status != .testing) {
        if (zgui.smallButton("Testing##rul")) {
            _ = s.setRuleStatus(r.id, .testing);
            ui.events.post(.info, "rules", "{s} \u{2192} testing", .{r.code.slice()});
        }
        zgui.sameLine(.{ .spacing = 6 });
    }
    if (r.status != .disabled) {
        if (disable_pending != null and disable_pending.? == r.id) {
            if (disable_dwell.ready(ui.confirm.DWELL_T1_MS)) {
                if (zgui.smallButton("Confirm disable##rul")) {
                    _ = s.setRuleStatus(r.id, .disabled);
                    ui.events.post(.warn, "rules", "{s} DISABLED \u{2014} coverage gap for {s}", .{ r.code.slice(), tech.id });
                    disable_pending = null;
                    disable_dwell.reset();
                }
            } else {
                zgui.textColored(t.text.lo, "confirm in {d:.1}s\u{2026}", .{disable_dwell.remainingSecs(ui.confirm.DWELL_T1_MS)});
            }
        } else if (zgui.smallButton("Disable\u{2026}##rul")) {
            disable_pending = r.id;
            disable_dwell.arm();
        }
    }
    zgui.sameLine(.{ .spacing = 14 });
    var lf: [16]u8 = undefined;
    const last_fire: []const u8 = if (r.last_fire_ms > 0)
        ui.fmt.age(&lf, @divFloor(dash.unixNowMs() - r.last_fire_ms, 1000))
    else
        "never";
    zgui.textColored(t.text.mid, "fires 7d: {d} \u{00B7} FP: {d} ({d:.0}%) \u{00B7} last fired {s}{s}", .{
        r.fires_7d, r.fp_7d, r.fpRate() * 100, last_fire, if (r.last_fire_ms > 0) " ago" else "",
    });
}
