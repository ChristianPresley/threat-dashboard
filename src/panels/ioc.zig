//! IOC · IOC List: indicators by type/feed/confidence with hit counts,
//! type filter chips, substring filter, click-to-copy value.

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const domain = @import("domain");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

const MAX_ROWS = 2048;

pub fn render(d: *Dashboard) void {
    const t = ui.theme.active;
    const s = &d.store;

    zgui.textColored(t.text.lo, "type:", .{});
    const type_names = [_][:0]const u8{ "ip", "domain", "sha256", "url", "email" };
    inline for (type_names, 0..) |nm, i| {
        zgui.sameLine(.{ .spacing = 4 });
        if (dash.filterChip(nm ++ "##ioct", d.ioc_type_show[i], t.accent)) {
            d.ioc_type_show[i] = !d.ioc_type_show[i];
        }
    }
    zgui.sameLine(.{ .spacing = 14 });
    if (d.ioc_focus_filter and zgui.isWindowFocused(.{ .root_window = true, .child_windows = true })) {
        d.ioc_focus_filter = false;
        zgui.setKeyboardFocusHere(0);
    }
    zgui.setNextItemWidth(200);
    _ = zgui.inputTextWithHint("##ioc_filter", .{ .hint = "filter (Ctrl+F)", .buf = &d.ioc_filter_buf });

    const filter = std.mem.sliceTo(&d.ioc_filter_buf, 0);
    var rows: [MAX_ROWS]u32 = undefined;
    var m: usize = 0;
    for (s.iocs.items, 0..) |*ic, i| {
        if (m >= rows.len) break;
        if (!d.ioc_type_show[@intFromEnum(ic.type)]) continue;
        if (filter.len > 0 and std.ascii.indexOfIgnoreCase(ic.value.slice(), filter) == null) continue;
        rows[m] = @intCast(i);
        m += 1;
    }
    zgui.sameLine(.{ .spacing = 14 });
    if (zgui.smallButton("Enrich shown##ioc")) {
        var ids: [25]u32 = undefined;
        var n: usize = 0;
        for (0..m) |ri| {
            if (n >= ids.len) break;
            ids[n] = s.iocs.items[rows[ri]].id;
            n += 1;
        }
        // The batch caps at 25 — say so instead of silently truncating.
        if (m > ids.len) {
            ui.events.post(.info, "enrich", "enriching the first {d} of {d} shown \u{2014} narrow the filter for the rest", .{ ids.len, m });
        }
        d.requestEnrichment(ids[0..n]);
    }
    zgui.sameLine(.{ .spacing = 10 });
    zgui.textColored(t.text.lo, "{d} / {d} \u{00B7} click value to copy \u{00B7} select row \u{2192} ENR", .{ m, s.iocs.items.len });

    // Width plan: Feed drops first (fattest, least triage-relevant), then
    // Last seen, then Conf — Value (the indicator itself) keeps width.
    const cols = [_]ui.table.Col{
        .{ .name = "Type", .w = 62 },
        .{ .name = "Value" },
        .{ .name = "Conf", .w = 44, .prio = 1 },
        .{ .name = "Verdict", .w = 90 },
        .{ .name = "Feed", .w = 165, .prio = 3 },
        .{ .name = "Last seen", .w = 76, .prio = 2 },
        .{ .name = "Hits", .w = 44 },
    };
    const pl = ui.table.plan(&cols, zgui.getContentRegionAvail()[0], 200);
    const flags = zgui.TableFlags{ .resizable = true, .no_saved_settings = true, .borders = .{ .inner_h = true }, .scroll_y = true };
    if (zgui.beginTable("##ioc_table", .{ .column = pl.count, .flags = flags })) {
        ui.table.setup(&cols, &pl);
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
                const ic = &s.iocs.items[rows[ri]];
                zgui.tableNextRow(.{});
                const selected = d.enr_sel != null and d.enr_sel.? == ic.id;
                if (selected) {
                    zgui.tableSetBgColor(.{ .target = .row_bg0, .color = zgui.colorConvertFloat4ToU32(t.bg.selected) });
                }

                // Type cell: select-row → ENR (double-click focuses it).
                _ = zgui.tableNextColumn();
                var tl: [24]u8 = undefined;
                const tlbl = std.fmt.bufPrintZ(&tl, "{s}##ioct{d}", .{ ic.type.label(), ic.id }) catch continue;
                if (zgui.selectable(tlbl, .{ .selected = selected })) {
                    if (d.enr_sel) |cur| {
                        if (cur != ic.id and d.enr_history_len < d.enr_history.len) {
                            d.enr_history[d.enr_history_len] = cur;
                            d.enr_history_len += 1;
                        }
                    }
                    d.enr_sel = ic.id;
                    if (zgui.isMouseDoubleClicked(.left)) d.focusPanel(dash.PANEL_ENR);
                }
                _ = zgui.tableNextColumn();
                var vl: [140]u8 = undefined;
                const vlbl = std.fmt.bufPrintZ(&vl, "{s}##iocv{d}", .{ ic.value.slice(), ic.id }) catch continue;
                if (zgui.selectable(vlbl, .{})) {
                    var copy_buf: [200:0]u8 = undefined;
                    if (ui.prefs.current.defang_copy) {
                        var df: [180]u8 = undefined;
                        const safe = domain.defang(&df, ic.type, ic.value.slice());
                        const cz = std.fmt.bufPrintZ(&copy_buf, "{s}", .{safe}) catch "";
                        zgui.setClipboardText(cz);
                        ui.events.post(.ok, "intel", "IOC copied DEFANGED (raw copy: SET \u{2192} Time & tables)", .{});
                    } else {
                        const cz = std.fmt.bufPrintZ(&copy_buf, "{s}", .{ic.value.slice()}) catch "";
                        zgui.setClipboardText(cz);
                        ui.events.post(.ok, "intel", "raw IOC value copied to clipboard", .{});
                    }
                }
                if (pl.on(2)) {
                    _ = zgui.tableNextColumn();
                    const conf_col = if (ic.confidence >= 80) t.sev.ok else if (ic.confidence >= 50) t.sev.warn else t.text.lo;
                    zgui.textColored(conf_col, "{d}", .{ic.confidence});
                }
                _ = zgui.tableNextColumn();
                if (s.enrichmentForIoc(ic.id)) |en| {
                    switch (en.status) {
                        .done => zgui.textColored(dash.verdictColor(en.verdict), "{s}", .{en.verdict.label()}),
                        .pending => zgui.textColored(t.sev.warn, "\u{2026}", .{}),
                        .err => zgui.textColored(t.sev.crit, "err", .{}),
                        .none => zgui.textColored(t.text.lo, "\u{00B7}", .{}),
                    }
                } else {
                    zgui.textColored(t.text.lo, "\u{00B7}", .{});
                }
                if (pl.on(4)) {
                    _ = zgui.tableNextColumn();
                    if (ic.feed < s.feeds.items.len) {
                        zgui.textUnformattedColored(t.text.mid, s.feeds.items[ic.feed].name.slice());
                    }
                }
                if (pl.on(5)) {
                    _ = zgui.tableNextColumn();
                    var ab: [16]u8 = undefined;
                    const age_s = @divFloor(dash.unixNowMs() - ic.last_seen_ms, 1000);
                    zgui.textColored(t.text.lo, "{s}", .{ui.fmt.age(&ab, age_s)});
                    if (zgui.isItemHovered(.{})) {
                        if (zgui.beginTooltip()) {
                            var fb: [20]u8 = undefined;
                            var lb2: [20]u8 = undefined;
                            zgui.textColored(t.text.mid, "first seen {s} \u{00B7} last seen {s}", .{
                                ui.fmt.tsDate(&fb, @divFloor(ic.first_seen_ms, 1000)),
                                ui.fmt.tsDate(&lb2, @divFloor(ic.last_seen_ms, 1000)),
                            });
                            zgui.endTooltip();
                        }
                    }
                }
                _ = zgui.tableNextColumn();
                zgui.textColored(if (ic.hits > 0) t.sev.crit else t.text.lo, "{d}", .{ic.hits});
            }
        }
        zgui.endTable();
    }
}
