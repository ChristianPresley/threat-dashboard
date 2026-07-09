//! EVT · Event Search: filter bar (kind chips + substring) over the full
//! telemetry table via ListClipper; Enter/click opens a detail row.
//! Honors the TLN brush range when set.

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const domain = @import("domain");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

const MAX_ROWS = 8192;

pub fn render(d: *Dashboard) void {
    const t = ui.theme.active;
    const s = &d.store;

    // ── Filter bar ───────────────────────────────────────────────────────
    zgui.textColored(t.text.lo, "kind:", .{});
    const kind_names = [_][:0]const u8{ "proc", "net", "auth", "file", "dns", "reg", "script" };
    inline for (kind_names, 0..) |nm, i| {
        zgui.sameLine(.{ .spacing = 4 });
        if (dash.filterChip(nm ++ "##evtk", d.evt_kind_show[i], t.accent)) {
            d.evt_kind_show[i] = !d.evt_kind_show[i];
        }
    }
    zgui.sameLine(.{ .spacing = 14 });
    if (d.evt_focus_filter and zgui.isWindowFocused(.{ .root_window = true, .child_windows = true })) {
        d.evt_focus_filter = false;
        zgui.setKeyboardFocusHere(0);
    }
    zgui.setNextItemWidth(220);
    _ = zgui.inputTextWithHint("##evt_filter", .{ .hint = "filter (Ctrl+F)", .buf = &d.evt_filter_buf });
    if (d.evt_range != null) {
        zgui.sameLine(.{ .spacing = 10 });
        zgui.textColored(t.amber, "TLN range", .{});
        zgui.sameLine(.{ .spacing = 4 });
        if (zgui.smallButton("\u{00D7}##evtrange")) d.evt_range = null;
    }

    // ── Row collection (newest first) ────────────────────────────────────
    const filter = std.mem.sliceTo(&d.evt_filter_buf, 0);
    var rows: [MAX_ROWS]u32 = undefined;
    var m: usize = 0;
    {
        var i: usize = s.events.items.len;
        while (i > 0 and m < rows.len) {
            i -= 1;
            const e = &s.events.items[i];
            if (!d.evt_kind_show[@intFromEnum(e.kind)]) continue;
            if (d.evt_range) |r| {
                if (e.ts_ms < r[0] or e.ts_ms > r[1]) continue;
            }
            if (filter.len > 0) {
                const hit = std.ascii.indexOfIgnoreCase(e.process.slice(), filter) != null or
                    std.ascii.indexOfIgnoreCase(e.cmdline.slice(), filter) != null or
                    std.ascii.indexOfIgnoreCase(s.hostName(e.host), filter) != null or
                    std.ascii.indexOfIgnoreCase(s.userName(e.user), filter) != null;
                if (!hit) continue;
            }
            rows[m] = @intCast(i);
            m += 1;
        }
    }
    zgui.sameLine(.{ .spacing = 14 });
    zgui.textColored(t.text.lo, "{d} / {d}", .{ m, s.events.items.len });

    if (m == 0) {
        zgui.spacing();
        zgui.textColored(t.text.lo, "No events match.", .{});
        return;
    }

    // ── Keyboard: ↑↓ row selection, Enter opens the detail row ──────────
    {
        var sel_pos: ?usize = null;
        if (d.evt_sel) |eid| {
            for (rows[0..m], 0..) |ri, p| {
                if (s.events.items[ri].id == eid) {
                    sel_pos = p;
                    break;
                }
            }
        }
        const win_focused = zgui.isWindowFocused(.{ .root_window = true, .child_windows = true });
        if (win_focused and !zgui.io.getWantTextInput()) {
            if (zgui.isKeyPressed(.down_arrow, true)) {
                const p = if (sel_pos) |p| @min(p + 1, m - 1) else 0;
                d.evt_sel = s.events.items[rows[p]].id;
            }
            if (zgui.isKeyPressed(.up_arrow, true)) {
                const p = if (sel_pos) |p| p -| 1 else 0;
                d.evt_sel = s.events.items[rows[p]].id;
            }
            if (zgui.isKeyPressed(.enter, false) and d.evt_sel == null) {
                d.evt_sel = s.events.items[rows[0]].id;
            }
        }
    }

    const avail = zgui.getContentRegionAvail();
    const detail_h: f32 = if (d.evt_sel != null) 96 else 0;
    const table_h = @max(80, avail[1] - detail_h);

    const flags = zgui.TableFlags{ .resizable = true, .borders = .{ .inner_h = true }, .scroll_y = true };
    if (zgui.beginTable("##evt_table", .{ .column = 6, .flags = flags, .outer_size = .{ avail[0], table_h } })) {
        zgui.tableSetupColumn("Time", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 72 });
        zgui.tableSetupColumn("Kind", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 52 });
        zgui.tableSetupColumn("Host", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 100 });
        zgui.tableSetupColumn("User", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 86 });
        zgui.tableSetupColumn("Process", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 120 });
        zgui.tableSetupColumn("Detail", .{ .flags = .{ .width_stretch = true } });
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
                const e = &s.events.items[rows[ri]];
                zgui.tableNextRow(.{});
                const selected = d.evt_sel != null and d.evt_sel.? == e.id;
                if (selected) {
                    zgui.tableSetBgColor(.{ .target = .row_bg0, .color = zgui.colorConvertFloat4ToU32(t.bg.selected) });
                } else if (e.technique != null) {
                    zgui.tableSetBgColor(.{ .target = .row_bg0, .color = zgui.colorConvertFloat4ToU32(dash.sevDimColor(e.severity)) });
                }

                _ = zgui.tableNextColumn();
                var slbl: [24]u8 = undefined;
                const sl = std.fmt.bufPrintZ(&slbl, "##evtrow{d}", .{e.id}) catch "##e";
                const cur = zgui.getCursorPosX();
                if (zgui.selectable(sl, .{ .selected = selected, .flags = .{ .span_all_columns = true, .allow_overlap = true } })) {
                    d.evt_sel = e.id;
                }
                zgui.sameLine(.{});
                zgui.setCursorPosX(cur);
                var cb: [16]u8 = undefined;
                zgui.textColored(t.text.lo, "{s}", .{ui.fmt.ts(&cb, @divFloor(e.ts_ms, 1000))});

                _ = zgui.tableNextColumn();
                zgui.textColored(if (e.technique != null) dash.sevColor(e.severity) else t.text.mid, "{s}", .{e.kind.label()});
                _ = zgui.tableNextColumn();
                zgui.textUnformattedColored(t.text.hi, s.hostName(e.host));
                _ = zgui.tableNextColumn();
                zgui.textUnformattedColored(t.text.mid, s.userName(e.user));
                _ = zgui.tableNextColumn();
                zgui.textUnformattedColored(t.text.hi, e.process.slice());
                _ = zgui.tableNextColumn();
                zgui.textUnformattedColored(t.text.mid, e.cmdline.slice());
            }
        }
        zgui.endTable();
    }

    // ── Detail ───────────────────────────────────────────────────────────
    if (d.evt_sel) |eid| {
        if (s.eventById(eid)) |e| {
            zgui.separator();
            zgui.textColored(t.text.mid, "#{d} \u{00B7} {s} \u{00B7} {s} \u{00B7} {s}", .{
                e.id, e.kind.label(), s.hostName(e.host), s.userName(e.user),
            });
            if (e.sensor < s.sensors.items.len) {
                const sn = &s.sensors.items[e.sensor];
                zgui.sameLine(.{ .spacing = 10 });
                zgui.textColored(t.text.lo, "via {s} ({s})", .{ sn.host.slice(), sn.kind.label() });
            }
            if (e.technique) |tid| {
                const tech = domain.attack.get(tid);
                zgui.sameLine(.{ .spacing = 10 });
                zgui.textColored(dash.sevColor(e.severity), "{s} {s}", .{ tech.id, tech.name });
            }
            if (e.dst_ip.len > 0) {
                zgui.sameLine(.{ .spacing = 10 });
                zgui.textColored(t.text.mid, "\u{2192} {s}:{d}", .{ e.dst_ip.slice(), e.dst_port });
            }
            dash.textWrappedColored(t.text.hi, "{s}", .{e.cmdline.slice()});
            if (e.parent != null) {
                if (zgui.smallButton("open in PRC##evt")) {
                    // Walk to the chain root for the process tree.
                    var root = e.id;
                    var cur_e = e;
                    while (cur_e.parent) |p| {
                        cur_e = s.eventById(p) orelse break;
                        root = cur_e.id;
                    }
                    d.prc_sel_root = root;
                    d.focusPanel(dash.PANEL_PRC);
                }
            }
        }
    }
}
