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
    const t = ui.theme.default;
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
    _ = zgui.inputTextWithHint("##ioc_filter", .{ .hint = "filter value (Ctrl+F)", .buf = &d.ioc_filter_buf });

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
    zgui.textColored(t.text.lo, "{d} / {d} \u{00B7} click value to copy", .{ m, s.iocs.items.len });

    const flags = zgui.TableFlags{ .resizable = true, .borders = .{ .inner_h = true }, .scroll_y = true };
    if (zgui.beginTable("##ioc_table", .{ .column = 6, .flags = flags })) {
        zgui.tableSetupColumn("Type", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 62 });
        zgui.tableSetupColumn("Value", .{ .flags = .{ .width_stretch = true } });
        zgui.tableSetupColumn("Conf", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 44 });
        zgui.tableSetupColumn("Feed", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 140 });
        zgui.tableSetupColumn("Last seen", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 76 });
        zgui.tableSetupColumn("Hits", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 44 });
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

                _ = zgui.tableNextColumn();
                zgui.textColored(t.text.mid, "{s}", .{ic.type.label()});
                _ = zgui.tableNextColumn();
                var vl: [140]u8 = undefined;
                const vlbl = std.fmt.bufPrintZ(&vl, "{s}##iocv{d}", .{ ic.value.slice(), ic.id }) catch continue;
                if (zgui.selectable(vlbl, .{})) {
                    var copy_buf: [136:0]u8 = undefined;
                    const cz = std.fmt.bufPrintZ(&copy_buf, "{s}", .{ic.value.slice()}) catch "";
                    zgui.setClipboardText(cz);
                    ui.events.post(.ok, "intel", "IOC value copied to clipboard", .{});
                }
                _ = zgui.tableNextColumn();
                const conf_col = if (ic.confidence >= 80) t.sev.ok else if (ic.confidence >= 50) t.sev.warn else t.text.lo;
                zgui.textColored(conf_col, "{d}", .{ic.confidence});
                _ = zgui.tableNextColumn();
                if (ic.feed < s.feeds.items.len) {
                    zgui.textUnformattedColored(t.text.mid, s.feeds.items[ic.feed].name.slice());
                }
                _ = zgui.tableNextColumn();
                var ab: [16]u8 = undefined;
                const age_s = @divFloor(dash.unixNowMs() - ic.last_seen_ms, 1000);
                zgui.textColored(t.text.lo, "{s}", .{ui.fmt.age(&ab, age_s)});
                _ = zgui.tableNextColumn();
                zgui.textColored(if (ic.hits > 0) t.sev.crit else t.text.lo, "{d}", .{ic.hits});
            }
        }
        zgui.endTable();
    }
}
