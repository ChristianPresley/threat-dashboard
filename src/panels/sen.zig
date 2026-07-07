//! SEN · Sensor Health: RAG grid over the sensor fleet (kind, status,
//! EPS, ingest lag, version), with a detail line for the selection.

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const domain = @import("domain");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

pub fn render(d: *Dashboard) void {
    const t = ui.theme.default;
    const s = &d.store;

    var ok_n: u32 = 0;
    var deg_n: u32 = 0;
    var down_n: u32 = 0;
    for (s.sensors.items) |*sn| {
        switch (sn.status) {
            .ok => ok_n += 1,
            .degraded => deg_n += 1,
            .down => down_n += 1,
        }
    }
    zgui.textColored(t.sev.ok, "{d} ok", .{ok_n});
    zgui.sameLine(.{ .spacing = 10 });
    zgui.textColored(if (deg_n > 0) t.sev.warn else t.text.lo, "{d} degraded", .{deg_n});
    zgui.sameLine(.{ .spacing = 10 });
    zgui.textColored(if (down_n > 0) t.sev.crit else t.text.lo, "{d} down", .{down_n});

    const flags = zgui.TableFlags{ .resizable = true, .borders = .{ .inner_h = true }, .scroll_y = true };
    if (zgui.beginTable("##sen_table", .{ .column = 6, .flags = flags })) {
        zgui.tableSetupColumn("", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 20 });
        zgui.tableSetupColumn("Sensor", .{ .flags = .{ .width_stretch = true } });
        zgui.tableSetupColumn("Kind", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 58 });
        zgui.tableSetupColumn("EPS", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 66 });
        zgui.tableSetupColumn("Lag", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 64 });
        zgui.tableSetupColumn("Version", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 70 });
        zgui.tableSetupScrollFreeze(0, 1);
        zgui.tableHeadersRow();

        for (s.sensors.items) |*sn| {
            zgui.tableNextRow(.{});
            if (sn.status == .down) {
                zgui.tableSetBgColor(.{ .target = .row_bg0, .color = zgui.colorConvertFloat4ToU32(t.sev.crit_dim) });
            } else if (sn.status == .degraded) {
                zgui.tableSetBgColor(.{ .target = .row_bg0, .color = zgui.colorConvertFloat4ToU32(t.sev.warn_dim) });
            }
            _ = zgui.tableNextColumn();
            zgui.textColored(dash.sensorStatusColor(sn.status), "{s}", .{ui.fonts.fa.circle});
            if (zgui.isItemHovered(.{})) {
                if (zgui.beginTooltip()) {
                    zgui.text("{s}", .{sn.status.label()});
                    zgui.endTooltip();
                }
            }
            _ = zgui.tableNextColumn();
            zgui.textUnformattedColored(t.text.hi, sn.host.slice());
            _ = zgui.tableNextColumn();
            zgui.textColored(t.text.mid, "{s}", .{sn.kind.label()});
            _ = zgui.tableNextColumn();
            // EPS flash-on-update: background tint via the flash engine.
            const key = ui.flash.cellKey("sen_eps", sn.id, 0);
            const fl = ui.flash.update(key, @floatCast(sn.eps));
            if (fl.alpha > 0) {
                const c = t.accent_dim;
                zgui.tableSetBgColor(.{ .target = .cell_bg, .color = zgui.colorConvertFloat4ToU32(.{ c[0], c[1], c[2], fl.alpha }) });
            }
            if (sn.status == .down) {
                zgui.textColored(t.text.lo, "\u{2014}", .{});
            } else {
                zgui.textColored(t.text.hi, "{d:.0}", .{sn.eps});
            }
            _ = zgui.tableNextColumn();
            if (sn.status == .down) {
                zgui.textColored(t.sev.crit, "offline", .{});
            } else if (sn.lag_s > 30) {
                zgui.textColored(t.sev.warn, "{d:.0}s", .{sn.lag_s});
            } else {
                zgui.textColored(t.text.mid, "{d:.1}s", .{sn.lag_s});
            }
            _ = zgui.tableNextColumn();
            zgui.textUnformattedColored(t.text.lo, sn.version.slice());
        }
        zgui.endTable();
    }
}
