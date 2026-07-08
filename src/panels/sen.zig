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

    // Width-planned columns: the sensor name is the payload; narrow docks
    // drop Version, then Kind (both live in the status-dot tooltip).
    const cols = [_]ui.table.Col{
        .{ .name = "", .w = 20 },
        .{ .name = "Sensor" },
        .{ .name = "Kind", .w = 58, .prio = 1 },
        .{ .name = "EPS", .w = 66 },
        .{ .name = "Lag", .w = 64 },
        .{ .name = "Version", .w = 70, .prio = 2 },
    };
    const avail = zgui.getContentRegionAvail();
    const detail_h: f32 = if (d.sen_sel != null) 24 else 0;
    const pl = ui.table.plan(&cols, avail[0], 140);
    const flags = zgui.TableFlags{ .resizable = true, .no_saved_settings = true, .borders = .{ .inner_h = true }, .scroll_y = true };
    if (zgui.beginTable("##sen_table", .{ .column = pl.count, .flags = flags, .outer_size = .{ avail[0], @max(80, avail[1] - detail_h) } })) {
        ui.table.setup(&cols, &pl);
        zgui.tableSetupScrollFreeze(0, 1);
        zgui.tableHeadersRow();

        for (s.sensors.items) |*sn| {
            zgui.tableNextRow(.{});
            const selected = d.sen_sel != null and d.sen_sel.? == sn.id;
            if (selected) {
                zgui.tableSetBgColor(.{ .target = .row_bg0, .color = zgui.colorConvertFloat4ToU32(t.bg.selected) });
            } else if (sn.status == .down) {
                zgui.tableSetBgColor(.{ .target = .row_bg0, .color = zgui.colorConvertFloat4ToU32(t.sev.crit_dim) });
            } else if (sn.status == .degraded) {
                zgui.tableSetBgColor(.{ .target = .row_bg0, .color = zgui.colorConvertFloat4ToU32(t.sev.warn_dim) });
            }
            _ = zgui.tableNextColumn();
            // Row-spanning selectable behind the status dot.
            var slbl: [24]u8 = undefined;
            const sl = std.fmt.bufPrintZ(&slbl, "##senrow{d}", .{sn.id}) catch "##s";
            const cur = zgui.getCursorPosX();
            if (zgui.selectable(sl, .{ .selected = selected, .flags = .{ .span_all_columns = true, .allow_overlap = true } })) {
                d.sen_sel = if (selected) null else sn.id;
            }
            zgui.sameLine(.{});
            zgui.setCursorPosX(cur);
            zgui.textColored(dash.sensorStatusColor(sn.status), "{s}", .{ui.fonts.fa.circle});
            if (zgui.isItemHovered(.{})) {
                if (zgui.beginTooltip()) {
                    zgui.text("{s} \u{00B7} {s} \u{00B7} v{s}", .{ sn.status.label(), sn.kind.label(), sn.version.slice() });
                    zgui.endTooltip();
                }
            }
            _ = zgui.tableNextColumn();
            zgui.textUnformattedColored(t.text.hi, sn.host.slice());
            if (pl.on(2)) {
                _ = zgui.tableNextColumn();
                zgui.textColored(t.text.mid, "{s}", .{sn.kind.label()});
            }
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
            if (pl.on(5)) {
                _ = zgui.tableNextColumn();
                zgui.textUnformattedColored(t.text.lo, sn.version.slice());
            }
        }
        zgui.endTable();
    }

    // ── Detail line for the selection (the down-sensor "when did we last
    //    hear from it" answer) ────────────────────────────────────────────
    if (d.sen_sel) |sid| {
        const sn = blk: {
            for (s.sensors.items) |*x| {
                if (x.id == sid) break :blk x;
            }
            d.sen_sel = null;
            return;
        };
        var ab: [16]u8 = undefined;
        const age_s = @divFloor(dash.unixNowMs() - sn.last_seen_ms, 1000);
        zgui.textColored(dash.sensorStatusColor(sn.status), "{s}", .{sn.status.label()});
        zgui.sameLine(.{ .spacing = 8 });
        zgui.textColored(t.text.mid, "{s} \u{00B7} {s} \u{00B7} v{s} \u{00B7} last seen {s} ago", .{
            sn.host.slice(), sn.kind.label(), sn.version.slice(), ui.fmt.age(&ab, age_s),
        });
    }
}
