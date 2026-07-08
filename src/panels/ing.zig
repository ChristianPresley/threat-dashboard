//! ING · Ingestion Stats: EPS-over-time per sensor kind (ring-buffer
//! sampled each frame) + per-kind totals table.

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const domain = @import("domain");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

const SAMPLES = 240;
const KINDS = 6;

// Panel-local sampling state (one instance app-wide).
var ring: [KINDS][SAMPLES]f64 = @splat(@splat(0));
var xs: [SAMPLES]f64 = blk: {
    var out: [SAMPLES]f64 = undefined;
    for (&out, 0..) |*x, i| x.* = @floatFromInt(i);
    break :blk out;
};
var head: usize = 0;
var accum_s: f32 = 0;

pub fn render(d: *Dashboard) void {
    const t = ui.theme.default;
    const s = &d.store;

    // Sample ~4 Hz.
    accum_s += d.dt;
    if (accum_s >= 0.25) {
        accum_s = 0;
        var per_kind: [KINDS]f64 = @splat(0);
        for (s.sensors.items) |*sn| {
            if (sn.status != .down) per_kind[@intFromEnum(sn.kind)] += sn.eps;
        }
        for (0..KINDS) |k| ring[k][head] = per_kind[k];
        head = (head + 1) % SAMPLES;
    }

    var total: f64 = 0;
    for (s.sensors.items) |*sn| {
        if (sn.status != .down) total += sn.eps;
    }
    zgui.textColored(t.text.mid, "{d:.0} events/sec across the fleet \u{00B7} 60s window", .{total});

    const avail = zgui.getContentRegionAvail();
    const table_h: f32 = 148;
    if (zgui.plot.beginPlot("##ing_plot", .{
        .w = avail[0],
        .h = @max(100, avail[1] - table_h),
        .flags = .{ .no_title = true },
    })) {
        zgui.plot.setupAxis(.x1, .{ .flags = .{ .no_tick_labels = true, .no_grid_lines = true } });
        zgui.plot.setupAxis(.y1, .{ .flags = .{ .auto_fit = true } });
        zgui.plot.setupAxisLimits(.x1, .{ .min = 0, .max = SAMPLES - 1 });
        zgui.plot.setupLegend(.{ .north = true }, .{ .horizontal = true, .outside = true });
        const kind_names = [_][:0]const u8{ "EDR", "FW", "IDS", "DNS", "PROXY", "CLOUD" };
        inline for (0..KINDS) |k| {
            // Rotate so the newest sample is rightmost.
            var ys: [SAMPLES]f64 = undefined;
            for (0..SAMPLES) |i| ys[i] = ring[k][(head + i) % SAMPLES];
            zgui.plot.plotLine(kind_names[k], f64, .{ .xv = &xs, .yv = &ys });
        }
        zgui.plot.endPlot();
    }

    // Totals per kind.
    const flags = zgui.TableFlags{ .borders = .{ .inner_h = true } };
    if (zgui.beginTable("##ing_table", .{ .column = 4, .flags = flags })) {
        zgui.tableSetupColumn("Kind", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 70 });
        zgui.tableSetupColumn("Sensors", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 66 });
        zgui.tableSetupColumn("EPS", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 80 });
        zgui.tableSetupColumn("Share", .{ .flags = .{ .width_stretch = true } });
        zgui.tableHeadersRow();
        inline for (0..KINDS) |k| {
            const kind: domain.SensorKind = @enumFromInt(k);
            var eps: f64 = 0;
            var n: u32 = 0;
            for (s.sensors.items) |*sn| {
                if (sn.kind == kind) {
                    n += 1;
                    if (sn.status != .down) eps += sn.eps;
                }
            }
            zgui.tableNextRow(.{});
            _ = zgui.tableNextColumn();
            zgui.textColored(t.text.hi, "{s}", .{kind.label()});
            _ = zgui.tableNextColumn();
            zgui.textColored(t.text.mid, "{d}", .{n});
            _ = zgui.tableNextColumn();
            zgui.textColored(t.text.mid, "{d:.0}", .{eps});
            _ = zgui.tableNextColumn();
            const share: f32 = if (total > 0) @floatCast(eps / total) else 0;
            zgui.progressBar(.{ .fraction = share, .h = 12, .overlay = "" });
        }
        zgui.endTable();
    }
}
