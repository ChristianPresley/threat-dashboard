//! TLN · Timeline: severity-stacked event histogram over the world span.
//! A brush (two drag handles) selects a time range that filters EVT.

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const domain = @import("domain");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

const BUCKETS = 104; // 26 h / 15 min

var brush_on: bool = false;
var brush_a: f64 = 0; // unix seconds
var brush_b: f64 = 0;

pub fn render(d: *Dashboard) void {
    const t = ui.theme.default;
    const s = &d.store;

    const now_ms = dash.unixNowMs();
    const span_ms: i64 = data_span_ms;
    const start_ms = now_ms - span_ms;
    const bucket_ms = @divExact(span_ms, BUCKETS);

    // Per-severity stacked counts (cumulative for shaded stacking).
    var xs: [BUCKETS]f64 = undefined;
    var stack: [5][BUCKETS]f64 = @splat(@splat(0));
    for (&xs, 0..) |*x, i| {
        x.* = @as(f64, @floatFromInt(@divFloor(start_ms + @as(i64, @intCast(i)) * bucket_ms, 1000)));
    }
    for (s.events.items) |*e| {
        if (e.ts_ms < start_ms or e.ts_ms >= now_ms) continue;
        const bi: usize = @intCast(@min(@divFloor(e.ts_ms - start_ms, bucket_ms), BUCKETS - 1));
        stack[@intFromEnum(e.severity)][bi] += 1;
    }
    // Cumulate: crit on top of high on top of …
    var cum: [5][BUCKETS]f64 = undefined;
    {
        var running: [BUCKETS]f64 = @splat(0);
        var lvl: usize = 0;
        while (lvl < 5) : (lvl += 1) {
            for (0..BUCKETS) |i| {
                running[i] += stack[lvl][i];
                cum[lvl][i] = running[i];
            }
        }
    }

    // ── Controls ─────────────────────────────────────────────────────────
    if (dash.filterChip("brush##tln", brush_on, t.accent)) {
        brush_on = !brush_on;
        if (brush_on) {
            const mid = @as(f64, @floatFromInt(@divFloor(start_ms + span_ms / 2, 1000)));
            const w = @as(f64, @floatFromInt(@divFloor(span_ms, 8000)));
            brush_a = mid - w;
            brush_b = mid + w;
            applyBrush(d);
        } else {
            d.evt_range = null;
        }
    }
    zgui.sameLine(.{ .spacing = 10 });
    if (d.evt_range != null) {
        zgui.textColored(t.accent, "range \u{2192} EVT filter active", .{});
        zgui.sameLine(.{ .spacing = 8 });
        if (zgui.smallButton("clear##tlnrange")) {
            d.evt_range = null;
            brush_on = false;
        }
        zgui.sameLine(.{ .spacing = 8 });
        if (zgui.smallButton("open EVT##tln")) d.focusPanel(dash.PANEL_EVT);
    } else {
        zgui.textColored(t.text.lo, "{d} events \u{00B7} 26h \u{00B7} stacked by severity", .{s.events.items.len});
    }

    // ── Plot ─────────────────────────────────────────────────────────────
    const avail = zgui.getContentRegionAvail();
    if (zgui.plot.beginPlot("##tln_plot", .{
        .w = avail[0],
        .h = @max(120, avail[1] - 2),
        .flags = .{ .no_title = true },
    })) {
        zgui.plot.setupAxis(.x1, .{ .flags = .{ .no_label = true } });
        zgui.plot.setupAxisScale(.x1, .time);
        zgui.plot.setupAxis(.y1, .{ .flags = .{ .auto_fit = true, .no_label = true } });
        zgui.plot.setupAxisLimits(.x1, .{
            .min = @floatFromInt(@divFloor(start_ms, 1000)),
            .max = @floatFromInt(@divFloor(now_ms, 1000)),
        });
        zgui.plot.setupLegend(.{ .north = true, .west = true }, .{});

        // Draw top-down so lower layers stay visible under higher ones.
        const order = [_]domain.Severity{ .critical, .high, .medium, .low, .info };
        inline for (order) |sv| {
            const lvl = @intFromEnum(sv);
            zgui.plot.setNextFillStyle(.{ .col = ui.theme.withAlpha(dash.sevColor(sv), 0.65) });
            zgui.plot.plotShaded(sv.label(), f64, .{ .xv = &xs, .yv = &cum[lvl] });
        }

        if (brush_on) {
            var changed = false;
            if (zgui.plot.dragLineX(1, &brush_a, .{ .col = t.amber, .thickness = 2 })) changed = true;
            if (zgui.plot.dragLineX(2, &brush_b, .{ .col = t.amber, .thickness = 2 })) changed = true;
            if (changed) applyBrush(d);
        }
        zgui.plot.endPlot();
    }
}

const data_span_ms: i64 = 26 * std.time.ms_per_hour;

fn applyBrush(d: *Dashboard) void {
    const lo = @min(brush_a, brush_b);
    const hi = @max(brush_a, brush_b);
    d.evt_range = .{ @as(i64, @intFromFloat(lo)) * 1000, @as(i64, @intFromFloat(hi)) * 1000 };
}
