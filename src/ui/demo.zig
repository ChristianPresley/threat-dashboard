//! Bindings demo + render-stress window (`trading --demo`).
//!
//! Phase 1 acceptance artifact (DESIGN.md §9): exercises every ImPlot API
//! bound for the overhaul — DragLineX/Y, Annotation, TagY, PlotHeatmap,
//! ColormapScale, PlotHistogram, time-scale axis — plus a >64k-vertex
//! drawlist stress that proves `renderer_has_vtx_offset` end to end.
//! Later phases use this window as a living reference for the chart work.

const std = @import("std");
const zgui = @import("zgui");
const theme = @import("theme.zig");

var order_px: f64 = 67_210.0;
var stop_px: f64 = 65_800.0;
var anchor_ts: f64 = 1_760_000_000; // demo time-axis origin (Unix seconds)

var histo: [512]f64 = undefined;
var heat: [64]f64 = undefined;
var seeded: bool = false;

fn seed() void {
    if (seeded) return;
    seeded = true;
    // Deterministic pseudo-data — no RNG dependency, stable screenshots.
    for (&histo, 0..) |*v, i| {
        const x: f64 = @floatFromInt(i % 64);
        v.* = @mod(x * 7.31 + @as(f64, @floatFromInt(i / 64)) * 13.7, 64.0) - 32.0;
    }
    for (&heat, 0..) |*v, i| {
        const r: f64 = @floatFromInt(i / 8);
        const c: f64 = @floatFromInt(i % 8);
        v.* = (r - 3.5) * (c - 3.5) / 12.25; // diverging −1..1
    }
}

/// Render the demo window. Call per frame when `--demo` is set.
pub fn draw() void {
    seed();
    const t = &theme.active;

    zgui.setNextWindowSize(.{ .w = 980, .h = 720, .cond = .first_use_ever });
    if (!zgui.begin("Bindings Demo##ui_demo", .{})) {
        zgui.end();
        return;
    }
    defer zgui.end();

    // ── Drag lines + tags + annotation on a time axis ────────────────────
    zgui.textColored(t.text.mid, "DragLineY (order/stop), TagY, Annotation, time-scale X axis:", .{});
    if (zgui.plot.beginPlot("price##demo_price", .{ .h = 240 })) {
        zgui.plot.setupAxisScale(.x1, .time);
        zgui.plot.setupAxis(.x1, .{});
        zgui.plot.setupAxis(.y1, .{ .flags = .{ .opposite = true } });
        zgui.plot.setupAxisLimits(.x1, .{ .min = anchor_ts, .max = anchor_ts + 3600 * 6 });
        zgui.plot.setupAxisLimits(.y1, .{ .min = 65_000, .max = 68_500 });

        var px: [73]f64 = undefined;
        var py: [73]f64 = undefined;
        for (&px, 0..) |*x, i| {
            const fi: f64 = @floatFromInt(i);
            x.* = anchor_ts + fi * 300;
            py[i] = 66_500 + 800 * @sin(fi / 7.0) + 200 * @sin(fi / 2.3);
        }
        zgui.plot.plotLine("BTCUSD", f64, .{ .xv = &px, .yv = &py });

        _ = zgui.plot.dragLineY(1, &order_px, .{ .col = t.accent, .thickness = 1.5 });
        zgui.plot.tagYText(order_px, t.accent, "BUY @ {d:.0}", .{order_px});
        _ = zgui.plot.dragLineY(2, &stop_px, .{ .col = t.sev.crit, .thickness = 1.0 });
        zgui.plot.tagYText(stop_px, t.sev.crit, "STOP {d:.0}", .{stop_px});

        zgui.plot.annotationText(px[36], py[36], t.delta.pos, .{ .pix_offset = .{ 0, -14 }, .clamp = true }, "fill 0.05 @ {d:.0}", .{py[36]});
        zgui.plot.endPlot();
    }

    // ── Histogram + heatmap + colormap scale ─────────────────────────────
    zgui.textColored(t.text.mid, "PlotHistogram / PlotHeatmap / ColormapScale:", .{});
    if (zgui.plot.beginPlot("P&L distribution##demo_histo", .{ .w = 460, .h = 200 })) {
        _ = zgui.plot.plotHistogram("pnl", &histo, .{ .bins = zgui.plot.Bins.count(32) });
        zgui.plot.endPlot();
    }
    zgui.sameLine(.{});
    zgui.plot.pushColormap(.rd_bu);
    if (zgui.plot.beginPlot("coverage##demo_heat", .{ .w = 320, .h = 200 })) {
        zgui.plot.plotHeatmap("h", &heat, .{
            .rows = 8,
            .cols = 8,
            .scale_min = -1,
            .scale_max = 1,
            .label_fmt = "%.1f",
        });
        zgui.plot.endPlot();
    }
    zgui.sameLine(.{});
    zgui.plot.colormapScale("##demo_scale", -1, 1, .{ .size = .{ 60, 200 } });
    zgui.plot.popColormap(1);

    // ── >64k-vertex drawlist stress (vtx_offset proof) ───────────────────
    // 18,000 quads = 72,000 vertices in ONE window — overflows a u16 index
    // space unless the backend honors DrawCmd.vtx_offset.
    zgui.textColored(t.text.mid, "72,000-vertex drawlist stress (renderer_has_vtx_offset):", .{});
    const dl = zgui.getWindowDrawList();
    const origin = zgui.getCursorScreenPos();
    const cols: usize = 200;
    const rows: usize = 90;
    var r: usize = 0;
    while (r < rows) : (r += 1) {
        var c: usize = 0;
        while (c < cols) : (c += 1) {
            const x = origin[0] + @as(f32, @floatFromInt(c)) * 4.0;
            const y = origin[1] + @as(f32, @floatFromInt(r)) * 1.6;
            const shade: f32 = @as(f32, @floatFromInt((r * cols + c) % 255)) / 255.0;
            dl.addRectFilled(.{
                .pmin = .{ x, y },
                .pmax = .{ x + 3.0, y + 1.2 },
                .col = zgui.colorConvertFloat4ToU32(.{ shade * 0.3, 0.4 + shade * 0.4, 0.8 - shade * 0.3, 1.0 }),
            });
        }
    }
    zgui.dummy(.{
        .w = @as(f32, @floatFromInt(cols)) * 4.0,
        .h = @as(f32, @floatFromInt(rows)) * 1.6,
    });
}
