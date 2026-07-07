//! PST · Posture Summary: hero numbers (open alerts by severity, open
//! cases, MTTA, sensors down) + a 24 h alert-volume sparkline.

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const domain = @import("domain");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

pub fn render(d: *Dashboard) void {
    const t = ui.theme.default;
    const s = &d.store;

    const by_sev = s.openAlertCountBySeverity();
    var open_total: u32 = 0;
    for (by_sev) |n| open_total += n;

    // ── Hero row ─────────────────────────────────────────────────────────
    zgui.pushFont(ui.fonts.mono_medium, ui.fonts.size.hero);
    zgui.textColored(if (open_total > 0) dash.sevColor(.high) else t.sev.ok, "{d}", .{open_total});
    zgui.popFont();
    zgui.sameLine(.{ .spacing = 8 });
    zgui.textColored(t.text.mid, "open alerts", .{});

    zgui.sameLine(.{ .spacing = 24 });
    zgui.pushFont(ui.fonts.mono_medium, ui.fonts.size.hero);
    zgui.textColored(t.text.hi, "{d}", .{s.openCaseCount()});
    zgui.popFont();
    zgui.sameLine(.{ .spacing = 8 });
    zgui.textColored(t.text.mid, "open cases", .{});

    zgui.sameLine(.{ .spacing = 24 });
    const down = s.sensorsDown();
    zgui.pushFont(ui.fonts.mono_medium, ui.fonts.size.hero);
    zgui.textColored(if (down > 0) t.sev.crit else t.sev.ok, "{d}", .{down});
    zgui.popFont();
    zgui.sameLine(.{ .spacing = 8 });
    zgui.textColored(t.text.mid, "sensors down", .{});

    // ── Severity breakdown chips ─────────────────────────────────────────
    zgui.spacing();
    const order = [_]domain.Severity{ .critical, .high, .medium, .low, .info };
    inline for (order, 0..) |sv, i| {
        if (i > 0) zgui.sameLine(.{ .spacing = 10 });
        const n = by_sev[@intFromEnum(sv)];
        zgui.textColored(if (n > 0) dash.sevColor(sv) else t.text.lo, "{s} {d}", .{ sv.label(), n });
    }

    // MTTA over acked/resolved alerts (mock: alert ts → now spread).
    {
        var acked: u32 = 0;
        for (s.alerts.items) |*a| {
            if (!a.status.isOpen()) acked += 1;
        }
        zgui.sameLine(.{ .spacing = 22 });
        zgui.textColored(t.text.mid, "triaged: {d}", .{acked});
    }

    zgui.spacing();
    zgui.separator();

    // ── 24 h alert sparkline (30-min buckets) ────────────────────────────
    zgui.textColored(t.text.mid, "alerts \u{00B7} last 24h", .{});
    const buckets = 48;
    var xs: [buckets]f64 = undefined;
    var ys: [buckets]f64 = undefined;
    const now_ms = dash.unixNowMs();
    const span: i64 = 24 * std.time.ms_per_hour;
    const bucket_ms = @divExact(span, buckets);
    for (&xs, 0..) |*x, i| {
        x.* = @floatFromInt(i);
        ys[i] = 0;
    }
    for (s.alerts.items) |*a| {
        const age = now_ms - a.ts_ms;
        if (age < 0 or age >= span) continue;
        const bi: usize = @intCast(@divFloor(span - 1 - age, bucket_ms));
        if (bi < buckets) ys[bi] += 1;
    }
    const avail = zgui.getContentRegionAvail();
    if (zgui.plot.beginPlot("##pst_spark", .{
        .w = avail[0],
        .h = @max(80, avail[1] - 4),
        .flags = .{ .no_title = true, .no_mouse_text = true, .no_inputs = true, .no_legend = true },
    })) {
        zgui.plot.setupAxis(.x1, .{ .flags = .{ .no_tick_labels = true, .no_grid_lines = true } });
        zgui.plot.setupAxis(.y1, .{ .flags = .{ .auto_fit = true, .no_grid_lines = true } });
        zgui.plot.setupAxisLimits(.x1, .{ .min = 0, .max = buckets - 1 });
        zgui.plot.setNextFillStyle(.{ .col = ui.theme.withAlpha(t.accent, 0.35) });
        zgui.plot.plotShaded("alerts", f64, .{ .xv = &xs, .yv = &ys });
        zgui.plot.plotLine("alerts", f64, .{ .xv = &xs, .yv = &ys });
        zgui.plot.endPlot();
    }
}
