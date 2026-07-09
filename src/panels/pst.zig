//! PST · Posture Summary: hero numbers (open alerts by severity, open
//! cases, MTTA, sensors down) + a 24 h alert-volume sparkline.

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const domain = @import("domain");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

/// One SLA stat: "MTTA 14m" colored ok/amber/red against a target, with
/// the target itself in the tooltip so the color is explainable.
fn slaTile(label: [:0]const u8, mean_ms: ?i64, target_secs: f64, buf: *[16]u8) void {
    const t = ui.theme.active;
    if (mean_ms) |ms| {
        const secs: f64 = @floatFromInt(@divFloor(ms, 1000));
        const col = if (secs <= target_secs)
            t.sev.ok
        else if (secs <= target_secs * 2.0)
            t.sev.warn
        else
            t.sev.crit;
        zgui.textColored(col, "{s} {s}", .{ label, ui.fmt.age(buf, @divFloor(ms, 1000)) });
        if (zgui.isItemHovered(.{})) {
            if (zgui.beginTooltip()) {
                var tb: [16]u8 = undefined;
                zgui.text("target {s} (set in SET \u{2192} Triage SLA) \u{00B7} ok \u{2264} target \u{00B7} amber \u{2264} 2\u{00D7} \u{00B7} red beyond", .{ui.fmt.age(&tb, @intFromFloat(target_secs))});
                zgui.endTooltip();
            }
        }
    } else {
        zgui.textColored(t.text.lo, "{s} \u{2014}", .{label});
    }
}

pub fn render(d: *Dashboard) void {
    const t = ui.theme.active;
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

    // Triage SLA: real MTTA/MTTR from the alert ack/resolve stamps,
    // threshold-colored against the SET targets (ok ≤ target, amber ≤ 2×,
    // red beyond — threshold stat tiles beat gauges).
    {
        var triaged: u32 = 0;
        for (s.alerts.items) |*a| {
            if (!a.status.isOpen()) triaged += 1;
        }
        const means = s.triageMeans();
        zgui.sameLine(.{ .spacing = 22 });
        var mb: [16]u8 = undefined;
        slaTile("MTTA", means.mtta_ms, ui.prefs.current.sla_mtta_min * 60.0, &mb);
        zgui.sameLine(.{ .spacing = 10 });
        slaTile("MTTR", means.mttr_ms, ui.prefs.current.sla_mttr_hours * 3600.0, &mb);
        zgui.sameLine(.{ .spacing = 10 });
        zgui.textColored(t.text.mid, "triaged {d}", .{triaged});
    }

    // ── Open-alert severity mix: one stacked bar (glanceable proportions;
    // the chips above carry the exact counts) ────────────────────────────
    if (open_total > 0) {
        zgui.spacing();
        const dl = zgui.getWindowDrawList();
        const pos = zgui.getCursorScreenPos();
        const w = zgui.getContentRegionAvail()[0];
        const bar_h: f32 = 6;
        var x = pos[0];
        inline for (order) |sv| {
            const n = by_sev[@intFromEnum(sv)];
            if (n > 0) {
                const frac = @as(f32, @floatFromInt(n)) / @as(f32, @floatFromInt(open_total));
                const seg = w * frac;
                dl.addRectFilled(.{
                    .pmin = .{ x, pos[1] },
                    .pmax = .{ x + seg - 1, pos[1] + bar_h },
                    .col = zgui.colorConvertFloat4ToU32(dash.sevColor(sv)),
                });
                x += seg;
            }
        }
        zgui.dummy(.{ .w = w, .h = bar_h + 2 });
        if (zgui.isItemHovered(.{})) {
            if (zgui.beginTooltip()) {
                zgui.text("open-alert severity mix \u{2014} exact counts in the chips above", .{});
                zgui.endTooltip();
            }
        }
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
