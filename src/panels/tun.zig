//! TUN · Rule Tuning: noisiest rules ranked by FP volume, fires-vs-FP
//! bars, and a threshold what-if slider (recomputes suppressed share).

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const domain = @import("domain");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

pub fn render(d: *Dashboard) void {
    const t = ui.theme.default;
    const s = &d.store;

    // Rank rules by FP volume.
    var order: [64]u16 = undefined;
    var n: usize = @min(s.rules.items.len, order.len);
    for (0..n) |i| order[i] = @intCast(i);
    const ctx = s;
    std.mem.sort(u16, order[0..n], ctx, struct {
        fn less(store: @TypeOf(ctx), a: u16, b: u16) bool {
            return store.rules.items[a].fp_7d > store.rules.items[b].fp_7d;
        }
    }.less);

    // What-if: suppress rules whose FP rate exceeds the threshold.
    zgui.textColored(t.text.mid, "what-if: suppress rules with FP rate above", .{});
    zgui.sameLine(.{ .spacing = 8 });
    zgui.setNextItemWidth(160);
    _ = zgui.sliderFloat("##tun_thresh", .{ .v = &d.tun_threshold, .min = 0.05, .max = 0.95 });
    {
        var cut_fires: u64 = 0;
        var cut_rules: u32 = 0;
        for (s.rules.items) |*r| {
            if (r.status == .disabled) continue;
            if (r.fpRate() > d.tun_threshold) {
                cut_fires += r.fires_7d;
                cut_rules += 1;
            }
        }
        zgui.sameLine(.{ .spacing = 12 });
        zgui.textColored(t.text.mid, "\u{2192} {d} rules muted, alert volume \u{2212}{d} / week", .{ cut_rules, cut_fires });
    }
    zgui.separator();

    // Noisiest table: fires vs FP inline bars.
    n = @min(n, 20);
    const flags = zgui.TableFlags{ .resizable = true, .borders = .{ .inner_h = true }, .scroll_y = true };
    if (zgui.beginTable("##tun_table", .{ .column = 5, .flags = flags })) {
        zgui.tableSetupColumn("Code", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 62 });
        zgui.tableSetupColumn("Name", .{ .flags = .{ .width_stretch = true } });
        zgui.tableSetupColumn("Fires", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 140 });
        zgui.tableSetupColumn("FP rate", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 140 });
        zgui.tableSetupColumn("Verdict", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 90 });
        zgui.tableSetupScrollFreeze(0, 1);
        zgui.tableHeadersRow();

        var max_fires: f32 = 1;
        for (order[0..n]) |ri| {
            max_fires = @max(max_fires, @as(f32, @floatFromInt(s.rules.items[ri].fires_7d)));
        }

        for (order[0..n]) |ri| {
            const r = &s.rules.items[ri];
            zgui.tableNextRow(.{});
            _ = zgui.tableNextColumn();
            var slbl: [20]u8 = undefined;
            const sl = std.fmt.bufPrintZ(&slbl, "{s}##tun{d}", .{ r.code.slice(), r.id }) catch continue;
            if (zgui.selectable(sl, .{ .flags = .{ .allow_overlap = true } })) {
                d.rul_sel = r.id;
                d.focusPanel(dash.PANEL_RUL);
            }
            _ = zgui.tableNextColumn();
            zgui.textUnformattedColored(t.text.hi, r.name.slice());
            _ = zgui.tableNextColumn();
            zgui.pushStyleColor4f(.{ .idx = .plot_histogram, .c = t.accent });
            zgui.progressBar(.{ .fraction = @as(f32, @floatFromInt(r.fires_7d)) / max_fires, .w = 130, .h = 12, .overlay = "" });
            zgui.popStyleColor(.{ .count = 1 });
            zgui.sameLine(.{ .spacing = 4 });
            zgui.textColored(t.text.mid, "{d}", .{r.fires_7d});
            _ = zgui.tableNextColumn();
            const fp = r.fpRate();
            zgui.pushStyleColor4f(.{ .idx = .plot_histogram, .c = if (fp > d.tun_threshold) t.sev.warn else t.sev.ok });
            zgui.progressBar(.{ .fraction = fp, .w = 130, .h = 12, .overlay = "" });
            zgui.popStyleColor(.{ .count = 1 });
            zgui.sameLine(.{ .spacing = 4 });
            zgui.textColored(t.text.mid, "{d:.0}%", .{fp * 100});
            _ = zgui.tableNextColumn();
            if (fp > d.tun_threshold) {
                zgui.textColored(t.sev.warn, "would mute", .{});
            } else if (r.fires_7d == 0) {
                zgui.textColored(t.text.lo, "silent", .{});
            } else {
                zgui.textColored(t.sev.ok, "healthy", .{});
            }
        }
        zgui.endTable();
    }
}
