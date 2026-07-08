//! TUN · Rule Tuning: noisiest rules ranked by FP volume, fires-vs-FP
//! bars, and a threshold what-if slider (recomputes suppressed share).

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const domain = @import("domain");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

var apply_dwell: ui.confirm.Dwell = .{};
var apply_armed: bool = false;

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

    // What-if: suppress rules whose FP rate exceeds the threshold. The
    // label + slider sit on one line; the impact reads on the next so the
    // whole control fits the narrow tuning rail without clipping.
    zgui.textColored(t.text.mid, "what-if \u{00B7} mute FP rate >", .{});
    zgui.sameLine(.{ .spacing = 8 });
    zgui.setNextItemWidth(-1);
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
        zgui.textColored(t.text.mid, "\u{2192} {d} rules muted \u{00B7} \u{2212}{d} alerts / week", .{ cut_rules, cut_fires });

        // Apply the what-if for real: bulk-disable behind a T1 dwell (it's
        // a coverage cut, the same risk class as RUL's single disable).
        if (cut_rules > 0) {
            zgui.sameLine(.{ .spacing = 12 });
            if (apply_armed) {
                if (apply_dwell.ready(ui.confirm.DWELL_T1_MS)) {
                    var bb: [40]u8 = undefined;
                    const bl = std.fmt.bufPrintZ(&bb, "Confirm mute {d}##tunapply", .{cut_rules}) catch "Confirm";
                    if (zgui.smallButton(bl)) {
                        var muted: u32 = 0;
                        for (s.rules.items) |*r| {
                            if (r.status == .disabled) continue;
                            if (r.fpRate() > d.tun_threshold) {
                                _ = s.setRuleStatus(r.id, .disabled);
                                muted += 1;
                            }
                        }
                        ui.events.post(.warn, "rules", "{d} noisy rule(s) DISABLED via tuning \u{2014} review coverage in ATK", .{muted});
                        apply_armed = false;
                        apply_dwell.reset();
                    }
                } else {
                    zgui.textColored(t.text.lo, "confirm in {d:.1}s\u{2026}", .{apply_dwell.remainingSecs(ui.confirm.DWELL_T1_MS)});
                }
            } else if (zgui.smallButton("Mute them\u{2026}##tunapply")) {
                apply_armed = true;
                apply_dwell.arm();
            }
            // Esc disarms (never confirms).
            if (apply_armed and zgui.isKeyPressed(.escape, false)) {
                apply_armed = false;
                apply_dwell.reset();
            }
        } else apply_armed = false;
    }
    zgui.separator();

    // Noisiest table: fires vs FP inline bars.
    n = @min(n, 20);
    // Value lives INSIDE each bar (overlay) so the bar columns stay
    // compact and the rule Name keeps real width in the narrow rail; the
    // Verdict column is redundant with the FP-bar color and drops first.
    const cols = [_]ui.table.Col{
        .{ .name = "Code", .w = 60 },
        .{ .name = "Name" },
        .{ .name = "Fires", .w = 74 },
        .{ .name = "FP rate", .w = 74 },
        .{ .name = "Verdict", .w = 78, .prio = 1 },
    };
    const pl = ui.table.plan(&cols, zgui.getContentRegionAvail()[0], 140);
    const flags = zgui.TableFlags{ .resizable = true, .no_saved_settings = true, .borders = .{ .inner_h = true }, .scroll_y = true };
    if (zgui.beginTable("##tun_table", .{ .column = pl.count, .flags = flags })) {
        ui.table.setup(&cols, &pl);
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
            var fbuf: [12]u8 = undefined;
            const fires_lbl = std.fmt.bufPrintZ(&fbuf, "{d}", .{r.fires_7d}) catch "";
            zgui.pushStyleColor4f(.{ .idx = .plot_histogram, .c = t.accent });
            zgui.progressBar(.{ .fraction = @as(f32, @floatFromInt(r.fires_7d)) / max_fires, .w = -1, .h = 14, .overlay = fires_lbl });
            zgui.popStyleColor(.{ .count = 1 });
            _ = zgui.tableNextColumn();
            const fp = r.fpRate();
            var pbuf: [12]u8 = undefined;
            const fp_lbl = std.fmt.bufPrintZ(&pbuf, "{d:.0}%", .{fp * 100}) catch "";
            zgui.pushStyleColor4f(.{ .idx = .plot_histogram, .c = if (fp > d.tun_threshold) t.sev.warn else t.sev.ok });
            zgui.progressBar(.{ .fraction = fp, .w = -1, .h = 14, .overlay = fp_lbl });
            zgui.popStyleColor(.{ .count = 1 });
            if (pl.on(4)) {
                _ = zgui.tableNextColumn();
                if (fp > d.tun_threshold) {
                    zgui.textColored(t.sev.warn, "would mute", .{});
                } else if (r.fires_7d == 0) {
                    zgui.textColored(t.text.lo, "silent", .{});
                } else {
                    zgui.textColored(t.sev.ok, "healthy", .{});
                }
            }
        }
        zgui.endTable();
    }
}
