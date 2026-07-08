//! ATK · ATT&CK Matrix: 14 tactic columns, technique cells colored by rule
//! coverage (none / testing / enabled) with open-alert heat badges.
//! Clicking a cell filters RUL to that technique.

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const domain = @import("domain");
const attack = domain.attack;
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

pub fn render(d: *Dashboard) void {
    const t = ui.theme.default;
    const s = &d.store;

    // Legend.
    zgui.textColored(t.text.lo, "coverage:", .{});
    zgui.sameLine(.{ .spacing = 6 });
    zgui.textColored(t.sev.ok, "\u{25A0} enabled", .{});
    zgui.sameLine(.{ .spacing = 8 });
    zgui.textColored(t.sev.warn, "\u{25A0} testing", .{});
    zgui.sameLine(.{ .spacing = 8 });
    zgui.textColored(t.text.lo, "\u{25A0} none", .{});
    zgui.sameLine(.{ .spacing = 14 });
    zgui.textColored(t.sev.crit, "n = open alerts", .{});
    zgui.sameLine(.{ .spacing = 14 });
    zgui.textColored(t.text.lo, "click a cell \u{2192} RUL filter", .{});
    zgui.spacing();

    const flags = zgui.TableFlags{
        .borders = .{ .inner_v = true, .inner_h = true },
        .scroll_y = true,
        .scroll_x = true,
        .sizing = .fixed_fit,
    };
    if (zgui.beginTable("##atk_matrix", .{ .column = attack.tactic_count, .flags = flags })) {
        inline for (0..attack.tactic_count) |ci| {
            const tac: attack.Tactic = @enumFromInt(ci);
            zgui.tableSetupColumn(tac.label(), .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 118 });
        }
        zgui.tableSetupScrollFreeze(0, 1);
        zgui.tableHeadersRow();

        // Rows: max techniques per tactic.
        var max_rows: usize = 0;
        inline for (0..attack.tactic_count) |ci| {
            const tac: attack.Tactic = @enumFromInt(ci);
            max_rows = @max(max_rows, comptime attack.tacticTechniqueCount(tac));
        }

        var row: usize = 0;
        while (row < max_rows) : (row += 1) {
            zgui.tableNextRow(.{});
            inline for (0..attack.tactic_count) |ci| {
                const tac: attack.Tactic = @enumFromInt(ci);
                _ = zgui.tableNextColumn();
                if (nthTechniqueOfTactic(tac, row)) |tid| {
                    drawCell(d, s, tid);
                }
            }
        }
        zgui.endTable();
    }
}

fn nthTechniqueOfTactic(tac: attack.Tactic, n: usize) ?attack.TechniqueId {
    var seen: usize = 0;
    for (attack.techniques, 0..) |tech, i| {
        if (tech.tactic != tac) continue;
        if (seen == n) return @intCast(i);
        seen += 1;
    }
    return null;
}

fn drawCell(d: *Dashboard, s: *@import("data").Store, tid: attack.TechniqueId) void {
    const t = ui.theme.default;
    const tech = attack.get(tid);
    const cov = s.coverageForTechnique(tid);
    const heat = s.alertHeatForTechnique(tid);

    const cov_col: [4]f32 = switch (cov) {
        2 => t.sev.ok,
        1 => t.sev.warn,
        else => t.text.lo,
    };
    // Cell background: coverage tint, heat overrides toward crit_dim.
    const bg = if (heat > 0)
        ui.theme.mix(t.sev.crit_dim, t.bg.panel, 0.25)
    else switch (cov) {
        2 => t.sev.ok_dim,
        1 => t.sev.warn_dim,
        else => t.bg.panel,
    };
    zgui.tableSetBgColor(.{ .target = .cell_bg, .color = zgui.colorConvertFloat4ToU32(bg) });

    var lb: [40]u8 = undefined;
    const lbl = std.fmt.bufPrintZ(&lb, "{s}##atk{d}", .{ tech.id, tid }) catch return;
    zgui.pushStyleColor4f(.{ .idx = .text, .c = cov_col });
    const clicked = zgui.selectable(lbl, .{ .selected = d.atk_sel != null and d.atk_sel.? == tid });
    zgui.popStyleColor(.{ .count = 1 });
    if (clicked) {
        d.atk_sel = tid;
        d.rul_technique_filter = tid;
        d.yar_technique_filter = tid; // pre-filter YAR if the analyst tabs over
        d.focusPanel(dash.PANEL_RUL);
    }
    const yara_cov = s.yaraCoverageForTechnique(tid);
    if (zgui.isItemHovered(.{})) {
        if (zgui.beginTooltip()) {
            zgui.text("{s} \u{2014} {s}", .{ tech.id, tech.name });
            zgui.textColored(cov_col, "coverage: {s}", .{switch (cov) {
                2 => @as([]const u8, "enabled rule"),
                1 => "testing only",
                else => "NONE",
            }});
            if (yara_cov > 0) {
                var worst: u8 = 'A';
                for (s.yara.items) |*y| {
                    if (y.technique == tid and y.grade() > worst) worst = y.grade();
                }
                zgui.textColored(t.identity.detect, "YARA: covered (worst grade {c})", .{worst});
            }
            if (heat > 0) zgui.textColored(t.sev.crit, "{d} open alert(s)", .{heat});
            zgui.endTooltip();
        }
    }
    // Name (truncated by column) + YARA marker + heat badge.
    zgui.textColored(t.text.mid, "{s}", .{tech.name});
    if (yara_cov == 2) {
        zgui.sameLine(.{ .spacing = 4 });
        zgui.textColored(t.identity.detect, "Y", .{});
    }
    if (heat > 0) {
        // The heat badge clicks through to the actual alerts in ALQ.
        zgui.sameLine(.{ .spacing = 4 });
        var hb: [24]u8 = undefined;
        const hl = std.fmt.bufPrintZ(&hb, "{d}##atkheat{d}", .{ heat, tid }) catch "n";
        zgui.pushStyleColor4f(.{ .idx = .text, .c = t.sev.crit });
        if (zgui.selectable(hl, .{ .w = 22 })) {
            d.alq_technique_filter = tid;
            d.focusPanel(dash.PANEL_ALQ);
        }
        zgui.popStyleColor(.{ .count = 1 });
        if (zgui.isItemHovered(.{})) {
            if (zgui.beginTooltip()) {
                zgui.textColored(t.text.mid, "open the {d} open alert(s) in ALQ", .{heat});
                zgui.endTooltip();
            }
        }
    }
}
