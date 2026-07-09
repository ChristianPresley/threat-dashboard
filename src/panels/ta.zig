//! TA · Threat Actors: profile list + detail (aliases, motivation,
//! technique chips linking into the ATT&CK matrix, notes).

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const domain = @import("domain");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

pub fn render(d: *Dashboard) void {
    const t = ui.theme.active;
    const s = &d.store;

    if (s.actors.items.len == 0) {
        zgui.textColored(t.text.lo, "No threat actor profiles.", .{});
        return;
    }
    if (d.ta_sel >= s.actors.items.len) d.ta_sel = 0;

    // ── Actor list (left column) ─────────────────────────────────────────
    if (zgui.beginChild("##ta_list", .{ .w = 190 })) {
        for (s.actors.items, 0..) |*a, i| {
            var lb: [64]u8 = undefined;
            const lbl = std.fmt.bufPrintZ(&lb, "{s}##ta{d}", .{ a.name.slice(), i }) catch continue;
            if (zgui.selectable(lbl, .{ .selected = d.ta_sel == i })) {
                d.ta_sel = @intCast(i);
            }
        }
    }
    zgui.endChild();
    zgui.sameLine(.{ .spacing = 12 });

    // ── Detail ───────────────────────────────────────────────────────────
    if (zgui.beginChild("##ta_detail", .{})) {
        const a = &s.actors.items[d.ta_sel];
        zgui.pushFont(ui.fonts.mono_medium, ui.fonts.size.title);
        zgui.textUnformatted(a.name.slice());
        zgui.popFont();
        zgui.textColored(t.text.mid, "aka {s}", .{a.aliases.slice()});
        zgui.textColored(t.text.mid, "motivation: {s}", .{a.motivation.label()});
        zgui.spacing();

        zgui.textColored(t.text.lo, "techniques (click \u{2192} ATK):", .{});
        const chip_pad = zgui.getStyle().frame_padding[0] * 2;
        for (a.techniques[0..a.technique_count], 0..) |tid, i| {
            const tech = domain.attack.get(tid);
            // Wrap by measured width, not count — chips must never clip at
            // the panel edge however narrow the dock slot is.
            if (i != 0) {
                zgui.sameLine(.{ .spacing = 6 });
                const chip_w = zgui.calcTextSize(tech.id, .{})[0] + chip_pad;
                if (zgui.getContentRegionAvail()[0] < chip_w) zgui.newLine();
            }
            var cb: [32]u8 = undefined;
            const chip = std.fmt.bufPrintZ(&cb, "{s}##tat{d}", .{ tech.id, i }) catch continue;
            const covered = s.coverageForTechnique(tid) == 2;
            if (dash.filterChip(chip, covered, if (covered) t.sev.ok else t.sev.warn)) {
                d.atk_sel = tid;
                d.rul_technique_filter = tid;
                d.focusPanel(dash.PANEL_ATK);
            }
            if (zgui.isItemHovered(.{})) {
                if (zgui.beginTooltip()) {
                    zgui.text("{s} \u{00B7} {s} \u{00B7} {s}", .{
                        tech.name, tech.tactic.label(),
                        if (covered) "covered by an enabled rule" else "NOT covered",
                    });
                    zgui.endTooltip();
                }
            }
        }

        zgui.spacing();
        zgui.separator();
        dash.textWrappedColored(t.text.hi, "{s}", .{a.notes.slice()});
    }
    zgui.endChild();
}
