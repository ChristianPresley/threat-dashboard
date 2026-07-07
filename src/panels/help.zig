//! HELP · Directory: registry-generated code directory (grouped, identity-
//! tinted) + the keyboard map sections.

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

pub fn render(d: *Dashboard) void {
    const t = ui.theme.default;

    zgui.textColored(t.text.mid, "Every panel has a CODE \u{2014} type it into the command line (Ctrl+K) and press Enter.", .{});
    zgui.spacing();

    if (zgui.collapsingHeader("Panel directory", .{ .default_open = true })) {
        const flags = zgui.TableFlags{ .borders = .{ .inner_h = true } };
        if (zgui.beginTable("##help_dir", .{ .column = 3, .flags = flags })) {
            zgui.tableSetupColumn("Code", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 64 });
            zgui.tableSetupColumn("Panel", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 170 });
            zgui.tableSetupColumn("Group / workspaces", .{ .flags = .{ .width_stretch = true } });
            zgui.tableHeadersRow();
            for (dash.panels, 0..) |p, i| {
                zgui.tableNextRow(.{});
                _ = zgui.tableNextColumn();
                var cb: [16]u8 = undefined;
                const cl = std.fmt.bufPrintZ(&cb, "{s}##hd{d}", .{ p.code, i }) catch continue;
                zgui.pushStyleColor4f(.{ .idx = .text, .c = dash.groupIdentity(p.group) });
                if (zgui.selectable(cl, .{})) d.focusPanel(i);
                zgui.popStyleColor(.{ .count = 1 });
                _ = zgui.tableNextColumn();
                zgui.textUnformattedColored(t.text.hi, p.name);
                _ = zgui.tableNextColumn();
                // Which workspaces contain it.
                var wsbuf: [64]u8 = undefined;
                var len: usize = 0;
                inline for (0..ui.layout.workspace_count) |wi| {
                    const w: ui.layout.Workspace = @enumFromInt(wi);
                    if (dash.panelInWorkspace(i, w)) {
                        const tag = w.tag();
                        if (len + tag.len + 1 < wsbuf.len) {
                            if (len > 0) {
                                wsbuf[len] = ' ';
                                len += 1;
                            }
                            @memcpy(wsbuf[len .. len + tag.len], tag);
                            len += tag.len;
                        }
                    }
                }
                if (len == 0) {
                    zgui.textColored(t.text.lo, "{s} \u{00B7} opens by code (floats)", .{p.group});
                } else {
                    zgui.textColored(t.text.lo, "{s} \u{00B7} {s}", .{ p.group, wsbuf[0..len] });
                }
            }
            zgui.endTable();
        }
    }

    if (zgui.collapsingHeader("Keyboard map", .{ .default_open = true })) {
        inline for (dash.keymap_sections) |section| {
            zgui.textColored(t.accent, "{s}", .{section.title});
            const flags = zgui.TableFlags{ .borders = .{ .inner_h = true } };
            var idb: [48]u8 = undefined;
            const table_id = std.fmt.bufPrintZ(&idb, "##help_keys_{s}", .{section.title}) catch "##hk";
            if (zgui.beginTable(table_id, .{ .column = 2, .flags = flags })) {
                zgui.tableSetupColumn("Chord", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 210 });
                zgui.tableSetupColumn("Action", .{ .flags = .{ .width_stretch = true } });
                for (section.keys) |kb| {
                    zgui.tableNextRow(.{});
                    _ = zgui.tableNextColumn();
                    zgui.textColored(t.amber, "{s}", .{kb.chord});
                    _ = zgui.tableNextColumn();
                    zgui.textUnformattedColored(t.text.mid, kb.action);
                }
                zgui.endTable();
            }
            zgui.spacing();
        }
    }

    if (zgui.collapsingHeader("Command grammar", .{})) {
        zgui.textColored(t.text.mid, "CODE \u{2192} focus/open that panel (ALQ, EVT, RUL\u{2026})", .{});
        zgui.textColored(t.text.mid, "WORKSPACE \u{2192} switch (TRIAGE, HUNT, DETECT, INTEL, OPS)", .{});
        zgui.textColored(t.text.mid, "verbs \u{2192} RESET \u{00B7} SNAP \u{00B7} SEED \u{00B7} DEMO", .{});
        zgui.textColored(t.text.lo, "fuzzy search works too \u{2014} type part of a name and Enter runs the top match.", .{});
    }
}
