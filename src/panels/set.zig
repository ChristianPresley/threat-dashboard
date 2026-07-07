//! SET · Settings: mock-world seed, persistence paths, layout resets.

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

pub fn render(d: *Dashboard) void {
    const t = ui.theme.default;

    if (zgui.collapsingHeader("Mock world", .{ .default_open = true })) {
        zgui.textColored(t.text.mid, "seed: {d} \u{00B7} {d} events \u{00B7} {d} alerts \u{00B7} {d} rules \u{00B7} {d} IOCs", .{
            d.seed,
            d.store.events.items.len,
            d.store.alerts.items.len,
            d.store.rules.items.len,
            d.store.iocs.items.len,
        });
        if (zgui.smallButton("Regenerate with next seed##set")) {
            d.regenerateWorld(d.seed +% 1);
        }
        zgui.sameLine(.{ .spacing = 8 });
        zgui.textColored(t.text.lo, "same seed \u{21D2} identical world (launch with --seed <n>)", .{});
    }

    if (zgui.collapsingHeader("Layout", .{ .default_open = true })) {
        if (zgui.smallButton("Reset ACTIVE workspace##set")) {
            ui.layout.requestReset();
            ui.events.post(.info, "layout", "workspace preset rebuild queued", .{});
        }
        zgui.sameLine(.{ .spacing = 8 });
        if (zgui.smallButton("Save layout now (Ctrl+S)##set")) {
            ui.layout.saveNow();
            d.saveUiState();
            ui.events.post(.ok, "layout", "layout + UI state saved", .{});
        }
        zgui.textColored(t.text.lo, "layout.ini + ui_state.json live in --state-dir (default: cwd)", .{});
    }

    if (zgui.collapsingHeader("Data providers", .{ .default_open = true })) {
        zgui.textColored(t.text.mid, "active: {s}", .{d.provider_label});
        if (d.mock_ticking) {
            zgui.textColored(t.text.lo, "launch with --pg <conn-uri> to read a PostgreSQL world (seed one with the pgload subcommand); panels read the same Store either way.", .{});
        } else {
            zgui.textColored(t.text.lo, "panel actions (ack / rule toggles / case moves) write back to the database immediately.", .{});
        }
    }

    if (zgui.collapsingHeader("About", .{})) {
        zgui.textColored(t.text.mid, "threat-dashboard \u{00B7} Zig + Vulkan + ImGui docking", .{});
        zgui.textColored(t.text.lo, "F1\u{2026}F5 workspaces \u{00B7} Ctrl+K command line \u{00B7} ? directory", .{});
    }
}
