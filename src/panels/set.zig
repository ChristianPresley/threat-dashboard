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
            // Same guard as the SEED command: never stomp a DB-owned Store.
            if (d.mock_ticking) {
                d.regenerateWorld(d.seed +% 1);
            } else {
                ui.events.post(.warn, "world", "regenerate is mock-only \u{2014} the Store is owned by {s}", .{d.provider_label});
            }
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

    if (zgui.collapsingHeader("AI assistant", .{ .default_open = true })) {
        // Read-only status — secrets come from the environment and are
        // never shown or persisted.
        const cfg = &d.assistant.cfg;
        if (cfg.configured()) {
            zgui.textColored(t.sev.ok, "ANTHROPIC_API_KEY: set", .{});
            zgui.textColored(t.text.mid, "model: {s}", .{cfg.model});
            zgui.textColored(t.text.mid, "threat-intel MCP: {s} ({s})", .{
                cfg.mcp_cmd orelse "threatintel-mcp --transport stdio",
                @tagName(d.assistant.mcp_state),
            });
            zgui.textColored(t.text.lo, "open with Ctrl+Shift+A \u{00B7} tools are read-only \u{00B7} intel output stays defanged", .{});
        } else {
            zgui.textColored(t.text.lo, "ANTHROPIC_API_KEY: missing \u{2014} set it and restart to enable the AI panel", .{});
            zgui.textColored(t.text.lo, "optional: TD_AI_MODEL \u{00B7} TD_MCP_CMD \u{00B7} VT_API_KEY \u{00B7} URLSCAN_API_KEY", .{});
        }
    }

    if (zgui.collapsingHeader("About", .{})) {
        zgui.textColored(t.text.mid, "threat-dashboard \u{00B7} Zig + Vulkan + ImGui docking", .{});
        zgui.textColored(t.text.lo, "F1\u{2026}F5 workspaces \u{00B7} Ctrl+K command line \u{00B7} ? directory \u{00B7} Ctrl+Shift+A assistant", .{});
    }
}
