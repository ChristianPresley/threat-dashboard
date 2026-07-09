//! SET · Settings: deep, live-applying customization (2026-07 settings
//! program — every control takes effect the frame it changes and persists
//! via ui_state.json).
//!
//! Sections: Appearance · Time & tables · Notifications · Motion &
//! accessibility · Triage SLA · Data & world · AI assistant · Startup &
//! layout · About. A filter box narrows sections by name (the settings
//! surface follows the same Ctrl+F muscle memory as every table panel).

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

var filter_buf: [48:0]u8 = std.mem.zeroes([48:0]u8);

/// Deferred-save latch: apply() is cheap enough to run per drag frame, but
/// saveUiState() is a file write — dragging a slider must not rename
/// ui_state.json 60×/s. Set by changed(), flushed at the end of render()
/// once no widget is active.
var save_pending: bool = false;

/// Section gate: with a filter active, only matching sections render (and
/// render open). Returns whether the section body should draw.
fn section(name: [:0]const u8, keywords: []const u8, default_open: bool) bool {
    const f = std.mem.sliceTo(&filter_buf, 0);
    if (f.len > 0) {
        var hay_buf: [160]u8 = undefined;
        const hay = std.fmt.bufPrint(&hay_buf, "{s} {s}", .{ name, keywords }) catch name;
        if (std.ascii.indexOfIgnoreCase(hay, f) == null) return false;
        zgui.setNextItemOpen(.{ .is_open = true });
        return zgui.collapsingHeader(name, .{});
    }
    return zgui.collapsingHeader(name, .{ .default_open = default_open });
}

/// Post-change hook: apply at the top of the NEXT frame (a mid-frame
/// style rewrite tears the frame), persist once the interaction ends.
fn changed(d: *Dashboard) void {
    _ = d;
    ui.prefs.apply_pending = true;
    save_pending = true;
}

/// One combo per preference enum: every variant exposes label(), selection
/// writes through and queues apply+save. Keeps the five combos identical.
fn enumCombo(comptime E: type, label: [:0]const u8, val: *E, d: *Dashboard) void {
    zgui.setNextItemWidth(260);
    if (zgui.beginCombo(label, .{ .preview_value = val.label() })) {
        inline for (@typeInfo(E).@"enum".fields) |f| {
            const v: E = @enumFromInt(f.value);
            if (zgui.selectable(v.label(), .{ .selected = val.* == v })) {
                val.* = v;
                changed(d);
            }
        }
        zgui.endCombo();
    }
}

pub fn render(d: *Dashboard) void {
    const t = ui.theme.active;
    const p = &ui.prefs.current;

    // ── Header: filter + reset all ───────────────────────────────────────
    if (d.set_focus_filter and zgui.isWindowFocused(.{ .root_window = true, .child_windows = true })) {
        d.set_focus_filter = false;
        zgui.setKeyboardFocusHere(0);
    }
    zgui.setNextItemWidth(220);
    _ = zgui.inputTextWithHint("##set_filter", .{ .hint = "filter settings (Ctrl+F)", .buf = &filter_buf });
    zgui.sameLine(.{ .spacing = 10 });
    if (zgui.smallButton("Reset ALL to defaults##set")) {
        ui.prefs.current = .{};
        ui.prefs.apply_pending = true; // applied at next frame start
        save_pending = true;
        ui.events.post(.ok, "settings", "all preferences reset to shipped defaults", .{});
    }
    zgui.sameLine(.{ .spacing = 8 });
    zgui.textColored(t.text.lo, "changes apply instantly and persist", .{});
    zgui.spacing();

    // ── Appearance ───────────────────────────────────────────────────────
    if (section("Appearance", "theme dark midnight contrast color palette severity colorblind cvd font scale size density row height", true)) {
        enumCombo(ui.theme.Variant, "theme##set_theme", &p.theme_variant, d);
        zgui.sameLine(.{ .spacing = 8 });
        zgui.textColored(t.text.lo, "midnight = dim SOC floor \u{00B7} high contrast = AAA text", .{});

        // Severity palette + live swatch preview.
        enumCombo(ui.prefs.SevPalette, "severity palette##set_pal", &p.sev_palette, d);
        zgui.sameLine(.{ .spacing = 8 });
        // Swatches render from the ACTIVE tokens, so this row IS the
        // preview; grouped so the tooltip covers the whole row.
        const sw = [_]struct { name: [:0]const u8, c: [4]f32 }{
            .{ .name = "CRIT", .c = t.sev.crit },
            .{ .name = "HIGH", .c = t.sev.serious },
            .{ .name = "MED", .c = t.sev.warn },
            .{ .name = "INFO", .c = t.sev.info },
            .{ .name = "OK", .c = t.sev.ok },
        };
        zgui.beginGroup();
        inline for (sw, 0..) |s, i| {
            if (i > 0) zgui.sameLine(.{ .spacing = 6 });
            zgui.textColored(s.c, "\u{25A0} {s}", .{s.name});
        }
        zgui.endGroup();
        if (zgui.isItemHovered(.{})) {
            if (zgui.beginTooltip()) {
                zgui.text("Okabe-Ito ramp survives deuteranopia/protanopia/tritanopia;\nseverity always prints its label too \u{2014} color is never the only channel.", .{});
                zgui.endTooltip();
            }
        }

        // Font scale.
        zgui.setNextItemWidth(260);
        var scale_pct: f32 = p.font_scale * 100.0;
        if (zgui.sliderFloat("font scale##set_fs", .{ .v = &scale_pct, .min = 85, .max = 200, .cfmt = "%.0f%%" })) {
            p.font_scale = scale_pct / 100.0;
            changed(d);
        }
        zgui.sameLine(.{ .spacing = 8 });
        zgui.textColored(t.text.lo, "up to 200% (WCAG 1.4.4)", .{});

        enumCombo(ui.prefs.Density, "density##set_den", &p.density, d);
        zgui.sameLine(.{ .spacing = 8 });
        zgui.textColored(t.text.lo, "comfortable reaches \u{2265}24px hit targets (WCAG 2.5.8)", .{});
    }

    // ── Time & tables ────────────────────────────────────────────────────
    if (section("Time & tables", "timestamp utc local relative timezone clock age defang copy clipboard ioc", true)) {
        enumCombo(ui.fmt.TimeStyle, "timestamps##set_ts", &p.time_style, d);
        zgui.sameLine(.{ .spacing = 8 });
        var ex1: [16]u8 = undefined;
        zgui.textColored(t.text.lo, "a 4-min-old row shows \u{201C}{s}\u{201D} \u{00B7} local offset {d} min", .{
            ui.fmt.ts(&ex1, ui.fmt.now_ts - 245),
            ui.fmt.local_offset_min,
        });
        zgui.pushTextWrapPos(0);
        zgui.textColored(t.text.lo, "UTC is the SOC convention \u{2014} cross-timezone timelines need one reference. CSV exports stay UTC regardless.", .{});
        zgui.popTextWrapPos();

        var dfc = p.defang_copy;
        if (zgui.checkbox("defang IOC values on copy##set_dfc", .{ .v = &dfc })) {
            p.defang_copy = dfc;
            changed(d);
        }
        zgui.sameLine(.{ .spacing = 8 });
        zgui.textColored(t.text.lo, "hxxps://x[.]y in the clipboard \u{2014} a ticket paste can never be a live link", .{});
    }

    // ── Notifications ────────────────────────────────────────────────────
    if (section("Notifications", "toast duration dnd do not disturb quiet severity alert fatigue popup", true)) {
        zgui.setNextItemWidth(260);
        var secs = p.toast_secs;
        if (zgui.sliderFloat("toast duration##set_toast", .{ .v = &secs, .min = 2, .max = 30, .cfmt = "%.0f s" })) {
            p.toast_secs = secs;
            changed(d);
        }
        zgui.sameLine(.{ .spacing = 8 });
        zgui.textColored(t.text.lo, "warnings show 2\u{00D7} \u{00B7} hover pauses \u{00B7} all kept in LOG", .{});

        zgui.setNextItemWidth(260);
        const floor_names = [_][:0]const u8{ "everything (ok+)", "info and up", "warnings only" };
        if (zgui.beginCombo("toast floor##set_floor", .{ .preview_value = floor_names[p.toast_min_sev] })) {
            for (floor_names, 0..) |nm, i| {
                if (zgui.selectable(nm, .{ .selected = p.toast_min_sev == i })) {
                    p.toast_min_sev = @intCast(i);
                    changed(d);
                }
            }
            zgui.endCombo();
        }
        zgui.sameLine(.{ .spacing = 8 });
        zgui.textColored(t.text.lo, "below the floor \u{2192} LOG only (alert-fatigue control)", .{});

        var dnd = p.dnd;
        if (zgui.checkbox("do not disturb \u{2014} no toasts at all##set_dnd", .{ .v = &dnd })) {
            p.dnd = dnd;
            changed(d);
        }
        zgui.sameLine(.{ .spacing = 8 });
        zgui.textColored(t.text.lo, "serious/crit still raise the banner \u{2014} safety messaging is exempt", .{});

        if (zgui.smallButton("Send a test toast##set")) {
            ui.events.post(.info, "settings", "test toast \u{2014} this is what {d:.0}s feels like", .{p.toast_secs});
        }
        // The test posts .info — say so when the analyst's own gates would
        // swallow it, or the button looks broken.
        if (p.dnd) {
            zgui.sameLine(.{ .spacing = 8 });
            zgui.textColored(t.sev.warn, "DND is on \u{2014} the test lands in LOG only (that's the setting working)", .{});
        } else if (p.toast_min_sev > 1) {
            zgui.sameLine(.{ .spacing = 8 });
            zgui.textColored(t.sev.warn, "floor is warnings-only \u{2014} an info test lands in LOG only", .{});
        }
    }

    // ── Motion & accessibility ───────────────────────────────────────────
    if (section("Motion & accessibility", "reduced motion flash animation a11y wcag keyboard focus contrast screen reader", true)) {
        var rm = p.reduced_motion;
        if (zgui.checkbox("reduced motion \u{2014} disable value/insert flashes##set_rm", .{ .v = &rm })) {
            p.reduced_motion = rm;
            changed(d);
        }
        zgui.sameLine(.{ .spacing = 8 });
        zgui.textColored(t.text.lo, "WCAG 2.3.3 \u{00B7} changes land instantly, minus the tint", .{});

        var ring = p.focus_ring_always;
        if (zgui.checkbox("always show the keyboard focus ring##set_ring", .{ .v = &ring })) {
            p.focus_ring_always = ring;
            changed(d);
        }
        zgui.sameLine(.{ .spacing = 8 });
        zgui.textColored(t.text.lo, "WCAG 2.4.7 \u{00B7} the ring survives mouse use \u{2014} for keyboard-first triage", .{});

        zgui.spacing();
        zgui.textColored(t.text.mid, "built-in, always on:", .{});
        zgui.bulletText("full keyboard operation \u{2014} Ctrl+K commands, F1\u{2026}F5, \u{2191}\u{2193}/Enter row nav, Ctrl+F filters (see HELP)", .{});
        zgui.bulletText("text \u{2265}4.5:1 and boundaries \u{2265}3:1 on every surface (verified per theme)", .{});
        zgui.bulletText("severity is never color-only \u{2014} every chip prints its label", .{});
        zgui.bulletText("toasts pause on hover and persist in LOG (WCAG 2.2.1)", .{});
        zgui.pushTextWrapPos(0);
        zgui.textColored(t.text.lo, "honest gap: ImGui exposes no OS accessibility tree \u{2014} screen readers can't see this UI. LOG's Ctrl+E CSV export is the plain-text escape hatch.", .{});
        zgui.popTextWrapPos();
    }

    // ── Triage SLA ───────────────────────────────────────────────────────
    if (section("Triage SLA", "mtta mttr sla target posture response acknowledge", false)) {
        zgui.setNextItemWidth(260);
        var mtta = p.sla_mtta_min;
        if (zgui.sliderFloat("MTTA target##set_mtta", .{ .v = &mtta, .min = 1, .max = 240, .cfmt = "%.0f min" })) {
            p.sla_mtta_min = mtta;
            changed(d);
        }
        zgui.setNextItemWidth(260);
        var mttr = p.sla_mttr_hours;
        if (zgui.sliderFloat("MTTR target##set_mttr", .{ .v = &mttr, .min = 0.5, .max = 72, .cfmt = "%.1f h" })) {
            p.sla_mttr_hours = mttr;
            changed(d);
        }
        zgui.textColored(t.text.lo, "PST colors its MTTA/MTTR tiles against these: ok \u{2264} target \u{00B7} amber \u{2264} 2\u{00D7} \u{00B7} red beyond", .{});
    }

    // ── Data & world ─────────────────────────────────────────────────────
    if (section("Data & world", "seed mock provider postgres pause refresh freeze regenerate", true)) {
        zgui.textColored(t.text.mid, "provider: {s}", .{d.provider_label});
        var paused = d.data_paused;
        if (zgui.checkbox("pause data refresh (Ctrl+P)##set_pause", .{ .v = &paused })) {
            d.togglePause();
        }
        zgui.sameLine(.{ .spacing = 8 });
        zgui.textColored(t.text.lo, "rows stop moving during evidence capture \u{00B7} panel actions still write", .{});

        zgui.textColored(t.text.mid, "seed {d} \u{00B7} {d} events \u{00B7} {d} alerts \u{00B7} {d} rules \u{00B7} {d} IOCs", .{
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
        if (d.mock_ticking) {
            zgui.textColored(t.text.lo, "launch with --pg <conn-uri> to read a PostgreSQL world (seed one with the pgload subcommand).", .{});
        } else {
            zgui.textColored(t.text.lo, "panel actions (ack / rule toggles / case moves) write back to the database immediately.", .{});
        }
    }

    // ── AI assistant ─────────────────────────────────────────────────────
    if (section("AI assistant", "claude anthropic api key mcp model enable disable compliance", true)) {
        var ai_on = p.ai_enabled;
        if (zgui.checkbox("enable the AI assistant##set_ai", .{ .v = &ai_on })) {
            p.ai_enabled = ai_on;
            changed(d);
            if (!ai_on) {
                // Hard-off must also stop an in-flight agentic run — the
                // cancel flag aborts it at the next loop boundary.
                if (d.assistant.worker) |w| w.cancel();
                ui.events.post(.info, "settings", "AI assistant disabled \u{2014} new requests blocked, in-flight run canceled", .{});
            }
        }
        zgui.sameLine(.{ .spacing = 8 });
        zgui.textColored(t.text.lo, "blocks new requests + cancels any in-flight run", .{});

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

    // ── Startup & layout ─────────────────────────────────────────────────
    if (section("Startup & layout", "workspace boot launch default reset save autosave", false)) {
        enumCombo(ui.prefs.StartupWs, "startup workspace##set_sw", &p.startup_ws, d);
        zgui.sameLine(.{ .spacing = 8 });
        zgui.textColored(t.text.lo, "\u{201C}last used\u{201D} restores whatever was open at exit", .{});

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
        zgui.textColored(t.text.lo, "layout.ini + ui_state.json live in --state-dir (default: cwd) \u{00B7} layout autosaves after changes", .{});
    }

    // ── About ────────────────────────────────────────────────────────────
    if (section("About", "version keyboard help", false)) {
        zgui.textColored(t.text.mid, "threat-dashboard \u{00B7} Zig + Vulkan + ImGui docking", .{});
        zgui.textColored(t.text.lo, "F1\u{2026}F5 workspaces \u{00B7} Ctrl+K command line \u{00B7} ? directory \u{00B7} Ctrl+Shift+A assistant \u{00B7} Ctrl+P pause", .{});
    }

    // Deferred persistence: one write when the drag/click ends, not per frame.
    if (save_pending and !zgui.isAnyItemActive()) {
        save_pending = false;
        d.saveUiState();
    }
}
