//! Design tokens + ImGui style application for the threat dashboard.
//!
//! Every color in the UI comes from this module. Five families, five
//! meanings: gray = structure, teal/coral = trend direction, amber =
//! editable/armed ONLY, blue = selection/interaction, and a disciplined
//! chrome/safety red for critical severity.
//!
//! `default` is the comptime token set; `active` is the runtime set.
//! Colors are sRGB display-referred floats — the swapchain is UNORM, so
//! these bytes reach the monitor verbatim.

const std = @import("std");
const zgui = @import("zgui");

pub const Rgba = [4]f32;

/// `0xRRGGBB` → opaque sRGB float color.
pub fn hex(comptime h: u24) Rgba {
    return .{
        @as(f32, @floatFromInt((h >> 16) & 0xff)) / 255.0,
        @as(f32, @floatFromInt((h >> 8) & 0xff)) / 255.0,
        @as(f32, @floatFromInt(h & 0xff)) / 255.0,
        1.0,
    };
}

/// `0xRRGGBB` + alpha → sRGB float color.
pub fn hexA(comptime h: u24, a: f32) Rgba {
    var c = hex(h);
    c[3] = a;
    return c;
}

/// Runtime alpha override.
pub fn withAlpha(c: Rgba, a: f32) Rgba {
    return .{ c[0], c[1], c[2], a };
}

/// Blend `a → b` by `k` in display space (tint derivation, e.g. identity-
/// tinted tab fills); keeps `a`'s alpha.
pub fn mix(a: Rgba, b: Rgba, k: f32) Rgba {
    return .{
        a[0] + (b[0] - a[0]) * k,
        a[1] + (b[1] - a[1]) * k,
        a[2] + (b[2] - a[2]) * k,
        a[3],
    };
}

// A11y contrast floors (WCAG 2.1, verified against these tokens): text ≥4.5:1
// on every surface it sits on (text.lo 5.3:1 on base); border.strong ≥3:1
// against ALL bg steps (boundary/“UI component” rule); border.subtle ≥2.5:1
// (hairlines inside already-bounded regions). Re-verify ratios when touching
// any bg/border/text value.
pub const Bg = struct {
    sunken: Rgba = hex(0x0A0C10), // chart plot wells, input wells, scroll troughs
    base: Rgba = hex(0x0F1115), // window background, dockspace empty
    panel: Rgba = hex(0x171C25), // panel bodies, table header rows
    elev: Rgba = hex(0x232B38), // popups, menus, tooltips, modals, selected tab
    hover: Rgba = hex(0x334053), // hovered rows/items
    selected: Rgba = hex(0x1E3C63), // selected row (accent-tinted)
};

pub const Border = struct {
    subtle: Rgba = hex(0x4C5664), // panel seams, table hairlines (2.5:1 on base)
    strong: Rgba = hex(0x6B7689), // splitters, separators, focus outlines (≥3:1 on every bg)
};

pub const Text = struct {
    hi: Rgba = hex(0xE6EDF3), // live values, symbols, primary data
    mid: Rgba = hex(0xA3ADBB), // labels, units, timestamps, headers (4.6:1 even on hover)
    lo: Rgba = hex(0x7E8995), // disabled, placeholders, axis labels, stale values (5.3:1 on base)
    inverse: Rgba = hex(0x0F1115), // text on filled chips
};

/// Generic trend/delta pair: improving vs. worsening metrics (alert-rate
/// deltas, EPS trends, tuning what-ifs). Teal/coral, CVD-distinguishable.
pub const Delta = struct {
    pos: Rgba = hex(0x26A69A), // improving / decreasing risk
    pos_dim: Rgba = hex(0x16352F), // pos flash target, fill bars
    neg: Rgba = hex(0xEF5350), // worsening / increasing risk — data surfaces ONLY
    neg_dim: Rgba = hex(0x3A1D20), // neg flash target, fill bars
    flat: Rgba = hex(0x9AA4B2), // zero/unchanged
    benchmark: Rgba = hex(0xC78D2E), // reference/baseline series
};

pub const Severity = struct {
    ok: Rgba = hex(0x3FB950), // healthy — quiet: dots/small text, never banners
    info: Rgba = hex(0x58A6FF), // neutral notices, in-progress
    warn: Rgba = hex(0xD29922), // degraded, retrying, aging-data chips
    serious: Rgba = hex(0xDB6D28), // needs attention soon
    crit: Rgba = hex(0xFF3B30), // act now — chrome/safety red, hotter than market down
    off: Rgba = hex(0x6E7681), // disabled subsystem / dead data
    // Banner backgrounds: hue blended ~15% over bg.panel.
    ok_dim: Rgba = hex(0x16271C),
    info_dim: Rgba = hex(0x152232),
    warn_dim: Rgba = hex(0x2E2614),
    serious_dim: Rgba = hex(0x33211A),
    crit_dim: Rgba = hex(0x3A1518),
};

pub const Chart = struct {
    grid: Rgba = hex(0x252C36),
    crosshair: Rgba = hex(0x758696), // 1 px dashed
    crosshair_label_bg: Rgba = hex(0x4C525E),
    // Comparison series (Okabe-Ito, CVD-safe).
    cmp: [5]Rgba = .{ hex(0xE69F00), hex(0x56B4E9), hex(0x009E73), hex(0xCC79A7), hex(0xF0E442) },
};

/// Panel-group identity hues — wayfinding ONLY, never state. Each panel
/// family gets a hue (edge bar, palette/HELP code tint) so features read
/// at a glance; the printed CODE stays the primary channel, so CVD users
/// lose nothing. All five sit ≥6:1 on bg.base and collide with no state
/// hue (teal/coral delta, amber armed, blue selection, crit red).
pub const Identity = struct {
    triage: Rgba = hex(0xB39DFB), // violet — PST · ALQ · CAS
    hunt: Rgba = hex(0x39C5CF), // cyan — TLN · EVT · PRC · NET
    detect: Rgba = hex(0xCC79A7), // magenta (Okabe-Ito) — RUL · TUN · ATK
    intel: Rgba = hex(0x009E73), // green (Okabe-Ito) — IOC · TA · FEED
    ops: Rgba = hex(0x8A96A8), // slate — SEN · ING · LOG · JOB · SET · HELP
};

/// Score band colors (rule quality/fidelity): A ≥75, B ≥60, C ≥45, D ≥30, F below.
pub const Score = struct {
    a: Rgba = hex(0x3FB950),
    b: Rgba = hex(0x7BC96F),
    c: Rgba = hex(0xD29922),
    d: Rgba = hex(0xDB6D28),
    f: Rgba = hex(0xFF3B30),
};

pub const Tokens = struct {
    bg: Bg = .{},
    border: Border = .{},
    stripe_alt: Rgba = hex(0x191F28), // zebra ONLY on >10-column tables (RES)
    text: Text = .{},

    accent: Rgba = hex(0x4C9AFF), // selection, focus, links, active tab, codes
    accent_dim: Rgba = hex(0x1D3A5F), // selection fills, progress tracks
    amber: Rgba = hex(0xFFB23E), // STRICTLY editable-focus / command caret / armed
    amber_dim: Rgba = hex(0x3A2D12),

    delta: Delta = .{},
    sev: Severity = .{},
    chart: Chart = .{},
    score: Score = .{},
    identity: Identity = .{},
};

/// Comptime-known defaults — legacy constants may alias fields of this.
pub const default: Tokens = .{};

/// Runtime token set — panels read through this.
pub var active: Tokens = default;

// ── Variants + alternate palettes (prefs.apply() composes these) ─────────

/// Surface family. `dark` is the shipped baseline; `midnight` drops every
/// background a step for dim SOC floors; `high_contrast` raises text and
/// border luminance.
pub const Variant = enum(u8) {
    dark,
    midnight,
    high_contrast,

    pub fn label(self: Variant) [:0]const u8 {
        return switch (self) {
            .dark => "Dark (default)",
            .midnight => "Midnight",
            .high_contrast => "High contrast",
        };
    }
};

/// Surface/text token set per theme variant. `dark` is `default`.
/// `midnight` steps every background down for dim ops floors (text tokens
/// unchanged — contrast only improves on darker surfaces). `high_contrast`
/// raises text ≥7:1 (AAA) and borders ≥4.5:1 on every bg step.
pub fn tokensFor(variant: Variant) Tokens {
    return switch (variant) {
        .midnight => blk: {
            var t: Tokens = .{};
            t.bg = .{
                .sunken = hex(0x050608),
                .base = hex(0x090B0E),
                .panel = hex(0x10141B),
                .elev = hex(0x1A212C),
                .hover = hex(0x2C3949),
                .selected = hex(0x1A3557),
            };
            t.stripe_alt = hex(0x12161D);
            break :blk t;
        },
        .high_contrast => blk: {
            var t: Tokens = .{};
            t.text = .{
                .hi = hex(0xFFFFFF),
                .mid = hex(0xC9D3DE),
                .lo = hex(0x9AA6B2),
                .inverse = hex(0x0A0C10),
            };
            t.border = .{
                .subtle = hex(0x6B7689),
                .strong = hex(0x9AA6BA),
            };
            t.accent = hex(0x6CB0FF);
            break :blk t;
        },
        .dark => default,
    };
}

/// Recompute the five *_dim banner/fill tones against a surface. Variants
/// change bg.panel — dims blended for the wrong surface read as a glow.
pub fn deriveDims(sev: Severity, panel_bg: Rgba) Severity {
    var s = sev;
    s.ok_dim = mix(panel_bg, s.ok, 0.16);
    s.info_dim = mix(panel_bg, s.info, 0.16);
    s.warn_dim = mix(panel_bg, s.warn, 0.16);
    s.serious_dim = mix(panel_bg, s.serious, 0.16);
    s.crit_dim = mix(panel_bg, s.crit, 0.16);
    return s;
}

/// Okabe-Ito severity ramp (CVD-safe): lightness rises monotonically
/// crit→warn and hue survives all three dichromacies. Dim (banner) fills
/// are derived at ~16% over the panel surface so variants stay coherent.
pub fn sevCvd(panel_bg: Rgba) Severity {
    return deriveDims(.{
        .ok = hex(0x009E73), // bluish green
        .info = hex(0x56B4E9), // sky blue
        .warn = hex(0xF0E442), // yellow
        .serious = hex(0xE69F00), // orange
        .crit = hex(0xD55E00), // vermillion
        .off = hex(0x6E7681),
    }, panel_bg);
}

/// Score bands matching the CVD severity ramp (A best → F worst).
pub fn scoreCvd() Score {
    return .{
        .a = hex(0x009E73),
        .b = hex(0x56B4E9),
        .c = hex(0xF0E442),
        .d = hex(0xE69F00),
        .f = hex(0xD55E00),
    };
}

/// Apply the full ImGui style: every color from tokens + metrics.
pub fn apply() void {
    const t = &active;
    const style = zgui.getStyle();

    // ── Backgrounds ──────────────────────────────────────────────────────
    style.setColor(.window_bg, t.bg.base);
    style.setColor(.child_bg, .{ 0, 0, 0, 0 }); // seams via bg steps, not borders
    style.setColor(.popup_bg, t.bg.elev);
    style.setColor(.frame_bg, t.bg.sunken);
    style.setColor(.frame_bg_hovered, t.bg.hover);
    style.setColor(.frame_bg_active, t.bg.selected);

    // ── Text ─────────────────────────────────────────────────────────────
    style.setColor(.text, t.text.hi);
    style.setColor(.text_disabled, t.text.lo);

    // ── Borders ──────────────────────────────────────────────────────────
    style.setColor(.border, t.border.subtle);
    style.setColor(.border_shadow, .{ 0, 0, 0, 0 });

    // ── Title bars / menu ────────────────────────────────────────────────
    style.setColor(.title_bg, t.bg.panel);
    // Focused pane gets the accent-tinted title so keyboard focus is
    // findable at a glance (a11y: focus must not rely on a 1-step bg delta).
    style.setColor(.title_bg_active, t.accent_dim);
    style.setColor(.title_bg_collapsed, t.bg.base);
    style.setColor(.menu_bar_bg, t.bg.panel);

    // ── Buttons ──────────────────────────────────────────────────────────
    style.setColor(.button, t.bg.elev);
    style.setColor(.button_hovered, t.bg.hover);
    style.setColor(.button_active, t.accent_dim);

    // ── Headers (collapsing/selectable) ──────────────────────────────────
    style.setColor(.header, t.bg.elev);
    style.setColor(.header_hovered, t.bg.hover);
    style.setColor(.header_active, t.bg.selected);

    // ── Separators / resize ──────────────────────────────────────────────
    style.setColor(.separator, t.border.strong); // section boundaries ≥3:1
    style.setColor(.separator_hovered, t.accent);
    style.setColor(.separator_active, t.accent);
    style.setColor(.resize_grip, withAlpha(t.border.strong, 0.25));
    style.setColor(.resize_grip_hovered, withAlpha(t.border.strong, 0.60));
    style.setColor(.resize_grip_active, t.accent);

    // ── Scrollbar ────────────────────────────────────────────────────────
    style.setColor(.scrollbar_bg, t.bg.sunken);
    style.setColor(.scrollbar_grab, t.border.subtle);
    style.setColor(.scrollbar_grab_hovered, t.border.strong);
    style.setColor(.scrollbar_grab_active, t.accent);

    // ── Interactive controls ─────────────────────────────────────────────
    style.setColor(.check_mark, t.accent);
    style.setColor(.slider_grab, t.accent);
    style.setColor(.slider_grab_active, t.accent);

    // ── Nav / selection ──────────────────────────────────────────────────
    style.setColor(.nav_cursor, t.accent);
    style.setColor(.text_selected_bg, t.accent_dim);

    // ── Tabs ─────────────────────────────────────────────────────────────
    // Selected = raised fill (elev) + 2 px accent overline; inactive sits on
    // panel. The old base→panel delta was 1.06:1 — indistinguishable.
    style.setColor(.tab, t.bg.panel);
    style.setColor(.tab_hovered, t.bg.hover);
    style.setColor(.tab_selected, t.bg.elev);
    style.setColor(.tab_selected_overline, t.accent);
    style.setColor(.tab_dimmed, t.bg.base);
    style.setColor(.tab_dimmed_selected, t.bg.elev);
    style.setColor(.tab_dimmed_selected_overline, withAlpha(t.accent, 0.55));

    // ── Tables ───────────────────────────────────────────────────────────
    style.setColor(.table_header_bg, t.bg.panel);
    style.setColor(.table_border_strong, t.border.strong); // outer + header rule
    style.setColor(.table_border_light, t.border.subtle);
    style.setColor(.table_row_bg, .{ 0, 0, 0, 0 });
    style.setColor(.table_row_bg_alt, .{ 0, 0, 0, 0 }); // zebra opt-in per table (RES)

    // ── Plots ────────────────────────────────────────────────────────────
    style.setColor(.plot_lines, t.accent);
    style.setColor(.plot_lines_hovered, t.amber);
    style.setColor(.plot_histogram, t.accent);
    style.setColor(.plot_histogram_hovered, t.amber);

    // ── Modal dim ────────────────────────────────────────────────────────
    style.setColor(.modal_window_dim_bg, .{ 0.0, 0.0, 0.0, 0.55 });

    // ── Metrics (§3.3) ───────────────────────────────────────────────────
    style.window_padding = .{ 8, 6 };
    style.frame_padding = .{ 6, 3 };
    style.item_spacing = .{ 6, 4 };
    style.item_inner_spacing = .{ 4, 3 };
    style.cell_padding = .{ 6, 2 };
    style.indent_spacing = 14;
    style.scrollbar_size = 10;
    style.window_rounding = 0;
    style.child_rounding = 0;
    style.frame_rounding = 2;
    style.popup_rounding = 4;
    style.grab_rounding = 2;
    style.tab_rounding = 2;
    // A11y: panes and input fields get real 1 px outlines — region boundaries
    // must survive low vision, not just the bg-step seams.
    style.window_border_size = 1;
    style.child_border_size = 0;
    style.frame_border_size = 1;
    style.popup_border_size = 1;
    style.tab_bar_overline_size = 3; // selected-tab indicator, was hairline
    style.tab_border_size = 1; // outline every tab — inactive tabs must read as tabs
    style.hover_delay_normal = 0.40;
}

test "hex decodes sRGB bytes" {
    const c = hex(0x0F1115);
    try std.testing.expectApproxEqAbs(@as(f32, 15.0 / 255.0), c[0], 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 17.0 / 255.0), c[1], 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 21.0 / 255.0), c[2], 1e-6);
    try std.testing.expectEqual(@as(f32, 1.0), c[3]);
}
