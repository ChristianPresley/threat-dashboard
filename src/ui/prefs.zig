//! User preferences (SET panel): appearance, density, severity palette,
//! timestamps, notifications, motion, SLA targets. One struct, one apply().
//!
//! Design rules (research-backed, 2026-07-08 settings audit):
//! - Instant apply, no restart — every setting takes effect the frame it
//!   changes (apply() pushes values into theme/flash/events/fmt/zgui).
//! - Persistence rides ui_state.json (additive fields, old files parse).
//! - A11y first-class: CVD-safe severity palette (Okabe-Ito), reduced
//!   motion (WCAG 2.3.3), adjustable toast timing (WCAG 2.2.1), density
//!   step with ≥24 px hit targets (WCAG 2.5.8), 200% font scale (1.4.4).

const std = @import("std");
const zgui = @import("zgui");
const theme = @import("theme.zig");
const flash = @import("flash.zig");
const events = @import("events.zig");
const fmt = @import("fmt.zig");

/// Surface family — see theme.Variant.
pub const ThemeVariant = theme.Variant;

/// Severity hue set. `standard` is the shipped ramp (chrome red crit);
/// `cvd` is Okabe-Ito with monotonic lightness so critical→info stays
/// ordered under deuteranopia/protanopia/tritanopia. Severity is never
/// color-only anyway (chips print CRIT/HIGH/… text), but the CVD ramp
/// keeps the *color* channel informative too.
pub const SevPalette = enum(u8) {
    standard,
    cvd,

    pub fn label(self: SevPalette) [:0]const u8 {
        return switch (self) {
            .standard => "Standard",
            .cvd => "Colorblind-safe (Okabe-Ito)",
        };
    }
};

/// Vertical rhythm. `comfortable` also serves as the large-hit-target
/// a11y mode: button/row heights reach ≥24 px (WCAG 2.5.8).
pub const Density = enum(u8) {
    compact,
    cozy,
    comfortable,

    pub fn label(self: Density) [:0]const u8 {
        return switch (self) {
            .compact => "Compact",
            .cozy => "Cozy (default)",
            .comfortable => "Comfortable (large targets)",
        };
    }
};

/// Which workspace a fresh launch lands on.
pub const StartupWs = enum(u8) {
    last,
    triage,
    hunt,
    detect,
    intel,
    ops,

    pub fn label(self: StartupWs) [:0]const u8 {
        return switch (self) {
            .last => "Last used",
            .triage => "TRIAGE",
            .hunt => "HUNT",
            .detect => "DETECT",
            .intel => "INTEL",
            .ops => "OPS",
        };
    }
};

pub const Prefs = struct {
    theme_variant: ThemeVariant = .dark,
    sev_palette: SevPalette = .standard,
    density: Density = .cozy,
    /// UI font scale (style.font_scale_main). 0.85–2.0; 2.0 satisfies
    /// WCAG 1.4.4 resize-text.
    font_scale: f32 = 1.0,
    /// Kill decorative motion: value-flash decay, row-insert flashes
    /// (WCAG 2.3.3). Functional state changes still happen, instantly.
    reduced_motion: bool = false,
    /// Keep the keyboard-nav focus ring visible even after mouse use
    /// (WCAG 2.4.7). Off by default — mouse-first analysts find the
    /// persistent ring noisy; keyboard-first ones should turn it on.
    focus_ring_always: bool = false,
    time_style: fmt.TimeStyle = .utc,
    /// Copy IOC values defanged ("hxxps://x[.]y") so a paste into a ticket
    /// or chat can never be an accidental live link. Off = raw values for
    /// tools that need to match on the real indicator.
    defang_copy: bool = true,
    /// info/ok toast lifetime (seconds); warn shows 2×. WCAG 2.2.1:
    /// user-adjustable; toasts also pause while hovered and every one is
    /// retained in LOG.
    toast_secs: f32 = 4.0,
    /// Minimum event severity that raises a toast (ok=0, info=1, warn=2).
    /// Below the floor events still land in LOG. serious/crit always
    /// escalate to the banner regardless.
    toast_min_sev: u8 = 0,
    /// Do-not-disturb: no toasts at all (LOG + crit banner unaffected).
    dnd: bool = false,
    startup_ws: StartupWs = .last,
    /// Hard off-switch for the embedded assistant (compliance): sends are
    /// blocked, SET cancels any in-flight run on disable, and the panel
    /// renders a notice.
    ai_enabled: bool = true,
    /// Triage SLA targets — drive the MTTA/MTTR tile colors in PST.
    sla_mtta_min: f32 = 15.0,
    sla_mttr_hours: f32 = 4.0,

    pub fn clampAll(self: *Prefs) void {
        self.font_scale = std.math.clamp(self.font_scale, 0.85, 2.0);
        self.toast_secs = std.math.clamp(self.toast_secs, 2.0, 30.0);
        self.toast_min_sev = @min(self.toast_min_sev, 2);
        self.sla_mtta_min = std.math.clamp(self.sla_mtta_min, 1.0, 240.0);
        self.sla_mttr_hours = std.math.clamp(self.sla_mttr_hours, 0.5, 72.0);
    }
};

pub var current: Prefs = .{};

/// Mid-frame style rewrites tear the frame (windows drawn before the
/// change use the old style). SET sets this instead of calling apply();
/// Dashboard.render consumes it at the top of the next frame.
pub var apply_pending: bool = false;

/// Push every preference into the modules that consume it. Cheap — call
/// at frame START only (boot, harness reset, the apply_pending drain).
pub fn apply() void {
    current.clampAll();

    // ── Theme tokens: variant surfaces + severity palette ────────────────
    theme.active = theme.tokensFor(current.theme_variant);
    if (current.sev_palette == .cvd) {
        theme.active.sev = theme.sevCvd(theme.active.bg.panel);
        theme.active.score = theme.scoreCvd();
    } else if (current.theme_variant != .dark) {
        // Standard hues, non-default surfaces: the hand-tuned dims were
        // blended against the dark panel — re-derive for this variant.
        theme.active.sev = theme.deriveDims(theme.active.sev, theme.active.bg.panel);
    }
    theme.apply();

    // ── Density metrics (override theme.apply()'s cozy baseline) ─────────
    const style = zgui.getStyle();
    switch (current.density) {
        .compact => {
            style.window_padding = .{ 8, 4 };
            style.frame_padding = .{ 6, 2 };
            style.item_spacing = .{ 6, 3 };
            style.cell_padding = .{ 6, 1 };
        },
        .cozy => {}, // theme.apply() baseline
        .comfortable => {
            style.window_padding = .{ 10, 8 };
            style.frame_padding = .{ 7, 6 }; // 17px font + 12 ⇒ ≥24px targets
            style.item_spacing = .{ 7, 6 };
            style.cell_padding = .{ 6, 5 };
        },
    }
    style.font_scale_main = current.font_scale;

    // ── Motion ────────────────────────────────────────────────────────────
    flash.enabled = !current.reduced_motion;

    // ── Focus visibility ──────────────────────────────────────────────────
    zgui.setConfigNavCursorVisibleAlways(current.focus_ring_always);

    // ── Notifications ─────────────────────────────────────────────────────
    events.toast_ttl_info_ms = @intFromFloat(current.toast_secs * 1000.0);
    events.toast_min_sev = @enumFromInt(current.toast_min_sev);
    events.dnd = current.dnd;

    // ── Timestamps ────────────────────────────────────────────────────────
    fmt.time_style = current.time_style;
}

/// Reset everything to shipped defaults and apply.
pub fn resetAll() void {
    current = .{};
    apply();
}

// ── DST / timezone drift ──────────────────────────────────────────────────

var last_offset_check: i64 = 0;

/// Re-sample the OS timezone about once a minute — a SOC session runs for
/// days and crosses DST transitions; a frozen boot-time offset would skew
/// every "local" timestamp by an hour until restart. Reads fmt.now_ts
/// (the frame clock) so it costs nothing between checks.
pub fn tickLocalOffset() void {
    if (fmt.now_ts - last_offset_check < 60) return;
    last_offset_check = fmt.now_ts;
    detectLocalOffset();
}

// ── Local timezone offset (for the "local" time style) ───────────────────

const SYSTEMTIME = extern struct {
    wYear: u16,
    wMonth: u16,
    wDayOfWeek: u16,
    wDay: u16,
    wHour: u16,
    wMinute: u16,
    wSecond: u16,
    wMilliseconds: u16,
};

const TIME_ZONE_INFORMATION = extern struct {
    Bias: i32,
    StandardName: [32]u16,
    StandardDate: SYSTEMTIME,
    StandardBias: i32,
    DaylightName: [32]u16,
    DaylightDate: SYSTEMTIME,
    DaylightBias: i32,
};

const kernel32 = struct {
    extern "kernel32" fn GetTimeZoneInformation(tzi: *TIME_ZONE_INFORMATION) callconv(.winapi) u32;
};

/// Detect the OS UTC offset once at boot and hand it to fmt. Windows
/// convention: UTC = local + Bias, so the display offset is the negation.
pub fn detectLocalOffset() void {
    var tzi: TIME_ZONE_INFORMATION = undefined;
    // TIME_ZONE_ID_UNKNOWN(0)/STANDARD(1)/DAYLIGHT(2) fill tzi;
    // TIME_ZONE_ID_INVALID (0xFFFFFFFF) leaves it undefined — reading Bias
    // then would be garbage (and UB). Fall back to UTC.
    const extra: i32 = switch (kernel32.GetTimeZoneInformation(&tzi)) {
        0 => 0,
        1 => tzi.StandardBias,
        2 => tzi.DaylightBias,
        else => {
            fmt.local_offset_min = 0;
            return;
        },
    };
    fmt.local_offset_min = -(tzi.Bias + extra);
}

test "clamp keeps prefs in range" {
    var p = Prefs{ .font_scale = 9, .toast_secs = 0, .toast_min_sev = 7, .sla_mtta_min = 0, .sla_mttr_hours = 100 };
    p.clampAll();
    try std.testing.expectEqual(@as(f32, 2.0), p.font_scale);
    try std.testing.expectEqual(@as(f32, 2.0), p.toast_secs);
    try std.testing.expectEqual(@as(u8, 2), p.toast_min_sev);
    try std.testing.expectEqual(@as(f32, 1.0), p.sla_mtta_min);
    try std.testing.expectEqual(@as(f32, 72.0), p.sla_mttr_hours);
}
