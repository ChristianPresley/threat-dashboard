//! Safety-interlock timing (DESIGN.md §4.4) — ONE dwell-constant family,
//! wall-clock milliseconds, never frames. The UI always displays seconds.
//!
//! Tiers: T0 instant (toast) · T1 confirm popup + dwell · T2 hold-to-fire ·
//! T3 typed phrase + dwell. Constants are frozen in CONVENTIONS.md; do not
//! tune them casually — 800 ms hold was chosen over 600 ms because 600 ms
//! is within accidental-hold range.

const std = @import("std");

/// T1: confirm-button arm delay (popup opens, button enables after this).
pub const DWELL_T1_MS: i64 = 750;
/// T2: hold-to-fire duration — mouse press AND Enter-hold both use this.
pub const HOLD_T2_MS: i64 = 800;
/// T3: typed-phrase modal arm delay (after the phrase matches).
pub const DWELL_T3_MS: i64 = 1500;
/// Ticket anti-double-submit lockout.
pub const LOCKOUT_SUBMIT_MS: i64 = 3000;
/// Ticket one-click latch idle auto-revert (minutes). The ENGINE's REAL mode
/// NEVER auto-reverts (DESIGN.md §6.3) — this applies only to the manual
/// ticket latch.
pub const LATCH_REVERT_MIN: i64 = 15;

// MONOTONIC time, deliberately. Dwell timers gate REAL-money confirms: on a
// wall clock (GetSystemTimeAsFileTime) an NTP forward step >= dwell_ms would
// instantly arm the order/REAL/purge confirms, and a backward step would
// stall them and drive Hold.progress negative. QueryUnbiasedInterruptTime is
// kernel-monotonic (100 ns ticks since boot, excludes sleep) and immune to
// clock adjustment.
const kernel32 = struct {
    extern "kernel32" fn QueryUnbiasedInterruptTime(out: *u64) callconv(.winapi) c_int;
};

pub fn nowMs() i64 {
    var ticks: u64 = undefined;
    _ = kernel32.QueryUnbiasedInterruptTime(&ticks);
    return @intCast(ticks / 10_000);
}

/// Dwell timer for T1/T3 confirms: arm when the modal opens (or the phrase
/// matches), enable the confirm control once the dwell has elapsed.
pub const Dwell = struct {
    armed_at_ms: i64 = 0,

    pub fn arm(self: *Dwell) void {
        self.armed_at_ms = nowMs();
    }

    pub fn armAt(self: *Dwell, t_ms: i64) void {
        self.armed_at_ms = t_ms;
    }

    pub fn reset(self: *Dwell) void {
        self.armed_at_ms = 0;
    }

    pub fn isArmed(self: Dwell) bool {
        return self.armed_at_ms != 0;
    }

    pub fn ready(self: Dwell, dwell_ms: i64) bool {
        return self.armed_at_ms != 0 and nowMs() - self.armed_at_ms >= dwell_ms;
    }

    /// Seconds left before the confirm enables — for "(0.7s…)" countdowns.
    pub fn remainingSecs(self: Dwell, dwell_ms: i64) f32 {
        if (self.armed_at_ms == 0) return @as(f32, @floatFromInt(dwell_ms)) / 1000.0;
        const left = dwell_ms - (nowMs() - self.armed_at_ms);
        return @max(0.0, @as(f32, @floatFromInt(left)) / 1000.0);
    }
};

/// Hold-to-fire state for T2 (KILL / FLAT / Stop All): caller reports
/// whether the control is held each frame; fires once when the hold
/// crosses HOLD_T2_MS. Release aborts. `progress()` drives the radial fill.
pub const Hold = struct {
    held_since_ms: i64 = 0,
    fired: bool = false,

    /// Per-frame update. Returns true exactly once, on the frame the hold
    /// completes.
    pub fn update(self: *Hold, is_held: bool) bool {
        if (!is_held) {
            self.held_since_ms = 0;
            self.fired = false;
            return false;
        }
        const t = nowMs();
        if (self.held_since_ms == 0) {
            self.held_since_ms = t;
            return false;
        }
        if (!self.fired and t - self.held_since_ms >= HOLD_T2_MS) {
            self.fired = true;
            return true;
        }
        return false;
    }

    /// 0..1 fill fraction for the radial/linear hold indicator.
    pub fn progress(self: Hold) f32 {
        if (self.held_since_ms == 0) return 0;
        const t = nowMs() - self.held_since_ms;
        return std.math.clamp(@as(f32, @floatFromInt(t)) / @as(f32, @floatFromInt(HOLD_T2_MS)), 0.0, 1.0);
    }
};

test "dwell readiness is wall-clock based" {
    var d = Dwell{};
    try std.testing.expect(!d.ready(DWELL_T1_MS));
    d.armAt(nowMs() - DWELL_T1_MS - 1);
    try std.testing.expect(d.ready(DWELL_T1_MS));
    try std.testing.expectEqual(@as(f32, 0.0), d.remainingSecs(DWELL_T1_MS));
}

test "hold fires once at threshold and aborts on release" {
    var h = Hold{};
    try std.testing.expect(!h.update(true)); // arms
    h.held_since_ms = nowMs() - HOLD_T2_MS - 1;
    try std.testing.expect(h.update(true)); // fires
    try std.testing.expect(!h.update(true)); // only once
    _ = h.update(false); // release resets
    try std.testing.expect(h.held_since_ms == 0 and !h.fired);
}
