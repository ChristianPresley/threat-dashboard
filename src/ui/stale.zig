//! Staleness grammar (DESIGN.md §4.6): data that stops ticking visibly
//! decays instead of lying. Per STREAM, not per connection — thresholds
//! scale with the stream's expected cadence. Disconnected = freeze-and-
//! mark, never blank.
//!
//! fresh   < 5 s   nothing shown
//! aging   5–30 s  warn age chip ("12s")
//! stale   30–120 s value dims to text.lo + serious chip
//! dead    > 120 s  value → "—", crit chip

const std = @import("std");

pub const Level = enum {
    fresh,
    aging,
    stale,
    dead,

    /// Whether the value text should dim to text.lo.
    pub fn dimsValue(self: Level) bool {
        return self == .stale or self == .dead;
    }

    /// Whether to replace the value with an em-dash entirely.
    pub fn hidesValue(self: Level) bool {
        return self == .dead;
    }
};

pub const Thresholds = struct {
    aging_s: i64 = 5,
    stale_s: i64 = 30,
    dead_s: i64 = 120,

    /// Scale all bands for slower streams (e.g. 1D bars × 60).
    pub fn scaled(self: Thresholds, factor: i64) Thresholds {
        return .{
            .aging_s = self.aging_s * factor,
            .stale_s = self.stale_s * factor,
            .dead_s = self.dead_s * factor,
        };
    }
};

pub const default_thresholds: Thresholds = .{};

pub fn classify(age_s: i64, t: Thresholds) Level {
    if (age_s < t.aging_s) return .fresh;
    if (age_s < t.stale_s) return .aging;
    if (age_s < t.dead_s) return .stale;
    return .dead;
}

test "bands and scaling" {
    const t = default_thresholds;
    try std.testing.expectEqual(Level.fresh, classify(0, t));
    try std.testing.expectEqual(Level.fresh, classify(4, t));
    try std.testing.expectEqual(Level.aging, classify(5, t));
    try std.testing.expectEqual(Level.aging, classify(29, t));
    try std.testing.expectEqual(Level.stale, classify(30, t));
    try std.testing.expectEqual(Level.stale, classify(119, t));
    try std.testing.expectEqual(Level.dead, classify(120, t));
    try std.testing.expect(Level.dead.hidesValue());
    try std.testing.expect(Level.stale.dimsValue());
    try std.testing.expect(!Level.aging.dimsValue());

    const slow = t.scaled(2);
    try std.testing.expectEqual(Level.fresh, classify(9, slow));
    try std.testing.expectEqual(Level.aging, classify(10, slow));
}
