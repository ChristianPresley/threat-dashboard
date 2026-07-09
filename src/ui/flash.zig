//! Flash-on-update engine (DESIGN.md §4.6): per visible cell, remember the
//! last value + change time + direction; on draw, an exponential-decay
//! background tint (`alpha = 0.8·exp(−(now−ts)/350ms)`, clamped to zero
//! after 1 s) signals the change. Cells updating faster than ~3 Hz stop
//! flashing (tick-colored text takes over). Background-only, never text;
//! full-row flash is reserved for one-shot row inserts.
//!
//! Storage: fixed-capacity open-addressed map keyed by a caller-provided
//! 64-bit cell id (hash of table+row-key+column). Stale entries are
//! reclaimed lazily; the map never allocates.

const std = @import("std");
const confirm = @import("confirm.zig");

pub const Dir = enum(i8) { down = -1, none = 0, up = 1 };

const Slot = struct {
    key: u64 = 0, // 0 = empty
    value_bits: u64 = 0,
    change_ms: i64 = 0,
    prev_change_ms: i64 = 0,
    dir: Dir = .none,
};

const CAP: usize = 4096; // power of two
var slots: [CAP]Slot = @splat(.{});

/// Per-frame "now" — set once per frame via beginFrame so thousands of
/// cells don't each read the clock.
var now_ms: i64 = 0;

/// Reduced-motion gate (WCAG 2.3.3): false ⇒ update() still tracks values
/// and directions (tick-colored text keeps working) but never emits a
/// flash alpha, and insert flashes are no-ops.
pub var enabled: bool = true;

pub fn beginFrame() void {
    now_ms = confirm.nowMs();
}

pub const Result = struct {
    /// 0 = no flash. Multiply into the dim tint's alpha.
    alpha: f32,
    dir: Dir,
};

/// Report the cell's current value; returns the flash to draw this frame.
/// `key` must be stable per cell and non-zero.
pub fn update(key: u64, value: f64) Result {
    std.debug.assert(key != 0);
    const slot = find(key);
    const bits: u64 = @bitCast(value);

    if (slot.key != key) {
        // New cell (or reclaimed slot): seed without flashing.
        slot.* = .{ .key = key, .value_bits = bits, .change_ms = 0, .prev_change_ms = 0, .dir = .none };
        return .{ .alpha = 0, .dir = .none };
    }

    if (bits != slot.value_bits) {
        const old: f64 = @bitCast(slot.value_bits);
        slot.dir = if (value > old) .up else if (value < old) .down else slot.dir;
        slot.value_bits = bits;
        slot.prev_change_ms = slot.change_ms;
        slot.change_ms = now_ms;
    }

    if (slot.change_ms == 0) return .{ .alpha = 0, .dir = .none };

    if (!enabled) return .{ .alpha = 0, .dir = slot.dir };

    // Throttle: two consecutive changes < ~330ms apart = faster than 3 Hz —
    // suppress the flash until the cadence slows.
    if (slot.prev_change_ms != 0 and slot.change_ms - slot.prev_change_ms < 330) {
        return .{ .alpha = 0, .dir = slot.dir };
    }

    const age: f32 = @floatFromInt(now_ms - slot.change_ms);
    if (age > 1000) return .{ .alpha = 0, .dir = slot.dir };
    const alpha = 0.8 * @exp(-age / 350.0);
    return .{ .alpha = alpha, .dir = slot.dir };
}

/// One-shot row-insert flash: seed a synthetic change now (no direction).
pub fn markInsert(key: u64) void {
    if (!enabled) return;
    const slot = find(key);
    slot.* = .{ .key = key, .value_bits = 0, .change_ms = now_ms, .prev_change_ms = 0, .dir = .none };
}

/// Stable cell key helper: hash table-id + row-key + column index.
pub fn cellKey(table: []const u8, row_key: u64, col: u32) u64 {
    var h = std.hash.Wyhash.init(0x9E3779B97F4A7C15);
    h.update(table);
    h.update(std.mem.asBytes(&row_key));
    h.update(std.mem.asBytes(&col));
    const k = h.final();
    return if (k == 0) 1 else k;
}

fn find(key: u64) *Slot {
    var idx: usize = @intCast(key & (CAP - 1));
    var probes: usize = 0;
    var oldest: *Slot = &slots[idx];
    while (probes < 8) : (probes += 1) {
        const s = &slots[idx];
        if (s.key == key or s.key == 0) return s;
        // Track the least-recently-changed slot in the probe window for
        // eviction — flash state is decorative, losing one is harmless.
        if (s.change_ms < oldest.change_ms) oldest = s;
        idx = (idx + 1) & (CAP - 1);
    }
    return oldest;
}

pub fn reset() void {
    slots = @splat(.{});
}

test "flash decays, directions track, throttle suppresses" {
    reset();
    now_ms = 10_000;
    beginFrameAt(10_000);

    const k = cellKey("pos", 42, 3);
    // First sighting: seeded, no flash.
    try std.testing.expectEqual(@as(f32, 0), update(k, 100.0).alpha);

    // Change up: flash, direction up.
    beginFrameAt(12_000);
    const r1 = update(k, 101.0);
    try std.testing.expect(r1.alpha > 0.7);
    try std.testing.expectEqual(Dir.up, r1.dir);

    // 400ms later: decayed but visible.
    beginFrameAt(12_400);
    const r2 = update(k, 101.0);
    try std.testing.expect(r2.alpha > 0.1 and r2.alpha < r1.alpha);

    // >1s later: gone.
    beginFrameAt(13_500);
    try std.testing.expectEqual(@as(f32, 0), update(k, 101.0).alpha);

    // Rapid changes (<330ms apart): throttled.
    beginFrameAt(14_000);
    _ = update(k, 102.0);
    beginFrameAt(14_100);
    const r3 = update(k, 103.0);
    try std.testing.expectEqual(@as(f32, 0), r3.alpha);
    try std.testing.expectEqual(Dir.up, r3.dir);

    // Down direction.
    beginFrameAt(16_000);
    const r4 = update(k, 50.0);
    try std.testing.expectEqual(Dir.down, r4.dir);
}

/// Test hook: pin the frame clock.
fn beginFrameAt(t: i64) void {
    now_ms = t;
}
