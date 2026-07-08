//! Unified event spine (DESIGN.md §4.5): every status message, worker
//! completion, error, and alert transition posts ONE event here. The LOG
//! panel renders the ring; the toast renderer and critical banner consume
//! the same stream; panels that used ad-hoc status buffers render their
//! source's latest entry. Severity vocabulary matches the theme ramp.
//!
//! Single-threaded by design: post() is called from the render/engine tick
//! only. Worker threads hand their messages to the reaper, which posts.

const std = @import("std");
const confirm = @import("confirm.zig");

pub const Severity = enum(u8) {
    ok,
    info,
    warn,
    serious,
    crit,

    pub fn label(self: Severity) [:0]const u8 {
        return switch (self) {
            .ok => "OK",
            .info => "INFO",
            .warn => "WARN",
            .serious => "SERIOUS",
            .crit => "CRIT",
        };
    }
};

pub const SOURCE_CAP = 16;
pub const MSG_CAP = 160;

pub const Event = struct {
    /// Monotonic ms (confirm.nowMs clock) — display converts to wall clock
    /// via the offset captured at post time.
    ts_ms: i64,
    /// Wall-clock Unix seconds at post time (for HH:MM:SS display).
    wall_ts: i64,
    seq: u64,
    sev: Severity,
    source: [SOURCE_CAP]u8,
    source_len: u8,
    msg: [MSG_CAP]u8,
    msg_len: u8,

    pub fn sourceSlice(self: *const Event) []const u8 {
        return self.source[0..self.source_len];
    }
    pub fn msgSlice(self: *const Event) []const u8 {
        return self.msg[0..self.msg_len];
    }
};

pub const RING_CAP = 2048;

var ring: [RING_CAP]Event = undefined;
var head: usize = 0; // next write slot
var count: usize = 0;
var next_seq: u64 = 1;

/// Wall-clock source, injected once from the app (unix seconds fn) so this
/// module needs no OS deps. Defaults to 0 timestamps when unset.
pub var wallClock: ?*const fn () i64 = null;

/// Post an event. `source` identifies the producer ("backtest", "matrix",
/// "deploy", "ws", "db", "alerts", …) and is truncated to 15 chars.
pub fn post(sev: Severity, source: []const u8, comptime fmt: []const u8, args: anytype) void {
    var e: Event = undefined;
    // The truncation path below publishes the whole buffer — it must never
    // contain uninitialized stack bytes (they'd render in LOG/toasts and
    // land in the CSV export).
    @memset(&e.msg, 0);
    e.ts_ms = confirm.nowMs();
    e.wall_ts = if (wallClock) |f| f() else 0;
    e.seq = next_seq;
    next_seq += 1;
    e.sev = sev;

    const slen = @min(source.len, SOURCE_CAP);
    @memcpy(e.source[0..slen], source[0..slen]);
    e.source_len = @intCast(slen);

    const msg = std.fmt.bufPrint(&e.msg, fmt, args) catch blk: {
        // Truncated — keep what fit.
        break :blk e.msg[0..e.msg.len];
    };
    e.msg_len = @intCast(msg.len);

    ring[head] = e;
    head = (head + 1) % RING_CAP;
    if (count < RING_CAP) count += 1;

    onPost(&ring[(head + RING_CAP - 1) % RING_CAP]);
}

/// Number of events currently retained.
pub fn len() usize {
    return count;
}

/// Event by recency: nth(0) = newest. Asserts idx < len().
pub fn nth(idx: usize) *const Event {
    std.debug.assert(idx < count);
    const pos = (head + RING_CAP - 1 - idx) % RING_CAP;
    return &ring[pos];
}

/// Newest event from `source`, or null. Replaces the old per-panel status
/// buffers — panels render this inline.
pub fn latestFrom(source: []const u8) ?*const Event {
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const e = nth(i);
        if (std.mem.eql(u8, e.sourceSlice(), source)) return e;
    }
    return null;
}

pub fn clear() void {
    head = 0;
    count = 0;
    next_seq = 1;
    toasts = .{null} ** TOAST_CAP;
    banner = null;
}

// ── Toasts (§4.5: max 3, info/ok 4s, warn 8s; serious/crit never toast) ──

pub const TOAST_CAP = 3;

pub const Toast = struct {
    seq: u64,
    expires_ms: i64,
    pinned: bool = false,
};

pub var toasts: [TOAST_CAP]?Toast = .{null} ** TOAST_CAP;

/// Banner state: seq of the unacked serious/crit event being shown, if any.
/// The text is COPIED at escalation time (`banner_text`/`banner_source`) so
/// the banner survives the event scrolling out of the ring — an unacked
/// CRIT must never auto-dismiss because of an event storm.
pub var banner: ?u64 = null;
pub var banner_sev: Severity = .crit;
var banner_source_buf: [SOURCE_CAP]u8 = undefined;
var banner_source_len: u8 = 0;
var banner_msg_buf: [MSG_CAP]u8 = undefined;
var banner_msg_len: u8 = 0;

pub fn bannerSource() []const u8 {
    return banner_source_buf[0..banner_source_len];
}
pub fn bannerMsg() []const u8 {
    return banner_msg_buf[0..banner_msg_len];
}

fn onPost(e: *const Event) void {
    switch (e.sev) {
        .ok, .info, .warn => {
            const ttl_ms: i64 = if (e.sev == .warn) 8_000 else 4_000;
            const t = Toast{ .seq = e.seq, .expires_ms = e.ts_ms + ttl_ms };
            // Fill a free slot, else displace the oldest unpinned.
            var oldest: ?usize = null;
            for (&toasts, 0..) |*slot, i| {
                if (slot.* == null) {
                    slot.* = t;
                    return;
                }
                if (!slot.*.?.pinned and (oldest == null or slot.*.?.seq < toasts[oldest.?].?.seq)) {
                    oldest = i;
                }
            }
            if (oldest) |i| toasts[i] = t;
        },
        .serious, .crit => {
            // Escalate: banner shows the LATEST unacked serious/crit, with
            // its text copied so ring overflow can't dismiss it.
            banner = e.seq;
            banner_sev = e.sev;
            banner_source_len = e.source_len;
            @memcpy(banner_source_buf[0..e.source_len], e.source[0..e.source_len]);
            banner_msg_len = e.msg_len;
            @memcpy(banner_msg_buf[0..e.msg_len], e.msg[0..e.msg_len]);
        },
    }
}

/// Drop all toasts immediately (validate harness: captures must show panel
/// content, not the boot toast). Leaves the ring and crit banner intact.
pub fn dismissToasts() void {
    toasts = .{null} ** TOAST_CAP;
}

/// Drop expired toasts; call per frame.
pub fn tickToasts() void {
    const now = confirm.nowMs();
    for (&toasts) |*slot| {
        if (slot.*) |t| {
            if (!t.pinned and now >= t.expires_ms) slot.* = null;
        }
    }
}

/// Find an event by seq (for toast/banner rendering); null if it scrolled
/// out of the ring.
pub fn bySeq(seq: u64) ?*const Event {
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const e = nth(i);
        if (e.seq == seq) return e;
        if (e.seq < seq) return null; // ring is seq-ordered by recency
    }
    return null;
}

pub fn ackBanner() void {
    banner = null;
    banner_source_len = 0;
    banner_msg_len = 0;
}

test "ring ordering, latestFrom, toast + banner routing" {
    clear();
    post(.info, "backtest", "done in {d}ms", .{123});
    post(.warn, "ws", "reconnecting", .{});
    post(.crit, "engine", "kill tripped: {s}", .{"drift"});

    try std.testing.expectEqual(@as(usize, 3), len());
    try std.testing.expectEqualStrings("engine", nth(0).sourceSlice());
    try std.testing.expectEqualStrings("backtest", nth(2).sourceSlice());
    try std.testing.expect(latestFrom("ws") != null);
    try std.testing.expect(latestFrom("nope") == null);

    // crit → banner, not toast; info/warn → toasts.
    try std.testing.expect(banner != null);
    try std.testing.expectEqualStrings("kill tripped: drift", bySeq(banner.?).?.msgSlice());
    var toast_count: usize = 0;
    for (toasts) |t| {
        if (t != null) toast_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), toast_count);

    ackBanner();
    try std.testing.expect(banner == null);
}

test "ring wraps without corruption" {
    clear();
    var i: usize = 0;
    while (i < RING_CAP + 10) : (i += 1) {
        post(.info, "x", "{d}", .{i});
    }
    try std.testing.expectEqual(@as(usize, RING_CAP), len());
    // Newest is the last posted.
    var buf: [16]u8 = undefined;
    const want = std.fmt.bufPrint(&buf, "{d}", .{RING_CAP + 9}) catch unreachable;
    try std.testing.expectEqualStrings(want, nth(0).msgSlice());
}
