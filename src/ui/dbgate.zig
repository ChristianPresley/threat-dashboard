//! DbGate (DESIGN.md §4.7) — the single source of truth for "who owns the
//! DuckDB handle right now". DuckDB is single-writer, so every worker
//! close/reopen cycle routes through here; UI pollers check `canRead()`
//! and SKIP (rendering their last-good snapshot with a timestamped chip)
//! instead of erroring into a closed handle for hours during a backfill.
//!
//! Pure state machine — the dashboard wraps its reader calls; the footer
//! renders the segment from `snapshot()`.

const std = @import("std");
const confirm = @import("confirm.zig");

pub const State = enum { open, busy, err };

pub const OWNER_CAP = 24;

var state_: State = .open;
var owner: [OWNER_CAP]u8 = undefined;
var owner_len: u8 = 0;
var since_ms: i64 = 0;
/// Optional determinate progress (x of y); y == 0 means indeterminate.
var progress_x: u64 = 0;
var progress_y: u64 = 0;
/// Whether the owning job can be cancelled (footer shows the Esc hint).
var cancellable: bool = false;

pub const Snapshot = struct {
    state: State,
    owner: []const u8,
    since_ms: i64,
    elapsed_ms: i64,
    progress_x: u64,
    progress_y: u64,
    cancellable: bool,
};

pub fn snapshot() Snapshot {
    return .{
        .state = state_,
        .owner = owner[0..owner_len],
        .since_ms = since_ms,
        .elapsed_ms = if (since_ms == 0) 0 else confirm.nowMs() - since_ms,
        .progress_x = progress_x,
        .progress_y = progress_y,
        .cancellable = cancellable,
    };
}

/// A worker is taking the handle. `job` names it for the footer/tooltip.
pub fn setBusy(job: []const u8, can_cancel: bool) void {
    state_ = .busy;
    const n = @min(job.len, OWNER_CAP);
    @memcpy(owner[0..n], job[0..n]);
    owner_len = @intCast(n);
    since_ms = confirm.nowMs();
    progress_x = 0;
    progress_y = 0;
    cancellable = can_cancel;
}

/// Owning worker reports progress (x of y; y=0 → indeterminate).
pub fn setProgress(x: u64, y: u64) void {
    progress_x = x;
    progress_y = y;
}

/// Handle reopened — DB-backed panels may refresh.
pub fn setOpen() void {
    state_ = .open;
    owner_len = 0;
    since_ms = 0;
    cancellable = false;
}

pub fn setError(why: []const u8) void {
    state_ = .err;
    const n = @min(why.len, OWNER_CAP);
    @memcpy(owner[0..n], why[0..n]);
    owner_len = @intCast(n);
    since_ms = confirm.nowMs();
}

/// THE gate every DB poller checks before touching the handle. While busy,
/// pollers must keep their last-good snapshot + timestamp instead.
pub fn canRead() bool {
    return state_ == .open;
}

/// Selftest hook: counts reads attempted while the gate was closed —
/// a non-zero count after the gated-read selftest means a poller bypassed
/// the gate.
pub var blocked_read_attempts: u64 = 0;

/// Wrapper for reader call sites: returns false (and counts) when closed.
/// Usage: `if (!ui.dbgate.gatedRead()) { render snapshot-chip; } else { ...read... }`
pub fn gatedRead() bool {
    if (state_ != .open) {
        blocked_read_attempts += 1;
        return false;
    }
    return true;
}

pub fn reset() void {
    setOpen();
    blocked_read_attempts = 0;
}

test "gate blocks reads while busy and counts bypass attempts" {
    reset();
    try std.testing.expect(canRead());
    try std.testing.expect(gatedRead());
    try std.testing.expectEqual(@as(u64, 0), blocked_read_attempts);

    setBusy("trades backfill", true);
    try std.testing.expect(!canRead());
    try std.testing.expect(!gatedRead());
    try std.testing.expect(!gatedRead());
    try std.testing.expectEqual(@as(u64, 2), blocked_read_attempts);

    setProgress(412, 1024);
    const s = snapshot();
    try std.testing.expectEqual(State.busy, s.state);
    try std.testing.expectEqualStrings("trades backfill", s.owner);
    try std.testing.expectEqual(@as(u64, 412), s.progress_x);
    try std.testing.expect(s.cancellable);

    setOpen();
    try std.testing.expect(gatedRead());
    reset();
}
