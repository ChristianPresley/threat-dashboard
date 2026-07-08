//! Deterministic job queue engine: queued → running → done/failed/canceled
//! with N concurrent slots, FIFO promotion, per-job payloads, and a bounded
//! terminal history. Pure — no RNG, no clock, no I/O; the caller feeds
//! `dt`/`now_ms` and applies side effects to the Store when completions
//! come back from `tick`. Replaces the fixed "one flag per job name" array
//! so pipeline runs, feed syncs, and CI jobs queue instead of colliding.

const std = @import("std");
const domain = @import("domain");

pub const JobKind = enum(u8) {
    feed_sync,
    rule_backtest,
    ioc_enrichment,
    retention_sweep,
    yara_ci,
    pipeline_run,
    /// One urlscan submission (arg = scan id) — its own kind so canceling
    /// an enrichment batch never kills url scans (and vice versa).
    url_scan,

    pub fn label(self: JobKind) [:0]const u8 {
        return switch (self) {
            .feed_sync => "feed sync",
            .rule_backtest => "rule backtest",
            .ioc_enrichment => "ioc enrichment",
            .retention_sweep => "retention sweep",
            .yara_ci => "yara ci",
            .pipeline_run => "pipeline run",
            .url_scan => "url scan",
        };
    }

    /// Progress per second. The guided tour is tuned against 0.12 for
    /// yara_ci / ioc_enrichment (scenes 08 + 11 capture start→finish at
    /// dt = 1/12) — don't change those without re-timing the scenes.
    pub fn rate(self: JobKind) f32 {
        return switch (self) {
            .feed_sync => 0.25,
            .rule_backtest => 0.06,
            .ioc_enrichment => 0.12,
            .retention_sweep => 0.20,
            .yara_ci => 0.12,
            .pipeline_run => 0.12,
            .url_scan => 0.15,
        };
    }
};

pub const JobState = enum(u8) {
    queued,
    running,
    done,
    failed,
    canceled,

    pub fn label(self: JobState) [:0]const u8 {
        return switch (self) {
            .queued => "QUEUED",
            .running => "RUNNING",
            .done => "DONE",
            .failed => "FAILED",
            .canceled => "CANCELED",
        };
    }

    pub fn terminal(self: JobState) bool {
        return self != .queued and self != .running;
    }
};

pub const Job = struct {
    id: u32,
    kind: JobKind,
    state: JobState = .queued,
    progress: f32 = 0,
    /// Kind-specific payload: pipeline id (pipeline_run), feed id + 1
    /// (feed_sync; 0 = all feeds), 0 otherwise.
    arg: u32 = 0,
    queued_ms: i64 = 0,
    started_ms: i64 = 0,
    finished_ms: i64 = 0,
    /// Human context ("edr_events_ingest", "AbuseCH ThreatFox", …).
    detail: domain.FixedStr(48) = .{},
    err: domain.FixedStr(48) = .{},
};

/// Terminal jobs kept for the history view; older ones are pruned.
pub const HISTORY_CAP = 48;

pub const Engine = struct {
    allocator: std.mem.Allocator,
    jobs: std.ArrayList(Job) = .empty,
    next_id: u32 = 1,
    /// Concurrent running slots.
    slots: u32 = 2,

    pub fn init(allocator: std.mem.Allocator) Engine {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Engine) void {
        self.jobs.deinit(self.allocator);
    }

    pub fn find(self: *Engine, id: u32) ?*Job {
        for (self.jobs.items) |*j| {
            if (j.id == id) return j;
        }
        return null;
    }

    /// Queued-or-running job matching kind+arg (dedupe / in-flight checks).
    pub fn active(self: *Engine, kind: JobKind, arg: u32) ?*Job {
        for (self.jobs.items) |*j| {
            if (!j.state.terminal() and j.kind == kind and j.arg == arg) return j;
        }
        return null;
    }

    pub fn anyActive(self: *Engine, kind: JobKind) bool {
        for (self.jobs.items) |*j| {
            if (!j.state.terminal() and j.kind == kind) return true;
        }
        return false;
    }

    pub fn runningCount(self: *const Engine) u32 {
        var n: u32 = 0;
        for (self.jobs.items) |*j| {
            if (j.state == .running) n += 1;
        }
        return n;
    }

    pub fn queuedCount(self: *const Engine) u32 {
        var n: u32 = 0;
        for (self.jobs.items) |*j| {
            if (j.state == .queued) n += 1;
        }
        return n;
    }

    /// Enqueue unless an identical kind+arg job is already queued/running.
    /// Returns the job id, or null when deduped (or OOM).
    pub fn enqueue(self: *Engine, kind: JobKind, arg: u32, detail: []const u8, now_ms: i64) ?u32 {
        if (self.active(kind, arg) != null) return null;
        const id = self.next_id;
        self.jobs.append(self.allocator, .{
            .id = id,
            .kind = kind,
            .arg = arg,
            .queued_ms = now_ms,
            .detail = domain.FixedStr(48).from(detail),
        }) catch return null;
        self.next_id += 1;
        return id;
    }

    /// Cancel a queued or running job.
    pub fn cancel(self: *Engine, id: u32, now_ms: i64) bool {
        const j = self.find(id) orelse return false;
        if (j.state.terminal()) return false;
        j.state = .canceled;
        j.finished_ms = now_ms;
        return true;
    }

    /// Flip an already-completed job to FAILED (side effects discovered the
    /// failure after the progress bar finished — e.g. a pipeline run whose
    /// source was unreachable).
    pub fn markFailed(self: *Engine, id: u32, msg: []const u8) void {
        const j = self.find(id) orelse return;
        j.state = .failed;
        j.err = domain.FixedStr(48).from(msg);
    }

    /// Advance one frame: progress running jobs (completions are COPIED
    /// into `out` for the caller's side effects), promote queued jobs into
    /// free slots FIFO, prune terminal history beyond HISTORY_CAP.
    pub fn tick(self: *Engine, dt: f32, now_ms: i64, out: *std.ArrayList(Job)) void {
        for (self.jobs.items) |*j| {
            if (j.state != .running) continue;
            j.progress += dt * j.kind.rate();
            if (j.progress >= 1.0) {
                j.progress = 1.0;
                j.state = .done;
                j.finished_ms = now_ms;
                out.append(self.allocator, j.*) catch {};
            }
        }
        var free = self.slots -| self.runningCount();
        if (free > 0) {
            for (self.jobs.items) |*j| {
                if (free == 0) break;
                if (j.state != .queued) continue;
                j.state = .running;
                j.started_ms = now_ms;
                free -= 1;
            }
        }
        // Prune: drop the oldest terminal entries beyond the history cap.
        var terminal: usize = 0;
        for (self.jobs.items) |*j| {
            if (j.state.terminal()) terminal += 1;
        }
        while (terminal > HISTORY_CAP) : (terminal -= 1) {
            for (self.jobs.items, 0..) |*j, i| {
                if (j.state.terminal()) {
                    _ = self.jobs.orderedRemove(i);
                    break;
                }
            }
        }
    }
};

test "queue promotes FIFO within slots, completes, dedupes" {
    var e = Engine.init(std.testing.allocator);
    defer e.deinit();

    try std.testing.expect(e.enqueue(.yara_ci, 0, "all rules", 100) != null);
    try std.testing.expect(e.enqueue(.pipeline_run, 1, "p1", 101) != null);
    try std.testing.expect(e.enqueue(.pipeline_run, 2, "p2", 102) != null);
    // Dedupe: identical kind+arg while active.
    try std.testing.expectEqual(@as(?u32, null), e.enqueue(.pipeline_run, 1, "p1", 103));
    // Different arg is a different job.
    try std.testing.expectEqual(@as(u32, 3), e.queuedCount());

    var out: std.ArrayList(Job) = .empty;
    defer out.deinit(std.testing.allocator);

    // First tick: two slots fill, third stays queued.
    e.tick(0.0, 200, &out);
    try std.testing.expectEqual(@as(u32, 2), e.runningCount());
    try std.testing.expectEqual(@as(u32, 1), e.queuedCount());

    // Run yara_ci (rate 0.12) to completion: ~8.4 s.
    var t: f32 = 0;
    while (t < 9.0) : (t += 0.5) e.tick(0.5, 300, &out);
    try std.testing.expect(out.items.len >= 1);
    try std.testing.expectEqual(JobState.done, out.items[0].state);
    // The queued third job was promoted once a slot freed.
    try std.testing.expectEqual(@as(u32, 0), e.queuedCount());
}

test "cancel + markFailed + history prune" {
    var e = Engine.init(std.testing.allocator);
    defer e.deinit();
    var out: std.ArrayList(Job) = .empty;
    defer out.deinit(std.testing.allocator);

    const id = e.enqueue(.feed_sync, 3, "feed", 10).?;
    try std.testing.expect(e.cancel(id, 20));
    try std.testing.expect(!e.cancel(id, 30)); // already terminal
    try std.testing.expectEqual(JobState.canceled, e.find(id).?.state);

    const id2 = e.enqueue(.pipeline_run, 9, "p9", 40).?;
    e.tick(0.0, 50, &out); // promote
    var t: f32 = 0;
    while (t < 9.0) : (t += 0.5) e.tick(0.5, 60, &out);
    e.markFailed(id2, "connect timeout");
    try std.testing.expectEqual(JobState.failed, e.find(id2).?.state);

    // Flood terminal history past the cap; list stays bounded.
    var i: u32 = 0;
    while (i < HISTORY_CAP + 20) : (i += 1) {
        const jid = e.enqueue(.retention_sweep, 100 + i, "x", 70).?;
        _ = e.cancel(jid, 71);
    }
    e.tick(0.0, 80, &out);
    try std.testing.expect(e.jobs.items.len <= HISTORY_CAP + 2);
}
