//! PostgreSQL background worker: owns the PG connection off the render
//! thread (the trading LiveFeed pattern). Panel mutations queue to it
//! through the Store write hook instead of running synchronous UPDATEs on
//! the render thread, and it periodically loads a fresh world snapshot the
//! render thread swaps in via `Store.adoptFrom`.
//!
//! The render thread talks to it ONLY through two mutex-guarded channels
//! drained/filled once per frame (the ai/worker.zig contract) — the live
//! Store is never touched off-thread.
//!
//! Stale-snapshot guard: the write hook bumps `mutation_seq` (render
//! thread) before queueing each mutation. The worker captures the seq
//! BEFORE draining + loading and discards the snapshot if it changed; the
//! render thread re-checks at swap time. A snapshot can therefore never
//! revert a panel action that raced the load — at worst a refresh cycle is
//! skipped and the next one converges.
//!
//! Sync uses std.Io.Mutex + polling (this std's Condition has no timed
//! wait); a background thread polling at 25 ms is plenty for a 5 s
//! snapshot cadence.

const std = @import("std");
const Allocator = std.mem.Allocator;
const store_mod = @import("store.zig");
const Store = store_mod.Store;
const Mutation = store_mod.Mutation;
const Provider = @import("pg.zig").Provider;

const log = std.log.scoped(.pg_worker);

const POLL_MS = 25;
/// Snapshot cadence. Panel mutations hit the local Store immediately —
/// refreshes only pull in EXTERNAL writes (ingestion, other analysts).
pub const REFRESH_MS = 5_000;
const RECONNECT_MIN_MS = 1_000;
const RECONNECT_MAX_MS = 30_000;

fn sleepMs(io: std.Io, ms: i64) void {
    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(ms), .awake) catch {};
}

/// Render thread → worker.
pub const ToWorker = union(enum) {
    mutation: Mutation,
    shutdown,
};

pub const State = enum { connected, reconnecting };

/// Worker → render thread. The render thread takes ownership of snapshot
/// stores and error strings.
pub const Event = union(enum) {
    /// A freshly loaded world. `seq` is the mutation_seq captured before
    /// the load; the render thread must drop the snapshot if the current
    /// seq differs (a panel wrote in between).
    snapshot: struct { st: *Store, seq: u64 },
    state: State,
    err: []u8,
};

pub fn freeEvent(gpa: Allocator, ev: Event) void {
    switch (ev) {
        .snapshot => |s| {
            s.st.deinit();
            gpa.destroy(s.st);
        },
        .err => |m| gpa.free(m),
        .state => {},
    }
}

fn Channel(comptime T: type) type {
    return struct {
        const Self = @This();
        mutex: std.Io.Mutex = .init,
        items: std.ArrayList(T) = .empty,

        fn push(self: *Self, io: std.Io, gpa: Allocator, item: T) !void {
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            try self.items.append(gpa, item);
        }

        fn drainInto(self: *Self, io: std.Io, gpa: Allocator, out: *std.ArrayList(T)) void {
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            for (self.items.items) |it| out.append(gpa, it) catch {};
            self.items.clearRetainingCapacity();
        }

        fn tryPop(self: *Self, io: std.Io) ?T {
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            if (self.items.items.len == 0) return null;
            return self.items.orderedRemove(0);
        }
    };
}

pub const Worker = struct {
    gpa: Allocator,
    io: std.Io,
    uri: []u8,
    thread: ?std.Thread = null,
    inbox: Channel(ToWorker) = .{},
    outbox: Channel(Event) = .{},
    stop: std.atomic.Value(bool) = .init(false),
    /// Bumped by the render thread before each queued mutation — the
    /// stale-snapshot guard (see file header).
    mutation_seq: std.atomic.Value(u64) = .init(0),

    /// Spawns the thread immediately — callers only create a worker when
    /// --pg was given, so --selftest/--validate stay thread- and
    /// network-free by construction.
    pub fn create(gpa: Allocator, io: std.Io, uri_text: []const u8) !*Worker {
        const w = try gpa.create(Worker);
        errdefer gpa.destroy(w);
        const uri = try gpa.dupe(u8, uri_text);
        errdefer gpa.free(uri);
        w.* = .{ .gpa = gpa, .io = io, .uri = uri };
        w.thread = try std.Thread.spawn(.{}, threadMain, .{w});
        return w;
    }

    /// Render thread. Callers must detach the Store write hook first.
    pub fn shutdown(self: *Worker) void {
        if (self.thread) |th| {
            self.stop.store(true, .seq_cst);
            self.inbox.push(self.io, self.gpa, .shutdown) catch {};
            th.join();
        }
        self.inbox.items.deinit(self.gpa);
        for (self.outbox.items.items) |ev| freeEvent(self.gpa, ev);
        self.outbox.items.deinit(self.gpa);
        self.gpa.free(self.uri);
        self.gpa.destroy(self);
    }

    // ── Render-thread producers/consumers ────────────────────────────────

    pub fn installHook(self: *Worker, s: *Store) void {
        s.write_hook = .{ .ctx = self, .f = onMutation };
    }

    fn onMutation(ctx: *anyopaque, m: Mutation) void {
        const self: *Worker = @ptrCast(@alignCast(ctx));
        _ = self.mutation_seq.fetchAdd(1, .seq_cst);
        self.inbox.push(self.io, self.gpa, .{ .mutation = m }) catch {};
    }

    /// Drain the outbox into `out` (render thread, once per frame).
    pub fn drain(self: *Worker, out: *std.ArrayList(Event)) void {
        self.outbox.drainInto(self.io, self.gpa, out);
    }

    // ── Worker thread ─────────────────────────────────────────────────────

    fn threadMain(self: *Worker) void {
        var backoff_ms: i64 = RECONNECT_MIN_MS;
        outer: while (!self.stop.load(.seq_cst)) {
            var provider = Provider.connect(self.io, self.gpa, self.uri) catch |err| {
                self.pushErr("PG worker connect failed: {s} — retrying in {d} ms", .{ @errorName(err), backoff_ms });
                if (!self.sleepDropping(backoff_ms)) return;
                backoff_ms = @min(backoff_ms * 2, RECONNECT_MAX_MS);
                continue :outer;
            };
            backoff_ms = RECONNECT_MIN_MS;
            self.pushState(.connected);

            // Boot already did a full load — wait a whole interval before
            // the first refresh.
            var since_refresh: i64 = 0;
            while (!self.stop.load(.seq_cst)) {
                const seq = self.mutation_seq.load(.seq_cst);
                while (self.inbox.tryPop(self.io)) |msg| switch (msg) {
                    .shutdown => {
                        provider.deinit();
                        return;
                    },
                    .mutation => |m| provider.apply(m) catch |err| {
                        // The write was lost — refresh early so the UI
                        // converges back to DB truth instead of showing
                        // the unpersisted change until the next tick.
                        self.pushErr("PG write failed: {s} — refreshing from DB", .{@errorName(err)});
                        since_refresh = REFRESH_MS;
                    },
                };
                if (since_refresh >= REFRESH_MS) {
                    since_refresh = 0;
                    if (!self.loadAndPublish(&provider, seq)) {
                        provider.deinit();
                        self.pushState(.reconnecting);
                        continue :outer;
                    }
                }
                sleepMs(self.io, POLL_MS);
                since_refresh += POLL_MS;
            }
            provider.deinit();
            return;
        }
    }

    /// Load one snapshot and publish it unless a mutation raced the load.
    /// Returns false when the connection should be considered dead.
    fn loadAndPublish(self: *Worker, provider: *Provider, seq: u64) bool {
        const st = self.gpa.create(Store) catch return true; // OOM: skip this tick
        st.* = Store.init(self.gpa);
        provider.load(st) catch |err| {
            st.deinit();
            self.gpa.destroy(st);
            self.pushErr("PG snapshot load failed: {s} — reconnecting", .{@errorName(err)});
            return false;
        };
        if (self.mutation_seq.load(.seq_cst) != seq) {
            // A panel wrote during the load — the snapshot predates that
            // write. Discard; the next cycle reloads after it's applied.
            st.deinit();
            self.gpa.destroy(st);
            return true;
        }
        log.debug("snapshot published: {d} events / {d} alerts (seq {d})", .{ st.events.items.len, st.alerts.items.len, seq });
        self.outbox.push(self.io, self.gpa, .{ .snapshot = .{ .st = st, .seq = seq } }) catch {
            st.deinit();
            self.gpa.destroy(st);
        };
        return true;
    }

    /// Backoff sleep while disconnected. Queued mutations are dropped (the
    /// DB is unreachable; the post-reconnect snapshot restores DB truth) —
    /// same data-loss contract the v1 synchronous hook had on exec failure.
    fn sleepDropping(self: *Worker, ms: i64) bool {
        var dropped: usize = 0;
        var waited: i64 = 0;
        while (waited < ms) : (waited += POLL_MS) {
            if (self.stop.load(.seq_cst)) return false;
            while (self.inbox.tryPop(self.io)) |msg| switch (msg) {
                .shutdown => return false,
                .mutation => dropped += 1,
            };
            sleepMs(self.io, POLL_MS);
        }
        if (dropped > 0) {
            self.pushErr("dropped {d} panel write(s) while disconnected — reconnect will reload DB truth", .{dropped});
        }
        return true;
    }

    fn pushState(self: *Worker, s: State) void {
        self.outbox.push(self.io, self.gpa, .{ .state = s }) catch {};
    }

    fn pushErr(self: *Worker, comptime fmt: []const u8, args: anytype) void {
        log.warn(fmt, args);
        const d = std.fmt.allocPrint(self.gpa, fmt, args) catch return;
        self.outbox.push(self.io, self.gpa, .{ .err = d }) catch self.gpa.free(d);
    }
};

test "channel push/pop/drain round-trip" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = std.testing.allocator;

    var ch: Channel(u32) = .{};
    defer ch.items.deinit(gpa);
    try std.testing.expectEqual(@as(?u32, null), ch.tryPop(io));
    try ch.push(io, gpa, 1);
    try ch.push(io, gpa, 2);
    try ch.push(io, gpa, 3);
    try std.testing.expectEqual(@as(?u32, 1), ch.tryPop(io)); // FIFO
    var out: std.ArrayList(u32) = .empty;
    defer out.deinit(gpa);
    ch.drainInto(io, gpa, &out);
    try std.testing.expectEqualSlices(u32, &.{ 2, 3 }, out.items);
    try std.testing.expectEqual(@as(?u32, null), ch.tryPop(io));
}

test "write hook queues mutations and bumps the stale-snapshot seq" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = std.testing.allocator;

    // Hand-rolled worker (no thread, no connection) — exercises only the
    // render-thread half of the contract.
    var w: Worker = .{ .gpa = gpa, .io = io, .uri = @constCast("") };
    defer w.inbox.items.deinit(gpa);

    var s = Store.init(gpa);
    defer s.deinit();
    try s.alerts.append(gpa, .{ .id = 1, .ts_ms = 0, .rule = 0, .severity = .high });
    w.installHook(&s);

    try std.testing.expect(s.setAlertStatus(1, .resolved, 42));
    try std.testing.expectEqual(@as(u64, 1), w.mutation_seq.load(.seq_cst));
    const msg = w.inbox.tryPop(io).?;
    try std.testing.expectEqual(std.meta.Tag(ToWorker).mutation, std.meta.activeTag(msg));
    try std.testing.expectEqual(@as(u32, 1), msg.mutation.alert_status.id);
}
