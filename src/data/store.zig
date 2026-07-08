//! In-memory world state read by every panel and written by a provider
//! (the mock generator, or the Postgres background worker in
//! pg_worker.zig which swaps in whole snapshots via `adoptFrom`).
//! Panels never query a backend directly — they read Store snapshots and
//! mutate through the small action API here, so swapping the provider
//! never touches panel code.

const std = @import("std");
const domain = @import("domain");

pub const mock = @import("mock.zig");
pub const pg = @import("pg.zig");
pub const pg_worker = @import("pg_worker.zig");
pub const jobs = @import("jobs.zig");

/// Mutations panels perform through the Store — mirrored to the active
/// provider via `write_hook` so a backing database stays in sync.
pub const Mutation = union(enum) {
    alert_status: struct { id: u32, status: domain.AlertStatus, acked_ms: i64 = 0, resolved_ms: i64 = 0 },
    rule_status: struct { id: u16, status: domain.RuleStatus },
    case_status: struct { id: u16, status: domain.CaseStatus, now_ms: i64 },
    case_assign: struct { alert_id: u32, case_id: u16, now_ms: i64 },
    yara_status: struct { id: u16, status: domain.YaraStatus },
    yara_ci: struct { id: u16, gates: domain.YaraGates },
    /// Carries the full row so the PG hook can upsert in one statement.
    enrichment_upsert: struct { e: domain.IocEnrichment },
    urlscan_submit: struct { id: u32, ioc_id: u32, now_ms: i64 },
    urlscan_update: struct { id: u32, state: domain.ScanState, err: domain.FixedStr(32), now_ms: i64 },
    case_notes: struct { id: u16, notes: domain.FixedStr(480), now_ms: i64 },
    /// Carries the full row so the PG hook can insert in one statement.
    case_add: struct { c: domain.Case },
    /// Case metadata edit (title / severity / assignee).
    case_update: struct { id: u16, title: domain.FixedStr(96), severity: domain.Severity, assignee: domain.FixedStr(24), now_ms: i64 },
    case_unassign: struct { alert_id: u32, case_id: u16, now_ms: i64 },
    /// Feed sync lifecycle (syncing → ok/err) — carries the stamped
    /// last_sync_ms so a snapshot refresh can never revert a sync result.
    feed_status: struct { id: u16, status: domain.FeedStatus, last_sync_ms: i64 },
    /// Analyst FP feedback on a rule (carries the new absolute count).
    rule_fp: struct { id: u16, fp_7d: u32 },
    /// Retention sweep parameters — the PG hook mirrors the local prune
    /// with equivalent DELETEs so deletions survive snapshot refreshes.
    retention_prune: struct { keep_runs: u32, dlq_before_ms: i64 },
    source_tested: struct { id: u16, state: domain.ConnState, latency_ms: f32, now_ms: i64 },
    pipeline_status: struct { id: u16, status: domain.PipelineStatus },
    /// Carries the full row so the PG hook can insert in one statement.
    pipeline_add: struct { p: domain.Pipeline },
    pipeline_run_add: struct { run: domain.PipelineRun },
    pipeline_run_update: struct { run: domain.PipelineRun },
    /// Test suite rewrite after a run (statuses + failure counts).
    pipeline_tests: struct { id: u16, tests: [domain.PIPELINE_TEST_CAP]domain.PipelineTest, test_count: u8 },
    dead_letter_add: struct { dl: domain.DeadLetter },
    dead_letter_state: struct { id: u32, state: domain.DlqState },
};

pub const WriteHook = struct {
    ctx: *anyopaque,
    f: *const fn (ctx: *anyopaque, m: Mutation) void,
};

pub const Store = struct {
    allocator: std.mem.Allocator,

    hosts: std.ArrayList(domain.FixedStr(48)) = .empty,
    users: std.ArrayList(domain.FixedStr(32)) = .empty,
    sensors: std.ArrayList(domain.Sensor) = .empty,
    rules: std.ArrayList(domain.DetectionRule) = .empty,
    feeds: std.ArrayList(domain.IntelFeed) = .empty,
    iocs: std.ArrayList(domain.Ioc) = .empty,
    actors: std.ArrayList(domain.ThreatActor) = .empty,
    events: std.ArrayList(domain.Event) = .empty,
    alerts: std.ArrayList(domain.Alert) = .empty,
    cases: std.ArrayList(domain.Case) = .empty,
    yara: std.ArrayList(domain.YaraRule) = .empty,
    enrichments: std.ArrayList(domain.IocEnrichment) = .empty,
    urlscans: std.ArrayList(domain.UrlScanSubmission) = .empty,
    sources: std.ArrayList(domain.DataSource) = .empty,
    pipelines: std.ArrayList(domain.Pipeline) = .empty,
    pipeline_runs: std.ArrayList(domain.PipelineRun) = .empty,
    dead_letters: std.ArrayList(domain.DeadLetter) = .empty,

    /// Bumped on every mutation — panels use it to invalidate cached
    /// filter/sort scratch state.
    generation: u64 = 0,

    /// Installed by the active provider (PG); null under the mock.
    write_hook: ?WriteHook = null,
    /// Audit-trail tap: sees every mutation BEFORE the provider hook. The
    /// Dashboard installs it and owns the entries — never part of the
    /// swappable Store state.
    audit_hook: ?WriteHook = null,

    pub fn init(allocator: std.mem.Allocator) Store {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Store) void {
        self.hosts.deinit(self.allocator);
        self.users.deinit(self.allocator);
        self.sensors.deinit(self.allocator);
        self.rules.deinit(self.allocator);
        self.feeds.deinit(self.allocator);
        self.iocs.deinit(self.allocator);
        self.actors.deinit(self.allocator);
        self.events.deinit(self.allocator);
        self.alerts.deinit(self.allocator);
        self.cases.deinit(self.allocator);
        self.yara.deinit(self.allocator);
        self.enrichments.deinit(self.allocator);
        self.urlscans.deinit(self.allocator);
        self.sources.deinit(self.allocator);
        self.pipelines.deinit(self.allocator);
        self.pipeline_runs.deinit(self.allocator);
        self.dead_letters.deinit(self.allocator);
    }

    pub fn clear(self: *Store) void {
        self.hosts.clearRetainingCapacity();
        self.users.clearRetainingCapacity();
        self.sensors.clearRetainingCapacity();
        self.rules.clearRetainingCapacity();
        self.feeds.clearRetainingCapacity();
        self.iocs.clearRetainingCapacity();
        self.actors.clearRetainingCapacity();
        self.events.clearRetainingCapacity();
        self.alerts.clearRetainingCapacity();
        self.cases.clearRetainingCapacity();
        self.yara.clearRetainingCapacity();
        self.enrichments.clearRetainingCapacity();
        self.urlscans.clearRetainingCapacity();
        self.sources.clearRetainingCapacity();
        self.pipelines.clearRetainingCapacity();
        self.pipeline_runs.clearRetainingCapacity();
        self.dead_letters.clearRetainingCapacity();
        self.generation +%= 1;
    }

    pub fn touch(self: *Store) void {
        self.generation +%= 1;
    }

    /// Snapshot swap: take `other`'s contents wholesale (render thread;
    /// `other` is a fresh world the PG worker loaded off-thread). Keeps
    /// this store's write_hook and keeps `generation` monotonic so panel
    /// caches invalidate. `other` is left empty and safe to destroy.
    pub fn adoptFrom(self: *Store, other: *Store) void {
        const hook = self.write_hook;
        const ahook = self.audit_hook;
        const gen = self.generation;
        self.deinit();
        self.* = other.*;
        self.write_hook = hook;
        self.audit_hook = ahook;
        self.generation = gen +% 1;
        other.* = Store.init(other.allocator);
    }

    fn notify(self: *Store, m: Mutation) void {
        if (self.audit_hook) |h| h.f(h.ctx, m);
        if (self.write_hook) |h| h.f(h.ctx, m);
    }

    // ── Lookup helpers ───────────────────────────────────────────────────

    pub fn hostName(self: *const Store, idx: u16) []const u8 {
        if (idx >= self.hosts.items.len) return "?";
        return self.hosts.items[idx].slice();
    }

    pub fn userName(self: *const Store, idx: u16) []const u8 {
        if (idx >= self.users.items.len) return "?";
        return self.users.items[idx].slice();
    }

    pub fn ruleById(self: *Store, id: u16) ?*domain.DetectionRule {
        for (self.rules.items) |*r| {
            if (r.id == id) return r;
        }
        return null;
    }

    pub fn alertById(self: *Store, id: u32) ?*domain.Alert {
        for (self.alerts.items) |*a| {
            if (a.id == id) return a;
        }
        return null;
    }

    pub fn eventById(self: *Store, id: u64) ?*domain.Event {
        // Events are appended in id order — binary search.
        const items = self.events.items;
        var lo: usize = 0;
        var hi: usize = items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (items[mid].id == id) return &items[mid];
            if (items[mid].id < id) lo = mid + 1 else hi = mid;
        }
        return null;
    }

    pub fn feedById(self: *Store, id: u16) ?*domain.IntelFeed {
        for (self.feeds.items) |*f| {
            if (f.id == id) return f;
        }
        return null;
    }

    pub fn caseById(self: *Store, id: u16) ?*domain.Case {
        for (self.cases.items) |*c| {
            if (c.id == id) return c;
        }
        return null;
    }

    pub fn yaraById(self: *Store, id: u16) ?*domain.YaraRule {
        for (self.yara.items) |*y| {
            if (y.id == id) return y;
        }
        return null;
    }

    pub fn iocById(self: *Store, id: u32) ?*domain.Ioc {
        // IOCs are appended in id order — binary search.
        const items = self.iocs.items;
        var lo: usize = 0;
        var hi: usize = items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (items[mid].id == id) return &items[mid];
            if (items[mid].id < id) lo = mid + 1 else hi = mid;
        }
        return null;
    }

    pub fn enrichmentForIoc(self: *Store, ioc_id: u32) ?*domain.IocEnrichment {
        for (self.enrichments.items) |*e| {
            if (e.ioc_id == ioc_id) return e;
        }
        return null;
    }

    pub fn urlScanForIoc(self: *Store, ioc_id: u32) ?*domain.UrlScanSubmission {
        // Latest submission wins — scan back to front.
        var i = self.urlscans.items.len;
        while (i > 0) {
            i -= 1;
            if (self.urlscans.items[i].ioc_id == ioc_id) return &self.urlscans.items[i];
        }
        return null;
    }

    pub fn sourceById(self: *Store, id: u16) ?*domain.DataSource {
        for (self.sources.items) |*src| {
            if (src.id == id) return src;
        }
        return null;
    }

    pub fn pipelineById(self: *Store, id: u16) ?*domain.Pipeline {
        for (self.pipelines.items) |*p| {
            if (p.id == id) return p;
        }
        return null;
    }

    /// Latest run for a pipeline (runs append in start order — scan back).
    pub fn lastRunFor(self: *Store, pipeline_id: u16) ?*domain.PipelineRun {
        var i = self.pipeline_runs.items.len;
        while (i > 0) {
            i -= 1;
            if (self.pipeline_runs.items[i].pipeline == pipeline_id) return &self.pipeline_runs.items[i];
        }
        return null;
    }

    // ── Aggregates (PST / footer) ────────────────────────────────────────

    pub fn openAlertCountBySeverity(self: *const Store) [5]u32 {
        var out: [5]u32 = @splat(0);
        for (self.alerts.items) |*a| {
            if (a.status.isOpen()) out[@intFromEnum(a.severity)] += 1;
        }
        return out;
    }

    pub fn openCaseCount(self: *const Store) u32 {
        var n: u32 = 0;
        for (self.cases.items) |*c| {
            if (c.status != .closed) n += 1;
        }
        return n;
    }

    pub fn sensorsDown(self: *const Store) u32 {
        var n: u32 = 0;
        for (self.sensors.items) |*s| {
            if (s.status == .down) n += 1;
        }
        return n;
    }

    /// Rule coverage for a technique: 0 = none, 1 = testing only,
    /// 2 = enabled rule exists.
    pub fn coverageForTechnique(self: *const Store, tid: domain.attack.TechniqueId) u8 {
        var best: u8 = 0;
        for (self.rules.items) |*r| {
            if (r.technique != tid) continue;
            switch (r.status) {
                .enabled => return 2,
                .testing => best = @max(best, 1),
                .disabled => {},
            }
        }
        return best;
    }

    /// Open-alert count tagged with a technique (ATK heat).
    pub fn alertHeatForTechnique(self: *const Store, tid: domain.attack.TechniqueId) u32 {
        var n: u32 = 0;
        for (self.alerts.items) |*a| {
            if (a.status.isOpen() and a.technique != null and a.technique.? == tid) n += 1;
        }
        return n;
    }

    /// YARA coverage for a technique: 0 = none, 1 = draft/deprecated only,
    /// 2 = active rule exists.
    pub fn yaraCoverageForTechnique(self: *const Store, tid: domain.attack.TechniqueId) u8 {
        var best: u8 = 0;
        for (self.yara.items) |*y| {
            if (y.technique != tid) continue;
            if (y.status == .active) return 2;
            best = @max(best, 1);
        }
        return best;
    }

    /// Grade histogram indexed A=0 … F=4.
    pub fn yaraGradeHistogram(self: *const Store) [5]u32 {
        var out: [5]u32 = @splat(0);
        for (self.yara.items) |*y| {
            out[switch (y.grade()) {
                'A' => 0,
                'B' => 1,
                'C' => 2,
                'D' => 3,
                else => 4,
            }] += 1;
        }
        return out;
    }

    pub fn yaraSeverityDistribution(self: *const Store) [5]u32 {
        var out: [5]u32 = @splat(0);
        for (self.yara.items) |*y| {
            out[@intFromEnum(y.severity)] += 1;
        }
        return out;
    }

    pub fn yaraGatePassCounts(self: *const Store) struct { pass: u32, fail: u32 } {
        var pass: u32 = 0;
        var fail: u32 = 0;
        for (self.yara.items) |*y| {
            if (y.gates.allPass()) pass += 1 else fail += 1;
        }
        return .{ .pass = pass, .fail = fail };
    }

    pub fn enrichedCounts(self: *const Store) struct { done: u32, pending: u32, err: u32 } {
        var done: u32 = 0;
        var pending: u32 = 0;
        var err: u32 = 0;
        for (self.enrichments.items) |*e| {
            switch (e.status) {
                .done => done += 1,
                .pending => pending += 1,
                .err => err += 1,
                .none => {},
            }
        }
        return .{ .done = done, .pending = pending, .err = err };
    }

    /// Pipeline counts indexed by PipelineStatus (active/paused/err/draft).
    pub fn pipelineStatusCounts(self: *const Store) [4]u32 {
        var out: [4]u32 = @splat(0);
        for (self.pipelines.items) |*p| out[@intFromEnum(p.status)] += 1;
        return out;
    }

    pub fn sourceStateCounts(self: *const Store) [3]u32 {
        var out: [3]u32 = @splat(0);
        for (self.sources.items) |*src| out[@intFromEnum(src.state)] += 1;
        return out;
    }

    /// dbt test suite tallies across every pipeline.
    pub fn pipelineTestCounts(self: *const Store) struct { pass: u32, fail: u32 } {
        var pass: u32 = 0;
        var fail: u32 = 0;
        for (self.pipelines.items) |*p| {
            const tc = p.testCounts();
            pass += tc.pass;
            fail += tc.fail;
        }
        return .{ .pass = pass, .fail = fail };
    }

    /// Rows landed in sinks by runs that STARTED after `since_ms`.
    pub fn rowsIngestedSince(self: *const Store, since_ms: i64) u64 {
        var n: u64 = 0;
        for (self.pipeline_runs.items) |*r| {
            if (r.started_ms >= since_ms and r.status != .running) n += r.rows_out;
        }
        return n;
    }

    // ── Mutations (panel actions) ────────────────────────────────────────

    /// Status change with SLA stamps: first ack sets acked_ms, a terminal
    /// close sets resolved_ms (and backfills acked_ms) — MTTA/MTTR feed.
    pub fn setAlertStatus(self: *Store, id: u32, status: domain.AlertStatus, now_ms: i64) bool {
        const a = self.alertById(id) orelse return false;
        a.status = status;
        switch (status) {
            .acked, .investigating => {
                if (a.acked_ms == 0) a.acked_ms = now_ms;
            },
            .resolved, .false_positive, .suppressed => {
                if (a.acked_ms == 0) a.acked_ms = now_ms;
                if (a.resolved_ms == 0) a.resolved_ms = now_ms;
            },
            .new => {}, // reopen keeps historical stamps
        }
        self.touch();
        self.notify(.{ .alert_status = .{
            .id = id,
            .status = status,
            .acked_ms = a.acked_ms,
            .resolved_ms = a.resolved_ms,
        } });
        return true;
    }

    /// Mean time-to-acknowledge / time-to-resolve over stamped alerts (ms;
    /// null when nothing is stamped yet).
    pub fn triageMeans(self: *const Store) struct { mtta_ms: ?i64, mttr_ms: ?i64 } {
        var acked_sum: i64 = 0;
        var acked_n: i64 = 0;
        var res_sum: i64 = 0;
        var res_n: i64 = 0;
        for (self.alerts.items) |*a| {
            if (a.acked_ms > a.ts_ms) {
                acked_sum += a.acked_ms - a.ts_ms;
                acked_n += 1;
            }
            if (a.resolved_ms > a.ts_ms) {
                res_sum += a.resolved_ms - a.ts_ms;
                res_n += 1;
            }
        }
        return .{
            .mtta_ms = if (acked_n > 0) @divFloor(acked_sum, acked_n) else null,
            .mttr_ms = if (res_n > 0) @divFloor(res_sum, res_n) else null,
        };
    }

    /// Attach an alert to a case (and mirror case_id on the alert).
    pub fn assignAlertToCase(self: *Store, alert_id: u32, case_id: u16, now_ms: i64) bool {
        const a = self.alertById(alert_id) orelse return false;
        const c = self.caseById(case_id) orelse return false;
        if (c.alert_count >= domain.CASE_ALERT_CAP) return false;
        // Already linked?
        for (c.alert_ids[0..c.alert_count]) |aid| {
            if (aid == alert_id) return true;
        }
        c.alert_ids[c.alert_count] = alert_id;
        c.alert_count += 1;
        c.updated_ms = now_ms;
        a.case_id = case_id;
        if (a.status == .new) a.status = .investigating;
        self.touch();
        self.notify(.{ .case_assign = .{ .alert_id = alert_id, .case_id = case_id, .now_ms = now_ms } });
        return true;
    }

    /// Detach an alert from its case (reverse of assignAlertToCase). An
    /// implicit `.investigating` flip reverts to `.new`; explicit statuses
    /// stay put.
    pub fn unassignAlertFromCase(self: *Store, alert_id: u32, now_ms: i64) bool {
        const a = self.alertById(alert_id) orelse return false;
        const cid = a.case_id orelse return false;
        const c = self.caseById(cid) orelse return false;
        var i: u8 = 0;
        while (i < c.alert_count) : (i += 1) {
            if (c.alert_ids[i] != alert_id) continue;
            var j = i;
            while (j + 1 < c.alert_count) : (j += 1) c.alert_ids[j] = c.alert_ids[j + 1];
            c.alert_count -= 1;
            break;
        }
        c.updated_ms = now_ms;
        a.case_id = null;
        if (a.status == .investigating) a.status = .new;
        self.touch();
        self.notify(.{ .case_unassign = .{ .alert_id = alert_id, .case_id = cid, .now_ms = now_ms } });
        return true;
    }

    /// Open a new case; assigns the next free id. Returns the id (or null
    /// on OOM).
    pub fn addCase(self: *Store, proto: domain.Case) ?u16 {
        var next: u16 = 1;
        for (self.cases.items) |*c| {
            if (c.id >= next) next = c.id + 1;
        }
        var c = proto;
        c.id = next;
        self.cases.append(self.allocator, c) catch return null;
        self.touch();
        self.notify(.{ .case_add = .{ .c = c } });
        return next;
    }

    /// Edit case metadata (title / severity / assignee).
    pub fn updateCaseMeta(self: *Store, id: u16, title: []const u8, severity: domain.Severity, assignee: []const u8, now_ms: i64) bool {
        const c = self.caseById(id) orelse return false;
        c.title = domain.FixedStr(96).from(title);
        c.severity = severity;
        c.assignee = domain.FixedStr(24).from(assignee);
        c.updated_ms = now_ms;
        self.touch();
        self.notify(.{ .case_update = .{ .id = id, .title = c.title, .severity = severity, .assignee = c.assignee, .now_ms = now_ms } });
        return true;
    }

    /// Feed sync lifecycle. `sync_ms` non-null stamps last_sync_ms (a
    /// successful sync); null keeps the previous stamp (start / failure /
    /// cancel-revert).
    pub fn setFeedStatus(self: *Store, id: u16, status: domain.FeedStatus, sync_ms: ?i64) bool {
        const f = self.feedById(id) orelse return false;
        f.status = status;
        if (sync_ms) |ms| f.last_sync_ms = ms;
        self.touch();
        self.notify(.{ .feed_status = .{ .id = id, .status = status, .last_sync_ms = f.last_sync_ms } });
        return true;
    }

    /// Analyst FP feedback: bump a rule's 7-day false-positive count.
    pub fn bumpRuleFp(self: *Store, id: u16) bool {
        const r = self.ruleById(id) orelse return false;
        r.fp_7d += 1;
        self.touch();
        self.notify(.{ .rule_fp = .{ .id = id, .fp_7d = r.fp_7d } });
        return true;
    }

    pub fn setRuleStatus(self: *Store, id: u16, status: domain.RuleStatus) bool {
        const r = self.ruleById(id) orelse return false;
        r.status = status;
        self.touch();
        self.notify(.{ .rule_status = .{ .id = id, .status = status } });
        return true;
    }

    pub fn setCaseStatus(self: *Store, id: u16, status: domain.CaseStatus, now_ms: i64) bool {
        const c = self.caseById(id) orelse return false;
        c.status = status;
        c.updated_ms = now_ms;
        self.touch();
        self.notify(.{ .case_status = .{ .id = id, .status = status, .now_ms = now_ms } });
        return true;
    }

    pub fn setYaraStatus(self: *Store, id: u16, status: domain.YaraStatus) bool {
        const y = self.yaraById(id) orelse return false;
        y.status = status;
        self.touch();
        self.notify(.{ .yara_status = .{ .id = id, .status = status } });
        return true;
    }

    /// Record a CI run's gate results for one rule.
    pub fn recordYaraCi(self: *Store, id: u16, gates: domain.YaraGates) bool {
        const y = self.yaraById(id) orelse return false;
        y.gates = gates;
        self.touch();
        self.notify(.{ .yara_ci = .{ .id = id, .gates = gates } });
        return true;
    }

    /// Insert or replace the enrichment row for `e.ioc_id`. This is the
    /// entry point any async source (mock job today, live MCP later) uses.
    pub fn upsertEnrichment(self: *Store, e: domain.IocEnrichment) bool {
        if (self.enrichmentForIoc(e.ioc_id)) |existing| {
            existing.* = e;
        } else {
            self.enrichments.append(self.allocator, e) catch return false;
        }
        self.touch();
        self.notify(.{ .enrichment_upsert = .{ .e = e } });
        return true;
    }

    /// Create a url-scan submission for a url-type IOC; returns its id.
    pub fn submitUrlScan(self: *Store, ioc_id: u32, now_ms: i64) ?u32 {
        var next: u32 = 1;
        for (self.urlscans.items) |*u| {
            if (u.id >= next) next = u.id + 1;
        }
        self.urlscans.append(self.allocator, .{
            .id = next,
            .ioc_id = ioc_id,
            .state = .pending,
            .submitted_ms = now_ms,
        }) catch return null;
        self.touch();
        self.notify(.{ .urlscan_submit = .{ .id = next, .ioc_id = ioc_id, .now_ms = now_ms } });
        return next;
    }

    pub fn setUrlScanState(self: *Store, id: u32, state: domain.ScanState, err: []const u8, now_ms: i64) bool {
        for (self.urlscans.items) |*u| {
            if (u.id != id) continue;
            u.state = state;
            u.err = domain.FixedStr(32).from(err);
            if (state == .done or state == .err) u.completed_ms = now_ms;
            self.touch();
            self.notify(.{ .urlscan_update = .{ .id = id, .state = state, .err = u.err, .now_ms = now_ms } });
            return true;
        }
        return false;
    }

    pub fn setCaseNotes(self: *Store, id: u16, notes: []const u8, now_ms: i64) bool {
        const c = self.caseById(id) orelse return false;
        c.notes = domain.FixedStr(480).from(notes);
        c.updated_ms = now_ms;
        self.touch();
        self.notify(.{ .case_notes = .{ .id = id, .notes = c.notes, .now_ms = now_ms } });
        return true;
    }

    /// Record a connection-test result for a source.
    pub fn recordSourceTest(self: *Store, id: u16, state: domain.ConnState, latency_ms: f32, now_ms: i64) bool {
        const src = self.sourceById(id) orelse return false;
        src.state = state;
        src.latency_ms = latency_ms;
        src.last_test_ms = now_ms;
        self.touch();
        self.notify(.{ .source_tested = .{ .id = id, .state = state, .latency_ms = latency_ms, .now_ms = now_ms } });
        return true;
    }

    pub fn setPipelineStatus(self: *Store, id: u16, status: domain.PipelineStatus) bool {
        const p = self.pipelineById(id) orelse return false;
        p.status = status;
        self.touch();
        self.notify(.{ .pipeline_status = .{ .id = id, .status = status } });
        return true;
    }

    /// Register a builder-created pipeline; assigns the next free id and
    /// code. Returns the id, or null when the source is dangling / OOM.
    pub fn addPipeline(self: *Store, proto: domain.Pipeline) ?u16 {
        if (self.sourceById(proto.source) == null) return null;
        var next: u16 = 1;
        for (self.pipelines.items) |*p| {
            if (p.id >= next) next = p.id + 1;
        }
        var p = proto;
        p.id = next;
        p.code = domain.FixedStr(8).fromFmt("P-{d:0>4}", .{next});
        self.pipelines.append(self.allocator, p) catch return null;
        self.touch();
        self.notify(.{ .pipeline_add = .{ .p = p } });
        return next;
    }

    /// Start a run (status .running unless the caller pre-finalized it);
    /// assigns the next free run id and stamps the pipeline's last_run_ms.
    pub fn addPipelineRun(self: *Store, proto: domain.PipelineRun) ?u32 {
        const p = self.pipelineById(proto.pipeline) orelse return null;
        var next: u32 = 1;
        for (self.pipeline_runs.items) |*r| {
            if (r.id >= next) next = r.id + 1;
        }
        var run = proto;
        run.id = next;
        self.pipeline_runs.append(self.allocator, run) catch return null;
        p.last_run_ms = @max(p.last_run_ms, run.started_ms);
        self.touch();
        self.notify(.{ .pipeline_run_add = .{ .run = run } });
        return next;
    }

    /// Finalize a run in place (rows, duration, status, test tallies).
    /// Successful/partial runs advance the pipeline's watermark.
    pub fn updatePipelineRun(self: *Store, run: domain.PipelineRun) bool {
        for (self.pipeline_runs.items) |*r| {
            if (r.id != run.id) continue;
            r.* = run;
            if (run.status == .success or run.status == .partial) {
                if (self.pipelineById(run.pipeline)) |p| {
                    p.watermark_ms = @max(p.watermark_ms, run.watermark_ms);
                }
            }
            self.touch();
            self.notify(.{ .pipeline_run_update = .{ .run = run } });
            return true;
        }
        return false;
    }

    /// Append a dead-letter record; assigns the next free id.
    pub fn addDeadLetter(self: *Store, proto: domain.DeadLetter) ?u32 {
        if (self.pipelineById(proto.pipeline) == null) return null;
        var next: u32 = 1;
        for (self.dead_letters.items) |*dl| {
            if (dl.id >= next) next = dl.id + 1;
        }
        var dl = proto;
        dl.id = next;
        self.dead_letters.append(self.allocator, dl) catch return null;
        self.touch();
        self.notify(.{ .dead_letter_add = .{ .dl = dl } });
        return next;
    }

    pub fn setDeadLetterState(self: *Store, id: u32, state: domain.DlqState) bool {
        for (self.dead_letters.items) |*dl| {
            if (dl.id != id) continue;
            dl.state = state;
            self.touch();
            self.notify(.{ .dead_letter_state = .{ .id = id, .state = state } });
            return true;
        }
        return false;
    }

    pub fn openDeadLetterCount(self: *const Store, pipeline_id: u16) u32 {
        var n: u32 = 0;
        for (self.dead_letters.items) |*dl| {
            if (dl.pipeline == pipeline_id and dl.state == .open) n += 1;
        }
        return n;
    }

    /// Retention sweep: prune old runs + resolved dead letters locally and
    /// notify ONCE so the PG hook mirrors the deletions (they survive
    /// snapshot refreshes) and the sweep lands in the audit trail.
    pub fn pruneRetention(self: *Store, keep_runs: u32, dlq_before_ms: i64) struct { runs: u32, dlq: u32 } {
        const runs = self.prunePipelineRuns(keep_runs);
        const dlq = self.pruneDeadLetters(dlq_before_ms);
        self.notify(.{ .retention_prune = .{ .keep_runs = keep_runs, .dlq_before_ms = dlq_before_ms } });
        return .{ .runs = runs, .dlq = dlq };
    }

    // ── Retention (row removal helpers; mirrored to PG only through
    //    pruneRetention's single mutation) ───────────────────────────────────

    /// Drop the oldest completed runs beyond `keep` per pipeline. Returns
    /// how many were removed.
    pub fn prunePipelineRuns(self: *Store, keep: u32) u32 {
        var removed: u32 = 0;
        for (self.pipelines.items) |*p| {
            var n: u32 = 0;
            for (self.pipeline_runs.items) |*r| {
                if (r.pipeline == p.id and r.status != .running) n += 1;
            }
            // Runs append in start order — remove from the front.
            var i: usize = 0;
            while (n > keep and i < self.pipeline_runs.items.len) {
                const r = &self.pipeline_runs.items[i];
                if (r.pipeline == p.id and r.status != .running) {
                    _ = self.pipeline_runs.orderedRemove(i);
                    n -= 1;
                    removed += 1;
                    continue;
                }
                i += 1;
            }
        }
        if (removed > 0) self.touch();
        return removed;
    }

    /// Drop replayed/dropped dead letters older than `before_ms`.
    pub fn pruneDeadLetters(self: *Store, before_ms: i64) u32 {
        var removed: u32 = 0;
        var i: usize = 0;
        while (i < self.dead_letters.items.len) {
            const dl = &self.dead_letters.items[i];
            if (dl.state != .open and dl.ts_ms < before_ms) {
                _ = self.dead_letters.orderedRemove(i);
                removed += 1;
                continue;
            }
            i += 1;
        }
        if (removed > 0) self.touch();
        return removed;
    }

    /// Rewrite a pipeline's dbt test results after a run.
    pub fn setPipelineTests(self: *Store, id: u16, tests: [domain.PIPELINE_TEST_CAP]domain.PipelineTest, test_count: u8) bool {
        const p = self.pipelineById(id) orelse return false;
        p.tests = tests;
        p.test_count = @min(test_count, domain.PIPELINE_TEST_CAP);
        self.touch();
        self.notify(.{ .pipeline_tests = .{ .id = id, .tests = p.tests, .test_count = p.test_count } });
        return true;
    }
};

test "store mutations + aggregates" {
    var s = Store.init(std.testing.allocator);
    defer s.deinit();

    try s.rules.append(s.allocator, .{ .id = 7, .technique = 0, .status = .testing });
    try s.alerts.append(s.allocator, .{ .id = 1, .ts_ms = 0, .rule = 7, .severity = .high, .technique = 0 });
    try s.cases.append(s.allocator, .{ .id = 3 });

    try std.testing.expectEqual(@as(u8, 1), s.coverageForTechnique(0));
    try std.testing.expect(s.setRuleStatus(7, .enabled));
    try std.testing.expectEqual(@as(u8, 2), s.coverageForTechnique(0));

    const by_sev = s.openAlertCountBySeverity();
    try std.testing.expectEqual(@as(u32, 1), by_sev[@intFromEnum(domain.Severity.high)]);

    // Triage SLA stamps: ack sets acked_ms once; resolve backfills.
    try std.testing.expect(s.setAlertStatus(1, .acked, 60_000));
    try std.testing.expectEqual(@as(i64, 60_000), s.alertById(1).?.acked_ms);
    try std.testing.expect(s.setAlertStatus(1, .resolved, 120_000));
    try std.testing.expectEqual(@as(i64, 60_000), s.alertById(1).?.acked_ms); // unchanged
    try std.testing.expectEqual(@as(i64, 120_000), s.alertById(1).?.resolved_ms);
    const means = s.triageMeans();
    try std.testing.expectEqual(@as(?i64, 60_000), means.mtta_ms);
    try std.testing.expectEqual(@as(?i64, 120_000), means.mttr_ms);
    try std.testing.expect(s.setAlertStatus(1, .new, 130_000)); // reopen for the case-assign flow below

    try std.testing.expect(s.assignAlertToCase(1, 3, 42));
    try std.testing.expectEqual(@as(u8, 1), s.cases.items[0].alert_count);
    try std.testing.expectEqual(domain.AlertStatus.investigating, s.alerts.items[0].status);
}

test "yara + enrichment + urlscan round-trips" {
    var s = Store.init(std.testing.allocator);
    defer s.deinit();

    try s.yara.append(s.allocator, .{ .id = 1, .technique = 0, .status = .draft });
    try std.testing.expectEqual(@as(u8, 1), s.yaraCoverageForTechnique(0));
    try std.testing.expect(s.setYaraStatus(1, .active));
    try std.testing.expectEqual(@as(u8, 2), s.yaraCoverageForTechnique(0));
    try std.testing.expect(s.recordYaraCi(1, .{ .tp = .fail, .scan_ms = 12 }));
    try std.testing.expectEqual(domain.GateResult.fail, s.yara.items[0].gates.tp);
    try std.testing.expectEqual(@as(u32, 1), s.yaraGatePassCounts().fail);

    try s.iocs.append(s.allocator, .{ .id = 9, .type = .url });
    try std.testing.expect(s.upsertEnrichment(.{ .ioc_id = 9, .status = .pending }));
    try std.testing.expectEqual(@as(u32, 1), s.enrichedCounts().pending);
    try std.testing.expect(s.upsertEnrichment(.{ .ioc_id = 9, .status = .done, .verdict = .malicious }));
    try std.testing.expectEqual(@as(usize, 1), s.enrichments.items.len); // replaced, not appended
    try std.testing.expectEqual(domain.Verdict.malicious, s.enrichmentForIoc(9).?.verdict);

    const scan_id = s.submitUrlScan(9, 100).?;
    try std.testing.expect(s.setUrlScanState(scan_id, .done, "", 200));
    try std.testing.expectEqual(@as(i64, 200), s.urlScanForIoc(9).?.completed_ms);
    const scan2 = s.submitUrlScan(9, 300).?;
    try std.testing.expect(s.setUrlScanState(scan2, .err, "canceled", 400));
    try std.testing.expectEqualStrings("canceled", s.urlScanForIoc(9).?.err.slice());
}

test "case create / meta edit / unassign + feed status + rule fp" {
    var s = Store.init(std.testing.allocator);
    defer s.deinit();

    try s.alerts.append(s.allocator, .{ .id = 5, .ts_ms = 0, .rule = 1, .severity = .high });
    const cid = s.addCase(.{ .id = 0, .title = domain.FixedStr(96).from("Suspicious beaconing"), .severity = .high, .opened_ms = 10, .updated_ms = 10 }).?;
    try std.testing.expect(s.assignAlertToCase(5, cid, 20));
    try std.testing.expectEqual(domain.AlertStatus.investigating, s.alertById(5).?.status);

    // Unassign reverts the implicit investigating flip and detaches both sides.
    try std.testing.expect(s.unassignAlertFromCase(5, 30));
    try std.testing.expectEqual(@as(?u16, null), s.alertById(5).?.case_id);
    try std.testing.expectEqual(@as(u8, 0), s.caseById(cid).?.alert_count);
    try std.testing.expectEqual(domain.AlertStatus.new, s.alertById(5).?.status);
    try std.testing.expect(!s.unassignAlertFromCase(5, 31)); // no case anymore

    try std.testing.expect(s.updateCaseMeta(cid, "Beaconing (contained)", .medium, "nblake", 40));
    try std.testing.expectEqualStrings("Beaconing (contained)", s.caseById(cid).?.title.slice());
    try std.testing.expectEqual(domain.Severity.medium, s.caseById(cid).?.severity);

    try s.feeds.append(s.allocator, .{ .id = 2, .name = domain.FixedStr(48).from("AbuseCH"), .last_sync_ms = 100 });
    try std.testing.expect(s.setFeedStatus(2, .syncing, null));
    try std.testing.expectEqual(@as(i64, 100), s.feedById(2).?.last_sync_ms); // unchanged
    try std.testing.expect(s.setFeedStatus(2, .ok, 500));
    try std.testing.expectEqual(@as(i64, 500), s.feedById(2).?.last_sync_ms);

    try s.rules.append(s.allocator, .{ .id = 9, .technique = 0, .fp_7d = 3 });
    try std.testing.expect(s.bumpRuleFp(9));
    try std.testing.expectEqual(@as(u32, 4), s.ruleById(9).?.fp_7d);
}

test "pipeline + source round-trips" {
    var s = Store.init(std.testing.allocator);
    defer s.deinit();

    try s.sources.append(s.allocator, .{ .id = 1, .kind = .kafka, .name = domain.FixedStr(48).from("events bus") });
    try std.testing.expect(s.recordSourceTest(1, .degraded, 240, 100));
    try std.testing.expectEqual(domain.ConnState.degraded, s.sourceById(1).?.state);

    // Builder path: dangling source rejected, live source accepted.
    try std.testing.expectEqual(@as(?u16, null), s.addPipeline(.{ .id = 0, .source = 99 }));
    var proto = domain.Pipeline{ .id = 0, .source = 1, .name = domain.FixedStr(64).from("edr_events_ingest") };
    proto.steps[0] = .{ .kind = .staging, .model = domain.FixedStr(48).from("stg_edr_events") };
    proto.step_count = 1;
    const pid = s.addPipeline(proto).?;
    try std.testing.expectEqualStrings("P-0001", s.pipelineById(pid).?.code.slice());

    // Run lifecycle: add running → finalize.
    const rid = s.addPipelineRun(.{ .id = 0, .pipeline = pid, .started_ms = 500 }).?;
    try std.testing.expectEqual(@as(i64, 500), s.pipelineById(pid).?.last_run_ms);
    var run = s.lastRunFor(pid).?.*;
    run.status = .success;
    run.rows_in = 1000;
    run.rows_out = 990;
    run.duration_ms = 4200;
    try std.testing.expect(s.updatePipelineRun(run));
    try std.testing.expectEqual(domain.RunStatus.success, s.lastRunFor(pid).?.status);
    try std.testing.expectEqual(@as(u64, 990), s.rowsIngestedSince(0));
    try std.testing.expectEqual(@as(u32, rid), s.lastRunFor(pid).?.id);

    try std.testing.expect(s.setPipelineStatus(pid, .paused));
    try std.testing.expectEqual(@as(u32, 1), s.pipelineStatusCounts()[@intFromEnum(domain.PipelineStatus.paused)]);

    var tests: [domain.PIPELINE_TEST_CAP]domain.PipelineTest = @splat(domain.PipelineTest{});
    tests[0] = .{ .kind = .unique, .target = domain.FixedStr(48).from("stg_edr_events.event_id"), .status = .fail, .failures = 3 };
    try std.testing.expect(s.setPipelineTests(pid, tests, 1));
    try std.testing.expectEqual(@as(u32, 1), s.pipelineTestCounts().fail);
}

test "adoptFrom swaps contents, keeps hook + monotonic generation" {
    const gpa = std.testing.allocator;
    const Hook = struct {
        var hits: usize = 0;
        fn f(_: *anyopaque, _: Mutation) void {
            hits += 1;
        }
    };

    var live = Store.init(gpa);
    defer live.deinit();
    try live.alerts.append(gpa, .{ .id = 1, .ts_ms = 0, .rule = 0, .severity = .low });
    var dummy: u8 = 0;
    live.write_hook = .{ .ctx = &dummy, .f = Hook.f };
    live.touch();
    live.touch();
    const gen_before = live.generation;

    var snap = Store.init(gpa);
    defer snap.deinit(); // empty after adoption — must be a safe no-op
    try snap.alerts.append(gpa, .{ .id = 2, .ts_ms = 5, .rule = 0, .severity = .high });
    try snap.alerts.append(gpa, .{ .id = 3, .ts_ms = 6, .rule = 0, .severity = .high });

    live.adoptFrom(&snap);
    try std.testing.expectEqual(@as(usize, 2), live.alerts.items.len);
    try std.testing.expectEqual(@as(usize, 0), snap.alerts.items.len);
    try std.testing.expectEqual(gen_before +% 1, live.generation);
    // Hook survived the swap and still fires on mutation.
    try std.testing.expect(live.setAlertStatus(2, .acked, 42));
    try std.testing.expectEqual(@as(usize, 1), Hook.hits);
}

test "dead letters + watermark + retention" {
    var s = Store.init(std.testing.allocator);
    defer s.deinit();
    try s.sources.append(s.allocator, .{ .id = 1, .kind = .kafka });
    const pid = s.addPipeline(.{ .id = 0, .source = 1, .name = domain.FixedStr(64).from("wm_test") }).?;

    // Watermark advances only on success/partial.
    _ = s.addPipelineRun(.{ .id = 0, .pipeline = pid, .started_ms = 100 }).?;
    var run = s.lastRunFor(pid).?.*;
    run.status = .failed;
    run.watermark_ms = 500;
    try std.testing.expect(s.updatePipelineRun(run));
    try std.testing.expectEqual(@as(i64, 0), s.pipelineById(pid).?.watermark_ms);
    run.status = .success;
    try std.testing.expect(s.updatePipelineRun(run));
    try std.testing.expectEqual(@as(i64, 500), s.pipelineById(pid).?.watermark_ms);

    // DLQ lifecycle + counts.
    try std.testing.expectEqual(@as(?u32, null), s.addDeadLetter(.{ .id = 0, .pipeline = 99, .run_id = 1 }));
    const dl_id = s.addDeadLetter(.{ .id = 0, .pipeline = pid, .run_id = run.id, .ts_ms = 10, .kind = .unique }).?;
    try std.testing.expectEqual(@as(u32, 1), s.openDeadLetterCount(pid));
    try std.testing.expect(s.setDeadLetterState(dl_id, .dropped));
    try std.testing.expectEqual(@as(u32, 0), s.openDeadLetterCount(pid));

    // Retention: resolved dead letters + old completed runs prune.
    try std.testing.expectEqual(@as(u32, 1), s.pruneDeadLetters(100));
    var k: u32 = 0;
    while (k < 5) : (k += 1) {
        _ = s.addPipelineRun(.{ .id = 0, .pipeline = pid, .started_ms = 200 + k }).?;
        var rr = s.lastRunFor(pid).?.*;
        rr.status = .success;
        _ = s.updatePipelineRun(rr);
    }
    try std.testing.expectEqual(@as(u32, 4), s.prunePipelineRuns(2));
}

test "case notes round-trip" {
    var s = Store.init(std.testing.allocator);
    defer s.deinit();
    try s.cases.append(s.allocator, .{ .id = 3 });
    try std.testing.expect(s.setCaseNotes(3, "containment done; resetting creds", 42));
    try std.testing.expectEqualStrings("containment done; resetting creds", s.caseById(3).?.notes.slice());
    try std.testing.expectEqual(@as(i64, 42), s.caseById(3).?.updated_ms);
}

test {
    std.testing.refAllDecls(@This());
}
