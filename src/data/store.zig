//! In-memory world state read by every panel and written by a provider
//! (the mock generator today; the Postgres worker in a later phase).
//! Panels never query a backend directly — they read Store snapshots and
//! mutate through the small action API here, so swapping the provider
//! never touches panel code.

const std = @import("std");
const domain = @import("domain");

pub const mock = @import("mock.zig");
pub const pg = @import("pg.zig");

/// Mutations panels perform through the Store — mirrored to the active
/// provider via `write_hook` so a backing database stays in sync.
pub const Mutation = union(enum) {
    alert_status: struct { id: u32, status: domain.AlertStatus },
    rule_status: struct { id: u16, status: domain.RuleStatus },
    case_status: struct { id: u16, status: domain.CaseStatus, now_ms: i64 },
    case_assign: struct { alert_id: u32, case_id: u16, now_ms: i64 },
    yara_status: struct { id: u16, status: domain.YaraStatus },
    yara_ci: struct { id: u16, gates: domain.YaraGates },
    /// Carries the full row so the PG hook can upsert in one statement.
    enrichment_upsert: struct { e: domain.IocEnrichment },
    urlscan_submit: struct { id: u32, ioc_id: u32, now_ms: i64 },
    urlscan_update: struct { id: u32, state: domain.ScanState, now_ms: i64 },
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

    /// Bumped on every mutation — panels use it to invalidate cached
    /// filter/sort scratch state.
    generation: u64 = 0,

    /// Installed by the active provider (PG); null under the mock.
    write_hook: ?WriteHook = null,

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
        self.generation +%= 1;
    }

    pub fn touch(self: *Store) void {
        self.generation +%= 1;
    }

    fn notify(self: *Store, m: Mutation) void {
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

    // ── Mutations (panel actions) ────────────────────────────────────────

    pub fn setAlertStatus(self: *Store, id: u32, status: domain.AlertStatus) bool {
        const a = self.alertById(id) orelse return false;
        a.status = status;
        self.touch();
        self.notify(.{ .alert_status = .{ .id = id, .status = status } });
        return true;
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

    pub fn setUrlScanState(self: *Store, id: u32, state: domain.ScanState, now_ms: i64) bool {
        for (self.urlscans.items) |*u| {
            if (u.id != id) continue;
            u.state = state;
            if (state == .done or state == .err) u.completed_ms = now_ms;
            self.touch();
            self.notify(.{ .urlscan_update = .{ .id = id, .state = state, .now_ms = now_ms } });
            return true;
        }
        return false;
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
    try std.testing.expect(s.setUrlScanState(scan_id, .done, 200));
    try std.testing.expectEqual(@as(i64, 200), s.urlScanForIoc(9).?.completed_ms);
}

test {
    std.testing.refAllDecls(@This());
}
