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

test {
    std.testing.refAllDecls(@This());
}
