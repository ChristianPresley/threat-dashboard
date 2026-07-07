//! Threat-hunting domain model: alerts, events, detection rules, IOCs,
//! cases, sensors, intel feeds, threat actors. Pure std — no UI deps.
//!
//! Strings are fixed-capacity inline buffers (no allocator churn in render
//! paths; rows copy by value). Entity cross-references are by id/index into
//! the owning Store lists.

const std = @import("std");

pub const attack = @import("attack.zig");

/// Fixed-capacity inline string. `from` truncates silently.
pub fn FixedStr(comptime cap: usize) type {
    return struct {
        const Self = @This();
        pub const capacity = cap;

        buf: [cap]u8 = @splat(0),
        len: u16 = 0,

        pub fn from(s: []const u8) Self {
            var out: Self = .{};
            const n = @min(s.len, cap);
            @memcpy(out.buf[0..n], s[0..n]);
            out.len = @intCast(n);
            return out;
        }

        pub fn fromFmt(comptime fmt: []const u8, args: anytype) Self {
            var out: Self = .{};
            const s = std.fmt.bufPrint(&out.buf, fmt, args) catch out.buf[0..cap];
            out.len = @intCast(s.len);
            return out;
        }

        pub fn slice(self: *const Self) []const u8 {
            return self.buf[0..self.len];
        }

        pub fn set(self: *Self, s: []const u8) void {
            self.* = from(s);
        }
    };
}

// ── Severity / status vocabulary ─────────────────────────────────────────

pub const Severity = enum(u8) {
    info,
    low,
    medium,
    high,
    critical,

    pub fn label(self: Severity) [:0]const u8 {
        return switch (self) {
            .info => "INFO",
            .low => "LOW",
            .medium => "MED",
            .high => "HIGH",
            .critical => "CRIT",
        };
    }
};

pub const AlertStatus = enum(u8) {
    new,
    acked,
    investigating,
    resolved,
    false_positive,
    suppressed,

    pub fn label(self: AlertStatus) [:0]const u8 {
        return switch (self) {
            .new => "NEW",
            .acked => "ACKED",
            .investigating => "INVEST",
            .resolved => "RESOLVED",
            .false_positive => "FALSE+",
            .suppressed => "SUPPR",
        };
    }

    /// Open = still needs analyst attention.
    pub fn isOpen(self: AlertStatus) bool {
        return self == .new or self == .acked or self == .investigating;
    }
};

pub const CaseStatus = enum(u8) {
    open,
    active,
    contained,
    eradicated,
    closed,

    pub fn label(self: CaseStatus) [:0]const u8 {
        return switch (self) {
            .open => "OPEN",
            .active => "ACTIVE",
            .contained => "CONTAINED",
            .eradicated => "ERADICATED",
            .closed => "CLOSED",
        };
    }
};

pub const EventKind = enum(u8) {
    process,
    network,
    auth,
    file,
    dns,
    registry,
    script,

    pub fn label(self: EventKind) [:0]const u8 {
        return switch (self) {
            .process => "PROC",
            .network => "NET",
            .auth => "AUTH",
            .file => "FILE",
            .dns => "DNS",
            .registry => "REG",
            .script => "SCRIPT",
        };
    }
};

pub const IocType = enum(u8) {
    ip,
    domain,
    hash_sha256,
    url,
    email,

    pub fn label(self: IocType) [:0]const u8 {
        return switch (self) {
            .ip => "IP",
            .domain => "DOMAIN",
            .hash_sha256 => "SHA256",
            .url => "URL",
            .email => "EMAIL",
        };
    }
};

pub const SensorKind = enum(u8) {
    edr,
    firewall,
    ids,
    dns,
    proxy,
    cloud,

    pub fn label(self: SensorKind) [:0]const u8 {
        return switch (self) {
            .edr => "EDR",
            .firewall => "FW",
            .ids => "IDS",
            .dns => "DNS",
            .proxy => "PROXY",
            .cloud => "CLOUD",
        };
    }
};

pub const SensorStatus = enum(u8) {
    ok,
    degraded,
    down,

    pub fn label(self: SensorStatus) [:0]const u8 {
        return switch (self) {
            .ok => "OK",
            .degraded => "DEGRADED",
            .down => "DOWN",
        };
    }
};

pub const RuleStatus = enum(u8) {
    enabled,
    disabled,
    testing,

    pub fn label(self: RuleStatus) [:0]const u8 {
        return switch (self) {
            .enabled => "ENABLED",
            .disabled => "DISABLED",
            .testing => "TESTING",
        };
    }
};

pub const FeedStatus = enum(u8) {
    ok,
    syncing,
    err,

    pub fn label(self: FeedStatus) [:0]const u8 {
        return switch (self) {
            .ok => "OK",
            .syncing => "SYNCING",
            .err => "ERROR",
        };
    }
};

pub const Motivation = enum(u8) {
    espionage,
    financial,
    hacktivism,
    destruction,

    pub fn label(self: Motivation) [:0]const u8 {
        return switch (self) {
            .espionage => "espionage",
            .financial => "financial",
            .hacktivism => "hacktivism",
            .destruction => "destruction",
        };
    }
};

// ── Entities ─────────────────────────────────────────────────────────────

/// One telemetry event (process start, connection, logon, …).
pub const Event = struct {
    id: u64,
    ts_ms: i64,
    kind: EventKind,
    severity: Severity = .info,
    /// Index into Store.hosts.
    host: u16,
    /// Index into Store.users.
    user: u16,
    /// Index into Store.sensors.
    sensor: u16 = 0,
    /// Parent event id (process ancestry) — process-tree edges.
    parent: ?u64 = null,
    technique: ?attack.TechniqueId = null,
    process: FixedStr(64) = .{},
    cmdline: FixedStr(160) = .{},
    dst_ip: FixedStr(46) = .{},
    dst_port: u16 = 0,
};

pub const ALERT_EVENT_CAP = 8;

pub const Alert = struct {
    id: u32,
    ts_ms: i64,
    /// Index into Store.rules.
    rule: u16,
    severity: Severity,
    status: AlertStatus = .new,
    technique: ?attack.TechniqueId = null,
    title: FixedStr(96) = .{},
    /// Primary entity: "host · user".
    entity: FixedStr(64) = .{},
    assignee: FixedStr(24) = .{},
    case_id: ?u16 = null,
    event_ids: [ALERT_EVENT_CAP]u64 = @splat(0),
    event_count: u8 = 0,
};

pub const DetectionRule = struct {
    id: u16,
    code: FixedStr(8) = .{}, // "R-0042"
    name: FixedStr(96) = .{},
    status: RuleStatus = .enabled,
    severity: Severity = .medium,
    technique: attack.TechniqueId,
    fires_7d: u32 = 0,
    fp_7d: u32 = 0,
    last_fire_ms: i64 = 0,
    author: FixedStr(24) = .{},
    query: FixedStr(240) = .{},

    /// False-positive share of the last 7 days' fires (0..1).
    pub fn fpRate(self: *const DetectionRule) f32 {
        if (self.fires_7d == 0) return 0;
        return @as(f32, @floatFromInt(self.fp_7d)) / @as(f32, @floatFromInt(self.fires_7d));
    }
};

pub const Ioc = struct {
    id: u32,
    type: IocType,
    value: FixedStr(128) = .{},
    confidence: u8 = 50, // 0..100
    /// Index into Store.feeds.
    feed: u8 = 0,
    first_seen_ms: i64 = 0,
    last_seen_ms: i64 = 0,
    hits: u32 = 0,
};

pub const CASE_ALERT_CAP = 16;

pub const Case = struct {
    id: u16,
    title: FixedStr(96) = .{},
    severity: Severity = .medium,
    status: CaseStatus = .open,
    assignee: FixedStr(24) = .{},
    opened_ms: i64 = 0,
    updated_ms: i64 = 0,
    alert_ids: [CASE_ALERT_CAP]u32 = @splat(0),
    alert_count: u8 = 0,
    notes: FixedStr(480) = .{},
};

pub const Sensor = struct {
    id: u16,
    host: FixedStr(48) = .{},
    kind: SensorKind,
    status: SensorStatus = .ok,
    eps: f32 = 0,
    lag_s: f32 = 0,
    last_seen_ms: i64 = 0,
    version: FixedStr(16) = .{},
};

pub const IntelFeed = struct {
    id: u8,
    name: FixedStr(48) = .{},
    url: FixedStr(96) = .{},
    last_sync_ms: i64 = 0,
    ioc_count: u32 = 0,
    status: FeedStatus = .ok,
};

pub const ACTOR_TECHNIQUE_CAP = 12;

pub const ThreatActor = struct {
    id: u8,
    name: FixedStr(48) = .{},
    aliases: FixedStr(96) = .{},
    motivation: Motivation = .financial,
    techniques: [ACTOR_TECHNIQUE_CAP]attack.TechniqueId = @splat(0),
    technique_count: u8 = 0,
    notes: FixedStr(600) = .{},
};

test "fixed string truncates + round-trips" {
    const S = FixedStr(8);
    const a = S.from("short");
    try std.testing.expectEqualStrings("short", a.slice());
    const b = S.from("way too long for eight");
    try std.testing.expectEqual(@as(usize, 8), b.slice().len);
}

test {
    std.testing.refAllDecls(@This());
}
