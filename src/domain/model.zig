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
    /// Triage SLA timestamps (0 = not yet): first ack, final resolution.
    /// MTTA/MTTR in PST derive from these.
    acked_ms: i64 = 0,
    resolved_ms: i64 = 0,
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

// ── YARA rule engineering (rules-as-code CI) ─────────────────────────────

pub const GateResult = enum(u8) {
    pass,
    fail,

    pub fn label(self: GateResult) [:0]const u8 {
        return switch (self) {
            .pass => "PASS",
            .fail => "FAIL",
        };
    }
};

/// Per-rule CI health record — the five gates every YARA rule must satisfy:
/// compile (warnings-as-errors), metadata policy, true-positive fixture,
/// false-positive goodware corpus, and a per-rule scan-time budget.
pub const YaraGates = struct {
    compile: GateResult = .pass,
    meta: GateResult = .pass,
    tp: GateResult = .pass,
    fp_count: u16 = 0, // goodware-corpus hits; 0 = pass
    scan_ms: f32 = 0, // best-of-3 corpus scan time
    budget_ms: f32 = 50,
    last_ci_ms: i64 = 0,

    pub fn fpPass(self: *const YaraGates) bool {
        return self.fp_count == 0;
    }

    pub fn perfPass(self: *const YaraGates) bool {
        return self.scan_ms <= self.budget_ms;
    }

    pub fn allPass(self: *const YaraGates) bool {
        return self.compile == .pass and self.meta == .pass and
            self.tp == .pass and self.fpPass() and self.perfPass();
    }
};

pub const YaraStatus = enum(u8) {
    active,
    draft,
    deprecated,

    pub fn label(self: YaraStatus) [:0]const u8 {
        return switch (self) {
            .active => "ACTIVE",
            .draft => "DRAFT",
            .deprecated => "DEPRECATED",
        };
    }
};

/// A YARA rule as a versioned artifact: mandatory 7-field metadata
/// (author, date, description, reference, mitre_attack, severity, version)
/// plus its latest CI gate results.
pub const YaraRule = struct {
    id: u16,
    code: FixedStr(8) = .{}, // "Y-0001"
    name: FixedStr(64) = .{}, // rule identifier, e.g. PowerShell_AMSI_Bypass
    status: YaraStatus = .active,
    severity: Severity = .medium,
    technique: attack.TechniqueId,
    author: FixedStr(24) = .{},
    date_ms: i64 = 0,
    description: FixedStr(160) = .{},
    reference: FixedStr(96) = .{},
    version: u16 = 1,
    strings_excerpt: FixedStr(240) = .{},
    condition: FixedStr(160) = .{},
    gates: YaraGates = .{},

    /// Quality score 0..100 from gate results. Compile failure is a hard 0
    /// (nothing else can be trusted); the rest subtract: meta −20, TP miss
    /// −30, −8 per goodware FP (cap −24), perf over budget −15 (over 2×
    /// budget −25).
    pub fn score(self: *const YaraRule) u8 {
        const g = &self.gates;
        if (g.compile == .fail) return 0;
        var s: i32 = 100;
        if (g.meta == .fail) s -= 20;
        if (g.tp == .fail) s -= 30;
        s -= @min(@as(i32, g.fp_count) * 8, 24);
        if (!g.perfPass()) s -= if (g.scan_ms > g.budget_ms * 2) @as(i32, 25) else 15;
        return @intCast(@max(s, 0));
    }

    /// Letter grade for the theme Score band: A ≥75, B ≥60, C ≥45, D ≥30, F.
    pub fn grade(self: *const YaraRule) u8 {
        const s = self.score();
        if (s >= 75) return 'A';
        if (s >= 60) return 'B';
        if (s >= 45) return 'C';
        if (s >= 30) return 'D';
        return 'F';
    }
};

// ── IOC enrichment (threat-intel lookup shapes) ──────────────────────────

pub const Verdict = enum(u8) {
    unknown,
    clean,
    suspicious,
    malicious,

    pub fn label(self: Verdict) [:0]const u8 {
        return switch (self) {
            .unknown => "UNKNOWN",
            .clean => "CLEAN",
            .suspicious => "SUSPICIOUS",
            .malicious => "MALICIOUS",
        };
    }
};

/// Async-fill lifecycle: a live source marks `.pending`, then upserts
/// `.done` or `.err`. The mock build writes `.done` records directly.
pub const EnrichStatus = enum(u8) {
    none,
    pending,
    done,
    err,

    pub fn label(self: EnrichStatus) [:0]const u8 {
        return switch (self) {
            .none => "NONE",
            .pending => "PENDING",
            .done => "DONE",
            .err => "ERROR",
        };
    }
};

pub const EnrichSource = enum(u8) {
    mock,
    virustotal,
    urlscan,

    pub fn label(self: EnrichSource) [:0]const u8 {
        return switch (self) {
            .mock => "mock",
            .virustotal => "virustotal",
            .urlscan => "urlscan",
        };
    }
};

pub const ENRICH_PIVOT_CAP = 25;

/// Reputation/hosting context for one IOC, keyed by `ioc_id`. Sparse — most
/// IOCs never get enriched; the Store holds these in a separate list.
pub const IocEnrichment = struct {
    ioc_id: u32,
    status: EnrichStatus = .none,
    source: EnrichSource = .mock,
    fetched_ms: i64 = 0,
    err: FixedStr(32) = .{}, // structured error kind: "rate_limited", "timeout", …

    verdict: Verdict = .unknown,
    det_malicious: u16 = 0,
    det_suspicious: u16 = 0,
    det_harmless: u16 = 0,
    det_undetected: u16 = 0,
    reputation: i32 = 0,
    threat_label: FixedStr(48) = .{},
    first_seen_ms: i64 = 0,
    last_seen_ms: i64 = 0,

    // domain-type extras
    registrar: FixedStr(48) = .{},
    creation_ms: i64 = 0, // newly-registered-domain signal when recent
    categories: FixedStr(96) = .{},

    // ip-type extras
    asn: u32 = 0,
    as_owner: FixedStr(48) = .{},
    country: FixedStr(4) = .{},
    network: FixedStr(24) = .{}, // CIDR

    // url-scan extras
    scan_score: u8 = 0, // 0..100
    brands: FixedStr(48) = .{},
    page_domain: FixedStr(64) = .{},
    page_ip: FixedStr(46) = .{},
    tls_issuer: FixedStr(48) = .{},

    /// Contacted-infrastructure pivots: Ioc.id refs (0 = empty slot).
    pivot_ids: [ENRICH_PIVOT_CAP]u32 = @splat(0),
    pivot_count: u8 = 0,

    pub fn detTotal(self: *const IocEnrichment) u32 {
        return @as(u32, self.det_malicious) + self.det_suspicious +
            self.det_harmless + self.det_undetected;
    }

    /// "57/72"-style detection ratio: engines flagging vs. engines total.
    pub fn detRatio(self: *const IocEnrichment) struct { hit: u32, total: u32 } {
        return .{
            .hit = @as(u32, self.det_malicious) + self.det_suspicious,
            .total = self.detTotal(),
        };
    }
};

pub const ScanState = enum(u8) {
    submitted,
    pending,
    done,
    err,

    pub fn label(self: ScanState) [:0]const u8 {
        return switch (self) {
            .submitted => "SUBMITTED",
            .pending => "PENDING",
            .done => "DONE",
            .err => "ERROR",
        };
    }
};

/// A url-scan submission lifecycle: submit → pending → done/err.
pub const UrlScanSubmission = struct {
    id: u32,
    ioc_id: u32, // must reference a url-type Ioc
    state: ScanState = .submitted,
    submitted_ms: i64 = 0,
    completed_ms: i64 = 0,
    err: FixedStr(32) = .{},
};

// ── Data pipelines (dbt-style ELT: sources → models → sinks) ─────────────

pub const SourceKind = enum(u8) {
    postgres,
    mysql,
    mssql,
    s3_bucket,
    kafka,
    syslog,
    rest_api,
    csv_file,

    pub fn label(self: SourceKind) [:0]const u8 {
        return switch (self) {
            .postgres => "POSTGRES",
            .mysql => "MYSQL",
            .mssql => "MSSQL",
            .s3_bucket => "S3",
            .kafka => "KAFKA",
            .syslog => "SYSLOG",
            .rest_api => "API",
            .csv_file => "CSV",
        };
    }
};

pub const ConnState = enum(u8) {
    ok,
    degraded,
    err,

    pub fn label(self: ConnState) [:0]const u8 {
        return switch (self) {
            .ok => "OK",
            .degraded => "DEGRADED",
            .err => "UNREACHABLE",
        };
    }
};

/// A selectable ingest source: a database, bucket, topic, or feed the
/// pipelines read from. `dsn` is display-safe (never carries secrets).
pub const DataSource = struct {
    id: u16,
    name: FixedStr(48) = .{},
    kind: SourceKind,
    dsn: FixedStr(96) = .{},
    state: ConnState = .ok,
    last_test_ms: i64 = 0,
    latency_ms: f32 = 0,
    /// Discoverable tables / topics / objects behind the source.
    tables: u16 = 0,
};

pub const SinkKind = enum(u8) {
    postgres,
    elasticsearch,
    s3_parquet,
    clickhouse,
    kafka_topic,

    pub fn label(self: SinkKind) [:0]const u8 {
        return switch (self) {
            .postgres => "POSTGRES",
            .elasticsearch => "ELASTIC",
            .s3_parquet => "S3 PARQUET",
            .clickhouse => "CLICKHOUSE",
            .kafka_topic => "KAFKA",
        };
    }
};

/// dbt materialization strategy for one model.
pub const Materialization = enum(u8) {
    view,
    table,
    incremental,
    snapshot,

    pub fn label(self: Materialization) [:0]const u8 {
        return switch (self) {
            .view => "view",
            .table => "table",
            .incremental => "incremental",
            .snapshot => "snapshot",
        };
    }
};

pub const StepKind = enum(u8) {
    staging,
    dedup,
    filter,
    enrich,
    join,
    aggregate,
    mask,

    pub fn label(self: StepKind) [:0]const u8 {
        return switch (self) {
            .staging => "STAGE",
            .dedup => "DEDUP",
            .filter => "FILTER",
            .enrich => "ENRICH",
            .join => "JOIN",
            .aggregate => "AGG",
            .mask => "MASK",
        };
    }
};

pub const PIPELINE_STEP_CAP = 6;

/// One model in a pipeline's DAG: a named transform with a materialization
/// (dbt convention: stg_* → int_* → mart_*).
pub const PipelineStep = struct {
    kind: StepKind = .staging,
    model: FixedStr(48) = .{},
    materialization: Materialization = .view,
};

pub const DbtTestKind = enum(u8) {
    not_null,
    unique,
    accepted_values,
    relationships,
    freshness,

    pub fn label(self: DbtTestKind) [:0]const u8 {
        return switch (self) {
            .not_null => "not_null",
            .unique => "unique",
            .accepted_values => "accepted_values",
            .relationships => "relationships",
            .freshness => "freshness",
        };
    }
};

pub const PIPELINE_TEST_CAP = 6;

/// A dbt-style data test attached to a pipeline: schema tests over a
/// model.column target plus source freshness.
pub const PipelineTest = struct {
    kind: DbtTestKind = .not_null,
    target: FixedStr(48) = .{},
    status: GateResult = .pass,
    /// Failing rows on the last run (0 when passing).
    failures: u32 = 0,
};

pub const PipelineStatus = enum(u8) {
    active,
    paused,
    err,
    draft,

    pub fn label(self: PipelineStatus) [:0]const u8 {
        return switch (self) {
            .active => "ACTIVE",
            .paused => "PAUSED",
            .err => "ERROR",
            .draft => "DRAFT",
        };
    }
};

/// A data processing pipeline: one source, an ordered model DAG, one sink,
/// a schedule, and its dbt-style test suite.
pub const Pipeline = struct {
    id: u16,
    code: FixedStr(8) = .{}, // "P-0001"
    name: FixedStr(64) = .{},
    /// DataSource.id this pipeline reads from.
    source: u16,
    sink: SinkKind = .postgres,
    /// Sink target: schema.table / index / bucket prefix / topic.
    target: FixedStr(64) = .{},
    /// Run cadence in minutes; 0 = manual only.
    schedule_min: u16 = 15,
    status: PipelineStatus = .active,
    steps: [PIPELINE_STEP_CAP]PipelineStep = @splat(PipelineStep{}),
    step_count: u8 = 0,
    tests: [PIPELINE_TEST_CAP]PipelineTest = @splat(PipelineTest{}),
    test_count: u8 = 0,
    last_run_ms: i64 = 0,
    /// High-water mark: newest source data successfully landed in the sink.
    /// Lag = now − watermark; freshness tests key off it.
    watermark_ms: i64 = 0,
    owner: FixedStr(24) = .{},

    pub fn testCounts(self: *const Pipeline) struct { pass: u8, fail: u8 } {
        var pass: u8 = 0;
        var fail: u8 = 0;
        for (self.tests[0..self.test_count]) |*ts| {
            if (ts.status == .pass) pass += 1 else fail += 1;
        }
        return .{ .pass = pass, .fail = fail };
    }

    pub fn testFailures(self: *const Pipeline) u32 {
        var n: u32 = 0;
        for (self.tests[0..self.test_count]) |*ts| n += ts.failures;
        return n;
    }
};

pub const RunStatus = enum(u8) {
    running,
    success,
    failed,
    partial,

    pub fn label(self: RunStatus) [:0]const u8 {
        return switch (self) {
            .running => "RUNNING",
            .success => "SUCCESS",
            .failed => "FAILED",
            .partial => "PARTIAL",
        };
    }
};

/// One pipeline execution: rows in/out/rejected + test tallies. Lifecycle
/// mirrors the url-scan pattern: add as `.running`, finalize via update.
pub const PipelineRun = struct {
    id: u32,
    pipeline: u16,
    started_ms: i64 = 0,
    duration_ms: i64 = 0,
    rows_in: u64 = 0,
    rows_out: u64 = 0,
    rows_rejected: u64 = 0,
    status: RunStatus = .running,
    tests_passed: u8 = 0,
    tests_failed: u8 = 0,
    /// This run's high-water mark; the pipeline takes the max.
    watermark_ms: i64 = 0,
    err: FixedStr(64) = .{},
};

pub const DlqState = enum(u8) {
    open,
    replayed,
    dropped,

    pub fn label(self: DlqState) [:0]const u8 {
        return switch (self) {
            .open => "OPEN",
            .replayed => "REPLAYED",
            .dropped => "DROPPED",
        };
    }
};

/// A dead-letter record: one rejected-row sample from a pipeline run,
/// with the dbt test that rejected it. Analysts replay (re-run after a
/// fix) or drop them; the retention sweep prunes resolved ones.
pub const DeadLetter = struct {
    id: u32,
    pipeline: u16,
    run_id: u32,
    ts_ms: i64 = 0,
    /// Which test rejected the row.
    kind: DbtTestKind = .not_null,
    target: FixedStr(48) = .{},
    /// Defanged/truncated sample of the offending row.
    sample: FixedStr(96) = .{},
    state: DlqState = .open,
};

// ── Audit trail (chain of custody) ───────────────────────────────────────

/// One analyst/system action recorded at the Store mutation choke point.
/// Kept OUTSIDE the Store's swappable state (the Dashboard owns the list)
/// so PG snapshot refreshes can't erase the record.
pub const AuditEntry = struct {
    id: u32,
    ts_ms: i64 = 0,
    actor: FixedStr(24) = .{},
    /// Mutation tag, e.g. "alert_status".
    action: FixedStr(28) = .{},
    /// Compact human target, e.g. "alert #142 → ACKED".
    target: FixedStr(64) = .{},
};

/// Defang an indicator for display OPSEC: "https://x.y/z" → "hxxps://x[.]y/z",
/// "1.2.3.4" → "1[.]2[.]3[.]4". Hashes/emails pass through untouched (emails
/// keep their dots — matching how analysts share them is out of scope here;
/// the click-hazard is URLs/domains/IPs). Output truncates at buf capacity.
pub fn defang(buf: []u8, ty: IocType, value: []const u8) []const u8 {
    switch (ty) {
        .hash_sha256, .email => {
            const n = @min(value.len, buf.len);
            @memcpy(buf[0..n], value[0..n]);
            return buf[0..n];
        },
        .ip, .domain, .url => {},
    }
    var out: usize = 0;
    var i: usize = 0;
    while (i < value.len and out < buf.len) {
        // scheme rewrite: http → hxxp, https → hxxps, ftp → fxp
        if (i == 0 and std.mem.startsWith(u8, value, "http")) {
            const s = if (std.mem.startsWith(u8, value, "https")) "hxxps" else "hxxp";
            const n = @min(s.len, buf.len);
            @memcpy(buf[0..n], s[0..n]);
            out = n;
            i = if (s.len == 5) 5 else 4;
            continue;
        }
        if (i == 0 and std.mem.startsWith(u8, value, "ftp")) {
            const n = @min(3, buf.len);
            @memcpy(buf[0..n], "fxp"[0..n]);
            out = n;
            i = 3;
            continue;
        }
        if (value[i] == '.') {
            if (out + 3 > buf.len) break;
            @memcpy(buf[out..][0..3], "[.]");
            out += 3;
            i += 1;
            continue;
        }
        buf[out] = value[i];
        out += 1;
        i += 1;
    }
    return buf[0..out];
}

test "yara score + grade bands" {
    var y = YaraRule{ .id = 1, .technique = 0 };
    try std.testing.expectEqual(@as(u8, 100), y.score());
    try std.testing.expectEqual(@as(u8, 'A'), y.grade());
    y.gates.compile = .fail;
    try std.testing.expectEqual(@as(u8, 0), y.score());
    try std.testing.expectEqual(@as(u8, 'F'), y.grade());
    y.gates.compile = .pass;
    y.gates.tp = .fail; // 70
    try std.testing.expectEqual(@as(u8, 'B'), y.grade());
    y.gates.fp_count = 2; // 70 - 16 = 54
    try std.testing.expectEqual(@as(u8, 'C'), y.grade());
}

test "enrichment detection ratio" {
    var e = IocEnrichment{ .ioc_id = 7 };
    e.det_malicious = 55;
    e.det_suspicious = 2;
    e.det_harmless = 10;
    e.det_undetected = 5;
    const r = e.detRatio();
    try std.testing.expectEqual(@as(u32, 57), r.hit);
    try std.testing.expectEqual(@as(u32, 72), r.total);
}

test "defang neutralizes urls, domains, ips" {
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "hxxps://phish[.]test/login",
        defang(&buf, .url, "https://phish.test/login"),
    );
    try std.testing.expectEqualStrings("evil[.]example[.]com", defang(&buf, .domain, "evil.example.com"));
    try std.testing.expectEqualStrings("203[.]0[.]113[.]9", defang(&buf, .ip, "203.0.113.9"));
    try std.testing.expectEqualStrings("abc123", defang(&buf, .hash_sha256, "abc123"));
}

test "pipeline test tallies" {
    var p = Pipeline{ .id = 1, .source = 0 };
    p.tests[0] = .{ .kind = .not_null, .target = FixedStr(48).from("stg_events.host") };
    p.tests[1] = .{ .kind = .accepted_values, .target = FixedStr(48).from("stg_iocs.type"), .status = .fail, .failures = 12 };
    p.test_count = 2;
    const tc = p.testCounts();
    try std.testing.expectEqual(@as(u8, 1), tc.pass);
    try std.testing.expectEqual(@as(u8, 1), tc.fail);
    try std.testing.expectEqual(@as(u32, 12), p.testFailures());
}

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
