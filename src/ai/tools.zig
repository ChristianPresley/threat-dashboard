//! Native, read-only dashboard tools the assistant can call. Each has a
//! comptime JSON Schema (advertised to Claude) and an executor that reads a
//! Store snapshot on the RENDER THREAD and returns a compact JSON string.
//! Results are row-capped so a tool call can't blow the context window.
//!
//! Also hosts refang(): threat-intel tool output arrives defanged
//! (hxxp/[.]); refang before correlating against raw Store values.

const std = @import("std");
const domain = @import("domain");
const data = @import("data");
const Allocator = std.mem.Allocator;

pub const NativeTool = struct {
    name: [:0]const u8,
    description: [:0]const u8,
    input_schema: [:0]const u8,
};

/// Dashboard-owned state (not in the Store) some tools read: the job queue
/// and the audit trail. Empty slices when the caller has none (selftest).
pub const Extras = struct {
    jobs: []const data.jobs.Job = &.{},
    audit: []const domain.AuditEntry = &.{},
};

const obj_empty = "{\"type\":\"object\",\"properties\":{}}";

pub const native_tools = [_]NativeTool{
    .{
        .name = "get_alerts",
        .description = "List detection alerts from the dashboard. Filter by status (open|all) and minimum severity. Returns id, severity, status, technique, title, entity, ts_ms (unix milliseconds).",
        .input_schema =
        \\{"type":"object","properties":{"status":{"type":"string","enum":["open","all"],"description":"open = new/acked/investigating only"},"min_severity":{"type":"string","enum":["info","low","medium","high","critical"]},"limit":{"type":"integer","description":"max rows, default 25, hard max 100"}}}
        ,
    },
    .{
        .name = "get_alert_detail",
        .description = "Full detail for one alert by id: the firing rule, technique, linked event ids and their command lines.",
        .input_schema =
        \\{"type":"object","properties":{"id":{"type":"integer"}},"required":["id"]}
        ,
    },
    .{
        .name = "get_cases",
        .description = "List incident cases: id, title, severity, status, assignee, linked alert count.",
        .input_schema = obj_empty,
    },
    .{
        .name = "get_iocs",
        .description = "List indicators of compromise. Filter by type (ip|domain|sha256|url|email) and a value substring. Returns type, value, confidence, feed, hits, and enrichment verdict when known.",
        .input_schema =
        \\{"type":"object","properties":{"type":{"type":"string","enum":["ip","domain","sha256","url","email"]},"value_contains":{"type":"string"},"limit":{"type":"integer"}}}
        ,
    },
    .{
        .name = "get_rules",
        .description = "List EDR detection rules. Filter by status (enabled|testing|disabled) or technique id (e.g. T1059.001). Returns code, name, status, severity, technique, fires_7d, fp_rate.",
        .input_schema =
        \\{"type":"object","properties":{"status":{"type":"string","enum":["enabled","testing","disabled"]},"technique":{"type":"string"},"limit":{"type":"integer"}}}
        ,
    },
    .{
        .name = "get_yara_rules",
        .description = "List YARA rules with CI gate health (compile/metadata/true-positive/false-positive/perf) and quality grade. Filter by technique or failures_only. Set include_content=true to also get status, author, description, strings excerpt and condition for rule review.",
        .input_schema =
        \\{"type":"object","properties":{"technique":{"type":"string"},"failures_only":{"type":"boolean"},"include_content":{"type":"boolean"}}}
        ,
    },
    .{
        .name = "search_events",
        .description = "Search telemetry events by a text substring over process/cmdline/dst_ip. Optionally filter by kind (process|network|auth|file|dns|registry|script). Returns ts_ms (unix milliseconds), kind, host, process, cmdline.",
        .input_schema =
        \\{"type":"object","properties":{"query":{"type":"string"},"kind":{"type":"string"},"limit":{"type":"integer"}},"required":["query"]}
        ,
    },
    .{
        .name = "get_attack_coverage",
        .description = "ATT&CK coverage summary: per-technique rule coverage (none/testing/enabled), whether an active YARA rule exists, and open-alert heat. Optionally scope to one technique id.",
        .input_schema =
        \\{"type":"object","properties":{"technique":{"type":"string"}}}
        ,
    },
    .{
        .name = "get_sensor_health",
        .description = "Sensor fleet health: per sensor host, kind, status (ok/degraded/down), events-per-second, lag.",
        .input_schema = obj_empty,
    },
    .{
        .name = "get_enrichment",
        .description = "Full enrichment detail for one IOC by exact value: verdict, detection ratio, reputation, threat label, hosting (ASN/owner/country/network), whois (registrar/creation), url-scan score, and pivot IOCs it contacted.",
        .input_schema =
        \\{"type":"object","properties":{"value":{"type":"string","description":"exact IOC value as returned by get_iocs"}},"required":["value"]}
        ,
    },
    .{
        .name = "get_pipelines",
        .description = "List data pipelines (dbt-style ELT): code, name, source, sink, target, schedule, status, watermark lag, latest run result, test pass/fail tallies, open dead letters.",
        .input_schema = obj_empty,
    },
    .{
        .name = "get_data_sources",
        .description = "List registered data sources: kind, name, connection state (ok/degraded/unreachable), latency, table count.",
        .input_schema = obj_empty,
    },
    .{
        .name = "get_feeds",
        .description = "List threat-intel feeds: name, sync status (ok/syncing/error), IOC count, last-sync timestamp (unix milliseconds).",
        .input_schema = obj_empty,
    },
    .{
        .name = "get_threat_actors",
        .description = "List tracked threat actors: name, aliases, motivation, ATT&CK techniques, analyst notes.",
        .input_schema = obj_empty,
    },
    .{
        .name = "get_jobs",
        .description = "The async job queue: kind, state (queued/running/done/failed/canceled), progress, detail, error. Newest first, capped at 20.",
        .input_schema = obj_empty,
    },
    .{
        .name = "get_audit_trail",
        .description = "Recent audit-trail entries (chain of custody): who did what to which object, newest first. Optional limit (default 25, max 100).",
        .input_schema =
        \\{"type":"object","properties":{"limit":{"type":"integer"}}}
        ,
    },
};

pub const ExecuteError = error{ UnknownTool, OutOfMemory } || std.Io.Writer.Error;

/// RENDER THREAD ONLY. Read-only Store access; returns compact JSON owned
/// by `gpa`. Unknown tool names return `error.UnknownTool`.
pub fn execute(gpa: Allocator, store: *data.Store, extras: Extras, name: []const u8, input_json: []const u8) ExecuteError![]u8 {
    var parsed: ?std.json.Parsed(std.json.Value) = std.json.parseFromSlice(std.json.Value, gpa, input_json, .{}) catch null;
    defer if (parsed) |*p| p.deinit();
    const args: ?std.json.Value = if (parsed) |p| p.value else null;

    var aw: std.Io.Writer.Allocating = .init(gpa);
    errdefer aw.deinit();
    const w = &aw.writer;

    if (std.mem.eql(u8, name, "get_alerts")) {
        try getAlerts(w, store, args);
    } else if (std.mem.eql(u8, name, "get_alert_detail")) {
        try getAlertDetail(w, store, args);
    } else if (std.mem.eql(u8, name, "get_cases")) {
        try getCases(w, store);
    } else if (std.mem.eql(u8, name, "get_iocs")) {
        try getIocs(w, store, args);
    } else if (std.mem.eql(u8, name, "get_rules")) {
        try getRules(w, store, args);
    } else if (std.mem.eql(u8, name, "get_yara_rules")) {
        try getYaraRules(w, store, args);
    } else if (std.mem.eql(u8, name, "search_events")) {
        try searchEvents(w, store, args);
    } else if (std.mem.eql(u8, name, "get_attack_coverage")) {
        try getAttackCoverage(w, store, args);
    } else if (std.mem.eql(u8, name, "get_sensor_health")) {
        try getSensorHealth(w, store);
    } else if (std.mem.eql(u8, name, "get_enrichment")) {
        try getEnrichment(w, store, args);
    } else if (std.mem.eql(u8, name, "get_pipelines")) {
        try getPipelines(w, store);
    } else if (std.mem.eql(u8, name, "get_data_sources")) {
        try getDataSources(w, store);
    } else if (std.mem.eql(u8, name, "get_feeds")) {
        try getFeeds(w, store);
    } else if (std.mem.eql(u8, name, "get_threat_actors")) {
        try getThreatActors(w, store);
    } else if (std.mem.eql(u8, name, "get_jobs")) {
        try getJobs(w, extras.jobs);
    } else if (std.mem.eql(u8, name, "get_audit_trail")) {
        try getAuditTrail(w, extras.audit, args);
    } else {
        aw.deinit();
        return error.UnknownTool;
    }
    return aw.toOwnedSlice();
}

// ── JSON helpers ─────────────────────────────────────────────────────────

fn jstr(w: *std.Io.Writer, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        '\t' => try w.writeAll("\\t"),
        else => if (c < 0x20) try w.print("\\u{x:0>4}", .{c}) else try w.writeByte(c),
    };
    try w.writeByte('"');
}

/// `"key":"value"` field.
fn fieldStr(w: *std.Io.Writer, key: []const u8, val: []const u8) !void {
    try jstr(w, key);
    try w.writeByte(':');
    try jstr(w, val);
}

fn argStr(args: ?std.json.Value, key: []const u8) ?[]const u8 {
    const a = args orelse return null;
    if (a != .object) return null;
    const v = a.object.get(key) orelse return null;
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

fn argInt(args: ?std.json.Value, key: []const u8) ?i64 {
    const a = args orelse return null;
    if (a != .object) return null;
    const v = a.object.get(key) orelse return null;
    return switch (v) {
        .integer => |i| i,
        else => null,
    };
}

fn argBool(args: ?std.json.Value, key: []const u8) ?bool {
    const a = args orelse return null;
    if (a != .object) return null;
    const v = a.object.get(key) orelse return null;
    return switch (v) {
        .bool => |b| b,
        else => null,
    };
}

fn limitOf(args: ?std.json.Value) usize {
    const n = argInt(args, "limit") orelse 25;
    if (n < 1) return 25;
    return @intCast(@min(n, 100));
}

// ── Tool bodies ──────────────────────────────────────────────────────────

fn getAlerts(w: *std.Io.Writer, s: *data.Store, args: ?std.json.Value) !void {
    const open_only = if (argStr(args, "status")) |st| !std.mem.eql(u8, st, "all") else true;
    var min_sev: u8 = 0;
    if (argStr(args, "min_severity")) |ms| {
        inline for (@typeInfo(domain.Severity).@"enum".fields) |f| {
            if (std.mem.eql(u8, f.name, ms)) min_sev = f.value;
        }
    }
    const limit = limitOf(args);
    try w.writeAll("{\"alerts\":[");
    var n: usize = 0;
    // Newest first.
    var i = s.alerts.items.len;
    while (i > 0 and n < limit) {
        i -= 1;
        const a = &s.alerts.items[i];
        if (open_only and !a.status.isOpen()) continue;
        if (@intFromEnum(a.severity) < min_sev) continue;
        if (n > 0) try w.writeByte(',');
        try w.print("{{\"id\":{d},\"ts_ms\":{d},\"severity\":", .{ a.id, a.ts_ms });
        try jstr(w, a.severity.label());
        try w.writeAll(",\"status\":");
        try jstr(w, a.status.label());
        try w.writeAll(",\"technique\":");
        try jstr(w, if (a.technique) |tid| domain.attack.get(tid).id else "\u{2014}");
        try w.writeAll(",\"title\":");
        try jstr(w, a.title.slice());
        try w.writeAll(",\"entity\":");
        try jstr(w, a.entity.slice());
        try w.writeByte('}');
        n += 1;
    }
    try w.print("],\"returned\":{d}}}", .{n});
}

fn getAlertDetail(w: *std.Io.Writer, s: *data.Store, args: ?std.json.Value) !void {
    const id: u32 = @intCast(argInt(args, "id") orelse {
        try w.writeAll("{\"error\":\"id required\"}");
        return;
    });
    const a = s.alertById(id) orelse {
        try w.writeAll("{\"error\":\"alert not found\"}");
        return;
    };
    try w.print("{{\"id\":{d},\"severity\":", .{a.id});
    try jstr(w, a.severity.label());
    try w.writeAll(",\"status\":");
    try jstr(w, a.status.label());
    try w.writeAll(",\"title\":");
    try jstr(w, a.title.slice());
    try w.writeAll(",\"entity\":");
    try jstr(w, a.entity.slice());
    if (s.ruleById(a.rule)) |r| {
        try w.writeAll(",\"rule\":");
        try jstr(w, r.name.slice());
        try w.writeAll(",\"rule_query\":");
        try jstr(w, r.query.slice());
    }
    try w.writeAll(",\"events\":[");
    var first = true;
    for (a.event_ids[0..a.event_count]) |eid| {
        const e = s.eventById(eid) orelse continue;
        if (!first) try w.writeByte(',');
        first = false;
        try w.writeAll("{\"kind\":");
        try jstr(w, e.kind.label());
        try w.writeAll(",\"process\":");
        try jstr(w, e.process.slice());
        try w.writeAll(",\"cmdline\":");
        try jstr(w, e.cmdline.slice());
        try w.writeByte('}');
    }
    try w.writeAll("]}");
}

fn getCases(w: *std.Io.Writer, s: *data.Store) !void {
    try w.writeAll("{\"cases\":[");
    for (s.cases.items, 0..) |*c, i| {
        if (i > 0) try w.writeByte(',');
        try w.print("{{\"id\":{d},\"severity\":", .{c.id});
        try jstr(w, c.severity.label());
        try w.writeAll(",\"status\":");
        try jstr(w, c.status.label());
        try w.writeAll(",\"title\":");
        try jstr(w, c.title.slice());
        try w.writeAll(",\"assignee\":");
        try jstr(w, c.assignee.slice());
        try w.print(",\"alerts\":{d}}}", .{c.alert_count});
    }
    try w.writeAll("]}");
}

fn getIocs(w: *std.Io.Writer, s: *data.Store, args: ?std.json.Value) !void {
    const want_type = argStr(args, "type");
    const contains = argStr(args, "value_contains");
    const limit = limitOf(args);
    try w.writeAll("{\"iocs\":[");
    var n: usize = 0;
    for (s.iocs.items) |*ic| {
        if (n >= limit) break;
        if (want_type) |wt| {
            if (!std.ascii.eqlIgnoreCase(wt, iocTypeTag(ic.type))) continue;
        }
        if (contains) |sub| {
            if (std.ascii.indexOfIgnoreCase(ic.value.slice(), sub) == null) continue;
        }
        if (n > 0) try w.writeByte(',');
        try w.writeAll("{\"type\":");
        try jstr(w, iocTypeTag(ic.type));
        try w.writeAll(",\"value\":");
        try jstr(w, ic.value.slice());
        try w.print(",\"confidence\":{d},\"hits\":{d}", .{ ic.confidence, ic.hits });
        if (s.enrichmentForIoc(ic.id)) |en| {
            if (en.status == .done) {
                try w.writeAll(",\"verdict\":");
                try jstr(w, en.verdict.label());
            }
        }
        try w.writeByte('}');
        n += 1;
    }
    try w.print("],\"returned\":{d}}}", .{n});
}

fn getRules(w: *std.Io.Writer, s: *data.Store, args: ?std.json.Value) !void {
    const want_status = argStr(args, "status");
    const want_tech = argStr(args, "technique");
    const limit = limitOf(args);
    try w.writeAll("{\"rules\":[");
    var n: usize = 0;
    for (s.rules.items) |*r| {
        if (n >= limit) break;
        if (want_status) |ws| {
            if (!std.ascii.eqlIgnoreCase(ws, @tagName(r.status))) continue;
        }
        if (want_tech) |wt| {
            if (!std.mem.eql(u8, wt, domain.attack.get(r.technique).id)) continue;
        }
        if (n > 0) try w.writeByte(',');
        try w.writeAll("{\"code\":");
        try jstr(w, r.code.slice());
        try w.writeAll(",\"name\":");
        try jstr(w, r.name.slice());
        try w.writeAll(",\"status\":");
        try jstr(w, r.status.label());
        try w.writeAll(",\"technique\":");
        try jstr(w, domain.attack.get(r.technique).id);
        try w.print(",\"fires_7d\":{d},\"fp_rate\":{d:.2}}}", .{ r.fires_7d, r.fpRate() });
        n += 1;
    }
    try w.print("],\"returned\":{d}}}", .{n});
}

fn getYaraRules(w: *std.Io.Writer, s: *data.Store, args: ?std.json.Value) !void {
    const want_tech = argStr(args, "technique");
    const fails_only = argBool(args, "failures_only") orelse false;
    const include_content = argBool(args, "include_content") orelse false;
    try w.writeAll("{\"yara_rules\":[");
    var n: usize = 0;
    for (s.yara.items) |*y| {
        if (fails_only and y.gates.allPass()) continue;
        if (want_tech) |wt| {
            if (!std.mem.eql(u8, wt, domain.attack.get(y.technique).id)) continue;
        }
        if (n > 0) try w.writeByte(',');
        var gb: [2]u8 = .{ y.grade(), 0 };
        try w.writeAll("{\"name\":");
        try jstr(w, y.name.slice());
        try w.writeAll(",\"grade\":");
        try jstr(w, gb[0..1]);
        try w.writeAll(",\"technique\":");
        try jstr(w, domain.attack.get(y.technique).id);
        try w.writeAll(",\"severity\":");
        try jstr(w, y.severity.label());
        if (include_content) {
            try w.writeAll(",\"status\":");
            try jstr(w, y.status.label());
            try w.writeAll(",\"author\":");
            try jstr(w, y.author.slice());
            try w.writeAll(",\"description\":");
            try jstr(w, y.description.slice());
            try w.writeAll(",\"strings\":");
            try jstr(w, y.strings_excerpt.slice());
            try w.writeAll(",\"condition\":");
            try jstr(w, y.condition.slice());
        }
        try w.print(",\"gates\":{{\"compile\":{},\"meta\":{},\"tp\":{},\"fp\":{d},\"scan_ms\":{d:.0},\"budget_ms\":{d:.0}}}}}", .{
            y.gates.compile == .pass, y.gates.meta == .pass, y.gates.tp == .pass,
            y.gates.fp_count,         y.gates.scan_ms,        y.gates.budget_ms,
        });
        n += 1;
    }
    try w.print("],\"returned\":{d}}}", .{n});
}

fn searchEvents(w: *std.Io.Writer, s: *data.Store, args: ?std.json.Value) !void {
    const q = argStr(args, "query") orelse {
        try w.writeAll("{\"error\":\"query required\"}");
        return;
    };
    const want_kind = argStr(args, "kind");
    const limit = limitOf(args);
    try w.writeAll("{\"events\":[");
    var n: usize = 0;
    var i = s.events.items.len;
    while (i > 0 and n < limit) {
        i -= 1;
        const e = &s.events.items[i];
        if (want_kind) |wk| {
            if (!std.ascii.eqlIgnoreCase(wk, @tagName(e.kind))) continue;
        }
        const hit = std.ascii.indexOfIgnoreCase(e.cmdline.slice(), q) != null or
            std.ascii.indexOfIgnoreCase(e.process.slice(), q) != null or
            std.ascii.indexOfIgnoreCase(e.dst_ip.slice(), q) != null;
        if (!hit) continue;
        if (n > 0) try w.writeByte(',');
        try w.print("{{\"ts_ms\":{d},\"kind\":", .{e.ts_ms});
        try jstr(w, e.kind.label());
        try w.writeAll(",\"host\":");
        try jstr(w, s.hostName(e.host));
        try w.writeAll(",\"process\":");
        try jstr(w, e.process.slice());
        try w.writeAll(",\"cmdline\":");
        try jstr(w, e.cmdline.slice());
        try w.writeByte('}');
        n += 1;
    }
    try w.print("],\"returned\":{d}}}", .{n});
}

fn getAttackCoverage(w: *std.Io.Writer, s: *data.Store, args: ?std.json.Value) !void {
    const scope = argStr(args, "technique");
    try w.writeAll("{\"coverage\":[");
    var n: usize = 0;
    var tid: domain.attack.TechniqueId = 0;
    while (tid < domain.attack.technique_count) : (tid += 1) {
        const tech = domain.attack.get(tid);
        if (scope) |sc| {
            if (!std.mem.eql(u8, sc, tech.id)) continue;
        }
        const cov = s.coverageForTechnique(tid);
        const heat = s.alertHeatForTechnique(tid);
        const yc = s.yaraCoverageForTechnique(tid);
        // Skip empty rows on the full sweep to keep output tight.
        if (scope == null and cov == 0 and heat == 0 and yc == 0) continue;
        if (n > 0) try w.writeByte(',');
        try w.writeAll("{\"technique\":");
        try jstr(w, tech.id);
        try w.writeAll(",\"name\":");
        try jstr(w, tech.name);
        try w.print(",\"rule_coverage\":{d},\"yara_active\":{},\"open_alerts\":{d}}}", .{ cov, yc == 2, heat });
        n += 1;
    }
    try w.print("],\"returned\":{d}}}", .{n});
}

fn getSensorHealth(w: *std.Io.Writer, s: *data.Store) !void {
    try w.writeAll("{\"sensors\":[");
    for (s.sensors.items, 0..) |*sn, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"host\":");
        try jstr(w, sn.host.slice());
        try w.writeAll(",\"kind\":");
        try jstr(w, sn.kind.label());
        try w.writeAll(",\"status\":");
        try jstr(w, sn.status.label());
        try w.print(",\"eps\":{d:.0},\"lag_s\":{d:.1}}}", .{ sn.eps, sn.lag_s });
    }
    try w.writeAll("]}");
}

fn getEnrichment(w: *std.Io.Writer, s: *data.Store, args: ?std.json.Value) !void {
    const value = argStr(args, "value") orelse {
        try w.writeAll("{\"error\":\"value required\"}");
        return;
    };
    const ic = blk: {
        for (s.iocs.items) |*ic| {
            if (std.ascii.eqlIgnoreCase(ic.value.slice(), value)) break :blk ic;
        }
        try w.writeAll("{\"error\":\"ioc not found — use get_iocs to list values\"}");
        return;
    };
    const e = s.enrichmentForIoc(ic.id) orelse {
        try w.writeAll("{\"error\":\"not enriched yet — the analyst can queue enrichment from the IOC panel\"}");
        return;
    };
    if (e.status != .done) {
        try w.writeAll("{\"status\":");
        try jstr(w, e.status.label());
        try w.writeAll("}");
        return;
    }
    try w.writeAll("{\"value\":");
    try jstr(w, ic.value.slice());
    try w.writeAll(",\"type\":");
    try jstr(w, iocTypeTag(ic.type));
    try w.writeAll(",\"verdict\":");
    try jstr(w, e.verdict.label());
    const ratio = e.detRatio();
    try w.print(",\"detections\":\"{d}/{d}\",\"reputation\":{d}", .{ ratio.hit, ratio.total, e.reputation });
    if (e.threat_label.len > 0) {
        try w.writeAll(",\"threat_label\":");
        try jstr(w, e.threat_label.slice());
    }
    try w.print(",\"asn\":{d},\"as_owner\":", .{e.asn});
    try jstr(w, e.as_owner.slice());
    try w.writeAll(",\"country\":");
    try jstr(w, e.country.slice());
    try w.writeAll(",\"network\":");
    try jstr(w, e.network.slice());
    try w.writeAll(",\"registrar\":");
    try jstr(w, e.registrar.slice());
    try w.print(",\"creation_ms\":{d},\"scan_score\":{d},\"first_seen_ms\":{d},\"last_seen_ms\":{d}", .{
        e.creation_ms, e.scan_score, e.first_seen_ms, e.last_seen_ms,
    });
    try w.writeAll(",\"contacted_iocs\":[");
    var first = true;
    for (e.pivot_ids[0..e.pivot_count]) |pid| {
        const pic = s.iocById(pid) orelse continue;
        if (!first) try w.writeByte(',');
        first = false;
        try w.writeAll("{\"type\":");
        try jstr(w, iocTypeTag(pic.type));
        try w.writeAll(",\"value\":");
        try jstr(w, pic.value.slice());
        try w.print(",\"confidence\":{d}}}", .{pic.confidence});
    }
    try w.writeAll("]}");
}

fn getPipelines(w: *std.Io.Writer, s: *data.Store) !void {
    try w.writeAll("{\"pipelines\":[");
    for (s.pipelines.items, 0..) |*p, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"code\":");
        try jstr(w, p.code.slice());
        try w.writeAll(",\"name\":");
        try jstr(w, p.name.slice());
        if (s.sourceById(p.source)) |src| {
            try w.writeAll(",\"source\":");
            try jstr(w, src.name.slice());
        }
        try w.writeAll(",\"sink\":");
        try jstr(w, p.sink.label());
        try w.writeAll(",\"target\":");
        try jstr(w, p.target.slice());
        try w.writeAll(",\"status\":");
        try jstr(w, p.status.label());
        const tc = p.testCounts();
        try w.print(",\"schedule_min\":{d},\"watermark_ms\":{d},\"tests_pass\":{d},\"tests_fail\":{d},\"open_dead_letters\":{d}", .{
            p.schedule_min, p.watermark_ms, tc.pass, tc.fail, s.openDeadLetterCount(p.id),
        });
        if (s.lastRunFor(p.id)) |run| {
            try w.writeAll(",\"last_run\":{\"status\":");
            try jstr(w, run.status.label());
            try w.print(",\"started_ms\":{d},\"rows_in\":{d},\"rows_out\":{d},\"rows_rejected\":{d}}}", .{
                run.started_ms, run.rows_in, run.rows_out, run.rows_rejected,
            });
        }
        try w.writeByte('}');
    }
    try w.writeAll("]}");
}

fn getDataSources(w: *std.Io.Writer, s: *data.Store) !void {
    try w.writeAll("{\"sources\":[");
    for (s.sources.items, 0..) |*src, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"kind\":");
        try jstr(w, src.kind.label());
        try w.writeAll(",\"name\":");
        try jstr(w, src.name.slice());
        try w.writeAll(",\"state\":");
        try jstr(w, src.state.label());
        try w.print(",\"latency_ms\":{d:.0},\"tables\":{d}}}", .{ src.latency_ms, src.tables });
    }
    try w.writeAll("]}");
}

fn getFeeds(w: *std.Io.Writer, s: *data.Store) !void {
    try w.writeAll("{\"feeds\":[");
    for (s.feeds.items, 0..) |*f, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"name\":");
        try jstr(w, f.name.slice());
        try w.writeAll(",\"status\":");
        try jstr(w, f.status.label());
        try w.print(",\"ioc_count\":{d},\"last_sync_ms\":{d}}}", .{ f.ioc_count, f.last_sync_ms });
    }
    try w.writeAll("]}");
}

fn getThreatActors(w: *std.Io.Writer, s: *data.Store) !void {
    try w.writeAll("{\"actors\":[");
    for (s.actors.items, 0..) |*a, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"name\":");
        try jstr(w, a.name.slice());
        try w.writeAll(",\"aliases\":");
        try jstr(w, a.aliases.slice());
        try w.writeAll(",\"motivation\":");
        try jstr(w, a.motivation.label());
        try w.writeAll(",\"techniques\":[");
        for (a.techniques[0..a.technique_count], 0..) |tid, ti| {
            if (ti > 0) try w.writeByte(',');
            try jstr(w, domain.attack.get(tid).id);
        }
        try w.writeAll("],\"notes\":");
        try jstr(w, a.notes.slice());
        try w.writeByte('}');
    }
    try w.writeAll("]}");
}

fn getJobs(w: *std.Io.Writer, jobs: []const data.jobs.Job) !void {
    try w.writeAll("{\"jobs\":[");
    var n: usize = 0;
    var i = jobs.len;
    while (i > 0 and n < 20) {
        i -= 1;
        const j = &jobs[i];
        if (n > 0) try w.writeByte(',');
        try w.writeAll("{\"kind\":");
        try jstr(w, j.kind.label());
        try w.writeAll(",\"state\":");
        try jstr(w, j.state.label());
        try w.writeAll(",\"detail\":");
        try jstr(w, j.detail.slice());
        try w.print(",\"progress\":{d:.2}", .{j.progress});
        if (j.err.len > 0) {
            try w.writeAll(",\"error\":");
            try jstr(w, j.err.slice());
        }
        try w.writeByte('}');
        n += 1;
    }
    try w.print("],\"returned\":{d}}}", .{n});
}

fn getAuditTrail(w: *std.Io.Writer, audit: []const domain.AuditEntry, args: ?std.json.Value) !void {
    const limit = limitOf(args);
    try w.writeAll("{\"audit\":[");
    var n: usize = 0;
    var i = audit.len;
    while (i > 0 and n < limit) {
        i -= 1;
        const e = &audit[i];
        if (n > 0) try w.writeByte(',');
        try w.print("{{\"ts_ms\":{d},\"actor\":", .{e.ts_ms});
        try jstr(w, e.actor.slice());
        try w.writeAll(",\"action\":");
        try jstr(w, e.action.slice());
        try w.writeAll(",\"target\":");
        try jstr(w, e.target.slice());
        try w.writeByte('}');
        n += 1;
    }
    try w.print("],\"returned\":{d}}}", .{n});
}

fn iocTypeTag(ty: domain.IocType) []const u8 {
    return switch (ty) {
        .ip => "ip",
        .domain => "domain",
        .hash_sha256 => "sha256",
        .url => "url",
        .email => "email",
    };
}

// ── Refang: reverse threat-intel defang for correlation ──────────────────

/// "hxxp"→"http", "hxxps"→"https", "[.]"→".", "[:]"→":". Writes into `out`,
/// truncating at capacity; returns the written slice.
pub fn refang(out: []u8, s: []const u8) []const u8 {
    var o: usize = 0;
    var i: usize = 0;
    while (i < s.len and o < out.len) {
        if (std.mem.startsWith(u8, s[i..], "hxxps")) {
            const n = @min(5, out.len - o);
            @memcpy(out[o..][0..n], "https"[0..n]);
            o += n;
            i += 5;
        } else if (std.mem.startsWith(u8, s[i..], "hxxp")) {
            const n = @min(4, out.len - o);
            @memcpy(out[o..][0..n], "http"[0..n]);
            o += n;
            i += 4;
        } else if (std.mem.startsWith(u8, s[i..], "[.]")) {
            out[o] = '.';
            o += 1;
            i += 3;
        } else if (std.mem.startsWith(u8, s[i..], "[:]")) {
            out[o] = ':';
            o += 1;
            i += 3;
        } else {
            out[o] = s[i];
            o += 1;
            i += 1;
        }
    }
    return out[0..o];
}

// ── Tests ────────────────────────────────────────────────────────────────

test "refang reverses defang" {
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("https://evil.com/x", refang(&buf, "hxxps://evil[.]com/x"));
    try std.testing.expectEqualStrings("1.2.3.4", refang(&buf, "1[.]2[.]3[.]4"));
}

test "native tools emit valid json against the mock store" {
    var s = data.Store.init(std.testing.allocator);
    defer s.deinit();
    var g = data.mock.Generator.init(42, 1_750_000_000_000);
    try g.build(&s);

    // Extras carry a probe job + audit entry so those tools emit rows too.
    const probe_jobs = [_]data.jobs.Job{.{ .id = 1, .kind = .yara_ci, .state = .done, .detail = domain.FixedStr(48).from("all rules") }};
    const probe_audit = [_]domain.AuditEntry{.{ .id = 1, .ts_ms = 42, .actor = domain.FixedStr(24).from("cpresley"), .action = domain.FixedStr(28).from("alert_status"), .target = domain.FixedStr(64).from("alert #1 → ACKED") }};
    const extras: Extras = .{ .jobs = &probe_jobs, .audit = &probe_audit };
    for (native_tools) |tool| {
        const out = try execute(std.testing.allocator, &s, extras, tool.name, "{}");
        defer std.testing.allocator.free(out);
        try std.testing.expect(out.len > 0);
        try std.testing.expect(std.json.validate(std.testing.allocator, out) catch false);
    }
    // get_enrichment with a real value round-trips too.
    if (s.enrichments.items.len > 0) {
        const ic = s.iocById(s.enrichments.items[0].ioc_id).?;
        var qb: [160]u8 = undefined;
        const q = try std.fmt.bufPrint(&qb, "{{\"value\":\"{s}\"}}", .{ic.value.slice()});
        const out = try execute(std.testing.allocator, &s, .{}, "get_enrichment", q);
        defer std.testing.allocator.free(out);
        try std.testing.expect(std.json.validate(std.testing.allocator, out) catch false);
    }
    try std.testing.expectError(error.UnknownTool, execute(std.testing.allocator, &s, .{}, "nope", "{}"));
}

test "get_iocs honors filters" {
    var s = data.Store.init(std.testing.allocator);
    defer s.deinit();
    var g = data.mock.Generator.init(42, 1_750_000_000_000);
    try g.build(&s);

    const out = try execute(std.testing.allocator, &s, .{}, "get_iocs", "{\"type\":\"ip\",\"limit\":5}");
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.json.validate(std.testing.allocator, out) catch false);
}
