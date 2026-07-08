//! PostgreSQL provider: a second writer for the same in-memory Store the
//! panels read — swapping mock ⇄ PG never touches panel code.
//!
//! v1 shape (deliberately synchronous): connect + migrate + full load at
//! boot; panel mutations flush through Store's write hook as immediate
//! UPDATEs on the render thread (single-digit ms on a local/LAN server).
//! A background worker with snapshot swaps (the trading LiveFeed pattern)
//! is the planned upgrade once real ingestion volume exists.

const std = @import("std");
const pg = @import("pg");
const domain = @import("domain");
const store_mod = @import("store.zig");
const Store = store_mod.Store;

const log = std.log.scoped(.pg);

const schema_sql = @embedFile("schema.sql");

pub const Provider = struct {
    pool: *pg.Pool,
    allocator: std.mem.Allocator,

    pub fn connect(io: std.Io, allocator: std.mem.Allocator, uri_text: []const u8) !Provider {
        const uri = try std.Uri.parse(uri_text);
        const pool = try pg.Pool.initUri(io, allocator, uri, .{ .size = 2, .timeout = 10_000 });
        return .{ .pool = pool, .allocator = allocator };
    }

    pub fn deinit(self: *Provider) void {
        self.pool.deinit();
    }

    /// Apply schema.sql statement-by-statement (idempotent DDL). Comment
    /// lines are stripped BEFORE splitting on ';' so semicolons inside
    /// comments can't shear a statement.
    pub fn migrate(self: *Provider) !void {
        var clean_buf: [schema_sql.len]u8 = undefined;
        var clean_len: usize = 0;
        var lines = std.mem.splitScalar(u8, schema_sql, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (std.mem.startsWith(u8, line, "--")) continue;
            @memcpy(clean_buf[clean_len .. clean_len + raw.len], raw);
            clean_len += raw.len;
            clean_buf[clean_len] = '\n';
            clean_len += 1;
        }

        var it = std.mem.splitScalar(u8, clean_buf[0..clean_len], ';');
        var n: usize = 0;
        while (it.next()) |raw| {
            const stmt = std.mem.trim(u8, raw, " \t\r\n");
            if (stmt.len == 0) continue;
            _ = self.pool.exec(stmt, .{}) catch |err| {
                log.err("migrate statement failed: {s}\n{s}", .{ @errorName(err), stmt });
                return err;
            };
            n += 1;
        }
        log.info("migrate: {d} statements applied", .{n});
    }

    // ── Load: DB → Store ─────────────────────────────────────────────────

    pub fn load(self: *Provider, s: *Store) !void {
        s.clear();
        const alloc = s.allocator;

        {
            var res = try self.pool.query("select name from hosts order by id", .{});
            defer res.deinit();
            while (try res.next()) |row| {
                try s.hosts.append(alloc, domain.FixedStr(48).from(try row.get([]const u8, 0)));
            }
        }
        {
            var res = try self.pool.query("select name from users order by id", .{});
            defer res.deinit();
            while (try res.next()) |row| {
                try s.users.append(alloc, domain.FixedStr(32).from(try row.get([]const u8, 0)));
            }
        }
        {
            var res = try self.pool.query("select id, host, kind, status, eps, lag_s, last_seen_ms, version from sensors order by id", .{});
            defer res.deinit();
            while (try res.next()) |row| {
                try s.sensors.append(alloc, .{
                    .id = @intCast(try row.get(i16, 0)),
                    .host = domain.FixedStr(48).from(try row.get([]const u8, 1)),
                    .kind = @enumFromInt(@as(u8, @intCast(try row.get(i16, 2)))),
                    .status = @enumFromInt(@as(u8, @intCast(try row.get(i16, 3)))),
                    .eps = try row.get(f32, 4),
                    .lag_s = try row.get(f32, 5),
                    .last_seen_ms = try row.get(i64, 6),
                    .version = domain.FixedStr(16).from(try row.get([]const u8, 7)),
                });
            }
        }
        {
            var res = try self.pool.query("select id, name, url, last_sync_ms, ioc_count, status from feeds order by id", .{});
            defer res.deinit();
            while (try res.next()) |row| {
                try s.feeds.append(alloc, .{
                    .id = @intCast(try row.get(i16, 0)),
                    .name = domain.FixedStr(48).from(try row.get([]const u8, 1)),
                    .url = domain.FixedStr(96).from(try row.get([]const u8, 2)),
                    .last_sync_ms = try row.get(i64, 3),
                    .ioc_count = @intCast(try row.get(i32, 4)),
                    .status = @enumFromInt(@as(u8, @intCast(try row.get(i16, 5)))),
                });
            }
        }
        {
            var res = try self.pool.query("select id, code, name, status, severity, technique, fires_7d, fp_7d, last_fire_ms, author, query from rules order by id", .{});
            defer res.deinit();
            while (try res.next()) |row| {
                try s.rules.append(alloc, .{
                    .id = @intCast(try row.get(i16, 0)),
                    .code = domain.FixedStr(8).from(try row.get([]const u8, 1)),
                    .name = domain.FixedStr(96).from(try row.get([]const u8, 2)),
                    .status = @enumFromInt(@as(u8, @intCast(try row.get(i16, 3)))),
                    .severity = @enumFromInt(@as(u8, @intCast(try row.get(i16, 4)))),
                    .technique = @intCast(try row.get(i16, 5)),
                    .fires_7d = @intCast(try row.get(i32, 6)),
                    .fp_7d = @intCast(try row.get(i32, 7)),
                    .last_fire_ms = try row.get(i64, 8),
                    .author = domain.FixedStr(24).from(try row.get([]const u8, 9)),
                    .query = domain.FixedStr(240).from(try row.get([]const u8, 10)),
                });
            }
        }
        {
            // Cap: newest 10k indicators (v1 OOM guard).
            var res = try self.pool.query("select id, type, value, confidence, feed, first_seen_ms, last_seen_ms, hits from iocs order by last_seen_ms desc limit 10000", .{});
            defer res.deinit();
            while (try res.next()) |row| {
                try s.iocs.append(alloc, .{
                    .id = @intCast(try row.get(i32, 0)),
                    .type = @enumFromInt(@as(u8, @intCast(try row.get(i16, 1)))),
                    .value = domain.FixedStr(128).from(try row.get([]const u8, 2)),
                    .confidence = @intCast(try row.get(i16, 3)),
                    .feed = @intCast(try row.get(i16, 4)),
                    .first_seen_ms = try row.get(i64, 5),
                    .last_seen_ms = try row.get(i64, 6),
                    .hits = @intCast(try row.get(i32, 7)),
                });
            }
        }
        {
            var res = try self.pool.query("select id, name, aliases, motivation, techniques, notes from actors order by id", .{});
            defer res.deinit();
            while (try res.next()) |row| {
                var actor: domain.ThreatActor = .{
                    .id = @intCast(try row.get(i16, 0)),
                    .name = domain.FixedStr(48).from(try row.get([]const u8, 1)),
                    .aliases = domain.FixedStr(96).from(try row.get([]const u8, 2)),
                    .motivation = @enumFromInt(@as(u8, @intCast(try row.get(i16, 3)))),
                    .notes = domain.FixedStr(600).from(try row.get([]const u8, 5)),
                };
                var it = std.mem.splitScalar(u8, try row.get([]const u8, 4), ',');
                while (it.next()) |tok| {
                    if (tok.len == 0 or actor.technique_count >= domain.ACTOR_TECHNIQUE_CAP) continue;
                    actor.techniques[actor.technique_count] = std.fmt.parseInt(domain.attack.TechniqueId, tok, 10) catch continue;
                    actor.technique_count += 1;
                }
                try s.actors.append(alloc, actor);
            }
        }
        {
            // Cap: newest 20k events, loaded ascending so eventById's
            // binary search over id order holds (mock ids are ts-ordered;
            // pgload preserves that).
            var res = try self.pool.query("select id, ts_ms, kind, severity, host, usr, sensor, parent, technique, process, cmdline, dst_ip, dst_port from (select * from events order by id desc limit 20000) sub order by id asc", .{});
            defer res.deinit();
            while (try res.next()) |row| {
                try s.events.append(alloc, .{
                    .id = @intCast(try row.get(i64, 0)),
                    .ts_ms = try row.get(i64, 1),
                    .kind = @enumFromInt(@as(u8, @intCast(try row.get(i16, 2)))),
                    .severity = @enumFromInt(@as(u8, @intCast(try row.get(i16, 3)))),
                    .host = @intCast(try row.get(i16, 4)),
                    .user = @intCast(try row.get(i16, 5)),
                    .sensor = @intCast(try row.get(i16, 6)),
                    .parent = if (try row.get(?i64, 7)) |p| @intCast(p) else null,
                    .technique = if (try row.get(?i16, 8)) |tq| @intCast(tq) else null,
                    .process = domain.FixedStr(64).from(try row.get([]const u8, 9)),
                    .cmdline = domain.FixedStr(160).from(try row.get([]const u8, 10)),
                    .dst_ip = domain.FixedStr(46).from(try row.get([]const u8, 11)),
                    .dst_port = @intCast(try row.get(i32, 12)),
                });
            }
        }
        {
            var res = try self.pool.query("select id, ts_ms, rule, severity, status, technique, title, entity, assignee, case_id, event_ids from alerts order by ts_ms asc", .{});
            defer res.deinit();
            while (try res.next()) |row| {
                var a: domain.Alert = .{
                    .id = @intCast(try row.get(i32, 0)),
                    .ts_ms = try row.get(i64, 1),
                    .rule = @intCast(try row.get(i16, 2)),
                    .severity = @enumFromInt(@as(u8, @intCast(try row.get(i16, 3)))),
                    .status = @enumFromInt(@as(u8, @intCast(try row.get(i16, 4)))),
                    .technique = if (try row.get(?i16, 5)) |tq| @intCast(tq) else null,
                    .title = domain.FixedStr(96).from(try row.get([]const u8, 6)),
                    .entity = domain.FixedStr(64).from(try row.get([]const u8, 7)),
                    .assignee = domain.FixedStr(24).from(try row.get([]const u8, 8)),
                    .case_id = if (try row.get(?i16, 9)) |c| @intCast(c) else null,
                };
                var it = std.mem.splitScalar(u8, try row.get([]const u8, 10), ',');
                while (it.next()) |tok| {
                    if (tok.len == 0 or a.event_count >= domain.ALERT_EVENT_CAP) continue;
                    a.event_ids[a.event_count] = std.fmt.parseInt(u64, tok, 10) catch continue;
                    a.event_count += 1;
                }
                try s.alerts.append(alloc, a);
            }
        }
        {
            var res = try self.pool.query("select id, title, severity, status, assignee, opened_ms, updated_ms, alert_ids, notes from cases order by id", .{});
            defer res.deinit();
            while (try res.next()) |row| {
                var c: domain.Case = .{
                    .id = @intCast(try row.get(i16, 0)),
                    .title = domain.FixedStr(96).from(try row.get([]const u8, 1)),
                    .severity = @enumFromInt(@as(u8, @intCast(try row.get(i16, 2)))),
                    .status = @enumFromInt(@as(u8, @intCast(try row.get(i16, 3)))),
                    .assignee = domain.FixedStr(24).from(try row.get([]const u8, 4)),
                    .opened_ms = try row.get(i64, 5),
                    .updated_ms = try row.get(i64, 6),
                    .notes = domain.FixedStr(480).from(try row.get([]const u8, 8)),
                };
                var it = std.mem.splitScalar(u8, try row.get([]const u8, 7), ',');
                while (it.next()) |tok| {
                    if (tok.len == 0 or c.alert_count >= domain.CASE_ALERT_CAP) continue;
                    c.alert_ids[c.alert_count] = std.fmt.parseInt(u32, tok, 10) catch continue;
                    c.alert_count += 1;
                }
                try s.cases.append(alloc, c);
            }
        }
        {
            var res = try self.pool.query("select id, code, name, status, severity, technique, author, date_ms, description, reference, version, strings_excerpt, condition, gate_compile, gate_meta, gate_tp, fp_count, scan_ms, budget_ms, last_ci_ms from yara_rules order by id", .{});
            defer res.deinit();
            while (try res.next()) |row| {
                try s.yara.append(alloc, .{
                    .id = @intCast(try row.get(i16, 0)),
                    .code = domain.FixedStr(8).from(try row.get([]const u8, 1)),
                    .name = domain.FixedStr(64).from(try row.get([]const u8, 2)),
                    .status = @enumFromInt(@as(u8, @intCast(try row.get(i16, 3)))),
                    .severity = @enumFromInt(@as(u8, @intCast(try row.get(i16, 4)))),
                    .technique = @intCast(try row.get(i16, 5)),
                    .author = domain.FixedStr(24).from(try row.get([]const u8, 6)),
                    .date_ms = try row.get(i64, 7),
                    .description = domain.FixedStr(160).from(try row.get([]const u8, 8)),
                    .reference = domain.FixedStr(96).from(try row.get([]const u8, 9)),
                    .version = @intCast(try row.get(i16, 10)),
                    .strings_excerpt = domain.FixedStr(240).from(try row.get([]const u8, 11)),
                    .condition = domain.FixedStr(160).from(try row.get([]const u8, 12)),
                    .gates = .{
                        .compile = @enumFromInt(@as(u8, @intCast(try row.get(i16, 13)))),
                        .meta = @enumFromInt(@as(u8, @intCast(try row.get(i16, 14)))),
                        .tp = @enumFromInt(@as(u8, @intCast(try row.get(i16, 15)))),
                        .fp_count = @intCast(try row.get(i32, 16)),
                        .scan_ms = try row.get(f32, 17),
                        .budget_ms = try row.get(f32, 18),
                        .last_ci_ms = try row.get(i64, 19),
                    },
                });
            }
        }
        {
            var res = try self.pool.query("select ioc_id, status, source, fetched_ms, err, verdict, det_malicious, det_suspicious, det_harmless, det_undetected, reputation, threat_label, first_seen_ms, last_seen_ms, registrar, creation_ms, categories, asn, as_owner, country, network, scan_score, brands, page_domain, page_ip, tls_issuer, pivot_ids from ioc_enrichment", .{});
            defer res.deinit();
            while (try res.next()) |row| {
                var e: domain.IocEnrichment = .{
                    .ioc_id = @intCast(try row.get(i32, 0)),
                    .status = @enumFromInt(@as(u8, @intCast(try row.get(i16, 1)))),
                    .source = @enumFromInt(@as(u8, @intCast(try row.get(i16, 2)))),
                    .fetched_ms = try row.get(i64, 3),
                    .err = domain.FixedStr(32).from(try row.get([]const u8, 4)),
                    .verdict = @enumFromInt(@as(u8, @intCast(try row.get(i16, 5)))),
                    .det_malicious = @intCast(try row.get(i32, 6)),
                    .det_suspicious = @intCast(try row.get(i32, 7)),
                    .det_harmless = @intCast(try row.get(i32, 8)),
                    .det_undetected = @intCast(try row.get(i32, 9)),
                    .reputation = try row.get(i32, 10),
                    .threat_label = domain.FixedStr(48).from(try row.get([]const u8, 11)),
                    .first_seen_ms = try row.get(i64, 12),
                    .last_seen_ms = try row.get(i64, 13),
                    .registrar = domain.FixedStr(48).from(try row.get([]const u8, 14)),
                    .creation_ms = try row.get(i64, 15),
                    .categories = domain.FixedStr(96).from(try row.get([]const u8, 16)),
                    .asn = @intCast(try row.get(i64, 17)),
                    .as_owner = domain.FixedStr(48).from(try row.get([]const u8, 18)),
                    .country = domain.FixedStr(4).from(try row.get([]const u8, 19)),
                    .network = domain.FixedStr(24).from(try row.get([]const u8, 20)),
                    .scan_score = @intCast(try row.get(i16, 21)),
                    .brands = domain.FixedStr(48).from(try row.get([]const u8, 22)),
                    .page_domain = domain.FixedStr(64).from(try row.get([]const u8, 23)),
                    .page_ip = domain.FixedStr(46).from(try row.get([]const u8, 24)),
                    .tls_issuer = domain.FixedStr(48).from(try row.get([]const u8, 25)),
                };
                var it = std.mem.splitScalar(u8, try row.get([]const u8, 26), ',');
                while (it.next()) |tok| {
                    if (tok.len == 0 or e.pivot_count >= domain.ENRICH_PIVOT_CAP) continue;
                    e.pivot_ids[e.pivot_count] = std.fmt.parseInt(u32, tok, 10) catch continue;
                    e.pivot_count += 1;
                }
                try s.enrichments.append(alloc, e);
            }
        }
        {
            var res = try self.pool.query("select id, ioc_id, state, submitted_ms, completed_ms, err from urlscan_scans order by id", .{});
            defer res.deinit();
            while (try res.next()) |row| {
                try s.urlscans.append(alloc, .{
                    .id = @intCast(try row.get(i32, 0)),
                    .ioc_id = @intCast(try row.get(i32, 1)),
                    .state = @enumFromInt(@as(u8, @intCast(try row.get(i16, 2)))),
                    .submitted_ms = try row.get(i64, 3),
                    .completed_ms = try row.get(i64, 4),
                    .err = domain.FixedStr(32).from(try row.get([]const u8, 5)),
                });
            }
        }
        s.touch();
        log.info("load: {d} events / {d} alerts / {d} rules / {d} iocs / {d} cases / {d} yara / {d} enrich", .{
            s.events.items.len, s.alerts.items.len, s.rules.items.len, s.iocs.items.len, s.cases.items.len,
            s.yara.items.len,   s.enrichments.items.len,
        });
    }

    // ── Mutation hook: Store writes → immediate UPDATEs ──────────────────

    pub fn installHook(self: *Provider, s: *Store) void {
        s.write_hook = .{ .ctx = self, .f = onMutation };
    }

    fn onMutation(ctx: *anyopaque, m: store_mod.Mutation) void {
        const self: *Provider = @ptrCast(@alignCast(ctx));
        const result = switch (m) {
            .alert_status => |v| self.pool.exec(
                "update alerts set status = $1 where id = $2",
                .{ @as(i16, @intFromEnum(v.status)), @as(i32, @intCast(v.id)) },
            ),
            .rule_status => |v| self.pool.exec(
                "update rules set status = $1 where id = $2",
                .{ @as(i16, @intFromEnum(v.status)), @as(i16, @intCast(v.id)) },
            ),
            .case_status => |v| self.pool.exec(
                "update cases set status = $1, updated_ms = $2 where id = $3",
                .{ @as(i16, @intFromEnum(v.status)), v.now_ms, @as(i16, @intCast(v.id)) },
            ),
            .case_assign => |v| blk: {
                _ = self.pool.exec(
                    "update alerts set case_id = $1 where id = $2",
                    .{ @as(i16, @intCast(v.case_id)), @as(i32, @intCast(v.alert_id)) },
                ) catch |err| break :blk @as(anyerror!?i64, err);
                break :blk self.pool.exec(
                    "update cases set alert_ids = trim(both ',' from alert_ids || ',' || $1), updated_ms = $2 where id = $3",
                    .{ v.alert_id, v.now_ms, @as(i16, @intCast(v.case_id)) },
                );
            },
            .yara_status => |v| self.pool.exec(
                "update yara_rules set status = $1 where id = $2",
                .{ @as(i16, @intFromEnum(v.status)), @as(i16, @intCast(v.id)) },
            ),
            .yara_ci => |v| self.pool.exec(
                "update yara_rules set gate_compile=$1, gate_meta=$2, gate_tp=$3, fp_count=$4, scan_ms=$5, budget_ms=$6, last_ci_ms=$7 where id=$8",
                .{ @as(i16, @intFromEnum(v.gates.compile)), @as(i16, @intFromEnum(v.gates.meta)), @as(i16, @intFromEnum(v.gates.tp)), @as(i32, @intCast(v.gates.fp_count)), v.gates.scan_ms, v.gates.budget_ms, v.gates.last_ci_ms, @as(i16, @intCast(v.id)) },
            ),
            .enrichment_upsert => |v| self.upsertEnrichmentRow(&v.e),
            .urlscan_submit => |v| self.pool.exec(
                "insert into urlscan_scans (id, ioc_id, state, submitted_ms, completed_ms, err) values ($1,$2,$3,$4,0,'') on conflict (id) do nothing",
                .{ @as(i32, @intCast(v.id)), @as(i32, @intCast(v.ioc_id)), @as(i16, @intFromEnum(domain.ScanState.pending)), v.now_ms },
            ),
            .urlscan_update => |v| self.pool.exec(
                "update urlscan_scans set state=$1, completed_ms=$2 where id=$3",
                .{ @as(i16, @intFromEnum(v.state)), v.now_ms, @as(i32, @intCast(v.id)) },
            ),
        };
        _ = result catch |err| {
            log.err("mutation write failed: {s} — DB is now behind the UI (reload from SET)", .{@errorName(err)});
        };
    }

    /// Upsert one enrichment row (insert-or-replace by ioc_id). Shared by
    /// the mutation hook and the bulk upload.
    fn upsertEnrichmentRow(self: *Provider, e: *const domain.IocEnrichment) anyerror!?i64 {
        var csv_buf: [256]u8 = undefined;
        const pivots = idCsv(u32, &csv_buf, e.pivot_ids[0..e.pivot_count]);
        return self.pool.exec(
            \\insert into ioc_enrichment (ioc_id, status, source, fetched_ms, err, verdict, det_malicious, det_suspicious, det_harmless, det_undetected, reputation, threat_label, first_seen_ms, last_seen_ms, registrar, creation_ms, categories, asn, as_owner, country, network, scan_score, brands, page_domain, page_ip, tls_issuer, pivot_ids)
            \\values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27)
            \\on conflict (ioc_id) do update set status=excluded.status, source=excluded.source, fetched_ms=excluded.fetched_ms, err=excluded.err, verdict=excluded.verdict, det_malicious=excluded.det_malicious, det_suspicious=excluded.det_suspicious, det_harmless=excluded.det_harmless, det_undetected=excluded.det_undetected, reputation=excluded.reputation, threat_label=excluded.threat_label, first_seen_ms=excluded.first_seen_ms, last_seen_ms=excluded.last_seen_ms, registrar=excluded.registrar, creation_ms=excluded.creation_ms, categories=excluded.categories, asn=excluded.asn, as_owner=excluded.as_owner, country=excluded.country, network=excluded.network, scan_score=excluded.scan_score, brands=excluded.brands, page_domain=excluded.page_domain, page_ip=excluded.page_ip, tls_issuer=excluded.tls_issuer, pivot_ids=excluded.pivot_ids
        ,
            .{
                @as(i32, @intCast(e.ioc_id)),          @as(i16, @intFromEnum(e.status)),  @as(i16, @intFromEnum(e.source)),
                e.fetched_ms,                          e.err.slice(),                     @as(i16, @intFromEnum(e.verdict)),
                @as(i32, @intCast(e.det_malicious)),   @as(i32, @intCast(e.det_suspicious)), @as(i32, @intCast(e.det_harmless)),
                @as(i32, @intCast(e.det_undetected)),  e.reputation,                      e.threat_label.slice(),
                e.first_seen_ms,                       e.last_seen_ms,                    e.registrar.slice(),
                e.creation_ms,                         e.categories.slice(),              @as(i64, @intCast(e.asn)),
                e.as_owner.slice(),                    e.country.slice(),                 e.network.slice(),
                @as(i16, @intCast(e.scan_score)),      e.brands.slice(),                  e.page_domain.slice(),
                e.page_ip.slice(),                     e.tls_issuer.slice(),              pivots,
            },
        );
    }

    // ── pgload: Store → DB bulk upload ───────────────────────────────────

    /// Wipe + bulk-insert a world (the `pgload` dev subcommand).
    pub fn upload(self: *Provider, s: *const Store) !void {
        const wipe = [_][]const u8{
            "delete from urlscan_scans", "delete from ioc_enrichment", "delete from yara_rules",
            "delete from cases", "delete from alerts",  "delete from events",
            "delete from actors", "delete from iocs",   "delete from rules",
            "delete from feeds",  "delete from sensors", "delete from users",
            "delete from hosts",
        };
        for (wipe) |stmt| _ = try self.pool.exec(stmt, .{});

        for (s.hosts.items, 0..) |*h, i| {
            _ = try self.pool.exec("insert into hosts (id, name) values ($1, $2)", .{ @as(i16, @intCast(i)), h.slice() });
        }
        for (s.users.items, 0..) |*u, i| {
            _ = try self.pool.exec("insert into users (id, name) values ($1, $2)", .{ @as(i16, @intCast(i)), u.slice() });
        }
        for (s.sensors.items) |*sn| {
            _ = try self.pool.exec(
                "insert into sensors (id, host, kind, status, eps, lag_s, last_seen_ms, version) values ($1,$2,$3,$4,$5,$6,$7,$8)",
                .{ @as(i16, @intCast(sn.id)), sn.host.slice(), @as(i16, @intFromEnum(sn.kind)), @as(i16, @intFromEnum(sn.status)), sn.eps, sn.lag_s, sn.last_seen_ms, sn.version.slice() },
            );
        }
        for (s.feeds.items) |*f| {
            _ = try self.pool.exec(
                "insert into feeds (id, name, url, last_sync_ms, ioc_count, status) values ($1,$2,$3,$4,$5,$6)",
                .{ @as(i16, @intCast(f.id)), f.name.slice(), f.url.slice(), f.last_sync_ms, @as(i32, @intCast(f.ioc_count)), @as(i16, @intFromEnum(f.status)) },
            );
        }
        for (s.rules.items) |*r| {
            _ = try self.pool.exec(
                "insert into rules (id, code, name, status, severity, technique, fires_7d, fp_7d, last_fire_ms, author, query) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
                .{ @as(i16, @intCast(r.id)), r.code.slice(), r.name.slice(), @as(i16, @intFromEnum(r.status)), @as(i16, @intFromEnum(r.severity)), @as(i16, @intCast(r.technique)), @as(i32, @intCast(r.fires_7d)), @as(i32, @intCast(r.fp_7d)), r.last_fire_ms, r.author.slice(), r.query.slice() },
            );
        }
        for (s.iocs.items) |*ic| {
            _ = try self.pool.exec(
                "insert into iocs (id, type, value, confidence, feed, first_seen_ms, last_seen_ms, hits) values ($1,$2,$3,$4,$5,$6,$7,$8)",
                .{ @as(i32, @intCast(ic.id)), @as(i16, @intFromEnum(ic.type)), ic.value.slice(), @as(i16, @intCast(ic.confidence)), @as(i16, @intCast(ic.feed)), ic.first_seen_ms, ic.last_seen_ms, @as(i32, @intCast(ic.hits)) },
            );
        }
        for (s.actors.items) |*a| {
            var csv_buf: [128]u8 = undefined;
            const csv = techniqueCsv(&csv_buf, a.techniques[0..a.technique_count]);
            _ = try self.pool.exec(
                "insert into actors (id, name, aliases, motivation, techniques, notes) values ($1,$2,$3,$4,$5,$6)",
                .{ @as(i16, @intCast(a.id)), a.name.slice(), a.aliases.slice(), @as(i16, @intFromEnum(a.motivation)), csv, a.notes.slice() },
            );
        }
        for (s.events.items) |*e| {
            _ = try self.pool.exec(
                "insert into events (id, ts_ms, kind, severity, host, usr, sensor, parent, technique, process, cmdline, dst_ip, dst_port) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
                .{
                    @as(i64, @intCast(e.id)),
                    e.ts_ms,
                    @as(i16, @intFromEnum(e.kind)),
                    @as(i16, @intFromEnum(e.severity)),
                    @as(i16, @intCast(e.host)),
                    @as(i16, @intCast(e.user)),
                    @as(i16, @intCast(e.sensor)),
                    if (e.parent) |p| @as(?i64, @intCast(p)) else null,
                    if (e.technique) |tq| @as(?i16, @intCast(tq)) else null,
                    e.process.slice(),
                    e.cmdline.slice(),
                    e.dst_ip.slice(),
                    @as(i32, @intCast(e.dst_port)),
                },
            );
        }
        for (s.alerts.items) |*a| {
            var csv_buf: [200]u8 = undefined;
            const csv = idCsv(u64, &csv_buf, a.event_ids[0..a.event_count]);
            _ = try self.pool.exec(
                "insert into alerts (id, ts_ms, rule, severity, status, technique, title, entity, assignee, case_id, event_ids) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
                .{
                    @as(i32, @intCast(a.id)),
                    a.ts_ms,
                    @as(i16, @intCast(a.rule)),
                    @as(i16, @intFromEnum(a.severity)),
                    @as(i16, @intFromEnum(a.status)),
                    if (a.technique) |tq| @as(?i16, @intCast(tq)) else null,
                    a.title.slice(),
                    a.entity.slice(),
                    a.assignee.slice(),
                    if (a.case_id) |c| @as(?i16, @intCast(c)) else null,
                    csv,
                },
            );
        }
        for (s.cases.items) |*c| {
            var csv_buf: [200]u8 = undefined;
            const csv = idCsv(u32, &csv_buf, c.alert_ids[0..c.alert_count]);
            _ = try self.pool.exec(
                "insert into cases (id, title, severity, status, assignee, opened_ms, updated_ms, alert_ids, notes) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
                .{ @as(i16, @intCast(c.id)), c.title.slice(), @as(i16, @intFromEnum(c.severity)), @as(i16, @intFromEnum(c.status)), c.assignee.slice(), c.opened_ms, c.updated_ms, csv, c.notes.slice() },
            );
        }
        for (s.yara.items) |*y| {
            _ = try self.pool.exec(
                "insert into yara_rules (id, code, name, status, severity, technique, author, date_ms, description, reference, version, strings_excerpt, condition, gate_compile, gate_meta, gate_tp, fp_count, scan_ms, budget_ms, last_ci_ms) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)",
                .{ @as(i16, @intCast(y.id)), y.code.slice(), y.name.slice(), @as(i16, @intFromEnum(y.status)), @as(i16, @intFromEnum(y.severity)), @as(i16, @intCast(y.technique)), y.author.slice(), y.date_ms, y.description.slice(), y.reference.slice(), @as(i16, @intCast(y.version)), y.strings_excerpt.slice(), y.condition.slice(), @as(i16, @intFromEnum(y.gates.compile)), @as(i16, @intFromEnum(y.gates.meta)), @as(i16, @intFromEnum(y.gates.tp)), @as(i32, @intCast(y.gates.fp_count)), y.gates.scan_ms, y.gates.budget_ms, y.gates.last_ci_ms },
            );
        }
        for (s.enrichments.items) |*e| {
            _ = try self.upsertEnrichmentRow(e);
        }
        for (s.urlscans.items) |*u| {
            _ = try self.pool.exec(
                "insert into urlscan_scans (id, ioc_id, state, submitted_ms, completed_ms, err) values ($1,$2,$3,$4,$5,$6)",
                .{ @as(i32, @intCast(u.id)), @as(i32, @intCast(u.ioc_id)), @as(i16, @intFromEnum(u.state)), u.submitted_ms, u.completed_ms, u.err.slice() },
            );
        }
        log.info("upload: {d} events / {d} alerts / {d} rules / {d} iocs / {d} cases / {d} yara / {d} enrich", .{
            s.events.items.len, s.alerts.items.len, s.rules.items.len, s.iocs.items.len, s.cases.items.len,
            s.yara.items.len,   s.enrichments.items.len,
        });
    }

    fn techniqueCsv(buf: []u8, ids: []const domain.attack.TechniqueId) []const u8 {
        var len: usize = 0;
        for (ids, 0..) |id, i| {
            const chunk = std.fmt.bufPrint(buf[len..], "{s}{d}", .{ if (i > 0) "," else "", id }) catch break;
            len += chunk.len;
        }
        return buf[0..len];
    }

    fn idCsv(comptime T: type, buf: []u8, ids: []const T) []const u8 {
        var len: usize = 0;
        for (ids, 0..) |id, i| {
            const chunk = std.fmt.bufPrint(buf[len..], "{s}{d}", .{ if (i > 0) "," else "", id }) catch break;
            len += chunk.len;
        }
        return buf[0..len];
    }
};
