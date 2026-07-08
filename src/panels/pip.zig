//! PIP · Data Pipelines: dbt-style ELT management. Pick a source (database
//! / bucket / topic / feed), chain transform models (stg_* → int_* →
//! mart_*), land in PostgreSQL or another sink. Shows per-pipeline lineage,
//! dbt test suite results, and run history; a builder section creates new
//! pipelines against the registered sources.

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const domain = @import("domain");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

var pause_dwell: ui.confirm.Dwell = .{};
var pause_pending: ?u16 = null;

fn statusColor(st: domain.PipelineStatus) [4]f32 {
    const t = ui.theme.default;
    return switch (st) {
        .active => t.sev.ok,
        .paused => t.text.lo,
        .err => t.sev.crit,
        .draft => t.sev.warn,
    };
}

fn runColor(st: domain.RunStatus) [4]f32 {
    const t = ui.theme.default;
    return switch (st) {
        .running => t.sev.info,
        .success => t.sev.ok,
        .failed => t.sev.crit,
        .partial => t.sev.warn,
    };
}

fn connColor(st: domain.ConnState) [4]f32 {
    const t = ui.theme.default.sev;
    return switch (st) {
        .ok => t.ok,
        .degraded => t.warn,
        .err => t.crit,
    };
}

/// Default materialization for a step kind (dbt convention: stage as a
/// view, aggregate as a table, everything in between incremental).
fn defaultMat(kind: domain.StepKind) domain.Materialization {
    return switch (kind) {
        .staging => .view,
        .aggregate => .table,
        else => .incremental,
    };
}

pub fn render(d: *Dashboard) void {
    const t = ui.theme.default;
    const s = &d.store;

    // ── Header strip: pipeline health · tests · 24h volume · run job ────
    {
        const pc = s.pipelineStatusCounts();
        zgui.textColored(t.text.lo, "{d} pipelines", .{s.pipelines.items.len});
        zgui.sameLine(.{ .spacing = 10 });
        zgui.textColored(t.sev.ok, "{d} active", .{pc[@intFromEnum(domain.PipelineStatus.active)]});
        const n_err = pc[@intFromEnum(domain.PipelineStatus.err)];
        zgui.sameLine(.{ .spacing = 8 });
        zgui.textColored(if (n_err > 0) t.sev.crit else t.text.lo, "{d} error", .{n_err});
        zgui.sameLine(.{ .spacing = 8 });
        zgui.textColored(t.text.lo, "{d} paused \u{00B7} {d} draft", .{
            pc[@intFromEnum(domain.PipelineStatus.paused)], pc[@intFromEnum(domain.PipelineStatus.draft)],
        });

        const tc = s.pipelineTestCounts();
        zgui.sameLine(.{ .spacing = 14 });
        zgui.textColored(if (tc.fail == 0) t.sev.ok else t.sev.warn, "tests {d}/{d} passing", .{ tc.pass, tc.pass + tc.fail });

        zgui.sameLine(.{ .spacing = 14 });
        const rows_24h = s.rowsIngestedSince(dash.unixNowMs() - 24 * std.time.ms_per_hour);
        zgui.textColored(t.text.mid, "{d} rows / 24h", .{rows_24h});

        if (d.jobs.anyActive(.pipeline_run)) {
            zgui.sameLine(.{ .spacing = 14 });
            zgui.textColored(t.sev.warn, "{s} run(s) in flight \u{00B7} see JOB", .{ui.fonts.fa.arrows_rotate});
        }
    }
    zgui.separator();

    // ── Filter bar + section toggles ─────────────────────────────────────
    if (d.pip_focus_filter and zgui.isWindowFocused(.{ .root_window = true, .child_windows = true })) {
        d.pip_focus_filter = false;
        zgui.setKeyboardFocusHere(0);
    }
    zgui.setNextItemWidth(200);
    _ = zgui.inputTextWithHint("##pip_filter", .{ .hint = "filter name/model (Ctrl+F)", .buf = &d.pip_filter_buf });
    zgui.sameLine(.{ .spacing = 8 });
    {
        const sc = s.sourceStateCounts();
        var lbl: [48]u8 = undefined;
        const l = std.fmt.bufPrintZ(&lbl, "sources {d}\u{00B7}{d}\u{00B7}{d}##pipsrc", .{ sc[0], sc[1], sc[2] }) catch "sources";
        const worst: domain.ConnState = if (sc[2] > 0) .err else if (sc[1] > 0) .degraded else .ok;
        if (dash.filterChip(l, d.pip_show_sources, connColor(worst))) d.pip_show_sources = !d.pip_show_sources;
    }
    zgui.sameLine(.{ .spacing = 8 });
    if (dash.filterChip("+ new pipeline##pipnew", d.pip_show_builder, t.accent)) {
        d.pip_show_builder = !d.pip_show_builder;
    }

    if (d.pip_show_sources) renderSources(d);
    if (d.pip_show_builder) renderBuilder(d);

    const filter = std.mem.sliceTo(&d.pip_filter_buf, 0);

    const avail = zgui.getContentRegionAvail();
    const detail_h: f32 = if (d.pip_sel != null) @max(190, avail[1] * 0.46) else 0;
    const table_h = @max(80, avail[1] - detail_h);

    // ── Pipeline table ───────────────────────────────────────────────────
    const flags = zgui.TableFlags{ .resizable = true, .borders = .{ .inner_h = true }, .scroll_y = true };
    if (zgui.beginTable("##pip_table", .{ .column = 9, .flags = flags, .outer_size = .{ avail[0], table_h } })) {
        zgui.tableSetupColumn("Code", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 58 });
        zgui.tableSetupColumn("Status", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 62 });
        zgui.tableSetupColumn("Name", .{ .flags = .{ .width_stretch = true } });
        zgui.tableSetupColumn("Source \u{2192} Sink", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 190 });
        zgui.tableSetupColumn("Sched", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 52 });
        zgui.tableSetupColumn("Last run", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 70 });
        zgui.tableSetupColumn("Next", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 60 });
        zgui.tableSetupColumn("Rows", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 74 });
        zgui.tableSetupColumn("Tests", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 56 });
        zgui.tableSetupScrollFreeze(0, 1);
        zgui.tableHeadersRow();

        for (s.pipelines.items) |*p| {
            if (filter.len > 0 and !pipelineMatches(p, filter)) continue;
            zgui.tableNextRow(.{});
            const selected = d.pip_sel != null and d.pip_sel.? == p.id;
            if (selected) {
                zgui.tableSetBgColor(.{ .target = .row_bg0, .color = zgui.colorConvertFloat4ToU32(t.bg.selected) });
            }

            _ = zgui.tableNextColumn();
            var slbl: [20]u8 = undefined;
            const sl = std.fmt.bufPrintZ(&slbl, "##piprow{d}", .{p.id}) catch "##p";
            const cur = zgui.getCursorPosX();
            if (zgui.selectable(sl, .{ .selected = selected, .flags = .{ .span_all_columns = true, .allow_overlap = true } })) {
                d.pip_sel = p.id;
                pause_pending = null;
                pause_dwell.reset();
            }
            zgui.sameLine(.{});
            zgui.setCursorPosX(cur);
            zgui.textUnformattedColored(t.accent, p.code.slice());

            _ = zgui.tableNextColumn();
            zgui.textColored(statusColor(p.status), "{s}", .{p.status.label()});
            _ = zgui.tableNextColumn();
            zgui.textUnformattedColored(if (p.status == .paused or p.status == .draft) t.text.lo else t.text.hi, p.name.slice());

            _ = zgui.tableNextColumn();
            if (s.sourceById(p.source)) |src| {
                zgui.textColored(connColor(src.state), "{s}", .{src.kind.label()});
            } else {
                zgui.textColored(t.sev.crit, "?", .{});
            }
            zgui.sameLine(.{ .spacing = 4 });
            zgui.textColored(t.text.lo, "\u{2192}", .{});
            zgui.sameLine(.{ .spacing = 4 });
            zgui.textColored(t.text.mid, "{s} {s}", .{ p.sink.label(), p.target.slice() });

            _ = zgui.tableNextColumn();
            if (p.schedule_min == 0) {
                zgui.textColored(t.text.lo, "manual", .{});
            } else {
                zgui.textColored(t.text.mid, "{d}m", .{p.schedule_min});
            }

            _ = zgui.tableNextColumn();
            if (p.last_run_ms > 0) {
                var ab: [16]u8 = undefined;
                const age_s = @divFloor(dash.unixNowMs() - p.last_run_ms, 1000);
                zgui.textColored(t.text.lo, "{s}", .{ui.fmt.age(&ab, age_s)});
            } else {
                zgui.textColored(t.text.lo, "\u{2014}", .{});
            }

            // Next scheduled run (countdown / due / — for manual+paused).
            _ = zgui.tableNextColumn();
            if (d.jobs.active(.pipeline_run, p.id) != null) {
                zgui.textColored(t.sev.info, "{s}", .{ui.fonts.fa.arrows_rotate});
            } else if (p.status != .active or p.schedule_min == 0) {
                zgui.textColored(t.text.lo, "\u{2014}", .{});
            } else {
                const due_ms = p.last_run_ms + @as(i64, p.schedule_min) * std.time.ms_per_min;
                const in_s = @divFloor(due_ms - dash.unixNowMs(), 1000);
                if (in_s <= 0) {
                    zgui.textColored(t.sev.warn, "due", .{});
                } else {
                    var nb2: [16]u8 = undefined;
                    zgui.textColored(t.text.lo, "{s}", .{ui.fmt.age(&nb2, in_s)});
                }
            }

            _ = zgui.tableNextColumn();
            if (s.lastRunFor(p.id)) |run| {
                zgui.textColored(runColor(run.status), "{d}", .{run.rows_out});
            } else {
                zgui.textColored(t.text.lo, "\u{2014}", .{});
            }

            _ = zgui.tableNextColumn();
            const tc = p.testCounts();
            if (tc.fail > 0) {
                zgui.textColored(t.sev.crit, "{d} FAIL", .{tc.fail});
            } else if (tc.pass > 0) {
                zgui.textColored(t.sev.ok, "{d} ok", .{tc.pass});
            } else {
                zgui.textColored(t.text.lo, "\u{2014}", .{});
            }
        }
        zgui.endTable();
    }

    // ── Detail: lineage · tests · runs · actions ─────────────────────────
    const sel = d.pip_sel orelse return;
    const p = s.pipelineById(sel) orelse {
        d.pip_sel = null;
        return;
    };

    zgui.separator();
    zgui.textUnformattedColored(t.accent, p.code.slice());
    zgui.sameLine(.{ .spacing = 8 });
    zgui.textUnformatted(p.name.slice());
    zgui.sameLine(.{ .spacing = 8 });
    zgui.textColored(statusColor(p.status), "{s}", .{p.status.label()});
    zgui.sameLine(.{ .spacing = 8 });
    zgui.textColored(t.text.mid, "owner {s}", .{if (p.owner.len > 0) p.owner.slice() else "\u{2014}"});

    // Lineage: source → models (materialization) → sink.
    {
        if (s.sourceById(p.source)) |src| {
            zgui.textColored(connColor(src.state), "{s} {s}", .{ src.kind.label(), src.name.slice() });
        } else {
            zgui.textColored(t.sev.crit, "source #{d} missing", .{p.source});
        }
        for (p.steps[0..p.step_count]) |*st| {
            zgui.sameLine(.{ .spacing = 5 });
            zgui.textColored(t.text.lo, "\u{2192}", .{});
            zgui.sameLine(.{ .spacing = 5 });
            zgui.textColored(t.amber, "{s}", .{st.model.slice()});
            zgui.sameLine(.{ .spacing = 3 });
            zgui.textColored(t.text.lo, "({s} \u{00B7} {s})", .{ st.kind.label(), st.materialization.label() });
        }
        zgui.sameLine(.{ .spacing = 5 });
        zgui.textColored(t.text.lo, "\u{2192}", .{});
        zgui.sameLine(.{ .spacing = 5 });
        zgui.textColored(t.text.hi, "{s} {s}", .{ p.sink.label(), p.target.slice() });
    }

    // Sink health: last landing, 24h volume, watermark lag.
    {
        const now = dash.unixNowMs();
        var rows_24h: u64 = 0;
        for (s.pipeline_runs.items) |*r| {
            if (r.pipeline == p.id and r.started_ms >= now - 24 * std.time.ms_per_hour and r.status != .running)
                rows_24h += r.rows_out;
        }
        const last = s.lastRunFor(p.id);
        const health: enum { healthy, degraded, failing, idle } = blk: {
            const lr = last orelse break :blk .idle;
            break :blk switch (lr.status) {
                .failed => .failing,
                .partial => .degraded,
                .success, .running => .healthy,
            };
        };
        const hcol = switch (health) {
            .healthy => t.sev.ok,
            .degraded => t.sev.warn,
            .failing => t.sev.crit,
            .idle => t.text.lo,
        };
        zgui.textColored(t.text.mid, "sink:", .{});
        zgui.sameLine(.{ .spacing = 6 });
        zgui.textColored(hcol, "{s}", .{@tagName(health)});
        zgui.sameLine(.{ .spacing = 10 });
        zgui.textColored(t.text.mid, "{d} rows / 24h", .{rows_24h});
        zgui.sameLine(.{ .spacing = 10 });
        if (p.watermark_ms > 0) {
            var lb: [16]u8 = undefined;
            const lag_s = @divFloor(now - p.watermark_ms, 1000);
            const stale = p.schedule_min > 0 and lag_s > @as(i64, p.schedule_min) * 3 * 60;
            zgui.textColored(if (stale) t.sev.warn else t.text.lo, "watermark lag {s}", .{ui.fmt.age(&lb, lag_s)});
        } else {
            zgui.textColored(t.text.lo, "no watermark yet", .{});
        }
    }

    // Actions.
    {
        if (d.jobs.active(.pipeline_run, p.id)) |job| {
            zgui.textColored(t.sev.warn, "{s} {s}\u{2026}", .{
                ui.fonts.fa.arrows_rotate, if (job.state == .queued) "queued" else "running",
            });
        } else if (zgui.smallButton("Run now##pip")) {
            d.requestPipelineRun(p.id);
        }
        if (p.status == .draft or p.status == .paused or p.status == .err) {
            zgui.sameLine(.{ .spacing = 6 });
            if (zgui.smallButton("Activate##pip")) {
                _ = s.setPipelineStatus(p.id, .active);
                ui.events.post(.ok, "pipeline", "{s} activated", .{p.code.slice()});
            }
        }
        // Pausing an ACTIVE pipeline stops ingestion — dwell-guarded.
        if (p.status == .active) {
            zgui.sameLine(.{ .spacing = 6 });
            if (pause_pending != null and pause_pending.? == p.id) {
                if (pause_dwell.ready(ui.confirm.DWELL_T1_MS)) {
                    if (zgui.smallButton("Confirm pause##pip")) {
                        _ = s.setPipelineStatus(p.id, .paused);
                        ui.events.post(.warn, "pipeline", "{s} PAUSED \u{2014} {s} stops filling", .{ p.code.slice(), p.target.slice() });
                        pause_pending = null;
                        pause_dwell.reset();
                    }
                } else {
                    zgui.textColored(t.text.lo, "confirm in {d:.1}s\u{2026}", .{pause_dwell.remainingSecs(ui.confirm.DWELL_T1_MS)});
                }
            } else if (zgui.smallButton("Pause\u{2026}##pip")) {
                pause_pending = p.id;
                pause_dwell.arm();
            }
        }
    }

    // Two-column lower half: dbt tests | run history.
    const lower = zgui.getContentRegionAvail();
    const col_w = lower[0] * 0.46;
    if (zgui.beginChild("##pip_tests", .{ .w = col_w, .h = lower[1] })) {
        zgui.textColored(t.text.mid, "dbt tests ({d}):", .{p.test_count});
        for (p.tests[0..p.test_count]) |*ts| {
            zgui.textColored(dash.gateColor(ts.status == .pass), "  {s}", .{ts.status.label()});
            zgui.sameLine(.{ .spacing = 8 });
            zgui.textColored(t.text.hi, "{s}({s})", .{ ts.kind.label(), ts.target.slice() });
            if (ts.failures > 0) {
                zgui.sameLine(.{ .spacing = 6 });
                zgui.textColored(t.sev.crit, "{d} failing rows", .{ts.failures});
            }
        }
        if (p.test_count == 0) zgui.textColored(t.text.lo, "  none defined", .{});

        // Dead letters: rejected-row samples with replay/drop.
        const open_n = s.openDeadLetterCount(p.id);
        zgui.spacing();
        zgui.textColored(if (open_n > 0) t.sev.warn else t.text.mid, "dead letters ({d} open):", .{open_n});
        var shown: u32 = 0;
        for (s.dead_letters.items) |*dl| {
            if (dl.pipeline != p.id or dl.state != .open) continue;
            if (shown >= 6) {
                zgui.textColored(t.text.lo, "  \u{2026} {d} more", .{open_n - shown});
                break;
            }
            shown += 1;
            zgui.textColored(t.sev.crit, "  {s}", .{dl.kind.label()});
            zgui.sameLine(.{ .spacing = 6 });
            zgui.textColored(t.text.mid, "{s}", .{dl.sample.slice()});
            zgui.sameLine(.{ .spacing = 8 });
            var rb: [28]u8 = undefined;
            const rl = std.fmt.bufPrintZ(&rb, "Replay##dlq{d}", .{dl.id}) catch continue;
            if (zgui.smallButton(rl)) {
                _ = s.setDeadLetterState(dl.id, .replayed);
                d.requestPipelineRun(p.id);
            }
            zgui.sameLine(.{ .spacing = 4 });
            var db2: [28]u8 = undefined;
            const dl2 = std.fmt.bufPrintZ(&db2, "Drop##dlq{d}", .{dl.id}) catch continue;
            if (zgui.smallButton(dl2)) {
                _ = s.setDeadLetterState(dl.id, .dropped);
                ui.events.post(.info, "pipeline", "dead letter #{d} dropped", .{dl.id});
            }
        }
    }
    zgui.endChild();
    zgui.sameLine(.{ .spacing = 10 });
    if (zgui.beginChild("##pip_runs", .{ .h = lower[1] })) {
        zgui.textColored(t.text.mid, "run history:", .{});
        var shown: u32 = 0;
        var i = s.pipeline_runs.items.len;
        while (i > 0 and shown < 10) {
            i -= 1;
            const run = &s.pipeline_runs.items[i];
            if (run.pipeline != p.id) continue;
            shown += 1;
            var ab: [16]u8 = undefined;
            const age_s = @divFloor(dash.unixNowMs() - run.started_ms, 1000);
            zgui.textColored(runColor(run.status), "  {s}", .{run.status.label()});
            zgui.sameLine(.{ .spacing = 8 });
            if (run.status == .failed) {
                zgui.textColored(t.text.mid, "{s} ago \u{00B7} {s}", .{ ui.fmt.age(&ab, age_s), run.err.slice() });
            } else if (run.status == .running) {
                zgui.textColored(t.text.mid, "{s} ago", .{ui.fmt.age(&ab, age_s)});
            } else {
                zgui.textColored(t.text.mid, "{s} ago \u{00B7} {d} in \u{2192} {d} out \u{00B7} {d:.1}s", .{
                    ui.fmt.age(&ab, age_s),
                    run.rows_in,
                    run.rows_out,
                    @as(f64, @floatFromInt(run.duration_ms)) / 1000.0,
                });
                if (run.rows_rejected > 0) {
                    zgui.sameLine(.{ .spacing = 6 });
                    zgui.textColored(t.sev.warn, "{d} rejected", .{run.rows_rejected});
                }
            }
        }
        if (shown == 0) zgui.textColored(t.text.lo, "  no runs yet", .{});
    }
    zgui.endChild();
}

fn pipelineMatches(p: *const domain.Pipeline, filter: []const u8) bool {
    if (std.ascii.indexOfIgnoreCase(p.name.slice(), filter) != null) return true;
    if (std.ascii.indexOfIgnoreCase(p.code.slice(), filter) != null) return true;
    for (p.steps[0..p.step_count]) |*st| {
        if (std.ascii.indexOfIgnoreCase(st.model.slice(), filter) != null) return true;
    }
    return false;
}

// ── Sources strip: registered databases/buckets/topics + Test action ────

fn renderSources(d: *Dashboard) void {
    const t = ui.theme.default;
    const s = &d.store;
    zgui.pushStyleColor4f(.{ .idx = .child_bg, .c = t.bg.sunken });
    defer zgui.popStyleColor(.{ .count = 1 });
    const h: f32 = @floatFromInt(28 + 19 * s.sources.items.len);
    if (zgui.beginChild("##pip_sources", .{ .h = @min(h, 190) })) {
        const flags = zgui.TableFlags{ .borders = .{ .inner_h = true }, .scroll_y = true };
        if (zgui.beginTable("##pip_src_table", .{ .column = 6, .flags = flags })) {
            zgui.tableSetupColumn("Kind", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 66 });
            zgui.tableSetupColumn("Source", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 150 });
            zgui.tableSetupColumn("DSN", .{ .flags = .{ .width_stretch = true } });
            zgui.tableSetupColumn("State", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 92 });
            zgui.tableSetupColumn("Latency", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 64 });
            zgui.tableSetupColumn("##test", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 44 });
            zgui.tableSetupScrollFreeze(0, 1);
            zgui.tableHeadersRow();
            for (s.sources.items) |*src| {
                zgui.tableNextRow(.{});
                _ = zgui.tableNextColumn();
                zgui.textColored(t.text.hi, "{s}", .{src.kind.label()});
                _ = zgui.tableNextColumn();
                zgui.textUnformattedColored(t.text.mid, src.name.slice());
                _ = zgui.tableNextColumn();
                zgui.textUnformattedColored(t.text.lo, src.dsn.slice());
                _ = zgui.tableNextColumn();
                zgui.textColored(connColor(src.state), "{s}", .{src.state.label()});
                _ = zgui.tableNextColumn();
                if (src.state == .err) {
                    zgui.textColored(t.text.lo, "\u{2014}", .{});
                } else {
                    zgui.textColored(t.text.mid, "{d:.0}ms", .{src.latency_ms});
                }
                _ = zgui.tableNextColumn();
                var bb: [24]u8 = undefined;
                const bl = std.fmt.bufPrintZ(&bb, "Test##src{d}", .{src.id}) catch "Test";
                if (zgui.smallButton(bl)) {
                    // Mock probe: an unreachable source stays unreachable
                    // (the story); healthy ones re-measure latency
                    // deterministically off the DSN.
                    const state = src.state;
                    const hash = std.hash.Fnv1a_64.hash(src.dsn.slice());
                    const lat: f32 = if (state == .err) 0 else 1.5 + @as(f32, @floatFromInt(hash % 240));
                    _ = s.recordSourceTest(src.id, state, lat, dash.unixNowMs());
                    ui.events.post(
                        if (state == .err) .warn else .ok,
                        "pipeline",
                        "{s}: connection {s}",
                        .{ src.name.slice(), if (state == .err) "FAILED" else "ok" },
                    );
                }
            }
            zgui.endTable();
        }
    }
    zgui.endChild();
}

// ── Builder: create a pipeline from source + steps + sink ───────────────

fn renderBuilder(d: *Dashboard) void {
    const t = ui.theme.default;
    const s = &d.store;
    zgui.pushStyleColor4f(.{ .idx = .child_bg, .c = t.bg.sunken });
    defer zgui.popStyleColor(.{ .count = 1 });
    if (zgui.beginChild("##pip_builder", .{ .h = 108 })) {
        zgui.textColored(t.text.mid, "new pipeline \u{2014} source \u{2192} models \u{2192} sink", .{});

        zgui.setNextItemWidth(170);
        _ = zgui.inputTextWithHint("##pip_name", .{ .hint = "name (snake_case)", .buf = &d.pip_new_name });
        zgui.sameLine(.{ .spacing = 8 });

        // Source picker.
        if (d.pip_new_source >= s.sources.items.len) d.pip_new_source = 0;
        var pb: [64]u8 = undefined;
        const src_preview: [:0]const u8 = if (s.sources.items.len == 0) "no sources" else blk: {
            const src = &s.sources.items[d.pip_new_source];
            break :blk std.fmt.bufPrintZ(&pb, "{s} \u{00B7} {s}", .{ src.kind.label(), src.name.slice() }) catch "source";
        };
        zgui.setNextItemWidth(210);
        if (zgui.beginCombo("##pip_src", .{ .preview_value = src_preview })) {
            for (s.sources.items, 0..) |*src, i| {
                var lb: [72]u8 = undefined;
                const ll = std.fmt.bufPrintZ(&lb, "{s} \u{00B7} {s}##bsrc{d}", .{ src.kind.label(), src.name.slice(), i }) catch continue;
                if (zgui.selectable(ll, .{ .selected = i == d.pip_new_source })) d.pip_new_source = i;
            }
            zgui.endCombo();
        }
        zgui.sameLine(.{ .spacing = 8 });

        // Sink picker + target.
        const sink_fields = @typeInfo(domain.SinkKind).@"enum".fields;
        if (d.pip_new_sink >= sink_fields.len) d.pip_new_sink = 0;
        const sink: domain.SinkKind = @enumFromInt(d.pip_new_sink);
        zgui.setNextItemWidth(120);
        if (zgui.beginCombo("##pip_sink", .{ .preview_value = sink.label() })) {
            inline for (0..sink_fields.len) |i| {
                const cand: domain.SinkKind = @enumFromInt(i);
                if (zgui.selectable(cand.label(), .{ .selected = i == d.pip_new_sink })) d.pip_new_sink = i;
            }
            zgui.endCombo();
        }
        zgui.sameLine(.{ .spacing = 8 });
        zgui.setNextItemWidth(160);
        _ = zgui.inputTextWithHint("##pip_target", .{ .hint = "target (schema.table)", .buf = &d.pip_new_target });
        zgui.sameLine(.{ .spacing = 8 });
        zgui.setNextItemWidth(90);
        _ = zgui.dragInt("##pip_sched", .{ .v = &d.pip_new_sched, .speed = 1, .min = 0, .max = 1440, .cfmt = "%d min" });

        // Step chips + add-step buttons (model names derive from the
        // pipeline name at create time).
        zgui.textColored(t.text.lo, "models:", .{});
        for (d.pip_new_steps[0..d.pip_new_step_count], 0..) |*st, i| {
            zgui.sameLine(.{ .spacing = 5 });
            var cb: [48]u8 = undefined;
            const cl = std.fmt.bufPrintZ(&cb, "{s} ({s}) \u{00D7}##bstep{d}", .{ st.kind.label(), st.materialization.label(), i }) catch continue;
            if (zgui.smallButton(cl)) {
                // Remove: shift the tail left.
                var k = i;
                while (k + 1 < d.pip_new_step_count) : (k += 1) d.pip_new_steps[k] = d.pip_new_steps[k + 1];
                d.pip_new_step_count -= 1;
            }
        }
        if (d.pip_new_step_count < domain.PIPELINE_STEP_CAP) {
            const kinds = [_]domain.StepKind{ .staging, .dedup, .filter, .enrich, .join, .aggregate, .mask };
            for (kinds, 0..) |k, ki| {
                zgui.sameLine(.{ .spacing = 4 });
                var ab: [24]u8 = undefined;
                const al = std.fmt.bufPrintZ(&ab, "+{s}##badd{d}", .{ k.label(), ki }) catch continue;
                if (zgui.smallButton(al)) {
                    d.pip_new_steps[d.pip_new_step_count] = .{ .kind = k, .materialization = defaultMat(k) };
                    d.pip_new_step_count += 1;
                }
            }
        }

        // Create.
        const name = std.mem.sliceTo(&d.pip_new_name, 0);
        const target = std.mem.sliceTo(&d.pip_new_target, 0);
        const ready = name.len > 0 and target.len > 0 and d.pip_new_step_count > 0 and s.sources.items.len > 0;
        if (ready) {
            zgui.sameLine(.{ .spacing = 14 });
            if (zgui.smallButton("Create##pipmk")) createPipeline(d, name, target, sink);
        } else {
            zgui.sameLine(.{ .spacing = 14 });
            zgui.textColored(t.text.lo, "need name + target + \u{2265}1 model", .{});
        }
    }
    zgui.endChild();
}

fn createPipeline(d: *Dashboard, name: []const u8, target: []const u8, sink: domain.SinkKind) void {
    const s = &d.store;
    var proto: domain.Pipeline = .{
        .id = 0,
        .name = domain.FixedStr(64).from(name),
        .source = s.sources.items[d.pip_new_source].id,
        .sink = sink,
        .target = domain.FixedStr(64).from(target),
        .schedule_min = @intCast(std.math.clamp(d.pip_new_sched, 0, 1440)),
        .status = .draft,
        .owner = domain.FixedStr(24).from("cpresley"),
    };
    // Materialize model names from the pipeline name: stg_/int_ prefixes
    // per dbt convention, deduped by ordinal.
    for (d.pip_new_steps[0..d.pip_new_step_count], 0..) |*st, i| {
        proto.steps[i] = st.*;
        proto.steps[i].model = if (st.kind == .staging)
            domain.FixedStr(48).fromFmt("stg_{s}", .{name})
        else
            domain.FixedStr(48).fromFmt("int_{s}_{s}", .{ name, @tagName(st.kind) });
    }
    proto.step_count = d.pip_new_step_count;
    // dbt starter tests: first model gets not_null + freshness.
    proto.tests[0] = .{ .kind = .not_null, .target = domain.FixedStr(48).fromFmt("{s}.id", .{proto.steps[0].model.slice()}) };
    proto.tests[1] = .{ .kind = .freshness, .target = proto.steps[0].model };
    proto.test_count = 2;

    if (s.addPipeline(proto)) |pid| {
        d.pip_sel = pid;
        d.pip_show_builder = false;
        d.pip_new_step_count = 0;
        @memset(&d.pip_new_name, 0);
        @memset(&d.pip_new_target, 0);
        ui.events.post(.ok, "pipeline", "{s} created as DRAFT \u{2014} activate to schedule", .{name});
    } else {
        ui.events.post(.warn, "pipeline", "create failed \u{2014} source missing?", .{});
    }
}
