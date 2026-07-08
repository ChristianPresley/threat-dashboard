//! YAR · YARA Rules: rules-as-code library with per-rule CI gate health
//! (compile / metadata / true-positive / false-positive / perf budget),
//! quality grades, and a detail pane exposing the 7-field metadata policy,
//! the rule body, and the gate breakdown. Modeled on rul.zig.

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const domain = @import("domain");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

var deprecate_dwell: ui.confirm.Dwell = .{};
var deprecate_pending: ?u16 = null;

fn statusColor(st: domain.YaraStatus) [4]f32 {
    const t = ui.theme.default;
    return switch (st) {
        .active => t.sev.ok,
        .draft => t.sev.warn,
        .deprecated => t.text.lo,
    };
}

/// One-glyph gate cell: letter tinted pass/fail with a tooltip.
fn gateGlyph(letter: [:0]const u8, pass: bool, tip: []const u8) void {
    zgui.textColored(dash.gateColor(pass), "{s}", .{letter});
    if (zgui.isItemHovered(.{})) {
        if (zgui.beginTooltip()) {
            zgui.text("{s}: {s}", .{ tip, if (pass) @as([]const u8, "PASS") else "FAIL" });
            zgui.endTooltip();
        }
    }
    zgui.sameLine(.{ .spacing = 3 });
}

pub fn render(d: *Dashboard) void {
    const t = ui.theme.default;
    const s = &d.store;

    // ── Header strip: grades · severity · gate pass rate · slowest ───────
    {
        const hist = s.yaraGradeHistogram();
        zgui.textColored(t.text.lo, "{d} rules", .{s.yara.items.len});
        zgui.sameLine(.{ .spacing = 10 });
        const grade_letters = [_][:0]const u8{ "A", "B", "C", "D", "F" };
        inline for (grade_letters, 0..) |gl, i| {
            if (i > 0) zgui.sameLine(.{ .spacing = 4 });
            zgui.textColored(dash.gradeColor(gl[0]), "{s}:{d}", .{ gl, hist[i] });
        }
        zgui.sameLine(.{ .spacing = 14 });
        const gp = s.yaraGatePassCounts();
        const total = gp.pass + gp.fail;
        zgui.textColored(if (gp.fail == 0) t.sev.ok else t.sev.warn, "gates {d}/{d} passing", .{ gp.pass, total });

        // Slowest rule vs budget.
        var worst: ?*domain.YaraRule = null;
        for (s.yara.items) |*y| {
            if (worst == null or y.gates.scan_ms > worst.?.gates.scan_ms) worst = y;
        }
        if (worst) |w| {
            zgui.sameLine(.{ .spacing = 14 });
            const over = !w.gates.perfPass();
            zgui.textColored(if (over) t.sev.warn else t.text.lo, "slowest {s} {d:.0}/{d:.0}ms", .{
                w.name.slice(), w.gates.scan_ms, w.gates.budget_ms,
            });
        }
        zgui.sameLine(.{ .spacing = 14 });
        if (d.jobs.active(.yara_ci, 0)) |job| {
            zgui.textColored(t.sev.warn, "{s} CI {s}\u{2026}", .{
                ui.fonts.fa.arrows_rotate, if (job.state == .queued) "queued" else "running",
            });
        } else if (zgui.smallButton("Run CI##yar")) {
            _ = d.enqueueJob(.yara_ci, 0, "all rules");
        }
    }
    zgui.separator();

    // ── Filter bar ───────────────────────────────────────────────────────
    if (d.yar_focus_filter and zgui.isWindowFocused(.{ .root_window = true, .child_windows = true })) {
        d.yar_focus_filter = false;
        zgui.setKeyboardFocusHere(0);
    }
    zgui.setNextItemWidth(200);
    _ = zgui.inputTextWithHint("##yar_filter", .{ .hint = "filter name/code (Ctrl+F)", .buf = &d.yar_filter_buf });
    zgui.sameLine(.{ .spacing = 8 });
    if (dash.filterChip("failures only##yarfail", d.yar_fail_only, t.sev.crit)) {
        d.yar_fail_only = !d.yar_fail_only;
    }
    if (d.yar_technique_filter) |tid| {
        const tech = domain.attack.get(tid);
        zgui.sameLine(.{ .spacing = 10 });
        zgui.textColored(t.amber, "technique {s}", .{tech.id});
        zgui.sameLine(.{ .spacing = 4 });
        if (zgui.smallButton("\u{00D7}##yartech")) d.yar_technique_filter = null;
    }

    const filter = std.mem.sliceTo(&d.yar_filter_buf, 0);

    const avail = zgui.getContentRegionAvail();
    const detail_h: f32 = if (d.yar_sel != null) 168 else 0;
    const table_h = @max(80, avail[1] - detail_h);

    const flags = zgui.TableFlags{ .resizable = true, .borders = .{ .inner_h = true }, .scroll_y = true };
    if (zgui.beginTable("##yar_table", .{ .column = 9, .flags = flags, .outer_size = .{ avail[0], table_h } })) {
        zgui.tableSetupColumn("Code", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 62 });
        zgui.tableSetupColumn("Gr", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 28 });
        zgui.tableSetupColumn("Name", .{ .flags = .{ .width_stretch = true } });
        zgui.tableSetupColumn("Sev", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 46 });
        zgui.tableSetupColumn("Technique", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 84 });
        zgui.tableSetupColumn("Gates", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 84 });
        zgui.tableSetupColumn("Scan ms", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 74 });
        zgui.tableSetupColumn("FP", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 34 });
        zgui.tableSetupColumn("Ver", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 36 });
        zgui.tableSetupScrollFreeze(0, 1);
        zgui.tableHeadersRow();

        for (s.yara.items) |*y| {
            if (filter.len > 0 and
                std.ascii.indexOfIgnoreCase(y.name.slice(), filter) == null and
                std.ascii.indexOfIgnoreCase(y.code.slice(), filter) == null) continue;
            if (d.yar_fail_only and y.gates.allPass()) continue;
            if (d.yar_technique_filter) |tid| {
                if (y.technique != tid) continue;
            }
            zgui.tableNextRow(.{});
            const selected = d.yar_sel != null and d.yar_sel.? == y.id;
            if (selected) {
                zgui.tableSetBgColor(.{ .target = .row_bg0, .color = zgui.colorConvertFloat4ToU32(t.bg.selected) });
            }

            _ = zgui.tableNextColumn();
            var slbl: [20]u8 = undefined;
            const sl = std.fmt.bufPrintZ(&slbl, "##yarrow{d}", .{y.id}) catch "##y";
            const cur = zgui.getCursorPosX();
            if (zgui.selectable(sl, .{ .selected = selected, .flags = .{ .span_all_columns = true, .allow_overlap = true } })) {
                d.yar_sel = y.id;
            }
            zgui.sameLine(.{});
            zgui.setCursorPosX(cur);
            zgui.textUnformattedColored(t.accent, y.code.slice());

            _ = zgui.tableNextColumn();
            var gb: [2]u8 = undefined;
            gb[0] = y.grade();
            gb[1] = 0;
            zgui.textColored(dash.gradeColor(y.grade()), "{s}", .{gb[0..1 :0]});

            _ = zgui.tableNextColumn();
            zgui.textUnformattedColored(if (y.status == .deprecated) t.text.lo else t.text.hi, y.name.slice());
            _ = zgui.tableNextColumn();
            zgui.textColored(dash.sevColor(y.severity), "{s}", .{y.severity.label()});
            _ = zgui.tableNextColumn();
            zgui.textColored(t.text.mid, "{s}", .{domain.attack.get(y.technique).id});

            // Gate glyphs C M T F P.
            _ = zgui.tableNextColumn();
            const g = &y.gates;
            gateGlyph("C", g.compile == .pass, "compile (warnings-as-errors)");
            gateGlyph("M", g.meta == .pass, "metadata policy");
            gateGlyph("T", g.tp == .pass, "true-positive fixture");
            gateGlyph("F", g.fpPass(), "false-positive corpus");
            zgui.textColored(dash.gateColor(g.perfPass()), "P", .{});
            if (zgui.isItemHovered(.{})) {
                if (zgui.beginTooltip()) {
                    zgui.text("perf budget: {s} ({d:.0}/{d:.0}ms)", .{
                        if (g.perfPass()) @as([]const u8, "PASS") else "FAIL", g.scan_ms, g.budget_ms,
                    });
                    zgui.endTooltip();
                }
            }

            _ = zgui.tableNextColumn();
            zgui.textColored(if (g.perfPass()) t.text.mid else t.sev.warn, "{d:.0}/{d:.0}", .{ g.scan_ms, g.budget_ms });
            _ = zgui.tableNextColumn();
            zgui.textColored(if (g.fp_count > 0) t.sev.crit else t.text.lo, "{d}", .{g.fp_count});
            _ = zgui.tableNextColumn();
            zgui.textColored(t.text.lo, "{d}", .{y.version});
        }
        zgui.endTable();
    }

    // ── Detail ───────────────────────────────────────────────────────────
    const sel = d.yar_sel orelse return;
    const y = s.yaraById(sel) orelse return;
    const g = &y.gates;

    zgui.separator();
    zgui.textUnformattedColored(t.accent, y.code.slice());
    zgui.sameLine(.{ .spacing = 8 });
    zgui.textUnformatted(y.name.slice());
    zgui.sameLine(.{ .spacing = 8 });
    zgui.textColored(dash.gradeColor(y.grade()), "grade {c} ({d})", .{ y.grade(), y.score() });
    zgui.sameLine(.{ .spacing = 8 });
    zgui.textColored(statusColor(y.status), "{s}", .{y.status.label()});

    // 7-field metadata policy, missing fields flagged.
    const tech = domain.attack.get(y.technique);
    var db: [16]u8 = undefined;
    zgui.textColored(t.text.mid, "author {s} \u{00B7} {s} \u{00B7} v{d} \u{00B7} {s} {s}", .{
        if (y.author.len > 0) y.author.slice() else "\u{2014}",
        ui.fmt.dateTime(&db, @divFloor(y.date_ms, 1000)),
        y.version,
        tech.id,
        tech.name,
    });
    if (y.reference.len > 0) {
        zgui.textColored(t.text.lo, "ref {s}", .{y.reference.slice()});
    } else {
        zgui.textColored(t.sev.crit, "ref \u{2014} MISSING (metadata policy: FAIL)", .{});
    }
    zgui.textColored(t.text.lo, "{s}", .{y.description.slice()});

    // Rule body: strings + condition in a sunken well.
    zgui.pushStyleColor4f(.{ .idx = .child_bg, .c = t.bg.sunken });
    if (zgui.beginChild("##yar_body", .{ .h = 56 })) {
        dash.textWrappedColored(t.text.hi, "{s}\ncondition: {s}", .{ y.strings_excerpt.slice(), y.condition.slice() });
    }
    zgui.endChild();
    zgui.popStyleColor(.{ .count = 1 });

    // Gate breakdown line + fixture note.
    zgui.textColored(t.text.mid, "gates:", .{});
    zgui.sameLine(.{ .spacing = 6 });
    gateGlyph("compile", g.compile == .pass, "compile");
    gateGlyph("meta", g.meta == .pass, "metadata");
    gateGlyph("tp", g.tp == .pass, "true-positive");
    gateGlyph("fp", g.fpPass(), "false-positive");
    zgui.textColored(dash.gateColor(g.perfPass()), "perf {d:.0}/{d:.0}ms", .{ g.scan_ms, g.budget_ms });
    zgui.sameLine(.{ .spacing = 10 });
    zgui.textColored(t.text.lo, "TP fixture: samples/{s}.bin (mapping.yml)", .{y.name.slice()});

    // Status controls. Deprecating an ACTIVE rule needs a dwell (coverage
    // gap), matching the RUL disable pattern.
    if (y.status != .active) {
        if (zgui.smallButton("Activate##yar")) {
            _ = s.setYaraStatus(y.id, .active);
            ui.events.post(.ok, "yara", "{s} activated", .{y.code.slice()});
        }
        zgui.sameLine(.{ .spacing = 6 });
    }
    if (y.status != .draft) {
        if (zgui.smallButton("Draft##yar")) {
            _ = s.setYaraStatus(y.id, .draft);
            ui.events.post(.info, "yara", "{s} \u{2192} draft", .{y.code.slice()});
        }
        zgui.sameLine(.{ .spacing = 6 });
    }
    if (y.status != .deprecated) {
        if (deprecate_pending != null and deprecate_pending.? == y.id) {
            if (deprecate_dwell.ready(ui.confirm.DWELL_T1_MS)) {
                if (zgui.smallButton("Confirm deprecate##yar")) {
                    _ = s.setYaraStatus(y.id, .deprecated);
                    ui.events.post(.warn, "yara", "{s} DEPRECATED \u{2014} coverage gap for {s}", .{ y.code.slice(), tech.id });
                    deprecate_pending = null;
                    deprecate_dwell.reset();
                }
            } else {
                zgui.textColored(t.text.lo, "confirm in {d:.1}s\u{2026}", .{deprecate_dwell.remainingSecs(ui.confirm.DWELL_T1_MS)});
            }
        } else if (zgui.smallButton("Deprecate\u{2026}##yar")) {
            deprecate_pending = y.id;
            deprecate_dwell.arm();
        }
    }
    zgui.sameLine(.{ .spacing = 14 });
    if (zgui.smallButton("\u{2192} ATT&CK rules##yar")) {
        d.rul_technique_filter = y.technique;
        d.focusPanel(dash.PANEL_RUL);
    }
}
