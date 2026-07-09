//! JOB · Jobs: the work queue — running jobs with progress + cancel,
//! queued jobs waiting on a slot, and a bounded terminal history
//! (done/failed/canceled with durations). Start buttons enqueue the
//! standard kinds; pipeline runs queue from PIP with their pipeline id.

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const data = @import("data");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

fn stateColor(st: data.jobs.JobState) [4]f32 {
    const t = ui.theme.active;
    return switch (st) {
        .queued => t.text.mid,
        .running => t.sev.info,
        .done => t.sev.ok,
        .failed => t.sev.crit,
        .canceled => t.text.lo,
    };
}

pub fn render(d: *Dashboard) void {
    const t = ui.theme.active;
    const e = &d.jobs;

    // ── Header: queue stats + start buttons ─────────────────────────────
    zgui.textColored(t.text.lo, "{d} running \u{00B7} {d} queued \u{00B7} {d} slots", .{
        e.runningCount(), e.queuedCount(), e.slots,
    });
    zgui.sameLine(.{ .spacing = 14 });
    const startable = [_]data.jobs.JobKind{ .feed_sync, .rule_backtest, .ioc_enrichment, .retention_sweep, .yara_ci };
    for (startable, 0..) |kind, i| {
        if (i > 0) zgui.sameLine(.{ .spacing = 4 });
        var bb: [40]u8 = undefined;
        const bl = std.fmt.bufPrintZ(&bb, "{s}##jobstart{d}", .{ kind.label(), i }) catch continue;
        const active = e.anyActive(kind);
        if (dash.filterChip(bl, active, t.accent) and !active) {
            _ = d.enqueueJob(kind, 0, "");
        }
    }

    // ── Queue + history table (newest first) ─────────────────────────────
    const flags = zgui.TableFlags{ .resizable = true, .borders = .{ .inner_h = true }, .scroll_y = true };
    if (zgui.beginTable("##job_table", .{ .column = 5, .flags = flags })) {
        zgui.tableSetupColumn("Job", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 116 });
        zgui.tableSetupColumn("Detail", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 130 });
        zgui.tableSetupColumn("State", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 74 });
        zgui.tableSetupColumn("Progress / result", .{ .flags = .{ .width_stretch = true } });
        zgui.tableSetupColumn("##act", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 62 });
        zgui.tableSetupScrollFreeze(0, 1);
        zgui.tableHeadersRow();

        var i = e.jobs.items.len;
        while (i > 0) {
            i -= 1;
            const j = &e.jobs.items[i];
            zgui.tableNextRow(.{});

            _ = zgui.tableNextColumn();
            zgui.textColored(if (j.state.terminal()) t.text.lo else t.text.hi, "{s}", .{j.kind.label()});
            _ = zgui.tableNextColumn();
            zgui.textUnformattedColored(t.text.mid, if (j.detail.len > 0) j.detail.slice() else "\u{2014}");
            _ = zgui.tableNextColumn();
            zgui.textColored(stateColor(j.state), "{s}", .{j.state.label()});

            _ = zgui.tableNextColumn();
            switch (j.state) {
                .running => zgui.progressBar(.{ .fraction = j.progress, .h = 14 }),
                .queued => {
                    var ab: [16]u8 = undefined;
                    const age_s = @divFloor(dash.unixNowMs() - j.queued_ms, 1000);
                    zgui.textColored(t.text.lo, "waiting {s} for a slot", .{ui.fmt.age(&ab, age_s)});
                },
                .failed => zgui.textColored(t.sev.crit, "{s}", .{if (j.err.len > 0) j.err.slice() else "failed"}),
                .done, .canceled => {
                    const dur_s = @divFloor(@max(0, j.finished_ms - j.started_ms), 1000);
                    var ab: [16]u8 = undefined;
                    const ago_s = @divFloor(dash.unixNowMs() - j.finished_ms, 1000);
                    zgui.textColored(t.text.lo, "{d}s \u{00B7} {s} ago", .{ dur_s, ui.fmt.age(&ab, ago_s) });
                },
            }

            _ = zgui.tableNextColumn();
            if (!j.state.terminal()) {
                var bb: [28]u8 = undefined;
                const bl = std.fmt.bufPrintZ(&bb, "Cancel##job{d}", .{j.id}) catch continue;
                if (zgui.smallButton(bl)) d.cancelJob(j.id);
            }
        }
        zgui.endTable();
    }
}
