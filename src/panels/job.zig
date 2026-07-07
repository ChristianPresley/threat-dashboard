//! JOB · Jobs: mock async work — phase, progress bar, start/cancel.

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

pub fn render(d: *Dashboard) void {
    const t = ui.theme.default;

    const flags = zgui.TableFlags{ .resizable = true, .borders = .{ .inner_h = true } };
    if (zgui.beginTable("##job_table", .{ .column = 4, .flags = flags })) {
        zgui.tableSetupColumn("Job", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 130 });
        zgui.tableSetupColumn("Phase", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 80 });
        zgui.tableSetupColumn("Progress", .{ .flags = .{ .width_stretch = true } });
        zgui.tableSetupColumn("", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 80 });
        zgui.tableHeadersRow();

        for (&d.jobs, 0..) |*j, i| {
            zgui.tableNextRow(.{});
            _ = zgui.tableNextColumn();
            zgui.textUnformattedColored(t.text.hi, j.name);
            _ = zgui.tableNextColumn();
            zgui.textColored(if (j.running) t.sev.info else t.text.lo, "{s}", .{j.phase});
            _ = zgui.tableNextColumn();
            if (j.running) {
                zgui.progressBar(.{ .fraction = j.progress, .h = 14 });
            } else {
                zgui.textColored(t.text.lo, "\u{2014}", .{});
            }
            _ = zgui.tableNextColumn();
            var bb: [32]u8 = undefined;
            if (j.running) {
                const bl = std.fmt.bufPrintZ(&bb, "Cancel##job{d}", .{i}) catch continue;
                if (zgui.smallButton(bl)) {
                    j.running = false;
                    j.phase = "cancelled";
                    j.progress = 0;
                    ui.events.post(.warn, "jobs", "{s} cancelled", .{j.name});
                }
            } else {
                const bl = std.fmt.bufPrintZ(&bb, "Start##job{d}", .{i}) catch continue;
                if (zgui.smallButton(bl)) d.startJob(i);
            }
        }
        zgui.endTable();
    }
    zgui.spacing();
    zgui.textColored(t.text.lo, "Jobs are mock async workers in this phase \u{2014} real ingestion/backtest workers land with the Postgres provider.", .{});
}
