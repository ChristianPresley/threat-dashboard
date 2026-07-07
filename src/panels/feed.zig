//! FEED · Intel Feeds: sync status per feed (staleness-aged), IOC counts,
//! and a mock "Sync now" that drives the JOB panel's feed-sync job.

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const domain = @import("domain");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

fn feedStatusColor(st: domain.FeedStatus) [4]f32 {
    const t = ui.theme.default.sev;
    return switch (st) {
        .ok => t.ok,
        .syncing => t.info,
        .err => t.crit,
    };
}

pub fn render(d: *Dashboard) void {
    const t = ui.theme.default;
    const s = &d.store;

    zgui.textColored(t.text.lo, "{d} feeds \u{00B7} {d} indicators total", .{ s.feeds.items.len, s.iocs.items.len });
    zgui.sameLine(.{ .spacing = 14 });
    if (zgui.smallButton("Sync all now##feed")) {
        d.startJob(0); // feed sync job
        for (s.feeds.items) |*f| {
            if (f.status != .err) f.status = .syncing;
        }
    }
    // Feed-sync job completion flips syncing feeds back to ok.
    if (!d.jobs[0].running) {
        for (s.feeds.items) |*f| {
            if (f.status == .syncing) {
                f.status = .ok;
                f.last_sync_ms = dash.unixNowMs();
            }
        }
    }

    const flags = zgui.TableFlags{ .resizable = true, .borders = .{ .inner_h = true }, .scroll_y = true };
    if (zgui.beginTable("##feed_table", .{ .column = 5, .flags = flags })) {
        zgui.tableSetupColumn("Status", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 70 });
        zgui.tableSetupColumn("Feed", .{ .flags = .{ .width_stretch = true } });
        zgui.tableSetupColumn("IOCs", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 56 });
        zgui.tableSetupColumn("Last sync", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 76 });
        zgui.tableSetupColumn("URL", .{ .flags = .{ .width_stretch = true } });
        zgui.tableSetupScrollFreeze(0, 1);
        zgui.tableHeadersRow();

        for (s.feeds.items) |*f| {
            zgui.tableNextRow(.{});
            _ = zgui.tableNextColumn();
            zgui.textColored(feedStatusColor(f.status), "{s} {s}", .{ ui.fonts.fa.circle, f.status.label() });
            _ = zgui.tableNextColumn();
            zgui.textUnformattedColored(t.text.hi, f.name.slice());
            _ = zgui.tableNextColumn();
            zgui.textColored(t.text.mid, "{d}", .{f.ioc_count});
            _ = zgui.tableNextColumn();
            var ab: [16]u8 = undefined;
            const age_s = @divFloor(dash.unixNowMs() - f.last_sync_ms, 1000);
            // Stale > 4h reads as a warning.
            const col = if (age_s > 4 * 3600 and f.status != .syncing) t.sev.warn else t.text.lo;
            zgui.textColored(col, "{s}", .{ui.fmt.age(&ab, age_s)});
            _ = zgui.tableNextColumn();
            zgui.textUnformattedColored(t.text.lo, f.url.slice());
        }
        zgui.endTable();
    }
}
