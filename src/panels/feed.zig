//! FEED · Intel Feeds: sync status per feed (staleness-aged), IOC counts,
//! per-feed + fleet-wide sync driving queued feed-sync jobs. Completion
//! side effects live in Dashboard.onJobComplete (a canceled sync reverts
//! instead of masquerading as success).

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

    zgui.textColored(t.text.lo, "{d} feeds \u{00B7} {d} IOCs", .{ s.feeds.items.len, s.iocs.items.len });
    zgui.sameLine(.{ .spacing = 10 });
    if (zgui.smallButton("Sync all##feed")) {
        // A fleet sync and per-feed syncs must never overlap — whichever
        // completes first would flip feeds the other still owns.
        if (d.jobs.anyActive(.feed_sync)) {
            ui.events.post(.warn, "feeds", "a feed sync is already queued/running \u{2014} see JOB", .{});
        } else if (d.jobs.enqueue(.feed_sync, 0, "all feeds", dash.unixNowMs()) != null) {
            for (s.feeds.items) |*f| {
                if (f.status != .syncing) _ = s.setFeedStatus(f.id, .syncing, null);
            }
        }
    }

    // Feed stretches: the name is the payload. Status is just the LED
    // (label + URL live in the hover tooltip); the width plan drops the
    // IOCs count first when the INTEL column runs narrow so names never
    // clip regardless of dock geometry.
    const cols = [_]ui.table.Col{
        .{ .name = "St", .w = 26 },
        .{ .name = "Feed" },
        .{ .name = "IOCs", .w = 50, .prio = 1 },
        .{ .name = "Sync", .w = 60 },
        .{ .name = "##act", .w = 42 },
    };
    const pl = ui.table.plan(&cols, zgui.getContentRegionAvail()[0], 150);
    const flags = zgui.TableFlags{ .resizable = true, .no_saved_settings = true, .borders = .{ .inner_h = true }, .scroll_y = true };
    if (zgui.beginTable("##feed_table", .{ .column = pl.count, .flags = flags })) {
        ui.table.setup(&cols, &pl);
        zgui.tableSetupScrollFreeze(0, 1);
        zgui.tableHeadersRow();

        for (s.feeds.items) |*f| {
            zgui.tableNextRow(.{});
            _ = zgui.tableNextColumn();
            zgui.textColored(feedStatusColor(f.status), "{s}", .{ui.fonts.fa.circle});
            if (zgui.isItemHovered(.{})) {
                if (zgui.beginTooltip()) {
                    zgui.textColored(feedStatusColor(f.status), "{s}", .{f.status.label()});
                    zgui.endTooltip();
                }
            }
            _ = zgui.tableNextColumn();
            zgui.textUnformattedColored(t.text.hi, f.name.slice());
            if (zgui.isItemHovered(.{})) {
                if (zgui.beginTooltip()) {
                    zgui.textColored(t.text.lo, "{s} \u{00B7} {s}", .{ f.status.label(), f.url.slice() });
                    zgui.endTooltip();
                }
            }
            if (pl.on(2)) {
                _ = zgui.tableNextColumn();
                zgui.textColored(t.text.mid, "{d}", .{f.ioc_count});
            }
            _ = zgui.tableNextColumn();
            var ab: [16]u8 = undefined;
            const age_s = @divFloor(dash.unixNowMs() - f.last_sync_ms, 1000);
            // Stale > 4h reads as a warning.
            const col = if (age_s > 4 * 3600 and f.status != .syncing) t.sev.warn else t.text.lo;
            zgui.textColored(col, "{s}", .{ui.fmt.age(&ab, age_s)});

            _ = zgui.tableNextColumn();
            if (f.status == .syncing) {
                zgui.textColored(t.sev.info, "{s}", .{ui.fonts.fa.arrows_rotate});
            } else {
                var bb: [24]u8 = undefined;
                const bl = std.fmt.bufPrintZ(&bb, "Sync##feed{d}", .{f.id}) catch "Sync";
                if (zgui.smallButton(bl)) {
                    if (d.jobs.active(.feed_sync, 0) != null) {
                        ui.events.post(.warn, "feeds", "a fleet sync is already queued/running \u{2014} see JOB", .{});
                    } else if (d.jobs.enqueue(.feed_sync, @as(u32, f.id) + 1, f.name.slice(), dash.unixNowMs()) != null) {
                        _ = s.setFeedStatus(f.id, .syncing, null);
                    }
                }
            }
        }
        zgui.endTable();
    }
}
