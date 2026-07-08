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
        if (d.jobs.enqueue(.feed_sync, 0, "all feeds", dash.unixNowMs()) != null) {
            for (s.feeds.items) |*f| f.status = .syncing;
            s.touch();
        } else {
            ui.events.post(.warn, "feeds", "a fleet sync is already queued/running", .{});
        }
    }

    const flags = zgui.TableFlags{ .resizable = true, .borders = .{ .inner_h = true }, .scroll_y = true };
    if (zgui.beginTable("##feed_table", .{ .column = 5, .flags = flags })) {
        // Feed stretches: the name is the payload. The source URL is dropped
        // from the table (it's boilerplate flavor) so names stay whole in the
        // narrow INTEL column; it's still available on hover.
        // Status is just the LED (color = state); the label + URL live in the
        // hover tooltip. That reclaims width for the feed Name in the narrow
        // INTEL column so names never clip.
        zgui.tableSetupColumn("St", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 26 });
        zgui.tableSetupColumn("Feed", .{ .flags = .{ .width_stretch = true } });
        zgui.tableSetupColumn("IOCs", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 50 });
        zgui.tableSetupColumn("Sync", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 60 });
        zgui.tableSetupColumn("##act", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 42 });
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
            _ = zgui.tableNextColumn();
            zgui.textColored(t.text.mid, "{d}", .{f.ioc_count});
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
                    if (d.jobs.enqueue(.feed_sync, @as(u32, f.id) + 1, f.name.slice(), dash.unixNowMs()) != null) {
                        f.status = .syncing;
                        s.touch();
                    }
                }
            }
        }
        zgui.endTable();
    }
}
