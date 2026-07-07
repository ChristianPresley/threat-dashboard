//! NET · Network Connections: network/dns events as a connections table
//! with IOC-match highlighting (dst against ip-type indicators).

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const domain = @import("domain");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

const MAX_ROWS = 4096;

pub fn render(d: *Dashboard) void {
    const t = ui.theme.default;
    const s = &d.store;

    var rows: [MAX_ROWS]u32 = undefined;
    var m: usize = 0;
    {
        var i: usize = s.events.items.len;
        while (i > 0 and m < rows.len) {
            i -= 1;
            const e = &s.events.items[i];
            if (e.kind != .network and e.kind != .dns) continue;
            rows[m] = @intCast(i);
            m += 1;
        }
    }

    zgui.textColored(t.text.lo, "{d} connections \u{00B7} IOC matches in red \u{00B7} flagged rows tinted", .{m});

    const flags = zgui.TableFlags{ .resizable = true, .borders = .{ .inner_h = true }, .scroll_y = true };
    if (zgui.beginTable("##net_table", .{ .column = 6, .flags = flags })) {
        zgui.tableSetupColumn("Time", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 72 });
        zgui.tableSetupColumn("Host", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 100 });
        zgui.tableSetupColumn("Process", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 110 });
        zgui.tableSetupColumn("Dst", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 130 });
        zgui.tableSetupColumn("Port", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 48 });
        zgui.tableSetupColumn("Detail", .{ .flags = .{ .width_stretch = true } });
        zgui.tableSetupScrollFreeze(0, 1);
        zgui.tableHeadersRow();

        var clipper = zgui.ListClipper.init();
        clipper.begin(@intCast(m), null);
        defer clipper.end();
        while (clipper.step()) {
            var row: i32 = clipper.DisplayStart;
            while (row < clipper.DisplayEnd) : (row += 1) {
                const ri: usize = @intCast(row);
                if (ri >= m) break;
                const e = &s.events.items[rows[ri]];
                zgui.tableNextRow(.{});
                if (e.technique != null) {
                    zgui.tableSetBgColor(.{ .target = .row_bg0, .color = zgui.colorConvertFloat4ToU32(dash.sevDimColor(e.severity)) });
                }
                const ioc_hit = e.dst_ip.len > 0 and iocMatch(s, e.dst_ip.slice()) != null;

                _ = zgui.tableNextColumn();
                var cb: [16]u8 = undefined;
                zgui.textColored(t.text.lo, "{s}", .{ui.fmt.clock(&cb, @divFloor(e.ts_ms, 1000))});
                _ = zgui.tableNextColumn();
                zgui.textUnformattedColored(t.text.hi, s.hostName(e.host));
                _ = zgui.tableNextColumn();
                zgui.textUnformattedColored(t.text.mid, e.process.slice());
                _ = zgui.tableNextColumn();
                if (e.dst_ip.len > 0) {
                    zgui.textUnformattedColored(if (ioc_hit) t.sev.crit else t.text.hi, e.dst_ip.slice());
                    if (ioc_hit and zgui.isItemHovered(.{})) {
                        if (zgui.beginTooltip()) {
                            const ioc = iocMatch(s, e.dst_ip.slice()).?;
                            zgui.text("IOC match \u{00B7} confidence {d} \u{00B7} feed {s}", .{
                                ioc.confidence, s.feeds.items[ioc.feed].name.slice(),
                            });
                            zgui.endTooltip();
                        }
                    }
                } else {
                    zgui.textColored(t.text.lo, "\u{2014}", .{});
                }
                _ = zgui.tableNextColumn();
                if (e.dst_port > 0) {
                    zgui.textColored(t.text.mid, "{d}", .{e.dst_port});
                } else {
                    zgui.textColored(t.text.lo, "\u{2014}", .{});
                }
                _ = zgui.tableNextColumn();
                zgui.textUnformattedColored(t.text.mid, e.cmdline.slice());
            }
        }
        zgui.endTable();
    }
}

/// Linear IOC lookup on ip-type indicators — world scale keeps this cheap.
fn iocMatch(s: *@import("data").Store, dst: []const u8) ?*const domain.Ioc {
    for (s.iocs.items) |*ic| {
        if (ic.type == .ip and std.mem.eql(u8, ic.value.slice(), dst)) return ic;
    }
    return null;
}
