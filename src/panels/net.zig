//! NET · Network Connections: network/dns events as a connections table
//! with IOC-match highlighting (dst against ip-type indicators). Filterable
//! (Ctrl+F), honors the TLN brush range, and IOC hits click through to ENR.

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const domain = @import("domain");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

const MAX_ROWS = 4096;

pub fn render(d: *Dashboard) void {
    const t = ui.theme.active;
    const s = &d.store;

    // ── Filter bar ───────────────────────────────────────────────────────
    if (d.net_focus_filter and zgui.isWindowFocused(.{ .root_window = true, .child_windows = true })) {
        d.net_focus_filter = false;
        zgui.setKeyboardFocusHere(0);
    }
    zgui.setNextItemWidth(170);
    _ = zgui.inputTextWithHint("##net_filter", .{ .hint = "filter (Ctrl+F)", .buf = &d.net_filter_buf });
    zgui.sameLine(.{ .spacing = 8 });
    if (dash.filterChip("IOC hits only##net", d.net_ioc_only, t.sev.crit)) {
        d.net_ioc_only = !d.net_ioc_only;
    }
    if (d.evt_range != null) {
        zgui.sameLine(.{ .spacing = 10 });
        zgui.textColored(t.amber, "TLN range", .{});
        zgui.sameLine(.{ .spacing = 4 });
        if (zgui.smallButton("\u{00D7}##netrange")) d.evt_range = null;
    }

    const filter = std.mem.sliceTo(&d.net_filter_buf, 0);
    var rows: [MAX_ROWS]u32 = undefined;
    var m: usize = 0;
    {
        var i: usize = s.events.items.len;
        while (i > 0 and m < rows.len) {
            i -= 1;
            const e = &s.events.items[i];
            if (e.kind != .network and e.kind != .dns) continue;
            if (d.evt_range) |r| {
                if (e.ts_ms < r[0] or e.ts_ms > r[1]) continue;
            }
            if (filter.len > 0) {
                const hit = std.ascii.indexOfIgnoreCase(e.dst_ip.slice(), filter) != null or
                    std.ascii.indexOfIgnoreCase(e.process.slice(), filter) != null or
                    std.ascii.indexOfIgnoreCase(s.hostName(e.host), filter) != null or
                    std.ascii.indexOfIgnoreCase(e.cmdline.slice(), filter) != null;
                if (!hit) continue;
            }
            if (d.net_ioc_only and (e.dst_ip.len == 0 or iocMatch(s, e.dst_ip.slice()) == null)) continue;
            rows[m] = @intCast(i);
            m += 1;
        }
    }

    zgui.sameLine(.{ .spacing = 12 });
    zgui.textColored(t.text.lo, "{d} connections \u{00B7} IOC hits click through to ENR", .{m});

    // Width-planned columns: Port is folded into Dst as ip:port, and the
    // plan drops Detail then Process in narrow docks — the old fixed set
    // (460px) exceeded the HUNT slot outright, crushing trailing columns
    // into unreadable fragments.
    const cols = [_]ui.table.Col{
        .{ .name = "Time", .w = 72 },
        .{ .name = "Host", .w = 100 },
        .{ .name = "Process", .w = 110, .prio = 1 },
        .{ .name = "Dst", .w = 150 },
        .{ .name = "Detail", .prio = 2 },
    };
    const pl = ui.table.plan(&cols, zgui.getContentRegionAvail()[0], 120);
    const flags = zgui.TableFlags{ .resizable = true, .no_saved_settings = true, .borders = .{ .inner_h = true }, .scroll_y = true };
    if (zgui.beginTable("##net_table", .{ .column = pl.count, .flags = flags })) {
        ui.table.setup(&cols, &pl);
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
                // Row click opens the underlying event in EVT.
                var slbl: [24]u8 = undefined;
                const sl = std.fmt.bufPrintZ(&slbl, "##netrow{d}", .{e.id}) catch "##n";
                const cur = zgui.getCursorPosX();
                if (zgui.selectable(sl, .{ .flags = .{ .span_all_columns = true, .allow_overlap = true } })) {
                    d.evt_sel = e.id;
                    d.focusPanel(dash.PANEL_EVT);
                }
                zgui.sameLine(.{});
                zgui.setCursorPosX(cur);
                var cb: [16]u8 = undefined;
                zgui.textColored(t.text.lo, "{s}", .{ui.fmt.ts(&cb, @divFloor(e.ts_ms, 1000))});
                _ = zgui.tableNextColumn();
                zgui.textUnformattedColored(t.text.hi, s.hostName(e.host));
                if (pl.on(2)) {
                    _ = zgui.tableNextColumn();
                    zgui.textUnformattedColored(t.text.mid, e.process.slice());
                }
                _ = zgui.tableNextColumn();
                if (e.dst_ip.len > 0) {
                    var db: [40]u8 = undefined;
                    const dst = if (e.dst_port > 0)
                        std.fmt.bufPrint(&db, "{s}:{d}", .{ e.dst_ip.slice(), e.dst_port }) catch e.dst_ip.slice()
                    else
                        e.dst_ip.slice();
                    var dz: [64]u8 = undefined;
                    const dstz = std.fmt.bufPrintZ(&dz, "{s}##netdst{d}", .{ dst, e.id }) catch @as([:0]const u8, "dst");
                    if (ioc_hit) {
                        // Confirmed indicator: click pivots to ENR.
                        const ioc = iocMatch(s, e.dst_ip.slice()).?;
                        zgui.pushStyleColor4f(.{ .idx = .text, .c = t.sev.crit });
                        if (zgui.selectable(dstz, .{})) {
                            d.enr_sel = ioc.id;
                            d.enr_history_len = 0;
                            d.focusPanel(dash.PANEL_ENR);
                        }
                        zgui.popStyleColor(.{ .count = 1 });
                        if (zgui.isItemHovered(.{})) {
                            if (zgui.beginTooltip()) {
                                zgui.text("IOC match \u{00B7} confidence {d} \u{00B7} feed {s} \u{00B7} click to enrich", .{
                                    ioc.confidence, s.feeds.items[ioc.feed].name.slice(),
                                });
                                zgui.endTooltip();
                            }
                        }
                    } else {
                        zgui.textUnformattedColored(t.text.hi, dst);
                    }
                } else {
                    zgui.textColored(t.text.lo, "\u{2014}", .{});
                }
                if (pl.on(4)) {
                    _ = zgui.tableNextColumn();
                    zgui.textUnformattedColored(t.text.mid, e.cmdline.slice());
                }
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
