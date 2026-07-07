//! LOG · Event Log: the app's unified status/event stream (ui.events
//! ring). Severity chips, pause-on-scroll with a "N new" jump pill,
//! insert flashes, Ctrl+E CSV export. Near-copy of the trading LOG.

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

pub fn render(d: *Dashboard) void {
    const t = ui.theme.default;
    const n = ui.events.len();

    zgui.textColored(t.text.lo, "sev:", .{});
    const sev_names = [_][:0]const u8{ "ok", "info", "warn", "serious", "crit" };
    inline for (sev_names, 0..) |nm, i| {
        zgui.sameLine(.{ .spacing = 4 });
        if (dash.filterChip(nm ++ "##logsev", d.log_sev_show[i], dash.evSevColor(@enumFromInt(i)))) {
            d.log_sev_show[i] = !d.log_sev_show[i];
        }
    }
    zgui.sameLine(.{ .spacing = 14 });
    zgui.textColored(t.text.lo, "{d} events \u{00B7} UTC \u{00B7} Ctrl+E exports CSV", .{n});

    if (n == 0) {
        zgui.spacing();
        zgui.textColored(t.text.lo, "No events yet \u{2014} status, saves, and errors land here.", .{});
        return;
    }

    // Pause-on-scroll: freeze the displayed head while scrolled away.
    const frozen = d.log_frozen_head_seq;
    if (frozen > 0) {
        var fresh: usize = 0;
        var i: usize = 0;
        while (i < n) : (i += 1) {
            if (ui.events.nth(i).seq > frozen) fresh += 1 else break;
        }
        var pbuf: [48]u8 = undefined;
        const plbl = std.fmt.bufPrintZ(&pbuf, "{d} new \u{2014} jump to top##logjump", .{fresh}) catch "jump##logjump";
        zgui.pushStyleColor4f(.{ .idx = .text, .c = t.accent });
        if (zgui.smallButton(plbl)) d.log_jump_requested = true;
        zgui.popStyleColor(.{ .count = 1 });
    }

    var idxs: [ui.events.RING_CAP]u16 = undefined;
    var m: usize = 0;
    {
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const e = ui.events.nth(i);
            if (frozen > 0 and e.seq > frozen) continue;
            if (!d.log_sev_show[@intFromEnum(e.sev)]) continue;
            idxs[m] = @intCast(i);
            m += 1;
        }
    }
    if (m == 0) {
        zgui.textColored(t.text.lo, "No rows match \u{2014}", .{});
        zgui.sameLine(.{ .spacing = 6 });
        if (zgui.smallButton("Clear filters##log")) d.log_sev_show = @splat(true);
        return;
    }

    // Ctrl+E export while this panel is focused.
    {
        const ctrl = zgui.isKeyDown(.left_ctrl) or zgui.isKeyDown(.right_ctrl);
        if (ctrl and zgui.isKeyPressed(.e, false) and
            !zgui.io.getWantTextInput() and
            zgui.isWindowFocused(.{ .root_window = true, .child_windows = true }))
        {
            exportCsv(d, idxs[0..m]);
        }
    }

    const flags = zgui.TableFlags{
        .resizable = true,
        .borders = .{ .inner_h = true },
        .scroll_y = true,
    };
    if (zgui.beginTable("##log_table", .{ .column = 4, .flags = flags })) {
        defer zgui.endTable();
        zgui.tableSetupColumn("Time", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 84 });
        zgui.tableSetupColumn("Sev", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 64 });
        zgui.tableSetupColumn("Source", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 84 });
        zgui.tableSetupColumn("Message", .{ .flags = .{ .width_stretch = true } });
        zgui.tableSetupScrollFreeze(0, 1);
        zgui.tableHeadersRow();

        if (d.log_jump_requested) {
            d.log_jump_requested = false;
            d.log_frozen_head_seq = 0;
            zgui.setScrollY(0);
        } else {
            const sy = zgui.getScrollY();
            if (d.log_frozen_head_seq == 0 and sy > 1.0) {
                d.log_frozen_head_seq = ui.events.nth(0).seq;
            } else if (d.log_frozen_head_seq != 0 and sy <= 1.0) {
                d.log_frozen_head_seq = 0;
            }
        }

        var clipper = zgui.ListClipper.init();
        clipper.begin(@intCast(m), null);
        defer clipper.end();
        while (clipper.step()) {
            var row: i32 = clipper.DisplayStart;
            while (row < clipper.DisplayEnd) : (row += 1) {
                const ri: usize = @intCast(row);
                if (ri >= m) break;
                const e = ui.events.nth(idxs[ri]);
                zgui.tableNextRow(.{});

                // One-shot insert flash.
                const fl = ui.flash.update(ui.flash.cellKey("log", e.seq, 0), 0);
                if (fl.alpha > 0) {
                    const c = t.accent_dim;
                    zgui.tableSetBgColor(.{
                        .target = .row_bg0,
                        .color = zgui.colorConvertFloat4ToU32(.{ c[0], c[1], c[2], fl.alpha }),
                    });
                }

                _ = zgui.tableNextColumn();
                var cb: [16]u8 = undefined;
                ui.fmt.rightAlignedTextColored(t.text.lo, ui.fmt.clock(&cb, e.wall_ts));
                _ = zgui.tableNextColumn();
                zgui.textColored(dash.evSevColor(e.sev), "{s}", .{e.sev.label()});
                _ = zgui.tableNextColumn();
                zgui.textUnformatted(e.sourceSlice());
                _ = zgui.tableNextColumn();
                zgui.textUnformatted(e.msgSlice());
                if (zgui.isItemHovered(.{ .delay_normal = true })) {
                    if (zgui.beginTooltip()) {
                        dash.textWrappedColored(t.text.hi, "{s}", .{e.msgSlice()});
                        zgui.endTooltip();
                    }
                }
            }
        }
    }
}

/// Ctrl+E: visible rows → `<state-dir>/log-export.csv` (atomic write) + toast.
fn exportCsv(d: *Dashboard, idxs: []const u16) void {
    var path_buf: [300]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "{s}/log-export.csv", .{d.state_dir[0..d.state_dir_len]}) catch return;

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(d.allocator);
    out.appendSlice(d.allocator, "time_utc,severity,source,message\r\n") catch return;
    for (idxs) |ix| {
        const e = ui.events.nth(ix);
        var cb: [16]u8 = undefined;
        out.appendSlice(d.allocator, ui.fmt.clock(&cb, e.wall_ts)) catch return;
        out.append(d.allocator, ',') catch return;
        out.appendSlice(d.allocator, e.sev.label()) catch return;
        out.append(d.allocator, ',') catch return;
        out.appendSlice(d.allocator, e.sourceSlice()) catch return;
        out.appendSlice(d.allocator, ",\"") catch return;
        for (e.msgSlice()) |ch| {
            if (ch == '"') {
                out.appendSlice(d.allocator, "\"\"") catch return;
            } else {
                out.append(d.allocator, ch) catch return;
            }
        }
        out.appendSlice(d.allocator, "\"\r\n") catch return;
    }
    ui.layout.atomicWrite(path, out.items) catch |err| {
        ui.events.post(.crit, "cmd", "log export failed: {s}", .{@errorName(err)});
        return;
    };
    ui.events.post(.ok, "cmd", "exported {d} LOG rows \u{2192} {s}", .{ idxs.len, path });
}
