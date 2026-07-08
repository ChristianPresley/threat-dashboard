//! AUD · Audit Trail: chain of custody — every analyst/system action
//! recorded at the Store mutation choke point (who · what · when). The
//! list lives on the Dashboard (not the Store) so PG snapshot refreshes
//! can never erase it; bounded at Dashboard.AUDIT_CAP.

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

pub fn render(d: *Dashboard) void {
    const t = ui.theme.default;

    zgui.textColored(t.text.lo, "{d} action(s) recorded \u{00B7} cap {d}", .{ d.audit.items.len, Dashboard.AUDIT_CAP });
    zgui.sameLine(.{ .spacing = 10 });
    zgui.setNextItemWidth(180);
    _ = zgui.inputTextWithHint("##aud_filter", .{ .hint = "filter action/target", .buf = &d.aud_filter_buf });
    const filter = std.mem.sliceTo(&d.aud_filter_buf, 0);

    const flags = zgui.TableFlags{ .resizable = true, .borders = .{ .inner_h = true }, .scroll_y = true };
    if (zgui.beginTable("##aud_table", .{ .column = 4, .flags = flags })) {
        zgui.tableSetupColumn("Time", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 70 });
        zgui.tableSetupColumn("Actor", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 76 });
        zgui.tableSetupColumn("Action", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 130 });
        zgui.tableSetupColumn("Target", .{ .flags = .{ .width_stretch = true } });
        zgui.tableSetupScrollFreeze(0, 1);
        zgui.tableHeadersRow();

        var i = d.audit.items.len;
        while (i > 0) {
            i -= 1;
            const e = &d.audit.items[i];
            if (filter.len > 0 and
                std.ascii.indexOfIgnoreCase(e.action.slice(), filter) == null and
                std.ascii.indexOfIgnoreCase(e.target.slice(), filter) == null) continue;
            zgui.tableNextRow(.{});
            _ = zgui.tableNextColumn();
            var cb: [16]u8 = undefined;
            zgui.textColored(t.text.lo, "{s}", .{ui.fmt.clock(&cb, @divFloor(e.ts_ms, 1000))});
            _ = zgui.tableNextColumn();
            const is_system = std.mem.eql(u8, e.actor.slice(), "system");
            zgui.textUnformattedColored(if (is_system) t.text.lo else t.accent, e.actor.slice());
            _ = zgui.tableNextColumn();
            zgui.textUnformattedColored(t.text.mid, e.action.slice());
            _ = zgui.tableNextColumn();
            zgui.textUnformattedColored(t.text.hi, e.target.slice());
        }
        zgui.endTable();
    }
    if (d.audit.items.len == 0) {
        zgui.textColored(t.text.lo, "no actions yet \u{2014} ack an alert, toggle a rule, or run a pipeline", .{});
    }
}
