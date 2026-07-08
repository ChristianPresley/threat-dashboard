//! Panel dispatch: index → renderer. Bodies live one-per-file here;
//! shared helpers (sevColor, filterChip, …) live on the dashboard module.

const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

pub fn render(d: *Dashboard, idx: usize) void {
    switch (idx) {
        dash.PANEL_PST => @import("pst.zig").render(d),
        dash.PANEL_ALQ => @import("alq.zig").render(d),
        dash.PANEL_CAS => @import("cas.zig").render(d),
        dash.PANEL_TLN => @import("tln.zig").render(d),
        dash.PANEL_EVT => @import("evt.zig").render(d),
        dash.PANEL_PRC => @import("prc.zig").render(d),
        dash.PANEL_NET => @import("net.zig").render(d),
        dash.PANEL_RUL => @import("rul.zig").render(d),
        dash.PANEL_TUN => @import("tun.zig").render(d),
        dash.PANEL_ATK => @import("atk.zig").render(d),
        dash.PANEL_IOC => @import("ioc.zig").render(d),
        dash.PANEL_TA => @import("ta.zig").render(d),
        dash.PANEL_FEED => @import("feed.zig").render(d),
        dash.PANEL_SEN => @import("sen.zig").render(d),
        dash.PANEL_ING => @import("ing.zig").render(d),
        dash.PANEL_LOG => @import("log.zig").render(d),
        dash.PANEL_JOB => @import("job.zig").render(d),
        dash.PANEL_SET => @import("set.zig").render(d),
        dash.PANEL_HELP => @import("help.zig").render(d),
        dash.PANEL_YAR => @import("yar.zig").render(d),
        dash.PANEL_ENR => @import("enr.zig").render(d),
        else => {},
    }
}
