//! Width-aware column planning for dense tables.
//!
//! Panels declare their columns once (fixed px or stretch weight, plus a
//! hide priority); `plan` drops the most expendable columns until the
//! stretch payload keeps a readable minimum width, whatever dock slot the
//! panel lands in. Without this, ImGui honors fixed widths first and the
//! lone stretch column absorbs the entire deficit — identity columns
//! collapse to 2-3 characters in narrow slots.
//!
//! Usage: build a `[]const Col`, call `plan` with the panel's available
//! width, pass `p.count` to beginTable, call `setup`, and guard each
//! hideable column's setup-order cell emission with `p.on(i)`. Tables
//! driven by a plan should set `.no_saved_settings = true`: a saved
//! `[Table]` ini section would override the planned widths, and the saved
//! column count fights width-dependent hiding.

const zgui = @import("zgui");

pub const MAX_COLS = 12;

pub const Col = struct {
    name: [:0]const u8,
    /// Fixed width in px; 0 = stretch (weight applies).
    w: f32 = 0,
    /// Stretch weight (stretch columns only).
    weight: f32 = 1,
    /// 0 = never hidden; higher values are hidden first when space is short.
    prio: u8 = 0,
};

pub const Plan = struct {
    vis: [MAX_COLS]bool = .{true} ** MAX_COLS,
    count: i32 = 0,

    pub fn on(self: *const Plan, i: usize) bool {
        return self.vis[i];
    }
};

/// Decide which columns fit `avail_w` (pass getContentRegionAvail()[0]):
/// hide the highest-priority hideable columns until at least `min_stretch_w`
/// px remain for the stretch column(s). Falls back to keeping every prio-0
/// column even when the minimum can't be met.
pub fn plan(cols: []const Col, avail_w: f32, min_stretch_w: f32) Plan {
    var p = Plan{ .count = @intCast(cols.len) };
    const cell_pad = 2 * zgui.getStyle().cell_padding[0];
    const scrollbar: f32 = 14;
    while (true) {
        var fixed: f32 = scrollbar;
        var has_stretch = false;
        for (cols, 0..) |c, i| {
            if (!p.vis[i]) continue;
            fixed += cell_pad + c.w;
            if (c.w == 0) has_stretch = true;
        }
        const need: f32 = if (has_stretch) min_stretch_w else 0;
        if (avail_w - fixed >= need) return p;
        var pick: ?usize = null;
        for (cols, 0..) |c, i| {
            if (!p.vis[i] or c.prio == 0) continue;
            if (pick == null or c.prio > cols[pick.?].prio) pick = i;
        }
        const i = pick orelse return p;
        p.vis[i] = false;
        p.count -= 1;
    }
}

/// Emit tableSetupColumn for every visible column.
pub fn setup(cols: []const Col, p: *const Plan) void {
    for (cols, 0..) |c, i| {
        if (!p.vis[i]) continue;
        if (c.w > 0) {
            zgui.tableSetupColumn(c.name, .{ .flags = .{ .width_fixed = true }, .init_width_or_height = c.w });
        } else {
            zgui.tableSetupColumn(c.name, .{ .flags = .{ .width_stretch = true }, .init_width_or_height = c.weight });
        }
    }
}
