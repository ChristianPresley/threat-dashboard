//! PRC · Process Tree: parent/child chains for flagged (technique-tagged)
//! activity. Left: chain roots; right: TreeNode hierarchy with technique
//! badges and severity coloring.

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const domain = @import("domain");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

pub fn render(d: *Dashboard) void {
    const t = ui.theme.active;
    const s = &d.store;

    // Chain roots: technique-tagged events with no parent.
    var roots: [64]u64 = undefined;
    var nroots: usize = 0;
    for (s.events.items) |*e| {
        if (e.technique != null and e.parent == null and nroots < roots.len) {
            roots[nroots] = e.id;
            nroots += 1;
        }
    }

    if (nroots == 0) {
        zgui.textColored(t.text.lo, "No flagged process chains in the current world.", .{});
        return;
    }
    if (d.prc_sel_root == null) d.prc_sel_root = roots[0];

    // ── Root picker ──────────────────────────────────────────────────────
    zgui.textColored(t.text.lo, "chains:", .{});
    for (roots[0..nroots], 0..) |rid, i| {
        const e = s.eventById(rid) orelse continue;
        zgui.sameLine(.{ .spacing = 6 });
        var bb: [96]u8 = undefined;
        const bl = std.fmt.bufPrintZ(&bb, "{s} @ {s}##prcroot{d}", .{ e.process.slice(), s.hostName(e.host), i }) catch continue;
        if (dash.filterChip(bl, d.prc_sel_root == rid, dash.sevColor(chainWorst(s, rid)))) {
            d.prc_sel_root = rid;
        }
    }
    zgui.separator();

    const root = d.prc_sel_root orelse return;
    const root_e = s.eventById(root) orelse return;
    zgui.textColored(t.text.mid, "host {s} \u{00B7} user {s} \u{00B7} chain root #{d}", .{
        s.hostName(root_e.host), s.userName(root_e.user), root,
    });
    zgui.spacing();

    if (zgui.beginChild("##prc_tree", .{})) {
        drawNode(d, root, 0);
    }
    zgui.endChild();
}

/// Worst severity along a chain (for the root chip hue).
fn chainWorst(s: *@import("data").Store, root: u64) domain.Severity {
    var worst: domain.Severity = .info;
    for (s.events.items) |*e| {
        if (!inChain(s, e, root)) continue;
        if (@intFromEnum(e.severity) > @intFromEnum(worst)) worst = e.severity;
    }
    return worst;
}

fn inChain(s: *@import("data").Store, e: *const domain.Event, root: u64) bool {
    if (e.id == root) return true;
    var cur = e;
    var hops: usize = 0;
    while (cur.parent) |p| {
        if (p == root) return true;
        cur = s.eventById(p) orelse return false;
        hops += 1;
        if (hops > 32) return false;
    }
    return false;
}

fn drawNode(d: *Dashboard, id: u64, depth: usize) void {
    const t = ui.theme.active;
    const s = &d.store;
    const e = s.eventById(id) orelse return;
    if (depth > 24) return;

    var lb: [120]u8 = undefined;
    const label = std.fmt.bufPrintZ(&lb, "{s}  ({s})##prcn{d}", .{ e.process.slice(), e.kind.label(), id }) catch return;

    zgui.pushStyleColor4f(.{ .idx = .text, .c = dash.sevColor(e.severity) });
    const open = zgui.treeNodeFlags(label, .{ .default_open = true, .open_on_arrow = false });
    zgui.popStyleColor(.{ .count = 1 });

    // Technique badge + cmdline on the same line.
    if (e.technique) |tid| {
        const tech = domain.attack.get(tid);
        zgui.sameLine(.{ .spacing = 10 });
        zgui.textColored(t.accent, "[{s}]", .{tech.id});
        if (zgui.isItemHovered(.{})) {
            if (zgui.beginTooltip()) {
                zgui.text("{s} \u{00B7} {s}", .{ tech.name, tech.tactic.label() });
                zgui.endTooltip();
            }
        }
    }
    zgui.sameLine(.{ .spacing = 10 });
    var cb: [16]u8 = undefined;
    var ckb: [40]u8 = undefined;
    const clock_lbl = std.fmt.bufPrintZ(&ckb, "{s}##prcevt{d}", .{ ui.fmt.ts(&cb, @divFloor(e.ts_ms, 1000)), id }) catch "t";
    zgui.pushStyleColor4f(.{ .idx = .text, .c = t.text.lo });
    // Reverse of EVT's "open in PRC": the timestamp clicks through to EVT.
    if (zgui.selectable(clock_lbl, .{ .w = 44 })) {
        d.evt_sel = id;
        d.focusPanel(dash.PANEL_EVT);
    }
    zgui.popStyleColor(.{ .count = 1 });
    if (zgui.isItemHovered(.{})) {
        if (zgui.beginTooltip()) {
            zgui.textColored(t.text.mid, "open this event in EVT", .{});
            zgui.endTooltip();
        }
    }

    if (open) {
        dash.textWrappedColored(t.text.mid, "{s}", .{e.cmdline.slice()});
        // Children: linear scan is fine at world scale.
        for (s.events.items) |*child| {
            if (child.parent != null and child.parent.? == id) {
                drawNode(d, child.id, depth + 1);
            }
        }
        zgui.treePop();
    }
}
