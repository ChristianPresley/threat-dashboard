//! Command registry (DESIGN.md §4.2) — ONE source of truth for every panel
//! code and action verb. The command line, `>` palette, View menu, keyboard
//! chords, HELP directory, and the --selftest coverage check all read this
//! table; mouse parity is enforced by construction (every entry carries a
//! menu path) rather than by discipline.
//!
//! The registry is generic over an opaque context (the Dashboard) so this
//! module stays free of app dependencies.

const std = @import("std");

pub const Kind = enum {
    /// Focuses/opens a panel window.
    panel,
    /// A verb (KILL, FLAT, ARM…). Running it opens its interlock flow —
    /// typing a code NEVER fires the action directly.
    action,
};

pub const Command = struct {
    /// 2–4 letter function code, uppercase, fixed forever once shipped.
    code: [:0]const u8,
    name: [:0]const u8,
    kind: Kind,
    /// One-line description (palette + HELP).
    desc: [:0]const u8 = "",
    /// Keyboard chord hint, display-only ("F2", "Ctrl+Shift+K", "").
    key_hint: [:0]const u8 = "",
    /// View-menu group ("Market", "Ops", "Research", "Actions").
    menu_group: [:0]const u8 = "Panels",
    run: *const fn (ctx: *anyopaque) void,
    /// Non-null result = disabled, with the human reason shown inline in the
    /// palette/menu (DESIGN.md: disabled commands state WHY).
    disabled_reason: ?*const fn (ctx: *anyopaque) ?[:0]const u8 = null,
};

pub fn isEnabled(cmd: Command, ctx: *anyopaque) bool {
    return disabledReason(cmd, ctx) == null;
}

pub fn disabledReason(cmd: Command, ctx: *anyopaque) ?[:0]const u8 {
    const f = cmd.disabled_reason orelse return null;
    return f(ctx);
}

/// Exact code match, case-insensitive.
pub fn findByCode(cmds: []const Command, code: []const u8) ?*const Command {
    for (cmds) |*c| {
        if (std.ascii.eqlIgnoreCase(c.code, code)) return c;
    }
    return null;
}

/// Case-insensitive subsequence fuzzy score against "CODE name". Higher is
/// better; null = no match. Word-start and code hits weigh extra so "qm"
/// beats incidental letter scatter.
pub fn fuzzyScore(cmd: Command, query: []const u8) ?i32 {
    if (query.len == 0) return 0;
    var hay_buf: [128]u8 = undefined;
    const hay = std.fmt.bufPrint(&hay_buf, "{s} {s}", .{ cmd.code, cmd.name }) catch return null;

    var score: i32 = 0;
    var hi: usize = 0;
    var last_hit: usize = 0;
    for (query) |qc| {
        const q = std.ascii.toLower(qc);
        var found = false;
        while (hi < hay.len) : (hi += 1) {
            if (std.ascii.toLower(hay[hi]) == q) {
                // Adjacent-run + start-of-word + in-code bonuses.
                score += 2;
                if (hi == last_hit + 1) score += 3;
                if (hi == 0 or hay[hi - 1] == ' ') score += 4;
                if (hi < cmd.code.len) score += 5;
                last_hit = hi;
                hi += 1;
                found = true;
                break;
            }
        }
        if (!found) return null;
    }
    // Shorter targets rank higher on equal hits.
    score -= @intCast(@min(hay.len / 8, 8));
    return score;
}

pub const Match = struct { idx: usize, score: i32 };

/// Fill `out` with the best matches for `query`, sorted descending.
/// Returns the slice actually filled.
pub fn fuzzyTop(cmds: []const Command, query: []const u8, out: []Match) []Match {
    var n: usize = 0;
    for (cmds, 0..) |c, i| {
        const s = fuzzyScore(c, query) orelse continue;
        if (n < out.len) {
            out[n] = .{ .idx = i, .score = s };
            n += 1;
        } else {
            // Replace the current minimum if this beats it.
            var min_at: usize = 0;
            for (out[0..n], 0..) |m, j| {
                if (m.score < out[min_at].score) min_at = j;
            }
            if (s > out[min_at].score) out[min_at] = .{ .idx = i, .score = s };
        }
    }
    std.mem.sort(Match, out[0..n], {}, struct {
        fn less(_: void, a: Match, b: Match) bool {
            return a.score > b.score;
        }
    }.less);
    return out[0..n];
}

test "exact + fuzzy lookup" {
    const noop = struct {
        fn run(_: *anyopaque) void {}
    }.run;
    const cmds = [_]Command{
        .{ .code = "QM", .name = "Quote Monitor", .kind = .panel, .run = noop },
        .{ .code = "CH", .name = "Chart", .kind = .panel, .run = noop },
        .{ .code = "KILL", .name = "Kill switch", .kind = .action, .run = noop },
    };
    try std.testing.expect(findByCode(&cmds, "qm") != null);
    try std.testing.expect(findByCode(&cmds, "QM").?.kind == .panel);
    try std.testing.expect(findByCode(&cmds, "ZZ") == null);

    var out: [4]Match = undefined;
    const top = fuzzyTop(&cmds, "ki", &out);
    try std.testing.expect(top.len >= 1);
    try std.testing.expectEqualStrings("KILL", cmds[top[0].idx].code);
}
