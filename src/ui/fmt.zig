//! Canonical numeric/time formatting for the GUI (DESIGN.md §3.2).
//!
//! Rules: right-align every quantitative column; fixed decimals per column
//! with trailing zeros; thousands separators on ≥4-digit integers; explicit
//! sign on every delta using U+2212 MINUS SIGN; timestamps HH:MM:SS UTC.
//! All writers take caller buffers — zero allocation on the render path.

const std = @import("std");
const zgui = @import("zgui");

/// U+2212 MINUS SIGN — typographically matches the digits in Geist Mono,
/// unlike ASCII hyphen-minus.
pub const minus = "\u{2212}";

/// Fixed-decimal value, trailing zeros kept: `fixed(buf, 0.05, 5)` → "0.05000".
pub fn fixed(buf: []u8, value: f64, decimals: u8) [:0]const u8 {
    return std.fmt.bufPrintZ(buf, "{d:.[1]}", .{ value, decimals }) catch unreachable_short(buf);
}

/// Fixed-decimal with thousands separators in the integer part:
/// `thousands(buf, 12482.1, 2)` → "12,482.10".
pub fn thousands(buf: []u8, value: f64, decimals: u8) [:0]const u8 {
    if (buf.len == 0) return unreachable_short(buf);
    var tmp: [64]u8 = undefined;
    const plain = std.fmt.bufPrint(&tmp, "{d:.[1]}", .{ @abs(value), decimals }) catch return unreachable_short(buf);
    const dot = std.mem.indexOfScalar(u8, plain, '.') orelse plain.len;

    var w: usize = 0;
    // Sign only when the ROUNDED magnitude is nonzero — avoids "−0.00".
    const shows_nonzero = blk: {
        for (plain) |c| {
            if (c >= '1' and c <= '9') break :blk true;
        }
        break :blk false;
    };
    if (value < 0 and shows_nonzero) {
        // U+2212 is 3 bytes.
        if (w + minus.len > buf.len - 1) return unreachable_short(buf);
        @memcpy(buf[w .. w + minus.len], minus);
        w += minus.len;
    }
    var i: usize = 0;
    while (i < dot) : (i += 1) {
        if (i != 0 and (dot - i) % 3 == 0) {
            if (w >= buf.len - 1) return unreachable_short(buf);
            buf[w] = ',';
            w += 1;
        }
        if (w >= buf.len - 1) return unreachable_short(buf);
        buf[w] = plain[i];
        w += 1;
    }
    const rest = plain[dot..];
    if (w + rest.len > buf.len - 1) return unreachable_short(buf);
    @memcpy(buf[w .. w + rest.len], rest);
    w += rest.len;
    buf[w] = 0;
    return buf[0..w :0];
}

/// Signed delta: `signed(buf, 1.24, 2, "%")` → "+1.24%", negative uses U+2212.
pub fn signed(buf: []u8, value: f64, decimals: u8, suffix: []const u8) [:0]const u8 {
    if (buf.len == 0) return unreachable_short(buf);
    const sign: []const u8 = if (value < 0) minus else "+";
    return std.fmt.bufPrintZ(buf, "{[0]s}{[1]d:.[2]}{[3]s}", .{ sign, @abs(value), decimals, suffix }) catch unreachable_short(buf);
}

/// Signed dollar delta with thousands separators: "+$1,234.56" / "−$18.20".
pub fn signedUsd(buf: []u8, value: f64) [:0]const u8 {
    if (buf.len == 0) return unreachable_short(buf);
    var tmp: [48]u8 = undefined;
    const mag = thousands(&tmp, @abs(value), 2);
    const sign: []const u8 = if (value < 0) minus else "+";
    return std.fmt.bufPrintZ(buf, "{s}${s}", .{ sign, mag }) catch unreachable_short(buf);
}

/// Abbreviated volume: 12_400_000 → "12.4M"; below 10k prints plain.
/// Negative values carry the U+2212 sign like every other delta.
pub fn abbrev(buf: []u8, value: f64) [:0]const u8 {
    const v = @abs(value);
    const sign: []const u8 = if (value < 0) minus else "";
    if (v >= 1e9) return std.fmt.bufPrintZ(buf, "{s}{d:.1}B", .{ sign, v / 1e9 }) catch unreachable_short(buf);
    if (v >= 1e6) return std.fmt.bufPrintZ(buf, "{s}{d:.1}M", .{ sign, v / 1e6 }) catch unreachable_short(buf);
    if (v >= 1e4) return std.fmt.bufPrintZ(buf, "{s}{d:.1}k", .{ sign, v / 1e3 }) catch unreachable_short(buf);
    return std.fmt.bufPrintZ(buf, "{s}{d:.0}", .{ sign, v }) catch unreachable_short(buf);
}

// ── Timestamp style (SET preference) ─────────────────────────────────────
// Data timestamps render through ts()/tsDate() honoring the analyst's
// choice; panel headers print tsSuffix() once so the frame of reference is
// always visible (SOC convention: UTC default, cross-tz IR needs it).

pub const TimeStyle = enum(u8) {
    utc,
    local,
    relative,

    pub fn label(self: TimeStyle) [:0]const u8 {
        return switch (self) {
            .utc => "UTC (SOC standard)",
            .local => "Local time",
            .relative => "Relative (3m ago)",
        };
    }
};

pub var time_style: TimeStyle = .utc;
/// Local UTC offset in minutes (set once at boot from the OS).
pub var local_offset_min: i32 = 0;
/// Wall-clock "now" (unix secs) — dashboard sets it once per frame so
/// relative timestamps don't each read the OS clock.
pub var now_ts: i64 = 0;

/// Data timestamp in the analyst's chosen style: HH:MM:SS (UTC or local)
/// or a compact age ("4m"). THE way panel time columns render.
pub fn ts(buf: []u8, wall_ts: i64) [:0]const u8 {
    return switch (time_style) {
        .utc => clock(buf, wall_ts),
        .local => clock(buf, wall_ts + @as(i64, local_offset_min) * 60),
        .relative => age(buf, now_ts - wall_ts),
    };
}

/// Date+time variant (MM-DD HH:MM in the chosen zone; relative style still
/// prints an age — dates read poorly as ages beyond a day anyway).
pub fn tsDate(buf: []u8, wall_ts: i64) [:0]const u8 {
    return switch (time_style) {
        .utc => dateTime(buf, wall_ts),
        .local => dateTime(buf, wall_ts + @as(i64, local_offset_min) * 60),
        .relative => age(buf, now_ts - wall_ts),
    };
}

/// Frame-of-reference marker for panel headers ("UTC" · "local" · "age").
pub fn tsSuffix() [:0]const u8 {
    return switch (time_style) {
        .utc => "UTC",
        .local => "local",
        .relative => "age",
    };
}

/// Time-column header carrying the frame of reference — a bare "Time"
/// column over local/relative timestamps reads as UTC in an IR report.
pub fn tsColHeader() [:0]const u8 {
    return switch (time_style) {
        .utc => "Time UTC",
        .local => "Time local",
        .relative => "Age",
    };
}

/// Absolute wall clock + zone label for chrome (top strip, footer).
/// Relative style keeps UTC — a live clock can't be an age. THE single
/// place the chrome clock derives from, so strip and footer can't skew.
pub fn wallClock(buf: []u8, now_secs: i64) [:0]const u8 {
    const local = time_style == .local;
    const shifted = if (local) now_secs + @as(i64, local_offset_min) * 60 else now_secs;
    var cb: [16]u8 = undefined;
    return std.fmt.bufPrintZ(buf, "{s} {s}", .{
        clock(&cb, shifted),
        if (local) "local" else "UTC",
    }) catch unreachable_short(buf);
}

/// HH:MM:SS from a Unix timestamp (UTC). One "UTC" marker per panel header,
/// not per cell (§3.2).
pub fn clock(buf: []u8, ts_secs: i64) [:0]const u8 {
    const secs_in_day: i64 = 86_400;
    // @mod with a positive divisor is already non-negative.
    const s = @mod(ts_secs, secs_in_day);
    const h: u32 = @intCast(@divFloor(s, 3600));
    const m: u32 = @intCast(@mod(@divFloor(s, 60), 60));
    const sec: u32 = @intCast(@mod(s, 60));
    return std.fmt.bufPrintZ(buf, "{d:0>2}:{d:0>2}:{d:0>2}", .{ h, m, sec }) catch unreachable_short(buf);
}

/// MM-DD HH:MM from a Unix timestamp (UTC).
pub fn dateTime(buf: []u8, ts_secs: i64) [:0]const u8 {
    const epoch = std.time.epoch.EpochSeconds{ .secs = @intCast(@max(ts_secs, 0)) };
    const day = epoch.getEpochDay().calculateYearDay();
    const md = day.calculateMonthDay();
    const ds = epoch.getDaySeconds();
    return std.fmt.bufPrintZ(buf, "{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}", .{
        md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(),
    }) catch unreachable_short(buf);
}

/// Compact age: 12s · 4m · 2.1h · 3d.
pub fn age(buf: []u8, age_secs: i64) [:0]const u8 {
    const a = @max(age_secs, 0);
    if (a < 60) return std.fmt.bufPrintZ(buf, "{d}s", .{a}) catch unreachable_short(buf);
    if (a < 3600) return std.fmt.bufPrintZ(buf, "{d}m", .{@divFloor(a, 60)}) catch unreachable_short(buf);
    if (a < 86_400) return std.fmt.bufPrintZ(buf, "{d:.1}h", .{@as(f64, @floatFromInt(a)) / 3600.0}) catch unreachable_short(buf);
    return std.fmt.bufPrintZ(buf, "{d}d", .{@divFloor(a, 86_400)}) catch unreachable_short(buf);
}

/// Place the cursor so `text` ends at the right edge of the current
/// column/region, then draw it. THE way quantitative cells render (§3.2).
pub fn rightAlignedText(text: []const u8) void {
    shiftRight(text);
    zgui.textUnformatted(text);
}

/// Right-aligned colored variant.
pub fn rightAlignedTextColored(color: [4]f32, text: []const u8) void {
    shiftRight(text);
    zgui.textUnformattedColored(color, text);
}

fn shiftRight(text: []const u8) void {
    const w = zgui.calcTextSize(text, .{})[0];
    const avail = zgui.getContentRegionAvail()[0];
    if (avail > w) {
        zgui.setCursorPosX(zgui.getCursorPosX() + avail - w);
    }
}

/// Truncated-buffer fallback — formatting into an undersized buffer is a
/// programmer error; render an empty cell rather than crash the frame.
fn unreachable_short(buf: []u8) [:0]const u8 {
    if (buf.len == 0) return "";
    buf[0] = 0;
    return buf[0..0 :0];
}

test "thousands separators + U+2212" {
    var buf: [48]u8 = undefined;
    try std.testing.expectEqualStrings("12,482.10", thousands(&buf, 12482.1, 2));
    try std.testing.expectEqualStrings("999", thousands(&buf, 999, 0));
    try std.testing.expectEqualStrings("1,000", thousands(&buf, 1000, 0));
    try std.testing.expectEqualStrings("\u{2212}1,234.50", thousands(&buf, -1234.5, 2));
    // Sign suppressed when the rounded magnitude is zero.
    try std.testing.expectEqualStrings("0.00", thousands(&buf, -0.001, 2));
    try std.testing.expectEqualStrings("0.00", thousands(&buf, -0.0, 2));
    // NaN/inf from DB metrics must not crash or garble grouping.
    try std.testing.expectEqualStrings("nan", thousands(&buf, std.math.nan(f64), 2));
    var tiny: [0]u8 = .{};
    try std.testing.expectEqualStrings("", thousands(&tiny, 1.0, 2));
}

test "signed deltas" {
    var buf: [48]u8 = undefined;
    try std.testing.expectEqualStrings("+1.24%", signed(&buf, 1.24, 2, "%"));
    try std.testing.expectEqualStrings("\u{2212}0.87%", signed(&buf, -0.87, 2, "%"));
    try std.testing.expectEqualStrings("+$1,234.56", signedUsd(&buf, 1234.56));
    try std.testing.expectEqualStrings("\u{2212}$18.20", signedUsd(&buf, -18.2));
}

test "fixed keeps trailing zeros" {
    var buf: [48]u8 = undefined;
    try std.testing.expectEqualStrings("0.05000", fixed(&buf, 0.05, 5));
}

test "ts honors time style" {
    var buf: [48]u8 = undefined;
    const t: i64 = 1_749_479_525; // 14:32:05 UTC
    time_style = .utc;
    try std.testing.expectEqualStrings("14:32:05", ts(&buf, t));
    try std.testing.expectEqualStrings("UTC", tsSuffix());
    time_style = .local;
    local_offset_min = -300; // UTC-5
    try std.testing.expectEqualStrings("09:32:05", ts(&buf, t));
    time_style = .relative;
    now_ts = t + 245;
    try std.testing.expectEqualStrings("4m", ts(&buf, t));
    time_style = .utc;
    local_offset_min = 0;
}

test "clock and age" {
    var buf: [48]u8 = undefined;
    try std.testing.expectEqualStrings("14:32:05", clock(&buf, 1_749_479_525));
    try std.testing.expectEqualStrings("12s", age(&buf, 12));
    try std.testing.expectEqualStrings("4m", age(&buf, 245));
    try std.testing.expectEqualStrings("2.1h", age(&buf, 7560));
}

test "abbrev" {
    var buf: [48]u8 = undefined;
    try std.testing.expectEqualStrings("12.4M", abbrev(&buf, 12_400_000));
    try std.testing.expectEqualStrings("950", abbrev(&buf, 950));
}
