//! Font loading (DESIGN.md §3.2): Geist Mono is THE data font (default —
//! numerics, tables, footer, command line; mono = the tabular-figures
//! strategy), Geist Sans is prose (tooltips, modals, empty states), and
//! Font Awesome 6 solid is merged into both for status/icon glyphs
//! (replaces hand-drawn badges and the `✕ ⚠ ▶ ≥` mojibake).
//!
//! ImGui 1.92 dynamic fonts: each face is added once at its base size and
//! rendered at any size via `zgui.pushFont(font, size)`; glyphs (including
//! the FA range) rasterize lazily into the atlas, which the Vulkan backend
//! re-uploads via processTextureUpdates().

const std = @import("std");
const zgui = @import("zgui");

const log = std.log.scoped(.ui_fonts);

/// Type scale (px @ 96 dpi) — DESIGN.md §3.2.
pub const size = struct {
    pub const micro: f32 = 14; // axis labels, age chips, footer
    pub const label: f32 = 15; // table headers (ALL-CAPS)
    pub const body: f32 = 17; // table cells, command line, all data
    pub const title: f32 = 17; // panel headers
    pub const hero: f32 = 24; // SUM/POS/TKT hero numbers only
    pub const prose: f32 = 17; // Geist Sans tooltips/help/modals
};

/// Data font (Geist Mono) — the io default; most code never pushes a font.
pub var mono: zgui.Font = undefined;
/// Medium-weight mono for emphasis (large prints, panel titles).
pub var mono_medium: zgui.Font = undefined;
/// Prose font (Geist Sans).
pub var sans: zgui.Font = undefined;

var loaded: bool = false;
/// Directory that resolved to real font files ("" until load()).
var fonts_dir: [260:0]u8 = undefined;
var fonts_dir_len: usize = 0;

const cstdio = struct {
    extern fn fopen(path: [*:0]const u8, mode: [*:0]const u8) ?*anyopaque;
    extern fn fclose(f: *anyopaque) c_int;
};

const kernel32 = struct {
    extern "kernel32" fn GetModuleFileNameW(module: ?*anyopaque, out: [*]u16, cap: u32) callconv(.winapi) u32;
};

fn fileExists(path: [:0]const u8) bool {
    const f = cstdio.fopen(path.ptr, "rb") orelse return false;
    _ = cstdio.fclose(f);
    return true;
}

/// Locate assets/fonts by probing: cwd (normal `zig build run` from repo
/// root), then exe-dir, then exe-dir/../.. (zig-out/bin -> repo root). The
/// old embedded-default font could never fail; file-backed fonts must not
/// turn a wrong cwd into a startup crash.
fn resolveFontsDir() bool {
    if (probeDir("assets/fonts")) return true;

    var wbuf: [260]u16 = undefined;
    const n = kernel32.GetModuleFileNameW(null, &wbuf, wbuf.len);
    if (n > 0 and n < wbuf.len) {
        var utf8: [780]u8 = undefined;
        if (std.unicode.utf16LeToUtf8(&utf8, wbuf[0..n])) |len| {
            const exe_path = utf8[0..len];
            if (std.fs.path.dirname(exe_path)) |exe_dir| {
                var p: [512]u8 = undefined;
                if (std.fmt.bufPrint(&p, "{s}/assets/fonts", .{exe_dir})) |d| {
                    if (probeDir(d)) return true;
                } else |_| {}
                if (std.fmt.bufPrint(&p, "{s}/../../assets/fonts", .{exe_dir})) |d| {
                    if (probeDir(d)) return true;
                } else |_| {}
            }
        } else |_| {}
    }
    return false;
}

fn probeDir(dir: []const u8) bool {
    var p: [512]u8 = undefined;
    const probe = std.fmt.bufPrintZ(&p, "{s}/GeistMono-Regular.ttf", .{dir}) catch return false;
    if (!fileExists(probe)) return false;
    if (dir.len >= fonts_dir.len) return false;
    @memcpy(fonts_dir[0..dir.len], dir);
    fonts_dir[dir.len] = 0;
    fonts_dir_len = dir.len;
    return true;
}

fn fontPath(buf: []u8, name: []const u8) ?[:0]const u8 {
    return std.fmt.bufPrintZ(buf, "{s}/{s}", .{ fonts_dir[0..fonts_dir_len], name }) catch null;
}

/// Call once after `zgui.init` and before the first frame. The first font
/// added becomes ImGui's default. Missing font files degrade to the
/// embedded ProggyClean default with a logged warning — never a crash.
pub fn load() void {
    if (loaded) return;
    loaded = true;

    if (!resolveFontsDir()) {
        log.warn("assets/fonts not found near cwd or exe — falling back to the embedded default font", .{});
        const d = zgui.io.addFontDefault(null);
        mono = d;
        mono_medium = d;
        sans = d;
        return;
    }

    var p: [512]u8 = undefined;
    mono = addFont(&p, "GeistMono-Regular.ttf", size.body);
    mergeIcons(&p);

    mono_medium = addFont(&p, "GeistMono-Medium.ttf", size.body);
    mergeIcons(&p);

    sans = addFont(&p, "Geist-Regular.ttf", size.prose);
    mergeIcons(&p);
}

/// Drop the cached handles + latch. Call when the zgui context is destroyed
/// (e.g. the selftest's short-lived context) so a later context re-loads
/// instead of dereferencing dead ImFont pointers.
pub fn reset() void {
    loaded = false;
    fonts_dir_len = 0;
}

fn addFont(p: []u8, name: []const u8, px: f32) zgui.Font {
    if (fontPath(p, name)) |path| {
        if (fileExists(path)) return zgui.io.addFontFromFile(path, px);
    }
    log.warn("font '{s}' missing — using embedded default", .{name});
    return zgui.io.addFontDefault(null);
}

/// Merge Font Awesome into the most recently added font so icon glyphs
/// resolve in any font context.
fn mergeIcons(p: []u8) void {
    const path = fontPath(p, "fa-solid-900.ttf") orelse return;
    if (!fileExists(path)) return;
    var cfg = zgui.FontConfig.init();
    cfg.merge_mode = true;
    cfg.pixel_snap_h = true;
    cfg.glyph_min_advance_x = size.body; // monospace-align the icons
    _ = zgui.io.addFontFromFileWithConfig(path, size.body, cfg, null);
}

// Font Awesome 6 solid codepoints used by the UI (keep in sync with usage;
// FA unicode reference: fontawesome.com/icons → "unicode").
pub const fa = struct {
    pub const circle = "\u{f111}"; // status LED
    pub const triangle_exclamation = "\u{f071}"; // ⚠ warning
    pub const circle_info = "\u{f05a}"; // ⓘ help badge
    pub const xmark = "\u{f00d}"; // ✕ close/cancel
    pub const check = "\u{f00c}"; // ack / ok
    pub const play = "\u{f04b}"; // ▶ running
    pub const stop = "\u{f04d}"; // ■ stop
    pub const power_off = "\u{f011}"; // KILL
    pub const link = "\u{f0c1}"; // linked to global context
    pub const thumbtack = "\u{f08d}"; // pinned
    pub const gear = "\u{f013}"; // settings
    pub const bell = "\u{f0f3}"; // alerts
    pub const clock_rotate = "\u{f1da}"; // history / restore
    pub const arrows_rotate = "\u{f021}"; // jobs / refresh
    pub const umbrella = "\u{f0e9}"; // regime de-risk chip
    pub const caret_right = "\u{f0da}"; // ▸ row-actions popup
    pub const magnifying_glass = "\u{f002}"; // search / filter
};
