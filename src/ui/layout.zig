//! Workspace + docking layout mechanics (DESIGN.md §2.3/§2.4).
//!
//! Five F-key workspaces, each owning its OWN dockspace ID; only the active
//! workspace's dockspace is submitted per frame, and a panel shared by N
//! workspaces is N ImGui windows named `CODE · Name###CODE@WS` over one
//! state struct — so every workspace's dock assignment coexists in ONE ini
//! with no blob-swapping.
//!
//! Persistence is MANUAL and crash-safe: ImGui's own ini writer is disabled
//! (`setIniFilename(null)`); we load `layout.ini` into the context at boot
//! and save via SaveIniSettingsToMemory → `layout.ini.tmp` → atomic
//! MoveFileExW — every 60 s when dirty, on workspace switch, and on exit.
//! Geometry (which window docks where) is built by the caller through
//! `needsBuild`/`markBuilt` using DockBuilder; this module owns ids, the
//! switch/reset/autosave plumbing, and the round-trip selftest.

const std = @import("std");
const zgui = @import("zgui");
const confirm = @import("confirm.zig");

const log = std.log.scoped(.ui_layout);

pub const Workspace = enum(u8) {
    triage,
    hunt,
    detect,
    intel,
    ops,

    pub fn dockspaceId(self: Workspace) [:0]const u8 {
        return switch (self) {
            .triage => "ws_triage",
            .hunt => "ws_hunt",
            .detect => "ws_detect",
            .intel => "ws_intel",
            .ops => "ws_ops",
        };
    }

    /// Suffix used in `###CODE@WS` window identities.
    pub fn tag(self: Workspace) []const u8 {
        return switch (self) {
            .triage => "TRIAGE",
            .hunt => "HUNT",
            .detect => "DETECT",
            .intel => "INTEL",
            .ops => "OPS",
        };
    }

    pub fn label(self: Workspace) [:0]const u8 {
        return switch (self) {
            .triage => "F1 TRIAGE",
            .hunt => "F2 HUNT",
            .detect => "F3 DETECT",
            .intel => "F4 INTEL",
            .ops => "F5 OPS",
        };
    }
};

pub const workspace_count = @typeInfo(Workspace).@"enum".fields.len;

pub var active: Workspace = .triage;

/// Bump when a phase changes preset geometry: stored ini sections for a
/// workspace whose preset version advanced are discarded (rebuild).
pub const preset_version: u32 = 1;

var built: [workspace_count]bool = @splat(false);
var reset_requested: [workspace_count]bool = @splat(false);

/// Wall path of layout.ini (set by `init`); static — ImGui never sees it,
/// only our loader/saver.
var ini_path: [512:0]u8 = undefined;
var ini_path_len: usize = 0;

var last_save_ms: i64 = 0;
var pending_switch_save: bool = false;

/// Harness suppression (--validate/--screenshot): forced workspace cycling
/// and the exit save must never rewrite the user's real layout.ini.
pub var save_suppressed: bool = false;

/// Compose `CODE · Name###CODE@WS` into `buf`. The visible part carries the
/// function code for passive learning; the ### identity keys DockBuilder and
/// the ini, so per-workspace assignments never collide.
pub fn windowName(buf: []u8, code: []const u8, name: []const u8, ws: Workspace) [:0]const u8 {
    return std.fmt.bufPrintZ(buf, "{s} \u{00B7} {s}###{s}@{s}", .{ code, name, code, ws.tag() }) catch blk: {
        buf[0] = 0;
        break :blk buf[0..0 :0];
    };
}

/// Load persisted layout into the (fresh) ImGui context and remember the
/// path for saves. Call once after `zgui.init`, before the first frame.
/// ImGui's own ini handling must already be disabled via setIniFilename(null).
pub fn init(path: []const u8) void {
    if (path.len > ini_path.len - 1) {
        log.warn("layout ini path truncated ({d} > {d} bytes) — persistence disabled", .{ path.len, ini_path.len - 1 });
        ini_path_len = 0;
        return;
    }
    ini_path_len = path.len;
    @memcpy(ini_path[0..ini_path_len], path[0..ini_path_len]);
    ini_path[ini_path_len] = 0;

    const data = readFileAlloc(ini_path[0..ini_path_len :0]) orelse {
        log.info("no layout ini at '{s}' — presets will build fresh", .{path});
        return;
    };
    defer std.heap.page_allocator.free(data);
    zgui.loadIniSettingsFromMemory(data);
    // Loaded settings only apply to windows/dockspaces ImGui sees again, so
    // a node that exists in the ini marks its workspace as built.
    log.info("layout restored from '{s}' ({d} bytes)", .{ path, data.len });
}

/// Submit the active workspace's dockspace filling `size` at the current
/// cursor. Returns the dockspace id for DockBuilder use.
pub fn dockspace(size: [2]f32) zgui.Ident {
    return zgui.dockSpace(active.dockspaceId(), size, .{ .passthru_central_node = false });
}

/// True when the active workspace's dock tree must be (re)built: first run
/// with no persisted node, or an explicit reset.
pub fn needsBuild(id: zgui.Ident) bool {
    const idx = @intFromEnum(active);
    if (reset_requested[idx]) return true;
    if (built[idx]) return false;
    return zgui.dockBuilderGetNode(id) == null;
}

pub fn markBuilt() void {
    const idx = @intFromEnum(active);
    built[idx] = true;
    reset_requested[idx] = false;
}

/// Queue "Reset workspace": the caller's next needsBuild() returns true and
/// must DockBuilderRemoveNode + rebuild the preset.
pub fn requestReset() void {
    reset_requested[@intFromEnum(active)] = true;
}

pub fn consumeResetRequest(id: zgui.Ident) void {
    zgui.dockBuilderRemoveNode(id);
    _ = zgui.dockBuilderAddNode(id, .{ .dock_space = true });
}

pub fn switchTo(ws: Workspace) void {
    if (ws == active) return;
    active = ws;
    pending_switch_save = true;
}

/// Autosave tick: call once per frame with a monotonic clock. Saves when
/// (a) a workspace switch happened, or (b) ImGui flagged dirty settings and
/// 60 s elapsed since the last save.
pub fn tick() void {
    const now = confirm.nowMs();
    const dirty = zgui.io.getWantSaveIniSettings();
    const interval_due = dirty and (now - last_save_ms >= 60_000);
    if (pending_switch_save or interval_due) {
        // saveNow clears pending_switch_save only on SUCCESS — a failed
        // switch-save stays pending and retries after the backoff.
        saveNow();
    }
}

/// Serialize + atomically replace layout.ini. Also call on clean exit.
pub fn saveNow() void {
    if (ini_path_len == 0 or save_suppressed) return;
    const data = zgui.saveIniSettingsToMemory();
    atomicWrite(ini_path[0..ini_path_len :0], data) catch |err| {
        // Keep the dirty state so the next tick retries — clearing it on a
        // failed write (disk full, AV lock) would silently drop the layout.
        log.warn("layout save failed: {s} — will retry", .{@errorName(err)});
        last_save_ms = confirm.nowMs(); // backoff: not before the next interval
        return;
    };
    zgui.io.clearWantSaveIniSettings();
    pending_switch_save = false;
    last_save_ms = confirm.nowMs();
}

// ── File plumbing (libc + kernel32; ui module links into a libc exe) ─────

const cstdio = struct {
    extern fn fopen(path: [*:0]const u8, mode: [*:0]const u8) ?*anyopaque;
    extern fn fread(buf: [*]u8, sz: usize, n: usize, f: *anyopaque) usize;
    extern fn fwrite(buf: [*]const u8, sz: usize, n: usize, f: *anyopaque) usize;
    extern fn fclose(f: *anyopaque) c_int;
    extern fn fseek(f: *anyopaque, off: c_long, origin: c_int) c_int;
    extern fn ftell(f: *anyopaque) c_long;
    extern fn remove(path: [*:0]const u8) c_int;
};
const SEEK_SET: c_int = 0;
const SEEK_END: c_int = 2;

const kernel32 = struct {
    extern "kernel32" fn MoveFileExW(from: [*:0]const u16, to: [*:0]const u16, flags: u32) callconv(.winapi) c_int;
};
const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;

/// Read a whole file via the page allocator; null when absent/unreadable.
fn readFileAlloc(path: [:0]const u8) ?[]u8 {
    const f = cstdio.fopen(path.ptr, "rb") orelse return null;
    defer _ = cstdio.fclose(f);
    if (cstdio.fseek(f, 0, SEEK_END) != 0) return null;
    const len = cstdio.ftell(f);
    if (len <= 0) return null;
    if (cstdio.fseek(f, 0, SEEK_SET) != 0) return null;
    const buf = std.heap.page_allocator.alloc(u8, @intCast(len)) catch return null;
    const got = cstdio.fread(buf.ptr, 1, buf.len, f);
    if (got != buf.len) {
        std.heap.page_allocator.free(buf);
        return null;
    }
    return buf;
}

pub const WriteError = error{ OpenFailed, WriteFailed, RenameFailed, PathTooLong };

/// Write `data` to `<path>.tmp`, then atomically rename over `path`.
/// Public: ui_state.json persistence reuses it. Process-crash safe; not
/// power-loss durable (no FlushFileBuffers — these are convenience files).
pub fn atomicWrite(path: [:0]const u8, data: []const u8) WriteError!void {
    var tmp_buf: [560:0]u8 = undefined;
    const tmp = std.fmt.bufPrintZ(&tmp_buf, "{s}.tmp", .{path}) catch return WriteError.PathTooLong;

    const f = cstdio.fopen(tmp.ptr, "wb") orelse return WriteError.OpenFailed;
    const written = cstdio.fwrite(data.ptr, 1, data.len, f);
    const close_rc = cstdio.fclose(f);
    if (written != data.len or close_rc != 0) {
        _ = cstdio.remove(tmp.ptr); // don't leave a partial .tmp behind
        return WriteError.WriteFailed;
    }

    var from_w: [560:0]u16 = undefined;
    var to_w: [560:0]u16 = undefined;
    const fl = std.unicode.utf8ToUtf16Le(&from_w, tmp) catch return WriteError.PathTooLong;
    from_w[fl] = 0;
    const tl = std.unicode.utf8ToUtf16Le(&to_w, path) catch return WriteError.PathTooLong;
    to_w[tl] = 0;
    if (kernel32.MoveFileExW(from_w[0..fl :0], to_w[0..tl :0], MOVEFILE_REPLACE_EXISTING) == 0) {
        return WriteError.RenameFailed;
    }
}

// ── Round-trip selftest (gates Phase 2; DESIGN.md §2.4 #5) ───────────────

/// Headless layout round-trip inside an EXISTING zgui context (caller inits
/// zgui with docking enabled and tears it down): build a two-way split with
/// two windows, pump a frame so ImGui records assignments, save to memory,
/// reload into the wiped settings state, pump the same frame (a dock node's
/// host-window link only re-binds on submission — exactly the boot path),
/// save again, assert byte-equality.
pub fn selfTest() !void {
    // Build the dockspace + split + two docked windows, then settle: dock
    // geometry propagates to the windows on the SECOND frame (Pos/Size,
    // tab-order DockId suffix, node Selected=) — saving earlier would
    // compare a half-applied layout against the settled reload.
    var id: zgui.Ident = 0;
    for (0..3) |_| id = selfTestFrame();

    const first = zgui.saveIniSettingsToMemory();
    if (first.len == 0) return error.EmptySave;
    // Own a copy — the next save reuses ImGui's internal buffer.
    const snapshot = std.heap.page_allocator.dupe(u8, first) catch return error.OutOfMemory;
    defer std.heap.page_allocator.free(snapshot);
    if (std.mem.indexOf(u8, snapshot, "ST_A@TEST") == null) return error.WindowMissingFromIni;
    // Dock nodes serialize by hex id, never by str_id ("DockSpace ID=0x%08X").
    var id_buf: [16]u8 = undefined;
    const id_hex = std.fmt.bufPrint(&id_buf, "ID=0x{X:0>8}", .{id}) catch unreachable;
    if (std.mem.indexOf(u8, snapshot, id_hex) == null) return error.DockspaceMissingFromIni;

    // Reload the snapshot, re-submit + settle the same frames (restoring
    // from settings the way a real boot does), save again — must round-trip
    // byte-equal.
    zgui.loadIniSettingsFromMemory(snapshot);
    for (0..3) |_| _ = selfTestFrame();
    const second = zgui.saveIniSettingsToMemory();
    if (!std.mem.eql(u8, snapshot, second)) return error.RoundTripMismatch;
}

/// One selftest frame: submit the dockspace (building the preset split only
/// when no node exists — second pass restores it from settings, and ImGui
/// asserts on re-splitting a split node) + the two docked windows. Returns
/// the dockspace id.
fn selfTestFrame() zgui.Ident {
    zgui.io.setDisplaySize(1400, 900);
    zgui.io.setDeltaTime(1.0 / 60.0);
    zgui.newFrame();

    // Probe BEFORE dockSpace creates the node — same window ID stack, so
    // getStrId == DockSpace's GetID (mirrors the dashboard's needsBuild).
    const needs_build = zgui.dockBuilderGetNode(zgui.getStrId("ws_selftest")) == null;
    const id = zgui.dockSpace("ws_selftest", .{ 1200, 800 }, .{});
    if (needs_build) {
        zgui.dockBuilderSetNodeSize(id, .{ 1200, 800 });
        var left: zgui.Ident = 0;
        var right: zgui.Ident = 0;
        _ = zgui.dockBuilderSplitNode(id, .left, 0.31, &left, &right);
        zgui.dockBuilderDockWindow("st_a###ST_A@TEST", left);
        zgui.dockBuilderDockWindow("st_b###ST_B@TEST", right);
        zgui.dockBuilderFinish(id);
    }

    inline for (.{ "st_a###ST_A@TEST", "st_b###ST_B@TEST" }) |name| {
        if (zgui.begin(name, .{})) {
            zgui.text("selftest", .{});
        }
        zgui.end();
    }
    zgui.endFrame();
    zgui.render();
    return id;
}
