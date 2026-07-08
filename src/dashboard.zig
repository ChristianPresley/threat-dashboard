//! Dashboard orchestrator: panel registry, 5 F-key workspaces, dock
//! presets, hotkeys, command line + palette, toasts/banner, footer, and
//! ui_state.json persistence. Panel bodies live in src/panels/.
//!
//! Ported mechanics from the trading dashboard: per-workspace dockspaces
//! with DockBuilder presets (rebuilt on first boot / RESET), window naming
//! `CODE · Name###CODE@WS`, per-panel tab hues snapshotted at begin(),
//! force-open + one-shot focus requests, and the --validate/--screenshot
//! forced-workspace cycle.

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const domain = @import("domain");
const data = @import("data");

pub const attack = domain.attack;
const panels_mod = @import("panels/panels.zig");

const Allocator = std.mem.Allocator;

const TOP_STRIP_H: f32 = 28;
const FOOTER_H: f32 = 26;

/// FA "bars" glyph (☰) for the View menu button.
const fa_bars = "\u{f0c9}";

// ===== Panel registry ====================================================

pub const Panel = struct {
    code: [:0]const u8,
    name: [:0]const u8,
    /// Identity-hue group + View-menu header.
    group: [:0]const u8,
};

pub const panels = [_]Panel{
    .{ .code = "PST", .name = "Posture Summary", .group = "Triage" },
    .{ .code = "ALQ", .name = "Alert Queue", .group = "Triage" },
    .{ .code = "CAS", .name = "Cases", .group = "Triage" },
    .{ .code = "TLN", .name = "Timeline", .group = "Hunt" },
    .{ .code = "EVT", .name = "Event Search", .group = "Hunt" },
    .{ .code = "PRC", .name = "Process Tree", .group = "Hunt" },
    .{ .code = "NET", .name = "Network Connections", .group = "Hunt" },
    .{ .code = "RUL", .name = "Detection Rules", .group = "Detect" },
    .{ .code = "TUN", .name = "Rule Tuning", .group = "Detect" },
    .{ .code = "ATK", .name = "ATT&CK Matrix", .group = "Detect" },
    .{ .code = "IOC", .name = "IOC List", .group = "Intel" },
    .{ .code = "TA", .name = "Threat Actors", .group = "Intel" },
    .{ .code = "FEED", .name = "Intel Feeds", .group = "Intel" },
    .{ .code = "SEN", .name = "Sensor Health", .group = "Ops" },
    .{ .code = "ING", .name = "Ingestion Stats", .group = "Ops" },
    .{ .code = "LOG", .name = "Event Log", .group = "Ops" },
    .{ .code = "JOB", .name = "Jobs", .group = "Ops" },
    .{ .code = "SET", .name = "Settings", .group = "Ops" },
    .{ .code = "HELP", .name = "Directory", .group = "Ops" },
    .{ .code = "YAR", .name = "YARA Rules", .group = "Detect" },
    .{ .code = "ENR", .name = "IOC Enrichment", .group = "Intel" },
};

pub const PANEL_PST: usize = 0;
pub const PANEL_ALQ: usize = 1;
pub const PANEL_CAS: usize = 2;
pub const PANEL_TLN: usize = 3;
pub const PANEL_EVT: usize = 4;
pub const PANEL_PRC: usize = 5;
pub const PANEL_NET: usize = 6;
pub const PANEL_RUL: usize = 7;
pub const PANEL_TUN: usize = 8;
pub const PANEL_ATK: usize = 9;
pub const PANEL_IOC: usize = 10;
pub const PANEL_TA: usize = 11;
pub const PANEL_FEED: usize = 12;
pub const PANEL_SEN: usize = 13;
pub const PANEL_ING: usize = 14;
pub const PANEL_LOG: usize = 15;
pub const PANEL_JOB: usize = 16;
pub const PANEL_SET: usize = 17;
pub const PANEL_HELP: usize = 18;
pub const PANEL_YAR: usize = 19;
pub const PANEL_ENR: usize = 20;

/// Workspace membership: only members of the ACTIVE workspace are
/// submitted (plus force-opens). SET and HELP are in no preset — they
/// open by code/hotkey and float.
pub fn panelInWorkspace(idx: usize, ws: ui.layout.Workspace) bool {
    return switch (ws) {
        .triage => idx == PANEL_PST or idx == PANEL_ALQ or idx == PANEL_CAS or
            idx == PANEL_TLN or idx == PANEL_SEN or idx == PANEL_LOG or
            idx == PANEL_JOB,
        .hunt => idx == PANEL_EVT or idx == PANEL_TLN or idx == PANEL_PRC or
            idx == PANEL_NET or idx == PANEL_IOC or idx == PANEL_LOG or
            idx == PANEL_JOB,
        .detect => idx == PANEL_RUL or idx == PANEL_ATK or idx == PANEL_TUN or
            idx == PANEL_ALQ or idx == PANEL_LOG or idx == PANEL_YAR,
        .intel => idx == PANEL_FEED or idx == PANEL_IOC or idx == PANEL_TA or
            idx == PANEL_CAS or idx == PANEL_LOG or idx == PANEL_ENR,
        .ops => idx == PANEL_SEN or idx == PANEL_ING or idx == PANEL_JOB or
            idx == PANEL_ALQ or idx == PANEL_LOG,
    };
}

/// Wayfinding hue for a panel group (theme identity family — never state).
pub fn groupIdentity(group: []const u8) [4]f32 {
    const id = ui.theme.active.identity;
    if (std.mem.eql(u8, group, "Triage")) return id.triage;
    if (std.mem.eql(u8, group, "Hunt")) return id.hunt;
    if (std.mem.eql(u8, group, "Detect")) return id.detect;
    if (std.mem.eql(u8, group, "Intel")) return id.intel;
    return id.ops;
}

/// Identity hue for a panel CODE; null for non-panel codes.
fn codeIdentity(code: []const u8) ?[4]f32 {
    for (&panels) |*p| {
        if (std.ascii.eqlIgnoreCase(p.code, code)) return groupIdentity(p.group);
    }
    return null;
}

/// Number of style colors pushPanelTabColors pushes (pop count).
const panel_tab_color_count = 7;

/// Per-panel docked-tab colors. Pushed across `begin()` ONLY: docking
/// snapshots these slots into the window's DockStyle inside Begin, so each
/// tab keeps its family hue in any shared tab bar — popping right after
/// begin keeps the panel CONTENT on the global style.
fn pushPanelTabColors(idx: usize) void {
    const t = &ui.theme.active;
    const hue = groupIdentity(panels[idx].group);
    const mix = ui.theme.mix;
    zgui.pushStyleColor4f(.{ .idx = .tab, .c = mix(t.bg.elev, hue, 0.15) });
    zgui.pushStyleColor4f(.{ .idx = .tab_hovered, .c = mix(t.bg.hover, hue, 0.45) });
    zgui.pushStyleColor4f(.{ .idx = .tab_selected, .c = mix(t.bg.hover, hue, 0.35) });
    zgui.pushStyleColor4f(.{ .idx = .tab_selected_overline, .c = hue });
    zgui.pushStyleColor4f(.{ .idx = .tab_dimmed, .c = mix(t.bg.panel, hue, 0.12) });
    zgui.pushStyleColor4f(.{ .idx = .tab_dimmed_selected, .c = mix(t.bg.elev, hue, 0.30) });
    zgui.pushStyleColor4f(.{ .idx = .tab_dimmed_selected_overline, .c = ui.theme.withAlpha(hue, 0.65) });
}

/// 3 px group-colored bar on the panel's left edge.
fn drawPanelIdentityBar(idx: usize) void {
    const wp = zgui.getWindowPos();
    const wsz = zgui.getWindowSize();
    zgui.getWindowDrawList().addRectFilled(.{
        .pmin = .{ wp[0], wp[1] },
        .pmax = .{ wp[0] + 3, wp[1] + wsz[1] },
        .col = zgui.colorConvertFloat4ToU32(groupIdentity(panels[idx].group)),
    });
}

/// `CODE · Name###CODE@WS` for panel `idx` in workspace `ws`.
pub fn panelWindowName(buf: []u8, idx: usize, ws: ui.layout.Workspace) [:0]const u8 {
    return ui.layout.windowName(buf, panels[idx].code, panels[idx].name, ws);
}

// ===== Shared color helpers (panels import these) ========================

/// Domain severity → theme color.
pub fn sevColor(sev: domain.Severity) [4]f32 {
    const t = ui.theme.default.sev;
    return switch (sev) {
        .info => t.info,
        .low => t.ok,
        .medium => t.warn,
        .high => t.serious,
        .critical => t.crit,
    };
}

pub fn sevDimColor(sev: domain.Severity) [4]f32 {
    const t = ui.theme.default.sev;
    return switch (sev) {
        .info => t.info_dim,
        .low => t.ok_dim,
        .medium => t.warn_dim,
        .high => t.serious_dim,
        .critical => t.crit_dim,
    };
}

/// Event-spine severity → theme color (LOG/toasts).
pub fn evSevColor(sev: ui.events.Severity) [4]f32 {
    const t = ui.theme.default.sev;
    return switch (sev) {
        .ok => t.ok,
        .info => t.info,
        .warn => t.warn,
        .serious => t.serious,
        .crit => t.crit,
    };
}

pub fn sensorStatusColor(s: domain.SensorStatus) [4]f32 {
    const t = ui.theme.default.sev;
    return switch (s) {
        .ok => t.ok,
        .degraded => t.warn,
        .down => t.crit,
    };
}

/// YARA quality grade ('A'..'F') → theme score band.
pub fn gradeColor(g: u8) [4]f32 {
    const t = ui.theme.default.score;
    return switch (g) {
        'A' => t.a,
        'B' => t.b,
        'C' => t.c,
        'D' => t.d,
        else => t.f,
    };
}

/// Enrichment verdict → severity family (state, not identity).
pub fn verdictColor(v: domain.Verdict) [4]f32 {
    const t = ui.theme.default;
    return switch (v) {
        .malicious => t.sev.crit,
        .suspicious => t.sev.warn,
        .clean => t.sev.ok,
        .unknown => t.text.lo,
    };
}

pub fn gateColor(pass: bool) [4]f32 {
    const t = ui.theme.default.sev;
    return if (pass) t.ok else t.crit;
}

/// Toggleable filter chip: filled when on, outlined when off.
pub fn filterChip(label: [:0]const u8, on: bool, hue: [4]f32) bool {
    const t = ui.theme.default;
    const fill = if (on) ui.theme.mix(t.bg.elev, hue, 0.35) else t.bg.panel;
    const txt = if (on) t.text.hi else t.text.lo;
    zgui.pushStyleColor4f(.{ .idx = .button, .c = fill });
    zgui.pushStyleColor4f(.{ .idx = .button_hovered, .c = ui.theme.mix(t.bg.hover, hue, 0.3) });
    zgui.pushStyleColor4f(.{ .idx = .button_active, .c = ui.theme.mix(t.bg.hover, hue, 0.5) });
    zgui.pushStyleColor4f(.{ .idx = .text, .c = txt });
    defer zgui.popStyleColor(.{ .count = 4 });
    return zgui.smallButton(label);
}

pub fn textWrappedColored(color: [4]f32, comptime fmt: []const u8, args: anytype) void {
    zgui.pushStyleColor4f(.{ .idx = .text, .c = color });
    defer zgui.popStyleColor(.{ .count = 1 });
    zgui.textWrapped(fmt, args);
}

// Wall clock via kernel32 (this std has no std.time.timestamp).
const kernel32_time = struct {
    extern "kernel32" fn GetSystemTimeAsFileTime(lpSystemTimeAsFileTime: *u64) callconv(.winapi) void;
};
const filetime_to_unix_offset: u64 = 116444736000000000;

/// Unix seconds now (wall clock for LOG display + domain timestamps).
pub fn unixNow() i64 {
    var ft: u64 = undefined;
    kernel32_time.GetSystemTimeAsFileTime(&ft);
    return @intCast((ft - filetime_to_unix_offset) / 10_000_000);
}

pub fn unixNowMs() i64 {
    var ft: u64 = undefined;
    kernel32_time.GetSystemTimeAsFileTime(&ft);
    return @intCast((ft - filetime_to_unix_offset) / 10_000);
}

// ===== Command registry ==================================================

fn cmdDash(ctx: *anyopaque) *Dashboard {
    return @ptrCast(@alignCast(ctx));
}

fn makePanelRun(comptime idx: usize) *const fn (*anyopaque) void {
    return struct {
        fn run(ctx: *anyopaque) void {
            cmdDash(ctx).focusPanel(idx);
        }
    }.run;
}

fn makeWorkspaceRun(comptime ws: ui.layout.Workspace) *const fn (*anyopaque) void {
    return struct {
        fn run(ctx: *anyopaque) void {
            _ = ctx;
            ui.layout.switchTo(ws);
        }
    }.run;
}

fn runResetCmd(ctx: *anyopaque) void {
    _ = ctx;
    ui.layout.requestReset();
    ui.events.post(.info, "layout", "workspace preset rebuild queued", .{});
}

fn runSnapCmd(ctx: *anyopaque) void {
    const d = cmdDash(ctx);
    ui.layout.saveNow();
    d.saveUiState();
    ui.events.post(.ok, "layout", "layout + UI state saved", .{});
}

fn runDemoCmd(ctx: *anyopaque) void {
    const d = cmdDash(ctx);
    d.show_demo_window = !d.show_demo_window;
}

fn runSeedCmd(ctx: *anyopaque) void {
    const d = cmdDash(ctx);
    if (!d.mock_ticking) {
        ui.events.post(.warn, "world", "SEED is mock-only — the Store is owned by {s}", .{d.provider_label});
        return;
    }
    d.regenerateWorld(d.seed +% 1);
}

const commands = [_]ui.registry.Command{
    // -- Panels --
    .{ .code = "PST", .name = "Posture Summary", .kind = .panel, .menu_group = "Panels", .run = makePanelRun(PANEL_PST), .desc = "Focus the Posture Summary (open alerts by severity \u{00B7} cases \u{00B7} MTTA \u{00B7} sensor health \u{00B7} 24h sparkline)" },
    .{ .code = "ALQ", .name = "Alert Queue", .kind = .panel, .menu_group = "Panels", .run = makePanelRun(PANEL_ALQ), .desc = "Focus the Alert Queue (triage table: ack / assign to case / mark FP, keyboard-first)" },
    .{ .code = "CAS", .name = "Cases", .kind = .panel, .menu_group = "Panels", .run = makePanelRun(PANEL_CAS), .desc = "Focus Cases (incident tracking: linked alerts, notes, status transitions)" },
    .{ .code = "TLN", .name = "Timeline", .kind = .panel, .menu_group = "Panels", .run = makePanelRun(PANEL_TLN), .desc = "Focus the Timeline (severity-stacked event histogram; drag a range to filter EVT)" },
    .{ .code = "EVT", .name = "Event Search", .kind = .panel, .menu_group = "Panels", .run = makePanelRun(PANEL_EVT), .desc = "Focus Event Search (filterable telemetry table: kind/host/user/text)" },
    .{ .code = "PRC", .name = "Process Tree", .kind = .panel, .menu_group = "Panels", .run = makePanelRun(PANEL_PRC), .desc = "Focus the Process Tree (parent/child chains for flagged activity, technique badges)" },
    .{ .code = "NET", .name = "Network Connections", .kind = .panel, .menu_group = "Panels", .run = makePanelRun(PANEL_NET), .desc = "Focus Network Connections (dst/port/bytes with IOC-match highlighting)" },
    .{ .code = "RUL", .name = "Detection Rules", .kind = .panel, .menu_group = "Panels", .run = makePanelRun(PANEL_RUL), .desc = "Focus Detection Rules (enable/disable, fire + FP stats, query text)" },
    .{ .code = "TUN", .name = "Rule Tuning", .kind = .panel, .menu_group = "Panels", .run = makePanelRun(PANEL_TUN), .desc = "Focus Rule Tuning (noisiest rules, fires vs FP rate)" },
    .{ .code = "ATK", .name = "ATT&CK Matrix", .kind = .panel, .menu_group = "Panels", .run = makePanelRun(PANEL_ATK), .desc = "Focus the ATT&CK coverage matrix (rule coverage + open-alert heat per technique)" },
    .{ .code = "YAR", .name = "YARA Rules", .kind = .panel, .menu_group = "Panels", .run = makePanelRun(PANEL_YAR), .desc = "Focus YARA Rules (rule library + CI gate health: compile/meta/TP/FP/perf, quality grades)" },
    .{ .code = "IOC", .name = "IOC List", .kind = .panel, .menu_group = "Panels", .run = makePanelRun(PANEL_IOC), .desc = "Focus the IOC List (indicators by type/feed/confidence, hit counts)" },
    .{ .code = "ENR", .name = "IOC Enrichment", .kind = .panel, .menu_group = "Panels", .run = makePanelRun(PANEL_ENR), .desc = "Focus IOC Enrichment (verdict, detection stats, whois/ASN, url scan, pivot to contacted indicators)" },
    .{ .code = "TA", .name = "Threat Actors", .kind = .panel, .menu_group = "Panels", .run = makePanelRun(PANEL_TA), .desc = "Focus Threat Actors (profiles, aliases, technique chips, notes)" },
    .{ .code = "FEED", .name = "Intel Feeds", .kind = .panel, .menu_group = "Panels", .run = makePanelRun(PANEL_FEED), .desc = "Focus Intel Feeds (sync status, staleness, IOC counts)" },
    .{ .code = "SEN", .name = "Sensor Health", .kind = .panel, .menu_group = "Panels", .run = makePanelRun(PANEL_SEN), .desc = "Focus Sensor Health (RAG grid: EDR/FW/IDS/DNS/proxy/cloud, EPS + lag)" },
    .{ .code = "ING", .name = "Ingestion Stats", .kind = .panel, .menu_group = "Panels", .run = makePanelRun(PANEL_ING), .desc = "Focus Ingestion Stats (events/sec per sensor kind over time)" },
    .{ .code = "LOG", .name = "Event Log", .kind = .panel, .menu_group = "Panels", .run = makePanelRun(PANEL_LOG), .desc = "Focus the Event Log (app status/event stream, Ctrl+E exports CSV)" },
    .{ .code = "JOB", .name = "Jobs", .kind = .panel, .menu_group = "Panels", .run = makePanelRun(PANEL_JOB), .desc = "Focus Jobs (async work: phase, progress, cancel)" },
    .{ .code = "SET", .name = "Settings", .kind = .panel, .menu_group = "Panels", .key_hint = "Ctrl+,", .run = makePanelRun(PANEL_SET), .desc = "Focus Settings (appearance \u{00B7} mock seed \u{00B7} persistence paths)" },
    .{ .code = "HELP", .name = "Directory", .kind = .panel, .menu_group = "Panels", .key_hint = "?", .run = makePanelRun(PANEL_HELP), .desc = "Focus the HELP directory (codes \u{00B7} keyboard map \u{00B7} command grammar)" },
    // -- Workspaces --
    .{ .code = "TRIAGE", .name = "Triage workspace", .kind = .panel, .menu_group = "Workspaces", .key_hint = "F1", .run = makeWorkspaceRun(.triage), .desc = "Switch to TRIAGE (alert queue \u{00B7} cases \u{00B7} posture \u{00B7} timeline)" },
    .{ .code = "HUNT", .name = "Hunt workspace", .kind = .panel, .menu_group = "Workspaces", .key_hint = "F2", .run = makeWorkspaceRun(.hunt), .desc = "Switch to HUNT (event search \u{00B7} timeline \u{00B7} process tree \u{00B7} network)" },
    .{ .code = "DETECT", .name = "Detect workspace", .kind = .panel, .menu_group = "Workspaces", .key_hint = "F3", .run = makeWorkspaceRun(.detect), .desc = "Switch to DETECT (rules \u{00B7} ATT&CK coverage \u{00B7} tuning)" },
    .{ .code = "INTEL", .name = "Intel workspace", .kind = .panel, .menu_group = "Workspaces", .key_hint = "F4", .run = makeWorkspaceRun(.intel), .desc = "Switch to INTEL (feeds \u{00B7} IOCs \u{00B7} threat actors)" },
    .{ .code = "OPS", .name = "Ops workspace", .kind = .panel, .menu_group = "Workspaces", .key_hint = "F5", .run = makeWorkspaceRun(.ops), .desc = "Switch to OPS (sensors \u{00B7} ingestion \u{00B7} jobs)" },
    // -- Actions --
    .{ .code = "RESET", .name = "Reset workspace", .kind = .action, .menu_group = "Actions", .run = runResetCmd, .desc = "Rebuild the active workspace's dock preset" },
    .{ .code = "SNAP", .name = "Snapshot layout", .kind = .action, .menu_group = "Actions", .key_hint = "Ctrl+S", .run = runSnapCmd, .desc = "Save the dock layout + UI state now" },
    .{ .code = "SEED", .name = "Regenerate world", .kind = .action, .menu_group = "Actions", .run = runSeedCmd, .desc = "Rebuild the mock world with the next seed (mock-data phase only)" },
    .{ .code = "DEMO", .name = "Bindings demo", .kind = .action, .menu_group = "Actions", .run = runDemoCmd, .desc = "Toggle the ImPlot-bindings demo window" },
};

/// Panel-targeting registry commands — main.zig's --validate exit line
/// reports this so the claim tracks the registry.
pub const registry_panel_count: usize = blk: {
    var n: usize = 0;
    for (commands) |cmd| {
        if (cmd.kind == .panel and std.mem.eql(u8, cmd.menu_group, "Panels")) n += 1;
    }
    break :blk n;
};

// ===== Keyboard map as data (HELP renders it) ============================

pub const KeyBinding = struct {
    chord: [:0]const u8,
    action: [:0]const u8,
};

pub const KeyMapSection = struct {
    title: [:0]const u8,
    keys: []const KeyBinding,
};

const keymap_global = [_]KeyBinding{
    .{ .chord = "Ctrl+K or /", .action = "focus the command line (primary navigation)" },
    .{ .chord = "F1\u{2026}F5", .action = "workspace TRIAGE / HUNT / DETECT / INTEL / OPS" },
    .{ .chord = "Ctrl+Tab / Ctrl+Shift+Tab", .action = "cycle windows/tabs in the focused dock node (ImGui native)" },
    .{ .chord = "F11", .action = "borderless fullscreen toggle" },
    .{ .chord = "Ctrl+,", .action = "SET \u{00B7} Settings" },
    .{ .chord = "?", .action = "HELP directory (Shift+/ outside text inputs)" },
    .{ .chord = "Ctrl+S", .action = "snapshot layout + UI state now (toast confirms)" },
    .{ .chord = "Esc", .action = "clear command line \u{2192} close popup \u{2192} cancel modal (never confirms)" },
};

const keymap_tables = [_]KeyBinding{
    .{ .chord = "Ctrl+F", .action = "focus the panel's filter box (ALQ EVT RUL IOC)" },
    .{ .chord = "\u{2191} \u{2193}", .action = "row selection (ALQ EVT RUL CAS)" },
    .{ .chord = "Enter", .action = "default row action (ALQ ack \u{00B7} EVT detail \u{00B7} RUL toggle detail)" },
    .{ .chord = "Ctrl+E", .action = "export visible rows to CSV (LOG \u{2014} toast with path)" },
};

const keymap_alq = [_]KeyBinding{
    .{ .chord = "A", .action = "ack the selected alert" },
    .{ .chord = "F", .action = "mark the selected alert false-positive" },
    .{ .chord = "C", .action = "assign the selected alert to the selected case" },
};

const keymap_modal = [_]KeyBinding{
    .{ .chord = "Enter", .action = "confirms only after the dwell has elapsed" },
    .{ .chord = "Esc", .action = "always cancels" },
};

pub const keymap_sections = [_]KeyMapSection{
    .{ .title = "Global", .keys = &keymap_global },
    .{ .title = "Tables (focused panel)", .keys = &keymap_tables },
    .{ .title = "Alert Queue (ALQ focused)", .keys = &keymap_alq },
    .{ .title = "Modals", .keys = &keymap_modal },
};

// ===== ui_state.json plumbing ============================================

const cstdio = struct {
    extern fn fopen(path: [*:0]const u8, mode: [*:0]const u8) ?*anyopaque;
    extern fn fread(buf: [*]u8, sz: usize, n: usize, f: *anyopaque) usize;
    extern fn fclose(f: *anyopaque) c_int;
};

fn readSmallFile(path: [:0]const u8, buf: []u8) ?[]u8 {
    const f = cstdio.fopen(path.ptr, "rb") orelse return null;
    defer _ = cstdio.fclose(f);
    const got = cstdio.fread(buf.ptr, 1, buf.len, f);
    if (got == 0) return null;
    return buf[0..got];
}

const UiStateJson = struct {
    schema_version: i64 = 0,
    workspace: []const u8 = "",
    seed: u64 = 42,
    alq_show_closed: bool = false,
    evt_filter: []const u8 = "",
};

/// Command-line InputText callback: ↑↓ move the suggestion selection while
/// matches are open (history recall is a later nicety).
fn cmdInputCallback(cb_data: *zgui.InputTextCallbackData) callconv(.c) i32 {
    const self: *Dashboard = @ptrCast(@alignCast(cb_data.user_data orelse return 0));
    if (!cb_data.event_flag.callback_history) return 0;
    const n = self.palette_match_count;
    if (n > 0) {
        if (cb_data.event_key == .up_arrow) {
            self.palette_sel = if (self.palette_sel == 0) n - 1 else self.palette_sel - 1;
        } else if (cb_data.event_key == .down_arrow) {
            self.palette_sel = (self.palette_sel + 1) % n;
        }
    }
    return 0;
}

// ===== Mock async jobs (JOB panel + FEED sync) ===========================

pub const MockJob = struct {
    name: [:0]const u8,
    phase: [:0]const u8 = "idle",
    progress: f32 = 0,
    running: bool = false,
};

// ===== The Dashboard =====================================================

pub const Dashboard = struct {
    allocator: Allocator,
    store: data.Store,
    gen: data.mock.Generator,
    seed: u64,

    dt: f32 = 1.0 / 60.0,
    wall_clock_s: f64 = 0,

    /// False when a real provider (PG) owns the Store — stops the mock
    /// trickle from writing over database truth.
    mock_ticking: bool = true,
    provider_label: [:0]const u8 = "mock generator",

    // -- Window/panel plumbing --
    panel_force_open: [panels.len]bool = @splat(false),
    panel_float_request: [panels.len]bool = @splat(false),
    panel_focus_request: ?usize = null,
    preset_focus_queue: [2]?usize = .{ null, null },
    preset_focus_countdown: u8 = 0,
    show_demo_window: bool = false,

    // -- Validation harness --
    validate_cycle: u32 = 0,

    // -- Command line --
    cmd_buf: [64:0]u8 = std.mem.zeroes([64:0]u8),
    cmd_focus_request: bool = false,
    palette_sel: usize = 0,
    palette_matches: [8]ui.registry.Match = undefined,
    palette_match_count: usize = 0,

    // -- ui_state persistence --
    state_dir: [256]u8 = @splat(0),
    state_dir_len: usize = 1,
    ui_state_last_ws: ui.layout.Workspace = .triage,
    ui_state_save_suppressed: bool = false,

    // -- LOG panel state --
    log_sev_show: [5]bool = @splat(true),
    log_frozen_head_seq: u64 = 0,
    log_jump_requested: bool = false,
    log_last_seen_seq: u64 = 0,

    // -- ALQ panel state --
    alq_sel: ?u32 = null,
    alq_show_closed: bool = false,
    alq_sev_show: [5]bool = @splat(true),
    alq_filter_buf: [48:0]u8 = std.mem.zeroes([48:0]u8),
    alq_focus_filter: bool = false,
    alq_assign_case: ?u16 = null,

    // -- EVT panel state --
    evt_filter_buf: [64:0]u8 = std.mem.zeroes([64:0]u8),
    evt_kind_show: [7]bool = @splat(true),
    evt_sel: ?u64 = null,
    evt_range: ?[2]i64 = null,
    evt_focus_filter: bool = false,

    // -- CAS / RUL / ATK / IOC / TA / PRC / SEN selections --
    cas_sel: ?u16 = null,
    rul_sel: ?u16 = null,
    rul_filter_buf: [48:0]u8 = std.mem.zeroes([48:0]u8),
    rul_technique_filter: ?attack.TechniqueId = null,
    rul_focus_filter: bool = false,
    atk_sel: ?attack.TechniqueId = null,
    ioc_type_show: [5]bool = @splat(true),
    ioc_filter_buf: [48:0]u8 = std.mem.zeroes([48:0]u8),
    ioc_focus_filter: bool = false,
    ta_sel: u8 = 0,
    prc_sel_root: ?u64 = null,
    sen_sel: ?u16 = null,
    tun_threshold: f32 = 0.5,

    // -- YAR panel state --
    yar_sel: ?u16 = null,
    yar_filter_buf: [48:0]u8 = std.mem.zeroes([48:0]u8),
    yar_focus_filter: bool = false,
    yar_fail_only: bool = false,
    yar_technique_filter: ?attack.TechniqueId = null,

    // -- ENR panel state --
    enr_sel: ?u32 = null, // Ioc.id
    enr_history: [8]u32 = @splat(0), // pivot breadcrumb (back button)
    enr_history_len: u8 = 0,

    // -- Mock jobs --
    jobs: [5]MockJob = .{
        .{ .name = "feed sync" },
        .{ .name = "rule backtest" },
        .{ .name = "ioc enrichment" },
        .{ .name = "retention sweep" },
        .{ .name = "yara ci" },
    },

    pub const JOB_ENRICH: usize = 2;
    pub const JOB_YARA_CI: usize = 4;

    pub fn init(allocator: Allocator, seed: u64) Dashboard {
        var d = Dashboard{
            .allocator = allocator,
            .store = data.Store.init(allocator),
            .gen = data.mock.Generator.init(seed, unixNowMs()),
            .seed = seed,
        };
        d.state_dir[0] = '.';
        ui.events.wallClock = &unixNow;
        d.gen.build(&d.store) catch |err| {
            std.log.err("mock world build failed: {s}", .{@errorName(err)});
        };
        ui.events.post(.ok, "world", "mock world seed {d}: {d} events \u{00B7} {d} alerts \u{00B7} {d} rules \u{00B7} {d} IOCs", .{
            seed,
            d.store.events.items.len,
            d.store.alerts.items.len,
            d.store.rules.items.len,
            d.store.iocs.items.len,
        });
        return d;
    }

    pub fn deinit(self: *Dashboard) void {
        self.store.deinit();
    }

    pub fn setStateDir(self: *Dashboard, dir: []const u8) void {
        const n = @min(dir.len, self.state_dir.len - 1);
        @memcpy(self.state_dir[0..n], dir[0..n]);
        self.state_dir_len = n;
    }

    fn stateDir(self: *const Dashboard) []const u8 {
        return self.state_dir[0..self.state_dir_len];
    }

    pub fn regenerateWorld(self: *Dashboard, seed: u64) void {
        self.seed = seed;
        self.gen = data.mock.Generator.init(seed, unixNowMs());
        self.gen.build(&self.store) catch |err| {
            std.log.err("mock world rebuild failed: {s}", .{@errorName(err)});
            return;
        };
        // Selections reference the old world — drop them.
        self.alq_sel = null;
        self.evt_sel = null;
        self.cas_sel = null;
        self.rul_sel = null;
        self.prc_sel_root = null;
        self.evt_range = null;
        self.yar_sel = null;
        self.yar_technique_filter = null;
        self.enr_sel = null;
        self.enr_history_len = 0;
        ui.events.post(.ok, "world", "world regenerated with seed {d}", .{seed});
    }

    // ── Validation harness ───────────────────────────────────────────────

    /// Frames each workspace is held during a --validate / --screenshot cycle.
    pub const VALIDATE_HOLD: u32 = 48;
    pub const VALIDATE_TOTAL: u32 = VALIDATE_HOLD * ui.layout.workspace_count;

    pub fn forcedWorkspace(self: *const Dashboard) ?ui.layout.Workspace {
        if (self.validate_cycle == 0) return null;
        const done = VALIDATE_TOTAL -| self.validate_cycle;
        return @enumFromInt(@min(done / VALIDATE_HOLD, ui.layout.workspace_count - 1));
    }

    /// Forced-cycle bookkeeping: switch to the held workspace and walk the
    /// focus through its member panels so every panel body renders at least
    /// once (tabs hidden behind a selected sibling would otherwise skip).
    fn tickValidateHarness(self: *Dashboard) void {
        if (self.validate_cycle == 0) return;
        const ws = self.forcedWorkspace().?;
        if (ui.layout.active != ws) ui.layout.switchTo(ws);
        const hold_pos = (VALIDATE_TOTAL -| self.validate_cycle) % VALIDATE_HOLD;
        // Every 5 frames, focus the next member panel of this workspace.
        if (hold_pos % 5 == 2) {
            const want_nth = hold_pos / 5;
            var nth: u32 = 0;
            for (panels, 0..) |_, i| {
                if (!panelInWorkspace(i, ws)) continue;
                if (nth == want_nth) {
                    self.panel_focus_request = i;
                    break;
                }
                nth += 1;
            }
        }
        // Float SET + HELP once, late in the OPS hold, so they get coverage.
        if (ws == .ops and hold_pos == VALIDATE_HOLD - 14) {
            self.panel_force_open[PANEL_SET] = true;
            self.panel_force_open[PANEL_HELP] = true;
            self.panel_focus_request = PANEL_HELP;
        }
        if (ws == .ops and hold_pos == VALIDATE_HOLD - 2) {
            self.panel_force_open[PANEL_SET] = false;
            self.panel_force_open[PANEL_HELP] = false;
        }
        self.validate_cycle -= 1;
    }

    // ── Frame ────────────────────────────────────────────────────────────

    pub fn render(self: *Dashboard, dt: f32) void {
        self.dt = if (dt > 0) dt else 1.0 / 60.0;
        self.wall_clock_s += @as(f64, self.dt);

        // Event spine: per-frame flash clock + toast expiry + insert
        // flashes for events that arrived since the previous frame.
        ui.flash.beginFrame();
        ui.events.tickToasts();
        {
            const n = ui.events.len();
            if (n > 0) {
                const newest = ui.events.nth(0).seq;
                if (newest > self.log_last_seen_seq) {
                    var i: usize = 0;
                    while (i < n) : (i += 1) {
                        const e = ui.events.nth(i);
                        if (e.seq <= self.log_last_seen_seq) break;
                        ui.flash.markInsert(e.seq);
                    }
                    self.log_last_seen_seq = newest;
                }
            }
        }

        // Mock world heartbeat: trickle events/alerts + sensor drift.
        // Suppressed when a real provider owns the Store.
        if (self.mock_ticking) self.gen.tick(&self.store, unixNowMs());
        self.tickJobs();

        self.tickValidateHarness();
        self.handleGlobalKeys();

        const viewport = zgui.getMainViewport();
        const wp = viewport.work_pos;
        const wsz = viewport.work_size;

        self.renderTopStrip(wp, wsz);
        self.renderDockArea(wp, wsz);
        // Deferred preset tab selection: once the dock assignments settle,
        // drain ONE queued focus request per frame.
        if (self.preset_focus_countdown > 0) {
            self.preset_focus_countdown -= 1;
        } else if (self.preset_focus_queue[0] != null or self.preset_focus_queue[1] != null) {
            for (&self.preset_focus_queue) |*slot| {
                if (slot.*) |p| {
                    self.panel_focus_request = p;
                    slot.* = null;
                    break;
                }
            }
        }
        self.renderPanelWindows();

        self.renderToasts(wp, wsz);
        self.renderCritBanner(wp, wsz);
        self.renderFooter(wp, wsz);

        if (self.show_demo_window) ui.demo.draw();

        // Layout autosave: 60 s when dirty + on workspace switch.
        ui.layout.tick();

        // ui_state.json: persist on workspace switch (clean-exit save lives
        // in main.zig). saveUiState() no-ops under --validate.
        if (ui.layout.active != self.ui_state_last_ws) {
            self.ui_state_last_ws = ui.layout.active;
            self.saveUiState();
        }
    }

    // ── Global keys ──────────────────────────────────────────────────────

    fn handleGlobalKeys(self: *Dashboard) void {
        const ctrl = zgui.isKeyDown(.left_ctrl) or zgui.isKeyDown(.right_ctrl);
        const shift = zgui.isKeyDown(.left_shift) or zgui.isKeyDown(.right_shift);

        // F1..F5 switch workspaces — suppressed while typing into a text
        // field so an input focus can never flip the screen.
        if (!zgui.io.getWantTextInput()) {
            const fkeys = [_]zgui.Key{ .f1, .f2, .f3, .f4, .f5 };
            for (fkeys, 0..) |key, i| {
                if (zgui.isKeyPressed(key, false)) {
                    ui.layout.switchTo(@enumFromInt(i));
                }
            }
        }

        if (ctrl and !shift and zgui.isKeyPressed(.s, false)) {
            ui.layout.saveNow();
            self.saveUiState();
            ui.events.post(.ok, "layout", "layout + UI state saved", .{});
        }

        // Ctrl+, opens SET.
        if (ctrl and !shift and zgui.isKeyPressed(.comma, false)) self.focusPanel(PANEL_SET);

        // Ctrl+K (always) or `/` (outside text inputs) focuses the command
        // line. `/` also routes to the focused panel's filter box when that
        // panel advertises one (the panel checks its own flag).
        if (ctrl and !shift and zgui.isKeyPressed(.k, false)) self.cmd_focus_request = true;
        if (!zgui.io.getWantTextInput() and !ctrl and !shift and zgui.isKeyPressed(.slash, false)) {
            self.cmd_focus_request = true;
        }

        // Ctrl+F: focus the focused panel's filter box (panels consume the
        // matching *_focus_filter flag on their next render).
        if (ctrl and !shift and zgui.isKeyPressed(.f, false)) {
            self.alq_focus_filter = true;
            self.evt_focus_filter = true;
            self.rul_focus_filter = true;
            self.ioc_focus_filter = true;
            self.yar_focus_filter = true;
        }

        // `?` (Shift+/ outside text inputs) opens the HELP directory.
        if (!zgui.io.getWantTextInput() and !ctrl and shift and zgui.isKeyPressed(.slash, false)) {
            self.focusPanel(PANEL_HELP);
        }
    }

    /// Focus/open a panel: force-open latch when it isn't a member of the
    /// active workspace, plus the one-shot focus request the renderer turns
    /// into setNextWindowFocus.
    pub fn focusPanel(self: *Dashboard, idx: usize) void {
        if (!panelInWorkspace(idx, ui.layout.active)) {
            self.panel_force_open[idx] = true;
        }
        self.panel_focus_request = idx;
    }

    // ── Top strip: workspaces · command line · View · clock ─────────────

    fn renderTopStrip(self: *Dashboard, wp: [2]f32, wsz: [2]f32) void {
        zgui.setNextWindowPos(.{ .x = wp[0], .y = wp[1] });
        zgui.setNextWindowSize(.{ .w = wsz[0], .h = TOP_STRIP_H });
        zgui.pushStyleVar2f(.{ .idx = .window_padding, .v = .{ 8, 3 } });
        zgui.pushStyleVar2f(.{ .idx = .frame_padding, .v = .{ 6, 2 } });
        defer zgui.popStyleVar(.{ .count = 2 });

        const flags = zgui.WindowFlags{
            .no_title_bar = true,
            .no_resize = true,
            .no_move = true,
            .no_scrollbar = true,
            .no_collapse = true,
            .no_saved_settings = true,
            .no_docking = true,
            .no_bring_to_front_on_focus = true,
        };
        if (zgui.begin("##TopStrip", .{ .flags = flags })) {
            self.renderTopStripContent();
        }
        zgui.end();
    }

    fn renderTopStripContent(self: *Dashboard) void {
        const t = ui.theme.default;

        // ── Left: workspace switcher ─────────────────────────────────────
        inline for (0..ui.layout.workspace_count) |wi| {
            const w: ui.layout.Workspace = @enumFromInt(wi);
            const active = ui.layout.active == w;
            if (wi > 0) zgui.sameLine(.{ .spacing = 3 });
            zgui.pushStyleColor4f(.{ .idx = .button, .c = if (active) t.accent_dim else t.bg.panel });
            zgui.pushStyleColor4f(.{ .idx = .text, .c = if (active) t.text.hi else t.text.mid });
            if (zgui.smallButton(w.label())) ui.layout.switchTo(w);
            zgui.popStyleColor(.{ .count = 2 });
        }

        // Open-alert badge (worst severity colored).
        {
            const by_sev = self.store.openAlertCountBySeverity();
            var total: u32 = 0;
            var worst: domain.Severity = .info;
            for (by_sev, 0..) |n, i| {
                if (n > 0) {
                    total += n;
                    worst = @enumFromInt(i);
                }
            }
            zgui.sameLine(.{ .spacing = 14 });
            var bb: [40]u8 = undefined;
            const lbl = std.fmt.bufPrintZ(&bb, "{s} {d} open##alqbadge", .{ ui.fonts.fa.bell, total }) catch "open";
            zgui.pushStyleColor4f(.{ .idx = .text, .c = if (total > 0) sevColor(worst) else t.text.lo });
            if (zgui.smallButton(lbl)) self.focusPanel(PANEL_ALQ);
            zgui.popStyleColor(.{ .count = 1 });
        }

        // ── Right: command line · ☰ View · UTC clock ─────────────────────
        var clock_buf: [16]u8 = undefined;
        var clock_full: [24]u8 = undefined;
        const clock_z = std.fmt.bufPrintZ(&clock_full, "{s} UTC", .{
            ui.fmt.clock(&clock_buf, unixNow()),
        }) catch "";

        const view_label: [:0]const u8 = fa_bars ++ " View";
        const style = zgui.getStyle();
        const gap: f32 = 10;
        const cmd_w: f32 = 260;
        const clock_w = zgui.calcTextSize(clock_z, .{})[0];
        const view_w = zgui.calcTextSize(view_label, .{})[0] + style.frame_padding[0] * 2;
        const total_w = cmd_w + gap + view_w + gap + clock_w;
        const avail = zgui.getContentRegionAvail()[0];
        if (avail > total_w + 20) {
            zgui.sameLine(.{ .spacing = avail - total_w });
        } else {
            zgui.sameLine(.{ .spacing = 20 });
        }

        self.renderCommandLine(cmd_w);
        zgui.sameLine(.{ .spacing = gap });
        if (zgui.smallButton(view_label)) zgui.openPopup("##view_menu", .{});
        self.renderViewMenu();
        zgui.sameLine(.{ .spacing = gap });
        zgui.textColored(t.text.mid, "{s}", .{clock_z});
    }

    // ── Command line + palette ───────────────────────────────────────────

    fn renderCommandLine(self: *Dashboard, w: f32) void {
        if (self.cmd_focus_request) {
            self.cmd_focus_request = false;
            zgui.setKeyboardFocusHere(0);
        }
        zgui.setNextItemWidth(w);
        const submitted = zgui.inputTextWithHint("##cmdline", .{
            .hint = "code or search \u{00B7} Ctrl+K",
            .buf = &self.cmd_buf,
            .flags = .{ .enter_returns_true = true, .callback_history = true },
            .callback = cmdInputCallback,
            .user_data = self,
        });
        const cmd_active = zgui.isItemActive();
        const text = std.mem.sliceTo(&self.cmd_buf, 0);

        // Refresh fuzzy matches while typing.
        if (text.len > 0) {
            const q = if (text[0] == '>') text[1..] else text;
            const top = ui.registry.fuzzyTop(&commands, q, &self.palette_matches);
            self.palette_match_count = top.len;
            if (self.palette_sel >= top.len) self.palette_sel = 0;
        } else {
            self.palette_match_count = 0;
            self.palette_sel = 0;
        }

        if (submitted) {
            var ran = false;
            if (text.len > 0) {
                if (ui.registry.findByCode(&commands, text)) |cmd| {
                    cmd.run(@ptrCast(self));
                    ran = true;
                } else if (self.palette_match_count > 0) {
                    const m = self.palette_matches[self.palette_sel];
                    commands[m.idx].run(@ptrCast(self));
                    ran = true;
                }
            }
            if (ran) {
                @memset(&self.cmd_buf, 0);
                self.palette_match_count = 0;
            }
            // Keep focus for chained commands.
            zgui.setKeyboardFocusHere(-1);
        }

        // Suggestions popup under the input while it has focus + text.
        if (cmd_active and self.palette_match_count > 0) {
            const rmin = zgui.getItemRectMin();
            const rmax = zgui.getItemRectMax();
            zgui.setNextWindowPos(.{ .x = rmin[0], .y = rmax[1] + 2 });
            zgui.setNextWindowSize(.{ .w = 380, .h = 0 });
            const flags = zgui.WindowFlags{
                .no_title_bar = true,
                .no_resize = true,
                .no_move = true,
                .no_saved_settings = true,
                .no_docking = true,
                .no_focus_on_appearing = true,
                .no_nav_focus = true,
            };
            if (zgui.begin("##cmd_sugg", .{ .flags = flags })) {
                const t = ui.theme.default;
                for (self.palette_matches[0..self.palette_match_count], 0..) |m, i| {
                    const cmd = &commands[m.idx];
                    const selected = i == self.palette_sel;
                    if (selected) {
                        const p = zgui.getCursorScreenPos();
                        zgui.getWindowDrawList().addRectFilled(.{
                            .pmin = .{ p[0] - 4, p[1] - 1 },
                            .pmax = .{ p[0] + 372, p[1] + 17 },
                            .col = zgui.colorConvertFloat4ToU32(t.accent_dim),
                        });
                    }
                    const code_col = codeIdentity(cmd.code) orelse t.accent;
                    zgui.textColored(code_col, "{s}", .{cmd.code});
                    zgui.sameLine(.{ .spacing = 8 });
                    zgui.textUnformatted(cmd.name);
                    if (cmd.key_hint.len > 0) {
                        zgui.sameLine(.{ .spacing = 8 });
                        zgui.textColored(t.text.lo, "{s}", .{cmd.key_hint});
                    }
                }
                zgui.textColored(t.text.lo, "Enter runs \u{00B7} \u{2191}\u{2193} select \u{00B7} Esc clears", .{});
            }
            zgui.end();
        }
    }

    fn tickJobs(self: *Dashboard) void {
        for (&self.jobs, 0..) |*j, i| {
            if (!j.running) continue;
            j.progress += self.dt * 0.12;
            if (j.progress >= 1.0) {
                j.progress = 0;
                j.running = false;
                j.phase = "done";
                ui.events.post(.ok, "jobs", "{s} finished", .{j.name});
                self.onJobDone(i);
            }
        }
    }

    /// Job-completion side effects (render thread; panels see the results
    /// next frame via Store.generation).
    fn onJobDone(self: *Dashboard, idx: usize) void {
        const now = unixNowMs();
        switch (idx) {
            JOB_ENRICH => {
                // Complete every pending enrichment with its deterministic
                // record (pure function of the IOC value — see mock.zig).
                var done: u32 = 0;
                var i: usize = 0;
                while (i < self.store.enrichments.items.len) : (i += 1) {
                    const e = &self.store.enrichments.items[i];
                    if (e.status != .pending) continue;
                    const ic = self.store.iocById(e.ioc_id) orelse continue;
                    var filled = data.mock.Generator.enrichmentFor(&self.store, ic, now);
                    filled.status = .done;
                    _ = self.store.upsertEnrichment(filled);
                    done += 1;
                }
                // Pending url scans complete alongside.
                for (self.store.urlscans.items) |*u| {
                    if (u.state == .pending) _ = self.store.setUrlScanState(u.id, .done, now);
                }
                if (done > 0) ui.events.post(.ok, "enrich", "{d} IOC(s) enriched", .{done});
            },
            JOB_YARA_CI => {
                // Re-run CI: fresh scan times with a small deterministic
                // jitter keyed off the rule name (not the world PRNG).
                var pass: u32 = 0;
                for (self.store.yara.items) |*y| {
                    var g = y.gates;
                    const h = std.hash.Fnv1a_64.hash(y.name.slice()) ^ @as(u64, @bitCast(now));
                    var local = std.Random.DefaultPrng.init(h);
                    const jitter = local.random().float(f32) * 4.0 - 2.0;
                    g.scan_ms = @max(0.5, g.scan_ms + jitter);
                    g.last_ci_ms = now;
                    _ = self.store.recordYaraCi(y.id, g);
                    if (g.allPass()) pass += 1;
                }
                ui.events.post(
                    if (pass == self.store.yara.items.len) .ok else .warn,
                    "yara",
                    "CI run: {d}/{d} rules passing all gates",
                    .{ pass, self.store.yara.items.len },
                );
            },
            else => {},
        }
    }

    /// Mark IOCs pending + kick the enrichment job. Mock flavor of the
    /// live pipeline: a real MCP source would upsert the same shapes.
    pub fn requestEnrichment(self: *Dashboard, ioc_ids: []const u32) void {
        if (self.jobs[JOB_ENRICH].running) {
            ui.events.post(.warn, "enrich", "enrichment rate-limited \u{2014} a run is already in flight", .{});
            return;
        }
        var queued: u32 = 0;
        for (ioc_ids) |id| {
            if (self.store.iocById(id) == null) continue;
            if (self.store.enrichmentForIoc(id)) |e| {
                if (e.status == .done) continue; // already enriched
                var p = e.*;
                p.status = .pending;
                _ = self.store.upsertEnrichment(p); // touch + PG mirror
            } else {
                _ = self.store.upsertEnrichment(.{ .ioc_id = id, .status = .pending });
            }
            queued += 1;
        }
        if (queued == 0) {
            ui.events.post(.info, "enrich", "nothing to enrich \u{2014} selection already covered", .{});
            return;
        }
        ui.events.post(.info, "enrich", "{d} IOC(s) queued for enrichment", .{queued});
        self.startJob(JOB_ENRICH);
    }

    pub fn startJob(self: *Dashboard, idx: usize) void {
        var j = &self.jobs[idx];
        if (j.running) return;
        j.running = true;
        j.progress = 0;
        j.phase = "running";
        ui.events.post(.info, "jobs", "{s} started", .{j.name});
    }

    // ── View menu ────────────────────────────────────────────────────────

    fn renderViewMenu(self: *Dashboard) void {
        if (!zgui.beginPopup("##view_menu", .{})) return;
        defer zgui.endPopup();
        const t = ui.theme.default;

        var group: []const u8 = "";
        for (&commands) |*cmd| {
            if (!std.mem.eql(u8, group, cmd.menu_group)) {
                if (group.len > 0) zgui.separator();
                zgui.textColored(t.text.lo, "{s}", .{cmd.menu_group});
                group = cmd.menu_group;
            }
            const reason = ui.registry.disabledReason(cmd.*, self);
            var lbl_buf: [96]u8 = undefined;
            const lbl = std.fmt.bufPrintZ(&lbl_buf, "{s} \u{00B7} {s}", .{ cmd.code, cmd.name }) catch cmd.code;
            const hint: ?[:0]const u8 = if (cmd.key_hint.len > 0) cmd.key_hint else null;
            if (zgui.menuItem(lbl, .{
                .shortcut = hint,
                .selected = self.commandSelected(cmd),
                .enabled = reason == null,
            })) {
                cmd.run(@ptrCast(self));
            }
            if (codeIdentity(cmd.code)) |idc| {
                const rmin = zgui.getItemRectMin();
                const rmax = zgui.getItemRectMax();
                zgui.getWindowDrawList().addRectFilled(.{
                    .pmin = .{ rmin[0] - 6, rmin[1] + 2 },
                    .pmax = .{ rmin[0] - 3, rmax[1] - 2 },
                    .col = zgui.colorConvertFloat4ToU32(idc),
                });
            }
            if (zgui.isItemHovered(.{ .delay_normal = true })) {
                if (zgui.beginTooltip()) {
                    zgui.textColored(t.text.mid, "{s}", .{cmd.desc});
                    zgui.endTooltip();
                }
            }
        }
    }

    fn commandSelected(self: *Dashboard, cmd: *const ui.registry.Command) bool {
        for (panels, 0..) |p, i| {
            if (std.mem.eql(u8, p.code, cmd.code))
                return panelInWorkspace(i, ui.layout.active) or self.panel_force_open[i];
        }
        inline for (0..ui.layout.workspace_count) |wi| {
            const w: ui.layout.Workspace = @enumFromInt(wi);
            if (std.ascii.eqlIgnoreCase(cmd.code, w.tag())) return ui.layout.active == w;
        }
        if (std.mem.eql(u8, cmd.code, "DEMO")) return self.show_demo_window;
        return false;
    }

    // ── Dockspace + presets ──────────────────────────────────────────────

    fn renderDockArea(self: *Dashboard, wp: [2]f32, wsz: [2]f32) void {
        zgui.setNextWindowPos(.{ .x = wp[0], .y = wp[1] + TOP_STRIP_H });
        zgui.setNextWindowSize(.{ .w = wsz[0], .h = @max(wsz[1] - TOP_STRIP_H - FOOTER_H, 64) });
        zgui.pushStyleVar2f(.{ .idx = .window_padding, .v = .{ 0, 0 } });
        defer zgui.popStyleVar(.{ .count = 1 });

        const flags = zgui.WindowFlags{
            .no_title_bar = true,
            .no_resize = true,
            .no_move = true,
            .no_collapse = true,
            .no_background = true,
            .no_saved_settings = true,
            .no_docking = true,
            .no_bring_to_front_on_focus = true,
            .no_nav_focus = true,
        };
        if (zgui.begin("##DockHost", .{ .flags = flags })) {
            const size = zgui.getContentRegionAvail();
            // Probe the id BEFORE dockSpace() submits — DockSpace creates
            // the node on first submit, which would defeat needsBuild's
            // "no persisted node" check.
            const id = zgui.getStrId(ui.layout.active.dockspaceId());
            if (ui.layout.needsBuild(id)) {
                ui.layout.consumeResetRequest(id);
                zgui.dockBuilderSetNodeSize(id, size);
                buildWorkspacePreset(id);
                zgui.dockBuilderFinish(id);
                ui.layout.markBuilt();
                // Preset's intended selected tabs, deferred two frames so
                // dock assignments settle first.
                switch (ui.layout.active) {
                    .triage => self.preset_focus_queue = .{ PANEL_ALQ, PANEL_LOG },
                    .hunt => self.preset_focus_queue = .{ PANEL_EVT, PANEL_PRC },
                    .detect => self.preset_focus_queue = .{ PANEL_RUL, PANEL_ALQ },
                    .intel => self.preset_focus_queue = .{ PANEL_IOC, PANEL_CAS },
                    .ops => self.preset_focus_queue = .{ PANEL_SEN, PANEL_JOB },
                }
                self.preset_focus_countdown = 2;
            }
            _ = ui.layout.dockspace(size);
        }
        zgui.end();
    }

    /// DockBuilder preset for the ACTIVE workspace. Build order matters:
    /// split the bottom off the root FIRST so it spans the full width, then
    /// side columns off the remaining top.
    fn buildWorkspacePreset(root: zgui.Ident) void {
        const ws = ui.layout.active;
        var nb: [64]u8 = undefined;
        switch (ws) {
            .triage => {
                // Top 0.36 (PST 0.44 | ALQ) · middle (CAS 0.30 | TLN | SEN
                // 0.26) · bottom 0.24 = LOG ; JOB tab group.
                var top: zgui.Ident = 0;
                var rest: zgui.Ident = 0;
                _ = zgui.dockBuilderSplitNode(root, .up, 0.36, &top, &rest);
                var bottom: zgui.Ident = 0;
                var middle: zgui.Ident = 0;
                _ = zgui.dockBuilderSplitNode(rest, .down, 0.24 / 0.64, &bottom, &middle);
                var pst_node: zgui.Ident = 0;
                var alq_node: zgui.Ident = 0;
                _ = zgui.dockBuilderSplitNode(top, .left, 0.44, &pst_node, &alq_node);
                var cas_node: zgui.Ident = 0;
                var mid_rest: zgui.Ident = 0;
                _ = zgui.dockBuilderSplitNode(middle, .left, 0.30, &cas_node, &mid_rest);
                var sen_node: zgui.Ident = 0;
                var tln_node: zgui.Ident = 0;
                _ = zgui.dockBuilderSplitNode(mid_rest, .right, 0.26 / 0.70, &sen_node, &tln_node);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_PST, ws), pst_node);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_ALQ, ws), alq_node);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_CAS, ws), cas_node);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_TLN, ws), tln_node);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_SEN, ws), sen_node);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_JOB, ws), bottom);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_LOG, ws), bottom);
            },
            .hunt => {
                // TLN strip above center 0.28 · PRC right 0.28 (NET tabbed)
                // · bottom 0.24 (IOC ; LOG JOB) · EVT = dominant center.
                var right: zgui.Ident = 0;
                var rest: zgui.Ident = 0;
                _ = zgui.dockBuilderSplitNode(root, .right, 0.28, &right, &rest);
                var bottom: zgui.Ident = 0;
                var top: zgui.Ident = 0;
                _ = zgui.dockBuilderSplitNode(rest, .down, 0.24, &bottom, &top);
                var tln_node: zgui.Ident = 0;
                var evt_node: zgui.Ident = 0;
                _ = zgui.dockBuilderSplitNode(top, .up, 0.30, &tln_node, &evt_node);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_NET, ws), right);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_PRC, ws), right);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_TLN, ws), tln_node);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_EVT, ws), evt_node);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_JOB, ws), bottom);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_LOG, ws), bottom);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_IOC, ws), bottom);
            },
            .detect => {
                // RUL center (ATK tabbed, RUL selected) · TUN right 0.30 ·
                // bottom 0.32 = ALQ ; LOG.
                var right: zgui.Ident = 0;
                var rest: zgui.Ident = 0;
                _ = zgui.dockBuilderSplitNode(root, .right, 0.30, &right, &rest);
                var bottom: zgui.Ident = 0;
                var center: zgui.Ident = 0;
                _ = zgui.dockBuilderSplitNode(rest, .down, 0.32, &bottom, &center);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_TUN, ws), right);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_LOG, ws), bottom);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_ALQ, ws), bottom);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_YAR, ws), center);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_ATK, ws), center);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_RUL, ws), center);
            },
            .intel => {
                // FEED top-left 0.35 (column 0.34 wide) · IOC center · TA
                // right 0.30 · bottom 0.28 = CAS ; LOG.
                var right: zgui.Ident = 0;
                var rest: zgui.Ident = 0;
                _ = zgui.dockBuilderSplitNode(root, .right, 0.30, &right, &rest);
                var bottom: zgui.Ident = 0;
                var top: zgui.Ident = 0;
                _ = zgui.dockBuilderSplitNode(rest, .down, 0.28, &bottom, &top);
                var feed_node: zgui.Ident = 0;
                var ioc_node: zgui.Ident = 0;
                _ = zgui.dockBuilderSplitNode(top, .left, 0.34, &feed_node, &ioc_node);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_TA, ws), right);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_FEED, ws), feed_node);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_ENR, ws), ioc_node);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_IOC, ws), ioc_node);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_LOG, ws), bottom);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_CAS, ws), bottom);
            },
            .ops => {
                // SEN left 0.45 · ING right of it · bottom 0.32 (JOB 0.5 |
                // ALQ ; LOG tabbed with JOB).
                var bottom: zgui.Ident = 0;
                var top: zgui.Ident = 0;
                _ = zgui.dockBuilderSplitNode(root, .down, 0.32, &bottom, &top);
                var sen_node: zgui.Ident = 0;
                var ing_node: zgui.Ident = 0;
                _ = zgui.dockBuilderSplitNode(top, .left, 0.45, &sen_node, &ing_node);
                var job_node: zgui.Ident = 0;
                var alq_node: zgui.Ident = 0;
                _ = zgui.dockBuilderSplitNode(bottom, .left, 0.5, &job_node, &alq_node);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_SEN, ws), sen_node);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_ING, ws), ing_node);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_LOG, ws), job_node);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_JOB, ws), job_node);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_ALQ, ws), alq_node);
            },
        }
    }

    // ── Panel windows ────────────────────────────────────────────────────

    fn renderPanelWindows(self: *Dashboard) void {
        const ws = ui.layout.active;
        for (panels, 0..) |_, i| {
            const member = panelInWorkspace(i, ws);
            if (!member and !self.panel_force_open[i]) continue;

            var nb: [64]u8 = undefined;
            const name = panelWindowName(&nb, i, ws);

            if (self.panel_focus_request == i) {
                zgui.setNextWindowFocus();
                self.panel_focus_request = null;
            }

            if (self.panel_float_request[i]) {
                self.panel_float_request[i] = false;
                zgui.dockBuilderDockWindow(name, 0);
                zgui.setNextWindowSize(.{ .w = 880, .h = 540, .cond = .always });
            }

            var keep_open = true;
            pushPanelTabColors(i);
            const visible = if (member)
                zgui.begin(name, .{})
            else blk: {
                zgui.setNextWindowSize(.{ .w = 880, .h = 540, .cond = .first_use_ever });
                break :blk zgui.begin(name, .{ .popen = &keep_open });
            };
            // Pop immediately: the DockStyle snapshot happened inside begin,
            // and the panel body must render on the global style.
            zgui.popStyleColor(.{ .count = panel_tab_color_count });
            if (visible) {
                drawPanelIdentityBar(i);
                panels_mod.render(self, i);
            }
            zgui.end();
            if (!keep_open) self.panel_force_open[i] = false;
        }
    }

    // ── Toasts + critical banner ─────────────────────────────────────────

    fn renderToasts(self: *Dashboard, wp: [2]f32, wsz: [2]f32) void {
        _ = self;
        const t = ui.theme.default;
        const right = wp[0] + wsz[0] - 10;
        var bottom = wp[1] + wsz[1] - FOOTER_H - 10;

        for (&ui.events.toasts, 0..) |*slot, i| {
            if (slot.* == null) continue;
            const e = ui.events.bySeq(slot.*.?.seq) orelse {
                slot.* = null;
                continue;
            };

            zgui.setNextWindowPos(.{ .x = right, .y = bottom, .pivot_x = 1.0, .pivot_y = 1.0 });
            zgui.setNextWindowSize(.{ .w = 340, .h = 0 });
            zgui.pushStyleColor4f(.{ .idx = .window_bg, .c = t.bg.elev });
            zgui.pushStyleVar2f(.{ .idx = .window_padding, .v = .{ 12, 6 } });

            var name_buf: [16]u8 = undefined;
            const name = std.fmt.bufPrintZ(&name_buf, "##toast{d}", .{i}) catch "##toast";
            const flags = zgui.WindowFlags{
                .no_title_bar = true,
                .no_resize = true,
                .no_move = true,
                .no_scrollbar = true,
                .no_collapse = true,
                .no_saved_settings = true,
                .no_docking = true,
                .no_nav_focus = true,
                .no_focus_on_appearing = true,
            };
            var h: f32 = 44;
            if (zgui.begin(name, .{ .flags = flags })) {
                const p = zgui.getWindowPos();
                const sz = zgui.getWindowSize();
                h = sz[1];
                const dl = zgui.getWindowDrawList();
                dl.addRectFilled(.{
                    .pmin = .{ p[0], p[1] },
                    .pmax = .{ p[0] + 3, p[1] + sz[1] },
                    .col = zgui.colorConvertFloat4ToU32(evSevColor(e.sev)),
                });
                var cb: [16]u8 = undefined;
                zgui.textColored(t.text.mid, "{s}  {s}", .{ e.sourceSlice(), ui.fmt.clock(&cb, e.wall_ts) });

                var dismissed = false;
                {
                    zgui.sameLine(.{});
                    const xw = zgui.calcTextSize(ui.fonts.fa.xmark, .{})[0] + 10;
                    const avail = zgui.getContentRegionAvail()[0];
                    if (avail > xw) zgui.setCursorPosX(zgui.getCursorPosX() + avail - xw);
                    var xb: [24]u8 = undefined;
                    const xlbl = std.fmt.bufPrintZ(&xb, "{s}##toastx{d}", .{ ui.fonts.fa.xmark, i }) catch "x";
                    if (zgui.smallButton(xlbl)) dismissed = true;
                }
                textWrappedColored(t.text.hi, "{s}", .{e.msgSlice()});

                const hovered = zgui.isWindowHovered(.{});
                slot.*.?.pinned = hovered;
                if (hovered and zgui.isMouseClicked(.middle)) dismissed = true;
                if (dismissed) slot.* = null;
            }
            zgui.end();
            zgui.popStyleVar(.{ .count = 1 });
            zgui.popStyleColor(.{ .count = 1 });

            bottom -= h + 6;
        }
    }

    /// Critical banner: a strip OVERLAYING the top of the dockspace —
    /// never a layout row, so an unacked CRIT cannot reflow the dockspace.
    fn renderCritBanner(self: *Dashboard, wp: [2]f32, wsz: [2]f32) void {
        _ = self;
        if (ui.events.banner == null) return;
        const t = ui.theme.default;
        const bsev = ui.events.banner_sev;
        const col = evSevColor(bsev);
        const dim = if (bsev == .crit) t.sev.crit_dim else t.sev.serious_dim;

        zgui.setNextWindowPos(.{ .x = wp[0], .y = wp[1] + TOP_STRIP_H });
        zgui.setNextWindowSize(.{ .w = wsz[0], .h = 26 });
        zgui.pushStyleColor4f(.{ .idx = .window_bg, .c = dim });
        zgui.pushStyleVar2f(.{ .idx = .window_padding, .v = .{ 10, 3 } });
        defer {
            zgui.popStyleVar(.{ .count = 1 });
            zgui.popStyleColor(.{ .count = 1 });
        }
        const flags = zgui.WindowFlags{
            .no_title_bar = true,
            .no_resize = true,
            .no_move = true,
            .no_scrollbar = true,
            .no_collapse = true,
            .no_saved_settings = true,
            .no_docking = true,
        };
        if (zgui.begin("##crit_banner", .{ .flags = flags })) {
            zgui.textColored(col, "{s} {s}", .{ ui.fonts.fa.triangle_exclamation, ui.events.bannerSource() });
            zgui.sameLine(.{ .spacing = 10 });
            zgui.textUnformatted(ui.events.bannerMsg());
            zgui.sameLine(.{ .spacing = 16 });
            if (zgui.smallButton("ACK##banner")) ui.events.ackBanner();
        }
        zgui.end();
    }

    // ── Footer ───────────────────────────────────────────────────────────

    fn renderFooter(self: *Dashboard, wp: [2]f32, wsz: [2]f32) void {
        zgui.setNextWindowPos(.{ .x = wp[0], .y = wp[1] + wsz[1] - FOOTER_H });
        zgui.setNextWindowSize(.{ .w = wsz[0], .h = FOOTER_H });
        zgui.pushStyleVar2f(.{ .idx = .window_padding, .v = .{ 8, 4 } });
        zgui.pushStyleVar2f(.{ .idx = .frame_padding, .v = .{ 5, 1 } });
        defer zgui.popStyleVar(.{ .count = 2 });

        const flags = zgui.WindowFlags{
            .no_title_bar = true,
            .no_resize = true,
            .no_move = true,
            .no_scrollbar = true,
            .no_collapse = true,
            .no_saved_settings = true,
            .no_docking = true,
            .no_bring_to_front_on_focus = true,
        };
        if (zgui.begin("##StatusFooter", .{ .flags = flags })) {
            zgui.pushFont(ui.fonts.mono, ui.fonts.size.micro);
            self.renderFooterContent();
            zgui.popFont();
        }
        zgui.end();
    }

    fn renderFooterContent(self: *Dashboard) void {
        const t = ui.theme.default;

        // Sensor-fleet LEDs by kind: worst status wins per kind family.
        const led_defs = [_]struct { label: [:0]const u8, kinds: []const domain.SensorKind }{
            .{ .label = "EDR", .kinds = &.{.edr} },
            .{ .label = "NET", .kinds = &.{ .firewall, .ids, .dns, .proxy } },
            .{ .label = "CLOUD", .kinds = &.{.cloud} },
        };
        inline for (led_defs, 0..) |ld, li| {
            if (li > 0) zgui.sameLine(.{ .spacing = 8 });
            var worst: domain.SensorStatus = .ok;
            for (self.store.sensors.items) |*s| {
                for (ld.kinds) |k| {
                    if (s.kind == k and @intFromEnum(s.status) > @intFromEnum(worst)) worst = s.status;
                }
            }
            zgui.textColored(sensorStatusColor(worst), "{s}", .{ui.fonts.fa.circle});
            zgui.sameLine(.{ .spacing = 3 });
            zgui.textColored(t.text.mid, "{s}", .{ld.label});
            if (zgui.isItemHovered(.{})) {
                if (zgui.beginTooltip()) {
                    zgui.text("{s} sensors: worst = {s} \u{00B7} see SEN", .{ ld.label, worst.label() });
                    zgui.endTooltip();
                }
            }
        }

        // Open alerts by severity.
        zgui.sameLine(.{ .spacing = 16 });
        {
            const by_sev = self.store.openAlertCountBySeverity();
            const order = [_]domain.Severity{ .critical, .high, .medium, .low };
            inline for (order, 0..) |sv, i| {
                if (i > 0) zgui.sameLine(.{ .spacing = 6 });
                const n = by_sev[@intFromEnum(sv)];
                zgui.textColored(if (n > 0) sevColor(sv) else t.text.lo, "{s} {d}", .{ sv.label(), n });
            }
        }

        // Total EPS.
        zgui.sameLine(.{ .spacing = 16 });
        {
            var eps: f32 = 0;
            for (self.store.sensors.items) |*s| {
                if (s.status != .down) eps += s.eps;
            }
            zgui.textColored(t.text.mid, "{d:.0} eps", .{eps});
        }

        // Right side: seed · workspace · clock.
        var right_buf: [96]u8 = undefined;
        var cb: [16]u8 = undefined;
        const right_txt = std.fmt.bufPrintZ(&right_buf, "seed {d} \u{00B7} {s} \u{00B7} {s} UTC", .{
            self.seed,
            ui.layout.active.tag(),
            ui.fmt.clock(&cb, unixNow()),
        }) catch "";
        const w = zgui.calcTextSize(right_txt, .{})[0];
        const avail = zgui.getContentRegionAvail()[0];
        if (avail > w + 10) zgui.sameLine(.{ .spacing = avail - w });
        zgui.textColored(t.text.mid, "{s}", .{right_txt});
    }

    // ── ui_state.json ────────────────────────────────────────────────────

    fn uiStatePath(self: *const Dashboard, buf: []u8) ?[:0]const u8 {
        return std.fmt.bufPrintZ(buf, "{s}/ui_state.json", .{self.stateDir()}) catch null;
    }

    pub fn saveUiState(self: *Dashboard) void {
        if (self.ui_state_save_suppressed) return;
        var pbuf: [300]u8 = undefined;
        const path = self.uiStatePath(&pbuf) orelse return;

        var jbuf: [512]u8 = undefined;
        const evt_filter = std.mem.sliceTo(&self.evt_filter_buf, 0);
        // Fields are JSON-escape-free by construction (enum tag, ints, a
        // filter string that panels keep to plain ASCII).
        const json = std.fmt.bufPrint(&jbuf, "{{\n  \"schema_version\": 1,\n  \"workspace\": \"{s}\",\n  \"seed\": {d},\n  \"alq_show_closed\": {},\n  \"evt_filter\": \"{s}\"\n}}\n", .{
            @tagName(ui.layout.active),
            self.seed,
            self.alq_show_closed,
            evt_filter,
        }) catch return;
        ui.layout.atomicWrite(path, json) catch |err| {
            std.log.warn("ui_state: save failed: {s}", .{@errorName(err)});
        };
    }

    pub fn loadUiState(self: *Dashboard) void {
        var pbuf: [300]u8 = undefined;
        const path = self.uiStatePath(&pbuf) orelse return;
        var buf: [4096]u8 = undefined;
        const data_slice = readSmallFile(path, &buf) orelse return;
        if (!self.applyUiStateData(data_slice)) {
            std.log.warn("ui_state: malformed '{s}' — using defaults", .{path});
        }
    }

    pub fn applyUiStateData(self: *Dashboard, data_slice: []const u8) bool {
        const parsed = std.json.parseFromSlice(UiStateJson, self.allocator, data_slice, .{
            .ignore_unknown_fields = true,
        }) catch return false;
        defer parsed.deinit();
        const v = parsed.value;
        if (v.schema_version != 1) return false;

        inline for (0..ui.layout.workspace_count) |wi| {
            const w: ui.layout.Workspace = @enumFromInt(wi);
            if (std.mem.eql(u8, v.workspace, @tagName(w))) ui.layout.switchTo(w);
        }
        self.ui_state_last_ws = ui.layout.active;
        self.alq_show_closed = v.alq_show_closed;
        const flen = @min(v.evt_filter.len, self.evt_filter_buf.len - 1);
        @memset(&self.evt_filter_buf, 0);
        @memcpy(self.evt_filter_buf[0..flen], v.evt_filter[0..flen]);
        // Seed restore only when the current world was built with the
        // default: an explicit --seed wins.
        if (v.seed != self.seed and self.seed == 42) {
            self.regenerateWorld(v.seed);
        }
        return true;
    }

    // ── Selftest ─────────────────────────────────────────────────────────

    /// Headless data-path exercise (no zgui): determinism, referential
    /// integrity, and every panel's filter/aggregate prep.
    pub fn selfTest(self: *Dashboard) !void {
        // Determinism: a second same-seed world checksums identically.
        {
            var s2 = data.Store.init(self.allocator);
            defer s2.deinit();
            var g2 = data.mock.Generator.init(self.gen.seed, self.gen.base_ms);
            try g2.build(&s2);
            if (data.mock.Generator.checksum(&self.store) != data.mock.Generator.checksum(&s2))
                return error.WorldNotDeterministic;
        }

        const s = &self.store;
        if (s.events.items.len < 1000) return error.WorldTooSmall;
        if (s.alerts.items.len < 40) return error.WorldTooSmall;

        // Referential integrity.
        for (s.alerts.items) |*a| {
            if (a.rule >= s.rules.items.len) return error.AlertRuleDangling;
            if (a.event_count > 0 and s.eventById(a.event_ids[0]) == null) return error.AlertEventDangling;
            if (a.case_id) |cid| {
                if (s.caseById(cid) == null) return error.AlertCaseDangling;
            }
        }
        for (s.events.items) |*e| {
            if (e.parent) |p| {
                if (s.eventById(p) == null) return error.EventParentDangling;
            }
            if (e.host >= s.hosts.items.len) return error.EventHostDangling;
        }

        // Panel data preps.
        _ = s.openAlertCountBySeverity();
        _ = s.openCaseCount();
        _ = s.sensorsDown();
        var tid: attack.TechniqueId = 0;
        while (tid < attack.technique_count) : (tid += 1) {
            _ = s.coverageForTechnique(tid);
            _ = s.alertHeatForTechnique(tid);
        }
        // EVT filter path over the full table.
        var shown: usize = 0;
        for (s.events.items) |*e| {
            if (std.mem.indexOf(u8, e.cmdline.slice(), "powershell") != null) shown += 1;
            _ = e.kind.label();
        }
        if (shown == 0) return error.NoPowershellInWorld;

        // YARA rules: technique bounds + gate consistency (a TP can't fire
        // if the rule doesn't compile).
        if (s.yara.items.len == 0) return error.NoYaraRules;
        for (s.yara.items) |*y| {
            if (y.technique >= attack.technique_count) return error.YaraTechniqueDangling;
            if (y.gates.tp == .pass and y.gates.compile == .fail) return error.YaraGateInconsistent;
            _ = y.score();
            _ = y.grade();
        }
        _ = s.yaraGradeHistogram();
        _ = s.yaraSeverityDistribution();
        _ = s.yaraGatePassCounts();
        tid = 0;
        while (tid < attack.technique_count) : (tid += 1) _ = s.yaraCoverageForTechnique(tid);

        // Enrichment: every row resolves to an IOC; pivots resolve; url
        // scans reference url-type IOCs.
        for (s.enrichments.items) |*e| {
            if (s.iocById(e.ioc_id) == null) return error.EnrichmentIocDangling;
            if (e.status == .done and e.detTotal() == 0) return error.EnrichmentEmpty;
            for (e.pivot_ids[0..e.pivot_count]) |pid| {
                if (s.iocById(pid) == null) return error.PivotIocDangling;
            }
        }
        for (s.urlscans.items) |*u| {
            const ic = s.iocById(u.ioc_id) orelse return error.UrlScanIocDangling;
            if (ic.type != .url) return error.UrlScanNotUrl;
        }
        _ = s.enrichedCounts();

        // enrichmentFor is a pure function of the IOC (guards the FNV seed).
        if (s.iocs.items.len > 0) {
            const ic0 = &s.iocs.items[0];
            const a0 = data.mock.Generator.enrichmentFor(s, ic0, 1);
            const b0 = data.mock.Generator.enrichmentFor(s, ic0, 2);
            if (a0.verdict != b0.verdict or a0.det_malicious != b0.det_malicious or
                a0.pivot_count != b0.pivot_count) return error.EnrichmentNotPure;
        }

        // Mutation round-trip.
        const first_alert = s.alerts.items[0].id;
        if (!s.setAlertStatus(first_alert, .acked)) return error.MutateFailed;
        if (!s.setAlertStatus(first_alert, .new)) return error.MutateFailed;

        // New mutation paths round-trip (no hook installed under selftest).
        const y0 = s.yara.items[0].id;
        if (!s.setYaraStatus(y0, .deprecated)) return error.MutateFailed;
        if (!s.setYaraStatus(y0, .active)) return error.MutateFailed;
        if (!s.recordYaraCi(y0, s.yara.items[0].gates)) return error.MutateFailed;
        {
            const probe_id: u32 = s.iocs.items[0].id;
            _ = s.upsertEnrichment(.{ .ioc_id = probe_id, .status = .pending });
            var filled = data.mock.Generator.enrichmentFor(s, &s.iocs.items[0], unixNowMs());
            filled.status = .done;
            if (!s.upsertEnrichment(filled)) return error.MutateFailed;
        }

        // ui_state round-trip through the JSON path.
        if (!self.applyUiStateData("{\"schema_version\":1,\"workspace\":\"hunt\",\"seed\":42}"))
            return error.UiStateRoundTrip;
        ui.layout.switchTo(.triage);

        std.log.info("selftest: world {d} events / {d} alerts / {d} rules — data paths OK", .{
            s.events.items.len, s.alerts.items.len, s.rules.items.len,
        });
    }
};

test {
    std.testing.refAllDecls(@This());
}
