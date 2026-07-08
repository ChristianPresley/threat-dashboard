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
const ai = @import("ai");

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
    .{ .code = "AI", .name = "AI Assistant", .group = "Intel" },
    .{ .code = "PIP", .name = "Data Pipelines", .group = "Ops" },
    .{ .code = "AUD", .name = "Audit Trail", .group = "Ops" },
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
pub const PANEL_AI: usize = 21;
pub const PANEL_PIP: usize = 22;
pub const PANEL_AUD: usize = 23;

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
            idx == PANEL_ALQ or idx == PANEL_LOG or idx == PANEL_PIP or
            idx == PANEL_AUD,
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

/// ATT&CK technique id lookup by string (e.g. "T1059.001"); null if absent.
fn findTechnique(id: []const u8) ?attack.TechniqueId {
    for (attack.techniques, 0..) |tech, i| {
        if (std.mem.eql(u8, tech.id, id)) return @intCast(i);
    }
    return null;
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
    .{ .code = "PIP", .name = "Data Pipelines", .kind = .panel, .menu_group = "Panels", .run = makePanelRun(PANEL_PIP), .desc = "Focus Data Pipelines (dbt-style ELT: pick a source, chain models, run tests, land in PostgreSQL or another sink)" },
    .{ .code = "AUD", .name = "Audit Trail", .kind = .panel, .menu_group = "Panels", .run = makePanelRun(PANEL_AUD), .desc = "Focus the Audit Trail (chain of custody: every analyst/system action, who \u{00B7} what \u{00B7} when)" },
    .{ .code = "LOG", .name = "Event Log", .kind = .panel, .menu_group = "Panels", .run = makePanelRun(PANEL_LOG), .desc = "Focus the Event Log (app status/event stream, Ctrl+E exports CSV)" },
    .{ .code = "JOB", .name = "Jobs", .kind = .panel, .menu_group = "Panels", .run = makePanelRun(PANEL_JOB), .desc = "Focus Jobs (async work: phase, progress, cancel)" },
    .{ .code = "SET", .name = "Settings", .kind = .panel, .menu_group = "Panels", .key_hint = "Ctrl+,", .run = makePanelRun(PANEL_SET), .desc = "Focus Settings (appearance \u{00B7} mock seed \u{00B7} persistence paths)" },
    .{ .code = "HELP", .name = "Directory", .kind = .panel, .menu_group = "Panels", .key_hint = "?", .run = makePanelRun(PANEL_HELP), .desc = "Focus the HELP directory (codes \u{00B7} keyboard map \u{00B7} command grammar)" },
    .{ .code = "AI", .name = "AI Assistant", .kind = .panel, .menu_group = "Panels", .key_hint = "Ctrl+Shift+A", .run = makePanelRun(PANEL_AI), .desc = "Focus the AI Assistant (Claude chat with read-only dashboard + threat-intel tools)" },
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
    .{ .chord = "Ctrl+Shift+A", .action = "AI \u{00B7} Assistant (Claude chat with dashboard + threat-intel tools)" },
    .{ .chord = "?", .action = "HELP directory (Shift+/ outside text inputs)" },
    .{ .chord = "Ctrl+S", .action = "snapshot layout + UI state now (toast confirms)" },
    .{ .chord = "Esc", .action = "clear command line \u{2192} close popup \u{2192} cancel modal (never confirms)" },
};

const keymap_tables = [_]KeyBinding{
    .{ .chord = "Ctrl+F", .action = "focus the panel's filter box (ALQ EVT RUL IOC YAR PIP)" },
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
/// matches are open; on an empty line (or mid-recall) they walk the
/// submitted-command history instead, shell-style.
fn cmdInputCallback(cb_data: *zgui.InputTextCallbackData) callconv(.c) i32 {
    const self: *Dashboard = @ptrCast(@alignCast(cb_data.user_data orelse return 0));
    if (!cb_data.event_flag.callback_history) return 0;
    const n = self.palette_match_count;
    if (self.cmd_history_pos == null and n > 0) {
        if (cb_data.event_key == .up_arrow) {
            self.palette_sel = if (self.palette_sel == 0) n - 1 else self.palette_sel - 1;
        } else if (cb_data.event_key == .down_arrow) {
            self.palette_sel = (self.palette_sel + 1) % n;
        }
        return 0;
    }
    if (self.cmd_history_len == 0) return 0;
    var pos: usize = undefined;
    if (cb_data.event_key == .up_arrow) {
        pos = if (self.cmd_history_pos) |p| @min(p + 1, self.cmd_history_len - 1) else 0;
    } else if (cb_data.event_key == .down_arrow) {
        const p = self.cmd_history_pos orelse return 0;
        if (p == 0) {
            // Walking past the newest entry clears the line.
            self.cmd_history_pos = null;
            cb_data.deleteChars(0, cb_data.buf_text_len);
            return 0;
        }
        pos = p - 1;
    } else return 0;
    self.cmd_history_pos = pos;
    cb_data.deleteChars(0, cb_data.buf_text_len);
    cb_data.insertChars(0, std.mem.sliceTo(&self.cmd_history[pos], 0));
    return 0;
}

// ===== Jobs ==============================================================
// The queue engine lives in data/jobs.zig (pure, unit-tested); completion
// and cancel SIDE EFFECTS live here on the render thread (onJobComplete /
// onJobCanceled) so every world write still goes through the Store API and
// mirrors to PG.

/// Re-export for panels: `dash.jobs_mod.JobKind` etc.
pub const jobs_mod = data.jobs;

// ===== AI assistant UI state =============================================

pub const ChatItem = struct {
    kind: enum { user, assistant, tool_call, tool_result, err },
    text: []u8, // owned
    meta: [64]u8 = @splat(0),
    meta_len: u8 = 0,
    is_error: bool = false,
    expanded: bool = false,

    pub fn metaSlice(self: *const ChatItem) []const u8 {
        return self.meta[0..self.meta_len];
    }
};

pub const AssistantUi = struct {
    cfg: ai.Config = .{},
    worker: ?*ai.worker.Worker = null,
    io: ?std.Io = null,
    mcp_argv_buf: [16][]const u8 = undefined,

    transcript: std.ArrayList(ChatItem) = .empty,
    input_buf: [4096:0]u8 = std.mem.zeroes([4096:0]u8),
    busy: bool = false,
    status: [96]u8 = @splat(0),
    status_len: u8 = 0,
    mcp_state: ai.worker.McpState = .off,
    last_in_tokens: u64 = 0,
    last_out_tokens: u64 = 0,
    attach_alert: bool = false,
    attach_ioc: bool = false,
    scroll_to_bottom: bool = false,
    /// Tour-only: render the transcript even without a configured worker.
    tour_demo: bool = false,

    pub fn statusSlice(self: *const AssistantUi) []const u8 {
        return self.status[0..self.status_len];
    }

    pub fn setStatus(self: *AssistantUi, s: []const u8) void {
        const n = @min(s.len, self.status.len);
        @memcpy(self.status[0..n], s[0..n]);
        self.status_len = @intCast(n);
    }
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
    /// Background PG worker (set by main when --pg is live). Owns the DB
    /// connection; drained once per frame in drainPg.
    pg_worker: ?*data.pg_worker.Worker = null,

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
    /// Submitted-command recall ring: newest at index 0.
    cmd_history: [8][64:0]u8 = @splat(std.mem.zeroes([64:0]u8)),
    cmd_history_len: usize = 0,
    cmd_history_pos: ?usize = null,

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

    // -- CAS notes editing --
    cas_notes_edit: ?u16 = null, // case id being edited
    cas_notes_buf: [480:0]u8 = std.mem.zeroes([480:0]u8),

    // -- PIP panel state --
    pip_sel: ?u16 = null,
    pip_filter_buf: [48:0]u8 = std.mem.zeroes([48:0]u8),
    pip_focus_filter: bool = false,
    pip_show_builder: bool = false,
    pip_show_sources: bool = false,
    pip_new_name: [48:0]u8 = std.mem.zeroes([48:0]u8),
    pip_new_target: [64:0]u8 = std.mem.zeroes([64:0]u8),
    pip_new_source: usize = 0, // index into store.sources
    pip_new_sink: usize = 0, // SinkKind ordinal
    pip_new_sched: i32 = 15,
    pip_new_steps: [domain.PIPELINE_STEP_CAP]domain.PipelineStep = @splat(domain.PipelineStep{}),
    pip_new_step_count: u8 = 0,

    // -- Audit trail (chain of custody; owned here so PG snapshot swaps
    //    can never erase it) --
    audit: std.ArrayList(domain.AuditEntry) = .empty,
    audit_next_id: u32 = 1,
    /// True while job/scheduler side effects run — their mutations
    /// attribute to "system" instead of the analyst.
    audit_system: bool = false,
    aud_filter_buf: [48:0]u8 = std.mem.zeroes([48:0]u8),

    // -- Jobs (queue engine; side effects in onJobComplete/onJobCanceled) --
    jobs: data.jobs.Engine,
    /// Pipeline-scheduler throttle (last due-check wall ms).
    sched_last_ms: i64 = 0,
    /// True once the guided tour drives frames — suppresses the scheduler
    /// so captures aren't perturbed by auto-enqueued runs.
    tour_running: bool = false,

    // -- AI assistant --
    assistant: AssistantUi = .{},

    // -- Guided-tour harness --
    tour_scene: usize = 0,
    tour_frame: u32 = 0,
    tour_cap_seq: u32 = 0,

    pub fn init(allocator: Allocator, seed: u64) Dashboard {
        var d = Dashboard{
            .allocator = allocator,
            .store = data.Store.init(allocator),
            .gen = data.mock.Generator.init(seed, unixNowMs()),
            .seed = seed,
            .jobs = data.jobs.Engine.init(allocator),
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
        if (self.assistant.worker) |w| w.shutdown();
        for (self.assistant.transcript.items) |*it| self.allocator.free(it.text);
        self.assistant.transcript.deinit(self.allocator);
        self.jobs.deinit();
        self.audit.deinit(self.allocator);
        self.store.deinit();
    }

    /// Install the audit tap once `self` has its final address (init
    /// returns by value, so this runs from render()/selfTest() instead).
    fn ensureAuditHook(self: *Dashboard) void {
        if (self.store.audit_hook != null) return;
        self.store.audit_hook = .{ .ctx = self, .f = onAuditMutation };
    }

    pub const AUDIT_CAP = 512;

    fn onAuditMutation(ctx: *anyopaque, m: data.Mutation) void {
        const self: *Dashboard = @ptrCast(@alignCast(ctx));
        var entry: domain.AuditEntry = .{
            .id = self.audit_next_id,
            .ts_ms = unixNowMs(),
            .actor = domain.FixedStr(24).from(if (self.audit_system) "system" else "cpresley"),
            .action = domain.FixedStr(28).from(@tagName(m)),
        };
        var tb: [64]u8 = undefined;
        entry.target = domain.FixedStr(64).from(auditTarget(&tb, m));
        self.audit.append(self.allocator, entry) catch return;
        self.audit_next_id += 1;
        if (self.audit.items.len > AUDIT_CAP) _ = self.audit.orderedRemove(0);
    }

    fn auditTarget(buf: []u8, m: data.Mutation) []const u8 {
        const r = switch (m) {
            .alert_status => |v| std.fmt.bufPrint(buf, "alert #{d} \u{2192} {s}", .{ v.id, v.status.label() }),
            .rule_status => |v| std.fmt.bufPrint(buf, "rule #{d} \u{2192} {s}", .{ v.id, v.status.label() }),
            .case_status => |v| std.fmt.bufPrint(buf, "case #{d} \u{2192} {s}", .{ v.id, v.status.label() }),
            .case_assign => |v| std.fmt.bufPrint(buf, "alert #{d} \u{2192} case #{d}", .{ v.alert_id, v.case_id }),
            .case_notes => |v| std.fmt.bufPrint(buf, "case #{d} notes edited", .{v.id}),
            .yara_status => |v| std.fmt.bufPrint(buf, "yara #{d} \u{2192} {s}", .{ v.id, v.status.label() }),
            .yara_ci => |v| std.fmt.bufPrint(buf, "yara #{d} CI recorded", .{v.id}),
            .enrichment_upsert => |v| std.fmt.bufPrint(buf, "ioc #{d} enrichment {s}", .{ v.e.ioc_id, v.e.status.label() }),
            .urlscan_submit => |v| std.fmt.bufPrint(buf, "urlscan #{d} for ioc #{d}", .{ v.id, v.ioc_id }),
            .urlscan_update => |v| std.fmt.bufPrint(buf, "urlscan #{d} \u{2192} {s}", .{ v.id, v.state.label() }),
            .source_tested => |v| std.fmt.bufPrint(buf, "source #{d} probed: {s}", .{ v.id, v.state.label() }),
            .pipeline_status => |v| std.fmt.bufPrint(buf, "pipeline #{d} \u{2192} {s}", .{ v.id, v.status.label() }),
            .pipeline_add => |v| std.fmt.bufPrint(buf, "pipeline {s} created", .{v.p.name.slice()}),
            .pipeline_run_add => |v| std.fmt.bufPrint(buf, "run #{d} started (pipeline #{d})", .{ v.run.id, v.run.pipeline }),
            .pipeline_run_update => |v| std.fmt.bufPrint(buf, "run #{d} \u{2192} {s}", .{ v.run.id, v.run.status.label() }),
            .pipeline_tests => |v| std.fmt.bufPrint(buf, "pipeline #{d} tests updated", .{v.id}),
            .dead_letter_add => |v| std.fmt.bufPrint(buf, "dead letter (pipeline #{d})", .{v.dl.pipeline}),
            .dead_letter_state => |v| std.fmt.bufPrint(buf, "dead letter #{d} \u{2192} {s}", .{ v.id, v.state.label() }),
        };
        return r catch buf[0..0];
    }

    /// Wire the AI assistant from env-sourced config (GUI path only). The
    /// worker thread is NOT spawned here — that happens lazily on first send.
    pub fn configureAssistant(self: *Dashboard, io: std.Io, cfg: ai.Config) void {
        self.assistant.cfg = cfg;
        self.assistant.io = io;
        if (!cfg.configured()) return;
        const argv = ai.resolveMcpArgv(cfg, &self.assistant.mcp_argv_buf);
        self.assistant.worker = ai.worker.Worker.create(self.allocator, io, .{
            .api_key = cfg.api_key.?,
            .model = cfg.model,
            .mcp_argv = argv,
            .system_prompt = ai.SYSTEM_PROMPT,
        }) catch null;
    }

    pub fn appendChat(self: *Dashboard, kind: anytype, text: []const u8, meta: []const u8, is_error: bool) void {
        const owned = self.allocator.dupe(u8, text) catch return;
        var item: ChatItem = .{ .kind = kind, .text = owned, .is_error = is_error };
        const mn = @min(meta.len, item.meta.len);
        @memcpy(item.meta[0..mn], meta[0..mn]);
        item.meta_len = @intCast(mn);
        self.assistant.transcript.append(self.allocator, item) catch {
            self.allocator.free(owned);
            return;
        };
        self.assistant.scroll_to_bottom = true;
    }

    /// Send the assistant a message, serializing any attached context.
    pub fn assistantSend(self: *Dashboard, text: []const u8) void {
        const w = self.assistant.worker orelse return;
        self.appendChat(.user, text, "", false);
        // Build attached-context JSON from current selections, if requested.
        var ctx_buf: std.Io.Writer.Allocating = .init(self.allocator);
        defer ctx_buf.deinit();
        var has_ctx = false;
        if (self.assistant.attach_alert) {
            if (self.alq_sel) |aid| {
                var qb: [48]u8 = undefined;
                const q = std.fmt.bufPrint(&qb, "{{\"id\":{d}}}", .{aid}) catch "{}";
                if (ai.tools.execute(self.allocator, &self.store, "get_alert_detail", q)) |j| {
                    defer self.allocator.free(j);
                    ctx_buf.writer.print("<attached_alert>{s}</attached_alert>", .{j}) catch {};
                    has_ctx = true;
                } else |_| {}
            }
        }
        if (self.assistant.attach_ioc) {
            if (self.enr_sel) |iid| {
                if (self.store.iocById(iid)) |ic| {
                    ctx_buf.writer.print("<attached_ioc>type={s} value={s} confidence={d}</attached_ioc>", .{
                        ic.type.label(), ic.value.slice(), ic.confidence,
                    }) catch {};
                    has_ctx = true;
                }
            }
        }
        w.send(text, if (has_ctx) ctx_buf.written() else null);
        self.assistant.busy = true;
        self.assistant.setStatus("thinking");
    }

    /// Drain worker → UI events once per frame (the only place worker output
    /// touches the transcript / Store).
    fn drainAssistant(self: *Dashboard) void {
        const w = self.assistant.worker orelse return;
        var batch: std.ArrayList(ai.worker.WorkerToUi) = .empty;
        defer batch.deinit(self.allocator);
        w.drain(&batch);
        for (batch.items) |ev| {
            switch (ev) {
                .status => |s| {
                    self.assistant.setStatus(s);
                    self.allocator.free(s);
                },
                .assistant_text => |txt| {
                    self.appendChat(.assistant, txt, "", false);
                    self.allocator.free(txt);
                },
                .tool_call => |tc| {
                    self.appendChat(.tool_call, tc.input_preview, tc.name, false);
                    self.allocator.free(tc.name);
                    self.allocator.free(tc.input_preview);
                },
                .tool_done => |td| {
                    self.appendChat(.tool_result, td.result_preview, td.name, td.is_error);
                    self.allocator.free(td.name);
                    self.allocator.free(td.result_preview);
                },
                .tool_query => |q| {
                    // Execute the native tool against the Store, reply.
                    if (ai.tools.execute(self.allocator, &self.store, q.name, q.input_json)) |res| {
                        w.replyToolQuery(q.id, res, false);
                        self.allocator.free(res);
                    } else |err| {
                        w.replyToolQuery(q.id, @errorName(err), true);
                    }
                    self.allocator.free(q.name);
                    self.allocator.free(q.input_json);
                },
                .turn_done => |t| {
                    self.assistant.last_in_tokens = t.input_tokens;
                    self.assistant.last_out_tokens = t.output_tokens;
                },
                .mcp_state => |ms| self.assistant.mcp_state = ms,
                .err => |m| {
                    self.appendChat(.err, m, "error", true);
                    ui.events.post(.warn, "ai", "{s}", .{m});
                    self.allocator.free(m);
                    self.assistant.busy = false;
                },
                .idle => self.assistant.busy = false,
            }
        }
    }

    /// Drain PG worker → UI events once per frame (the only place worker
    /// output touches the Store — mirror of drainAssistant).
    fn drainPg(self: *Dashboard) void {
        const w = self.pg_worker orelse return;
        var batch: std.ArrayList(data.pg_worker.Event) = .empty;
        defer batch.deinit(self.allocator);
        w.drain(&batch);
        for (batch.items) |ev| {
            switch (ev) {
                .snapshot => |snap| {
                    // Stale-snapshot guard: a panel mutation queued after
                    // the worker captured `seq` isn't in this snapshot —
                    // swapping would revert it. Drop; the next cycle
                    // reloads after the write lands.
                    if (snap.seq == w.mutation_seq.load(.seq_cst)) {
                        self.store.adoptFrom(snap.st);
                        std.log.scoped(.pg_worker).debug("snapshot swapped in: {d} events / {d} alerts", .{ self.store.events.items.len, self.store.alerts.items.len });
                    } else {
                        std.log.scoped(.pg_worker).debug("stale snapshot dropped (seq {d} behind)", .{snap.seq});
                        snap.st.deinit();
                    }
                    self.allocator.destroy(snap.st);
                },
                .state => |st| switch (st) {
                    .connected => ui.events.post(.ok, "db", "PG worker connected — snapshot refresh every {d} s", .{data.pg_worker.REFRESH_MS / 1000}),
                    .reconnecting => ui.events.post(.warn, "db", "PG connection lost — reconnecting", .{}),
                },
                .err => |m| {
                    ui.events.post(.warn, "db", "{s}", .{m});
                    self.allocator.free(m);
                },
            }
        }
    }

    // ── Guided-tour capture harness ──────────────────────────────────────
    //
    // `--tour <dir>` drives the app through a scripted sequence of scenes,
    // mutating the SAME state fields a real click would, and requests frame
    // captures. Stills capture one settled frame; GIF scenes capture a strip
    // the encoder assembles. Everything is deterministic (fixed synthetic dt
    // set by main.zig), so the tour reproduces byte-for-byte.

    pub const TourKind = enum { still, gif };

    pub const TourScene = struct {
        name: []const u8,
        ws: ui.layout.Workspace,
        kind: TourKind,
        /// Frames to hold the scene before/while capturing.
        hold: u32,
        /// First frame (into the hold) to begin capturing.
        cap_from: u32,
        /// Capture every Nth frame from cap_from to hold end.
        cap_stride: u32 = 1,
    };

    pub const tour_scenes = [_]TourScene{
        .{ .name = "01-triage", .ws = .triage, .kind = .still, .hold = 40, .cap_from = 38 },
        .{ .name = "02-alert-select", .ws = .triage, .kind = .still, .hold = 30, .cap_from = 28 },
        .{ .name = "03-hunt", .ws = .hunt, .kind = .still, .hold = 36, .cap_from = 34 },
        .{ .name = "04-timeline-brush", .ws = .hunt, .kind = .gif, .hold = 64, .cap_from = 4, .cap_stride = 3 },
        .{ .name = "05-process-tree", .ws = .hunt, .kind = .still, .hold = 30, .cap_from = 28 },
        .{ .name = "06-detect", .ws = .detect, .kind = .still, .hold = 36, .cap_from = 34 },
        .{ .name = "07-yara-detail", .ws = .detect, .kind = .still, .hold = 30, .cap_from = 28 },
        .{ .name = "08-yara-ci", .ws = .detect, .kind = .gif, .hold = 150, .cap_from = 2, .cap_stride = 7 },
        .{ .name = "09-attack-drill", .ws = .detect, .kind = .still, .hold = 30, .cap_from = 28 },
        .{ .name = "10-intel", .ws = .intel, .kind = .still, .hold = 36, .cap_from = 34 },
        .{ .name = "11-enrich-job", .ws = .intel, .kind = .gif, .hold = 160, .cap_from = 2, .cap_stride = 7 },
        .{ .name = "12-enrich-detail", .ws = .intel, .kind = .still, .hold = 30, .cap_from = 28 },
        .{ .name = "13-pivot", .ws = .intel, .kind = .gif, .hold = 96, .cap_from = 4, .cap_stride = 6 },
        .{ .name = "14-ops", .ws = .ops, .kind = .still, .hold = 36, .cap_from = 34 },
        .{ .name = "15-ai-config", .ws = .ops, .kind = .still, .hold = 30, .cap_from = 28 },
        .{ .name = "16-ai-chat", .ws = .ops, .kind = .gif, .hold = 90, .cap_from = 2, .cap_stride = 5 },
    };

    /// What main.zig should capture this frame (null = capture nothing).
    pub const TourCapture = struct {
        scene: []const u8,
        seq: u32,
        kind: TourKind,
    };

    /// Advance the tour by one frame. Returns a capture request (or null),
    /// and drives the scene's on-screen state. `done` flips true when the
    /// whole tour has been captured.
    pub fn tourFrame(self: *Dashboard, done: *bool) ?TourCapture {
        self.tour_running = true;
        if (self.tour_scene >= tour_scenes.len) {
            done.* = true;
            return null;
        }
        const sc = &tour_scenes[self.tour_scene];
        const local = self.tour_frame;

        if (local == 0) {
            self.tourResetTransient();
            if (ui.layout.active != sc.ws) ui.layout.switchTo(sc.ws);
            self.tourSetup(self.tour_scene);
        }
        self.tourAnimate(self.tour_scene, local);

        var cap: ?TourCapture = null;
        if (local >= sc.cap_from and (local - sc.cap_from) % sc.cap_stride == 0) {
            cap = .{ .scene = sc.name, .seq = self.tour_cap_seq, .kind = sc.kind };
            self.tour_cap_seq += 1;
        }

        self.tour_frame += 1;
        if (self.tour_frame >= sc.hold) {
            self.tour_scene += 1;
            self.tour_frame = 0;
            self.tour_cap_seq = 0;
        }
        return cap;
    }

    /// Clean slate between scenes: drop floated panels and scene-scoped
    /// filters so nothing leaks into the next capture.
    fn tourResetTransient(self: *Dashboard) void {
        self.panel_force_open = @splat(false);
        self.rul_technique_filter = null;
        self.yar_technique_filter = null;
        self.evt_range = null;
        @memset(&self.cmd_buf, 0);
        self.palette_match_count = 0;
    }

    /// One-time state setup when a scene begins.
    fn tourSetup(self: *Dashboard, scene: usize) void {
        const sc = &tour_scenes[scene];
        const s = &self.store;
        if (std.mem.eql(u8, sc.name, "02-alert-select")) {
            self.focusPanel(PANEL_ALQ);
            // Newest open alert for a populated detail view.
            var i = s.alerts.items.len;
            while (i > 0) {
                i -= 1;
                if (s.alerts.items[i].status.isOpen()) {
                    self.alq_sel = s.alerts.items[i].id;
                    break;
                }
            }
        } else if (std.mem.eql(u8, sc.name, "04-timeline-brush")) {
            self.focusPanel(PANEL_TLN);
            self.evt_range = null;
        } else if (std.mem.eql(u8, sc.name, "05-process-tree")) {
            self.focusPanel(PANEL_PRC);
        } else if (std.mem.eql(u8, sc.name, "07-yara-detail")) {
            self.focusPanel(PANEL_YAR);
            self.yar_sel = 2; // Webshell_PHP_Eval_Base64 — shows an FP gate story
        } else if (std.mem.eql(u8, sc.name, "08-yara-ci")) {
            self.focusPanel(PANEL_YAR);
            _ = self.jobs.enqueue(.yara_ci, 0, "all rules", unixNowMs());
        } else if (std.mem.eql(u8, sc.name, "09-attack-drill")) {
            self.focusPanel(PANEL_ATK);
            // Drill T1059.001 (PowerShell) → RUL filter, as a cell click does.
            if (findTechnique("T1059.001")) |tid| {
                self.atk_sel = tid;
                self.rul_technique_filter = tid;
                self.yar_technique_filter = tid;
            }
        } else if (std.mem.eql(u8, sc.name, "11-enrich-job")) {
            self.focusPanel(PANEL_IOC);
            // Queue a handful of unenriched IOCs so verdicts fill on screen.
            var ids: [12]u32 = undefined;
            var n: usize = 0;
            for (s.iocs.items) |*ic| {
                if (n >= ids.len) break;
                if (s.enrichmentForIoc(ic.id) == null) {
                    ids[n] = ic.id;
                    n += 1;
                }
            }
            self.requestEnrichment(ids[0..n]);
        } else if (std.mem.eql(u8, sc.name, "12-enrich-detail")) {
            self.focusPanel(PANEL_ENR);
            // A malicious IP with rich hosting context + pivots.
            self.enr_sel = self.tourFirstVerdict(.malicious) orelse (if (s.enrichments.items.len > 0) s.enrichments.items[0].ioc_id else null);
            self.enr_history_len = 0;
        } else if (std.mem.eql(u8, sc.name, "13-pivot")) {
            self.focusPanel(PANEL_ENR);
            self.enr_sel = self.tourFirstVerdict(.malicious) orelse (if (s.enrichments.items.len > 0) s.enrichments.items[0].ioc_id else null);
            self.enr_history_len = 0;
        } else if (std.mem.eql(u8, sc.name, "15-ai-config")) {
            self.focusPanel(PANEL_AI);
        } else if (std.mem.eql(u8, sc.name, "16-ai-chat")) {
            self.focusPanel(PANEL_AI);
            self.tourSeedChat();
        }
    }

    /// Per-frame animation within a scene (brush sweep, pivot hops, typing).
    fn tourAnimate(self: *Dashboard, scene: usize, local: u32) void {
        const sc = &tour_scenes[scene];
        if (std.mem.eql(u8, sc.name, "04-timeline-brush")) {
            // Sweep a widening brush across the last third of the window.
            const span = data.mock.WORLD_SPAN_MS;
            const base = self.gen.base_ms;
            const start = base - @divFloor(span * 40, 100);
            const grow = @as(i64, local) * @divFloor(span, 240);
            self.evt_range = .{ start, @min(base, start + grow) };
        } else if (std.mem.eql(u8, sc.name, "13-pivot")) {
            // Hop along the pivot chain every ~24 frames.
            if (local > 0 and local % 24 == 0) {
                if (self.enr_sel) |cur| {
                    if (self.store.enrichmentForIoc(cur)) |e| {
                        if (e.pivot_count > 0) {
                            const pick = e.pivot_ids[(local / 24) % e.pivot_count];
                            if (self.enr_history_len < self.enr_history.len) {
                                self.enr_history[self.enr_history_len] = cur;
                                self.enr_history_len += 1;
                            }
                            self.enr_sel = pick;
                        }
                    }
                }
            }
        }
    }

    fn tourExpandLast(self: *Dashboard) void {
        const n = self.assistant.transcript.items.len;
        if (n > 0) self.assistant.transcript.items[n - 1].expanded = true;
    }

    fn tourFirstVerdict(self: *Dashboard, want: domain.Verdict) ?u32 {
        for (self.store.enrichments.items) |*e| {
            if (e.status == .done and e.verdict == want and e.pivot_count > 0) return e.ioc_id;
        }
        return null;
    }

    fn tourSeedChat(self: *Dashboard) void {
        if (self.assistant.transcript.items.len > 0) return; // once
        self.assistant.tour_demo = true;
        self.assistant.mcp_state = .ready;
        self.assistant.last_in_tokens = 1840;
        self.assistant.last_out_tokens = 213;
        self.appendChat(.user, "Is 45.144.68.79 malicious, and do any of our IOCs touch the same hosting?", "", false);
        self.appendChat(.tool_call, "{\"ip\": \"45.144.68.79\"}", "ti_lookup_ip", false);
        self.tourExpandLast();
        self.appendChat(.tool_result, "{\"verdict\": \"malicious\", \"detection_ratio\": \"39/65\", \"reputation\": -43, \"asn\": \"AS44477\", \"as_owner\": \"STARK-INDUSTRIES\", \"country\": \"MD\", \"network\": \"45.144.68.0/24\"}", "ti_lookup_ip", false);
        self.tourExpandLast();
        self.appendChat(.tool_call, "{\"value_contains\": \"44477\"}", "get_iocs", false);
        self.appendChat(.tool_result, "{\"iocs\": [{\"type\": \"domain\", \"value\": \"sync-5512[.]org\", \"verdict\": \"MALICIOUS\"}], \"returned\": 1}", "get_iocs", false);
        self.tourExpandLast();
        self.appendChat(.assistant, "Yes \u{2014} 45.144.68.79 is malicious (39/65 engines, reputation \u{2212}43) hosted on AS44477 STARK-INDUSTRIES in Moldova, a bulletproof-hosting AS. One of your indicators shares it: the domain sync-5512[.]org resolves into the same /24 and is already flagged MALICIOUS. Recommend pivoting on that domain in ENR and checking NET for endpoints that beaconed to either.", "", false);
        self.assistant.scroll_to_bottom = true;
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
        self.pip_sel = null;
        self.cas_notes_edit = null;
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
        // Open PIP's detail + builder + sources sections once, mid-OPS-hold,
        // so those render paths get crash coverage too.
        if (ws == .ops and hold_pos == VALIDATE_HOLD - 24) {
            if (self.store.pipelines.items.len > 0) self.pip_sel = self.store.pipelines.items[0].id;
            self.pip_show_builder = true;
            self.pip_show_sources = true;
            self.panel_focus_request = PANEL_PIP;
        }
        // Float SET + HELP + AI once, late in the OPS hold, for coverage.
        if (ws == .ops and hold_pos == VALIDATE_HOLD - 14) {
            self.panel_force_open[PANEL_SET] = true;
            self.panel_force_open[PANEL_HELP] = true;
            self.panel_force_open[PANEL_AI] = true;
            self.panel_focus_request = PANEL_AI;
        }
        if (ws == .ops and hold_pos == VALIDATE_HOLD - 2) {
            self.panel_force_open[PANEL_SET] = false;
            self.panel_force_open[PANEL_HELP] = false;
            self.panel_force_open[PANEL_AI] = false;
        }
        self.validate_cycle -= 1;
    }

    // ── Frame ────────────────────────────────────────────────────────────

    pub fn render(self: *Dashboard, dt: f32) void {
        self.dt = if (dt > 0) dt else 1.0 / 60.0;
        self.wall_clock_s += @as(f64, self.dt);
        self.ensureAuditHook();

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
        self.tickScheduler();
        self.drainAssistant();
        self.drainPg();

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

        // Ctrl+Shift+A opens the AI assistant.
        if (ctrl and shift and zgui.isKeyPressed(.a, false)) self.focusPanel(PANEL_AI);

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
            self.pip_focus_filter = true;
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
            // An empty line ends any in-progress history walk.
            if (!cmd_active) self.cmd_history_pos = null;
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
                self.pushCmdHistory(text);
                @memset(&self.cmd_buf, 0);
                self.palette_match_count = 0;
                self.cmd_history_pos = null;
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

    /// Record a submitted command for ↑-recall (consecutive dupes skipped).
    fn pushCmdHistory(self: *Dashboard, text: []const u8) void {
        if (text.len == 0) return;
        if (self.cmd_history_len > 0 and
            std.mem.eql(u8, std.mem.sliceTo(&self.cmd_history[0], 0), text)) return;
        var i: usize = @min(self.cmd_history_len, self.cmd_history.len - 1);
        while (i > 0) : (i -= 1) self.cmd_history[i] = self.cmd_history[i - 1];
        @memset(&self.cmd_history[0], 0);
        const n = @min(text.len, self.cmd_history[0].len - 1);
        @memcpy(self.cmd_history[0][0..n], text[0..n]);
        self.cmd_history_len = @min(self.cmd_history_len + 1, self.cmd_history.len);
    }

    fn tickJobs(self: *Dashboard) void {
        var completed: std.ArrayList(data.jobs.Job) = .empty;
        defer completed.deinit(self.allocator);
        self.jobs.tick(self.dt, unixNowMs(), &completed);
        for (completed.items) |*j| {
            ui.events.post(.ok, "jobs", "{s} finished", .{j.kind.label()});
            self.audit_system = true;
            defer self.audit_system = false;
            self.onJobComplete(j);
        }
    }

    /// Enqueue with a toast; dedupes identical kind+arg jobs.
    pub fn enqueueJob(self: *Dashboard, kind: data.jobs.JobKind, arg: u32, detail: []const u8) ?u32 {
        const id = self.jobs.enqueue(kind, arg, detail, unixNowMs());
        if (id != null) {
            ui.events.post(.info, "jobs", "{s} queued{s}{s}", .{
                kind.label(), if (detail.len > 0) " \u{00B7} " else "", detail,
            });
        } else {
            ui.events.post(.warn, "jobs", "{s} already queued/running", .{kind.label()});
        }
        return id;
    }

    /// Cancel + CLEANUP: a canceled job must never strand half-open state
    /// (`.running` run rows, `.pending` enrichments, `.syncing` feeds).
    pub fn cancelJob(self: *Dashboard, id: u32) void {
        const j = self.jobs.find(id) orelse return;
        const snapshot = j.*;
        if (!self.jobs.cancel(id, unixNowMs())) return;
        self.onJobCanceled(&snapshot);
        ui.events.post(.warn, "jobs", "{s} canceled", .{snapshot.kind.label()});
    }

    fn onJobCanceled(self: *Dashboard, j: *const data.jobs.Job) void {
        const now = unixNowMs();
        switch (j.kind) {
            .pipeline_run => {
                // Fail (not strand) this pipeline's in-flight run rows.
                for (self.store.pipeline_runs.items) |*r| {
                    if (r.pipeline != @as(u16, @intCast(j.arg)) or r.status != .running) continue;
                    var run = r.*;
                    run.status = .failed;
                    run.duration_ms = @max(0, now - run.started_ms);
                    run.err = domain.FixedStr(64).from("canceled by analyst");
                    _ = self.store.updatePipelineRun(run);
                }
            },
            .ioc_enrichment => {
                // Pending → err("canceled") so ENR shows its Retry button
                // instead of a forever-stuck progress line.
                for (self.store.enrichments.items) |*e| {
                    if (e.status != .pending) continue;
                    var upd = e.*;
                    upd.status = .err;
                    upd.err = domain.FixedStr(32).from("canceled");
                    _ = self.store.upsertEnrichment(upd);
                }
                for (self.store.urlscans.items) |*u| {
                    if (u.state == .pending) _ = self.store.setUrlScanState(u.id, .err, now);
                }
            },
            .feed_sync => {
                // A canceled sync is NOT a successful one: revert the spinner
                // without stamping last_sync_ms.
                for (self.store.feeds.items) |*f| {
                    if (f.status == .syncing) f.status = .ok;
                }
                self.store.touch();
            },
            else => {},
        }
    }

    /// Job-completion side effects (render thread; panels see the results
    /// next frame via Store.generation).
    fn onJobComplete(self: *Dashboard, j: *const data.jobs.Job) void {
        const now = unixNowMs();
        switch (j.kind) {
            .ioc_enrichment => {
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
            .yara_ci => {
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
            .pipeline_run => {
                // Finalize THIS pipeline's in-flight runs with their
                // deterministic result (pure fn — see mock.pipelineRunResult).
                // Keyed by arg so a completion never touches another
                // pipeline's queued/running rows.
                const pid: u16 = @intCast(j.arg);
                var failed = false;
                var partial = false;
                var i: usize = 0;
                while (i < self.store.pipeline_runs.items.len) : (i += 1) {
                    const r = &self.store.pipeline_runs.items[i];
                    if (r.pipeline != pid or r.status != .running) continue;
                    const result = data.mock.Generator.pipelineRunResult(&self.store, r.*, now);
                    _ = self.store.updatePipelineRun(result);
                    if (result.status == .failed) failed = true;
                    if (result.status == .partial) {
                        partial = true;
                        self.spillDeadLetters(pid, &result, now);
                    }
                }
                if (failed) {
                    self.jobs.markFailed(j.id, "source unreachable");
                    ui.events.post(.warn, "pipeline", "{s} run FAILED \u{2014} see PIP", .{j.detail.slice()});
                } else {
                    self.refreshPipelineTests(pid, now);
                    ui.events.post(
                        if (partial) .warn else .ok,
                        "pipeline",
                        "{s} run completed{s}",
                        .{ j.detail.slice(), if (partial) " with rejected rows — see PIP dead letters" else "" },
                    );
                }
            },
            .feed_sync => {
                // Per-feed (arg = id + 1) or fleet-wide (arg = 0). The
                // err-story feed stays broken: its sync completes as a
                // deterministic failure instead of silently healing.
                var synced: u32 = 0;
                for (self.store.feeds.items) |*f| {
                    if (j.arg != 0 and f.id != j.arg - 1) continue;
                    if (f.status != .syncing) continue;
                    if (std.mem.eql(u8, f.name.slice(), "Emerging Threats")) {
                        f.status = .err;
                        ui.events.post(.warn, "feeds", "{s} sync FAILED: upstream 401 \u{2014} check credentials", .{f.name.slice()});
                    } else {
                        f.status = .ok;
                        f.last_sync_ms = now;
                        synced += 1;
                    }
                }
                self.store.touch();
                if (synced > 0) ui.events.post(.ok, "feeds", "{d} feed(s) synced", .{synced});
            },
            .rule_backtest => {
                // Derived analysis only (no Store writes): surface the
                // noisiest enabled rule so TUN has a pointer.
                var worst: ?*domain.DetectionRule = null;
                for (self.store.rules.items) |*r| {
                    if (r.status != .enabled or r.fires_7d < 10) continue;
                    if (worst == null or r.fpRate() > worst.?.fpRate()) worst = r;
                }
                if (worst) |w| {
                    ui.events.post(.warn, "backtest", "noisiest rule {s} {s}: {d:.0}% FP over 7d \u{2014} see TUN", .{
                        w.code.slice(), w.name.slice(), w.fpRate() * 100,
                    });
                }
            },
            .retention_sweep => {
                // Bounded-history housekeeping (mock mode only — under PG
                // the snapshot refresh owns the row set).
                if (self.mock_ticking) {
                    const runs = self.store.prunePipelineRuns(30);
                    const dlq = self.store.pruneDeadLetters(now - 24 * std.time.ms_per_hour);
                    ui.events.post(.ok, "retention", "sweep: {d} old run(s), {d} resolved dead letter(s) pruned", .{ runs, dlq });
                }
            },
        }
    }

    /// Spill a partial run's rejected rows into the dead-letter queue —
    /// deterministic samples keyed off the pipeline name + run id, capped
    /// so a chronically failing test can't flood the Store.
    fn spillDeadLetters(self: *Dashboard, pid: u16, run: *const domain.PipelineRun, now: i64) void {
        const p = self.store.pipelineById(pid) orelse return;
        if (self.store.openDeadLetterCount(pid) >= 20) return;
        for (p.tests[0..p.test_count]) |*ts| {
            if (ts.status != .fail or ts.failures == 0 or ts.kind == .freshness) continue;
            const hash = std.hash.Fnv1a_64.hash(p.name.slice()) +% run.id;
            var k: u32 = 0;
            while (k < @min(ts.failures, 4)) : (k += 1) {
                _ = self.store.addDeadLetter(.{
                    .id = 0,
                    .pipeline = pid,
                    .run_id = run.id,
                    .ts_ms = now,
                    .kind = ts.kind,
                    .target = ts.target,
                    .sample = domain.FixedStr(96).fromFmt("row #{d}: {s} violated", .{
                        (hash +% k) % 100_000, ts.kind.label(),
                    }),
                });
            }
        }
    }

    /// Recompute freshness tests from the pipeline's watermark after a run:
    /// fresh while the watermark lag stays under 3× the schedule (min 30 m).
    fn refreshPipelineTests(self: *Dashboard, pid: u16, now: i64) void {
        const p = self.store.pipelineById(pid) orelse return;
        var tests = p.tests;
        var changed = false;
        for (tests[0..p.test_count]) |*ts| {
            if (ts.kind != .freshness) continue;
            const limit_min: i64 = @max(@as(i64, p.schedule_min) * 3, 30);
            const fresh = p.watermark_ms > 0 and (now - p.watermark_ms) <= limit_min * std.time.ms_per_min;
            const want: domain.GateResult = if (fresh) .pass else .fail;
            if (ts.status != want) {
                ts.status = want;
                ts.failures = if (fresh) 0 else 1;
                changed = true;
            }
        }
        if (changed) _ = self.store.setPipelineTests(pid, tests, p.test_count);
    }

    /// Pipeline scheduler: auto-enqueue runs for ACTIVE pipelines whose
    /// schedule elapsed. Mock mode only (a real orchestrator owns schedules
    /// under PG) and suppressed inside the validate/tour harnesses so
    /// captures stay reproducible.
    fn tickScheduler(self: *Dashboard) void {
        if (!self.mock_ticking or self.validate_cycle > 0 or self.tour_running) return;
        const now = unixNowMs();
        if (now - self.sched_last_ms < 5_000) return;
        self.sched_last_ms = now;
        self.audit_system = true;
        defer self.audit_system = false;
        for (self.store.pipelines.items) |*p| {
            if (p.status != .active or p.schedule_min == 0) continue;
            if (now - p.last_run_ms < @as(i64, p.schedule_min) * std.time.ms_per_min) continue;
            if (self.jobs.active(.pipeline_run, p.id) != null) continue;
            self.startPipelineRun(p.id, true);
        }
    }

    /// Start a pipeline run: add a `.running` row + queue the job (arg =
    /// pipeline id, so runs for different pipelines execute concurrently
    /// across the engine's slots). Completion finalizes rows/tests/DLQ.
    pub fn startPipelineRun(self: *Dashboard, pipeline_id: u16, scheduled: bool) void {
        const p = self.store.pipelineById(pipeline_id) orelse return;
        if (self.jobs.active(.pipeline_run, pipeline_id) != null) {
            if (!scheduled) ui.events.post(.warn, "pipeline", "{s} already queued/running \u{2014} see JOB", .{p.name.slice()});
            return;
        }
        if (self.store.addPipelineRun(.{ .id = 0, .pipeline = pipeline_id, .started_ms = unixNowMs() })) |_| {
            _ = self.jobs.enqueue(.pipeline_run, pipeline_id, p.name.slice(), unixNowMs());
            ui.events.post(.info, "pipeline", "{s} run {s}", .{
                p.name.slice(), if (scheduled) "scheduled" else "queued",
            });
        }
    }

    /// Back-compat shim for the manual "Run now" path.
    pub fn requestPipelineRun(self: *Dashboard, pipeline_id: u16) void {
        self.startPipelineRun(pipeline_id, false);
    }

    /// Mark IOCs pending + queue the enrichment job. Mock flavor of the
    /// live pipeline: a real MCP source would upsert the same shapes.
    pub fn requestEnrichment(self: *Dashboard, ioc_ids: []const u32) void {
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
        // Dedupe is fine here: pending IOCs ride an already-active job.
        _ = self.jobs.enqueue(.ioc_enrichment, 0, "pending IOCs", unixNowMs());
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
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_PIP, ws), ing_node);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_ING, ws), ing_node);
                zgui.dockBuilderDockWindow(panelWindowName(&nb, PANEL_AUD, ws), job_node);
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
        self.ensureAuditHook();
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
        if (!s.setAlertStatus(first_alert, .acked, unixNowMs())) return error.MutateFailed;
        if (!s.setAlertStatus(first_alert, .new, unixNowMs())) return error.MutateFailed;
        _ = s.triageMeans();

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

        // Pipelines: sources/runs resolve, caps hold, aggregates run.
        if (s.sources.items.len == 0 or s.pipelines.items.len == 0) return error.NoPipelines;
        for (s.pipelines.items) |*p| {
            if (s.sourceById(p.source) == null) return error.PipelineSourceDangling;
            if (p.step_count == 0 or p.step_count > domain.PIPELINE_STEP_CAP) return error.PipelineStepsBad;
            if (p.test_count > domain.PIPELINE_TEST_CAP) return error.PipelineTestsBad;
        }
        for (s.pipeline_runs.items) |*r| {
            if (s.pipelineById(r.pipeline) == null) return error.RunPipelineDangling;
        }
        for (s.dead_letters.items) |*dl| {
            if (s.pipelineById(dl.pipeline) == null) return error.DeadLetterPipelineDangling;
        }
        _ = s.pipelineStatusCounts();
        _ = s.sourceStateCounts();
        _ = s.pipelineTestCounts();
        _ = s.rowsIngestedSince(0);

        // Dead-letter lifecycle round-trip + retention.
        {
            const pid = s.pipelines.items[0].id;
            const dl_id = s.addDeadLetter(.{
                .id = 0,
                .pipeline = pid,
                .run_id = 1,
                .ts_ms = unixNowMs(),
                .kind = .unique,
            }) orelse return error.MutateFailed;
            if (s.openDeadLetterCount(pid) == 0) return error.MutateFailed;
            if (!s.setDeadLetterState(dl_id, .dropped)) return error.MutateFailed;
            _ = s.pruneDeadLetters(unixNowMs() + 1);
        }

        // Full job-completion plumbing: queue a run for the failing-tests
        // pipeline, complete it through onJobComplete — the run finalizes
        // PARTIAL, rejected rows spill to the DLQ, and the audit trail
        // records the whole chain as "system".
        {
            const pid = blk: {
                for (s.pipelines.items) |*p| {
                    if (p.status == .active and p.testCounts().fail > 0) break :blk p.id;
                }
                break :blk s.pipelines.items[0].id;
            };
            const dlq_before = s.openDeadLetterCount(pid);
            self.startPipelineRun(pid, false);
            const job = self.jobs.active(.pipeline_run, pid) orelse return error.JobNotQueued;
            const jcopy = job.*;
            self.audit_system = true;
            self.onJobComplete(&jcopy);
            self.audit_system = false;
            const last = s.lastRunFor(pid) orelse return error.RunMissing;
            if (last.status == .running) return error.RunNotFinalized;
            if (last.status == .partial and s.openDeadLetterCount(pid) <= dlq_before)
                return error.DeadLettersNotSpilled;
            if (self.audit.items.len == 0) return error.AuditSilent;
            for (self.audit.items) |*ae| {
                if (ae.target.len == 0) return error.AuditTargetEmpty;
            }
        }

        // Scheduler tick crash-coverage (deterministic gating asserted by
        // the harness flags; queued work is engine-local).
        self.tickScheduler();

        // Run lifecycle round-trip; the result function must be pure
        // (independent of completion time).
        {
            const pid = s.pipelines.items[0].id;
            _ = s.addPipelineRun(.{ .id = 0, .pipeline = pid, .started_ms = unixNowMs() }) orelse return error.MutateFailed;
            const run = s.lastRunFor(pid).?.*;
            const a = data.mock.Generator.pipelineRunResult(s, run, run.started_ms + 5_000);
            const b = data.mock.Generator.pipelineRunResult(s, run, run.started_ms + 9_000);
            if (a.rows_in != b.rows_in or a.status != b.status or a.rows_rejected != b.rows_rejected)
                return error.PipelineRunNotPure;
            if (!s.updatePipelineRun(a)) return error.MutateFailed;
            if (!s.setPipelineStatus(pid, .paused)) return error.MutateFailed;
            if (!s.setPipelineStatus(pid, .active)) return error.MutateFailed;
            if (!s.recordSourceTest(s.pipelines.items[0].source, .ok, 3.0, unixNowMs())) return error.MutateFailed;
            if (!s.setPipelineTests(pid, s.pipelines.items[0].tests, s.pipelines.items[0].test_count)) return error.MutateFailed;
        }

        // Case-notes editing round-trip.
        {
            const cid = s.cases.items[0].id;
            const before = s.cases.items[0].notes;
            if (!s.setCaseNotes(cid, "selftest probe note", unixNowMs())) return error.MutateFailed;
            if (!std.mem.eql(u8, s.cases.items[0].notes.slice(), "selftest probe note")) return error.MutateFailed;
            if (!s.setCaseNotes(cid, before.slice(), unixNowMs())) return error.MutateFailed;
        }

        // ui_state round-trip through the JSON path.
        if (!self.applyUiStateData("{\"schema_version\":1,\"workspace\":\"hunt\",\"seed\":42}"))
            return error.UiStateRoundTrip;
        ui.layout.switchTo(.triage);

        // AI subsystem offline self-check (pure encode/decode + native tools;
        // no network, no threads).
        try ai.selfTest(self.allocator, &self.store);

        std.log.info("selftest: world {d} events / {d} alerts / {d} rules — data paths OK", .{
            s.events.items.len, s.alerts.items.len, s.rules.items.len,
        });
    }
};

test {
    std.testing.refAllDecls(@This());
}
