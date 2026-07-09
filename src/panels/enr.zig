//! ENR · IOC Enrichment: a detail + pivot view for one IOC — verdict,
//! detection stats, reputation, whois/ASN/hosting context, url-scan
//! lifecycle, and a pivot table of contacted indicators. Indicators are
//! shown defanged (OPSEC); click copies the raw (refanged) value.
//! Enrichment is mock by default; a live threatintel-mcp source upserts the
//! same shapes.

const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const domain = @import("domain");
const dash = @import("../dashboard.zig");
const Dashboard = dash.Dashboard;

fn pivotTo(d: *Dashboard, id: u32) void {
    // Push current selection onto the breadcrumb, then follow the pivot.
    if (d.enr_sel) |cur| {
        if (d.enr_history_len < d.enr_history.len) {
            d.enr_history[d.enr_history_len] = cur;
            d.enr_history_len += 1;
        }
    }
    d.enr_sel = id;
}

/// Create a urlscan submission and queue its own url_scan job (arg = scan
/// id) — independent of enrichment batches, so canceling one never kills
/// the other.
fn submitScan(d: *Dashboard, ioc_id: u32) void {
    const scan_id = d.store.submitUrlScan(ioc_id, dash.unixNowMs()) orelse return;
    var db: [24]u8 = undefined;
    const detail = std.fmt.bufPrint(&db, "scan #{d}", .{scan_id}) catch "scan";
    _ = d.jobs.enqueue(.url_scan, scan_id, detail, dash.unixNowMs());
    ui.events.post(.info, "urlscan", "submission #{d} queued (unlisted)", .{scan_id});
}

fn copyIocValue(ty: domain.IocType, value: []const u8) void {
    var copy_buf: [200:0]u8 = undefined;
    if (ui.prefs.current.defang_copy) {
        var df: [180]u8 = undefined;
        const safe = domain.defang(&df, ty, value);
        const cz = std.fmt.bufPrintZ(&copy_buf, "{s}", .{safe}) catch "";
        zgui.setClipboardText(cz);
        ui.events.post(.ok, "intel", "IOC copied DEFANGED (raw copy: SET \u{2192} Time & tables)", .{});
    } else {
        const cz = std.fmt.bufPrintZ(&copy_buf, "{s}", .{value}) catch "";
        zgui.setClipboardText(cz);
        ui.events.post(.ok, "intel", "raw IOC value copied to clipboard", .{});
    }
}

pub fn render(d: *Dashboard) void {
    const t = ui.theme.active;
    const s = &d.store;

    // ── Header: selected IOC (defanged) + breadcrumb back ────────────────
    // Default to the first enriched indicator so the panel is useful on open.
    if (d.enr_sel == null and s.enrichments.items.len > 0) {
        d.enr_sel = s.enrichments.items[0].ioc_id;
    }
    const sel = d.enr_sel orelse {
        zgui.textColored(t.text.lo, "No IOC selected.", .{});
        zgui.spacing();
        zgui.textWrapped("Select a row in IOC (the Verdict column links here), or use \"Enrich shown\" in the IOC panel. Enrichment covers verdict, detection ratio, reputation, hosting/whois context, url scans, and pivots to contacted indicators.", .{});
        return;
    };
    const ic = s.iocById(sel) orelse {
        d.enr_sel = null;
        return;
    };

    if (d.enr_history_len > 0) {
        if (zgui.smallButton("\u{2190} back##enr")) {
            d.enr_history_len -= 1;
            d.enr_sel = d.enr_history[d.enr_history_len];
            return;
        }
        zgui.sameLine(.{ .spacing = 10 });
    }
    zgui.textColored(t.text.lo, "{s}", .{ic.type.label()});
    zgui.sameLine(.{ .spacing = 6 });
    var fbuf: [200]u8 = undefined;
    const shown = domain.defang(&fbuf, ic.type, ic.value.slice());
    var vlbl: [220]u8 = undefined;
    const vz = std.fmt.bufPrintZ(&vlbl, "{s}##enrval", .{shown}) catch "##enrval";
    if (zgui.smallButton(vz)) copyIocValue(ic.type, ic.value.slice());
    if (zgui.isItemHovered(.{})) {
        if (zgui.beginTooltip()) {
            const copy_hint: [:0]const u8 = if (ui.prefs.current.defang_copy)
                "click to copy (defanged \u{2014} raw copy toggles in SET)"
            else
                "click to copy the raw (refanged) value";
            zgui.textUnformattedColored(t.text.lo, copy_hint);
            zgui.endTooltip();
        }
    }
    zgui.sameLine(.{ .spacing = 8 });
    const conf_col = if (ic.confidence >= 80) t.sev.ok else if (ic.confidence >= 50) t.sev.warn else t.text.lo;
    zgui.textColored(conf_col, "conf {d}", .{ic.confidence});
    zgui.separator();

    // ── Status line ──────────────────────────────────────────────────────
    const enr = s.enrichmentForIoc(sel);
    const status: domain.EnrichStatus = if (enr) |e| e.status else .none;
    switch (status) {
        .none => {
            zgui.textColored(t.text.lo, "not enriched", .{});
            zgui.sameLine(.{ .spacing = 10 });
            if (zgui.smallButton("Enrich now##enr")) {
                d.requestEnrichment(&.{sel});
            }
            return;
        },
        .pending => {
            if (d.jobs.active(.ioc_enrichment, 0)) |job| {
                zgui.textColored(t.sev.warn, "{s} enrichment {s}\u{2026} {d:.0}%", .{
                    ui.fonts.fa.arrows_rotate, if (job.state == .queued) "queued" else "pending", job.progress * 100,
                });
            } else {
                // No job carries this pending row (canceled/stalled) —
                // offer recovery instead of a forever-spinner.
                zgui.textColored(t.sev.warn, "enrichment stalled \u{2014} no job in flight", .{});
                zgui.sameLine(.{ .spacing = 10 });
                if (zgui.smallButton("Retry##enrstall")) d.requestEnrichment(&.{sel});
            }
            return;
        },
        .err => {
            zgui.textColored(t.sev.crit, "enrichment error: {s}", .{enr.?.err.slice()});
            zgui.sameLine(.{ .spacing = 10 });
            if (zgui.smallButton("Retry##enr")) d.requestEnrichment(&.{sel});
            return;
        },
        .done => {},
    }
    const e = enr.?;

    // ── Verdict block ────────────────────────────────────────────────────
    zgui.textColored(dash.verdictColor(e.verdict), "{s}", .{e.verdict.label()});
    zgui.sameLine(.{ .spacing = 10 });
    const ratio = e.detRatio();
    zgui.textColored(t.text.mid, "detections {d}/{d}", .{ ratio.hit, ratio.total });
    zgui.sameLine(.{ .spacing = 8 });
    {
        const frac: f32 = if (ratio.total > 0)
            @as(f32, @floatFromInt(ratio.hit)) / @as(f32, @floatFromInt(ratio.total))
        else
            0;
        zgui.pushStyleColor4f(.{ .idx = .plot_histogram, .c = dash.verdictColor(e.verdict) });
        zgui.setNextItemWidth(120);
        var pb: [16]u8 = undefined;
        const pz = std.fmt.bufPrintZ(&pb, "{d:.0}%", .{frac * 100}) catch "";
        zgui.progressBar(.{ .fraction = frac, .overlay = pz });
        zgui.popStyleColor(.{ .count = 1 });
    }
    zgui.textColored(t.text.lo, "malicious {d} \u{00B7} suspicious {d} \u{00B7} harmless {d} \u{00B7} undetected {d}", .{
        e.det_malicious, e.det_suspicious, e.det_harmless, e.det_undetected,
    });
    // Reputation + threat label on their own line so a long label can't be
    // clipped by the panel edge.
    zgui.textColored(if (e.reputation < 0) t.sev.crit else t.text.mid, "reputation {d}", .{e.reputation});
    if (e.threat_label.len > 0) {
        zgui.sameLine(.{ .spacing = 12 });
        zgui.textColored(t.sev.serious, "threat: {s}", .{e.threat_label.slice()});
    }
    {
        var b1: [20]u8 = undefined;
        var b2: [20]u8 = undefined;
        zgui.textColored(t.text.lo, "first seen {s} \u{00B7} last seen {s} \u{00B7} src {s}", .{
            ui.fmt.tsDate(&b1, @divFloor(e.first_seen_ms, 1000)),
            ui.fmt.tsDate(&b2, @divFloor(e.last_seen_ms, 1000)),
            e.source.label(),
        });
    }
    zgui.separator();

    // ── Type-specific context ────────────────────────────────────────────
    switch (ic.type) {
        .domain => {
            zgui.textColored(t.text.mid, "registrar {s}", .{if (e.registrar.len > 0) e.registrar.slice() else "\u{2014}"});
            if (e.creation_ms > 0) {
                const age_days = @divFloor(dash.unixNowMs() - e.creation_ms, std.time.ms_per_day);
                zgui.sameLine(.{ .spacing = 12 });
                var cb: [20]u8 = undefined;
                zgui.textColored(t.text.lo, "created {s}", .{ui.fmt.tsDate(&cb, @divFloor(e.creation_ms, 1000))});
                if (age_days < 30) {
                    zgui.sameLine(.{ .spacing = 6 });
                    zgui.textColored(t.sev.warn, "[NRD \u{00B7} {d}d old]", .{age_days});
                }
            }
            if (e.categories.len > 0) zgui.textColored(t.text.lo, "categories: {s}", .{e.categories.slice()});
        },
        .ip => {
            zgui.textColored(t.text.mid, "AS{d} {s} \u{00B7} {s} \u{00B7} {s}", .{
                e.asn,
                if (e.as_owner.len > 0) e.as_owner.slice() else "\u{2014}",
                if (e.country.len > 0) e.country.slice() else "\u{2014}",
                if (e.network.len > 0) e.network.slice() else "\u{2014}",
            });
        },
        .url => {
            const score_col = if (e.scan_score >= 70) t.sev.crit else if (e.scan_score >= 40) t.sev.warn else t.sev.ok;
            zgui.textColored(score_col, "scan score {d}/100", .{e.scan_score});
            if (e.brands.len > 0) {
                zgui.sameLine(.{ .spacing = 12 });
                zgui.textColored(t.sev.serious, "impersonates {s}", .{e.brands.slice()});
            }
            var pib: [64]u8 = undefined;
            const page_ip_defanged = domain.defang(&pib, .ip, e.page_ip.slice());
            zgui.textColored(t.text.lo, "page {s} \u{00B7} {s} \u{00B7} TLS {s}", .{
                if (e.page_domain.len > 0) e.page_domain.slice() else "\u{2014}",
                page_ip_defanged,
                if (e.tls_issuer.len > 0) e.tls_issuer.slice() else "\u{2014}",
            });
            // Screenshot placeholder well — a live source drops an image here.
            zgui.pushStyleColor4f(.{ .idx = .child_bg, .c = t.bg.sunken });
            if (zgui.beginChild("##enr_shot", .{ .h = 40 })) {
                zgui.textColored(t.text.lo, "  [ screenshot \u{2014} live urlscan source populates this ]", .{});
            }
            zgui.endChild();
            zgui.popStyleColor(.{ .count = 1 });

            // urlscan submission lifecycle.
            if (s.urlScanForIoc(sel)) |scan| {
                var ab: [16]u8 = undefined;
                const age_s = @divFloor(dash.unixNowMs() - scan.submitted_ms, 1000);
                const scan_col = switch (scan.state) {
                    .done => t.sev.ok,
                    .err => t.sev.crit,
                    else => t.sev.warn,
                };
                zgui.textColored(scan_col, "urlscan: {s}", .{scan.state.label()});
                if (scan.state == .err and scan.err.len > 0) {
                    zgui.sameLine(.{ .spacing = 6 });
                    zgui.textColored(t.sev.crit, "({s})", .{scan.err.slice()});
                }
                zgui.sameLine(.{ .spacing = 6 });
                zgui.textColored(t.text.lo, "submitted {s} ago", .{ui.fmt.age(&ab, age_s)});
                // A failed scan is retryable — a fresh submission supersedes
                // the errored one (urlScanForIoc returns the latest).
                if (scan.state == .err) {
                    zgui.sameLine(.{ .spacing = 10 });
                    if (zgui.smallButton("Resubmit##enrscan")) submitScan(d, sel);
                }
            } else {
                if (zgui.smallButton("Submit to urlscan##enr")) submitScan(d, sel);
            }
        },
        .hash_sha256, .email => {},
    }

    // ── Pivot table: contacted indicators ────────────────────────────────
    if (e.pivot_count == 0) return;
    zgui.separator();
    zgui.textColored(t.text.lo, "contacted indicators ({d}) \u{00B7} click to pivot", .{e.pivot_count});

    const flags = zgui.TableFlags{ .resizable = true, .borders = .{ .inner_h = true }, .scroll_y = true };
    if (zgui.beginTable("##enr_pivots", .{ .column = 4, .flags = flags })) {
        zgui.tableSetupColumn("Type", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 62 });
        zgui.tableSetupColumn("Value", .{ .flags = .{ .width_stretch = true } });
        zgui.tableSetupColumn("Conf", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 44 });
        zgui.tableSetupColumn("Verdict", .{ .flags = .{ .width_fixed = true }, .init_width_or_height = 96 });
        zgui.tableSetupScrollFreeze(0, 1);
        zgui.tableHeadersRow();

        for (e.pivot_ids[0..e.pivot_count]) |pid| {
            const pic = s.iocById(pid) orelse continue;
            zgui.tableNextRow(.{});
            _ = zgui.tableNextColumn();
            zgui.textColored(t.text.mid, "{s}", .{pic.type.label()});
            _ = zgui.tableNextColumn();
            var pb: [200]u8 = undefined;
            const pdef = domain.defang(&pb, pic.type, pic.value.slice());
            var plbl: [220]u8 = undefined;
            const pz = std.fmt.bufPrintZ(&plbl, "{s}##enrpiv{d}", .{ pdef, pid }) catch continue;
            if (zgui.selectable(pz, .{})) pivotTo(d, pid);
            _ = zgui.tableNextColumn();
            zgui.textColored(t.text.lo, "{d}", .{pic.confidence});
            _ = zgui.tableNextColumn();
            if (s.enrichmentForIoc(pid)) |pe| {
                zgui.textColored(dash.verdictColor(pe.verdict), "{s}", .{pe.verdict.label()});
            } else {
                zgui.textColored(t.text.lo, "\u{2014}", .{});
            }
        }
        zgui.endTable();
    }
}
