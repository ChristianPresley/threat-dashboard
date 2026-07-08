const std = @import("std");
const zgui = @import("zgui");
const ui = @import("ui");
const data = @import("data");
const ai = @import("ai");
const dashboard_mod = @import("dashboard");
const Dashboard = dashboard_mod.Dashboard;
const render = @import("render");

const glfw = render.window;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args_iter = init.minimal.args.iterateAllocator(allocator) catch {
        std.log.err("Failed to initialize argument iterator", .{});
        std.process.exit(1);
    };
    defer args_iter.deinit();

    _ = args_iter.skip();

    var selftest = false;
    var validate_mode = false;
    var screenshot_dir: ?[:0]const u8 = null;
    var show_demo = false;
    var dpi_scale_override: ?f32 = null;
    var seed: u64 = 42;
    var state_dir: [:0]const u8 = ".";
    var win_w: c_int = 1400;
    var win_h: c_int = 900;
    var pg_uri: ?[:0]const u8 = null;
    var do_pgload = false;
    var mcp_check = false;
    var ai_ping = false;
    var tour_dir: ?[:0]const u8 = null;

    while (args_iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "pgload")) {
            // Dev subcommand: bulk-insert a mock world into PostgreSQL so
            // the --pg path is testable without real sensors.
            do_pgload = true;
        } else if (std.mem.eql(u8, arg, "--pg")) {
            // PostgreSQL provider: load the world from this database and
            // write panel actions back to it. Absent ⇒ mock generator.
            pg_uri = args_iter.next();
        } else if (std.mem.eql(u8, arg, "--selftest")) {
            // Headless: mock-world determinism + panel data prep + font atlas
            // + layout round-trip, then exit.
            selftest = true;
        } else if (std.mem.eql(u8, arg, "--mcp-check")) {
            // Headless diagnostic: spawn the threat-intel MCP server, run
            // the initialize handshake + tools/list, print the tool names,
            // then exit. Needs no API keys — validates the stdio client
            // against the real server.
            mcp_check = true;
        } else if (std.mem.eql(u8, arg, "--ai-ping")) {
            // Headless diagnostic (hidden): run one message through the AI
            // worker — TLS to the Anthropic API, encode/parse, channels,
            // clean shutdown. Without a valid ANTHROPIC_API_KEY this still
            // PASSes connectivity when the API's error envelope comes back.
            ai_ping = true;
        } else if (std.mem.eql(u8, arg, "--validate")) {
            // GUI: force-cycle through all workspaces/panels, then auto-exit.
            validate_mode = true;
        } else if (std.mem.eql(u8, arg, "--screenshot")) {
            // GUI: --validate cycling + capture one PNG per workspace into <dir>.
            validate_mode = true;
            screenshot_dir = args_iter.next() orelse "screenshots";
        } else if (std.mem.eql(u8, arg, "--tour")) {
            // GUI: drive a scripted feature tour, capturing numbered PNG
            // frames (stills + GIF strips) into <dir>, then exit. Runs at a
            // fixed synthetic dt so captures are deterministic.
            tour_dir = args_iter.next() orelse "tour";
        } else if (std.mem.eql(u8, arg, "--mailbox")) {
            // Uncapped present mode (MAILBOX). Default is FIFO (vsync) so an
            // idle terminal doesn't burn a CPU core + GPU re-rendering.
            render.setPreferMailbox(true);
        } else if (std.mem.eql(u8, arg, "--demo")) {
            show_demo = true;
        } else if (std.mem.eql(u8, arg, "--seed")) {
            if (args_iter.next()) |s| {
                seed = std.fmt.parseInt(u64, s, 10) catch seed;
            }
        } else if (std.mem.eql(u8, arg, "--state-dir")) {
            // Where layout.ini + ui_state.json live (default: cwd).
            if (args_iter.next()) |d| {
                state_dir = d;
            }
        } else if (std.mem.eql(u8, arg, "--window")) {
            if (args_iter.next()) |spec| {
                var ok = false;
                if (std.mem.indexOfScalar(u8, spec, 'x')) |xi| {
                    const w = std.fmt.parseInt(c_int, spec[0..xi], 10) catch 0;
                    const h = std.fmt.parseInt(c_int, spec[xi + 1 ..], 10) catch 0;
                    if (w >= 320 and h >= 240 and w <= 16_384 and h <= 16_384) {
                        win_w = w;
                        win_h = h;
                        ok = true;
                    }
                }
                if (!ok) std.log.warn("--window: unusable size '{s}' (want WxH, min 320x240) — keeping {d}x{d}", .{ spec, win_w, win_h });
            }
        } else if (std.mem.eql(u8, arg, "--dpi-scale")) {
            // Force a font DPI scale (overrides the monitor content scale).
            if (args_iter.next()) |s| {
                dpi_scale_override = std.fmt.parseFloat(f32, s) catch null;
            }
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            return;
        }
    }

    // Validation/screenshot cycles + the guided tour are frame-count-bounded
    // — run them at MAILBOX rate so a bounded run finishes in ~1s per phase
    // instead of stalling on vsync.
    if (validate_mode or tour_dir != null) render.setPreferMailbox(true);

    // Headless pgload: mock world → PostgreSQL, then exit.
    if (do_pgload) {
        const uri = pg_uri orelse {
            std.log.err("pgload requires --pg <conn-uri> (e.g. postgres://user:pass@localhost:5432/threats)", .{});
            std.process.exit(1);
        };
        var st = data.Store.init(allocator);
        defer st.deinit();
        var gen = data.mock.Generator.init(seed, dashboard_mod.unixNowMs());
        gen.build(&st) catch |err| {
            std.log.err("pgload: mock world build failed: {s}", .{@errorName(err)});
            std.process.exit(1);
        };
        var provider = data.pg.Provider.connect(io, allocator, uri) catch |err| {
            std.log.err("pgload: connect '{s}' failed: {s}", .{ uri, @errorName(err) });
            std.process.exit(1);
        };
        defer provider.deinit();
        provider.migrate() catch std.process.exit(1);
        provider.upload(&st) catch |err| {
            std.log.err("pgload: upload failed: {s}", .{@errorName(err)});
            std.process.exit(1);
        };
        std.log.info("pgload: seed {d} world uploaded to {s}", .{ seed, uri });
        return;
    }

    // Headless MCP diagnostic: handshake + tools/list against the real
    // threat-intel server, then exit (no GUI, no API keys required).
    if (mcp_check) {
        const cfg: ai.Config = .{
            .api_key = "unused",
            .mcp_cmd = init.environ_map.get("TD_MCP_CMD"),
        };
        var argv_buf: [16][]const u8 = undefined;
        const argv = ai.resolveMcpArgv(cfg, &argv_buf);
        std.log.info("mcp-check: spawning '{s}' \u{2026}", .{argv[0]});
        var client = ai.mcp.Client.spawn(allocator, io, argv) catch |err| {
            std.log.err("mcp-check: spawn failed: {s} (is threatintel-mcp installed and on PATH?)", .{@errorName(err)});
            std.process.exit(1);
        };
        defer client.deinit();
        client.handshake() catch |err| {
            std.log.err("mcp-check: handshake failed: {s}", .{@errorName(err)});
            std.process.exit(1);
        };
        std.log.info("mcp-check: handshake OK \u{2014} {d} tool(s):", .{client.tools.items.len});
        for (client.tools.items) |tool| {
            std.log.info("  ti_{s} \u{2014} {s}", .{ tool.name, tool.description[0..@min(tool.description.len, 80)] });
        }
        if (client.tools.items.len == 0) {
            std.log.err("mcp-check: server returned no tools", .{});
            std.process.exit(1);
        }
        std.log.info("mcp-check: PASS", .{});
        return;
    }

    // Headless AI-worker diagnostic: one message through the full stack.
    if (ai_ping) {
        const key = init.environ_map.get("ANTHROPIC_API_KEY") orelse "connectivity-probe-invalid-key";
        const cfg: ai.Config = .{
            .api_key = key,
            .model = init.environ_map.get("TD_AI_MODEL") orelse "claude-sonnet-5",
            .mcp_cmd = init.environ_map.get("TD_MCP_CMD"),
        };
        var argv_buf: [16][]const u8 = undefined;
        const argv = ai.resolveMcpArgv(cfg, &argv_buf);
        const worker = ai.worker.Worker.create(allocator, io, .{
            .api_key = cfg.api_key.?,
            .model = cfg.model,
            .mcp_argv = argv,
            .system_prompt = ai.SYSTEM_PROMPT,
        }) catch {
            std.log.err("ai-ping: worker alloc failed", .{});
            std.process.exit(1);
        };
        defer worker.shutdown();
        std.log.info("ai-ping: sending one message (model {s})\u{2026}", .{cfg.model});
        worker.send("Reply with the single word: pong", null);

        var events: std.ArrayList(ai.worker.WorkerToUi) = .empty;
        defer events.deinit(allocator);
        var api_reachable = false;
        var got_text = false;
        var done = false;
        var waited_ms: u32 = 0;
        while (!done and waited_ms < 90_000) : (waited_ms += 100) {
            std.Io.sleep(io, std.Io.Duration.fromMilliseconds(100), .awake) catch {};
            worker.drain(&events);
            for (events.items) |ev| {
                switch (ev) {
                    .mcp_state => |ms| std.log.info("ai-ping: mcp {s}", .{@tagName(ms)}),
                    .status => |s| std.log.info("ai-ping: status: {s}", .{s}),
                    .assistant_text => |txt| {
                        got_text = true;
                        api_reachable = true;
                        std.log.info("ai-ping: assistant: {s}", .{txt[0..@min(txt.len, 120)]});
                    },
                    .err => |m| {
                        // An API error envelope means TLS + HTTP + parse all
                        // worked — only auth was rejected.
                        api_reachable = std.mem.startsWith(u8, m, "API error:");
                        std.log.info("ai-ping: {s}", .{m});
                    },
                    .turn_done => |t| std.log.info("ai-ping: turn done ({d} in / {d} out tokens)", .{ t.input_tokens, t.output_tokens }),
                    .idle => done = true,
                    else => {},
                }
                ai.worker.freeOutbox(allocator, ev);
            }
            events.clearRetainingCapacity();
        }
        if (got_text) {
            std.log.info("ai-ping: PASS (full round-trip)", .{});
        } else if (api_reachable) {
            std.log.info("ai-ping: PASS (API reachable; key rejected as expected without ANTHROPIC_API_KEY)", .{});
        } else {
            std.log.err("ai-ping: FAIL (API not reachable — TLS/network problem)", .{});
            std.process.exit(1);
        }
        return;
    }

    // Headless self-test: mock-world + panel data paths without Vulkan/GLFW.
    if (selftest) {
        // Own a DebugAllocator so a leak / incorrect-free ESCALATES to a
        // non-zero exit — a CI gate. NOTE: leak tracking needs a safety build
        // (Debug/ReleaseSafe).
        var st_gpa: std.heap.DebugAllocator(.{}) = .init;
        const st_alloc = st_gpa.allocator();
        {
            var st_dash = Dashboard.init(st_alloc, seed);
            defer st_dash.deinit();
            st_dash.selfTest() catch |err| {
                std.log.err("selftest: dashboard data paths FAILED: {s}", .{@errorName(err)});
                std.process.exit(1);
            };
        }
        if (st_gpa.deinit() == .leak) {
            std.log.err("selftest: DebugAllocator reported leak(s) or incorrect free — failing.", .{});
            std.process.exit(1);
        }

        // Font/size atlas stress: push every (face, size) pair in one frame
        // so ImGui 1.92's lazy atlas (grow + re-rasterize, incl. the merged
        // FA icon range) is exercised headlessly.
        zgui.init(allocator);
        zgui.io.setIniFilename(null);
        // ImGui 1.92 lazy atlases assert at render() unless the backend
        // declares texture support — mirror the real backend's flag.
        zgui.io.setBackendFlags(.{ .renderer_has_textures = true });
        // Docking on, mirroring the real context — required by the layout
        // round-trip selftest below (dockSpace asserts without it).
        zgui.io.setConfigFlags(.{ .nav_enable_keyboard = true, .dock_enable = true });
        ui.fonts.load();
        zgui.io.setDisplaySize(800, 600);
        zgui.io.setDeltaTime(1.0 / 60.0);
        zgui.newFrame();
        const sizes = [_]f32{ ui.fonts.size.micro, ui.fonts.size.label, ui.fonts.size.body, ui.fonts.size.hero };
        const faces = [_]zgui.Font{ ui.fonts.mono, ui.fonts.mono_medium, ui.fonts.sans };
        for (faces) |f| {
            for (sizes) |s| {
                zgui.pushFont(f, s);
                zgui.text("0123456789 +1.24% \u{2212}0.87% {s} {s}", .{ ui.fonts.fa.triangle_exclamation, ui.fonts.fa.power_off });
                zgui.popFont();
            }
        }
        zgui.endFrame();
        zgui.render();
        std.log.info("selftest: font atlas cycled {d} faces x {d} sizes — OK", .{ faces.len, sizes.len });

        // Layout persistence round-trip: build a split dockspace, save,
        // reload, save again, byte-compare.
        ui.layout.selfTest() catch |err| {
            std.log.err("selftest: layout round-trip FAILED: {s}", .{@errorName(err)});
            std.process.exit(1);
        };
        std.log.info("selftest: layout round-trip — OK", .{});

        zgui.deinit();
        // The Font handles cached in ui.fonts died with the context above.
        ui.fonts.reset();

        std.log.info("selftest: completed without crashing.", .{});
        return;
    }

    zgui.init(allocator);
    defer zgui.deinit();
    zgui.plot.init();
    defer zgui.plot.deinit();
    // renderer_has_vtx_offset: the backend already passes DrawCmd.vtx_offset
    // to vkCmdDrawIndexed, so declaring it lifts the 64k-vertex-per-window
    // ceiling u16 indices would otherwise impose on dense docked layouts.
    zgui.io.setBackendFlags(.{ .renderer_has_textures = true, .renderer_has_vtx_offset = true });
    zgui.io.setConfigFlags(.{ .nav_enable_keyboard = true, .dock_enable = true });

    // ImGui's own ini writer is DISABLED (manual crash-safe persistence);
    // ui.layout loads/saves this path itself, after the context is fully
    // set up below.
    const layout_ini_path = stateFilePath(state_dir, "layout.ini");

    if (glfw.glfwInit() == 0) {
        std.log.err("Failed to initialize GLFW", .{});
        std.process.exit(1);
    }
    defer glfw.glfwTerminate();

    glfw.glfwWindowHint(glfw.GLFW_CLIENT_API, glfw.GLFW_NO_API);
    glfw.glfwWindowHint(glfw.GLFW_RESIZABLE, glfw.GLFW_TRUE);

    const glfw_window = glfw.glfwCreateWindow(win_w, win_h, "Threat Dashboard", null, null) orelse {
        std.log.err("Failed to create GLFW window", .{});
        std.process.exit(1);
    };
    defer glfw.glfwDestroyWindow(glfw_window);

    // Point the Vulkan loader at the exe directory so it discovers the
    // VkLayer_khronos_validation.json manifest that `zig build vulkan-layers`
    // copies next to the exe. Without this, the loader only checks the
    // system registry/SDK paths and won't pick up the colocated layer.
    setVulkanLayerPath();

    var renderer = try render.Renderer.create(allocator, glfw_window, "threat-dashboard");
    defer renderer.destroy();

    // Geist Mono (data, default) + Geist Sans (prose) + merged FA6 icons.
    // ImGui 1.92 dynamic fonts: any size via pushFont.
    ui.fonts.load();

    // Restore the persisted per-workspace dock layout BEFORE the first
    // NewFrame (ImGui's documented contract for LoadIniSettings) — the
    // atlas pump below is a real frame as far as settings application goes.
    ui.layout.init(layout_ini_path);

    zgui.io.setDisplaySize(1, 1);
    zgui.io.setDeltaTime(1.0 / 60.0);
    zgui.newFrame();
    zgui.endFrame();
    zgui.render();

    const textures = zgui.platform_io.getTextures();
    var atlas_tex: ?*zgui.TextureData = null;
    {
        const count: usize = @intCast(textures.len);
        var i: usize = 0;
        while (i < count) : (i += 1) {
            const t = textures.items[i];
            if (t.status == .want_create) {
                atlas_tex = t;
                break;
            }
        }
    }
    const tex = atlas_tex orelse {
        std.log.err("No want_create texture after pump", .{});
        std.process.exit(1);
    };

    const pixel_count: usize = @as(usize, @intCast(tex.width)) * @as(usize, @intCast(tex.height));
    const bytes_per_pixel: usize = @intCast(tex.bytes_per_pixel);
    const atlas_bytes = tex.pixels[0 .. pixel_count * bytes_per_pixel];

    var alpha8_buf: ?[]u8 = null;
    defer if (alpha8_buf) |b| allocator.free(b);
    const alpha8 = switch (tex.format) {
        .alpha8 => atlas_bytes,
        .rgba32 => blk: {
            const buf = try allocator.alloc(u8, pixel_count);
            var pi: usize = 0;
            while (pi < pixel_count) : (pi += 1) buf[pi] = atlas_bytes[pi * 4 + 3];
            alpha8_buf = buf;
            break :blk buf;
        },
    };

    var imgui_backend = try render.ImGuiBackend.create(allocator, renderer.device, .{
        .render_pass = renderer.render_pass,
        .pipeline_cache = renderer.pipeline_cache.handle,
        .atlas_alpha_pixels = alpha8,
        .atlas_width = @intCast(tex.width),
        .atlas_height = @intCast(tex.height),
    });
    defer imgui_backend.destroy();
    tex.status = .ok;
    tex.tex_id = @enumFromInt(@as(u64, @intFromEnum(imgui_backend.atlas_descriptor)));

    render.imgui_glfw.attach(glfw_window);
    defer render.imgui_glfw.detach(glfw_window);

    ui.theme.apply();

    // Scale fonts to the monitor's OS scale (96 dpi = 1.0). ImGui 1.92's
    // font_scale_dpi re-rasterizes the dynamic atlas at the scaled size —
    // crisp glyphs at 125/150%, not bitmap upscaling.
    {
        var xs: f32 = 1.0;
        var ys: f32 = 1.0;
        glfw.glfwGetWindowContentScale(glfw_window, &xs, &ys);
        const scale = dpi_scale_override orelse xs;
        if (scale > 0.5 and scale < 4.0) {
            zgui.getStyle().font_scale_dpi = scale;
            if (scale != 1.0) std.log.info("font_scale_dpi = {d:.2}", .{scale});
        }
    }

    var dashboard = Dashboard.init(allocator, seed);
    defer dashboard.deinit();
    dashboard.setStateDir(state_dir);
    if (show_demo) dashboard.show_demo_window = true;

    // Restore {workspace, filters, seed} from <state-dir>/ui_state.json.
    dashboard.loadUiState();

    // AI assistant: config from environment (secrets are never persisted).
    // The worker thread is spawned lazily on the first message, so this is
    // a no-op cost until the analyst actually uses the assistant.
    dashboard.configureAssistant(io, .{
        .api_key = init.environ_map.get("ANTHROPIC_API_KEY"),
        .model = init.environ_map.get("TD_AI_MODEL") orelse "claude-sonnet-5",
        .mcp_cmd = init.environ_map.get("TD_MCP_CMD"),
    });

    // PostgreSQL provider: replace the mock world with database truth.
    // Boot is synchronous (connect + migrate + full load — fast fail
    // degrades to the mock world with a critical banner), then the boot
    // connection closes and a background worker owns the DB from there:
    // panel mutations queue to it and it periodically loads fresh
    // snapshots the render thread swaps in (Dashboard.drainPg).
    var pg_worker: ?*data.pg_worker.Worker = null;
    defer if (pg_worker) |w| {
        dashboard.store.write_hook = null;
        dashboard.pg_worker = null;
        w.shutdown();
    };
    if (pg_uri) |uri| {
        if (data.pg.Provider.connect(io, allocator, uri)) |prov| {
            var boot = prov;
            const ok = blk: {
                boot.migrate() catch |err| {
                    ui.events.post(.crit, "db", "PG migrate failed: {s} — running on the mock world", .{@errorName(err)});
                    break :blk false;
                };
                boot.load(&dashboard.store) catch |err| {
                    ui.events.post(.crit, "db", "PG load failed: {s} — running on the mock world", .{@errorName(err)});
                    break :blk false;
                };
                // Chain of custody: restore the persisted audit trail so a
                // restart doesn't blank AUD.
                if (boot.loadAudit(allocator, &dashboard.audit, dashboard_mod.Dashboard.AUDIT_CAP)) |max_id| {
                    dashboard.audit_next_id = max_id + 1;
                } else |err| {
                    ui.events.post(.warn, "db", "audit trail load failed: {s}", .{@errorName(err)});
                }
                break :blk true;
            };
            boot.deinit();
            if (ok) {
                if (data.pg_worker.Worker.create(allocator, io, uri)) |w| {
                    pg_worker = w;
                    w.installHook(&dashboard.store);
                    dashboard.pg_worker = w;
                    dashboard.mock_ticking = false;
                    dashboard.provider_label = "postgresql";
                    ui.events.post(.ok, "db", "PostgreSQL world loaded: {d} events \u{00B7} {d} alerts", .{
                        dashboard.store.events.items.len, dashboard.store.alerts.items.len,
                    });
                } else |err| {
                    ui.events.post(.crit, "db", "PG worker spawn failed: {s} — running on the mock world", .{@errorName(err)});
                    dashboard.regenerateWorld(seed);
                }
            } else {
                dashboard.regenerateWorld(seed);
            }
        } else |err| {
            ui.events.post(.crit, "db", "PG connect failed: {s} — running on the mock world", .{@errorName(err)});
        }
    }

    // GUI validation harness: arm the dashboard's forced workspace cycle
    // and, in screenshot mode, prepare the output directory + check
    // readback support.
    if (validate_mode) {
        dashboard.validate_cycle = Dashboard.VALIDATE_TOTAL;
        // Harness cycling must never clobber the user's saved UI state —
        // neither ui_state.json nor layout.ini.
        dashboard.ui_state_save_suppressed = true;
        ui.layout.save_suppressed = true;
        if (screenshot_dir) |dir| {
            std.Io.Dir.cwd().createDirPath(io, dir) catch |err| {
                std.log.warn("screenshot: could not create '{s}': {} — degrading to --validate.", .{ dir, err });
                screenshot_dir = null;
            };
            if (!renderer.swapchain.readback) {
                std.log.warn("screenshot: swapchain lacks TRANSFER_SRC; degrading to --validate.", .{});
                screenshot_dir = null;
            }
        }
    }

    // GUI tour harness: prepare the output dir + suppress persistence so the
    // scripted run never clobbers the user's saved layout/state.
    if (tour_dir) |dir| {
        dashboard.ui_state_save_suppressed = true;
        ui.layout.save_suppressed = true;
        std.Io.Dir.cwd().createDirPath(io, dir) catch |err| {
            std.log.err("tour: could not create '{s}': {}", .{ dir, err });
            tour_dir = null;
        };
        if (tour_dir != null and !renderer.swapchain.readback) {
            std.log.err("tour: swapchain lacks TRANSFER_SRC — cannot capture.", .{});
            tour_dir = null;
        }
    }

    // Fullscreen-toggle state: stash windowed pos+size so F11 restores them.
    var is_fullscreen: bool = false;
    var saved_x: c_int = 0;
    var saved_y: c_int = 0;
    var saved_w: c_int = win_w;
    var saved_h: c_int = win_h;
    var f11_was_down: bool = false;

    var last_time = glfw.glfwGetTime();
    var frame_no: u32 = 0;
    while (glfw.glfwWindowShouldClose(glfw_window) == 0) {
        // Validation harness (--validate / --screenshot): the dashboard
        // force-cycles workspaces; once the cycle is spent, exit cleanly so
        // a headless run confirms no render-path crash on any panel.
        frame_no += 1;
        if (validate_mode and dashboard.validate_cycle == 0 and frame_no > Dashboard.VALIDATE_TOTAL) {
            std.debug.print("[validate] rendered {d} frames force-cycling {d} workspaces + {d} panels -> NO CRASH\n", .{
                frame_no - 1, ui.layout.workspace_count, @import("dashboard").registry_panel_count,
            });
            break;
        }
        glfw.glfwPollEvents();
        render.imgui_glfw.updateMouseCursor(glfw_window);

        // F11 toggles between windowed + borderless-fullscreen on the
        // primary monitor. Vulkan handles the swapchain recreation via the
        // existing out-of-date/suboptimal acquire path.
        const f11_now = glfw.glfwGetKey(glfw_window, glfw.GLFW_KEY_F11) == glfw.GLFW_PRESS;
        if (f11_now and !f11_was_down) {
            if (!is_fullscreen) {
                glfw.glfwGetWindowPos(glfw_window, &saved_x, &saved_y);
                glfw.glfwGetWindowSize(glfw_window, &saved_w, &saved_h);
                if (glfw.glfwGetPrimaryMonitor()) |mon| {
                    if (glfw.glfwGetVideoMode(mon)) |mode| {
                        glfw.glfwSetWindowMonitor(
                            glfw_window,
                            mon,
                            0,
                            0,
                            mode.width,
                            mode.height,
                            mode.refresh_rate,
                        );
                        is_fullscreen = true;
                    }
                }
            } else {
                glfw.glfwSetWindowMonitor(
                    glfw_window,
                    null,
                    saved_x,
                    saved_y,
                    saved_w,
                    saved_h,
                    glfw.GLFW_DONT_CARE,
                );
                is_fullscreen = false;
            }
        }
        f11_was_down = f11_now;

        var fb_w: c_int = 0;
        var fb_h: c_int = 0;
        glfw.glfwGetFramebufferSize(glfw_window, &fb_w, &fb_h);
        if (fb_w == 0 or fb_h == 0) continue;

        const now = glfw.glfwGetTime();
        // The tour runs at a FIXED synthetic dt so animations (job progress,
        // brush sweep) are byte-reproducible regardless of frame timing. At
        // dt=1/12 a mock job (progress += dt*0.12) completes in ~100 frames,
        // which the job scenes are sized to capture start→finish.
        const dt: f32 = if (tour_dir != null) 1.0 / 12.0 else blk: {
            const d: f32 = @floatCast(now - last_time);
            break :blk if (d > 0) d else 1.0 / 60.0;
        };
        last_time = now;

        zgui.io.setDisplaySize(@floatFromInt(fb_w), @floatFromInt(fb_h));
        zgui.io.setDeltaTime(dt);

        // Guided tour: drive the scripted scene state + decide capture.
        var tour_cap: ?Dashboard.TourCapture = null;
        if (tour_dir != null) {
            var tour_done = false;
            tour_cap = dashboard.tourFrame(&tour_done);
            if (tour_done) {
                std.log.info("tour: complete", .{});
                break;
            }
        }

        // Decide BEFORE dashboard.render (which decrements validate_cycle)
        // whether to capture this frame: late in each workspace's hold
        // window, so lazy loads and animations have settled.
        const cycle_before = dashboard.validate_cycle;
        const forced_ws = dashboard.forcedWorkspace();
        const hold_pos = (Dashboard.VALIDATE_TOTAL -| cycle_before) % Dashboard.VALIDATE_HOLD;
        const capture_this_frame = screenshot_dir != null and forced_ws != null and
            hold_pos == Dashboard.VALIDATE_HOLD - 8;

        zgui.newFrame();
        dashboard.render(dt);
        zgui.render();

        const ctx_opt = try renderer.beginFrame(.{ 0.06, 0.06, 0.10, 1.0 });
        const ctx = ctx_opt orelse continue;
        errdefer renderer.abortFrame(ctx);

        try imgui_backend.render(ctx.cmd, ctx.extent, ctx.frame_index);
        if (tour_cap) |tc| {
            const cap = try renderer.endFrameCapture(ctx, allocator);
            defer allocator.free(cap.pixels);
            var name_buf: [80]u8 = undefined;
            const base = std.fmt.bufPrint(&name_buf, "{s}-{d:0>3}", .{ tc.scene, tc.seq }) catch "tour";
            writeScreenshot(allocator, io, tour_dir.?, base, cap);
        } else if (capture_this_frame) {
            const cap = try renderer.endFrameCapture(ctx, allocator);
            defer allocator.free(cap.pixels);
            var name_buf: [64]u8 = undefined;
            const ws = forced_ws.?;
            const base = std.fmt.bufPrint(&name_buf, "ws-{d}-{s}", .{ @intFromEnum(ws), ws.tag() }) catch "ws";
            writeScreenshot(allocator, io, screenshot_dir.?, base, cap);
        } else {
            try renderer.endFrame(ctx);
        }
    }

    // Clean exit: persist the dock layout (autosave only covers dirty+60 s
    // and workspace switches) + the core UI state.
    ui.layout.saveNow();
    dashboard.saveUiState();
}

/// Compose `<state-dir>/<name>` (static storage) and DISABLE ImGui's own
/// ini handling — persistence is manual via ui.layout (load at boot, atomic
/// tmp+rename saves).
fn stateFilePath(dir: []const u8, name: []const u8) [:0]const u8 {
    const S = struct {
        var buf: [512:0]u8 = undefined;
    };
    zgui.io.setIniFilename(null);
    return std.fmt.bufPrintZ(&S.buf, "{s}/{s}", .{ dir, name }) catch "layout.ini";
}

/// Encode a captured frame as PNG and write it to `<dir>/<base>.png`.
/// Best-effort: failures log a warning; the validation cycle keeps going.
fn writeScreenshot(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    base: []const u8,
    cap: render.Renderer.Capture,
) void {
    const png_bytes = render.png.encodeRgba(allocator, cap.pixels, cap.width, cap.height) catch |err| {
        std.log.warn("screenshot: PNG encode failed: {}", .{err});
        return;
    };
    defer allocator.free(png_bytes);

    var path_buf: [256]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}/{s}.png", .{ dir, base }) catch return;
    std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = png_bytes }) catch |err| {
        std.log.warn("screenshot: write '{s}' failed: {}", .{ path, err });
        return;
    };
    std.log.info("screenshot: wrote {s} ({d}x{d})", .{ path, cap.width, cap.height });
}

/// Set VK_LAYER_PATH to the directory of the running executable. If
/// build.zig copied VkLayer_khronos_validation.{dll,json} there (i.e. the
/// developer has the LunarG SDK installed), the Vulkan loader will pick it
/// up and the renderer's Debug build will run with validation enabled.
fn setVulkanLayerPath() void {
    var buf: [windows.MAX_PATH:0]u16 = undefined;
    const n = windows.GetModuleFileNameW(null, &buf, buf.len);
    if (n == 0 or n >= buf.len) return;

    // Trim filename off the path: walk back to the last '\\'.
    var end: usize = n;
    while (end > 0) : (end -= 1) {
        if (buf[end - 1] == '\\') {
            end -= 1;
            break;
        }
    }
    buf[end] = 0;

    const name = std.unicode.utf8ToUtf16LeStringLiteral("VK_LAYER_PATH");
    _ = windows.SetEnvironmentVariableW(name, buf[0..end :0]);
}

const windows = struct {
    const MAX_PATH = 260;
    extern "kernel32" fn GetModuleFileNameW(
        hModule: ?*anyopaque,
        lpFilename: [*]u16,
        nSize: u32,
    ) callconv(.winapi) u32;
    extern "kernel32" fn SetEnvironmentVariableW(
        lpName: [*:0]const u16,
        lpValue: ?[*:0]const u16,
    ) callconv(.winapi) i32;
};

fn printUsage() void {
    const usage =
        \\Threat Dashboard — threat hunting, detection & management
        \\
        \\Usage:
        \\  threat-dashboard [options]
        \\
        \\Subcommands:
        \\  pgload --pg <uri>   Bulk-insert a mock world into PostgreSQL, then exit
        \\
        \\Options:
        \\  --pg <conn-uri>     Read the world from PostgreSQL (postgres://user:pass@host/db)
        \\  --seed <u64>        Mock-world seed (default 42; same seed = same world)
        \\  --state-dir <dir>   Where layout.ini + ui_state.json live (default: cwd)
        \\  --selftest          Headless data-path self-test, then exit
        \\  --mcp-check         Spawn the threat-intel MCP server, list its tools, exit
        \\  --validate          Force-cycle all workspaces for a bounded run, then exit
        \\  --screenshot <dir>  --validate + write one PNG per workspace into <dir>
        \\  --tour <dir>        Drive a scripted feature tour, capturing frames into <dir>, then exit
        \\  --mailbox           Uncapped MAILBOX presentation (default: FIFO vsync)
        \\  --demo              Show the ImPlot-bindings demo window
        \\  --window <WxH>      Initial window size, e.g. 1280x800 (default 1400x900)
        \\  --dpi-scale <f>     Force font DPI scale (default: monitor content scale)
        \\
    ;
    std.debug.print("{s}", .{usage});
}
