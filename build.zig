const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zgui_dep = b.dependency("zgui", .{
        .target = target,
        .optimize = optimize,
        .backend = .no_backend,
        .with_implot = true,
        .with_te = false,
    });

    const zglfw_dep = b.dependency("zglfw", .{
        .target = target,
        .optimize = optimize,
    });

    // -- UI foundation module (design tokens, fonts, layout/docking,
    // registry, formatting, safety-interlock timing) --
    const ui_mod = b.createModule(.{
        .root_source_file = b.path("src/ui/ui.zig"),
        .imports = &.{
            .{ .name = "zgui", .module = zgui_dep.module("root") },
        },
    });

    // -- Render module (Vulkan renderer + ImGui backend + input bridge) --
    const render_mod = b.createModule(.{
        .root_source_file = b.path("src/render/render.zig"),
        .imports = &.{
            .{ .name = "zgui", .module = zgui_dep.module("root") },
        },
    });

    // -- Domain model (std-only: alerts, events, rules, IOCs, cases,
    // sensors, ATT&CK technique table) --
    const domain_mod = b.createModule(.{
        .root_source_file = b.path("src/domain/model.zig"),
    });

    // -- PostgreSQL client (pure Zig; no libpq) --
    const pg_dep = b.dependency("pg", .{
        .target = target,
        .optimize = optimize,
    });

    // -- Data layer (in-memory Store + deterministic mock generator + the
    // Postgres provider behind the same Store) --
    const data_mod = b.createModule(.{
        .root_source_file = b.path("src/data/store.zig"),
        .imports = &.{
            .{ .name = "domain", .module = domain_mod },
            .{ .name = "pg", .module = pg_dep.module("pg") },
        },
    });

    // -- Dashboard orchestrator (panel registry, workspaces, dock presets,
    // hotkeys, per-panel renderers) --
    const dashboard_mod = b.createModule(.{
        .root_source_file = b.path("src/dashboard.zig"),
        .imports = &.{
            .{ .name = "zgui", .module = zgui_dep.module("root") },
            .{ .name = "ui", .module = ui_mod },
            .{ .name = "domain", .module = domain_mod },
            .{ .name = "data", .module = data_mod },
        },
    });

    // -- Main executable --
    const exe = b.addExecutable(.{
        .name = "threat-dashboard",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "zgui", .module = zgui_dep.module("root") },
                .{ .name = "ui", .module = ui_mod },
                .{ .name = "render", .module = render_mod },
                .{ .name = "dashboard", .module = dashboard_mod },
                .{ .name = "domain", .module = domain_mod },
                .{ .name = "data", .module = data_mod },
            },
        }),
    });

    exe.root_module.linkLibrary(zgui_dep.artifact("imgui"));
    exe.root_module.linkLibrary(zglfw_dep.artifact("glfw"));

    exe.root_module.linkSystemLibrary("gdi32", .{});
    exe.root_module.linkSystemLibrary("user32", .{});
    exe.root_module.linkSystemLibrary("shell32", .{});

    b.installArtifact(exe);

    // -- LunarG Vulkan SDK validation layer install (Debug builds only) --
    //
    // The LunarG SDK is declared as an external requirement in build.zig.zon.
    // When the `VULKAN_SDK` env var points at a local install, copy the
    // validation layer DLL + manifest next to the exe so the Vulkan loader
    // picks them up regardless of registry state. Runtime code sets
    // VK_LAYER_PATH to the exe dir before instance creation so this
    // colocated layer is found.
    const vulkan_layers_step = b.step("vulkan-layers", "Copy LunarG validation layer next to the exe (requires VULKAN_SDK)");
    if (b.graph.environ_map.get("VULKAN_SDK")) |sdk_path| {
        const sdk_lazy = std.Build.LazyPath{ .cwd_relative = b.pathJoin(&.{ sdk_path, "Bin" }) };
        const install_layer_dll = b.addInstallBinFile(
            sdk_lazy.path(b, "VkLayer_khronos_validation.dll"),
            "VkLayer_khronos_validation.dll",
        );
        const install_layer_json = b.addInstallBinFile(
            sdk_lazy.path(b, "VkLayer_khronos_validation.json"),
            "VkLayer_khronos_validation.json",
        );
        vulkan_layers_step.dependOn(&install_layer_dll.step);
        vulkan_layers_step.dependOn(&install_layer_json.step);
        // Auto-install with the main exe only in Debug — Release builds
        // don't request validation, so shipping the DLL would be wasted bytes.
        if (optimize == .Debug) {
            b.getInstallStep().dependOn(&install_layer_dll.step);
            b.getInstallStep().dependOn(&install_layer_json.step);
        }
    } else {
        const warn_step = b.addSystemCommand(&.{
            "cmd", "/c",
            "echo VULKAN_SDK env var not set. Install the LunarG Vulkan SDK ^(https://vulkan.lunarg.com/sdk/home^) and re-run.",
        });
        vulkan_layers_step.dependOn(&warn_step.step);
    }

    // -- Run step --
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run the threat dashboard");
    run_step.dependOn(&run_cmd.step);

    // -- Tests --
    // UI foundation tests (tokens, formatting, interlock timing). Links the
    // imgui lib because refAllDecls reaches the zgui style/io externs.
    const test_ui = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/ui/ui.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "zgui", .module = zgui_dep.module("root") },
            },
        }),
    });
    test_ui.root_module.linkLibrary(zgui_dep.artifact("imgui"));

    const test_domain = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/domain/model.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const test_data = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/data/store.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "domain", .module = domain_mod },
                .{ .name = "pg", .module = pg_dep.module("pg") },
            },
        }),
    });

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(test_ui).step);
    test_step.dependOn(&b.addRunArtifact(test_domain).step);
    test_step.dependOn(&b.addRunArtifact(test_data).step);
}
