//! VkInstance creation with optional validation layer and VK_EXT_debug_utils messenger.
//!
//! Validation is enabled only in Debug builds. The required surface extensions come
//! from GLFW via `glfwGetRequiredInstanceExtensions` (which returns `VK_KHR_surface`
//! plus the right platform extension — `VK_KHR_win32_surface` on Windows). This keeps
//! the call site cross-platform.

const std = @import("std");
const builtin = @import("builtin");
const vk = @import("vk.zig");
const api = @import("api.zig");
const glfw = @import("glfw_vk.zig");

const log = std.log.scoped(.vk_instance);

pub const InstanceError = error{
    LoaderInitFailed,
    OutOfMemory,
} || vk.Error || api.InstanceApi.Error;

pub const Instance = struct {
    loader: api.Loader,
    api: api.InstanceApi,
    debug_messenger: vk.DebugUtilsMessengerEXT = .null_handle,
    validation_enabled: bool,

    pub fn create(allocator: std.mem.Allocator, app_name: [*:0]const u8) InstanceError!Instance {
        var loader = api.Loader.init() catch |err| switch (err) {
            error.LibraryNotFound, error.EntrypointNotFound => {
                log.err("Vulkan loader not found. Install GPU drivers or LunarG Vulkan Runtime.", .{});
                return InstanceError.LoaderInitFailed;
            },
        };
        errdefer loader.deinit();

        const want_validation = builtin.mode == .Debug;

        const required_layers: []const [*:0]const u8 = if (want_validation)
            &[_][*:0]const u8{"VK_LAYER_KHRONOS_validation"}
        else
            &[_][*:0]const u8{};

        const validation_ok = if (want_validation)
            checkLayersAvailable(allocator, &loader, required_layers) catch false
        else
            false;
        const validation_enabled = want_validation and validation_ok;
        if (want_validation) {
            if (validation_ok) {
                log.info("Vulkan validation layer enabled (VK_LAYER_KHRONOS_validation).", .{});
            } else {
                // Expected when only GPU drivers are installed (no LunarG
                // Vulkan SDK). Stays info-level so it doesn't look alarming.
                log.info("Vulkan validation layer not present; install the LunarG SDK to enable it.", .{});
            }
        }

        // Required surface extensions from GLFW.
        var ext_count: u32 = 0;
        const glfw_exts = glfw.glfwGetRequiredInstanceExtensions(&ext_count);
        var ext_list: std.ArrayList([*:0]const u8) = .empty;
        defer ext_list.deinit(allocator);
        if (glfw_exts) |list| {
            try ext_list.appendSlice(allocator, list[0..ext_count]);
        }
        if (validation_enabled) {
            try ext_list.append(allocator, "VK_EXT_debug_utils");
        }

        const app_info = vk.ApplicationInfo{
            .p_application_name = app_name,
            .application_version = vk.makeApiVersion(0, 0, 1, 0),
            .p_engine_name = "trading",
            .engine_version = vk.makeApiVersion(0, 0, 1, 0),
            .api_version = vk.API_VERSION_1_1,
        };

        const debug_ci = makeDebugMessengerCreateInfo();
        const create_info = vk.InstanceCreateInfo{
            .p_next = if (validation_enabled) @ptrCast(&debug_ci) else null,
            .p_application_info = &app_info,
            .enabled_layer_count = if (validation_enabled) @intCast(required_layers.len) else 0,
            .pp_enabled_layer_names = if (validation_enabled) required_layers.ptr else null,
            .enabled_extension_count = @intCast(ext_list.items.len),
            .pp_enabled_extension_names = ext_list.items.ptr,
        };

        var instance: vk.Instance = .null_handle;
        try vk.check(loader.create_instance(&create_info, null, &instance));
        errdefer {
            const destroy_pfn = blk: {
                const raw = loader.get_instance_proc_addr(instance, "vkDestroyInstance");
                break :blk @as(?api.PfnDestroyInstance, @ptrCast(raw));
            };
            if (destroy_pfn) |d| d(instance, null);
        }

        const instance_api = try api.InstanceApi.init(&loader, instance, validation_enabled);

        var messenger: vk.DebugUtilsMessengerEXT = .null_handle;
        if (validation_enabled) {
            if (instance_api.create_debug_utils_messenger_ext) |create_msg| {
                const dr = create_msg(instance, &debug_ci, null, &messenger);
                if (dr != .success) {
                    log.warn("Failed to create debug messenger: {any}", .{dr});
                    messenger = .null_handle;
                }
            }
        }

        return Instance{
            .loader = loader,
            .api = instance_api,
            .debug_messenger = messenger,
            .validation_enabled = validation_enabled,
        };
    }

    pub fn destroy(self: *Instance) void {
        if (self.debug_messenger != .null_handle) {
            if (self.api.destroy_debug_utils_messenger_ext) |destroy_msg| {
                destroy_msg(self.api.handle, self.debug_messenger, null);
            }
        }
        self.api.destroy_instance(self.api.handle, null);
        self.loader.deinit();
    }

    fn checkLayersAvailable(
        allocator: std.mem.Allocator,
        loader: *const api.Loader,
        required: []const [*:0]const u8,
    ) !bool {
        var count: u32 = 0;
        try vk.check(loader.enumerate_instance_layer_properties(&count, null));
        if (count == 0) return required.len == 0;
        const props = try allocator.alloc(vk.LayerProperties, count);
        defer allocator.free(props);
        try vk.check(loader.enumerate_instance_layer_properties(&count, props.ptr));

        for (required) |req| {
            const req_slice = std.mem.span(req);
            var found = false;
            for (props) |p| {
                const have = std.mem.sliceTo(&p.layer_name, 0);
                if (std.mem.eql(u8, have, req_slice)) {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }
        return true;
    }
};

fn makeDebugMessengerCreateInfo() vk.DebugUtilsMessengerCreateInfoEXT {
    return .{
        .message_severity = .{ .warning = true, .@"error" = true },
        .message_type = .{ .general = true, .validation = true, .performance = true },
        .pfn_user_callback = debugCallback,
        .p_user_data = null,
    };
}

fn debugCallback(
    severity: vk.DebugUtilsMessageSeverityFlagsEXT,
    msg_type: vk.DebugUtilsMessageTypeFlagsEXT,
    callback_data: *const vk.DebugUtilsMessengerCallbackDataEXT,
    user_data: ?*anyopaque,
) callconv(vk.CallConv) u32 {
    _ = user_data;
    const msg = std.mem.span(callback_data.p_message);
    if (severity.@"error") {
        log.err("[{s}{s}{s}] {s}", .{
            if (msg_type.validation) "validation " else "",
            if (msg_type.performance) "perf " else "",
            if (msg_type.general) "general" else "",
            msg,
        });
    } else if (severity.warning) {
        log.warn("[{s}{s}{s}] {s}", .{
            if (msg_type.validation) "validation " else "",
            if (msg_type.performance) "perf " else "",
            if (msg_type.general) "general" else "",
            msg,
        });
    } else {
        log.info("{s}", .{msg});
    }
    return vk.FALSE;
}
