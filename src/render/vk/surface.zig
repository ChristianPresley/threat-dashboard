//! VkSurfaceKHR creation via glfwCreateWindowSurface (cross-platform).

const std = @import("std");
const vk = @import("vk.zig");
const api = @import("api.zig");
const glfw = @import("glfw_vk.zig");
const Instance = @import("instance.zig").Instance;

const log = std.log.scoped(.vk_surface);

pub const Surface = struct {
    instance: *Instance,
    handle: vk.SurfaceKHR,

    pub fn create(instance: *Instance, window: *glfw.GLFWwindow) !Surface {
        var surface: vk.SurfaceKHR = .null_handle;
        const r = glfw.glfwCreateWindowSurface(instance.api.handle, window, null, &surface);
        try vk.check(r);
        return Surface{ .instance = instance, .handle = surface };
    }

    pub fn destroy(self: *Surface) void {
        self.instance.api.destroy_surface_khr(self.instance.api.handle, self.handle, null);
        self.handle = .null_handle;
    }
};
