//! Minimal GLFW externs used by the Vulkan layer.
//!
//! Pulled out so that the Vulkan modules don't reach into Win32 directly — the GLFW
//! helpers handle the platform differences for us. Only the symbols we actually
//! call are declared.

const vk = @import("vk.zig");
const api = @import("api.zig");

pub const GLFWwindow = opaque {};

pub extern fn glfwInit() c_int;
pub extern fn glfwTerminate() void;
pub extern fn glfwWindowHint(hint: c_int, value: c_int) void;
pub extern fn glfwCreateWindow(
    width: c_int,
    height: c_int,
    title: [*:0]const u8,
    monitor: ?*anyopaque,
    share: ?*anyopaque,
) ?*GLFWwindow;
pub extern fn glfwDestroyWindow(window: *GLFWwindow) void;
pub extern fn glfwWindowShouldClose(window: *GLFWwindow) c_int;
pub extern fn glfwPollEvents() void;
pub extern fn glfwGetFramebufferSize(window: *GLFWwindow, width: *c_int, height: *c_int) void;
pub extern fn glfwWaitEvents() void;
pub extern fn glfwGetTime() f64;

// --- Window state queries / mutations used by the fullscreen toggle ---

pub const GLFWmonitor = opaque {};

/// GLFW vidmode struct.  Layout per GLFW 3.x — six int fields.  We
/// only read width/height/refresh_rate from it.
pub const GLFWvidmode = extern struct {
    width: c_int,
    height: c_int,
    red_bits: c_int,
    green_bits: c_int,
    blue_bits: c_int,
    refresh_rate: c_int,
};

pub extern fn glfwGetPrimaryMonitor() ?*GLFWmonitor;
pub extern fn glfwGetVideoMode(monitor: *GLFWmonitor) ?*const GLFWvidmode;
pub extern fn glfwGetWindowMonitor(window: *GLFWwindow) ?*GLFWmonitor;
pub extern fn glfwSetWindowMonitor(
    window: *GLFWwindow,
    monitor: ?*GLFWmonitor,
    xpos: c_int,
    ypos: c_int,
    width: c_int,
    height: c_int,
    refresh_rate: c_int,
) void;
pub extern fn glfwGetWindowPos(window: *GLFWwindow, x: *c_int, y: *c_int) void;
pub extern fn glfwGetWindowSize(window: *GLFWwindow, w: *c_int, h: *c_int) void;
/// Per-monitor content scale (1.0 = 96 dpi, 1.25 = 125% OS scaling, …).
pub extern fn glfwGetWindowContentScale(window: *GLFWwindow, xscale: *f32, yscale: *f32) void;

/// Read a key's state — GLFW_PRESS (1) or GLFW_RELEASE (0).
pub extern fn glfwGetKey(window: *GLFWwindow, key: c_int) c_int;

pub const GLFW_KEY_F11: c_int = 300;
pub const GLFW_PRESS: c_int = 1;
pub const GLFW_RELEASE: c_int = 0;
pub const GLFW_DONT_CARE: c_int = -1;

// --- Vulkan-specific ---

pub extern fn glfwVulkanSupported() c_int;
pub extern fn glfwGetRequiredInstanceExtensions(count: *u32) ?[*]const [*:0]const u8;

// GLFW 3.4+: hand our loaded PFN to GLFW so it doesn't LoadLibrary() a second copy.
pub extern fn glfwInitVulkanLoader(loader_function: api.PfnGetInstanceProcAddr) void;

pub extern fn glfwCreateWindowSurface(
    instance: vk.Instance,
    window: *GLFWwindow,
    allocator: ?*const vk.AllocationCallbacks,
    surface: *vk.SurfaceKHR,
) vk.Result;

// GLFW window hints we need (avoids string lookups at runtime).
pub const GLFW_CLIENT_API: c_int = 0x00022001;
pub const GLFW_NO_API: c_int = 0;
pub const GLFW_VISIBLE: c_int = 0x00020004;
pub const GLFW_RESIZABLE: c_int = 0x00020003;
pub const GLFW_TRUE: c_int = 1;
pub const GLFW_FALSE: c_int = 0;
