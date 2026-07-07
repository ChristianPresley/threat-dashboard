//! Public interface of the `render` module.
//!
//! Exposes the renderer + ImGui Vulkan backend + GLFW input bridge. Raw Vulkan
//! types stay internal — callers below this module should never need them; if
//! they do, the renderer needs a wider public API.

pub const Renderer = @import("vk/renderer.zig").Renderer;
pub const ImGuiBackend = @import("vk/imgui_backend.zig").ImGuiBackend;
pub const imgui_glfw = @import("vk/imgui_glfw.zig");

/// Minimal PNG encoder — used by the `--screenshot` validation harness to
/// persist `Renderer.endFrameCapture` frames.
pub const png = @import("png.zig");

/// Opt into MAILBOX (uncapped) presentation instead of the FIFO/vsync
/// default. Call before `Renderer.create`.
pub fn setPreferMailbox(v: bool) void {
    @import("vk/swapchain.zig").prefer_mailbox = v;
}

/// Window-system bindings the renderer needs the caller to own (window creation,
/// event polling, framebuffer-size query). Renderer takes a `*window.GLFWwindow`.
pub const window = @import("vk/glfw_vk.zig");
