//! Swapchain lifecycle: creation, recreation with oldSwapchain handoff, image views.
//!
//! Format pick: prefer B8G8R8A8_UNORM. ImGui hands us sRGB display-referred
//! vertex colors and the passthrough fragment shader writes them unmodified;
//! a UNORM attachment stores those bytes verbatim so the monitor shows the
//! palette's exact hex values and alpha blending happens in sRGB space, which
//! is what ImGui's anti-aliasing is tuned for. An _SRGB attachment re-encodes
//! the already-encoded values on store and washes the whole UI out ~4x
//! (verified via --screenshot readback). Fall back to B8G8R8A8_SRGB only if
//! UNORM isn't offered.
//!
//! Present-mode pick: FIFO (vsync) by default — an ImGui terminal that
//! re-renders every frame should not burn a CPU core + GPU at uncapped
//! rates. MAILBOX is opt-in via `prefer_mailbox` (--mailbox flag) for
//! latency-sensitive sessions. FIFO is guaranteed available.
//!
//! Resize handling: callers call `recreate()` on VK_ERROR_OUT_OF_DATE_KHR or after
//! VK_SUBOPTIMAL_KHR from queuePresent. If the new surface extent is 0×0 (minimized),
//! `recreate` returns `WindowMinimized` and callers should skip frames until non-zero.

const std = @import("std");
const vk = @import("vk.zig");
const api = @import("api.zig");
const Device = @import("device.zig").Device;
const Surface = @import("surface.zig").Surface;

const log = std.log.scoped(.vk_swapchain);

pub const SwapchainError = error{
    WindowMinimized,
    NoSuitableFormat,
    OutOfMemory,
} || vk.Error;

/// Opt into MAILBOX (uncapped) presentation. Set before `Swapchain.create`
/// (also honored on recreate). Default FIFO = vsync.
pub var prefer_mailbox: bool = false;

pub const Swapchain = struct {
    allocator: std.mem.Allocator,
    device: *Device,
    surface: *const Surface,

    handle: vk.SwapchainKHR = .null_handle,
    format: vk.Format = .undefined,
    color_space: vk.ColorSpaceKHR = .srgb_nonlinear,
    extent: vk.Extent2D = .{ .width = 0, .height = 0 },
    present_mode: vk.PresentModeKHR = .fifo,
    images: []vk.Image = &[_]vk.Image{},
    image_views: []vk.ImageView = &[_]vk.ImageView{},
    /// True when the swapchain images were created with TRANSFER_SRC usage,
    /// i.e. `Renderer.endFrameCapture` can read frames back (screenshots).
    readback: bool = false,

    pub fn create(
        allocator: std.mem.Allocator,
        device: *Device,
        surface: *const Surface,
        wanted_extent: vk.Extent2D,
    ) SwapchainError!Swapchain {
        var sc = Swapchain{
            .allocator = allocator,
            .device = device,
            .surface = surface,
        };
        // If buildSwapchain fails partway through (after creating the VkSwapchainKHR
        // or some image views), we need to clean up the partial state since `sc` is
        // a local that the caller never sees.
        errdefer sc.destroy();
        try sc.buildSwapchain(wanted_extent, .null_handle);
        return sc;
    }

    pub fn destroy(self: *Swapchain) void {
        self.destroyImageViews();
        if (self.handle != .null_handle) {
            self.device.api.destroy_swapchain_khr(self.device.api.handle, self.handle, null);
            self.handle = .null_handle;
        }
        if (self.images.len != 0) {
            self.allocator.free(self.images);
            self.images = &[_]vk.Image{};
        }
    }

    /// Tear down the old swapchain (image views first), then build a new one passing
    /// the old handle to VkSwapchainCreateInfoKHR.oldSwapchain. After vkCreateSwapchainKHR
    /// succeeds, the spec lets us destroy the old swapchain — which we do here.
    pub fn recreate(self: *Swapchain, wanted_extent: vk.Extent2D) SwapchainError!void {
        self.device.waitIdle();
        self.destroyImageViews();
        if (self.images.len != 0) {
            self.allocator.free(self.images);
            self.images = &[_]vk.Image{};
        }
        const old_handle = self.handle;
        try self.buildSwapchain(wanted_extent, old_handle);
        if (old_handle != .null_handle) {
            self.device.api.destroy_swapchain_khr(self.device.api.handle, old_handle, null);
        }
    }

    fn buildSwapchain(self: *Swapchain, wanted_extent: vk.Extent2D, old: vk.SwapchainKHR) SwapchainError!void {
        var caps: vk.SurfaceCapabilitiesKHR = undefined;
        try vk.check(self.device.instance.api.get_physical_device_surface_capabilities_khr(
            self.device.picked.physical,
            self.surface.handle,
            &caps,
        ));

        const extent = clampExtent(caps, wanted_extent);
        if (extent.width == 0 or extent.height == 0) return SwapchainError.WindowMinimized;

        const surface_format = try pickSurfaceFormat(self.allocator, self.device, self.surface);
        const present_mode = try pickPresentMode(self.allocator, self.device, self.surface);

        var image_count = caps.min_image_count + 1;
        if (caps.max_image_count > 0 and image_count > caps.max_image_count) {
            image_count = caps.max_image_count;
        }

        // Screenshot readback wants TRANSFER_SRC on the swapchain images.
        // Universally supported in practice, but the spec only guarantees
        // COLOR_ATTACHMENT — so gate on the surface caps.
        const readback = caps.supported_usage_flags.transfer_src;

        const ci = vk.SwapchainCreateInfoKHR{
            .surface = self.surface.handle,
            .min_image_count = image_count,
            .image_format = surface_format.format,
            .image_color_space = surface_format.color_space,
            .image_extent = extent,
            .image_array_layers = 1,
            .image_usage = .{ .color_attachment = true, .transfer_src = readback },
            .image_sharing_mode = .exclusive,
            .pre_transform = caps.current_transform,
            .composite_alpha = .{ .opaque_bit = true },
            .present_mode = present_mode,
            .clipped = vk.TRUE,
            .old_swapchain = old,
        };

        var handle: vk.SwapchainKHR = .null_handle;
        try vk.check(self.device.api.create_swapchain_khr(self.device.api.handle, &ci, null, &handle));

        self.handle = handle;
        self.format = surface_format.format;
        self.color_space = surface_format.color_space;
        self.extent = extent;
        self.present_mode = present_mode;
        self.readback = readback;

        // Fetch images.
        var n: u32 = 0;
        try vk.check(self.device.api.get_swapchain_images_khr(self.device.api.handle, handle, &n, null));
        self.images = try self.allocator.alloc(vk.Image, n);
        try vk.check(self.device.api.get_swapchain_images_khr(self.device.api.handle, handle, &n, self.images.ptr));

        // Build image views.
        self.image_views = try self.allocator.alloc(vk.ImageView, n);
        @memset(self.image_views, .null_handle);
        for (self.images, 0..) |img, i| {
            const vci = vk.ImageViewCreateInfo{
                .image = img,
                .view_type = .@"2d",
                .format = self.format,
                .components = .{},
                .subresource_range = .{
                    .aspect_mask = .{ .color = true },
                    .base_mip_level = 0,
                    .level_count = 1,
                    .base_array_layer = 0,
                    .layer_count = 1,
                },
            };
            try vk.check(self.device.api.create_image_view(self.device.api.handle, &vci, null, &self.image_views[i]));
        }

        log.info("Swapchain: {d}x{d}, fmt={any}, present={any}, images={d}", .{
            extent.width, extent.height, self.format, self.present_mode, self.images.len,
        });
    }

    fn destroyImageViews(self: *Swapchain) void {
        for (self.image_views) |v| {
            if (v != .null_handle) {
                self.device.api.destroy_image_view(self.device.api.handle, v, null);
            }
        }
        if (self.image_views.len != 0) {
            self.allocator.free(self.image_views);
            self.image_views = &[_]vk.ImageView{};
        }
    }
};

fn clampExtent(caps: vk.SurfaceCapabilitiesKHR, wanted: vk.Extent2D) vk.Extent2D {
    // 0xFFFFFFFF current_extent means "pick whatever you want within min/max."
    if (caps.current_extent.width != 0xFFFFFFFF) return caps.current_extent;
    return .{
        .width = std.math.clamp(wanted.width, caps.min_image_extent.width, caps.max_image_extent.width),
        .height = std.math.clamp(wanted.height, caps.min_image_extent.height, caps.max_image_extent.height),
    };
}

fn pickSurfaceFormat(
    allocator: std.mem.Allocator,
    device: *Device,
    surface: *const Surface,
) SwapchainError!vk.SurfaceFormatKHR {
    var count: u32 = 0;
    try vk.check(device.instance.api.get_physical_device_surface_formats_khr(
        device.picked.physical, surface.handle, &count, null,
    ));
    if (count == 0) return SwapchainError.NoSuitableFormat;
    const formats = try allocator.alloc(vk.SurfaceFormatKHR, count);
    defer allocator.free(formats);
    try vk.check(device.instance.api.get_physical_device_surface_formats_khr(
        device.picked.physical, surface.handle, &count, formats.ptr,
    ));

    // Prefer UNORM: stores ImGui's sRGB display-referred bytes verbatim
    // (see module doc — an _SRGB attachment double-encodes and washes out).
    for (formats) |f| {
        if (f.format == .b8g8r8a8_unorm and f.color_space == .srgb_nonlinear) return f;
    }
    for (formats) |f| {
        if (f.format == .b8g8r8a8_srgb and f.color_space == .srgb_nonlinear) return f;
    }
    return formats[0];
}

fn pickPresentMode(
    allocator: std.mem.Allocator,
    device: *Device,
    surface: *const Surface,
) SwapchainError!vk.PresentModeKHR {
    if (!prefer_mailbox) return .fifo;

    var count: u32 = 0;
    try vk.check(device.instance.api.get_physical_device_surface_present_modes_khr(
        device.picked.physical, surface.handle, &count, null,
    ));
    if (count == 0) return .fifo;
    const modes = try allocator.alloc(vk.PresentModeKHR, count);
    defer allocator.free(modes);
    try vk.check(device.instance.api.get_physical_device_surface_present_modes_khr(
        device.picked.physical, surface.handle, &count, modes.ptr,
    ));

    for (modes) |m| {
        if (m == .mailbox) return .mailbox;
    }
    return .fifo;
}
