//! Vulkan buffer + image allocation helpers.
//!
//! Minimal: per-allocation `VkDeviceMemory` (no suballocator). Fine for the small
//! number of long-lived buffers ImGui needs (font atlas, per-frame vertex/index
//! buffers). The atlas allocation is one-off; the per-frame vertex/index ring
//! lives in `imgui_backend.zig` (the `FrameBuffers` struct).

const std = @import("std");
const vk = @import("vk.zig");
const Device = @import("device.zig").Device;

pub const Buffer = struct {
    device: *Device,
    handle: vk.Buffer = .null_handle,
    memory: vk.DeviceMemory = .null_handle,
    size: u64 = 0,
    mapped: ?[*]u8 = null,

    /// Allocate a buffer + memory + (if host_visible) keep it persistently mapped.
    ///
    /// Note: if `props.host_visible` is set without `host_coherent`, the caller is
    /// responsible for `vkFlushMappedMemoryRanges` after writes and/or
    /// `vkInvalidateMappedMemoryRanges` before reads. The current callers in this
    /// codebase always pass both, so no explicit flush is needed.
    pub fn create(
        device: *Device,
        size: u64,
        usage: vk.BufferUsageFlags,
        props: vk.MemoryPropertyFlags,
    ) !Buffer {
        var self: Buffer = .{ .device = device, .size = size };
        errdefer self.destroy();

        const buf_ci = vk.BufferCreateInfo{ .size = size, .usage = usage };
        try vk.check(device.api.create_buffer(device.api.handle, &buf_ci, null, &self.handle));

        var req: vk.MemoryRequirements = undefined;
        device.api.get_buffer_memory_requirements(device.api.handle, self.handle, &req);

        const type_idx = device.findMemoryType(req.memory_type_bits, props) orelse
            return error.NoSuitableMemoryType;

        const alloc_info = vk.MemoryAllocateInfo{
            .allocation_size = req.size,
            .memory_type_index = type_idx,
        };
        try vk.check(device.api.allocate_memory(device.api.handle, &alloc_info, null, &self.memory));
        try vk.check(device.api.bind_buffer_memory(device.api.handle, self.handle, self.memory, 0));

        if (props.host_visible) {
            var ptr: ?*anyopaque = null;
            try vk.check(device.api.map_memory(device.api.handle, self.memory, 0, vk.WHOLE_SIZE, 0, &ptr));
            self.mapped = @ptrCast(@alignCast(ptr));
        }
        return self;
    }

    pub fn destroy(self: *Buffer) void {
        if (self.mapped != null) {
            self.device.api.unmap_memory(self.device.api.handle, self.memory);
            self.mapped = null;
        }
        if (self.handle != .null_handle) {
            self.device.api.destroy_buffer(self.device.api.handle, self.handle, null);
            self.handle = .null_handle;
        }
        if (self.memory != .null_handle) {
            self.device.api.free_memory(self.device.api.handle, self.memory, null);
            self.memory = .null_handle;
        }
    }
};

pub const Image = struct {
    device: *Device,
    handle: vk.Image = .null_handle,
    view: vk.ImageView = .null_handle,
    memory: vk.DeviceMemory = .null_handle,
    extent: vk.Extent2D = .{ .width = 0, .height = 0 },
    format: vk.Format = .undefined,

    /// Allocate a 2D image + view in device-local memory.
    ///
    /// Hardcoded defaults: 1 mip level, 1 array layer, 1 sample, `tiling = .optimal`,
    /// `initial_layout = .undefined`. Callers requiring mips, MSAA, array slices, or
    /// staged initial layouts need to extend this helper or use the lower-level API.
    pub fn create(
        device: *Device,
        extent: vk.Extent2D,
        format: vk.Format,
        usage: vk.ImageUsageFlags,
    ) !Image {
        var self: Image = .{
            .device = device,
            .extent = extent,
            .format = format,
        };
        errdefer self.destroy();

        const img_ci = vk.ImageCreateInfo{
            .image_type = .@"2d",
            .format = format,
            .extent = .{ .width = extent.width, .height = extent.height, .depth = 1 },
            .mip_levels = 1,
            .array_layers = 1,
            .samples = .{ .@"1" = true },
            .tiling = .optimal,
            .usage = usage,
            .initial_layout = .undefined,
        };
        try vk.check(device.api.create_image(device.api.handle, &img_ci, null, &self.handle));

        var req: vk.MemoryRequirements = undefined;
        device.api.get_image_memory_requirements(device.api.handle, self.handle, &req);

        const type_idx = device.findMemoryType(req.memory_type_bits, .{ .device_local = true }) orelse
            return error.NoSuitableMemoryType;

        const alloc_info = vk.MemoryAllocateInfo{
            .allocation_size = req.size,
            .memory_type_index = type_idx,
        };
        try vk.check(device.api.allocate_memory(device.api.handle, &alloc_info, null, &self.memory));
        try vk.check(device.api.bind_image_memory(device.api.handle, self.handle, self.memory, 0));

        const view_ci = vk.ImageViewCreateInfo{
            .image = self.handle,
            .view_type = .@"2d",
            .format = format,
            .subresource_range = .{
                .aspect_mask = .{ .color = true },
                .base_mip_level = 0,
                .level_count = 1,
                .base_array_layer = 0,
                .layer_count = 1,
            },
        };
        try vk.check(device.api.create_image_view(device.api.handle, &view_ci, null, &self.view));

        return self;
    }

    pub fn destroy(self: *Image) void {
        if (self.view != .null_handle) {
            self.device.api.destroy_image_view(self.device.api.handle, self.view, null);
            self.view = .null_handle;
        }
        if (self.handle != .null_handle) {
            self.device.api.destroy_image(self.device.api.handle, self.handle, null);
            self.handle = .null_handle;
        }
        if (self.memory != .null_handle) {
            self.device.api.free_memory(self.device.api.handle, self.memory, null);
            self.memory = .null_handle;
        }
    }
};

