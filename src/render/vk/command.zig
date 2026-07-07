//! Per-frame command pools and command buffers.
//!
//! One command pool per frame-in-flight (with `transient` flag) so we can reset the
//! entire pool at the start of each frame. Simpler and has better allocator behavior
//! than resetting individual buffers.

const std = @import("std");
const vk = @import("vk.zig");
const Device = @import("device.zig").Device;
const FRAMES_IN_FLIGHT = @import("sync.zig").FRAMES_IN_FLIGHT;

pub const FrameCommand = struct {
    pools: [FRAMES_IN_FLIGHT]vk.CommandPool,
    buffers: [FRAMES_IN_FLIGHT]vk.CommandBuffer,
    device: *Device,

    pub fn create(device: *Device, queue_family: u32) !FrameCommand {
        var self: FrameCommand = .{
            .pools = [_]vk.CommandPool{.null_handle} ** FRAMES_IN_FLIGHT,
            .buffers = [_]vk.CommandBuffer{.null_handle} ** FRAMES_IN_FLIGHT,
            .device = device,
        };
        // Errdefer guards partial-loop failure: pool[k] is created but pool[k+1]
        // or allocate_command_buffers fails — destroy whatever was created.
        errdefer self.destroy();

        const pool_ci = vk.CommandPoolCreateInfo{
            .flags = .{ .transient = true },
            .queue_family_index = queue_family,
        };
        for (&self.pools, 0..) |*pool, i| {
            try vk.check(device.api.create_command_pool(device.api.handle, &pool_ci, null, pool));
            const alloc_info = vk.CommandBufferAllocateInfo{
                .command_pool = pool.*,
                .level = .primary,
                .command_buffer_count = 1,
            };
            try vk.check(device.api.allocate_command_buffers(device.api.handle, &alloc_info, @ptrCast(&self.buffers[i])));
        }
        return self;
    }

    pub fn destroy(self: *FrameCommand) void {
        for (&self.pools) |*p| {
            if (p.* != .null_handle) {
                self.device.api.destroy_command_pool(self.device.api.handle, p.*, null);
                p.* = .null_handle;
            }
        }
    }

    pub fn resetFrame(self: *FrameCommand, frame: u32) !void {
        try vk.check(self.device.api.reset_command_pool(self.device.api.handle, self.pools[frame], 0));
    }
};
