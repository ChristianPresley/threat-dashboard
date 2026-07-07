//! Per-image and per-frame synchronization primitives.
//!
//! Pattern (textbook Khronos pattern, handles imageCount != FRAMES_IN_FLIGHT correctly):
//!   - `image_acquired[frame]`: per frame-in-flight; signaled by acquire, waited by submit.
//!     Per-frame because we don't know the image index until *after* acquire returns.
//!   - `render_finished[image]`: per swapchain image; signaled by submit, waited by present.
//!     Per-image because present wait is bound to the image, and the present operation
//!     may still be referencing the semaphore after submit returns.
//!   - `in_flight[frame]`: per frame-in-flight; fence the CPU waits on at the top of
//!     each frame to gate command-pool reset and frame_sync reuse.
//!   - `images_in_flight[image]`: per swapchain image; *aliases* the `in_flight` fence
//!     of whatever frame last used this image. Before submitting frame F to image I,
//!     wait on `images_in_flight[I]` (if non-null) — guarantees the previous use of
//!     `render_finished[I]` has completed and the semaphore is in a known state.
//!     This is the fix for VUID-vkQueueSubmit-pSignalSemaphores-00067 on MAILBOX,
//!     where the same image can come back into flight before the previous present
//!     finishes consuming its render_finished semaphore.

const std = @import("std");
const vk = @import("vk.zig");
const Device = @import("device.zig").Device;

pub const FRAMES_IN_FLIGHT: u32 = 2;

pub const FrameSync = struct {
    image_acquired: [FRAMES_IN_FLIGHT]vk.Semaphore,
    render_finished: []vk.Semaphore,
    in_flight: [FRAMES_IN_FLIGHT]vk.Fence,
    /// Aliases of in_flight fences; one slot per swapchain image. `.null_handle`
    /// means "image never used yet"; updated each frame after acquire.
    images_in_flight: []vk.Fence,

    allocator: std.mem.Allocator,
    device: *Device,

    pub fn create(allocator: std.mem.Allocator, device: *Device, image_count: u32) !FrameSync {
        var self: FrameSync = .{
            .image_acquired = [_]vk.Semaphore{.null_handle} ** FRAMES_IN_FLIGHT,
            .render_finished = try allocator.alloc(vk.Semaphore, image_count),
            .in_flight = [_]vk.Fence{.null_handle} ** FRAMES_IN_FLIGHT,
            .images_in_flight = try allocator.alloc(vk.Fence, image_count),
            .allocator = allocator,
            .device = device,
        };
        @memset(self.render_finished, .null_handle);
        @memset(self.images_in_flight, .null_handle);

        // Errdefer: on any failure mid-construction, destroy what we created.
        errdefer self.destroy();

        const sem_ci = vk.SemaphoreCreateInfo{};
        const fence_ci = vk.FenceCreateInfo{ .flags = .{ .signaled = true } };

        for (&self.image_acquired) |*s| {
            try vk.check(device.api.create_semaphore(device.api.handle, &sem_ci, null, s));
        }
        for (self.render_finished) |*s| {
            try vk.check(device.api.create_semaphore(device.api.handle, &sem_ci, null, s));
        }
        for (&self.in_flight) |*f| {
            try vk.check(device.api.create_fence(device.api.handle, &fence_ci, null, f));
        }
        return self;
    }

    pub fn destroy(self: *FrameSync) void {
        for (self.image_acquired) |s| {
            if (s != .null_handle) self.device.api.destroy_semaphore(self.device.api.handle, s, null);
        }
        // null-out so a second destroy is a no-op (idempotent).
        self.image_acquired = [_]vk.Semaphore{.null_handle} ** FRAMES_IN_FLIGHT;

        for (self.render_finished) |s| {
            if (s != .null_handle) self.device.api.destroy_semaphore(self.device.api.handle, s, null);
        }
        for (self.in_flight) |f| {
            if (f != .null_handle) self.device.api.destroy_fence(self.device.api.handle, f, null);
        }
        self.in_flight = [_]vk.Fence{.null_handle} ** FRAMES_IN_FLIGHT;

        if (self.render_finished.len != 0) {
            self.allocator.free(self.render_finished);
            self.render_finished = &[_]vk.Semaphore{};
        }
        if (self.images_in_flight.len != 0) {
            self.allocator.free(self.images_in_flight);
            self.images_in_flight = &[_]vk.Fence{};
        }
    }
};
