//! Top-level Vulkan renderer orchestrator.
//!
//! Owns Instance → Surface → Device → Swapchain plus the per-frame sync and
//! command state. The primary surface is `beginFrame` / `endFrame`: callers
//! record their own draws into `FrameContext.cmd` between the two. A smoke-test
//! triangle pipeline + `renderClear()` wrapper are kept for the vk-smoke
//! standalone harness.
//!
//! Resize / minimize handling:
//!   - VK_ERROR_OUT_OF_DATE_KHR from acquire → recreate swapchain, skip frame.
//!   - VK_SUBOPTIMAL_KHR from acquire → consume the (signaled) semaphore by submitting
//!     this frame normally, then mark for recreate at end of frame.
//!   - VK_SUBOPTIMAL_KHR / OUT_OF_DATE from present → recreate at end of frame.
//!   - Surface extent 0×0 → skip frames until restored.

const std = @import("std");
const vk = @import("vk.zig");
const api = @import("api.zig");
const glfw = @import("glfw_vk.zig");
const Instance = @import("instance.zig").Instance;
const Surface = @import("surface.zig").Surface;
const Device = @import("device.zig").Device;
const Swapchain = @import("swapchain.zig").Swapchain;
const sync_mod = @import("sync.zig");
const FrameSync = sync_mod.FrameSync;
const FRAMES_IN_FLIGHT = sync_mod.FRAMES_IN_FLIGHT;
const FrameCommand = @import("command.zig").FrameCommand;
const pipeline_mod = @import("pipeline.zig");
const buffer_mod = @import("buffer.zig");
const shaders = @import("../shaders/shaders.zig");

const log = std.log.scoped(.vk_renderer);

pub const Renderer = struct {
    allocator: std.mem.Allocator,
    window: *glfw.GLFWwindow,

    // Instance and Device are BOTH heap-allocated so sub-objects can hold
    // stable pointers across the create() → return boundary.
    //
    // Surface stores a `*Instance` (used at destroy time). Swapchain,
    // FrameSync, FrameCommand, PipelineCache, ImGuiBackend store a
    // `*Device`. If either parent were by-value here, those child
    // pointers would dangle after create() returns and the next stack
    // frame that happens to be the right size would clobber the slot.
    // Device-as-pointer fix landed in PR 1b; Instance-as-pointer fix
    // landed here in Phase 3 after a Dashboard stack-layout change
    // started exposing the surface variant of the same bug at exit.
    // See RENDERER_STATUS.md.
    instance: *Instance,
    /// Heap-allocated so `Swapchain.surface: *const Surface` stays a
    /// stable pointer across `Renderer.create`'s return.  Returning
    /// the Renderer by value used to copy the surface into the new
    /// struct, leaving the swapchain pointing at the defunct stack
    /// slot — that slot reads as 0 once it gets overwritten (e.g. on
    /// the first swapchain recreate triggered by a window resize),
    /// which surfaces as `VK_NULL_HANDLE` in vkGetPhysicalDeviceSurface*.
    surface: *Surface,
    device: *Device,
    swapchain: Swapchain,

    render_pass: vk.RenderPass = .null_handle,
    framebuffers: []vk.Framebuffer = &[_]vk.Framebuffer{},

    pipeline_cache: pipeline_mod.PipelineCache,
    pipeline_layout: vk.PipelineLayout = .null_handle,
    triangle_pipeline: vk.Pipeline = .null_handle,

    frame_sync: FrameSync,
    frame_cmd: FrameCommand,

    current_frame: u32 = 0,
    needs_recreate: bool = false,

    /// Context returned by `beginFrame` and consumed by `endFrame`. Carries the
    /// per-frame state callers need to record their own draws: the live command
    /// buffer (already inside an active render pass), the framebuffer extent for
    /// viewport math, the swapchain image index, and the frame-in-flight index.
    pub const FrameContext = struct {
        cmd: vk.CommandBuffer,
        extent: vk.Extent2D,
        image_index: u32,
        frame_index: u32,
    };

    pub fn create(
        allocator: std.mem.Allocator,
        window: *glfw.GLFWwindow,
        app_name: [*:0]const u8,
    ) !Renderer {
        if (glfw.glfwVulkanSupported() == 0) {
            log.err("GLFW reports Vulkan is not supported on this platform.", .{});
            return error.VulkanNotSupported;
        }

        // Heap-allocate Instance so Surface (and anything else that wants
        // a stable parent pointer) can hold a valid reference after
        // create() returns. See the comment on `Renderer.instance`.
        const instance = try allocator.create(Instance);
        errdefer allocator.destroy(instance);
        instance.* = try Instance.create(allocator, app_name);
        errdefer instance.destroy();

        // Hand our loaded vkGetInstanceProcAddr to GLFW so it shares our loader
        // rather than LoadLibrary'ing a second copy.
        glfw.glfwInitVulkanLoader(instance.loader.get_instance_proc_addr);

        // Heap-allocate the Surface so its address is stable across the
        // create() → return boundary.  Swapchain stores a *const Surface
        // that has to outlive the Renderer it belongs to.
        const surface = try allocator.create(Surface);
        errdefer allocator.destroy(surface);
        surface.* = try Surface.create(instance, window);
        errdefer surface.destroy();

        // Heap-allocate Device so sub-object `*Device` pointers stay valid
        // across the create() → return boundary.
        const device = try allocator.create(Device);
        errdefer allocator.destroy(device);
        device.* = try Device.create(allocator, instance, surface);
        errdefer device.destroy();

        var fb_w: c_int = 0;
        var fb_h: c_int = 0;
        glfw.glfwGetFramebufferSize(window, &fb_w, &fb_h);

        var swapchain = try Swapchain.create(allocator, device, surface, .{
            .width = @intCast(@max(fb_w, 1)),
            .height = @intCast(@max(fb_h, 1)),
        });
        errdefer swapchain.destroy();

        const render_pass = try createClearRenderPass(device, swapchain.format);
        errdefer device.api.destroy_render_pass(device.api.handle, render_pass, null);

        const framebuffers = try createFramebuffers(allocator, device, render_pass, &swapchain);
        errdefer destroyFramebuffers(allocator, device, framebuffers);

        var pipeline_cache = try pipeline_mod.PipelineCache.create(allocator, device, "trading");
        errdefer pipeline_cache.destroy();

        const layout_ci = vk.PipelineLayoutCreateInfo{};
        var pipeline_layout: vk.PipelineLayout = .null_handle;
        try vk.check(device.api.create_pipeline_layout(device.api.handle, &layout_ci, null, &pipeline_layout));
        errdefer device.api.destroy_pipeline_layout(device.api.handle, pipeline_layout, null);

        const triangle_pipeline = blk: {
            const vert = try pipeline_mod.createShaderModule(device, &shaders.triangle_vert);
            defer pipeline_mod.destroyShaderModule(device, vert);
            const frag = try pipeline_mod.createShaderModule(device, &shaders.triangle_frag);
            defer pipeline_mod.destroyShaderModule(device, frag);
            break :blk try pipeline_mod.createGraphicsPipeline(device, pipeline_cache.handle, .{
                .vert_module = vert,
                .frag_module = frag,
                .render_pass = render_pass,
                .pipeline_layout = pipeline_layout,
            });
        };
        errdefer device.api.destroy_pipeline(device.api.handle, triangle_pipeline, null);

        var frame_sync = try FrameSync.create(allocator, device, @intCast(swapchain.images.len));
        errdefer frame_sync.destroy();

        var frame_cmd = try FrameCommand.create(device, device.picked.queue_family_index);
        errdefer frame_cmd.destroy();

        return Renderer{
            .allocator = allocator,
            .window = window,
            .instance = instance,
            .surface = surface,
            .device = device,
            .swapchain = swapchain,
            .render_pass = render_pass,
            .framebuffers = framebuffers,
            .pipeline_cache = pipeline_cache,
            .pipeline_layout = pipeline_layout,
            .triangle_pipeline = triangle_pipeline,
            .frame_sync = frame_sync,
            .frame_cmd = frame_cmd,
        };
    }

    pub fn destroy(self: *Renderer) void {
        self.device.waitIdle();
        self.pipeline_cache.save();
        self.frame_cmd.destroy();
        self.frame_sync.destroy();
        if (self.triangle_pipeline != .null_handle) {
            self.device.api.destroy_pipeline(self.device.api.handle, self.triangle_pipeline, null);
            self.triangle_pipeline = .null_handle;
        }
        if (self.pipeline_layout != .null_handle) {
            self.device.api.destroy_pipeline_layout(self.device.api.handle, self.pipeline_layout, null);
            self.pipeline_layout = .null_handle;
        }
        self.pipeline_cache.destroy();
        destroyFramebuffers(self.allocator, self.device, self.framebuffers);
        self.framebuffers = &[_]vk.Framebuffer{};
        if (self.render_pass != .null_handle) {
            self.device.api.destroy_render_pass(self.device.api.handle, self.render_pass, null);
            self.render_pass = .null_handle;
        }
        self.swapchain.destroy();
        self.device.destroy();
        self.allocator.destroy(self.device);
        self.surface.destroy();
        self.allocator.destroy(self.surface);
        self.instance.destroy();
        self.allocator.destroy(self.instance);
    }

    /// Begin a frame: wait for the in-flight fence, acquire the next swapchain
    /// image, wait for any prior frame still owning that image, reset the per-
    /// frame command pool, open a command buffer, and enter the render pass with
    /// a clear-to-color load. Returns null if the frame should be skipped (window
    /// minimized or swapchain still being recreated). On success, the returned
    /// FrameContext is consumed by `endFrame`.
    pub fn beginFrame(self: *Renderer, clear_color: [4]f32) !?FrameContext {
        if (self.needs_recreate) {
            try self.handleRecreate();
            if (self.needs_recreate) return null;
        }

        const frame = self.current_frame;
        const dev = &self.device.api;

        // Wait for this frame's previous submit to finish.
        try vk.check(dev.wait_for_fences(dev.handle, 1, @ptrCast(&self.frame_sync.in_flight[frame]), vk.TRUE, std.math.maxInt(u64)));

        // Acquire next image.
        var image_index: u32 = 0;
        const acquire_result = dev.acquire_next_image_khr(
            dev.handle,
            self.swapchain.handle,
            std.math.maxInt(u64),
            self.frame_sync.image_acquired[frame],
            .null_handle,
            &image_index,
        );
        switch (acquire_result) {
            .success => {},
            .suboptimal_khr => self.needs_recreate = true, // continue this frame.
            .error_out_of_date_khr => {
                // Semaphore was NOT signaled; do not wait on it. Skip frame.
                self.needs_recreate = true;
                return null;
            },
            else => try vk.check(acquire_result),
        }

        // Wait on the fence of whichever frame previously used this image — protects
        // render_finished[image_index] from being re-signaled while a prior present
        // may still hold a reference to it (VUID-vkQueueSubmit-pSignalSemaphores-00067).
        if (self.frame_sync.images_in_flight[image_index] != .null_handle) {
            try vk.check(dev.wait_for_fences(
                dev.handle,
                1,
                @ptrCast(&self.frame_sync.images_in_flight[image_index]),
                vk.TRUE,
                std.math.maxInt(u64),
            ));
        }
        // This frame's fence now owns image_index.
        self.frame_sync.images_in_flight[image_index] = self.frame_sync.in_flight[frame];

        // Reset the fence only after we know we're going to submit (else we'd deadlock).
        try vk.check(dev.reset_fences(dev.handle, 1, @ptrCast(&self.frame_sync.in_flight[frame])));

        // Reset and re-record this frame's command buffer.
        try self.frame_cmd.resetFrame(frame);
        const cmd = self.frame_cmd.buffers[frame];

        const begin_info = vk.CommandBufferBeginInfo{
            .flags = .{ .one_time_submit = true },
        };
        try vk.check(dev.begin_command_buffer(cmd, &begin_info));

        const clear_value = vk.ClearValue{ .color = .{ .float32 = clear_color } };
        const rp_begin = vk.RenderPassBeginInfo{
            .render_pass = self.render_pass,
            .framebuffer = self.framebuffers[image_index],
            .render_area = .{ .offset = .{ .x = 0, .y = 0 }, .extent = self.swapchain.extent },
            .clear_value_count = 1,
            .p_clear_values = @ptrCast(&clear_value),
        };
        dev.cmd_begin_render_pass(cmd, &rp_begin, .@"inline");

        return FrameContext{
            .cmd = cmd,
            .extent = self.swapchain.extent,
            .image_index = image_index,
            .frame_index = frame,
        };
    }

    /// End a frame: close the render pass, close the command buffer, submit with
    /// the correct wait/signal semaphores, present, and advance the frame index.
    ///
    /// Callers MUST pair every successful `beginFrame` with either `endFrame` or
    /// `abortFrame`. The classic foot-gun: error path between begin and end leaves
    /// `in_flight[frame_index]` unsignaled, and the next frame's
    /// `wait_for_fences(maxInt(u64))` would block forever. Use an `errdefer
    /// renderer.abortFrame(ctx)` at the call site to keep the fence loop alive.
    pub fn endFrame(self: *Renderer, ctx: FrameContext) !void {
        std.debug.assert(ctx.frame_index == self.current_frame);
        const dev = &self.device.api;
        const cmd = ctx.cmd;
        const frame = ctx.frame_index;
        const image_index = ctx.image_index;

        dev.cmd_end_render_pass(cmd);
        try vk.check(dev.end_command_buffer(cmd));

        const wait_stages = [_]vk.PipelineStageFlags{.{ .color_attachment_output = true }};
        const wait_sems = [_]vk.Semaphore{self.frame_sync.image_acquired[frame]};
        const signal_sems = [_]vk.Semaphore{self.frame_sync.render_finished[image_index]};
        const submit = vk.SubmitInfo{
            .wait_semaphore_count = 1,
            .p_wait_semaphores = &wait_sems,
            .p_wait_dst_stage_mask = &wait_stages,
            .command_buffer_count = 1,
            .p_command_buffers = @ptrCast(&cmd),
            .signal_semaphore_count = 1,
            .p_signal_semaphores = &signal_sems,
        };
        try vk.check(dev.queue_submit(self.device.graphics_queue, 1, @ptrCast(&submit), self.frame_sync.in_flight[frame]));

        const present_info = vk.PresentInfoKHR{
            .wait_semaphore_count = 1,
            .p_wait_semaphores = &signal_sems,
            .swapchain_count = 1,
            .p_swapchains = @ptrCast(&self.swapchain.handle),
            .p_image_indices = @ptrCast(&image_index),
        };
        const present_result = dev.queue_present_khr(self.device.present_queue, &present_info);
        switch (present_result) {
            .success => {},
            .suboptimal_khr, .error_out_of_date_khr => self.needs_recreate = true,
            else => try vk.check(present_result),
        }

        self.current_frame = (self.current_frame + 1) % FRAMES_IN_FLIGHT;
    }

    /// A frame read back from the swapchain. `pixels` is tightly packed RGBA8,
    /// row-major, top-left origin, sRGB-encoded (the swapchain format is sRGB),
    /// owned by the caller.
    pub const Capture = struct {
        pixels: []u8,
        width: u32,
        height: u32,
    };

    /// `endFrame` variant that reads the rendered image back to host memory
    /// before presenting. Serializes the GPU (fence wait + one-shot transfer +
    /// queue idle) — screenshot/validation paths only, never the hot loop.
    pub fn endFrameCapture(self: *Renderer, ctx: FrameContext, allocator: std.mem.Allocator) !Capture {
        std.debug.assert(ctx.frame_index == self.current_frame);
        if (!self.swapchain.readback) return error.ReadbackUnsupported;
        const dev = &self.device.api;
        const cmd = ctx.cmd;
        const frame = ctx.frame_index;
        const image_index = ctx.image_index;

        dev.cmd_end_render_pass(cmd);
        try vk.check(dev.end_command_buffer(cmd));

        const wait_stages = [_]vk.PipelineStageFlags{.{ .color_attachment_output = true }};
        const wait_sems = [_]vk.Semaphore{self.frame_sync.image_acquired[frame]};
        const signal_sems = [_]vk.Semaphore{self.frame_sync.render_finished[image_index]};
        const submit = vk.SubmitInfo{
            .wait_semaphore_count = 1,
            .p_wait_semaphores = &wait_sems,
            .p_wait_dst_stage_mask = &wait_stages,
            .command_buffer_count = 1,
            .p_command_buffers = @ptrCast(&cmd),
            .signal_semaphore_count = 1,
            .p_signal_semaphores = &signal_sems,
        };
        try vk.check(dev.queue_submit(self.device.graphics_queue, 1, @ptrCast(&submit), self.frame_sync.in_flight[frame]));

        // Render finished ⇒ the image (in present_src_khr, not yet presented)
        // is safe to transition and copy.
        try vk.check(dev.wait_for_fences(dev.handle, 1, @ptrCast(&self.frame_sync.in_flight[frame]), vk.TRUE, std.math.maxInt(u64)));

        const w = self.swapchain.extent.width;
        const h = self.swapchain.extent.height;
        const byte_count: u64 = @as(u64, w) * @as(u64, h) * 4;

        var staging = try buffer_mod.Buffer.create(
            self.device,
            byte_count,
            .{ .transfer_dst = true },
            .{ .host_visible = true, .host_coherent = true },
        );
        defer staging.destroy();

        try self.recordReadback(self.swapchain.images[image_index], staging.handle, w, h);

        // BGRA (b8g8r8a8 swapchain) → RGBA, alpha forced opaque.
        const src = staging.mapped.?[0..@intCast(byte_count)];
        const pixels = try allocator.alloc(u8, @intCast(byte_count));
        errdefer allocator.free(pixels);
        var i: usize = 0;
        while (i < pixels.len) : (i += 4) {
            pixels[i + 0] = src[i + 2];
            pixels[i + 1] = src[i + 1];
            pixels[i + 2] = src[i + 0];
            pixels[i + 3] = 0xff;
        }

        const present_info = vk.PresentInfoKHR{
            .wait_semaphore_count = 1,
            .p_wait_semaphores = &signal_sems,
            .swapchain_count = 1,
            .p_swapchains = @ptrCast(&self.swapchain.handle),
            .p_image_indices = @ptrCast(&image_index),
        };
        const present_result = dev.queue_present_khr(self.device.present_queue, &present_info);
        switch (present_result) {
            .success => {},
            .suboptimal_khr, .error_out_of_date_khr => self.needs_recreate = true,
            else => try vk.check(present_result),
        }

        self.current_frame = (self.current_frame + 1) % FRAMES_IN_FLIGHT;
        return Capture{ .pixels = pixels, .width = w, .height = h };
    }

    /// One-shot transfer: present_src → transfer_src, copy image → buffer,
    /// transfer_src → present_src, submit, wait idle. Transient pool per call;
    /// capture frequency is a handful per process so the overhead is irrelevant.
    fn recordReadback(self: *Renderer, image: vk.Image, dst: vk.Buffer, w: u32, h: u32) !void {
        const dev = &self.device.api;

        const pool_ci = vk.CommandPoolCreateInfo{
            .flags = .{ .transient = true },
            .queue_family_index = self.device.picked.queue_family_index,
        };
        var pool: vk.CommandPool = .null_handle;
        try vk.check(dev.create_command_pool(dev.handle, &pool_ci, null, &pool));
        defer dev.destroy_command_pool(dev.handle, pool, null);

        const alloc_info = vk.CommandBufferAllocateInfo{
            .command_pool = pool,
            .level = .primary,
            .command_buffer_count = 1,
        };
        var copy_cmd: vk.CommandBuffer = .null_handle;
        try vk.check(dev.allocate_command_buffers(dev.handle, &alloc_info, @ptrCast(&copy_cmd)));

        const begin = vk.CommandBufferBeginInfo{ .flags = .{ .one_time_submit = true } };
        try vk.check(dev.begin_command_buffer(copy_cmd, &begin));

        const range = vk.ImageSubresourceRange{
            .aspect_mask = .{ .color = true },
            .base_mip_level = 0,
            .level_count = 1,
            .base_array_layer = 0,
            .layer_count = 1,
        };
        var to_src = vk.ImageMemoryBarrier{
            .src_access_mask = .{ .color_attachment_write = true },
            .dst_access_mask = .{ .transfer_read = true },
            .old_layout = .present_src_khr,
            .new_layout = .transfer_src_optimal,
            .image = image,
            .subresource_range = range,
        };
        dev.cmd_pipeline_barrier(
            copy_cmd,
            .{ .color_attachment_output = true },
            .{ .transfer = true },
            0,
            0, null,
            0, null,
            1, @ptrCast(&to_src),
        );

        const region = vk.BufferImageCopy{
            .buffer_offset = 0,
            .image_subresource = .{
                .aspect_mask = .{ .color = true },
                .mip_level = 0,
                .base_array_layer = 0,
                .layer_count = 1,
            },
            .image_offset = .{ .x = 0, .y = 0, .z = 0 },
            .image_extent = .{ .width = w, .height = h, .depth = 1 },
        };
        dev.cmd_copy_image_to_buffer(copy_cmd, image, .transfer_src_optimal, dst, 1, @ptrCast(&region));

        var to_present = vk.ImageMemoryBarrier{
            .src_access_mask = .{ .transfer_read = true },
            .dst_access_mask = .{},
            .old_layout = .transfer_src_optimal,
            .new_layout = .present_src_khr,
            .image = image,
            .subresource_range = range,
        };
        dev.cmd_pipeline_barrier(
            copy_cmd,
            .{ .transfer = true },
            .{ .bottom_of_pipe = true },
            0,
            0, null,
            0, null,
            1, @ptrCast(&to_present),
        );

        try vk.check(dev.end_command_buffer(copy_cmd));
        const submit = vk.SubmitInfo{
            .command_buffer_count = 1,
            .p_command_buffers = @ptrCast(&copy_cmd),
        };
        try vk.check(dev.queue_submit(self.device.graphics_queue, 1, @ptrCast(&submit), .null_handle));
        try vk.check(dev.queue_wait_idle(self.device.graphics_queue));
    }

    /// Emergency path: caller errored between `beginFrame` and `endFrame`. Close
    /// whatever recording state the command buffer is in, submit an empty batch
    /// signaling `in_flight[frame_index]` so the next frame's fence wait can
    /// progress. Best-effort: every failure here is logged-and-swallowed because
    /// the alternative is a permanent deadlock.
    pub fn abortFrame(self: *Renderer, ctx: FrameContext) void {
        const dev = &self.device.api;
        // The command buffer may or may not still be inside a render pass; both
        // are recoverable. `vkEndCommandBuffer` is valid whether or not a render
        // pass was active, as long as one was begun on this cmd buffer.
        dev.cmd_end_render_pass(ctx.cmd);
        _ = dev.end_command_buffer(ctx.cmd);
        const submit = vk.SubmitInfo{};
        _ = dev.queue_submit(self.device.graphics_queue, 1, @ptrCast(&submit), self.frame_sync.in_flight[ctx.frame_index]);
        // We do NOT advance current_frame — the next iteration retries this slot.
        self.needs_recreate = true;
        log.warn("abortFrame: empty submit to unblock fence in_flight[{d}]", .{ctx.frame_index});
    }

    /// Convenience wrapper: begin a frame, draw the smoke-test triangle, end frame.
    /// Used by `vk-smoke` to validate the renderer end-to-end without ImGui.
    /// Returns true if a frame was rendered, false if it was skipped.
    pub fn renderClear(self: *Renderer, color: [4]f32) !bool {
        const ctx_opt = try self.beginFrame(color);
        const ctx = ctx_opt orelse return false;
        const dev = &self.device.api;

        dev.cmd_bind_pipeline(ctx.cmd, .graphics, self.triangle_pipeline);
        const viewport = vk.Viewport{
            .x = 0, .y = 0,
            .width = @floatFromInt(ctx.extent.width),
            .height = @floatFromInt(ctx.extent.height),
            .min_depth = 0, .max_depth = 1,
        };
        const scissor = vk.Rect2D{ .offset = .{ .x = 0, .y = 0 }, .extent = ctx.extent };
        dev.cmd_set_viewport(ctx.cmd, 0, 1, @ptrCast(&viewport));
        dev.cmd_set_scissor(ctx.cmd, 0, 1, @ptrCast(&scissor));
        dev.cmd_draw(ctx.cmd, 3, 1, 0, 0);

        try self.endFrame(ctx);
        return true;
    }

    fn handleRecreate(self: *Renderer) !void {
        var fb_w: c_int = 0;
        var fb_h: c_int = 0;
        glfw.glfwGetFramebufferSize(self.window, &fb_w, &fb_h);
        if (fb_w == 0 or fb_h == 0) return; // still minimized; needs_recreate stays true

        self.device.waitIdle();
        destroyFramebuffers(self.allocator, self.device, self.framebuffers);
        self.framebuffers = &[_]vk.Framebuffer{};

        const new_extent = vk.Extent2D{ .width = @intCast(fb_w), .height = @intCast(fb_h) };
        self.swapchain.recreate(new_extent) catch |err| switch (err) {
            error.WindowMinimized => return,
            else => return err,
        };

        // Render pass is format-dependent; if the format changed, rebuild it too.
        // For our purposes (no format change expected), keep the existing render pass.

        self.framebuffers = try createFramebuffers(self.allocator, self.device, self.render_pass, &self.swapchain);

        if (self.frame_sync.render_finished.len != self.swapchain.images.len) {
            self.frame_sync.destroy();
            self.frame_sync = try FrameSync.create(
                self.allocator,
                self.device,
                @intCast(self.swapchain.images.len),
            );
        } else {
            // Reset images_in_flight aliases — the old fence aliases are stale after
            // device-wait-idle / recreate.
            @memset(self.frame_sync.images_in_flight, .null_handle);
        }

        self.needs_recreate = false;
    }
};

fn createClearRenderPass(device: *Device, color_format: vk.Format) !vk.RenderPass {
    const attachment = vk.AttachmentDescription{
        .format = color_format,
        .samples = .{ .@"1" = true },
        .load_op = .clear,
        .store_op = .store,
        .stencil_load_op = .dont_care,
        .stencil_store_op = .dont_care,
        .initial_layout = .undefined,
        .final_layout = .present_src_khr,
    };
    const color_ref = vk.AttachmentReference{
        .attachment = 0,
        .layout = .color_attachment_optimal,
    };
    const subpass = vk.SubpassDescription{
        .pipeline_bind_point = .graphics,
        .color_attachment_count = 1,
        .p_color_attachments = @ptrCast(&color_ref),
    };
    const dep = vk.SubpassDependency{
        .src_subpass = vk.SUBPASS_EXTERNAL,
        .dst_subpass = 0,
        .src_stage_mask = .{ .color_attachment_output = true },
        .dst_stage_mask = .{ .color_attachment_output = true },
        .src_access_mask = .{},
        .dst_access_mask = .{ .color_attachment_write = true },
    };
    const ci = vk.RenderPassCreateInfo{
        .attachment_count = 1,
        .p_attachments = @ptrCast(&attachment),
        .subpass_count = 1,
        .p_subpasses = @ptrCast(&subpass),
        .dependency_count = 1,
        .p_dependencies = @ptrCast(&dep),
    };
    var rp: vk.RenderPass = .null_handle;
    try vk.check(device.api.create_render_pass(device.api.handle, &ci, null, &rp));
    return rp;
}

fn createFramebuffers(
    allocator: std.mem.Allocator,
    device: *Device,
    render_pass: vk.RenderPass,
    swapchain: *const Swapchain,
) ![]vk.Framebuffer {
    const fbs = try allocator.alloc(vk.Framebuffer, swapchain.image_views.len);
    @memset(fbs, .null_handle);
    errdefer destroyFramebuffers(allocator, device, fbs);

    for (swapchain.image_views, 0..) |view, i| {
        const ci = vk.FramebufferCreateInfo{
            .render_pass = render_pass,
            .attachment_count = 1,
            .p_attachments = @ptrCast(&view),
            .width = swapchain.extent.width,
            .height = swapchain.extent.height,
            .layers = 1,
        };
        try vk.check(device.api.create_framebuffer(device.api.handle, &ci, null, &fbs[i]));
    }
    return fbs;
}

fn destroyFramebuffers(allocator: std.mem.Allocator, device: *Device, fbs: []vk.Framebuffer) void {
    for (fbs) |fb| {
        if (fb != .null_handle) device.api.destroy_framebuffer(device.api.handle, fb, null);
    }
    if (fbs.len != 0) allocator.free(fbs);
}
