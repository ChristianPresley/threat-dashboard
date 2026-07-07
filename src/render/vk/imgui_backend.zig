//! Custom ImGui Vulkan backend.
//!
//! Responsibilities:
//!   - Init: descriptor set layout (one combined image sampler), descriptor pool,
//!     pipeline layout with push constants for `(vec2 scale, vec2 translate)`,
//!     graphics pipeline using `imgui.vert.spv` + `imgui.frag.spv`, a single
//!     sampler.
//!   - Font atlas upload: take ImGui's atlas pixels (alpha-8 or RGBA32), copy
//!     into a VkImage via a staging buffer, transition layouts, write a
//!     descriptor set pointing at the atlas image.
//!   - Per-frame render: walk `ImDrawData` via zgui's existing accessors and
//!     emit Vulkan draws.
//!   - Destroy: tear down everything in reverse order.
//!
//! Current scope: single-texture path (one font atlas → one descriptor set).
//! Future MSDF text work will add a second pipeline (sharing this layout) and
//! switch the bound atlas per draw cmd via `ImTextureRef.tex_id`.

const std = @import("std");
const vk = @import("vk.zig");
const Device = @import("device.zig").Device;
const pipeline_mod = @import("pipeline.zig");
const buffer_mod = @import("buffer.zig");
const shaders = @import("../shaders/shaders.zig");
const FRAMES_IN_FLIGHT = @import("sync.zig").FRAMES_IN_FLIGHT;
const zgui = @import("zgui");

const log = std.log.scoped(.vk_imgui);

/// Push constant block size for the ImGui vertex shader (vec2 scale + vec2 translate).
const PUSH_CONSTANT_BYTES: u32 = @sizeOf([4]f32);
/// `ImDrawVert` layout: vec2 pos + vec2 uv + u32 packed color.
const IMDRAW_VERT_STRIDE: u32 = @sizeOf(zgui.DrawVert);
/// Descriptor pool capacity. Sized for the one font atlas plus headroom for
/// future texture registrations (e.g. an MSDF atlas, dashboard imagery).
const MAX_TEXTURES: u32 = 16;

/// Per-frame-in-flight vertex + index buffer pair. Grows on demand to fit the
/// current frame's ImGui vertex/index counts. Mapped persistently so each frame
/// is a memcpy + memcpy.
const FrameBuffers = struct {
    vtx: buffer_mod.Buffer = .{ .device = undefined },
    idx: buffer_mod.Buffer = .{ .device = undefined },
    vtx_capacity: u64 = 0,
    idx_capacity: u64 = 0,

    fn ensure(self: *FrameBuffers, device: *Device, vtx_bytes: u64, idx_bytes: u64) !void {
        if (vtx_bytes > self.vtx_capacity) {
            self.vtx.destroy();
            const new_cap = nextCapacity(self.vtx_capacity, vtx_bytes);
            self.vtx = try buffer_mod.Buffer.create(
                device,
                new_cap,
                .{ .vertex_buffer = true },
                .{ .host_visible = true, .host_coherent = true },
            );
            self.vtx_capacity = new_cap;
        }
        if (idx_bytes > self.idx_capacity) {
            self.idx.destroy();
            const new_cap = nextCapacity(self.idx_capacity, idx_bytes);
            self.idx = try buffer_mod.Buffer.create(
                device,
                new_cap,
                .{ .index_buffer = true },
                .{ .host_visible = true, .host_coherent = true },
            );
            self.idx_capacity = new_cap;
        }
    }

    fn destroy(self: *FrameBuffers) void {
        self.vtx.destroy();
        self.idx.destroy();
    }

    fn nextCapacity(current: u64, needed: u64) u64 {
        const grown = if (current == 0) @as(u64, 64 * 1024) else current + current / 2;
        return @max(grown, needed);
    }
};

pub const ImGuiBackend = struct {
    allocator: std.mem.Allocator,
    device: *Device,

    // Pipeline resources.
    descriptor_set_layout: vk.DescriptorSetLayout = .null_handle,
    descriptor_pool: vk.DescriptorPool = .null_handle,
    pipeline_layout: vk.PipelineLayout = .null_handle,
    pipeline: vk.Pipeline = .null_handle,
    sampler: vk.Sampler = .null_handle,

    // Font atlas (owned by the backend in this legacy path).
    atlas_image: buffer_mod.Image = .{ .device = undefined },
    atlas_descriptor: vk.DescriptorSet = .null_handle,

    // Per-frame vertex/index ring (grows on demand).
    frame_buffers: [FRAMES_IN_FLIGHT]FrameBuffers = [_]FrameBuffers{.{}} ** FRAMES_IN_FLIGHT,

    pub const InitOptions = struct {
        render_pass: vk.RenderPass,
        pipeline_cache: vk.PipelineCache,
        /// 8-bit alpha font atlas pixels from ImGui's `IO.Fonts->GetTexDataAsAlpha8`.
        /// The backend copies these into a VkImage and forgets the pointer.
        atlas_alpha_pixels: []const u8,
        atlas_width: u32,
        atlas_height: u32,
    };

    pub fn create(
        allocator: std.mem.Allocator,
        device: *Device,
        opts: InitOptions,
    ) !ImGuiBackend {
        var self: ImGuiBackend = .{
            .allocator = allocator,
            .device = device,
        };
        errdefer self.destroy();

        try self.createDescriptors();
        try self.createSampler();
        try self.createPipeline(opts.render_pass, opts.pipeline_cache);
        try self.uploadAtlas(opts.atlas_alpha_pixels, opts.atlas_width, opts.atlas_height);

        return self;
    }

    pub fn destroy(self: *ImGuiBackend) void {
        // The last submitted frame may still be running on the GPU when
        // the app exits. Destroying buffers/images/pipelines that are
        // still referenced by in-flight command buffers is a validation
        // error (VUID-vkDestroyBuffer-buffer-00922 et al.), so block
        // until the device is idle before tearing anything down.
        self.device.waitIdle();
        for (&self.frame_buffers) |*fb| fb.destroy();
        self.atlas_image.destroy();
        if (self.pipeline != .null_handle) {
            self.device.api.destroy_pipeline(self.device.api.handle, self.pipeline, null);
            self.pipeline = .null_handle;
        }
        if (self.pipeline_layout != .null_handle) {
            self.device.api.destroy_pipeline_layout(self.device.api.handle, self.pipeline_layout, null);
            self.pipeline_layout = .null_handle;
        }
        if (self.sampler != .null_handle) {
            self.device.api.destroy_sampler(self.device.api.handle, self.sampler, null);
            self.sampler = .null_handle;
        }
        if (self.descriptor_pool != .null_handle) {
            self.device.api.destroy_descriptor_pool(self.device.api.handle, self.descriptor_pool, null);
            self.descriptor_pool = .null_handle;
        }
        if (self.descriptor_set_layout != .null_handle) {
            self.device.api.destroy_descriptor_set_layout(self.device.api.handle, self.descriptor_set_layout, null);
            self.descriptor_set_layout = .null_handle;
        }
    }

    fn createDescriptors(self: *ImGuiBackend) !void {
        // One binding: combined image sampler for the (font / texture) atlas.
        const binding = vk.DescriptorSetLayoutBinding{
            .binding = 0,
            .descriptor_type = .combined_image_sampler,
            .descriptor_count = 1,
            .stage_flags = .{ .fragment = true },
        };
        const layout_ci = vk.DescriptorSetLayoutCreateInfo{
            .binding_count = 1,
            .p_bindings = @ptrCast(&binding),
        };
        try vk.check(self.device.api.create_descriptor_set_layout(self.device.api.handle, &layout_ci, null, &self.descriptor_set_layout));

        const pool_size = vk.DescriptorPoolSize{
            .type_ = .combined_image_sampler,
            .descriptor_count = MAX_TEXTURES,
        };
        const pool_ci = vk.DescriptorPoolCreateInfo{
            .max_sets = MAX_TEXTURES,
            .pool_size_count = 1,
            .p_pool_sizes = @ptrCast(&pool_size),
        };
        try vk.check(self.device.api.create_descriptor_pool(self.device.api.handle, &pool_ci, null, &self.descriptor_pool));
    }

    fn createSampler(self: *ImGuiBackend) !void {
        const ci = vk.SamplerCreateInfo{
            .mag_filter = .linear,
            .min_filter = .linear,
            .mipmap_mode = .linear,
            .address_mode_u = .clamp_to_edge,
            .address_mode_v = .clamp_to_edge,
            .address_mode_w = .clamp_to_edge,
            .min_lod = -1000,
            .max_lod = 1000,
        };
        try vk.check(self.device.api.create_sampler(self.device.api.handle, &ci, null, &self.sampler));
    }

    fn createPipeline(self: *ImGuiBackend, render_pass: vk.RenderPass, cache: vk.PipelineCache) !void {
        // Pipeline layout: one descriptor set + push constants for the projection.
        const push_range = vk.PushConstantRange{
            .stage_flags = .{ .vertex = true },
            .offset = 0,
            .size = PUSH_CONSTANT_BYTES,
        };
        const layout_ci = vk.PipelineLayoutCreateInfo{
            .set_layout_count = 1,
            .p_set_layouts = @ptrCast(&self.descriptor_set_layout),
            .push_constant_range_count = 1,
            .p_push_constant_ranges = @ptrCast(&push_range),
        };
        try vk.check(self.device.api.create_pipeline_layout(self.device.api.handle, &layout_ci, null, &self.pipeline_layout));

        // Vertex layout matches ImDrawVert: pos (vec2 r32g32_sfloat), uv (vec2
        // r32g32_sfloat), col (4 bytes r8g8b8a8_unorm).
        const binding = vk.VertexInputBindingDescription{
            .binding = 0,
            .stride = IMDRAW_VERT_STRIDE,
            .input_rate = .vertex,
        };
        const attrs = [_]vk.VertexInputAttributeDescription{
            .{ .location = 0, .binding = 0, .format = .r32g32_sfloat, .offset = 0 },
            .{ .location = 1, .binding = 0, .format = .r32g32_sfloat, .offset = 8 },
            .{ .location = 2, .binding = 0, .format = .r8g8b8a8_unorm, .offset = 16 },
        };

        const vert = try pipeline_mod.createShaderModule(self.device, &shaders.imgui_vert);
        defer pipeline_mod.destroyShaderModule(self.device, vert);
        const frag = try pipeline_mod.createShaderModule(self.device, &shaders.imgui_frag);
        defer pipeline_mod.destroyShaderModule(self.device, frag);

        self.pipeline = try pipeline_mod.createGraphicsPipeline(self.device, cache, .{
            .vert_module = vert,
            .frag_module = frag,
            .render_pass = render_pass,
            .pipeline_layout = self.pipeline_layout,
            .vertex_input = .{
                .bindings = @ptrCast(&binding),
                .attributes = &attrs,
            },
            .blend = .alpha,
        });
    }

    fn uploadAtlas(
        self: *ImGuiBackend,
        pixels: []const u8,
        width: u32,
        height: u32,
    ) !void {
        // Widen alpha8 -> RGBA8 so the existing imgui.frag.glsl (samples a vec4)
        // works unchanged.
        const pixel_count = @as(usize, width) * @as(usize, height);
        if (pixel_count != pixels.len) return error.AtlasSizeMismatch;

        const rgba = try self.allocator.alloc(u8, pixel_count * 4);
        defer self.allocator.free(rgba);
        for (pixels, 0..) |a, i| {
            rgba[i * 4 + 0] = 0xFF;
            rgba[i * 4 + 1] = 0xFF;
            rgba[i * 4 + 2] = 0xFF;
            rgba[i * 4 + 3] = a;
        }

        // Create the GPU image.
        self.atlas_image = try buffer_mod.Image.create(
            self.device,
            .{ .width = width, .height = height },
            .r8g8b8a8_unorm,
            .{ .transfer_dst = true, .sampled = true },
        );

        // Staging buffer.
        var staging = try buffer_mod.Buffer.create(
            self.device,
            rgba.len,
            .{ .transfer_src = true },
            .{ .host_visible = true, .host_coherent = true },
        );
        defer staging.destroy();
        @memcpy(staging.mapped.?[0..rgba.len], rgba);

        const pool_ci = vk.CommandPoolCreateInfo{
            .flags = .{ .transient = true },
            .queue_family_index = self.device.picked.queue_family_index,
        };
        var upload_pool: vk.CommandPool = .null_handle;
        try vk.check(self.device.api.create_command_pool(self.device.api.handle, &pool_ci, null, &upload_pool));
        defer self.device.api.destroy_command_pool(self.device.api.handle, upload_pool, null);

        try self.recordAndSubmitUpload(upload_pool, self.device.graphics_queue, &staging, width, height);

        // Allocate the descriptor set the first time; subsequent atlas
        // re-uploads reuse it and only re-write the image_view binding.
        if (self.atlas_descriptor == .null_handle) {
            const alloc_info = vk.DescriptorSetAllocateInfo{
                .descriptor_pool = self.descriptor_pool,
                .descriptor_set_count = 1,
                .p_set_layouts = @ptrCast(&self.descriptor_set_layout),
            };
            try vk.check(self.device.api.allocate_descriptor_sets(self.device.api.handle, &alloc_info, @ptrCast(&self.atlas_descriptor)));
        }

        const img_info = vk.DescriptorImageInfo{
            .sampler = self.sampler,
            .image_view = self.atlas_image.view,
            .image_layout = .shader_read_only_optimal,
        };
        const write = vk.WriteDescriptorSet{
            .dst_set = self.atlas_descriptor,
            .dst_binding = 0,
            .descriptor_count = 1,
            .descriptor_type = .combined_image_sampler,
            .p_image_info = @ptrCast(&img_info),
        };
        self.device.api.update_descriptor_sets(self.device.api.handle, 1, @ptrCast(&write), 0, null);

        log.info("ImGui font atlas uploaded ({d}x{d})", .{ width, height });
    }

    fn recordAndSubmitUpload(
        self: *ImGuiBackend,
        pool: vk.CommandPool,
        queue: vk.Queue,
        staging: *buffer_mod.Buffer,
        width: u32,
        height: u32,
    ) !void {
        const alloc_info = vk.CommandBufferAllocateInfo{
            .command_pool = pool,
            .level = .primary,
            .command_buffer_count = 1,
        };
        var cmd: vk.CommandBuffer = .null_handle;
        try vk.check(self.device.api.allocate_command_buffers(self.device.api.handle, &alloc_info, @ptrCast(&cmd)));
        defer self.device.api.free_command_buffers(self.device.api.handle, pool, 1, @ptrCast(&cmd));

        const begin = vk.CommandBufferBeginInfo{ .flags = .{ .one_time_submit = true } };
        try vk.check(self.device.api.begin_command_buffer(cmd, &begin));

        // Transition: undefined → transfer_dst_optimal
        var barrier1 = vk.ImageMemoryBarrier{
            .src_access_mask = .{},
            .dst_access_mask = .{ .transfer_write = true },
            .old_layout = .undefined,
            .new_layout = .transfer_dst_optimal,
            .image = self.atlas_image.handle,
            .subresource_range = .{
                .aspect_mask = .{ .color = true },
                .base_mip_level = 0,
                .level_count = 1,
                .base_array_layer = 0,
                .layer_count = 1,
            },
        };
        self.device.api.cmd_pipeline_barrier(
            cmd,
            .{ .top_of_pipe = true },
            .{ .transfer = true },
            0,
            0, null,
            0, null,
            1, @ptrCast(&barrier1),
        );

        // Copy staging buffer → image.
        const region = vk.BufferImageCopy{
            .buffer_offset = 0,
            .image_subresource = .{
                .aspect_mask = .{ .color = true },
                .mip_level = 0,
                .base_array_layer = 0,
                .layer_count = 1,
            },
            .image_offset = .{ .x = 0, .y = 0, .z = 0 },
            .image_extent = .{ .width = width, .height = height, .depth = 1 },
        };
        self.device.api.cmd_copy_buffer_to_image(
            cmd,
            staging.handle,
            self.atlas_image.handle,
            .transfer_dst_optimal,
            1,
            @ptrCast(&region),
        );

        // Transition: transfer_dst_optimal → shader_read_only_optimal
        var barrier2 = vk.ImageMemoryBarrier{
            .src_access_mask = .{ .transfer_write = true },
            .dst_access_mask = .{ .shader_read = true },
            .old_layout = .transfer_dst_optimal,
            .new_layout = .shader_read_only_optimal,
            .image = self.atlas_image.handle,
            .subresource_range = barrier1.subresource_range,
        };
        self.device.api.cmd_pipeline_barrier(
            cmd,
            .{ .transfer = true },
            .{ .fragment_shader = true },
            0,
            0, null,
            0, null,
            1, @ptrCast(&barrier2),
        );

        try vk.check(self.device.api.end_command_buffer(cmd));

        const submit = vk.SubmitInfo{
            .command_buffer_count = 1,
            .p_command_buffers = @ptrCast(&cmd),
        };
        try vk.check(self.device.api.queue_submit(queue, 1, @ptrCast(&submit), .null_handle));
        try vk.check(self.device.api.queue_wait_idle(queue));
    }

    /// Iterate ImGui's textures and apply any pending GPU operations. Run at
    /// the top of `render` so freshly added glyphs are visible the same frame.
    fn processTextureUpdates(self: *ImGuiBackend) !void {
        const textures = zgui.platform_io.getTextures();
        const count: usize = @intCast(textures.len);
        var i: usize = 0;
        while (i < count) : (i += 1) {
            const tex = textures.items[i];
            switch (tex.status) {
                .ok, .destroyed => {},
                .want_create, .want_updates => {
                    try self.recreateAtlasFromTex(tex);
                    tex.status = .ok;
                },
                .want_destroy => {
                    // We only ever bind one font atlas at a time and we destroy
                    // the image in our own `destroy()`. Nothing to do here.
                    tex.status = .destroyed;
                },
            }
        }
    }

    /// Tear down the current atlas image (if any) and re-upload from the
    /// supplied texture data. Updates the descriptor binding to the new image.
    /// Called both on `.want_create` (size changed, image must be new) and
    /// `.want_updates` (pixels changed; simpler to recreate than partial copy).
    fn recreateAtlasFromTex(self: *ImGuiBackend, tex: *zgui.TextureData) !void {
        // Make sure no in-flight frame is sampling the current atlas image
        // before we destroy it.
        self.device.waitIdle();

        const width: u32 = @intCast(tex.width);
        const height: u32 = @intCast(tex.height);
        const pixel_count: usize = @as(usize, width) * @as(usize, height);
        const bpp: usize = @intCast(tex.bytes_per_pixel);
        const bytes = tex.pixels[0 .. pixel_count * bpp];

        // Extract alpha channel so the path matches the init upload.
        var alpha8_buf: ?[]u8 = null;
        defer if (alpha8_buf) |b| self.allocator.free(b);
        const alpha8 = switch (tex.format) {
            .alpha8 => bytes,
            .rgba32 => blk: {
                const buf = try self.allocator.alloc(u8, pixel_count);
                var pi: usize = 0;
                while (pi < pixel_count) : (pi += 1) buf[pi] = bytes[pi * 4 + 3];
                alpha8_buf = buf;
                break :blk buf;
            },
        };

        // Drop the existing image; `uploadAtlas` will create a new one and
        // re-write the (preserved) descriptor binding.
        self.atlas_image.destroy();
        self.atlas_image = .{ .device = undefined };

        try self.uploadAtlas(alpha8, width, height);

        // The descriptor handle didn't change, but main.zig set
        // `tex.tex_id = atlas_descriptor` at init; ImGui uses that as the
        // bind key. Re-stamp it in case ImGui zeroed it during a recreate.
        tex.tex_id = @enumFromInt(@as(u64, @intFromEnum(self.atlas_descriptor)));
    }

    /// Walk ImGui's draw data and emit Vulkan commands. Must be called inside an
    /// active render pass; the renderer's `beginFrame` puts us there.
    ///
    /// `frame_index` is the frame-in-flight slot (0..FRAMES_IN_FLIGHT-1) — used to
    /// pick the per-frame vertex/index buffer pair so we don't stomp data the GPU
    /// is still reading from a previous submit.
    pub fn render(
        self: *ImGuiBackend,
        cmd: vk.CommandBuffer,
        framebuffer_size: vk.Extent2D,
        frame_index: u32,
    ) !void {
        // ImGui 1.92 lazily appends glyphs to the font atlas as new characters
        // are encountered. The atlas texture is flagged `.want_updates` (or
        // `.want_create` if it grew). Re-upload our VkImage from the current
        // pixel data so the next draws can sample the freshly added glyphs.
        try self.processTextureUpdates();

        const dd = zgui.getDrawData();
        if (dd.cmd_lists_count <= 0 or dd.total_vtx_count <= 0 or dd.total_idx_count <= 0) return;

        const dev = &self.device.api;

        const vtx_total: u64 = @intCast(@as(u64, @intCast(dd.total_vtx_count)) * @sizeOf(zgui.DrawVert));
        const idx_total: u64 = @intCast(@as(u64, @intCast(dd.total_idx_count)) * @sizeOf(zgui.DrawIdx));

        const fb = &self.frame_buffers[frame_index];
        try fb.ensure(self.device, vtx_total, idx_total);

        // Copy vertex/index data into the per-frame buffers at running offsets.
        var vtx_offset: usize = 0;
        var idx_offset: usize = 0;
        const vtx_dst = fb.vtx.mapped.?;
        const idx_dst = fb.idx.mapped.?;
        const cmd_list_count: usize = @intCast(dd.cmd_lists_count);
        var li: usize = 0;
        while (li < cmd_list_count) : (li += 1) {
            const list = dd.cmd_lists.items[li];
            const verts = list.getVertexBuffer();
            const idxs = list.getIndexBuffer();
            const vsize = verts.len * @sizeOf(zgui.DrawVert);
            const ibytes = idxs.len * @sizeOf(zgui.DrawIdx);
            @memcpy(vtx_dst[vtx_offset .. vtx_offset + vsize], std.mem.sliceAsBytes(verts));
            @memcpy(idx_dst[idx_offset .. idx_offset + ibytes], std.mem.sliceAsBytes(idxs));
            vtx_offset += vsize;
            idx_offset += ibytes;
        }

        // Bind pipeline + vertex/index buffers once per frame. The texture
        // descriptor binds per DrawCmd below (keyed by DrawCmd.texture_ref),
        // so images / future MSDF atlases sample their own texture instead of
        // silently sampling the font atlas.
        dev.cmd_bind_pipeline(cmd, .graphics, self.pipeline);
        const vtx_buf_offsets = [_]u64{0};
        dev.cmd_bind_vertex_buffers(cmd, 0, 1, @ptrCast(&fb.vtx.handle), &vtx_buf_offsets);
        dev.cmd_bind_index_buffer(cmd, fb.idx.handle, 0, if (zgui.DrawIdx == u16) .uint16 else .uint32);

        // Viewport: framebuffer-sized, set once.
        const viewport = vk.Viewport{
            .x = 0, .y = 0,
            .width = @floatFromInt(framebuffer_size.width),
            .height = @floatFromInt(framebuffer_size.height),
            .min_depth = 0, .max_depth = 1,
        };
        dev.cmd_set_viewport(cmd, 0, 1, @ptrCast(&viewport));

        // Push constants: project ImGui's display-space coords to clip space.
        const scale = [2]f32{ 2.0 / dd.display_size[0], 2.0 / dd.display_size[1] };
        const translate = [2]f32{
            -1.0 - dd.display_pos[0] * scale[0],
            -1.0 - dd.display_pos[1] * scale[1],
        };
        var push_block: [4]f32 = .{ scale[0], scale[1], translate[0], translate[1] };
        dev.cmd_push_constants(
            cmd,
            self.pipeline_layout,
            .{ .vertex = true },
            0,
            @sizeOf([4]f32),
            @ptrCast(&push_block),
        );

        // Walk each list and emit per-DrawCmd scissor + indexed draw.
        const clip_off = dd.display_pos;
        const clip_scale = dd.framebuffer_scale;
        // Clamp scissor to ImGui's expected framebuffer size (display_size × fb_scale)
        // rather than the swapchain extent — they can disagree mid-resize and a
        // scissor that exceeds the framebuffer trips a validation error.
        const fb_w_f: f32 = dd.display_size[0] * clip_scale[0];
        const fb_h_f: f32 = dd.display_size[1] * clip_scale[1];
        var saw_callback = false;
        var global_vtx_offset: u32 = 0;
        var global_idx_offset: u32 = 0;
        var bound_descriptor: vk.DescriptorSet = .null_handle;
        var list_i: usize = 0;
        while (list_i < cmd_list_count) : (list_i += 1) {
            const list = dd.cmd_lists.items[list_i];
            const cmds = list.getCmdBuffer();
            for (cmds) |c| {
                if (c.user_callback != null) {
                    if (!saw_callback) {
                        log.warn("ImGui DrawCmd.user_callback ignored (not supported by this backend)", .{});
                        saw_callback = true;
                    }
                    continue;
                }
                if (c.elem_count == 0) continue;

                // Project clip rect from ImGui display space to framebuffer pixel space.
                var clip_min_x = (c.clip_rect[0] - clip_off[0]) * clip_scale[0];
                var clip_min_y = (c.clip_rect[1] - clip_off[1]) * clip_scale[1];
                var clip_max_x = (c.clip_rect[2] - clip_off[0]) * clip_scale[0];
                var clip_max_y = (c.clip_rect[3] - clip_off[1]) * clip_scale[1];
                if (clip_min_x < 0) clip_min_x = 0;
                if (clip_min_y < 0) clip_min_y = 0;
                if (clip_max_x > fb_w_f) clip_max_x = fb_w_f;
                if (clip_max_y > fb_h_f) clip_max_y = fb_h_f;
                if (clip_max_x <= clip_min_x or clip_max_y <= clip_min_y) continue;

                const scissor = vk.Rect2D{
                    .offset = .{ .x = @intFromFloat(clip_min_x), .y = @intFromFloat(clip_min_y) },
                    .extent = .{
                        .width = @intFromFloat(clip_max_x - clip_min_x),
                        .height = @intFromFloat(clip_max_y - clip_min_y),
                    },
                };
                dev.cmd_set_scissor(cmd, 0, 1, @ptrCast(&scissor));

                // Resolve the cmd's texture exactly like ImGui's GetTexID():
                // prefer tex_data.tex_id, else the inline tex_id. Backends
                // stamp a VkDescriptorSet handle into tex_id, so a non-zero
                // value binds directly; zero falls back to the font atlas.
                const tex_id: u64 = if (c.texture_ref.tex_data) |td|
                    @intFromEnum(td.tex_id)
                else
                    @intFromEnum(c.texture_ref.tex_id);
                const desired: vk.DescriptorSet = if (tex_id != 0)
                    @enumFromInt(tex_id)
                else
                    self.atlas_descriptor;
                if (desired != bound_descriptor) {
                    dev.cmd_bind_descriptor_sets(
                        cmd,
                        .graphics,
                        self.pipeline_layout,
                        0, 1, @ptrCast(&desired),
                        0, null,
                    );
                    bound_descriptor = desired;
                }

                dev.cmd_draw_indexed(
                    cmd,
                    c.elem_count,
                    1,
                    c.idx_offset + global_idx_offset,
                    @intCast(c.vtx_offset + global_vtx_offset),
                    0,
                );
            }
            global_idx_offset += @intCast(list.getIndexBuffer().len);
            global_vtx_offset += @intCast(list.getVertexBuffer().len);
        }
    }
};
