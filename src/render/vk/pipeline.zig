//! Pipeline construction helpers + an in-process VkPipelineCache.
//!
//! Disk persistence is a future enhancement — Zig 0.16 moved the filesystem API
//! to `std.Io.Dir`, and threading an Io through the renderer just for cache I/O
//! is more disruption than the ~50–200 ms startup win is worth right now. The
//! cache still works within a single process run.

const std = @import("std");
const builtin = @import("builtin");
const vk = @import("vk.zig");
const Device = @import("device.zig").Device;

const log = std.log.scoped(.vk_pipeline);

/// Compile a SPIR-V blob into a VkShaderModule. `code` must be 4-byte-aligned u8.
///
/// Zig's `@embedFile` returns byte-aligned data; the canonical pattern to satisfy
/// the alignment requirement is to declare the consuming const with explicit
/// alignment, e.g.:
///
///     const my_shader_spv align(@alignOf(u32)) = @embedFile("foo.spv").*;
///
/// The `.*` dereference + the `align(...)` qualifier on the const force the storage
/// to be u32-aligned. Without that qualifier the @embedFile bytes may sit on a
/// 1-byte boundary and the Vulkan loader will read past misaligned u32s — silent UB.
pub fn createShaderModule(device: *Device, code: []align(@alignOf(u32)) const u8) !vk.ShaderModule {
    const ci = vk.ShaderModuleCreateInfo{
        .code_size = code.len,
        .p_code = @ptrCast(code.ptr),
    };
    var module: vk.ShaderModule = .null_handle;
    try vk.check(device.api.create_shader_module(device.api.handle, &ci, null, &module));
    return module;
}

pub fn destroyShaderModule(device: *Device, module: vk.ShaderModule) void {
    if (module != .null_handle) {
        device.api.destroy_shader_module(device.api.handle, module, null);
    }
}

/// In-process VkPipelineCache. Vulkan internally reuses results across multiple
/// `vkCreateGraphicsPipelines` calls in the same process; a persistent cache
/// adds *cross-process* reuse on top of that and will be wired later (see file
/// header doc).
pub const PipelineCache = struct {
    device: *Device,
    handle: vk.PipelineCache = .null_handle,

    pub fn create(allocator: std.mem.Allocator, device: *Device, app_name: []const u8) !PipelineCache {
        _ = allocator;
        _ = app_name;
        var self: PipelineCache = .{ .device = device };
        const ci = vk.PipelineCacheCreateInfo{};
        try vk.check(device.api.create_pipeline_cache(device.api.handle, &ci, null, &self.handle));
        return self;
    }

    pub fn destroy(self: *PipelineCache) void {
        if (self.handle != .null_handle) {
            self.device.api.destroy_pipeline_cache(self.device.api.handle, self.handle, null);
            self.handle = .null_handle;
        }
    }

    /// No-op stub for now. Will write the cache to `%LOCALAPPDATA%/trading/pipeline.bin`
    /// (and the XDG equivalent on POSIX) once the renderer has an `Io` to thread through.
    pub fn save(self: *PipelineCache) void {
        _ = self;
    }
};

// ============================================================================
// Graphics pipeline builder — captures the common "viewport-and-scissor dynamic,
// triangle list, no depth/stencil, alpha-blended single color attachment" shape
// we want for both the smoke triangle and (later) the ImGui draw pipelines.
// ============================================================================

pub const GraphicsPipelineDesc = struct {
    vert_module: vk.ShaderModule,
    frag_module: vk.ShaderModule,
    render_pass: vk.RenderPass,
    pipeline_layout: vk.PipelineLayout,
    /// `null` means no vertex buffer — vertices come from SV_VertexID in the shader.
    vertex_input: ?VertexInput = null,
    topology: vk.PrimitiveTopology = .triangle_list,
    cull_mode: vk.CullModeFlags = .{},
    blend: BlendMode = .opaque_,
};

pub const VertexInput = struct {
    bindings: []const vk.VertexInputBindingDescription,
    attributes: []const vk.VertexInputAttributeDescription,
};

pub const BlendMode = enum {
    /// No blending; fragment fully overwrites destination.
    opaque_,
    /// Straight (non-premultiplied) alpha blend: src * src.a + dst * (1 - src.a).
    /// Matches ImGui's default shader which emits non-premultiplied colors.
    alpha,
    /// Premultiplied alpha blend: src + dst * (1 - src.a).
    /// Matches an MSDF text shader that emits `vec4(rgb * coverage, coverage)`.
    premultiplied_alpha,
};

pub fn createGraphicsPipeline(
    device: *Device,
    cache: vk.PipelineCache,
    desc: GraphicsPipelineDesc,
) !vk.Pipeline {
    const stages = [_]vk.PipelineShaderStageCreateInfo{
        .{ .stage = .{ .vertex = true }, .module = desc.vert_module, .p_name = "main" },
        .{ .stage = .{ .fragment = true }, .module = desc.frag_module, .p_name = "main" },
    };

    const vi = if (desc.vertex_input) |vinput| vk.PipelineVertexInputStateCreateInfo{
        .vertex_binding_description_count = @intCast(vinput.bindings.len),
        .p_vertex_binding_descriptions = vinput.bindings.ptr,
        .vertex_attribute_description_count = @intCast(vinput.attributes.len),
        .p_vertex_attribute_descriptions = vinput.attributes.ptr,
    } else vk.PipelineVertexInputStateCreateInfo{};

    const ia = vk.PipelineInputAssemblyStateCreateInfo{ .topology = desc.topology };
    const viewport_state = vk.PipelineViewportStateCreateInfo{
        .viewport_count = 1,
        .scissor_count = 1,
        // viewport/scissor supplied dynamically
    };

    const rs = vk.PipelineRasterizationStateCreateInfo{
        .polygon_mode = .fill,
        .cull_mode = desc.cull_mode,
        .front_face = .counter_clockwise,
    };

    const ms = vk.PipelineMultisampleStateCreateInfo{};

    const blend_attachment: vk.PipelineColorBlendAttachmentState = switch (desc.blend) {
        .opaque_ => .{},
        .alpha => .{
            .blend_enable = vk.TRUE,
            .src_color_blend_factor = .src_alpha,
            .dst_color_blend_factor = .one_minus_src_alpha,
            .color_blend_op = .add,
            .src_alpha_blend_factor = .one,
            .dst_alpha_blend_factor = .one_minus_src_alpha,
            .alpha_blend_op = .add,
        },
        .premultiplied_alpha => .{
            .blend_enable = vk.TRUE,
            .src_color_blend_factor = .one,
            .dst_color_blend_factor = .one_minus_src_alpha,
            .color_blend_op = .add,
            .src_alpha_blend_factor = .one,
            .dst_alpha_blend_factor = .one_minus_src_alpha,
            .alpha_blend_op = .add,
        },
    };
    const cb = vk.PipelineColorBlendStateCreateInfo{
        .attachment_count = 1,
        .p_attachments = @ptrCast(&blend_attachment),
    };

    const dynamic_states = [_]vk.DynamicState{ .viewport, .scissor };
    const ds = vk.PipelineDynamicStateCreateInfo{
        .dynamic_state_count = dynamic_states.len,
        .p_dynamic_states = &dynamic_states,
    };

    const ci = vk.GraphicsPipelineCreateInfo{
        .stage_count = stages.len,
        .p_stages = &stages,
        .p_vertex_input_state = &vi,
        .p_input_assembly_state = &ia,
        .p_viewport_state = &viewport_state,
        .p_rasterization_state = &rs,
        .p_multisample_state = &ms,
        .p_color_blend_state = &cb,
        .p_dynamic_state = &ds,
        .layout = desc.pipeline_layout,
        .render_pass = desc.render_pass,
        .subpass = 0,
    };

    var pipeline: vk.Pipeline = .null_handle;
    try vk.check(device.api.create_graphics_pipelines(
        device.api.handle,
        cache,
        1,
        @ptrCast(&ci),
        null,
        @ptrCast(&pipeline),
    ));
    return pipeline;
}
