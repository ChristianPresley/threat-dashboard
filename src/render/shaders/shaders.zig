//! Centralized SPIR-V blob embeds. All shader bytes used by the renderer come
//! through here — keeps the relative-path fragility of @embedFile localized to
//! one file, and gives PR 1b's ImGui Vulkan backend a uniform import surface.
//!
//! Recompile shaders manually for now:
//!     glslc -fshader-stage=vert triangle.vert.glsl -o triangle.vert.spv
//!     glslc -fshader-stage=frag triangle.frag.glsl -o triangle.frag.spv
//! Future: `zig build shaders` step gated on `glslc` being on PATH.
//!
//! The `align(@alignOf(u32))` qualifier is load-bearing: VkShaderModuleCreateInfo
//! reads SPIR-V as `u32*` and an unaligned blob is silent UB.

pub const triangle_vert align(@alignOf(u32)) = @embedFile("triangle.vert.spv").*;
pub const triangle_frag align(@alignOf(u32)) = @embedFile("triangle.frag.spv").*;
pub const imgui_vert align(@alignOf(u32)) = @embedFile("imgui.vert.spv").*;
pub const imgui_frag align(@alignOf(u32)) = @embedFile("imgui.frag.spv").*;
