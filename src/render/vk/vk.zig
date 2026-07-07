//! Vulkan type, enum, and constant declarations for the subset of the API we use.
//!
//! This file replaces the role of `vulkan-zig` for our needs: hand-written declarations
//! that match the C ABI of `vulkan_core.h`. Keeping it hand-written means no codegen
//! dependency, and the surface stays small enough to be readable.
//!
//! When adding a new Vulkan call, add: (1) any new struct/enum/constant here,
//! (2) the function-pointer typedef in `api.zig`, (3) the PFN slot + load in `api.zig`.

const std = @import("std");
const builtin = @import("builtin");

// ============================================================================
// Calling convention — Vulkan uses VKAPI_PTR which is __stdcall on Win32, default elsewhere.
// ============================================================================

// Vulkan's VKAPI_PTR resolves to __stdcall on _WIN32 — that includes both x86
// and x64 Windows. On x64 the MS ABI and SysV diverge on XMM6-XMM15 (callee-
// saved on Win64, caller-saved on SysV) and shadow-space; mixing `.c` with a
// Win64 ABI callee silently corrupts callee-saved SSE state across complex
// driver entrypoints (vkAcquireNextImageKHR was crashing here). Always use
// .winapi on Windows.
pub const CallConv = if (builtin.os.tag == .windows)
    std.builtin.CallingConvention.winapi
else
    std.builtin.CallingConvention.c;

// ============================================================================
// Handles — opaque pointer types.
// ============================================================================

pub const Instance = enum(usize) { null_handle = 0, _ };
pub const PhysicalDevice = enum(usize) { null_handle = 0, _ };
pub const Device = enum(usize) { null_handle = 0, _ };
pub const Queue = enum(usize) { null_handle = 0, _ };
pub const CommandBuffer = enum(usize) { null_handle = 0, _ };

// Non-dispatchable handles are u64 on every platform.
pub const SurfaceKHR = enum(u64) { null_handle = 0, _ };
pub const SwapchainKHR = enum(u64) { null_handle = 0, _ };
pub const Image = enum(u64) { null_handle = 0, _ };
pub const ImageView = enum(u64) { null_handle = 0, _ };
pub const Sampler = enum(u64) { null_handle = 0, _ };
pub const Buffer = enum(u64) { null_handle = 0, _ };
pub const DeviceMemory = enum(u64) { null_handle = 0, _ };
pub const Fence = enum(u64) { null_handle = 0, _ };
pub const Semaphore = enum(u64) { null_handle = 0, _ };
pub const CommandPool = enum(u64) { null_handle = 0, _ };
pub const RenderPass = enum(u64) { null_handle = 0, _ };
pub const Framebuffer = enum(u64) { null_handle = 0, _ };
pub const Pipeline = enum(u64) { null_handle = 0, _ };
pub const PipelineLayout = enum(u64) { null_handle = 0, _ };
pub const PipelineCache = enum(u64) { null_handle = 0, _ };
pub const DescriptorSet = enum(u64) { null_handle = 0, _ };
pub const DescriptorSetLayout = enum(u64) { null_handle = 0, _ };
pub const DescriptorPool = enum(u64) { null_handle = 0, _ };
pub const ShaderModule = enum(u64) { null_handle = 0, _ };
pub const DebugUtilsMessengerEXT = enum(u64) { null_handle = 0, _ };

pub const AllocationCallbacks = opaque {};

// ============================================================================
// Result codes.
// ============================================================================

pub const Result = enum(i32) {
    success = 0,
    not_ready = 1,
    timeout = 2,
    event_set = 3,
    event_reset = 4,
    incomplete = 5,
    error_out_of_host_memory = -1,
    error_out_of_device_memory = -2,
    error_initialization_failed = -3,
    error_device_lost = -4,
    error_memory_map_failed = -5,
    error_layer_not_present = -6,
    error_extension_not_present = -7,
    error_feature_not_present = -8,
    error_incompatible_driver = -9,
    error_too_many_objects = -10,
    error_format_not_supported = -11,
    error_surface_lost_khr = -1000000000,
    error_native_window_in_use_khr = -1000000001,
    suboptimal_khr = 1000001003,
    error_out_of_date_khr = -1000001004,
    _,
};

pub const Error = error{
    OutOfHostMemory,
    OutOfDeviceMemory,
    InitializationFailed,
    DeviceLost,
    MemoryMapFailed,
    LayerNotPresent,
    ExtensionNotPresent,
    FeatureNotPresent,
    IncompatibleDriver,
    TooManyObjects,
    FormatNotSupported,
    SurfaceLost,
    NativeWindowInUse,
    OutOfDate,
    Unknown,
};

/// Translate a non-success VkResult into a Zig error. Returns void for `success`
/// (and for suboptimal_khr, which the caller usually wants to treat as success).
pub fn check(r: Result) Error!void {
    switch (r) {
        .success, .suboptimal_khr => return,
        .error_out_of_host_memory => return Error.OutOfHostMemory,
        .error_out_of_device_memory => return Error.OutOfDeviceMemory,
        .error_initialization_failed => return Error.InitializationFailed,
        .error_device_lost => return Error.DeviceLost,
        .error_memory_map_failed => return Error.MemoryMapFailed,
        .error_layer_not_present => return Error.LayerNotPresent,
        .error_extension_not_present => return Error.ExtensionNotPresent,
        .error_feature_not_present => return Error.FeatureNotPresent,
        .error_incompatible_driver => return Error.IncompatibleDriver,
        .error_too_many_objects => return Error.TooManyObjects,
        .error_format_not_supported => return Error.FormatNotSupported,
        .error_surface_lost_khr => return Error.SurfaceLost,
        .error_native_window_in_use_khr => return Error.NativeWindowInUse,
        .error_out_of_date_khr => return Error.OutOfDate,
        else => return Error.Unknown,
    }
}

// ============================================================================
// Common constants.
// ============================================================================

pub const TRUE: u32 = 1;
pub const FALSE: u32 = 0;
pub const WHOLE_SIZE: u64 = ~@as(u64, 0);
pub const SUBPASS_EXTERNAL: u32 = ~@as(u32, 0);
pub const QUEUE_FAMILY_IGNORED: u32 = ~@as(u32, 0);
pub const MAX_PHYSICAL_DEVICE_NAME_SIZE: usize = 256;
pub const MAX_EXTENSION_NAME_SIZE: usize = 256;
pub const MAX_DESCRIPTION_SIZE: usize = 256;
pub const UUID_SIZE: usize = 16;

pub const API_VERSION_1_0: u32 = (1 << 22) | (0 << 12);
pub const API_VERSION_1_1: u32 = (1 << 22) | (1 << 12);
pub const API_VERSION_1_2: u32 = (1 << 22) | (2 << 12);
pub const API_VERSION_1_3: u32 = (1 << 22) | (3 << 12);

pub fn makeApiVersion(variant: u32, major: u32, minor: u32, patch: u32) u32 {
    return (variant << 29) | (major << 22) | (minor << 12) | patch;
}

// ============================================================================
// sType values.
// ============================================================================

pub const StructureType = enum(i32) {
    application_info = 0,
    instance_create_info = 1,
    device_queue_create_info = 2,
    device_create_info = 3,
    submit_info = 4,
    memory_allocate_info = 5,
    mapped_memory_range = 6,
    bind_sparse_info = 7,
    fence_create_info = 8,
    semaphore_create_info = 9,
    event_create_info = 10,
    query_pool_create_info = 11,
    buffer_create_info = 12,
    buffer_view_create_info = 13,
    image_create_info = 14,
    image_view_create_info = 15,
    shader_module_create_info = 16,
    pipeline_cache_create_info = 17,
    pipeline_shader_stage_create_info = 18,
    pipeline_vertex_input_state_create_info = 19,
    pipeline_input_assembly_state_create_info = 20,
    pipeline_tessellation_state_create_info = 21,
    pipeline_viewport_state_create_info = 22,
    pipeline_rasterization_state_create_info = 23,
    pipeline_multisample_state_create_info = 24,
    pipeline_depth_stencil_state_create_info = 25,
    pipeline_color_blend_state_create_info = 26,
    pipeline_dynamic_state_create_info = 27,
    graphics_pipeline_create_info = 28,
    compute_pipeline_create_info = 29,
    pipeline_layout_create_info = 30,
    sampler_create_info = 31,
    descriptor_set_layout_create_info = 32,
    descriptor_pool_create_info = 33,
    descriptor_set_allocate_info = 34,
    write_descriptor_set = 35,
    copy_descriptor_set = 36,
    framebuffer_create_info = 37,
    render_pass_create_info = 38,
    command_pool_create_info = 39,
    command_buffer_allocate_info = 40,
    command_buffer_inheritance_info = 41,
    command_buffer_begin_info = 42,
    render_pass_begin_info = 43,
    buffer_memory_barrier = 44,
    image_memory_barrier = 45,
    memory_barrier = 46,
    swapchain_create_info_khr = 1000001000,
    present_info_khr = 1000001001,
    win32_surface_create_info_khr = 1000009000,
    debug_utils_messenger_create_info_ext = 1000128004,
    _,
};

// ============================================================================
// Format (subset — we use BGRA8 / RGBA8 / RG32 / D32 mainly).
// ============================================================================

pub const Format = enum(i32) {
    undefined = 0,
    r8g8b8a8_unorm = 37,
    r8g8b8a8_srgb = 43,
    b8g8r8a8_unorm = 44,
    b8g8r8a8_srgb = 50,
    r32_sfloat = 100,
    r32g32_sfloat = 103,
    r32g32b32_sfloat = 106,
    r32g32b32a32_sfloat = 109,
    d32_sfloat = 126,
    _,
};

// ============================================================================
// Bitflag types — we declare these as packed structs so individual bits are named.
// ============================================================================

pub const SampleCountFlags = packed struct(u32) {
    @"1": bool = false, @"2": bool = false, @"4": bool = false, @"8": bool = false,
    @"16": bool = false, @"32": bool = false, @"64": bool = false,
    _unused: u25 = 0,
};

pub const ImageUsageFlags = packed struct(u32) {
    transfer_src: bool = false,
    transfer_dst: bool = false,
    sampled: bool = false,
    storage: bool = false,
    color_attachment: bool = false,
    depth_stencil_attachment: bool = false,
    transient_attachment: bool = false,
    input_attachment: bool = false,
    _unused: u24 = 0,
};

pub const ImageAspectFlags = packed struct(u32) {
    color: bool = false,
    depth: bool = false,
    stencil: bool = false,
    metadata: bool = false,
    _unused: u28 = 0,
};

pub const BufferUsageFlags = packed struct(u32) {
    transfer_src: bool = false,
    transfer_dst: bool = false,
    uniform_texel_buffer: bool = false,
    storage_texel_buffer: bool = false,
    uniform_buffer: bool = false,
    storage_buffer: bool = false,
    index_buffer: bool = false,
    vertex_buffer: bool = false,
    indirect_buffer: bool = false,
    _unused: u23 = 0,
};

pub const MemoryPropertyFlags = packed struct(u32) {
    device_local: bool = false,
    host_visible: bool = false,
    host_coherent: bool = false,
    host_cached: bool = false,
    lazily_allocated: bool = false,
    _unused: u27 = 0,
};

pub const MemoryHeapFlags = packed struct(u32) {
    device_local: bool = false,
    multi_instance: bool = false,
    _unused: u30 = 0,
};

pub const QueueFlags = packed struct(u32) {
    graphics: bool = false,
    compute: bool = false,
    transfer: bool = false,
    sparse_binding: bool = false,
    protected: bool = false,
    _unused: u27 = 0,
};

pub const ShaderStageFlags = packed struct(u32) {
    vertex: bool = false,
    tessellation_control: bool = false,
    tessellation_evaluation: bool = false,
    geometry: bool = false,
    fragment: bool = false,
    compute: bool = false,
    _unused: u26 = 0,
};

pub const ColorComponentFlags = packed struct(u32) {
    r: bool = false, g: bool = false, b: bool = false, a: bool = false,
    _unused: u28 = 0,
};

pub const AccessFlags = packed struct(u32) {
    indirect_command_read: bool = false,
    index_read: bool = false,
    vertex_attribute_read: bool = false,
    uniform_read: bool = false,
    input_attachment_read: bool = false,
    shader_read: bool = false,
    shader_write: bool = false,
    color_attachment_read: bool = false,
    color_attachment_write: bool = false,
    depth_stencil_attachment_read: bool = false,
    depth_stencil_attachment_write: bool = false,
    transfer_read: bool = false,
    transfer_write: bool = false,
    host_read: bool = false,
    host_write: bool = false,
    memory_read: bool = false,
    memory_write: bool = false,
    _unused: u15 = 0,
};

pub const PipelineStageFlags = packed struct(u32) {
    top_of_pipe: bool = false,
    draw_indirect: bool = false,
    vertex_input: bool = false,
    vertex_shader: bool = false,
    tessellation_control_shader: bool = false,
    tessellation_evaluation_shader: bool = false,
    geometry_shader: bool = false,
    fragment_shader: bool = false,
    early_fragment_tests: bool = false,
    late_fragment_tests: bool = false,
    color_attachment_output: bool = false,
    compute_shader: bool = false,
    transfer: bool = false,
    bottom_of_pipe: bool = false,
    host: bool = false,
    all_graphics: bool = false,
    all_commands: bool = false,
    _unused: u15 = 0,
};

pub const CommandPoolCreateFlags = packed struct(u32) {
    transient: bool = false,
    reset_command_buffer: bool = false,
    protected: bool = false,
    _unused: u29 = 0,
};

pub const CommandBufferUsageFlags = packed struct(u32) {
    one_time_submit: bool = false,
    render_pass_continue: bool = false,
    simultaneous_use: bool = false,
    _unused: u29 = 0,
};

pub const FenceCreateFlags = packed struct(u32) {
    signaled: bool = false,
    _unused: u31 = 0,
};

pub const CompositeAlphaFlagsKHR = packed struct(u32) {
    opaque_bit: bool = false,
    pre_multiplied: bool = false,
    post_multiplied: bool = false,
    inherit: bool = false,
    _unused: u28 = 0,
};

pub const SurfaceTransformFlagsKHR = packed struct(u32) {
    identity: bool = false,
    rotate_90: bool = false,
    rotate_180: bool = false,
    rotate_270: bool = false,
    horizontal_mirror: bool = false,
    horizontal_mirror_rotate_90: bool = false,
    horizontal_mirror_rotate_180: bool = false,
    horizontal_mirror_rotate_270: bool = false,
    inherit: bool = false,
    _unused: u23 = 0,
};

// ============================================================================
// Enums.
// ============================================================================

pub const ImageLayout = enum(i32) {
    undefined = 0,
    general = 1,
    color_attachment_optimal = 2,
    depth_stencil_attachment_optimal = 3,
    shader_read_only_optimal = 5,
    transfer_src_optimal = 6,
    transfer_dst_optimal = 7,
    preinitialized = 8,
    present_src_khr = 1000001002,
    _,
};

pub const ImageType = enum(i32) { @"1d" = 0, @"2d" = 1, @"3d" = 2, _ };
pub const ImageViewType = enum(i32) { @"1d" = 0, @"2d" = 1, @"3d" = 2, cube = 3, _ };
pub const ImageTiling = enum(i32) { optimal = 0, linear = 1, _ };

pub const SharingMode = enum(i32) { exclusive = 0, concurrent = 1, _ };

pub const PrimitiveTopology = enum(i32) {
    point_list = 0,
    line_list = 1,
    line_strip = 2,
    triangle_list = 3,
    triangle_strip = 4,
    triangle_fan = 5,
    _,
};

pub const PolygonMode = enum(i32) { fill = 0, line = 1, point = 2, _ };
pub const CullModeFlags = packed struct(u32) {
    front: bool = false, back: bool = false,
    _unused: u30 = 0,
};
pub const FrontFace = enum(i32) { counter_clockwise = 0, clockwise = 1, _ };

pub const BlendFactor = enum(i32) {
    zero = 0,
    one = 1,
    src_color = 2,
    one_minus_src_color = 3,
    dst_color = 4,
    one_minus_dst_color = 5,
    src_alpha = 6,
    one_minus_src_alpha = 7,
    dst_alpha = 8,
    one_minus_dst_alpha = 9,
    _,
};
pub const BlendOp = enum(i32) {
    add = 0, subtract = 1, reverse_subtract = 2, min = 3, max = 4, _,
};

pub const LogicOp = enum(i32) { clear = 0, _ };
pub const CompareOp = enum(i32) { never = 0, less = 1, equal = 2, less_or_equal = 3, greater = 4, not_equal = 5, greater_or_equal = 6, always = 7, _ };

pub const VertexInputRate = enum(i32) { vertex = 0, instance = 1, _ };
pub const IndexType = enum(i32) { uint16 = 0, uint32 = 1, _ };

pub const AttachmentLoadOp = enum(i32) { load = 0, clear = 1, dont_care = 2, _ };
pub const AttachmentStoreOp = enum(i32) { store = 0, dont_care = 1, _ };

pub const PipelineBindPoint = enum(i32) { graphics = 0, compute = 1, _ };
pub const SubpassContents = enum(i32) { @"inline" = 0, secondary_command_buffers = 1, _ };

pub const CommandBufferLevel = enum(i32) { primary = 0, secondary = 1, _ };

pub const DescriptorType = enum(i32) {
    sampler = 0,
    combined_image_sampler = 1,
    sampled_image = 2,
    storage_image = 3,
    uniform_texel_buffer = 4,
    storage_texel_buffer = 5,
    uniform_buffer = 6,
    storage_buffer = 7,
    uniform_buffer_dynamic = 8,
    storage_buffer_dynamic = 9,
    input_attachment = 10,
    _,
};

pub const Filter = enum(i32) { nearest = 0, linear = 1, _ };
pub const SamplerMipmapMode = enum(i32) { nearest = 0, linear = 1, _ };
pub const SamplerAddressMode = enum(i32) { repeat = 0, mirrored_repeat = 1, clamp_to_edge = 2, clamp_to_border = 3, _ };

pub const ColorSpaceKHR = enum(i32) { srgb_nonlinear = 0, _ };
pub const PresentModeKHR = enum(i32) {
    immediate = 0,
    mailbox = 1,
    fifo = 2,
    fifo_relaxed = 3,
    _,
};

pub const PhysicalDeviceType = enum(i32) {
    other = 0,
    integrated_gpu = 1,
    discrete_gpu = 2,
    virtual_gpu = 3,
    cpu = 4,
    _,
};

pub const DynamicState = enum(i32) {
    viewport = 0,
    scissor = 1,
    line_width = 2,
    depth_bias = 3,
    blend_constants = 4,
    depth_bounds = 5,
    stencil_compare_mask = 6,
    stencil_write_mask = 7,
    stencil_reference = 8,
    _,
};

// ============================================================================
// Geometry structs.
// ============================================================================

pub const Offset2D = extern struct { x: i32, y: i32 };
pub const Offset3D = extern struct { x: i32, y: i32, z: i32 };
pub const Extent2D = extern struct { width: u32, height: u32 };
pub const Extent3D = extern struct { width: u32, height: u32, depth: u32 };
pub const Rect2D = extern struct { offset: Offset2D, extent: Extent2D };
pub const Viewport = extern struct {
    x: f32, y: f32, width: f32, height: f32, min_depth: f32, max_depth: f32,
};

pub const ClearColorValue = extern union {
    float32: [4]f32,
    int32: [4]i32,
    uint32: [4]u32,
};
pub const ClearDepthStencilValue = extern struct { depth: f32, stencil: u32 };
pub const ClearValue = extern union {
    color: ClearColorValue,
    depth_stencil: ClearDepthStencilValue,
};

// ============================================================================
// Application / instance.
// ============================================================================

pub const ApplicationInfo = extern struct {
    s_type: StructureType = .application_info,
    p_next: ?*const anyopaque = null,
    p_application_name: ?[*:0]const u8 = null,
    application_version: u32 = 0,
    p_engine_name: ?[*:0]const u8 = null,
    engine_version: u32 = 0,
    api_version: u32 = API_VERSION_1_0,
};

pub const InstanceCreateInfo = extern struct {
    s_type: StructureType = .instance_create_info,
    p_next: ?*const anyopaque = null,
    flags: u32 = 0,
    p_application_info: ?*const ApplicationInfo = null,
    enabled_layer_count: u32 = 0,
    pp_enabled_layer_names: ?[*]const [*:0]const u8 = null,
    enabled_extension_count: u32 = 0,
    pp_enabled_extension_names: ?[*]const [*:0]const u8 = null,
};

pub const ExtensionProperties = extern struct {
    extension_name: [MAX_EXTENSION_NAME_SIZE]u8,
    spec_version: u32,
};

pub const LayerProperties = extern struct {
    layer_name: [MAX_EXTENSION_NAME_SIZE]u8,
    spec_version: u32,
    implementation_version: u32,
    description: [MAX_DESCRIPTION_SIZE]u8,
};

// ============================================================================
// Physical device.
// ============================================================================

pub const PhysicalDeviceLimits = extern struct {
    // We only read a few fields; declare the layout enough to be ABI-correct.
    // For simplicity, treat as opaque-but-sized via a raw byte blob the right size.
    // The struct is 504 bytes in Vulkan 1.0. We hand-declare the prefix we use.
    _opaque: [504]u8,
};

pub const PhysicalDeviceSparseProperties = extern struct {
    residency_standard_2d_block_shape: u32,
    residency_standard_2d_multisample_block_shape: u32,
    residency_standard_3d_block_shape: u32,
    residency_aligned_mip_size: u32,
    residency_non_resident_strict: u32,
};

pub const PhysicalDeviceProperties = extern struct {
    api_version: u32,
    driver_version: u32,
    vendor_id: u32,
    device_id: u32,
    device_type: PhysicalDeviceType,
    device_name: [MAX_PHYSICAL_DEVICE_NAME_SIZE]u8,
    pipeline_cache_uuid: [UUID_SIZE]u8,
    limits: PhysicalDeviceLimits,
    sparse_properties: PhysicalDeviceSparseProperties,
};

pub const PhysicalDeviceFeatures = extern struct {
    // 55 VkBool32 fields. Declared as a raw [55]u32 for simplicity; we leave them all 0.
    fields: [55]u32 = [_]u32{0} ** 55,
};

pub const QueueFamilyProperties = extern struct {
    queue_flags: QueueFlags,
    queue_count: u32,
    timestamp_valid_bits: u32,
    min_image_transfer_granularity: Extent3D,
};

pub const MemoryType = extern struct {
    property_flags: MemoryPropertyFlags,
    heap_index: u32,
};
pub const MemoryHeap = extern struct {
    size: u64,
    flags: MemoryHeapFlags,
};
pub const MAX_MEMORY_TYPES: usize = 32;
pub const MAX_MEMORY_HEAPS: usize = 16;
pub const PhysicalDeviceMemoryProperties = extern struct {
    memory_type_count: u32,
    memory_types: [MAX_MEMORY_TYPES]MemoryType,
    memory_heap_count: u32,
    memory_heaps: [MAX_MEMORY_HEAPS]MemoryHeap,
};

// ============================================================================
// Device creation.
// ============================================================================

pub const DeviceQueueCreateInfo = extern struct {
    s_type: StructureType = .device_queue_create_info,
    p_next: ?*const anyopaque = null,
    flags: u32 = 0,
    queue_family_index: u32,
    queue_count: u32,
    p_queue_priorities: [*]const f32,
};

pub const DeviceCreateInfo = extern struct {
    s_type: StructureType = .device_create_info,
    p_next: ?*const anyopaque = null,
    flags: u32 = 0,
    queue_create_info_count: u32,
    p_queue_create_infos: [*]const DeviceQueueCreateInfo,
    enabled_layer_count: u32 = 0,
    pp_enabled_layer_names: ?[*]const [*:0]const u8 = null,
    enabled_extension_count: u32 = 0,
    pp_enabled_extension_names: ?[*]const [*:0]const u8 = null,
    p_enabled_features: ?*const PhysicalDeviceFeatures = null,
};

// ============================================================================
// Surface / Swapchain.
// ============================================================================

pub const SurfaceCapabilitiesKHR = extern struct {
    min_image_count: u32,
    max_image_count: u32,
    current_extent: Extent2D,
    min_image_extent: Extent2D,
    max_image_extent: Extent2D,
    max_image_array_layers: u32,
    supported_transforms: SurfaceTransformFlagsKHR,
    current_transform: SurfaceTransformFlagsKHR,
    supported_composite_alpha: CompositeAlphaFlagsKHR,
    supported_usage_flags: ImageUsageFlags,
};

pub const SurfaceFormatKHR = extern struct {
    format: Format,
    color_space: ColorSpaceKHR,
};

pub const SwapchainCreateInfoKHR = extern struct {
    s_type: StructureType = .swapchain_create_info_khr,
    p_next: ?*const anyopaque = null,
    flags: u32 = 0,
    surface: SurfaceKHR,
    min_image_count: u32,
    image_format: Format,
    image_color_space: ColorSpaceKHR,
    image_extent: Extent2D,
    image_array_layers: u32 = 1,
    image_usage: ImageUsageFlags,
    image_sharing_mode: SharingMode = .exclusive,
    queue_family_index_count: u32 = 0,
    p_queue_family_indices: ?[*]const u32 = null,
    pre_transform: SurfaceTransformFlagsKHR,
    composite_alpha: CompositeAlphaFlagsKHR,
    present_mode: PresentModeKHR,
    clipped: u32 = TRUE,
    old_swapchain: SwapchainKHR = .null_handle,
};

pub const PresentInfoKHR = extern struct {
    s_type: StructureType = .present_info_khr,
    p_next: ?*const anyopaque = null,
    wait_semaphore_count: u32 = 0,
    p_wait_semaphores: ?[*]const Semaphore = null,
    swapchain_count: u32,
    p_swapchains: [*]const SwapchainKHR,
    p_image_indices: [*]const u32,
    p_results: ?[*]Result = null,
};

// ============================================================================
// Image + ImageView.
// ============================================================================

pub const ComponentSwizzle = enum(i32) { identity = 0, zero = 1, one = 2, r = 3, g = 4, b = 5, a = 6, _ };
pub const ComponentMapping = extern struct {
    r: ComponentSwizzle = .identity,
    g: ComponentSwizzle = .identity,
    b: ComponentSwizzle = .identity,
    a: ComponentSwizzle = .identity,
};

pub const ImageSubresourceRange = extern struct {
    aspect_mask: ImageAspectFlags,
    base_mip_level: u32 = 0,
    level_count: u32 = 1,
    base_array_layer: u32 = 0,
    layer_count: u32 = 1,
};

pub const ImageViewCreateInfo = extern struct {
    s_type: StructureType = .image_view_create_info,
    p_next: ?*const anyopaque = null,
    flags: u32 = 0,
    image: Image,
    view_type: ImageViewType,
    format: Format,
    components: ComponentMapping = .{},
    subresource_range: ImageSubresourceRange,
};

pub const ImageMemoryBarrier = extern struct {
    s_type: StructureType = .image_memory_barrier,
    p_next: ?*const anyopaque = null,
    src_access_mask: AccessFlags = .{},
    dst_access_mask: AccessFlags = .{},
    old_layout: ImageLayout,
    new_layout: ImageLayout,
    src_queue_family_index: u32 = QUEUE_FAMILY_IGNORED,
    dst_queue_family_index: u32 = QUEUE_FAMILY_IGNORED,
    image: Image,
    subresource_range: ImageSubresourceRange,
};

// ============================================================================
// Render pass / framebuffer.
// ============================================================================

pub const AttachmentDescription = extern struct {
    flags: u32 = 0,
    format: Format,
    samples: SampleCountFlags = .{ .@"1" = true },
    load_op: AttachmentLoadOp,
    store_op: AttachmentStoreOp,
    stencil_load_op: AttachmentLoadOp = .dont_care,
    stencil_store_op: AttachmentStoreOp = .dont_care,
    initial_layout: ImageLayout,
    final_layout: ImageLayout,
};

pub const AttachmentReference = extern struct {
    attachment: u32,
    layout: ImageLayout,
};

pub const SubpassDescription = extern struct {
    flags: u32 = 0,
    pipeline_bind_point: PipelineBindPoint = .graphics,
    input_attachment_count: u32 = 0,
    p_input_attachments: ?[*]const AttachmentReference = null,
    color_attachment_count: u32 = 0,
    p_color_attachments: ?[*]const AttachmentReference = null,
    p_resolve_attachments: ?[*]const AttachmentReference = null,
    p_depth_stencil_attachment: ?*const AttachmentReference = null,
    preserve_attachment_count: u32 = 0,
    p_preserve_attachments: ?[*]const u32 = null,
};

pub const SubpassDependency = extern struct {
    src_subpass: u32,
    dst_subpass: u32,
    src_stage_mask: PipelineStageFlags,
    dst_stage_mask: PipelineStageFlags,
    src_access_mask: AccessFlags = .{},
    dst_access_mask: AccessFlags = .{},
    dependency_flags: u32 = 0,
};

pub const RenderPassCreateInfo = extern struct {
    s_type: StructureType = .render_pass_create_info,
    p_next: ?*const anyopaque = null,
    flags: u32 = 0,
    attachment_count: u32,
    p_attachments: [*]const AttachmentDescription,
    subpass_count: u32,
    p_subpasses: [*]const SubpassDescription,
    dependency_count: u32 = 0,
    p_dependencies: ?[*]const SubpassDependency = null,
};

pub const FramebufferCreateInfo = extern struct {
    s_type: StructureType = .framebuffer_create_info,
    p_next: ?*const anyopaque = null,
    flags: u32 = 0,
    render_pass: RenderPass,
    attachment_count: u32,
    p_attachments: [*]const ImageView,
    width: u32,
    height: u32,
    layers: u32 = 1,
};

pub const RenderPassBeginInfo = extern struct {
    s_type: StructureType = .render_pass_begin_info,
    p_next: ?*const anyopaque = null,
    render_pass: RenderPass,
    framebuffer: Framebuffer,
    render_area: Rect2D,
    clear_value_count: u32 = 0,
    p_clear_values: ?[*]const ClearValue = null,
};

// ============================================================================
// Pipeline.
// ============================================================================

pub const ShaderModuleCreateInfo = extern struct {
    s_type: StructureType = .shader_module_create_info,
    p_next: ?*const anyopaque = null,
    flags: u32 = 0,
    code_size: usize,
    p_code: [*]const u32,
};

pub const SpecializationInfo = extern struct {
    map_entry_count: u32 = 0,
    p_map_entries: ?*const anyopaque = null,
    data_size: usize = 0,
    p_data: ?*const anyopaque = null,
};

pub const PipelineShaderStageCreateInfo = extern struct {
    s_type: StructureType = .pipeline_shader_stage_create_info,
    p_next: ?*const anyopaque = null,
    flags: u32 = 0,
    stage: ShaderStageFlags,
    module: ShaderModule,
    p_name: [*:0]const u8,
    p_specialization_info: ?*const SpecializationInfo = null,
};

pub const VertexInputBindingDescription = extern struct {
    binding: u32,
    stride: u32,
    input_rate: VertexInputRate,
};
pub const VertexInputAttributeDescription = extern struct {
    location: u32,
    binding: u32,
    format: Format,
    offset: u32,
};
pub const PipelineVertexInputStateCreateInfo = extern struct {
    s_type: StructureType = .pipeline_vertex_input_state_create_info,
    p_next: ?*const anyopaque = null,
    flags: u32 = 0,
    vertex_binding_description_count: u32 = 0,
    p_vertex_binding_descriptions: ?[*]const VertexInputBindingDescription = null,
    vertex_attribute_description_count: u32 = 0,
    p_vertex_attribute_descriptions: ?[*]const VertexInputAttributeDescription = null,
};
pub const PipelineInputAssemblyStateCreateInfo = extern struct {
    s_type: StructureType = .pipeline_input_assembly_state_create_info,
    p_next: ?*const anyopaque = null,
    flags: u32 = 0,
    topology: PrimitiveTopology,
    primitive_restart_enable: u32 = FALSE,
};
pub const PipelineViewportStateCreateInfo = extern struct {
    s_type: StructureType = .pipeline_viewport_state_create_info,
    p_next: ?*const anyopaque = null,
    flags: u32 = 0,
    viewport_count: u32,
    p_viewports: ?[*]const Viewport = null,
    scissor_count: u32,
    p_scissors: ?[*]const Rect2D = null,
};
pub const PipelineRasterizationStateCreateInfo = extern struct {
    s_type: StructureType = .pipeline_rasterization_state_create_info,
    p_next: ?*const anyopaque = null,
    flags: u32 = 0,
    depth_clamp_enable: u32 = FALSE,
    rasterizer_discard_enable: u32 = FALSE,
    polygon_mode: PolygonMode = .fill,
    cull_mode: CullModeFlags = .{},
    front_face: FrontFace = .counter_clockwise,
    depth_bias_enable: u32 = FALSE,
    depth_bias_constant_factor: f32 = 0,
    depth_bias_clamp: f32 = 0,
    depth_bias_slope_factor: f32 = 0,
    line_width: f32 = 1.0,
};
pub const PipelineMultisampleStateCreateInfo = extern struct {
    s_type: StructureType = .pipeline_multisample_state_create_info,
    p_next: ?*const anyopaque = null,
    flags: u32 = 0,
    rasterization_samples: SampleCountFlags = .{ .@"1" = true },
    sample_shading_enable: u32 = FALSE,
    min_sample_shading: f32 = 0,
    p_sample_mask: ?[*]const u32 = null,
    alpha_to_coverage_enable: u32 = FALSE,
    alpha_to_one_enable: u32 = FALSE,
};
pub const PipelineColorBlendAttachmentState = extern struct {
    blend_enable: u32 = FALSE,
    src_color_blend_factor: BlendFactor = .one,
    dst_color_blend_factor: BlendFactor = .zero,
    color_blend_op: BlendOp = .add,
    src_alpha_blend_factor: BlendFactor = .one,
    dst_alpha_blend_factor: BlendFactor = .zero,
    alpha_blend_op: BlendOp = .add,
    color_write_mask: ColorComponentFlags = .{ .r = true, .g = true, .b = true, .a = true },
};
pub const PipelineColorBlendStateCreateInfo = extern struct {
    s_type: StructureType = .pipeline_color_blend_state_create_info,
    p_next: ?*const anyopaque = null,
    flags: u32 = 0,
    logic_op_enable: u32 = FALSE,
    logic_op: LogicOp = .clear,
    attachment_count: u32,
    p_attachments: [*]const PipelineColorBlendAttachmentState,
    blend_constants: [4]f32 = .{ 0, 0, 0, 0 },
};
pub const PipelineDynamicStateCreateInfo = extern struct {
    s_type: StructureType = .pipeline_dynamic_state_create_info,
    p_next: ?*const anyopaque = null,
    flags: u32 = 0,
    dynamic_state_count: u32,
    p_dynamic_states: [*]const DynamicState,
};

pub const PushConstantRange = extern struct {
    stage_flags: ShaderStageFlags,
    offset: u32,
    size: u32,
};

pub const PipelineLayoutCreateInfo = extern struct {
    s_type: StructureType = .pipeline_layout_create_info,
    p_next: ?*const anyopaque = null,
    flags: u32 = 0,
    set_layout_count: u32 = 0,
    p_set_layouts: ?[*]const DescriptorSetLayout = null,
    push_constant_range_count: u32 = 0,
    p_push_constant_ranges: ?[*]const PushConstantRange = null,
};

pub const GraphicsPipelineCreateInfo = extern struct {
    s_type: StructureType = .graphics_pipeline_create_info,
    p_next: ?*const anyopaque = null,
    flags: u32 = 0,
    stage_count: u32,
    p_stages: [*]const PipelineShaderStageCreateInfo,
    p_vertex_input_state: *const PipelineVertexInputStateCreateInfo,
    p_input_assembly_state: *const PipelineInputAssemblyStateCreateInfo,
    p_tessellation_state: ?*const anyopaque = null,
    p_viewport_state: *const PipelineViewportStateCreateInfo,
    p_rasterization_state: *const PipelineRasterizationStateCreateInfo,
    p_multisample_state: *const PipelineMultisampleStateCreateInfo,
    p_depth_stencil_state: ?*const anyopaque = null,
    p_color_blend_state: *const PipelineColorBlendStateCreateInfo,
    p_dynamic_state: ?*const PipelineDynamicStateCreateInfo = null,
    layout: PipelineLayout,
    render_pass: RenderPass,
    subpass: u32 = 0,
    base_pipeline_handle: Pipeline = .null_handle,
    base_pipeline_index: i32 = -1,
};

pub const PipelineCacheCreateInfo = extern struct {
    s_type: StructureType = .pipeline_cache_create_info,
    p_next: ?*const anyopaque = null,
    flags: u32 = 0,
    initial_data_size: usize = 0,
    p_initial_data: ?[*]const u8 = null,
};

// ============================================================================
// Command pool / buffer.
// ============================================================================

pub const CommandPoolCreateInfo = extern struct {
    s_type: StructureType = .command_pool_create_info,
    p_next: ?*const anyopaque = null,
    flags: CommandPoolCreateFlags = .{},
    queue_family_index: u32,
};

pub const CommandBufferAllocateInfo = extern struct {
    s_type: StructureType = .command_buffer_allocate_info,
    p_next: ?*const anyopaque = null,
    command_pool: CommandPool,
    level: CommandBufferLevel = .primary,
    command_buffer_count: u32,
};

pub const CommandBufferBeginInfo = extern struct {
    s_type: StructureType = .command_buffer_begin_info,
    p_next: ?*const anyopaque = null,
    flags: CommandBufferUsageFlags = .{},
    p_inheritance_info: ?*const anyopaque = null,
};

pub const SubmitInfo = extern struct {
    s_type: StructureType = .submit_info,
    p_next: ?*const anyopaque = null,
    wait_semaphore_count: u32 = 0,
    p_wait_semaphores: ?[*]const Semaphore = null,
    p_wait_dst_stage_mask: ?[*]const PipelineStageFlags = null,
    command_buffer_count: u32 = 0,
    p_command_buffers: ?[*]const CommandBuffer = null,
    signal_semaphore_count: u32 = 0,
    p_signal_semaphores: ?[*]const Semaphore = null,
};

// ============================================================================
// Sync.
// ============================================================================

pub const FenceCreateInfo = extern struct {
    s_type: StructureType = .fence_create_info,
    p_next: ?*const anyopaque = null,
    flags: FenceCreateFlags = .{},
};
pub const SemaphoreCreateInfo = extern struct {
    s_type: StructureType = .semaphore_create_info,
    p_next: ?*const anyopaque = null,
    flags: u32 = 0,
};

// ============================================================================
// Memory / buffer.
// ============================================================================

pub const MemoryAllocateInfo = extern struct {
    s_type: StructureType = .memory_allocate_info,
    p_next: ?*const anyopaque = null,
    allocation_size: u64,
    memory_type_index: u32,
};

pub const MappedMemoryRange = extern struct {
    s_type: StructureType = .mapped_memory_range,
    p_next: ?*const anyopaque = null,
    memory: DeviceMemory,
    offset: u64,
    size: u64,
};

pub const MemoryRequirements = extern struct {
    size: u64,
    alignment: u64,
    memory_type_bits: u32,
};

pub const BufferCreateInfo = extern struct {
    s_type: StructureType = .buffer_create_info,
    p_next: ?*const anyopaque = null,
    flags: u32 = 0,
    size: u64,
    usage: BufferUsageFlags,
    sharing_mode: SharingMode = .exclusive,
    queue_family_index_count: u32 = 0,
    p_queue_family_indices: ?[*]const u32 = null,
};

pub const ImageCreateInfo = extern struct {
    s_type: StructureType = .image_create_info,
    p_next: ?*const anyopaque = null,
    flags: u32 = 0,
    image_type: ImageType,
    format: Format,
    extent: Extent3D,
    mip_levels: u32 = 1,
    array_layers: u32 = 1,
    samples: SampleCountFlags = .{ .@"1" = true },
    tiling: ImageTiling = .optimal,
    usage: ImageUsageFlags,
    sharing_mode: SharingMode = .exclusive,
    queue_family_index_count: u32 = 0,
    p_queue_family_indices: ?[*]const u32 = null,
    initial_layout: ImageLayout = .undefined,
};

// ============================================================================
// Descriptors.
// ============================================================================

pub const DescriptorSetLayoutBinding = extern struct {
    binding: u32,
    descriptor_type: DescriptorType,
    descriptor_count: u32 = 1,
    stage_flags: ShaderStageFlags,
    p_immutable_samplers: ?[*]const Sampler = null,
};
pub const DescriptorSetLayoutCreateInfo = extern struct {
    s_type: StructureType = .descriptor_set_layout_create_info,
    p_next: ?*const anyopaque = null,
    flags: u32 = 0,
    binding_count: u32,
    p_bindings: [*]const DescriptorSetLayoutBinding,
};
pub const DescriptorPoolSize = extern struct {
    type_: DescriptorType,
    descriptor_count: u32,
};
pub const DescriptorPoolCreateInfo = extern struct {
    s_type: StructureType = .descriptor_pool_create_info,
    p_next: ?*const anyopaque = null,
    flags: u32 = 0,
    max_sets: u32,
    pool_size_count: u32,
    p_pool_sizes: [*]const DescriptorPoolSize,
};
pub const DescriptorSetAllocateInfo = extern struct {
    s_type: StructureType = .descriptor_set_allocate_info,
    p_next: ?*const anyopaque = null,
    descriptor_pool: DescriptorPool,
    descriptor_set_count: u32,
    p_set_layouts: [*]const DescriptorSetLayout,
};
pub const DescriptorImageInfo = extern struct {
    sampler: Sampler,
    image_view: ImageView,
    image_layout: ImageLayout,
};
pub const DescriptorBufferInfo = extern struct {
    buffer: Buffer,
    offset: u64,
    range: u64,
};
pub const WriteDescriptorSet = extern struct {
    s_type: StructureType = .write_descriptor_set,
    p_next: ?*const anyopaque = null,
    dst_set: DescriptorSet,
    dst_binding: u32,
    dst_array_element: u32 = 0,
    descriptor_count: u32,
    descriptor_type: DescriptorType,
    p_image_info: ?[*]const DescriptorImageInfo = null,
    p_buffer_info: ?[*]const DescriptorBufferInfo = null,
    p_texel_buffer_view: ?*const anyopaque = null,
};

// ============================================================================
// Sampler.
// ============================================================================

pub const BorderColor = enum(i32) {
    float_transparent_black = 0,
    int_transparent_black = 1,
    float_opaque_black = 2,
    int_opaque_black = 3,
    float_opaque_white = 4,
    int_opaque_white = 5,
    _,
};

pub const SamplerCreateInfo = extern struct {
    s_type: StructureType = .sampler_create_info,
    p_next: ?*const anyopaque = null,
    flags: u32 = 0,
    mag_filter: Filter = .linear,
    min_filter: Filter = .linear,
    mipmap_mode: SamplerMipmapMode = .linear,
    address_mode_u: SamplerAddressMode = .clamp_to_edge,
    address_mode_v: SamplerAddressMode = .clamp_to_edge,
    address_mode_w: SamplerAddressMode = .clamp_to_edge,
    mip_lod_bias: f32 = 0,
    anisotropy_enable: u32 = FALSE,
    max_anisotropy: f32 = 1,
    compare_enable: u32 = FALSE,
    compare_op: CompareOp = .always,
    min_lod: f32 = 0,
    max_lod: f32 = 0,
    border_color: BorderColor = .int_opaque_white,
    unnormalized_coordinates: u32 = FALSE,
};

// ============================================================================
// Buffer/image copies.
// ============================================================================

pub const BufferCopy = extern struct {
    src_offset: u64,
    dst_offset: u64,
    size: u64,
};

pub const ImageSubresourceLayers = extern struct {
    aspect_mask: ImageAspectFlags,
    mip_level: u32 = 0,
    base_array_layer: u32 = 0,
    layer_count: u32 = 1,
};

pub const BufferImageCopy = extern struct {
    buffer_offset: u64,
    buffer_row_length: u32 = 0,
    buffer_image_height: u32 = 0,
    image_subresource: ImageSubresourceLayers,
    image_offset: Offset3D,
    image_extent: Extent3D,
};

// ============================================================================
// Debug utils.
// ============================================================================

pub const DebugUtilsMessageSeverityFlagsEXT = packed struct(u32) {
    // bit 0
    verbose: bool = false,
    _unused0: u3 = 0,
    // bit 4
    info: bool = false,
    _unused1: u3 = 0,
    // bit 8
    warning: bool = false,
    _unused2: u3 = 0,
    // bit 12
    @"error": bool = false,
    _unused3: u19 = 0,
};
pub const DebugUtilsMessageTypeFlagsEXT = packed struct(u32) {
    general: bool = false,
    validation: bool = false,
    performance: bool = false,
    _unused: u29 = 0,
};
pub const DebugUtilsMessengerCallbackDataEXT = extern struct {
    s_type: StructureType,
    p_next: ?*const anyopaque,
    flags: u32,
    p_message_id_name: ?[*:0]const u8,
    message_id_number: i32,
    p_message: [*:0]const u8,
    // (queue_label_count, p_queue_labels, cmd_buf_label_count, p_cmd_buf_labels,
    //  object_count, p_objects) — omitted; we never read past p_message.
};
pub const DebugUtilsMessengerCallbackEXT = *const fn (
    severity: DebugUtilsMessageSeverityFlagsEXT,
    msg_type: DebugUtilsMessageTypeFlagsEXT,
    callback_data: *const DebugUtilsMessengerCallbackDataEXT,
    user_data: ?*anyopaque,
) callconv(CallConv) u32;
pub const DebugUtilsMessengerCreateInfoEXT = extern struct {
    s_type: StructureType = .debug_utils_messenger_create_info_ext,
    p_next: ?*const anyopaque = null,
    flags: u32 = 0,
    message_severity: DebugUtilsMessageSeverityFlagsEXT,
    message_type: DebugUtilsMessageTypeFlagsEXT,
    pfn_user_callback: DebugUtilsMessengerCallbackEXT,
    p_user_data: ?*anyopaque = null,
};
