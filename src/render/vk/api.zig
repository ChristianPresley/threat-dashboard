//! Vulkan dispatch tables.
//!
//! Three tiers, per the Vulkan spec dispatch rules:
//!   - `Loader`: opens `vulkan-1.dll` / `libvulkan.so.1` / `libvulkan.1.dylib` and resolves
//!     `vkGetInstanceProcAddr` plus the *global* entrypoints (functions that can be
//!     called before any VkInstance exists: vkEnumerateInstanceLayerProperties,
//!     vkEnumerateInstanceExtensionProperties, vkCreateInstance).
//!   - `InstanceApi`: built after vkCreateInstance succeeds. Resolved via
//!     vkGetInstanceProcAddr(instance, ...). Contains everything that needs a
//!     VkInstance (physical-device queries, surface/swapchain WSI, debug utils,
//!     device creation).
//!   - `DeviceApi`: built after vkCreateDevice succeeds. Resolved via
//!     vkGetDeviceProcAddr(device, ...). Contains the high-traffic command-buffer
//!     and draw functions; these dispatch faster than the instance table because
//!     the loader trampoline is skipped.

const std = @import("std");
const builtin = @import("builtin");
const vk = @import("vk.zig");
const dyn_lib = @import("dyn_lib.zig");

// ============================================================================
// PFN typedefs — match Vulkan's VKAPI_PTR calling convention.
// ============================================================================

const CC = vk.CallConv;

pub const PfnVoidFunction = *const fn () callconv(CC) void;
pub const PfnGetInstanceProcAddr = *const fn (
    instance: vk.Instance,
    p_name: [*:0]const u8,
) callconv(CC) ?PfnVoidFunction;
pub const PfnGetDeviceProcAddr = *const fn (
    device: vk.Device,
    p_name: [*:0]const u8,
) callconv(CC) ?PfnVoidFunction;

// --- Global ---
pub const PfnEnumerateInstanceVersion = *const fn (p_api_version: *u32) callconv(CC) vk.Result;
pub const PfnEnumerateInstanceLayerProperties = *const fn (
    p_property_count: *u32,
    p_properties: ?[*]vk.LayerProperties,
) callconv(CC) vk.Result;
pub const PfnEnumerateInstanceExtensionProperties = *const fn (
    p_layer_name: ?[*:0]const u8,
    p_property_count: *u32,
    p_properties: ?[*]vk.ExtensionProperties,
) callconv(CC) vk.Result;
pub const PfnCreateInstance = *const fn (
    p_create_info: *const vk.InstanceCreateInfo,
    p_allocator: ?*const vk.AllocationCallbacks,
    p_instance: *vk.Instance,
) callconv(CC) vk.Result;

// --- Instance-level ---
pub const PfnDestroyInstance = *const fn (instance: vk.Instance, p_allocator: ?*const vk.AllocationCallbacks) callconv(CC) void;
pub const PfnEnumeratePhysicalDevices = *const fn (
    instance: vk.Instance,
    p_count: *u32,
    p_devices: ?[*]vk.PhysicalDevice,
) callconv(CC) vk.Result;
pub const PfnGetPhysicalDeviceProperties = *const fn (
    physical_device: vk.PhysicalDevice,
    p_props: *vk.PhysicalDeviceProperties,
) callconv(CC) void;
pub const PfnGetPhysicalDeviceQueueFamilyProperties = *const fn (
    physical_device: vk.PhysicalDevice,
    p_count: *u32,
    p_props: ?[*]vk.QueueFamilyProperties,
) callconv(CC) void;
pub const PfnGetPhysicalDeviceMemoryProperties = *const fn (
    physical_device: vk.PhysicalDevice,
    p_props: *vk.PhysicalDeviceMemoryProperties,
) callconv(CC) void;
pub const PfnGetPhysicalDeviceSurfaceSupportKHR = *const fn (
    physical_device: vk.PhysicalDevice,
    queue_family_index: u32,
    surface: vk.SurfaceKHR,
    p_supported: *u32,
) callconv(CC) vk.Result;
pub const PfnGetPhysicalDeviceSurfaceCapabilitiesKHR = *const fn (
    physical_device: vk.PhysicalDevice,
    surface: vk.SurfaceKHR,
    p_caps: *vk.SurfaceCapabilitiesKHR,
) callconv(CC) vk.Result;
pub const PfnGetPhysicalDeviceSurfaceFormatsKHR = *const fn (
    physical_device: vk.PhysicalDevice,
    surface: vk.SurfaceKHR,
    p_count: *u32,
    p_formats: ?[*]vk.SurfaceFormatKHR,
) callconv(CC) vk.Result;
pub const PfnGetPhysicalDeviceSurfacePresentModesKHR = *const fn (
    physical_device: vk.PhysicalDevice,
    surface: vk.SurfaceKHR,
    p_count: *u32,
    p_modes: ?[*]vk.PresentModeKHR,
) callconv(CC) vk.Result;
pub const PfnEnumerateDeviceExtensionProperties = *const fn (
    physical_device: vk.PhysicalDevice,
    p_layer_name: ?[*:0]const u8,
    p_count: *u32,
    p_props: ?[*]vk.ExtensionProperties,
) callconv(CC) vk.Result;
pub const PfnCreateDevice = *const fn (
    physical_device: vk.PhysicalDevice,
    p_create_info: *const vk.DeviceCreateInfo,
    p_allocator: ?*const vk.AllocationCallbacks,
    p_device: *vk.Device,
) callconv(CC) vk.Result;
pub const PfnDestroySurfaceKHR = *const fn (
    instance: vk.Instance,
    surface: vk.SurfaceKHR,
    p_allocator: ?*const vk.AllocationCallbacks,
) callconv(CC) void;
pub const PfnCreateDebugUtilsMessengerEXT = *const fn (
    instance: vk.Instance,
    p_create_info: *const vk.DebugUtilsMessengerCreateInfoEXT,
    p_allocator: ?*const vk.AllocationCallbacks,
    p_messenger: *vk.DebugUtilsMessengerEXT,
) callconv(CC) vk.Result;
pub const PfnDestroyDebugUtilsMessengerEXT = *const fn (
    instance: vk.Instance,
    messenger: vk.DebugUtilsMessengerEXT,
    p_allocator: ?*const vk.AllocationCallbacks,
) callconv(CC) void;

// --- Device-level ---
pub const PfnDestroyDevice = *const fn (device: vk.Device, p_allocator: ?*const vk.AllocationCallbacks) callconv(CC) void;
pub const PfnGetDeviceQueue = *const fn (device: vk.Device, family: u32, index: u32, p_queue: *vk.Queue) callconv(CC) void;
pub const PfnDeviceWaitIdle = *const fn (device: vk.Device) callconv(CC) vk.Result;
pub const PfnQueueWaitIdle = *const fn (queue: vk.Queue) callconv(CC) vk.Result;
pub const PfnQueueSubmit = *const fn (
    queue: vk.Queue,
    submit_count: u32,
    p_submits: [*]const vk.SubmitInfo,
    fence: vk.Fence,
) callconv(CC) vk.Result;
pub const PfnQueuePresentKHR = *const fn (queue: vk.Queue, p_present_info: *const vk.PresentInfoKHR) callconv(CC) vk.Result;
pub const PfnCreateSwapchainKHR = *const fn (
    device: vk.Device,
    p_create_info: *const vk.SwapchainCreateInfoKHR,
    p_allocator: ?*const vk.AllocationCallbacks,
    p_swapchain: *vk.SwapchainKHR,
) callconv(CC) vk.Result;
pub const PfnDestroySwapchainKHR = *const fn (
    device: vk.Device,
    swapchain: vk.SwapchainKHR,
    p_allocator: ?*const vk.AllocationCallbacks,
) callconv(CC) void;
pub const PfnGetSwapchainImagesKHR = *const fn (
    device: vk.Device,
    swapchain: vk.SwapchainKHR,
    p_count: *u32,
    p_images: ?[*]vk.Image,
) callconv(CC) vk.Result;
pub const PfnAcquireNextImageKHR = *const fn (
    device: vk.Device,
    swapchain: vk.SwapchainKHR,
    timeout: u64,
    semaphore: vk.Semaphore,
    fence: vk.Fence,
    p_image_index: *u32,
) callconv(CC) vk.Result;
pub const PfnCreateImageView = *const fn (
    device: vk.Device,
    p_create_info: *const vk.ImageViewCreateInfo,
    p_allocator: ?*const vk.AllocationCallbacks,
    p_view: *vk.ImageView,
) callconv(CC) vk.Result;
pub const PfnDestroyImageView = *const fn (device: vk.Device, view: vk.ImageView, p_allocator: ?*const vk.AllocationCallbacks) callconv(CC) void;
pub const PfnCreateRenderPass = *const fn (
    device: vk.Device,
    p_create_info: *const vk.RenderPassCreateInfo,
    p_allocator: ?*const vk.AllocationCallbacks,
    p_render_pass: *vk.RenderPass,
) callconv(CC) vk.Result;
pub const PfnDestroyRenderPass = *const fn (device: vk.Device, render_pass: vk.RenderPass, p_allocator: ?*const vk.AllocationCallbacks) callconv(CC) void;
pub const PfnCreateFramebuffer = *const fn (
    device: vk.Device,
    p_create_info: *const vk.FramebufferCreateInfo,
    p_allocator: ?*const vk.AllocationCallbacks,
    p_framebuffer: *vk.Framebuffer,
) callconv(CC) vk.Result;
pub const PfnDestroyFramebuffer = *const fn (device: vk.Device, framebuffer: vk.Framebuffer, p_allocator: ?*const vk.AllocationCallbacks) callconv(CC) void;
pub const PfnCreateShaderModule = *const fn (
    device: vk.Device,
    p_create_info: *const vk.ShaderModuleCreateInfo,
    p_allocator: ?*const vk.AllocationCallbacks,
    p_module: *vk.ShaderModule,
) callconv(CC) vk.Result;
pub const PfnDestroyShaderModule = *const fn (device: vk.Device, module: vk.ShaderModule, p_allocator: ?*const vk.AllocationCallbacks) callconv(CC) void;
pub const PfnCreatePipelineLayout = *const fn (
    device: vk.Device,
    p_create_info: *const vk.PipelineLayoutCreateInfo,
    p_allocator: ?*const vk.AllocationCallbacks,
    p_layout: *vk.PipelineLayout,
) callconv(CC) vk.Result;
pub const PfnDestroyPipelineLayout = *const fn (device: vk.Device, layout: vk.PipelineLayout, p_allocator: ?*const vk.AllocationCallbacks) callconv(CC) void;
pub const PfnCreateGraphicsPipelines = *const fn (
    device: vk.Device,
    cache: vk.PipelineCache,
    count: u32,
    p_create_infos: [*]const vk.GraphicsPipelineCreateInfo,
    p_allocator: ?*const vk.AllocationCallbacks,
    p_pipelines: [*]vk.Pipeline,
) callconv(CC) vk.Result;
pub const PfnDestroyPipeline = *const fn (device: vk.Device, pipeline: vk.Pipeline, p_allocator: ?*const vk.AllocationCallbacks) callconv(CC) void;
pub const PfnCreatePipelineCache = *const fn (
    device: vk.Device,
    p_create_info: *const vk.PipelineCacheCreateInfo,
    p_allocator: ?*const vk.AllocationCallbacks,
    p_cache: *vk.PipelineCache,
) callconv(CC) vk.Result;
pub const PfnDestroyPipelineCache = *const fn (device: vk.Device, cache: vk.PipelineCache, p_allocator: ?*const vk.AllocationCallbacks) callconv(CC) void;
pub const PfnGetPipelineCacheData = *const fn (
    device: vk.Device,
    cache: vk.PipelineCache,
    p_size: *usize,
    p_data: ?[*]u8,
) callconv(CC) vk.Result;
pub const PfnCreateCommandPool = *const fn (
    device: vk.Device,
    p_create_info: *const vk.CommandPoolCreateInfo,
    p_allocator: ?*const vk.AllocationCallbacks,
    p_pool: *vk.CommandPool,
) callconv(CC) vk.Result;
pub const PfnDestroyCommandPool = *const fn (device: vk.Device, pool: vk.CommandPool, p_allocator: ?*const vk.AllocationCallbacks) callconv(CC) void;
pub const PfnResetCommandPool = *const fn (device: vk.Device, pool: vk.CommandPool, flags: u32) callconv(CC) vk.Result;
pub const PfnAllocateCommandBuffers = *const fn (
    device: vk.Device,
    p_info: *const vk.CommandBufferAllocateInfo,
    p_command_buffers: [*]vk.CommandBuffer,
) callconv(CC) vk.Result;
pub const PfnFreeCommandBuffers = *const fn (
    device: vk.Device,
    pool: vk.CommandPool,
    count: u32,
    p_command_buffers: [*]const vk.CommandBuffer,
) callconv(CC) void;
pub const PfnBeginCommandBuffer = *const fn (cmd: vk.CommandBuffer, p_info: *const vk.CommandBufferBeginInfo) callconv(CC) vk.Result;
pub const PfnEndCommandBuffer = *const fn (cmd: vk.CommandBuffer) callconv(CC) vk.Result;
pub const PfnCreateFence = *const fn (
    device: vk.Device,
    p_create_info: *const vk.FenceCreateInfo,
    p_allocator: ?*const vk.AllocationCallbacks,
    p_fence: *vk.Fence,
) callconv(CC) vk.Result;
pub const PfnDestroyFence = *const fn (device: vk.Device, fence: vk.Fence, p_allocator: ?*const vk.AllocationCallbacks) callconv(CC) void;
pub const PfnWaitForFences = *const fn (
    device: vk.Device,
    fence_count: u32,
    p_fences: [*]const vk.Fence,
    wait_all: u32,
    timeout: u64,
) callconv(CC) vk.Result;
pub const PfnResetFences = *const fn (device: vk.Device, fence_count: u32, p_fences: [*]const vk.Fence) callconv(CC) vk.Result;
pub const PfnCreateSemaphore = *const fn (
    device: vk.Device,
    p_create_info: *const vk.SemaphoreCreateInfo,
    p_allocator: ?*const vk.AllocationCallbacks,
    p_semaphore: *vk.Semaphore,
) callconv(CC) vk.Result;
pub const PfnDestroySemaphore = *const fn (device: vk.Device, semaphore: vk.Semaphore, p_allocator: ?*const vk.AllocationCallbacks) callconv(CC) void;
pub const PfnAllocateMemory = *const fn (
    device: vk.Device,
    p_info: *const vk.MemoryAllocateInfo,
    p_allocator: ?*const vk.AllocationCallbacks,
    p_memory: *vk.DeviceMemory,
) callconv(CC) vk.Result;
pub const PfnFreeMemory = *const fn (device: vk.Device, memory: vk.DeviceMemory, p_allocator: ?*const vk.AllocationCallbacks) callconv(CC) void;
pub const PfnMapMemory = *const fn (
    device: vk.Device,
    memory: vk.DeviceMemory,
    offset: u64,
    size: u64,
    flags: u32,
    pp_data: *?*anyopaque,
) callconv(CC) vk.Result;
pub const PfnUnmapMemory = *const fn (device: vk.Device, memory: vk.DeviceMemory) callconv(CC) void;
pub const PfnCreateBuffer = *const fn (
    device: vk.Device,
    p_info: *const vk.BufferCreateInfo,
    p_allocator: ?*const vk.AllocationCallbacks,
    p_buffer: *vk.Buffer,
) callconv(CC) vk.Result;
pub const PfnDestroyBuffer = *const fn (device: vk.Device, buffer: vk.Buffer, p_allocator: ?*const vk.AllocationCallbacks) callconv(CC) void;
pub const PfnGetBufferMemoryRequirements = *const fn (device: vk.Device, buffer: vk.Buffer, p_req: *vk.MemoryRequirements) callconv(CC) void;
pub const PfnBindBufferMemory = *const fn (device: vk.Device, buffer: vk.Buffer, memory: vk.DeviceMemory, offset: u64) callconv(CC) vk.Result;
pub const PfnCreateImage = *const fn (
    device: vk.Device,
    p_info: *const vk.ImageCreateInfo,
    p_allocator: ?*const vk.AllocationCallbacks,
    p_image: *vk.Image,
) callconv(CC) vk.Result;
pub const PfnDestroyImage = *const fn (device: vk.Device, image: vk.Image, p_allocator: ?*const vk.AllocationCallbacks) callconv(CC) void;
pub const PfnGetImageMemoryRequirements = *const fn (device: vk.Device, image: vk.Image, p_req: *vk.MemoryRequirements) callconv(CC) void;
pub const PfnBindImageMemory = *const fn (device: vk.Device, image: vk.Image, memory: vk.DeviceMemory, offset: u64) callconv(CC) vk.Result;
pub const PfnCmdBeginRenderPass = *const fn (cmd: vk.CommandBuffer, p_begin: *const vk.RenderPassBeginInfo, contents: vk.SubpassContents) callconv(CC) void;
pub const PfnCmdEndRenderPass = *const fn (cmd: vk.CommandBuffer) callconv(CC) void;
pub const PfnCmdBindPipeline = *const fn (cmd: vk.CommandBuffer, bind_point: vk.PipelineBindPoint, pipeline: vk.Pipeline) callconv(CC) void;
pub const PfnCmdSetViewport = *const fn (cmd: vk.CommandBuffer, first: u32, count: u32, p_viewports: [*]const vk.Viewport) callconv(CC) void;
pub const PfnCmdSetScissor = *const fn (cmd: vk.CommandBuffer, first: u32, count: u32, p_scissors: [*]const vk.Rect2D) callconv(CC) void;
pub const PfnCmdDraw = *const fn (cmd: vk.CommandBuffer, vertex_count: u32, instance_count: u32, first_vertex: u32, first_instance: u32) callconv(CC) void;
pub const PfnCmdDrawIndexed = *const fn (cmd: vk.CommandBuffer, index_count: u32, instance_count: u32, first_index: u32, vertex_offset: i32, first_instance: u32) callconv(CC) void;
pub const PfnCmdPipelineBarrier = *const fn (
    cmd: vk.CommandBuffer,
    src_stage: vk.PipelineStageFlags,
    dst_stage: vk.PipelineStageFlags,
    dep_flags: u32,
    mem_count: u32, p_mem: ?*const anyopaque,
    buf_count: u32, p_buf: ?*const anyopaque,
    img_count: u32, p_img: ?[*]const vk.ImageMemoryBarrier,
) callconv(CC) void;

// --- ImGui backend additions ---
pub const PfnCreateSampler = *const fn (
    device: vk.Device,
    p_info: *const vk.SamplerCreateInfo,
    p_allocator: ?*const vk.AllocationCallbacks,
    p_sampler: *vk.Sampler,
) callconv(CC) vk.Result;
pub const PfnDestroySampler = *const fn (device: vk.Device, sampler: vk.Sampler, p_allocator: ?*const vk.AllocationCallbacks) callconv(CC) void;
pub const PfnCreateDescriptorSetLayout = *const fn (
    device: vk.Device,
    p_info: *const vk.DescriptorSetLayoutCreateInfo,
    p_allocator: ?*const vk.AllocationCallbacks,
    p_layout: *vk.DescriptorSetLayout,
) callconv(CC) vk.Result;
pub const PfnDestroyDescriptorSetLayout = *const fn (device: vk.Device, layout: vk.DescriptorSetLayout, p_allocator: ?*const vk.AllocationCallbacks) callconv(CC) void;
pub const PfnCreateDescriptorPool = *const fn (
    device: vk.Device,
    p_info: *const vk.DescriptorPoolCreateInfo,
    p_allocator: ?*const vk.AllocationCallbacks,
    p_pool: *vk.DescriptorPool,
) callconv(CC) vk.Result;
pub const PfnDestroyDescriptorPool = *const fn (device: vk.Device, pool: vk.DescriptorPool, p_allocator: ?*const vk.AllocationCallbacks) callconv(CC) void;
pub const PfnAllocateDescriptorSets = *const fn (
    device: vk.Device,
    p_info: *const vk.DescriptorSetAllocateInfo,
    p_sets: [*]vk.DescriptorSet,
) callconv(CC) vk.Result;
pub const PfnUpdateDescriptorSets = *const fn (
    device: vk.Device,
    write_count: u32,
    p_writes: ?[*]const vk.WriteDescriptorSet,
    copy_count: u32,
    p_copies: ?*const anyopaque,
) callconv(CC) void;
pub const PfnCmdBindVertexBuffers = *const fn (
    cmd: vk.CommandBuffer,
    first_binding: u32,
    binding_count: u32,
    p_buffers: [*]const vk.Buffer,
    p_offsets: [*]const u64,
) callconv(CC) void;
pub const PfnCmdBindIndexBuffer = *const fn (
    cmd: vk.CommandBuffer,
    buffer: vk.Buffer,
    offset: u64,
    index_type: vk.IndexType,
) callconv(CC) void;
pub const PfnCmdBindDescriptorSets = *const fn (
    cmd: vk.CommandBuffer,
    bind_point: vk.PipelineBindPoint,
    layout: vk.PipelineLayout,
    first_set: u32,
    set_count: u32,
    p_sets: [*]const vk.DescriptorSet,
    dynamic_offset_count: u32,
    p_dynamic_offsets: ?[*]const u32,
) callconv(CC) void;
pub const PfnCmdPushConstants = *const fn (
    cmd: vk.CommandBuffer,
    layout: vk.PipelineLayout,
    stage_flags: vk.ShaderStageFlags,
    offset: u32,
    size: u32,
    p_values: *const anyopaque,
) callconv(CC) void;
pub const PfnCmdCopyBufferToImage = *const fn (
    cmd: vk.CommandBuffer,
    src_buffer: vk.Buffer,
    dst_image: vk.Image,
    dst_layout: vk.ImageLayout,
    region_count: u32,
    p_regions: [*]const vk.BufferImageCopy,
) callconv(CC) void;
pub const PfnCmdCopyImageToBuffer = *const fn (
    cmd: vk.CommandBuffer,
    src_image: vk.Image,
    src_layout: vk.ImageLayout,
    dst_buffer: vk.Buffer,
    region_count: u32,
    p_regions: [*]const vk.BufferImageCopy,
) callconv(CC) void;
pub const PfnFlushMappedMemoryRanges = *const fn (
    device: vk.Device,
    count: u32,
    p_ranges: [*]const vk.MappedMemoryRange,
) callconv(CC) vk.Result;

// ============================================================================
// Loader — owns the dynamic library handle and global entrypoints.
// ============================================================================

pub const Loader = struct {
    lib: dyn_lib.DynLib,
    get_instance_proc_addr: PfnGetInstanceProcAddr,

    // Global functions.
    enumerate_instance_version: ?PfnEnumerateInstanceVersion,
    enumerate_instance_layer_properties: PfnEnumerateInstanceLayerProperties,
    enumerate_instance_extension_properties: PfnEnumerateInstanceExtensionProperties,
    create_instance: PfnCreateInstance,

    pub const Error = error{LibraryNotFound, EntrypointNotFound};

    pub fn init() Loader.Error!Loader {
        const lib_name = switch (builtin.os.tag) {
            .windows => "vulkan-1.dll",
            .macos => "libvulkan.1.dylib",
            else => "libvulkan.so.1",
        };
        var lib = dyn_lib.DynLib.open(lib_name) catch return Loader.Error.LibraryNotFound;
        errdefer lib.close();

        const get_instance_proc_addr = lib.lookup(PfnGetInstanceProcAddr, "vkGetInstanceProcAddr") orelse
            return Loader.Error.EntrypointNotFound;

        // For global entrypoints, call vkGetInstanceProcAddr with a null instance.
        const null_instance: vk.Instance = .null_handle;
        const get = struct {
            fn f(gipa: PfnGetInstanceProcAddr, inst: vk.Instance, comptime T: type, name: [*:0]const u8) ?T {
                const raw = gipa(inst, name) orelse return null;
                return @as(T, @ptrCast(raw));
            }
        }.f;

        return Loader{
            .lib = lib,
            .get_instance_proc_addr = get_instance_proc_addr,
            .enumerate_instance_version = get(get_instance_proc_addr, null_instance, PfnEnumerateInstanceVersion, "vkEnumerateInstanceVersion"),
            .enumerate_instance_layer_properties = get(get_instance_proc_addr, null_instance, PfnEnumerateInstanceLayerProperties, "vkEnumerateInstanceLayerProperties") orelse return Loader.Error.EntrypointNotFound,
            .enumerate_instance_extension_properties = get(get_instance_proc_addr, null_instance, PfnEnumerateInstanceExtensionProperties, "vkEnumerateInstanceExtensionProperties") orelse return Loader.Error.EntrypointNotFound,
            .create_instance = get(get_instance_proc_addr, null_instance, PfnCreateInstance, "vkCreateInstance") orelse return Loader.Error.EntrypointNotFound,
        };
    }

    pub fn deinit(self: *Loader) void {
        self.lib.close();
    }
};

// ============================================================================
// InstanceApi — resolved after vkCreateInstance succeeds.
// ============================================================================

pub const InstanceApi = struct {
    handle: vk.Instance,
    get_proc_addr: PfnGetInstanceProcAddr,

    destroy_instance: PfnDestroyInstance,
    enumerate_physical_devices: PfnEnumeratePhysicalDevices,
    get_physical_device_properties: PfnGetPhysicalDeviceProperties,
    get_physical_device_queue_family_properties: PfnGetPhysicalDeviceQueueFamilyProperties,
    get_physical_device_memory_properties: PfnGetPhysicalDeviceMemoryProperties,
    get_physical_device_surface_support_khr: PfnGetPhysicalDeviceSurfaceSupportKHR,
    get_physical_device_surface_capabilities_khr: PfnGetPhysicalDeviceSurfaceCapabilitiesKHR,
    get_physical_device_surface_formats_khr: PfnGetPhysicalDeviceSurfaceFormatsKHR,
    get_physical_device_surface_present_modes_khr: PfnGetPhysicalDeviceSurfacePresentModesKHR,
    enumerate_device_extension_properties: PfnEnumerateDeviceExtensionProperties,
    create_device: PfnCreateDevice,
    destroy_surface_khr: PfnDestroySurfaceKHR,
    get_device_proc_addr: PfnGetDeviceProcAddr,

    // Optional (only present when VK_EXT_debug_utils is enabled).
    create_debug_utils_messenger_ext: ?PfnCreateDebugUtilsMessengerEXT,
    destroy_debug_utils_messenger_ext: ?PfnDestroyDebugUtilsMessengerEXT,

    pub const Error = error{EntrypointNotFound};

    pub fn init(loader: *const Loader, instance: vk.Instance, debug_utils_enabled: bool) InstanceApi.Error!InstanceApi {
        const gipa = loader.get_instance_proc_addr;

        const get = struct {
            fn f(g: PfnGetInstanceProcAddr, inst: vk.Instance, comptime T: type, name: [*:0]const u8) ?T {
                const raw = g(inst, name) orelse return null;
                return @as(T, @ptrCast(raw));
            }
        }.f;

        return InstanceApi{
            .handle = instance,
            .get_proc_addr = gipa,
            .destroy_instance = get(gipa, instance, PfnDestroyInstance, "vkDestroyInstance") orelse return InstanceApi.Error.EntrypointNotFound,
            .enumerate_physical_devices = get(gipa, instance, PfnEnumeratePhysicalDevices, "vkEnumeratePhysicalDevices") orelse return InstanceApi.Error.EntrypointNotFound,
            .get_physical_device_properties = get(gipa, instance, PfnGetPhysicalDeviceProperties, "vkGetPhysicalDeviceProperties") orelse return InstanceApi.Error.EntrypointNotFound,
            .get_physical_device_queue_family_properties = get(gipa, instance, PfnGetPhysicalDeviceQueueFamilyProperties, "vkGetPhysicalDeviceQueueFamilyProperties") orelse return InstanceApi.Error.EntrypointNotFound,
            .get_physical_device_memory_properties = get(gipa, instance, PfnGetPhysicalDeviceMemoryProperties, "vkGetPhysicalDeviceMemoryProperties") orelse return InstanceApi.Error.EntrypointNotFound,
            .get_physical_device_surface_support_khr = get(gipa, instance, PfnGetPhysicalDeviceSurfaceSupportKHR, "vkGetPhysicalDeviceSurfaceSupportKHR") orelse return InstanceApi.Error.EntrypointNotFound,
            .get_physical_device_surface_capabilities_khr = get(gipa, instance, PfnGetPhysicalDeviceSurfaceCapabilitiesKHR, "vkGetPhysicalDeviceSurfaceCapabilitiesKHR") orelse return InstanceApi.Error.EntrypointNotFound,
            .get_physical_device_surface_formats_khr = get(gipa, instance, PfnGetPhysicalDeviceSurfaceFormatsKHR, "vkGetPhysicalDeviceSurfaceFormatsKHR") orelse return InstanceApi.Error.EntrypointNotFound,
            .get_physical_device_surface_present_modes_khr = get(gipa, instance, PfnGetPhysicalDeviceSurfacePresentModesKHR, "vkGetPhysicalDeviceSurfacePresentModesKHR") orelse return InstanceApi.Error.EntrypointNotFound,
            .enumerate_device_extension_properties = get(gipa, instance, PfnEnumerateDeviceExtensionProperties, "vkEnumerateDeviceExtensionProperties") orelse return InstanceApi.Error.EntrypointNotFound,
            .create_device = get(gipa, instance, PfnCreateDevice, "vkCreateDevice") orelse return InstanceApi.Error.EntrypointNotFound,
            .destroy_surface_khr = get(gipa, instance, PfnDestroySurfaceKHR, "vkDestroySurfaceKHR") orelse return InstanceApi.Error.EntrypointNotFound,
            .get_device_proc_addr = get(gipa, instance, PfnGetDeviceProcAddr, "vkGetDeviceProcAddr") orelse return InstanceApi.Error.EntrypointNotFound,
            .create_debug_utils_messenger_ext = if (debug_utils_enabled) get(gipa, instance, PfnCreateDebugUtilsMessengerEXT, "vkCreateDebugUtilsMessengerEXT") else null,
            .destroy_debug_utils_messenger_ext = if (debug_utils_enabled) get(gipa, instance, PfnDestroyDebugUtilsMessengerEXT, "vkDestroyDebugUtilsMessengerEXT") else null,
        };
    }
};

// ============================================================================
// DeviceApi — resolved after vkCreateDevice succeeds.
// ============================================================================

pub const DeviceApi = struct {
    handle: vk.Device,

    destroy_device: PfnDestroyDevice,
    get_device_queue: PfnGetDeviceQueue,
    device_wait_idle: PfnDeviceWaitIdle,
    queue_wait_idle: PfnQueueWaitIdle,
    queue_submit: PfnQueueSubmit,
    queue_present_khr: PfnQueuePresentKHR,

    create_swapchain_khr: PfnCreateSwapchainKHR,
    destroy_swapchain_khr: PfnDestroySwapchainKHR,
    get_swapchain_images_khr: PfnGetSwapchainImagesKHR,
    acquire_next_image_khr: PfnAcquireNextImageKHR,

    create_image_view: PfnCreateImageView,
    destroy_image_view: PfnDestroyImageView,
    create_render_pass: PfnCreateRenderPass,
    destroy_render_pass: PfnDestroyRenderPass,
    create_framebuffer: PfnCreateFramebuffer,
    destroy_framebuffer: PfnDestroyFramebuffer,

    create_shader_module: PfnCreateShaderModule,
    destroy_shader_module: PfnDestroyShaderModule,
    create_pipeline_layout: PfnCreatePipelineLayout,
    destroy_pipeline_layout: PfnDestroyPipelineLayout,
    create_graphics_pipelines: PfnCreateGraphicsPipelines,
    destroy_pipeline: PfnDestroyPipeline,
    create_pipeline_cache: PfnCreatePipelineCache,
    destroy_pipeline_cache: PfnDestroyPipelineCache,
    get_pipeline_cache_data: PfnGetPipelineCacheData,

    create_command_pool: PfnCreateCommandPool,
    destroy_command_pool: PfnDestroyCommandPool,
    reset_command_pool: PfnResetCommandPool,
    allocate_command_buffers: PfnAllocateCommandBuffers,
    free_command_buffers: PfnFreeCommandBuffers,
    begin_command_buffer: PfnBeginCommandBuffer,
    end_command_buffer: PfnEndCommandBuffer,

    create_fence: PfnCreateFence,
    destroy_fence: PfnDestroyFence,
    wait_for_fences: PfnWaitForFences,
    reset_fences: PfnResetFences,
    create_semaphore: PfnCreateSemaphore,
    destroy_semaphore: PfnDestroySemaphore,

    allocate_memory: PfnAllocateMemory,
    free_memory: PfnFreeMemory,
    map_memory: PfnMapMemory,
    unmap_memory: PfnUnmapMemory,
    create_buffer: PfnCreateBuffer,
    destroy_buffer: PfnDestroyBuffer,
    get_buffer_memory_requirements: PfnGetBufferMemoryRequirements,
    bind_buffer_memory: PfnBindBufferMemory,
    create_image: PfnCreateImage,
    destroy_image: PfnDestroyImage,
    get_image_memory_requirements: PfnGetImageMemoryRequirements,
    bind_image_memory: PfnBindImageMemory,

    cmd_begin_render_pass: PfnCmdBeginRenderPass,
    cmd_end_render_pass: PfnCmdEndRenderPass,
    cmd_bind_pipeline: PfnCmdBindPipeline,
    cmd_set_viewport: PfnCmdSetViewport,
    cmd_set_scissor: PfnCmdSetScissor,
    cmd_draw: PfnCmdDraw,
    cmd_draw_indexed: PfnCmdDrawIndexed,
    cmd_pipeline_barrier: PfnCmdPipelineBarrier,

    // --- ImGui backend additions ---
    create_sampler: PfnCreateSampler,
    destroy_sampler: PfnDestroySampler,
    create_descriptor_set_layout: PfnCreateDescriptorSetLayout,
    destroy_descriptor_set_layout: PfnDestroyDescriptorSetLayout,
    create_descriptor_pool: PfnCreateDescriptorPool,
    destroy_descriptor_pool: PfnDestroyDescriptorPool,
    allocate_descriptor_sets: PfnAllocateDescriptorSets,
    update_descriptor_sets: PfnUpdateDescriptorSets,
    cmd_bind_vertex_buffers: PfnCmdBindVertexBuffers,
    cmd_bind_index_buffer: PfnCmdBindIndexBuffer,
    cmd_bind_descriptor_sets: PfnCmdBindDescriptorSets,
    cmd_push_constants: PfnCmdPushConstants,
    cmd_copy_buffer_to_image: PfnCmdCopyBufferToImage,
    cmd_copy_image_to_buffer: PfnCmdCopyImageToBuffer,
    flush_mapped_memory_ranges: PfnFlushMappedMemoryRanges,

    pub const Error = error{EntrypointNotFound};

    pub fn init(instance_api: *const InstanceApi, device: vk.Device) DeviceApi.Error!DeviceApi {
        const gdpa = instance_api.get_device_proc_addr;
        const must = struct {
            fn f(g: PfnGetDeviceProcAddr, dev: vk.Device, comptime T: type, name: [*:0]const u8) DeviceApi.Error!T {
                const raw = g(dev, name) orelse return DeviceApi.Error.EntrypointNotFound;
                return @as(T, @ptrCast(raw));
            }
        }.f;

        return DeviceApi{
            .handle = device,
            .destroy_device = try must(gdpa, device, PfnDestroyDevice, "vkDestroyDevice"),
            .get_device_queue = try must(gdpa, device, PfnGetDeviceQueue, "vkGetDeviceQueue"),
            .device_wait_idle = try must(gdpa, device, PfnDeviceWaitIdle, "vkDeviceWaitIdle"),
            .queue_wait_idle = try must(gdpa, device, PfnQueueWaitIdle, "vkQueueWaitIdle"),
            .queue_submit = try must(gdpa, device, PfnQueueSubmit, "vkQueueSubmit"),
            .queue_present_khr = try must(gdpa, device, PfnQueuePresentKHR, "vkQueuePresentKHR"),
            .create_swapchain_khr = try must(gdpa, device, PfnCreateSwapchainKHR, "vkCreateSwapchainKHR"),
            .destroy_swapchain_khr = try must(gdpa, device, PfnDestroySwapchainKHR, "vkDestroySwapchainKHR"),
            .get_swapchain_images_khr = try must(gdpa, device, PfnGetSwapchainImagesKHR, "vkGetSwapchainImagesKHR"),
            .acquire_next_image_khr = try must(gdpa, device, PfnAcquireNextImageKHR, "vkAcquireNextImageKHR"),
            .create_image_view = try must(gdpa, device, PfnCreateImageView, "vkCreateImageView"),
            .destroy_image_view = try must(gdpa, device, PfnDestroyImageView, "vkDestroyImageView"),
            .create_render_pass = try must(gdpa, device, PfnCreateRenderPass, "vkCreateRenderPass"),
            .destroy_render_pass = try must(gdpa, device, PfnDestroyRenderPass, "vkDestroyRenderPass"),
            .create_framebuffer = try must(gdpa, device, PfnCreateFramebuffer, "vkCreateFramebuffer"),
            .destroy_framebuffer = try must(gdpa, device, PfnDestroyFramebuffer, "vkDestroyFramebuffer"),
            .create_shader_module = try must(gdpa, device, PfnCreateShaderModule, "vkCreateShaderModule"),
            .destroy_shader_module = try must(gdpa, device, PfnDestroyShaderModule, "vkDestroyShaderModule"),
            .create_pipeline_layout = try must(gdpa, device, PfnCreatePipelineLayout, "vkCreatePipelineLayout"),
            .destroy_pipeline_layout = try must(gdpa, device, PfnDestroyPipelineLayout, "vkDestroyPipelineLayout"),
            .create_graphics_pipelines = try must(gdpa, device, PfnCreateGraphicsPipelines, "vkCreateGraphicsPipelines"),
            .destroy_pipeline = try must(gdpa, device, PfnDestroyPipeline, "vkDestroyPipeline"),
            .create_pipeline_cache = try must(gdpa, device, PfnCreatePipelineCache, "vkCreatePipelineCache"),
            .destroy_pipeline_cache = try must(gdpa, device, PfnDestroyPipelineCache, "vkDestroyPipelineCache"),
            .get_pipeline_cache_data = try must(gdpa, device, PfnGetPipelineCacheData, "vkGetPipelineCacheData"),
            .create_command_pool = try must(gdpa, device, PfnCreateCommandPool, "vkCreateCommandPool"),
            .destroy_command_pool = try must(gdpa, device, PfnDestroyCommandPool, "vkDestroyCommandPool"),
            .reset_command_pool = try must(gdpa, device, PfnResetCommandPool, "vkResetCommandPool"),
            .allocate_command_buffers = try must(gdpa, device, PfnAllocateCommandBuffers, "vkAllocateCommandBuffers"),
            .free_command_buffers = try must(gdpa, device, PfnFreeCommandBuffers, "vkFreeCommandBuffers"),
            .begin_command_buffer = try must(gdpa, device, PfnBeginCommandBuffer, "vkBeginCommandBuffer"),
            .end_command_buffer = try must(gdpa, device, PfnEndCommandBuffer, "vkEndCommandBuffer"),
            .create_fence = try must(gdpa, device, PfnCreateFence, "vkCreateFence"),
            .destroy_fence = try must(gdpa, device, PfnDestroyFence, "vkDestroyFence"),
            .wait_for_fences = try must(gdpa, device, PfnWaitForFences, "vkWaitForFences"),
            .reset_fences = try must(gdpa, device, PfnResetFences, "vkResetFences"),
            .create_semaphore = try must(gdpa, device, PfnCreateSemaphore, "vkCreateSemaphore"),
            .destroy_semaphore = try must(gdpa, device, PfnDestroySemaphore, "vkDestroySemaphore"),
            .allocate_memory = try must(gdpa, device, PfnAllocateMemory, "vkAllocateMemory"),
            .free_memory = try must(gdpa, device, PfnFreeMemory, "vkFreeMemory"),
            .map_memory = try must(gdpa, device, PfnMapMemory, "vkMapMemory"),
            .unmap_memory = try must(gdpa, device, PfnUnmapMemory, "vkUnmapMemory"),
            .create_buffer = try must(gdpa, device, PfnCreateBuffer, "vkCreateBuffer"),
            .destroy_buffer = try must(gdpa, device, PfnDestroyBuffer, "vkDestroyBuffer"),
            .get_buffer_memory_requirements = try must(gdpa, device, PfnGetBufferMemoryRequirements, "vkGetBufferMemoryRequirements"),
            .bind_buffer_memory = try must(gdpa, device, PfnBindBufferMemory, "vkBindBufferMemory"),
            .create_image = try must(gdpa, device, PfnCreateImage, "vkCreateImage"),
            .destroy_image = try must(gdpa, device, PfnDestroyImage, "vkDestroyImage"),
            .get_image_memory_requirements = try must(gdpa, device, PfnGetImageMemoryRequirements, "vkGetImageMemoryRequirements"),
            .bind_image_memory = try must(gdpa, device, PfnBindImageMemory, "vkBindImageMemory"),
            .cmd_begin_render_pass = try must(gdpa, device, PfnCmdBeginRenderPass, "vkCmdBeginRenderPass"),
            .cmd_end_render_pass = try must(gdpa, device, PfnCmdEndRenderPass, "vkCmdEndRenderPass"),
            .cmd_bind_pipeline = try must(gdpa, device, PfnCmdBindPipeline, "vkCmdBindPipeline"),
            .cmd_set_viewport = try must(gdpa, device, PfnCmdSetViewport, "vkCmdSetViewport"),
            .cmd_set_scissor = try must(gdpa, device, PfnCmdSetScissor, "vkCmdSetScissor"),
            .cmd_draw = try must(gdpa, device, PfnCmdDraw, "vkCmdDraw"),
            .cmd_draw_indexed = try must(gdpa, device, PfnCmdDrawIndexed, "vkCmdDrawIndexed"),
            .cmd_pipeline_barrier = try must(gdpa, device, PfnCmdPipelineBarrier, "vkCmdPipelineBarrier"),

            .create_sampler = try must(gdpa, device, PfnCreateSampler, "vkCreateSampler"),
            .destroy_sampler = try must(gdpa, device, PfnDestroySampler, "vkDestroySampler"),
            .create_descriptor_set_layout = try must(gdpa, device, PfnCreateDescriptorSetLayout, "vkCreateDescriptorSetLayout"),
            .destroy_descriptor_set_layout = try must(gdpa, device, PfnDestroyDescriptorSetLayout, "vkDestroyDescriptorSetLayout"),
            .create_descriptor_pool = try must(gdpa, device, PfnCreateDescriptorPool, "vkCreateDescriptorPool"),
            .destroy_descriptor_pool = try must(gdpa, device, PfnDestroyDescriptorPool, "vkDestroyDescriptorPool"),
            .allocate_descriptor_sets = try must(gdpa, device, PfnAllocateDescriptorSets, "vkAllocateDescriptorSets"),
            .update_descriptor_sets = try must(gdpa, device, PfnUpdateDescriptorSets, "vkUpdateDescriptorSets"),
            .cmd_bind_vertex_buffers = try must(gdpa, device, PfnCmdBindVertexBuffers, "vkCmdBindVertexBuffers"),
            .cmd_bind_index_buffer = try must(gdpa, device, PfnCmdBindIndexBuffer, "vkCmdBindIndexBuffer"),
            .cmd_bind_descriptor_sets = try must(gdpa, device, PfnCmdBindDescriptorSets, "vkCmdBindDescriptorSets"),
            .cmd_push_constants = try must(gdpa, device, PfnCmdPushConstants, "vkCmdPushConstants"),
            .cmd_copy_buffer_to_image = try must(gdpa, device, PfnCmdCopyBufferToImage, "vkCmdCopyBufferToImage"),
            .cmd_copy_image_to_buffer = try must(gdpa, device, PfnCmdCopyImageToBuffer, "vkCmdCopyImageToBuffer"),
            .flush_mapped_memory_ranges = try must(gdpa, device, PfnFlushMappedMemoryRanges, "vkFlushMappedMemoryRanges"),
        };
    }
};
