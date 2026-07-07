//! Physical-device selection and logical-device creation.
//!
//! Pick rule: first device satisfying our needs (graphics + present support,
//! VK_KHR_swapchain extension), preferring discrete > integrated > other.
//! One queue family for both graphics and present (the common case on consumer GPUs).

const std = @import("std");
const vk = @import("vk.zig");
const api = @import("api.zig");
const Instance = @import("instance.zig").Instance;
const Surface = @import("surface.zig").Surface;

const log = std.log.scoped(.vk_device);

pub const DeviceError = error{
    NoPhysicalDevices,
    NoSuitableDevice,
    OutOfMemory,
} || vk.Error || api.DeviceApi.Error;

pub const PickedDevice = struct {
    physical: vk.PhysicalDevice,
    queue_family_index: u32,
    name_buf: [vk.MAX_PHYSICAL_DEVICE_NAME_SIZE]u8,
    name_len: usize,

    pub fn name(self: *const PickedDevice) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

pub const Device = struct {
    instance: *Instance,
    picked: PickedDevice,
    api: api.DeviceApi,
    graphics_queue: vk.Queue,
    present_queue: vk.Queue, // Same as graphics_queue when one family.
    /// Cached memory property table for the picked physical device. Public so the
    /// ImGui backend and any future dashboard GPU code can scan for a memory type
    /// without re-querying.
    memory_props: vk.PhysicalDeviceMemoryProperties,

    pub fn create(
        allocator: std.mem.Allocator,
        instance: *Instance,
        surface: *const Surface,
    ) DeviceError!Device {
        const picked = try pickPhysicalDevice(allocator, instance, surface);
        log.info("Picked GPU: {s}", .{picked.name()});

        const priorities = [_]f32{1.0};
        const queue_ci = [_]vk.DeviceQueueCreateInfo{.{
            .queue_family_index = picked.queue_family_index,
            .queue_count = 1,
            .p_queue_priorities = &priorities,
        }};

        const device_extensions = [_][*:0]const u8{"VK_KHR_swapchain"};

        const features: vk.PhysicalDeviceFeatures = .{};
        const device_ci = vk.DeviceCreateInfo{
            .queue_create_info_count = queue_ci.len,
            .p_queue_create_infos = &queue_ci,
            .enabled_extension_count = device_extensions.len,
            .pp_enabled_extension_names = &device_extensions,
            .p_enabled_features = &features,
        };

        var device: vk.Device = .null_handle;
        try vk.check(instance.api.create_device(picked.physical, &device_ci, null, &device));
        // Errdefer to destroy the VkDevice if DeviceApi.init below fails. We resolve
        // vkDestroyDevice via the instance loader so we have a PFN even when the
        // device-level dispatch table hasn't been built yet.
        errdefer {
            const destroy_pfn = blk: {
                const raw = instance.api.get_device_proc_addr(device, "vkDestroyDevice");
                break :blk @as(?api.PfnDestroyDevice, @ptrCast(raw));
            };
            if (destroy_pfn) |d| d(device, null);
        }

        const dev_api = try api.DeviceApi.init(&instance.api, device);

        var graphics_queue: vk.Queue = .null_handle;
        dev_api.get_device_queue(device, picked.queue_family_index, 0, &graphics_queue);

        var memory_props: vk.PhysicalDeviceMemoryProperties = undefined;
        instance.api.get_physical_device_memory_properties(picked.physical, &memory_props);

        return Device{
            .instance = instance,
            .picked = picked,
            .api = dev_api,
            .graphics_queue = graphics_queue,
            .present_queue = graphics_queue,
            .memory_props = memory_props,
        };
    }

    /// Scan the memory type table for a slot that has all of `type_bits` set and
    /// satisfies all `required` property flags. Returns the type index.
    pub fn findMemoryType(self: *const Device, type_bits: u32, required: vk.MemoryPropertyFlags) ?u32 {
        const required_u: u32 = @bitCast(required);
        var i: u32 = 0;
        while (i < self.memory_props.memory_type_count) : (i += 1) {
            const this_bit = @as(u32, 1) << @intCast(i);
            if ((type_bits & this_bit) == 0) continue;
            const have_u: u32 = @bitCast(self.memory_props.memory_types[i].property_flags);
            if ((have_u & required_u) == required_u) return i;
        }
        return null;
    }

    pub fn destroy(self: *Device) void {
        self.api.destroy_device(self.api.handle, null);
    }

    pub fn waitIdle(self: *Device) void {
        _ = self.api.device_wait_idle(self.api.handle);
    }
};

fn pickPhysicalDevice(
    allocator: std.mem.Allocator,
    instance: *Instance,
    surface: *const Surface,
) DeviceError!PickedDevice {
    var count: u32 = 0;
    try vk.check(instance.api.enumerate_physical_devices(instance.api.handle, &count, null));
    if (count == 0) return DeviceError.NoPhysicalDevices;
    const devices = try allocator.alloc(vk.PhysicalDevice, count);
    defer allocator.free(devices);
    try vk.check(instance.api.enumerate_physical_devices(instance.api.handle, &count, devices.ptr));

    var best: ?PickedDevice = null;
    var best_score: i32 = -1;

    for (devices) |dev| {
        var props: vk.PhysicalDeviceProperties = undefined;
        instance.api.get_physical_device_properties(dev, &props);

        if (!deviceHasExtension(allocator, instance, dev, "VK_KHR_swapchain")) continue;

        const family_idx = findQueueFamily(allocator, instance, dev, surface) catch continue;
        if (family_idx == null) continue;

        const score: i32 = switch (props.device_type) {
            .discrete_gpu => 100,
            .integrated_gpu => 50,
            .virtual_gpu => 20,
            else => 10,
        };
        if (score > best_score) {
            best_score = score;
            const name_len = std.mem.indexOfScalar(u8, &props.device_name, 0) orelse props.device_name.len;
            var picked: PickedDevice = .{
                .physical = dev,
                .queue_family_index = family_idx.?,
                .name_buf = undefined,
                .name_len = name_len,
            };
            @memcpy(picked.name_buf[0..name_len], props.device_name[0..name_len]);
            best = picked;
        }
    }

    return best orelse DeviceError.NoSuitableDevice;
}

fn deviceHasExtension(
    allocator: std.mem.Allocator,
    instance: *Instance,
    dev: vk.PhysicalDevice,
    name: []const u8,
) bool {
    var count: u32 = 0;
    if (instance.api.enumerate_device_extension_properties(dev, null, &count, null) != .success) return false;
    if (count == 0) return false;
    const props = allocator.alloc(vk.ExtensionProperties, count) catch return false;
    defer allocator.free(props);
    if (instance.api.enumerate_device_extension_properties(dev, null, &count, props.ptr) != .success) return false;
    for (props) |p| {
        const have = std.mem.sliceTo(&p.extension_name, 0);
        if (std.mem.eql(u8, have, name)) return true;
    }
    return false;
}

fn findQueueFamily(
    allocator: std.mem.Allocator,
    instance: *Instance,
    dev: vk.PhysicalDevice,
    surface: *const Surface,
) !?u32 {
    var count: u32 = 0;
    instance.api.get_physical_device_queue_family_properties(dev, &count, null);
    if (count == 0) return null;
    const families = try allocator.alloc(vk.QueueFamilyProperties, count);
    defer allocator.free(families);
    instance.api.get_physical_device_queue_family_properties(dev, &count, families.ptr);

    for (families, 0..) |f, i| {
        if (!f.queue_flags.graphics) continue;
        var supported: u32 = vk.FALSE;
        const r = instance.api.get_physical_device_surface_support_khr(dev, @intCast(i), surface.handle, &supported);
        if (r != .success) continue;
        if (supported == vk.TRUE) return @intCast(i);
    }
    return null;
}
