//! Tiny cross-platform dynamic-library wrapper.
//!
//! `std.DynLib` doesn't support Windows in Zig 0.16, so we go direct to OS APIs.
//! On Windows: kernel32!LoadLibraryW + GetProcAddress + FreeLibrary, declared as
//! externs here to avoid pulling Zig's stdlib Windows surface (which has churned).
//! On POSIX: dlopen / dlsym / dlclose via std.c.
//! Only the surface we need is exposed.

const std = @import("std");
const builtin = @import("builtin");

const HMODULE = *opaque {};
const FARPROC = *const fn () callconv(.winapi) isize;
extern "kernel32" fn LoadLibraryW(lpLibFileName: [*:0]const u16) callconv(.winapi) ?HMODULE;
extern "kernel32" fn GetProcAddress(hModule: HMODULE, lpProcName: [*:0]const u8) callconv(.winapi) ?FARPROC;
extern "kernel32" fn FreeLibrary(hModule: HMODULE) callconv(.winapi) i32;

pub const DynLib = struct {
    handle: Handle,

    const Handle = if (builtin.os.tag == .windows) HMODULE else *anyopaque;

    pub const Error = error{LibraryNotFound, SymbolNotFound};

    pub fn open(name: []const u8) Error!DynLib {
        if (builtin.os.tag == .windows) {
            var buf: [512]u16 = undefined;
            const len = std.unicode.utf8ToUtf16Le(&buf, name) catch return Error.LibraryNotFound;
            if (len >= buf.len) return Error.LibraryNotFound;
            buf[len] = 0;
            const h = LoadLibraryW(@ptrCast(&buf)) orelse return Error.LibraryNotFound;
            return .{ .handle = h };
        } else {
            var name_buf: [256]u8 = undefined;
            if (name.len >= name_buf.len) return Error.LibraryNotFound;
            @memcpy(name_buf[0..name.len], name);
            name_buf[name.len] = 0;
            const h = std.c.dlopen(@ptrCast(&name_buf), .{ .NOW = true }) orelse
                return Error.LibraryNotFound;
            return .{ .handle = h };
        }
    }

    pub fn close(self: *DynLib) void {
        if (builtin.os.tag == .windows) {
            _ = FreeLibrary(self.handle);
        } else {
            _ = std.c.dlclose(self.handle);
        }
    }

    pub fn lookup(self: *DynLib, comptime T: type, name: [*:0]const u8) ?T {
        if (builtin.os.tag == .windows) {
            const proc = GetProcAddress(self.handle, name) orelse return null;
            return @as(T, @ptrCast(proc));
        } else {
            const proc = std.c.dlsym(self.handle, name) orelse return null;
            return @as(T, @ptrCast(@alignCast(proc)));
        }
    }
};
