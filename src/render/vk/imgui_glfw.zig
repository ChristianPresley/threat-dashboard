//! GLFW → ImGui input bridge.
//!
//! Replaces what `imgui_impl_glfw.cpp` did under the `.glfw_opengl3` zgui backend.
//! We can't use `imgui_impl_glfw.cpp` directly with `.no_backend` set, so this
//! module wires the GLFW callbacks we care about (mouse pos / button / scroll,
//! key press/release, character input, window focus, content scale) into the
//! corresponding `zgui.io.add*Event` calls.
//!
//! Coverage is the dashboard's needs — full keyboard + mouse + scroll + focus,
//! including modifier-key state (mods bitfield → mod_ctrl/shift/alt/super
//! KeyEvents) so ImGui shortcuts like Ctrl+V paste / Ctrl+A select-all fire
//! inside InputText fields.
//! Mouse cursor shapes ARE handled: `attach` creates the standard GLFW
//! cursors and declares `BackendFlags.has_mouse_cursors`; the frame loop
//! calls `updateMouseCursor` so splitters show resize arrows, links show a
//! hand, and text inputs show an I-beam (a docked layout is unusable
//! without them).
//!
//! Not handled (acceptable for now):
//!   - Gamepad / joystick
//!   - IME (clipboard get/set use ImGui's platform defaults — Win32 clipboard
//!     API on Windows — which work without explicit wiring)
//!   - Per-monitor DPI changes (we route framebuffer-scale once at init only;
//!     scale changes after window creation require re-init)

const std = @import("std");
const zgui = @import("zgui");
const glfw = @import("glfw_vk.zig");

const log = std.log.scoped(.imgui_glfw);

const window_user_pointer_key: *const anyopaque = @ptrCast(&window_user_pointer_key);

// GLFW callback function-pointer typedefs (subset).
const PfnCursorPos = ?*const fn (*glfw.GLFWwindow, f64, f64) callconv(.c) void;
const PfnMouseButton = ?*const fn (*glfw.GLFWwindow, c_int, c_int, c_int) callconv(.c) void;
const PfnScroll = ?*const fn (*glfw.GLFWwindow, f64, f64) callconv(.c) void;
const PfnKey = ?*const fn (*glfw.GLFWwindow, c_int, c_int, c_int, c_int) callconv(.c) void;
const PfnChar = ?*const fn (*glfw.GLFWwindow, c_uint) callconv(.c) void;
const PfnFocus = ?*const fn (*glfw.GLFWwindow, c_int) callconv(.c) void;

extern fn glfwSetCursorPosCallback(*glfw.GLFWwindow, PfnCursorPos) PfnCursorPos;
extern fn glfwSetMouseButtonCallback(*glfw.GLFWwindow, PfnMouseButton) PfnMouseButton;
extern fn glfwSetScrollCallback(*glfw.GLFWwindow, PfnScroll) PfnScroll;
extern fn glfwSetKeyCallback(*glfw.GLFWwindow, PfnKey) PfnKey;
extern fn glfwSetCharCallback(*glfw.GLFWwindow, PfnChar) PfnChar;
extern fn glfwSetWindowFocusCallback(*glfw.GLFWwindow, PfnFocus) PfnFocus;

// Cursor-shape API (GLFW 3.4 standard cursors).
const GLFWcursor = opaque {};
extern fn glfwCreateStandardCursor(shape: c_int) ?*GLFWcursor;
extern fn glfwDestroyCursor(cursor: *GLFWcursor) void;
extern fn glfwSetCursor(window: *glfw.GLFWwindow, cursor: ?*GLFWcursor) void;
extern fn glfwSetInputMode(window: *glfw.GLFWwindow, mode: c_int, value: c_int) void;

const GLFW_CURSOR: c_int = 0x00033001;
const GLFW_CURSOR_NORMAL: c_int = 0x00034001;
const GLFW_CURSOR_HIDDEN: c_int = 0x00034002;

const GLFW_ARROW_CURSOR: c_int = 0x00036001;
const GLFW_IBEAM_CURSOR: c_int = 0x00036002;
const GLFW_CROSSHAIR_CURSOR: c_int = 0x00036003;
const GLFW_POINTING_HAND_CURSOR: c_int = 0x00036004;
const GLFW_RESIZE_EW_CURSOR: c_int = 0x00036005;
const GLFW_RESIZE_NS_CURSOR: c_int = 0x00036006;
const GLFW_RESIZE_NWSE_CURSOR: c_int = 0x00036007;
const GLFW_RESIZE_NESW_CURSOR: c_int = 0x00036008;
const GLFW_RESIZE_ALL_CURSOR: c_int = 0x00036009;
const GLFW_NOT_ALLOWED_CURSOR: c_int = 0x0003600A;

/// Standard cursors, indexed by `zgui.Cursor` ordinal (arrow..not_allowed).
/// Created in `attach`; entries may be null where the platform lacks the
/// shape (GLFW falls back when passed null).
var cursors: [@intFromEnum(zgui.Cursor.count)]?*GLFWcursor = @splat(null);

// GLFW key/button constants we need (avoids depending on GLFW headers).
const GLFW_PRESS: c_int = 1;
const GLFW_RELEASE: c_int = 0;
const GLFW_REPEAT: c_int = 2;
const GLFW_MOUSE_BUTTON_LEFT: c_int = 0;
const GLFW_MOUSE_BUTTON_RIGHT: c_int = 1;
const GLFW_MOUSE_BUTTON_MIDDLE: c_int = 2;

// GLFW modifier bitfield flags (mods arg of key + mouse callbacks).
const GLFW_MOD_SHIFT: c_int = 0x0001;
const GLFW_MOD_CONTROL: c_int = 0x0002;
const GLFW_MOD_ALT: c_int = 0x0004;
const GLFW_MOD_SUPER: c_int = 0x0008;

/// Hook GLFW's input callbacks. The `window` must remain valid until `detach`.
/// We overwrite any prior callback handlers — this app has no other consumers
/// in the chain; if you add one, save the returned previous-callback pointers
/// here and forward to them from each hook.
pub fn attach(window: *glfw.GLFWwindow) void {
    _ = glfwSetCursorPosCallback(window, &onCursorPos);
    _ = glfwSetMouseButtonCallback(window, &onMouseButton);
    _ = glfwSetScrollCallback(window, &onScroll);
    _ = glfwSetKeyCallback(window, &onKey);
    _ = glfwSetCharCallback(window, &onChar);
    _ = glfwSetWindowFocusCallback(window, &onFocus);

    createCursors();
    var flags = zgui.io.getBackendFlags();
    flags.has_mouse_cursors = true;
    zgui.io.setBackendFlags(flags);
}

pub fn detach(window: *glfw.GLFWwindow) void {
    _ = glfwSetCursorPosCallback(window, null);
    _ = glfwSetMouseButtonCallback(window, null);
    _ = glfwSetScrollCallback(window, null);
    _ = glfwSetKeyCallback(window, null);
    _ = glfwSetCharCallback(window, null);
    _ = glfwSetWindowFocusCallback(window, null);

    for (&cursors) |*c| {
        if (c.*) |cur| {
            glfwDestroyCursor(cur);
            c.* = null;
        }
    }
}

fn createCursors() void {
    const shapes = [_]struct { idx: zgui.Cursor, shape: c_int }{
        .{ .idx = .arrow, .shape = GLFW_ARROW_CURSOR },
        .{ .idx = .text_input, .shape = GLFW_IBEAM_CURSOR },
        .{ .idx = .resize_all, .shape = GLFW_RESIZE_ALL_CURSOR },
        .{ .idx = .resize_ns, .shape = GLFW_RESIZE_NS_CURSOR },
        .{ .idx = .resize_ew, .shape = GLFW_RESIZE_EW_CURSOR },
        .{ .idx = .resize_nesw, .shape = GLFW_RESIZE_NESW_CURSOR },
        .{ .idx = .resize_nwse, .shape = GLFW_RESIZE_NWSE_CURSOR },
        .{ .idx = .hand, .shape = GLFW_POINTING_HAND_CURSOR },
        // GLFW has no standard wait/progress cursors — entries stay null and
        // updateMouseCursor falls back to the arrow.
        .{ .idx = .not_allowed, .shape = GLFW_NOT_ALLOWED_CURSOR },
    };
    for (shapes) |s| {
        // May return null (e.g. X11 without a shape) — GLFW then keeps the
        // default arrow when we pass null to glfwSetCursor.
        cursors[@intCast(@intFromEnum(s.idx))] = glfwCreateStandardCursor(s.shape);
    }
}

/// Sync the OS cursor with ImGui's requested shape. Call once per frame
/// after `glfwPollEvents`. Mirrors ImGui_ImplGlfw_UpdateMouseCursor.
pub fn updateMouseCursor(window: *glfw.GLFWwindow) void {
    const wanted = zgui.getMouseCursor();
    if (wanted == .none) {
        glfwSetInputMode(window, GLFW_CURSOR, GLFW_CURSOR_HIDDEN);
        return;
    }
    glfwSetInputMode(window, GLFW_CURSOR, GLFW_CURSOR_NORMAL);
    const idx: usize = @intCast(@intFromEnum(wanted));
    const cursor = if (idx < cursors.len) cursors[idx] else null;
    glfwSetCursor(window, cursor orelse cursors[@intFromEnum(zgui.Cursor.arrow)]);
}

fn onCursorPos(_: *glfw.GLFWwindow, x: f64, y: f64) callconv(.c) void {
    zgui.io.addMousePositionEvent(@floatCast(x), @floatCast(y));
}

fn onMouseButton(_: *glfw.GLFWwindow, button: c_int, action: c_int, mods: c_int) callconv(.c) void {
    if (action != GLFW_PRESS and action != GLFW_RELEASE) return;
    // Sync modifier state on every mouse event so chord clicks
    // (Shift-click, Ctrl-click, etc.) see the right mods.
    updateKeyModifiers(mods);
    const down = (action == GLFW_PRESS);
    const mb: zgui.MouseButton = switch (button) {
        GLFW_MOUSE_BUTTON_LEFT => .left,
        GLFW_MOUSE_BUTTON_RIGHT => .right,
        GLFW_MOUSE_BUTTON_MIDDLE => .middle,
        else => return,
    };
    zgui.io.addMouseButtonEvent(mb, down);
}

fn onScroll(_: *glfw.GLFWwindow, x: f64, y: f64) callconv(.c) void {
    zgui.io.addMouseWheelEvent(@floatCast(x), @floatCast(y));
}

fn onKey(_: *glfw.GLFWwindow, key: c_int, scancode: c_int, action: c_int, mods: c_int) callconv(.c) void {
    // Sync modifier state BEFORE emitting the key event so ImGui's
    // shortcut detection (Ctrl+V, Ctrl+C, Ctrl+A, …) sees the right
    // mods on the same frame the key fires.  Without this, KeyCtrl /
    // KeyShift stay false inside InputText and paste does nothing.
    updateKeyModifiers(mods);
    if (action == GLFW_REPEAT) return; // ImGui synthesizes repeats internally.
    const down = (action == GLFW_PRESS);
    const im_key = glfwKeyToImGui(key) orelse return;
    zgui.io.setKeyEventNativeData(im_key, key, scancode);
    zgui.io.addKeyEvent(im_key, down);
}

/// Translate GLFW's mods bitfield into ImGui's per-modifier KeyEvents.
/// Mirrors `ImGui_ImplGlfw_UpdateKeyModifiers` from imgui_impl_glfw.cpp.
fn updateKeyModifiers(mods: c_int) void {
    zgui.io.addKeyEvent(.mod_ctrl,  (mods & GLFW_MOD_CONTROL) != 0);
    zgui.io.addKeyEvent(.mod_shift, (mods & GLFW_MOD_SHIFT) != 0);
    zgui.io.addKeyEvent(.mod_alt,   (mods & GLFW_MOD_ALT) != 0);
    zgui.io.addKeyEvent(.mod_super, (mods & GLFW_MOD_SUPER) != 0);
}

fn onChar(_: *glfw.GLFWwindow, codepoint: c_uint) callconv(.c) void {
    zgui.io.addCharacterEvent(@intCast(codepoint));
}

fn onFocus(_: *glfw.GLFWwindow, focused: c_int) callconv(.c) void {
    zgui.io.addFocusEvent(focused != 0);
}

// GLFW key codes (subset — only what we actually translate). Full table at:
//   https://www.glfw.org/docs/latest/group__keys.html
fn glfwKeyToImGui(key: c_int) ?zgui.Key {
    return switch (key) {
        32 => .space,
        39 => .apostrophe,
        44 => .comma,
        45 => .minus,
        46 => .period,
        47 => .slash,
        48 => .zero,
        49 => .one,
        50 => .two,
        51 => .three,
        52 => .four,
        53 => .five,
        54 => .six,
        55 => .seven,
        56 => .eight,
        57 => .nine,
        59 => .semicolon,
        61 => .equal,
        65 => .a,
        66 => .b,
        67 => .c,
        68 => .d,
        69 => .e,
        70 => .f,
        71 => .g,
        72 => .h,
        73 => .i,
        74 => .j,
        75 => .k,
        76 => .l,
        77 => .m,
        78 => .n,
        79 => .o,
        80 => .p,
        81 => .q,
        82 => .r,
        83 => .s,
        84 => .t,
        85 => .u,
        86 => .v,
        87 => .w,
        88 => .x,
        89 => .y,
        90 => .z,
        91 => .left_bracket,
        92 => .back_slash,
        93 => .right_bracket,
        96 => .grave_accent,
        256 => .escape,
        257 => .enter,
        258 => .tab,
        259 => .back_space,
        260 => .insert,
        261 => .delete,
        262 => .right_arrow,
        263 => .left_arrow,
        264 => .down_arrow,
        265 => .up_arrow,
        266 => .page_up,
        267 => .page_down,
        268 => .home,
        269 => .end,
        280 => .caps_lock,
        281 => .scroll_lock,
        282 => .num_lock,
        283 => .print_screen,
        284 => .pause,
        290...301 => @enumFromInt(@intFromEnum(zgui.Key.f1) + (key - 290)), // F1..F12
        320...329 => @enumFromInt(@intFromEnum(zgui.Key.keypad_0) + (key - 320)), // KP_0..KP_9
        330 => .keypad_decimal,
        331 => .keypad_divide,
        332 => .keypad_multiply,
        333 => .keypad_subtract,
        334 => .keypad_add,
        335 => .keypad_enter,
        336 => .keypad_equal,
        340 => .left_shift,
        341 => .left_ctrl,
        342 => .left_alt,
        343 => .left_super,
        344 => .right_shift,
        345 => .right_ctrl,
        346 => .right_alt,
        347 => .right_super,
        348 => .menu,
        else => null,
    };
}
