//! Public interface of the `ui` module — the GUI-overhaul foundation layer
//! (docs/gui-overhaul/DESIGN.md). Panels and the dashboard orchestrator
//! import this one module for tokens, fonts, formatting, and interlocks.

pub const theme = @import("theme.zig");
pub const fonts = @import("fonts.zig");
pub const fmt = @import("fmt.zig");
pub const confirm = @import("confirm.zig");
pub const demo = @import("demo.zig");
pub const layout = @import("layout.zig");
pub const registry = @import("registry.zig");
pub const events = @import("events.zig");
pub const dbgate = @import("dbgate.zig");
pub const flash = @import("flash.zig");
pub const stale = @import("stale.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
