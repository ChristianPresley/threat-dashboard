//! Minimal HTTPS wrapper over std.http.Client (Zig 0.16, std.Io-based).
//!
//! Used ONLY from the AI worker thread — never the render thread. TLS is
//! std.crypto.tls; on Windows the CA bundle is rescanned from the system
//! cert store (crypt32) on first request, so no bundled roots are needed.
//! This wrapper isolates the backend: if std TLS ever proves unworkable,
//! a WinHTTP implementation can replace the internals without touching
//! callers.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Header = std.http.Header; // { name, value }

pub const Response = struct {
    status: u16,
    /// Owned by the caller's allocator; free with `allocator.free`.
    body: []u8,
};

pub const Client = struct {
    inner: std.http.Client,

    pub fn init(gpa: Allocator, io: std.Io) Client {
        return .{ .inner = .{ .allocator = gpa, .io = io } };
    }

    pub fn deinit(self: *Client) void {
        self.inner.deinit();
    }

    /// Blocking JSON POST. Collects the full response body (up to
    /// `max_body` bytes) regardless of status — non-2xx bodies are JSON
    /// error envelopes the caller parses. Returns `error.ResponseTooLarge`
    /// if the body exceeds `max_body`.
    pub fn postJson(
        self: *Client,
        gpa: Allocator,
        url: []const u8,
        extra_headers: []const Header,
        payload: []const u8,
        max_body: usize,
    ) !Response {
        var aw: std.Io.Writer.Allocating = .init(gpa);
        defer aw.deinit();

        const res = try self.inner.fetch(.{
            .location = .{ .url = url },
            .method = .POST,
            .payload = payload,
            .extra_headers = extra_headers,
            .headers = .{ .content_type = .{ .override = "application/json" } },
            .response_writer = &aw.writer,
        });

        if (aw.writer.end > max_body) return error.ResponseTooLarge;
        return .{
            .status = @intFromEnum(res.status),
            .body = try aw.toOwnedSlice(),
        };
    }
};

test "http client compiles" {
    std.testing.refAllDecls(@This());
}
