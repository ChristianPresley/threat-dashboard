//! Minimal PNG encoder for screenshot capture.
//!
//! Writes 8-bit RGB (color type 2) PNGs using stored (uncompressed) deflate
//! blocks inside the zlib stream — no compressor dependency, output is
//! byte-exact deterministic, and a 1400×900 frame lands around 3.8 MB, which
//! is fine for a validation artifact. Filter type 0 (None) on every scanline.

const std = @import("std");

const png_signature = [_]u8{ 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n' };

/// Encode tightly-packed RGBA8 pixels (stride = width*4) as an RGB PNG,
/// dropping alpha. Returns the encoded file contents, owned by the caller.
pub fn encodeRgba(allocator: std.mem.Allocator, pixels: []const u8, width: u32, height: u32) ![]u8 {
    std.debug.assert(pixels.len >= @as(usize, width) * @as(usize, height) * 4);

    // Raw zlib payload: each scanline is a filter byte + width*3 RGB bytes.
    const row_bytes: usize = 1 + @as(usize, width) * 3;
    const raw_len: usize = row_bytes * @as(usize, height);
    const raw = try allocator.alloc(u8, raw_len);
    defer allocator.free(raw);

    var y: usize = 0;
    while (y < height) : (y += 1) {
        const dst_row = raw[y * row_bytes ..][0..row_bytes];
        dst_row[0] = 0; // filter: None
        const src_row = pixels[y * @as(usize, width) * 4 ..];
        var x: usize = 0;
        while (x < width) : (x += 1) {
            dst_row[1 + x * 3 + 0] = src_row[x * 4 + 0];
            dst_row[1 + x * 3 + 1] = src_row[x * 4 + 1];
            dst_row[1 + x * 3 + 2] = src_row[x * 4 + 2];
        }
    }

    // zlib stream: 2-byte header, stored deflate blocks (≤ 65535 bytes each),
    // 4-byte Adler-32 of the raw payload.
    const max_block: usize = 65535;
    const n_blocks: usize = (raw_len + max_block - 1) / max_block;
    const idat_len: usize = 2 + raw_len + n_blocks * 5 + 4;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.ensureTotalCapacity(allocator, png_signature.len + 12 + 13 + 12 + idat_len + 12);

    out.appendSliceAssumeCapacity(&png_signature);

    // IHDR
    var ihdr: [13]u8 = undefined;
    std.mem.writeInt(u32, ihdr[0..4], width, .big);
    std.mem.writeInt(u32, ihdr[4..8], height, .big);
    ihdr[8] = 8; // bit depth
    ihdr[9] = 2; // color type: truecolor RGB
    ihdr[10] = 0; // compression
    ihdr[11] = 0; // filter
    ihdr[12] = 0; // interlace
    try writeChunk(allocator, &out, "IHDR", &ihdr);

    // IDAT
    const idat = try allocator.alloc(u8, idat_len);
    defer allocator.free(idat);
    idat[0] = 0x78; // CMF: deflate, 32K window
    idat[1] = 0x01; // FLG: no preset dict, fastest (check bits valid: 0x7801 % 31 == 0)
    var w: usize = 2;
    var off: usize = 0;
    while (off < raw_len) {
        const chunk_len: usize = @min(max_block, raw_len - off);
        const is_last: u8 = if (off + chunk_len == raw_len) 1 else 0;
        idat[w] = is_last; // BFINAL + BTYPE=00 (stored)
        const len16: u16 = @intCast(chunk_len);
        std.mem.writeInt(u16, idat[w + 1 ..][0..2], len16, .little);
        std.mem.writeInt(u16, idat[w + 3 ..][0..2], ~len16, .little);
        @memcpy(idat[w + 5 ..][0..chunk_len], raw[off..][0..chunk_len]);
        w += 5 + chunk_len;
        off += chunk_len;
    }
    std.mem.writeInt(u32, idat[w..][0..4], std.hash.Adler32.hash(raw), .big);
    w += 4;
    std.debug.assert(w == idat_len);
    try writeChunk(allocator, &out, "IDAT", idat);

    // IEND
    try writeChunk(allocator, &out, "IEND", &.{});

    return out.toOwnedSlice(allocator);
}

fn writeChunk(allocator: std.mem.Allocator, out: *std.ArrayList(u8), chunk_type: *const [4]u8, data: []const u8) !void {
    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(data.len), .big);
    try out.appendSlice(allocator, &len_buf);
    try out.appendSlice(allocator, chunk_type);
    try out.appendSlice(allocator, data);
    var crc = std.hash.Crc32.init();
    crc.update(chunk_type);
    crc.update(data);
    var crc_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &crc_buf, crc.final(), .big);
    try out.appendSlice(allocator, &crc_buf);
}

test "encodeRgba produces a structurally valid PNG" {
    const a = std.testing.allocator;
    // 3×2 image: red, green, blue / white, black, gray (RGBA in, RGB out).
    const px = [_]u8{
        255, 0, 0, 255, 0, 255, 0, 255, 0,   0,   255, 255,
        255, 255, 255, 255, 0, 0, 0, 255, 128, 128, 128, 255,
    };
    const enc = try encodeRgba(a, &px, 3, 2);
    defer a.free(enc);

    try std.testing.expect(std.mem.eql(u8, enc[0..8], &png_signature));
    // IHDR length 13, type at offset 12.
    try std.testing.expectEqual(@as(u32, 13), std.mem.readInt(u32, enc[8..12], .big));
    try std.testing.expect(std.mem.eql(u8, enc[12..16], "IHDR"));
    try std.testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, enc[16..20], .big));
    try std.testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, enc[20..24], .big));
    // Last 12 bytes are the IEND chunk.
    try std.testing.expect(std.mem.eql(u8, enc[enc.len - 8 .. enc.len - 4], "IEND"));
}
