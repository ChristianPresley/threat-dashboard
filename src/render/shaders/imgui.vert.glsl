#version 450

// ImGui vertex layout: pos (vec2), uv (vec2), color (u32 packed as 4xR8G8B8A8_UNORM).
layout(location = 0) in vec2 aPos;
layout(location = 1) in vec2 aUV;
layout(location = 2) in vec4 aColor;

layout(push_constant) uniform Push {
    vec2 scale;     // 2.0 / framebuffer_size
    vec2 translate; // -1.0 - position * scale
} pc;

layout(location = 0) out vec2 vUV;
layout(location = 1) out vec4 vColor;

void main() {
    vUV = aUV;
    vColor = aColor;
    gl_Position = vec4(aPos * pc.scale + pc.translate, 0.0, 1.0);
}
