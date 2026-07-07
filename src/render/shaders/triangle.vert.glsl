#version 450

// Hardcoded equilateral triangle, no vertex buffer — drawn with vkCmdDraw(3, 1, 0, 0).
// Validates pipeline + shader plumbing without needing memory.zig yet.

layout(location = 0) out vec3 vColor;

vec2 positions[3] = vec2[](
    vec2( 0.0, -0.6),
    vec2( 0.6,  0.6),
    vec2(-0.6,  0.6)
);

vec3 colors[3] = vec3[](
    vec3(1.0, 0.2, 0.3),
    vec3(0.2, 0.8, 0.4),
    vec3(0.3, 0.5, 1.0)
);

void main() {
    gl_Position = vec4(positions[gl_VertexIndex], 0.0, 1.0);
    vColor = colors[gl_VertexIndex];
}
