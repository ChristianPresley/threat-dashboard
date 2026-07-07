#version 450

// ImGui's default fragment shader: sample a single texture (either the font atlas
// or a 1x1 white pixel for non-textured primitives) and multiply by vertex color.
// PR 1b uses this for ALL ImGui draws; PR 3 will split text out into a separate
// MSDF fragment shader.

layout(set = 0, binding = 0) uniform sampler2D uTex;

layout(location = 0) in vec2 vUV;
layout(location = 1) in vec4 vColor;
layout(location = 0) out vec4 outColor;

void main() {
    outColor = vColor * texture(uTex, vUV);
}
