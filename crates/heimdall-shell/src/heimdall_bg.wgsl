// Heimdall desktop background.
//
// One full-screen pass, no texture bindings, no post-processing. The design
// brief was a "futuristic" field, and the temptation is to add a domain-warp
// fBm with a chromatic aberration pass. That would look impressive in a
// screenshot and then quietly spend a noticeable slice of the GPU on a machine
// whose whole job is to be watching for other things. So: cheap trig, two
// octaves of value noise, one smoothstep. The cost is a few dozen ALU ops per
// pixel, and the whole UI stays responsive on integrated graphics.

struct Uniforms {
    // Elapsed seconds since startup.
    time: f32,
    // Link health, 0.0 (down) to 1.0 (healthy). Drives the palette.
    health: f32,
    // Surface size in physical pixels.
    resolution: vec2<f32>,
    // Surface size in points, for aspect correction.
    size_points: vec2<f32>,
};

@group(0) @binding(0) var<uniform> uniforms: Uniforms;

struct VertexOutput {
    @builtin(position) clip_position: vec4<f32>,
    @location(0) uv: vec2<f32>,
};

// Two triangles covering clip space. The index is synthesised, so there is no
// vertex buffer to allocate or keep in sync.
@vertex
fn vs_main(@builtin(vertex_index) vertex_index: u32) -> VertexOutput {
    var out: VertexOutput;
    // 0,1,2 then 2,1,3 as two triangles.
    var x = f32(i32(vertex_index & 1u) * 4 - 1);
    var y = f32(i32((vertex_index >> 1u) & 1u) * 4 - 1);
    // Flip winding on the second triangle by swapping the corner order.
    if (vertex_index == 3u) { x = -1.0; y = -1.0; }
    if (vertex_index == 4u) { x = 1.0; y = -1.0; }
    if (vertex_index == 5u) { x = -1.0; y = 1.0; }
    out.clip_position = vec4<f32>(x, y, 0.0, 1.0);
    out.uv = (vec2<f32>(x, y) + vec2<f32>(1.0, 1.0)) * 0.5;
    return out;
}

fn hash21(p: vec2<f32>) -> f32 {
    var q = fract(p * vec2<f32>(123.34, 456.21));
    q = q + dot(q, q + 45.32);
    return fract(q.x * q.y);
}

fn value_noise(p: vec2<f32>) -> f32 {
    let i = floor(p);
    let f = fract(p);
    // Smoothstep interpolation rather than linear: the derivative discontinuity
    // at cell edges shows up as a grid of faint lines on a near-flat gradient.
    let u = f * f * (3.0 - 2.0 * f);

    let a = hash21(i);
    let b = hash21(i + vec2<f32>(1.0, 0.0));
    let c = hash21(i + vec2<f32>(0.0, 1.0));
    let d = hash21(i + vec2<f32>(1.0, 1.0));

    return mix(mix(a, b, u.x), mix(c, d, u.x), u.y);
}

@fragment
fn fs_main(in: VertexOutput) -> @location(0) vec4<f32> {
    // Aspect-correct so the pattern does not stretch when the window is resized.
    let aspect = max(uniforms.resolution.x / max(uniforms.resolution.y, 1.0), 0.001);
    let uv = vec2<f32>(in.uv.x * aspect, in.uv.y);
    let t = uniforms.time;

    // Two octaves. A third is not visibly better at these amplitudes and costs
    // a third more.
    let p = uv * 3.0;
    var n = value_noise(p + vec2<f32>(t * 0.06, t * 0.04)) * 0.65;
    n = n + value_noise(p * 2.3 - vec2<f32>(t * 0.09, t * 0.05)) * 0.35;

    // A slow radial sweep, so there is a sense of a scanning perimeter.
    let centre = vec2<f32>(0.5 * aspect, 0.5);
    let d = distance(uv, centre);
    let sweep = 0.5 + 0.5 * sin(d * 9.0 - t * 0.8);
    let sweep = sweep * sweep;

    // Healthy: deep blue with a cyan cast. Degraded: desaturated red.
    let healthy_a = vec3<f32>(0.04, 0.07, 0.16);
    let healthy_b = vec3<f32>(0.10, 0.42, 0.52);
    let failing_a = vec3<f32>(0.10, 0.03, 0.05);
    let failing_b = vec3<f32>(0.45, 0.10, 0.12);

    var base = mix(healthy_a, failing_a, 1.0 - uniforms.health);
    let glow = mix(healthy_b, failing_b, 1.0 - uniforms.health);

    var colour = base + glow * n * 0.42 + glow * sweep * 0.10;

    // Vignette. Keeps the middle bright where the panels sit and stops the
    // edges competing with text.
    let vignette = 1.0 - smoothstep(0.35, 1.1, d);
    colour = colour * (0.55 + 0.45 * vignette);

    // Output alpha below 1 so egui composites rather than replaces. Opaque
    // black corners on a window with rounded borders look like a bug.
    let alpha = clamp(0.82 * vignette + 0.18, 0.0, 1.0);
    return vec4<f32>(colour, alpha);
}