//! The animated background, drawn by a custom WGSL shader.
//!
//! `egui` composites widgets on the CPU and hands the GPU a vertex buffer, which
//! is the right call for chrome and the wrong one for a full-screen animated
//! field: doing it through the vertex path costs a buffer rewrite every frame.
//! This instead issues a single draw call from its own wgpu pipeline via
//! [`egui_wgpu::CallbackTrait`], so the cost is constant no matter how complex
//! the shader becomes.
//!
//! The pipeline is created in the first `prepare` rather than in the
//! constructor, because `eframe` hands the application a creation context but
//! not the `wgpu::Device` -- that only appears on the first frame.

// Pixel and viewport coordinates are converted to `f32` throughout. The casts
// are exact for any realistic window size and the lint does not apply here.
#![allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]

use std::sync::Arc;
use std::time::Instant;

use egui::PaintCallbackInfo;
use egui::{Color32, Rect};
use egui_wgpu::{Callback, CallbackResources, CallbackTrait, ScreenDescriptor};

// `egui-wgpu` re-exports the exact `wgpu` build it was compiled against.
// Referring to a separately-resolved `wgpu` here produces distinct but nominally
// identical types, which then fail to satisfy `CallbackTrait`.
use egui_wgpu::wgpu;

/// Uniform data shared with the shader. `#[repr(C)]` and field order matter:
/// WGSL reads this block as raw bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
struct Uniforms {
    /// Elapsed seconds since startup.
    time: f32,
    /// Link health in `0.0..=1.0`; the palette cools as health drops.
    health: f32,
    /// Surface size in physical pixels.
    resolution: [f32; 2],
    /// Surface size in points, for aspect correction.
    size_points: [f32; 2],
}

/// Six vertices, generated from `vertex_index` in the shader. No vertex buffer
/// is allocated or updated.
const FULLSCREEN_VERTEX_COUNT: u32 = 6;

const SHADER: &str = include_str!("heimdall_bg.wgsl");

/// GPU state, built once and shared across per-frame callbacks.
struct GpuState {
    pipeline: wgpu::RenderPipeline,
    bind_group: wgpu::BindGroup,
    uniform: wgpu::Buffer,
}

impl std::fmt::Debug for GpuState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GpuState(<wgpu handles>)")
    }
}

/// The animated field. Cloneable; each frame gets its own copy so egui can hold
/// it inside a paint callback.
#[derive(Debug, Clone)]
pub struct Backdrop {
    state: Option<Arc<GpuState>>,
    start: Instant,
    health: f32,
}

impl Default for Backdrop {
    fn default() -> Self {
        Self::new()
    }
}

impl Backdrop {
    pub fn new() -> Self {
        Self {
            state: None,
            start: Instant::now(),
            health: 1.0,
        }
    }

    /// Link health in `0.0..=1.0`.
    pub fn with_health(mut self, health: f32) -> Self {
        self.health = health.clamp(0.0, 1.0);
        self
    }

    /// The egui shape that requests the paint.
    pub fn callback(&self, rect: Rect) -> egui::Shape {
        egui::Shape::Callback(Callback::new_paint_callback(rect, self.clone()))
    }

    fn build(device: &wgpu::Device) -> GpuState {
        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("heimdall-background"),
            source: wgpu::ShaderSource::Wgsl(SHADER.into()),
        });

        let uniform = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("heimdall-background-uniforms"),
            size: std::mem::size_of::<Uniforms>() as u64,
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        // Fragment-only: the vertex stage derives position from the vertex
        // index and reads nothing.
        let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("heimdall-background-layout"),
            entries: &[wgpu::BindGroupLayoutEntry {
                binding: 0,
                visibility: wgpu::ShaderStages::FRAGMENT,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Uniform,
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            }],
        });

        let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("heimdall-background-bind-group"),
            layout: &bind_group_layout,
            entries: &[wgpu::BindGroupEntry {
                binding: 0,
                resource: uniform.as_entire_binding(),
            }],
        });

        let layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("heimdall-background-pipeline-layout"),
            bind_group_layouts: &[&bind_group_layout],
            push_constant_ranges: &[],
        });

        let pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("heimdall-background"),
            layout: Some(&layout),
            vertex: wgpu::VertexState {
                module: &shader,
                entry_point: Some("vs_main"),
                compilation_options: wgpu::PipelineCompilationOptions::default(),
                buffers: &[],
            },
            fragment: Some(wgpu::FragmentState {
                module: &shader,
                entry_point: Some("fs_main"),
                compilation_options: wgpu::PipelineCompilationOptions::default(),
                targets: &[Some(wgpu::ColorTargetState {
                    format: wgpu::TextureFormat::Bgra8Unorm,
                    // Alpha blending lets a faint pattern sit over whatever the
                    // window manager put behind the window.
                    blend: Some(wgpu::BlendState::ALPHA_BLENDING),
                    write_mask: wgpu::ColorWrites::ALL,
                })],
            }),
            primitive: wgpu::PrimitiveState {
                topology: wgpu::PrimitiveTopology::TriangleList,
                cull_mode: None,
                ..Default::default()
            },
            depth_stencil: None,
            multisample: wgpu::MultisampleState::default(),
            multiview: None,
            cache: None,
        });

        GpuState {
            pipeline,
            bind_group,
            uniform,
        }
    }
}

impl CallbackTrait for Backdrop {
    fn prepare(
        &self,
        device: &wgpu::Device,
        queue: &wgpu::Queue,
        screen: &ScreenDescriptor,
        _encoder: &mut wgpu::CommandEncoder,
        callback_resources: &mut CallbackResources,
    ) -> Vec<wgpu::CommandBuffer> {
        if !callback_resources.contains::<Self>() {
            callback_resources.insert(self.clone());
        }

        // The state may already exist from a previous frame; if not, build it.
        let state = if let Some(existing) = callback_resources
            .get::<Self>()
            .and_then(|holder| holder.state.clone())
        {
            existing
        } else {
            let built = Arc::new(Backdrop::build(device));
            callback_resources
                .get_mut::<Self>()
                .expect("just inserted or already present")
                .state = Some(Arc::clone(&built));
            built
        };

        let ppp = screen.pixels_per_point.max(f32::EPSILON);
        let uniforms = Uniforms {
            time: self.start.elapsed().as_secs_f32(),
            health: self.health,
            resolution: [
                screen.size_in_pixels[0] as f32,
                screen.size_in_pixels[1] as f32,
            ],
            size_points: [
                screen.size_in_pixels[0] as f32 / ppp,
                screen.size_in_pixels[1] as f32 / ppp,
            ],
        };
        queue.write_buffer(&state.uniform, 0, bytemuck::bytes_of(&uniforms));

        Vec::new()
    }

    fn paint(
        &self,
        info: PaintCallbackInfo,
        render_pass: &mut wgpu::RenderPass<'static>,
        callback_resources: &CallbackResources,
    ) {
        let Some(state) = callback_resources
            .get::<Self>()
            .and_then(|b| b.state.clone())
        else {
            return;
        };

        // The callback rect is in points. Converting to a pixel viewport lets the
        // shader stay in normalised device coordinates; egui's scissor still does
        // the clipping, so this does not need to respect the clip rect itself.
        let viewport = info.viewport_in_pixels();
        render_pass.set_viewport(
            viewport.left_px as f32,
            viewport.top_px as f32,
            viewport.width_px as f32,
            viewport.height_px as f32,
            0.0,
            1.0,
        );
        render_pass.set_pipeline(&state.pipeline);
        render_pass.set_bind_group(0, &state.bind_group, &[]);
        render_pass.draw(0..FULLSCREEN_VERTEX_COUNT, 0..1);
    }
}

/// Bottom colour of the field, painted by egui so the window has something
/// behind it before the shader's first frame lands.
pub const BACKGROUND_TINT: Color32 = Color32::from_rgb(8, 11, 20);
