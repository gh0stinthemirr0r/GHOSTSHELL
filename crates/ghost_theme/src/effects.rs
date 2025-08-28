use serde::{Deserialize, Serialize};

/// Visual effect definitions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualEffect {
    pub name: String,
    pub enabled: bool,
    pub intensity: f32,
    pub parameters: EffectParameters,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EffectParameters {
    Glow(GlowEffect),
    Blur(BlurEffect),
    Animation(AnimationEffect),
    Particle(ParticleEffect),
    Distortion(DistortionEffect),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlowEffect {
    pub color: String,
    pub radius: f32,
    pub intensity: f32,
    pub spread: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlurEffect {
    pub radius: f32,
    pub type_: BlurType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlurType {
    Gaussian,
    Motion,
    Radial,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnimationEffect {
    pub name: String,
    pub duration: f32,
    pub easing: String,
    pub loop_: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticleEffect {
    pub count: u32,
    pub size: f32,
    pub speed: f32,
    pub color: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistortionEffect {
    pub type_: DistortionType,
    pub intensity: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DistortionType {
    ChromaticAberration,
    ScanLines,
    Noise,
    Glitch,
}
