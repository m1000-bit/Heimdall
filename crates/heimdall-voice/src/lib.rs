//! # heimdall-voice
//!
//! The local voice pipeline: microphone capture, voice activity detection,
//! speech recognition and local speech synthesis, feeding natural-language
//! commands to the Core AI.
//!
//! ## What is real, and what is a seam
//!
//! The signal path is real. [`capture`] opens the microphone through the
//! platform audio API, [`vad`] finds speech in the stream, [`wav`] carries it
//! around as 16-bit PCM, and [`speak`] answers through the platform's speech
//! synthesiser.
//!
//! The acoustic model is **not** here. No speech-recognition model ships with
//! this workspace, and none can be downloaded at build time, so that step is
//! deliberately a seam: [`recognizer::Recognizer`] is a trait whose only
//! implementation today is [`recognizer::ScriptedRecognizer`], which replays a
//! fixed list of transcripts. A Whisper or Vosk backend drops in behind the
//! same trait without anything else in the pipeline changing.
//!
//! What *is* real on the recognition side is everything around the model: the
//! command grammar in [`recognizer::Grammar`] understands English and Italian
//! and turns a transcript into an intent the rest of Heimdall can act on.
//!
//! ## The pipeline
//!
//! ```text
//!   microphone ──> AudioCapture ──> VoiceActivityDetector ──> Wav
//!                                                              │
//!                                                              v
//!                        CommandIntent <── Grammar ──── Recognizer
//! ```
//!
//! ## Feature flags
//!
//! * `capture` (on by default) -- microphone capture through `cpal`. On Linux
//!   this needs `libasound2-dev` at build time. Without the feature the
//!   capture half compiles away and reports
//!   [`VoiceError::Unsupported`] instead of pretending to work.
//!
//! Everything else -- the codec, the detector, the grammar, the synthesiser
//! -- is pure Rust and needs no system library.

pub mod capture;
pub mod recognizer;
pub mod speak;
pub mod vad;
pub mod wav;

pub use capture::{AudioCapture, CaptureConfig, CaptureState};
pub use recognizer::{CommandIntent, Grammar, Recognizer, ScriptedRecognizer, Transcript};
pub use speak::{PlatformSpeaker, Speaker};
pub use vad::{SpeechSegment, VadConfig, VoiceActivityDetector};
pub use wav::Wav;

/// Everything that can go wrong in the voice pipeline.
///
/// One type for the whole crate on purpose: a caller that owns a microphone
/// and a grammar wants to handle "the machine has no input device" and "the
/// transcript did not parse" in the same place, and a pipeline that has to
/// distinguish a dozen error types is a pipeline nobody matches on.
#[derive(Debug, thiserror::Error)]
pub enum VoiceError {
    /// A file could not be read or written.
    #[error("i/o error: {0}")]
    Io(String),
    /// The bytes are not a wav file this codec can read.
    #[error("malformed wav data: {0}")]
    Wav(String),
    /// No speech backend exists on this machine.
    #[error("no speech backend is available on this system")]
    NoBackend,
    /// The capture device is not running.
    #[error("the capture device is not listening")]
    NotListening,
    /// A backend was found but failed.
    #[error("the speech backend failed: {0}")]
    Backend(String),
    /// The operation does not exist on this platform or in this build.
    #[error("unsupported on this platform: {0}")]
    Unsupported(String),
}
