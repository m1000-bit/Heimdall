//! The voice panel: a microphone, a command line, and the grammar that turns
//! an utterance into an intent.
//!
//! # What the operator gets
//!
//! Two things, kept visibly apart:
//!
//! * The microphone. Real capture, real voice-activity detection. The panel
//!   reports how much speech it heard and how loud it was, so the operator can
//!   tell a working microphone from a dead one.
//! * The command. An utterance, and the intent the grammar understood from it.
//!
//! # Where the model is missing
//!
//! The acoustic model is not in this build. The microphone therefore produces
//! audio and a duration, not a transcript: the panel says so plainly rather
//! than inventing a sentence. A model backend drops in behind
//! [`heimdall_voice::Recognizer`] and feeds the same grammar.
//!
//! # What voice is not allowed to do
//!
//! Voice can ask for things. It cannot approve them.
//!
//! An utterance is ambient: a radio, a colleague, a television in another room.
//! So a spoken "approve" never applies a patch and a spoken "contain" never
//! orders a containment; both only point the operator at the button that
//! carries the authority. The approval stays with the person who can see what
//! they are approving.

use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::Duration;

use heimdall_voice::{
    AudioCapture, CaptureConfig, CommandIntent, Grammar, Transcript, VadConfig,
    VoiceActivityDetector, Wav,
};

/// How long the microphone listens for one utterance.
const LISTEN_WINDOW: Duration = Duration::from_secs(3);

/// How long the tail of silence is, so the detector closes the last segment.
///
/// Without it the segment that is still open when the recording ends is never
/// reported, and the panel would claim silence on every utterance that ran to
/// the end of the window.
const SILENCE_TAIL_MS: u32 = 400;

/// The utterances the panel offers as examples.
///
/// They cover both languages the grammar knows and the two intents that voice
/// deliberately cannot carry out, so the operator can see what the difference
/// looks like without speaking.
pub const EXAMPLES: &[(&str, &str)] = &[
    ("en", "run a scan"),
    ("en", "show me the alerts"),
    ("en", "explain the last finding"),
    ("en", "reset the baseline"),
    ("en", "approve the change"),
    ("en", "contain the process"),
    ("it", "esegui una scansione"),
    ("it", "mostrami gli alert"),
    ("it", "spiegami questo"),
];

/// What the voice panel is doing.
#[derive(Debug, Clone, PartialEq)]
pub enum VoiceState {
    /// Nothing is happening.
    Idle,
    /// The microphone is open.
    Listening,
    /// The microphone heard speech. There is no transcript because this build
    /// has no acoustic model, so the command still has to be typed.
    Heard {
        /// How much speech was detected.
        speech_ms: u32,
        /// The loudest frame, in dBFS.
        peak_db: f32,
    },
    /// The microphone was open and heard nothing above the noise floor.
    Silent,
    /// Something failed. The text says what.
    Failed(String),
}

/// What one capture produced.
#[derive(Debug, Clone, PartialEq)]
pub struct Capture {
    /// How much speech the detector found.
    pub speech_ms: u32,
    /// The loudest frame, in dBFS.
    pub peak_db: f32,
    /// The audio, kept so a model backend can transcribe it later.
    pub audio: Wav,
}

/// The voice panel's state.
#[derive(Debug)]
pub struct VoicePanel {
    state: VoiceState,
    /// The utterance being interpreted.
    utterance: String,
    /// The intent the grammar understood, and how sure it is.
    understood: Option<(CommandIntent, f32)>,
    /// The last capture, when there was one.
    capture: Option<Capture>,
    /// The thread doing the capture, and the channel it reports on.
    listener: Option<Receiver<Result<Capture, String>>>,
    /// The grammar that turns an utterance into an intent.
    grammar: Grammar,
}

impl VoicePanel {
    /// A panel that has heard nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: VoiceState::Idle,
            utterance: String::new(),
            understood: None,
            capture: None,
            listener: None,
            grammar: Grammar::new(),
        }
    }

    /// What the panel is doing.
    #[must_use]
    pub fn state(&self) -> &VoiceState {
        &self.state
    }

    /// The utterance being interpreted.
    #[must_use]
    pub fn utterance(&self) -> &str {
        &self.utterance
    }

    /// The text the operator typed, or a model transcribed.
    pub fn set_utterance(&mut self, text: &str) {
        self.utterance = text.to_string();
        // Changing the words invalidates the understanding: the old intent
        // belonged to the old sentence.
        self.understood = None;
    }

    /// The intent the grammar understood, and its confidence.
    #[must_use]
    pub fn understood(&self) -> Option<(CommandIntent, f32)> {
        self.understood
    }

    /// The last capture.
    #[must_use]
    pub fn capture(&self) -> Option<&Capture> {
        self.capture.as_ref()
    }

    /// Whether the microphone is open.
    #[must_use]
    pub fn listening(&self) -> bool {
        self.listener.is_some()
    }

    /// Interprets the utterance and returns the intent, if it understood one.
    ///
    /// The confidence is the grammar's, not a model's: it says how much of the
    /// phrase matched, which is a different question from how sure a
    /// recogniser is.
    pub fn understand(&mut self) -> Option<CommandIntent> {
        let (intent, confidence) = self.grammar.match_intent_with_confidence(&self.utterance);
        if intent == CommandIntent::Unknown {
            self.understood = None;
            return None;
        }
        self.understood = Some((intent, confidence));
        Some(intent)
    }

    /// Feeds a transcript in as if a model had produced it.
    ///
    /// This is how a recognition backend hands its words to the grammar, and
    /// how the tests exercise the path without a microphone.
    pub fn accept_transcript(&mut self, transcript: &Transcript) {
        self.set_utterance(&transcript.text);
        let _ = self.understand();
    }

    /// Opens the microphone and listens for one utterance.
    ///
    /// The capture runs on its own thread: opening a device can take seconds,
    /// and the render loop must not wait for it.
    pub fn start_listening(&mut self) {
        if self.listener.is_some() {
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("heimdall-voice".into())
            .spawn(move || {
                let _ = tx.send(capture_once());
            });
        match spawned {
            Ok(_) => {
                self.listener = Some(rx);
                self.state = VoiceState::Listening;
            }
            Err(error) => {
                self.state =
                    VoiceState::Failed(format!("cannot start the capture thread: {error}"));
            }
        }
    }

    /// Folds in whatever the capture thread has produced.
    ///
    /// Called once per frame; never blocks.
    pub fn poll(&mut self) {
        let Some(receiver) = &self.listener else {
            return;
        };
        match receiver.try_recv() {
            Ok(result) => {
                self.listener = None;
                match result {
                    Ok(capture) => {
                        let silent = capture.speech_ms == 0;
                        self.state = if silent {
                            VoiceState::Silent
                        } else {
                            VoiceState::Heard {
                                speech_ms: capture.speech_ms,
                                peak_db: capture.peak_db,
                            }
                        };
                        self.capture = Some(capture);
                    }
                    Err(reason) => self.state = VoiceState::Failed(reason),
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                // The thread died without reporting: the state is unknown, and
                // saying "failed" is better than leaving the panel on
                // "listening" for ever.
                self.listener = None;
                self.state =
                    VoiceState::Failed("the capture thread stopped without a result".into());
            }
        }
    }
}

impl Default for VoicePanel {
    fn default() -> Self {
        Self::new()
    }
}

/// Opens the microphone, records one window, and finds the speech in it.
fn capture_once() -> Result<Capture, String> {
    let capture = AudioCapture::new(CaptureConfig::default());
    capture.start().map_err(|e| e.to_string())?;
    // The window is the capture's own: the device is already running, so this
    // is a plain sleep rather than a busy wait.
    std::thread::sleep(LISTEN_WINDOW);
    let _ = capture.stop();
    let audio = capture.take();
    Ok(analyse(&audio))
}

/// Measures the speech in a recording.
///
/// The trailing silence is appended so the detector closes the segment that
/// was still open when the recording ended.
fn analyse(audio: &Wav) -> Capture {
    let mono = audio.to_mono();
    let mut detector = VoiceActivityDetector::new(VadConfig::default());
    let mut stream = mono.samples.clone();
    let tail = Wav::silence(mono.sample_rate, SILENCE_TAIL_MS);
    stream.extend_from_slice(&tail.samples);
    let segments = detector.process(&stream, mono.sample_rate);

    let mut speech_ms = 0_u32;
    let mut peak_db = f32::MIN;
    for segment in &segments {
        speech_ms = speech_ms.saturating_add(segment.duration_ms(mono.sample_rate));
        peak_db = peak_db.max(segment.peak_db);
    }
    if segments.is_empty() {
        peak_db = detector.noise_floor_db();
    }

    Capture {
        speech_ms,
        peak_db,
        audio: mono,
    }
}

/// Reads one result from a channel, waiting at most a moment.
///
/// Used by the tests, which have no render loop to poll from.
#[cfg(test)]
fn recv_capture(receiver: &Receiver<Result<Capture, String>>) -> Option<Result<Capture, String>> {
    receiver.recv_timeout(Duration::from_secs(5)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_utterance_is_not_understood() {
        let mut panel = VoicePanel::new();
        panel.set_utterance("what is the weather like in bergamo");
        assert_eq!(panel.understand(), None);
        assert!(panel.understood().is_none());
    }

    #[test]
    fn the_grammar_understands_english_and_italian() {
        let mut panel = VoicePanel::new();
        panel.set_utterance("run a scan");
        assert_eq!(panel.understand(), Some(CommandIntent::Scan));

        panel.set_utterance("esegui una scansione");
        assert_eq!(panel.understand(), Some(CommandIntent::Scan));
    }

    #[test]
    fn a_transcript_is_interpreted_the_same_way_as_typed_words() {
        let mut panel = VoicePanel::new();
        panel.accept_transcript(&Transcript {
            text: "show me the alerts".into(),
            confidence: 0.9,
            language: "en".into(),
        });
        assert_eq!(
            panel.understood().map(|(i, _)| i),
            Some(CommandIntent::ListAlerts)
        );
    }

    #[test]
    fn changing_the_words_invalidates_the_understanding() {
        let mut panel = VoicePanel::new();
        panel.set_utterance("run a scan");
        assert!(panel.understand().is_some());
        panel.set_utterance("run a scan of the network");
        assert!(panel.understood().is_none());
    }

    #[test]
    fn silence_is_reported_as_silence() {
        let quiet = Wav::silence(16_000, 500);
        let result = analyse(&quiet);
        assert_eq!(result.speech_ms, 0, "silence holds no speech");
    }

    #[test]
    fn a_loud_tone_is_reported_as_speech() {
        let sample_rate = 16_000;
        // A triangle wave: it rises for twenty samples and falls for twenty.
        // Integer arithmetic, so the test does not depend on how a float
        // rounds.
        let samples: Vec<i16> = (0..sample_rate * 2)
            .map(|i| {
                let period = i % 40;
                let level = if period < 20 {
                    period * 600
                } else {
                    (40 - period) * 600
                };
                i16::try_from(level).unwrap_or(0)
            })
            .collect();
        let result = analyse(&Wav::mono(sample_rate, samples));
        assert!(result.speech_ms > 0, "a loud tone is not silence");
    }

    #[test]
    fn the_capture_thread_reports_a_result() {
        // The microphone may not exist on a build machine: the point of the
        // test is that the thread finishes and says so, not that it hears
        // anything.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(capture_once());
        });
        let outcome = recv_capture(&rx);
        assert!(
            outcome.is_some(),
            "the capture thread must report something"
        );
    }
}
