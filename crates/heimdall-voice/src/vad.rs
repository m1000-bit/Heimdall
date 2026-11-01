//! Voice activity detection: finding speech in a stream of audio.
//!
//! The detector answers one question -- *where did the person start talking
//! and when did they stop* -- and it answers it on a live stream, one chunk
//! at a time, without ever holding the whole recording in memory.
//!
//! ## How it decides
//!
//! The audio is cut into fixed frames. Each frame's level is measured as
//! RMS in dBFS, and a frame counts as speech when it is
//!
//! * above [`VadConfig::start_db`], the absolute level a quiet office
//!   microphone reaches for normal speech, and
//! * above the adaptive noise floor by a margin.
//!
//! The noise floor is the part that matters. A fixed threshold either fires
//! on a noisy room or misses a quiet speaker; the floor here follows the
//! room, moving up when the background gets louder and back down when it
//! gets quieter, so the same threshold works in both.
//!
//! ## What comes out
//!
//! A segment is reported when the detector has heard [`VadConfig::hangover_ms`]
//! of silence after the speech. The hangover does two things: it keeps a
//! pause inside a sentence from cutting one utterance in two, and it holds
//! the segment back until it is certain the speech has ended.
//!
//! The consequence is worth stating plainly: **a segment is delivered only
//! once the silence after it has arrived**. A caller that stops feeding
//! audio while someone is still talking leaves that segment pending. Feed a
//! short tail of silence -- [`crate::Wav::silence`] makes one -- to collect
//! it.
//!
//! ## What it is not
//!
//! This is an energy detector, not a phonetic one. It cannot tell speech
//! from a loud fan, and it has no idea what was said. It answers "was
//! somebody talking", and the recogniser downstream answers "what".

/// The level of digital silence, in dBFS.
///
/// `log10` of zero is minus infinity, which would poison every comparison
/// downstream, so the floor of the measurement is clamped here instead.
const SILENCE_DB: f32 = -100.0;

/// How far above the noise floor a frame has to sit to count as speech.
const NOISE_MARGIN_DB: f32 = 6.0;

/// How fast the noise floor follows the room.
///
/// Close to one: the floor moves slowly, so a passing loud sound does not
/// raise the bar for the rest of the session.
const NOISE_ALPHA: f32 = 0.95;

/// How the detector is tuned.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VadConfig {
    /// The analysis frame length, in milliseconds.
    ///
    /// Shorter frames react faster but measure less; 20 ms is the usual
    /// compromise and matches what the voice pipeline expects.
    pub frame_ms: u32,
    /// The absolute level, in dBFS, a frame must exceed to count as speech.
    ///
    /// This is a floor, not the whole decision: the adaptive noise floor can
    /// raise the bar in a noisy room but never lower it. Lower it for a
    /// quiet microphone, raise it for a loud one.
    pub start_db: f32,
    /// The initial estimate of the room's noise floor, in dBFS.
    ///
    /// The detector starts here and adapts from this point, so setting it
    /// close to the real room saves the first second of false triggers.
    pub noise_db: f32,
    /// Segments shorter than this are dropped as noise, not speech.
    pub min_speech_ms: u32,
    /// How long a pause can be before the speech counts as finished.
    pub hangover_ms: u32,
}

impl Default for VadConfig {
    fn default() -> Self {
        Self {
            frame_ms: 20,
            start_db: -35.0,
            noise_db: -50.0,
            min_speech_ms: 200,
            hangover_ms: 300,
        }
    }
}

/// A stretch of audio that held speech.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SpeechSegment {
    /// The index of the first sample of the segment in the stream.
    pub start_sample: usize,
    /// The index one past the last sample of the segment.
    pub end_sample: usize,
    /// The loudest frame in the segment, in dBFS.
    pub peak_db: f32,
}

impl SpeechSegment {
    /// How long the segment is, in milliseconds.
    #[must_use]
    pub fn duration_ms(&self, sample_rate: u32) -> u32 {
        if sample_rate == 0 {
            return 0;
        }
        let samples = self.end_sample.saturating_sub(self.start_sample);
        let ms =
            u64::from(u32::try_from(samples).unwrap_or(u32::MAX)) * 1000 / u64::from(sample_rate);
        u32::try_from(ms).unwrap_or(u32::MAX)
    }
}

/// A segment that is still open, waiting for the silence that ends it.
#[derive(Debug, Clone, Copy)]
struct OpenSegment {
    start: usize,
    end: usize,
    peak_db: f32,
}

/// Finds speech in a stream of audio.
///
/// The detector is a stream processor: feed it whatever arrives, in order,
/// and it reports the segments that have finished. It keeps the noise floor
/// and the open segment across calls, so a sentence that spans two chunks is
/// one segment and not two.
#[derive(Debug, Clone)]
pub struct VoiceActivityDetector {
    config: VadConfig,
    /// Samples that did not fill a whole frame yet.
    carry: Vec<i16>,
    /// How many samples have been framed; the stream position of the next
    /// frame.
    framed: usize,
    /// The adaptive noise floor, in dBFS.
    floor_db: f32,
    /// The segment currently open, if any.
    open: Option<OpenSegment>,
    /// How long the stream has been silent since the last speech frame.
    silence_ms: u32,
}

impl VoiceActivityDetector {
    /// A detector with the given tuning.
    #[must_use]
    pub fn new(config: VadConfig) -> Self {
        Self {
            floor_db: config.noise_db,
            config,
            carry: Vec::new(),
            framed: 0,
            open: None,
            silence_ms: 0,
        }
    }

    /// Feeds a chunk of audio and returns the segments that finished.
    ///
    /// The sample indices in the returned segments are positions in the whole
    /// stream, not in this chunk, so a caller can slice the original
    /// recording with them.
    ///
    /// A segment is returned only after the hangover silence has been seen;
    /// see the [module documentation](self) for what that means at the end
    /// of a stream.
    pub fn process(&mut self, samples: &[i16], sample_rate: u32) -> Vec<SpeechSegment> {
        let mut out = Vec::new();
        if sample_rate == 0 || samples.is_empty() {
            return out;
        }
        let frame_len = self.frame_len(sample_rate);
        self.carry.extend_from_slice(samples);
        let mut offset = 0;
        while self.carry.len() - offset >= frame_len {
            let db = frame_db(&self.carry[offset..offset + frame_len]);
            let start = self.framed;
            self.framed += frame_len;
            self.handle_frame(start, frame_len, db, sample_rate, &mut out);
            offset += frame_len;
        }
        if offset > 0 {
            self.carry.drain(..offset);
        }
        out
    }

    /// The current estimate of the room's noise floor, in dBFS.
    #[must_use]
    pub fn noise_floor_db(&self) -> f32 {
        self.floor_db
    }

    /// Forgets the stream: the noise floor, the open segment and the frame
    /// position all go back to their starting values.
    ///
    /// Use it when the stream restarts -- a new recording, or a new
    /// conversation -- so the segment indices of the next stream start at
    /// zero again.
    pub fn reset(&mut self) {
        self.carry.clear();
        self.framed = 0;
        self.floor_db = self.config.noise_db;
        self.open = None;
        self.silence_ms = 0;
    }

    /// How many samples a frame holds at this rate.
    fn frame_len(&self, sample_rate: u32) -> usize {
        let samples = u64::from(self.config.frame_ms) * u64::from(sample_rate) / 1000;
        usize::try_from(samples).unwrap_or(1).max(1)
    }

    /// The level a frame has to beat to count as speech.
    fn threshold_db(&self) -> f32 {
        self.config.start_db.max(self.floor_db + NOISE_MARGIN_DB)
    }

    /// The shortest segment worth reporting, in samples.
    fn min_speech_samples(&self, sample_rate: u32) -> usize {
        let samples = u64::from(self.config.min_speech_ms) * u64::from(sample_rate) / 1000;
        usize::try_from(samples).unwrap_or(usize::MAX)
    }

    /// Folds one frame into the state machine.
    fn handle_frame(
        &mut self,
        start: usize,
        frame_len: usize,
        db: f32,
        sample_rate: u32,
        out: &mut Vec<SpeechSegment>,
    ) {
        let end = start + frame_len;
        if db > self.threshold_db() {
            match &mut self.open {
                Some(segment) => {
                    segment.end = end;
                    segment.peak_db = segment.peak_db.max(db);
                }
                None => {
                    self.open = Some(OpenSegment {
                        start,
                        end,
                        peak_db: db,
                    });
                }
            }
            self.silence_ms = 0;
            return;
        }

        // Not speech, so this frame says something about the room.
        self.floor_db = NOISE_ALPHA * self.floor_db + (1.0 - NOISE_ALPHA) * db;
        if self.open.is_none() {
            return;
        }
        self.silence_ms = self.silence_ms.saturating_add(self.config.frame_ms);
        if self.silence_ms < self.config.hangover_ms {
            return;
        }
        // The silence has lasted long enough: the speech is over.
        let Some(segment) = self.open.take() else {
            return;
        };
        if segment.end - segment.start >= self.min_speech_samples(sample_rate) {
            out.push(SpeechSegment {
                start_sample: segment.start,
                end_sample: segment.end,
                peak_db: segment.peak_db,
            });
        }
    }
}

/// The RMS level of a frame, in dBFS.
fn frame_db(frame: &[i16]) -> f32 {
    let mut sum = 0.0f32;
    // The count is kept as a float as well, so that the mean needs no
    // narrowing conversion.
    let mut count = 0.0f32;
    for &sample in frame {
        let value = f32::from(sample) / 32_768.0;
        sum += value * value;
        count += 1.0;
    }
    if count <= 0.0 {
        return SILENCE_DB;
    }
    let rms = (sum / count).sqrt();
    if rms <= 0.0 {
        return SILENCE_DB;
    }
    (20.0 * rms.log10()).max(SILENCE_DB)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RATE: u32 = 16_000;
    const RATE_SAMPLES: usize = 16_000;

    /// A tone with an amplitude modulation: loud, but with the shape of
    /// speech rather than the shape of a test tone.
    fn speech_like(samples: usize) -> Vec<i16> {
        (0..samples)
            .map(|i| {
                let t = f64::from(u32::try_from(i).unwrap_or(0)) / f64::from(RATE);
                let carrier = (2.0 * std::f64::consts::PI * 440.0 * t).sin();
                let envelope = 0.6 + 0.4 * (2.0 * std::f64::consts::PI * 200.0 * t).sin();
                (carrier * envelope * 12_000.0) as i16
            })
            .collect()
    }

    /// A steady tone at a fixed level.
    fn tone(samples: usize, amplitude: f64, period: f64) -> Vec<i16> {
        (0..samples)
            .map(|i| {
                let t = f64::from(u32::try_from(i).unwrap_or(0)) / period;
                (t.sin() * amplitude) as i16
            })
            .collect()
    }

    fn silence(samples: usize) -> Vec<i16> {
        vec![0; samples]
    }

    #[test]
    fn silence_produces_no_segment() {
        let mut vad = VoiceActivityDetector::new(VadConfig::default());
        let segments = vad.process(&silence(RATE_SAMPLES * 2), RATE);
        assert!(segments.is_empty(), "silence must not produce a segment");
    }

    #[test]
    fn a_quiet_room_does_not_produce_a_segment() {
        let mut vad = VoiceActivityDetector::new(VadConfig::default());
        // A low hum, well below the speech threshold.
        let hum = tone(RATE_SAMPLES, 200.0, 40.0);
        let segments = vad.process(&hum, RATE);
        assert!(segments.is_empty(), "a hum must not produce a segment");
    }

    #[test]
    fn speech_produces_one_segment_of_a_plausible_length() {
        let mut vad = VoiceActivityDetector::new(VadConfig::default());
        let mut audio = speech_like(RATE_SAMPLES); // one second of speech
        audio.extend(silence(RATE_SAMPLES)); // and half a second of quiet
        let segments = vad.process(&audio, RATE);
        assert_eq!(segments.len(), 1, "exactly one segment");
        let segment = segments[0];
        let duration = segment.duration_ms(RATE);
        assert!(
            (800..=1_200).contains(&duration),
            "the segment should cover the speech, got {duration} ms"
        );
        assert_eq!(segment.start_sample, 0);
        assert!(
            segment.peak_db > -20.0,
            "the peak should be near the tone level"
        );
    }

    #[test]
    fn the_same_signal_in_two_chunks_is_one_segment() {
        let mut audio = speech_like(RATE_SAMPLES);
        audio.extend(silence(RATE_SAMPLES));

        let mut vad = VoiceActivityDetector::new(VadConfig::default());
        let half = audio.len() / 2;
        let (first, second) = audio.split_at(half);

        let mut segments = vad.process(first, RATE);
        segments.extend(vad.process(second, RATE));
        assert_eq!(
            segments.len(),
            1,
            "a chunk boundary must not split one utterance in two"
        );
        assert_eq!(segments[0].start_sample, 0);
        let duration = segments[0].duration_ms(RATE);
        assert!(
            (800..=1_200).contains(&duration),
            "the segment should cover the speech, got {duration} ms"
        );
    }

    #[test]
    fn a_short_click_is_not_speech() {
        let mut vad = VoiceActivityDetector::new(VadConfig::default());
        let mut audio = silence(RATE_SAMPLES);
        // 50 ms of loud noise: too short to be speech.
        audio.extend(speech_like(RATE_SAMPLES / 20));
        audio.extend(silence(RATE_SAMPLES));
        let segments = vad.process(&audio, RATE);
        assert!(
            segments.is_empty(),
            "a click shorter than min_speech_ms must be dropped"
        );
    }

    #[test]
    fn the_noise_floor_follows_the_room() {
        let mut vad = VoiceActivityDetector::new(VadConfig::default());
        let start = vad.noise_floor_db();
        // A steady hiss at about -38 dBFS: below the speech threshold, so the
        // detector treats it as the room and the floor should rise to it.
        let hiss = tone(RATE_SAMPLES, 600.0, 40.0);
        let segments = vad.process(&hiss, RATE);
        assert!(segments.is_empty(), "a hiss must not count as speech");
        assert!(
            vad.noise_floor_db() > start + 5.0,
            "the floor should have risen towards the hiss: {} -> {}",
            start,
            vad.noise_floor_db()
        );
    }

    #[test]
    fn a_reset_puts_the_detector_back_to_the_start() {
        let mut vad = VoiceActivityDetector::new(VadConfig::default());
        vad.process(&speech_like(RATE_SAMPLES), RATE);
        vad.reset();
        assert!(
            (vad.noise_floor_db() - VadConfig::default().noise_db).abs() < f32::EPSILON,
            "a reset puts the floor back where it started"
        );
        let mut audio = speech_like(RATE_SAMPLES);
        audio.extend(silence(RATE_SAMPLES));
        let segments = vad.process(&audio, RATE);
        assert_eq!(segments.len(), 1);
        assert_eq!(
            segments[0].start_sample, 0,
            "the indices must start again after a reset"
        );
    }

    #[test]
    fn a_chunk_that_does_not_fill_a_frame_is_carried_over() {
        let mut vad = VoiceActivityDetector::new(VadConfig::default());
        // A third of a frame: too short to analyse on its own.
        let odd: Vec<i16> = speech_like(100);
        assert_eq!(vad.process(&odd, RATE).len(), 0);
        let mut audio = speech_like(RATE_SAMPLES);
        audio.extend(silence(RATE_SAMPLES));
        let segments = vad.process(&audio, RATE);
        assert_eq!(segments.len(), 1);
    }

    #[test]
    fn extreme_sample_values_do_not_crash() {
        // i16::MIN is the loudest negative sample; dividing by 32768 must
        // not overflow or produce a NaN that poisons the noise floor.
        let mut vad = VoiceActivityDetector::new(VadConfig::default());
        let loud = vec![i16::MIN; RATE_SAMPLES];
        let segments = vad.process(&loud, RATE);
        assert!(
            vad.noise_floor_db().is_finite(),
            "noise floor must stay finite with extreme samples"
        );
        assert!(segments.is_empty() || segments[0].peak_db.is_finite());
    }

    #[test]
    fn empty_chunks_do_not_crash() {
        let mut vad = VoiceActivityDetector::new(VadConfig::default());
        for _ in 0..100 {
            assert_eq!(vad.process(&[], RATE).len(), 0);
        }
    }

    #[test]
    fn zero_sample_rate_is_ignored() {
        let mut vad = VoiceActivityDetector::new(VadConfig::default());
        let segments = vad.process(&speech_like(100), 0);
        assert!(segments.is_empty(), "a zero rate must produce nothing");
    }
}
