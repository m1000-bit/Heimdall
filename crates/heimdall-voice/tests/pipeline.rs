//! The pipeline, end to end, through the public API only.

use heimdall_voice::{
    AudioCapture, CaptureConfig, CaptureState, CommandIntent, Grammar, PlatformSpeaker, Recognizer,
    ScriptedRecognizer, Speaker, Transcript, VadConfig, VoiceActivityDetector, VoiceError, Wav,
};

/// The sample rate the tests pretend to record at.
const RATE: u32 = 16_000;

/// A tone with the shape of speech: loud enough to pass the detector, and
/// modulated so that it does not look like a steady test tone.
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

/// A transcript the scripted recogniser will say.
fn said(text: &str) -> Transcript {
    Transcript {
        text: text.into(),
        confidence: 0.95,
        language: "en".into(),
    }
}

#[test]
fn a_command_survives_the_whole_pipeline() {
    // One second of speech, then a second of quiet: the quiet is what
    // closes the segment.
    let mut audio = speech_like(16_000);
    audio.extend(vec![0_i16; 16_000]);

    // The detector finds the speech.
    let mut detector = VoiceActivityDetector::new(VadConfig::default());
    let segments = detector.process(&audio, RATE);
    assert_eq!(segments.len(), 1, "one stretch of speech");
    let segment = segments[0];
    assert_eq!(segment.start_sample, 0);

    // The stretch is cut out of the recording.
    let speech = Wav::mono(
        RATE,
        audio[segment.start_sample..segment.end_sample].to_vec(),
    );
    assert!(speech.duration_ms() > 500, "the speech is not a blip");

    // The recogniser says what was said.
    let recognizer = ScriptedRecognizer::new(vec![said("please run a scan of the system")]);
    let transcript = recognizer
        .transcribe(&speech)
        .expect("the scripted recogniser must answer");
    assert_eq!(transcript.text, "please run a scan of the system");

    // The grammar turns it into an intent.
    let grammar = Grammar::new();
    let (intent, confidence) = grammar.match_intent_with_confidence(&transcript.text);
    assert_eq!(intent, CommandIntent::Scan);
    assert!(confidence >= 0.5, "a matched command is confident");
}

#[test]
fn a_command_survives_a_trip_through_a_wav_file() {
    let speech = Wav::mono(RATE, speech_like(8_000));
    let path = std::env::temp_dir().join(format!(
        "heimdall-voice-{}-pipeline.wav",
        std::process::id()
    ));
    speech
        .write_to(&path)
        .expect("the segment must be writable");
    let read = Wav::read_from(&path).expect("the segment must be readable");
    let _ = std::fs::remove_file(&path);

    assert_eq!(read.sample_rate, RATE);
    assert_eq!(read.samples.len(), speech.samples.len());

    let recognizer = ScriptedRecognizer::new(vec![said("mostrami gli alert")]);
    let transcript = recognizer
        .transcribe(&read)
        .expect("the scripted recogniser must answer");
    let intent = Grammar::new().match_intent(&transcript.text);
    assert_eq!(intent, CommandIntent::ListAlerts);
}

#[test]
fn the_grammar_answers_in_both_languages() {
    let grammar = Grammar::new();
    assert_eq!(grammar.match_intent("scan the disk"), CommandIntent::Scan);
    assert_eq!(
        grammar.match_intent("analizza il disco"),
        CommandIntent::Scan
    );
    assert_eq!(grammar.match_intent("status"), CommandIntent::Status);
    assert_eq!(grammar.match_intent("come stai"), CommandIntent::Status);
    assert_eq!(
        grammar.match_intent("azzera la baseline"),
        CommandIntent::ResetBaseline
    );
    assert_eq!(grammar.match_intent("bluffer"), CommandIntent::Unknown);
}

#[test]
fn the_intents_carry_the_labels_the_ipc_layer_uses() {
    assert_eq!(CommandIntent::Status.label(), "status");
    assert_eq!(CommandIntent::ListAlerts.label(), "list-alerts");
    assert_eq!(CommandIntent::ResetBaseline.label(), "reset-baseline");
    assert_eq!(CommandIntent::Unknown.label(), "unknown");
}

#[test]
fn a_capture_starts_out_stopped() {
    let capture = AudioCapture::new(CaptureConfig::default());
    assert_eq!(capture.state(), CaptureState::Stopped);
    assert!(!capture.is_listening());
    let audio = capture.take();
    assert!(audio.samples.is_empty(), "there is nothing to take yet");
    assert_eq!(audio.sample_rate, 16_000);
    assert!(capture.stop().is_ok());
}

#[test]
fn a_capture_opens_a_device_when_the_machine_has_one() {
    let capture = AudioCapture::new(CaptureConfig::default());
    if let Err(error) = capture.start() {
        // No microphone, no permission, no device: the pipeline still has to
        // work without one, so this is not a failure of the crate.
        eprintln!("skipping the hardware test: {error}");
        return;
    }
    assert_eq!(capture.state(), CaptureState::Listening);
    assert!(capture.is_listening());
    assert!(capture.stop().is_ok());
    assert_eq!(capture.state(), CaptureState::Stopped);
}

#[test]
fn the_devices_of_the_machine_can_be_listed() {
    match AudioCapture::available_devices() {
        Ok(names) => {
            for name in names {
                assert!(!name.is_empty(), "a device has a name");
            }
        }
        Err(error) => {
            assert!(
                matches!(error, VoiceError::Unsupported(_) | VoiceError::Backend(_)),
                "listing the devices fails for a reason the caller can read: {error}"
            );
        }
    }
}

#[test]
fn the_speaker_says_whether_it_can_speak() {
    match PlatformSpeaker::detect() {
        Ok(speaker) => {
            assert!(speaker.available(), "a detected voice program is there");
            assert_eq!(Speaker::name(&speaker), "platform");
        }
        Err(error) => {
            assert!(
                matches!(error, VoiceError::NoBackend),
                "a machine without a voice fails with NoBackend: {error}"
            );
        }
    }
}
