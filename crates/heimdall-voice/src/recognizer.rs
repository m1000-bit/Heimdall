//! Turning a transcript into an intent.
//!
//! Two things live here, and they are different in kind.
//!
//! [`Recognizer`] is the **seam**. It is the one place where an acoustic
//! model would go: something that takes audio and produces words. No such
//! model ships with this workspace, and none can be fetched at build time,
//! so the only implementation today is [`ScriptedRecognizer`], which replays
//! a fixed list of transcripts. A Whisper or Vosk backend drops in behind
//! the same trait, and nothing else in the pipeline changes.
//!
//! [`Grammar`] is the part that is real. It knows the words an operator
//! would use to drive Heimdall, in English and in Italian, and it maps them
//! onto [`CommandIntent`] values. This is what makes the pipeline useful
//! today: with a scripted recogniser, or with any recogniser at all, "scan"
//! and "analizza" both mean *run a scan*.
//!
//! ## Matching
//!
//! Matching ignores case and punctuation, so "List Alerts!", "list alerts"
//! and "LIST   ALERTS" are the same utterance. A phrase that appears
//! anywhere in the sentence counts; a one-word answer such as "yes" only
//! counts when it stands alone, because otherwise every affirmative in a
//! sentence would approve something.
//!
//! ## What it does not do
//!
//! The grammar has no negation handling: "do not block" is read as "block".
//! It has no notion of arguments either -- "scan the network" and "scan the
//! disk" are the same intent, and the argument has to come from somewhere
//! else.

use std::sync::Mutex;

use crate::{VoiceError, wav::Wav};

/// The score a match has to reach before it counts as an intent.
const MIN_CONFIDENCE: f32 = 0.5;

/// The score for a phrase that appears, exactly, in the utterance.
const SCORE_EXACT: f32 = 1.0;

/// The score for a phrase whose words are all present but not in order.
const SCORE_ALL_WORDS: f32 = 0.85;

/// The score for a single word that only nearly appears.
const SCORE_STEM: f32 = 0.55;

/// The score for a phrase with some of its words present.
///
/// Below [`MIN_CONFIDENCE`]: half a phrase is not an intent.
const SCORE_PARTIAL: f32 = 0.45;

/// What a recogniser heard.
#[derive(Debug, Clone, PartialEq)]
pub struct Transcript {
    /// The words.
    pub text: String,
    /// How sure the recogniser is, from 0 to 1.
    pub confidence: f32,
    /// The language tag of the words, as the recogniser reported it.
    pub language: String,
}

/// Something the operator can ask Heimdall to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommandIntent {
    /// Report the current state of the defence.
    Status,
    /// Run a fresh scan.
    Scan,
    /// Show the alerts that have been raised.
    ListAlerts,
    /// Explain the last finding or decision.
    Explain,
    /// Throw away the learned baseline and start again.
    ResetBaseline,
    /// Contain the suspect host or process.
    Contain,
    /// Approve the proposed action.
    Approve,
    /// Reject the proposed action.
    Reject,
    /// Stop listening to the microphone.
    StopListening,
    /// The utterance did not mean anything the pipeline knows.
    Unknown,
}

impl CommandIntent {
    /// A short, stable name for the intent.
    ///
    /// The same shape as the intent strings the IPC layer already carries,
    /// so a voice command can be forwarded without a translation table.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Scan => "scan",
            Self::ListAlerts => "list-alerts",
            Self::Explain => "explain",
            Self::ResetBaseline => "reset-baseline",
            Self::Contain => "contain",
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::StopListening => "stop-listening",
            Self::Unknown => "unknown",
        }
    }

    /// A sentence describing what the intent asks for.
    ///
    /// Meant to be spoken back to the operator, so it reads as a request
    /// rather than as an identifier.
    #[must_use]
    pub fn describe(&self) -> &'static str {
        match self {
            Self::Status => "Report the current defence status.",
            Self::Scan => "Run a fresh scan of this host.",
            Self::ListAlerts => "List the alerts Sentinel has raised.",
            Self::Explain => "Explain the last finding.",
            Self::ResetBaseline => "Reset the learned baseline.",
            Self::Contain => "Contain the suspect process.",
            Self::Approve => "Approve the proposed action.",
            Self::Reject => "Reject the proposed action.",
            Self::StopListening => "Stop listening to the microphone.",
            Self::Unknown => "That was not a command I know.",
        }
    }
}

/// Phrases that count wherever they appear in the utterance.
///
/// The order matters: when two phrases match equally well, the first one
/// wins. The imperative verbs come first because they are what an operator
/// says when they mean to act, and a question such as "come stai" is
/// usually the tail of a longer sentence.
const PHRASES: &[(CommandIntent, &str)] = &[
    // Explain.
    (CommandIntent::Explain, "explain"),
    (CommandIntent::Explain, "explain this"),
    (CommandIntent::Explain, "explain that"),
    (CommandIntent::Explain, "spiegami"),
    (CommandIntent::Explain, "spiegami questo"),
    (CommandIntent::Explain, "spiega"),
    (CommandIntent::Explain, "cosa significa"),
    (CommandIntent::Explain, "cosa vuol dire"),
    (CommandIntent::Explain, "what does it mean"),
    (CommandIntent::Explain, "spiegazione"),
    // Scan.
    (CommandIntent::Scan, "scan"),
    (CommandIntent::Scan, "run a scan"),
    (CommandIntent::Scan, "scan the system"),
    (CommandIntent::Scan, "scan the network"),
    (CommandIntent::Scan, "analizza"),
    (CommandIntent::Scan, "analizza il sistema"),
    (CommandIntent::Scan, "analisi"),
    (CommandIntent::Scan, "analyze"),
    (CommandIntent::Scan, "analyse"),
    (CommandIntent::Scan, "scansione"),
    (CommandIntent::Scan, "esegui una scansione"),
    (CommandIntent::Scan, "fai una scansione"),
    // List the alerts.
    (CommandIntent::ListAlerts, "list alerts"),
    (CommandIntent::ListAlerts, "list the alerts"),
    (CommandIntent::ListAlerts, "show alerts"),
    (CommandIntent::ListAlerts, "show the alerts"),
    (CommandIntent::ListAlerts, "show me the alerts"),
    (CommandIntent::ListAlerts, "alerts"),
    (CommandIntent::ListAlerts, "alert"),
    (CommandIntent::ListAlerts, "mostrami gli alert"),
    (CommandIntent::ListAlerts, "mostrami gli allarmi"),
    (CommandIntent::ListAlerts, "mostra gli alert"),
    (CommandIntent::ListAlerts, "elenca gli alert"),
    (CommandIntent::ListAlerts, "quali alert"),
    (CommandIntent::ListAlerts, "allarmi"),
    // Reset the baseline.
    (CommandIntent::ResetBaseline, "reset baseline"),
    (CommandIntent::ResetBaseline, "reset the baseline"),
    (CommandIntent::ResetBaseline, "reset"),
    (CommandIntent::ResetBaseline, "azzera la baseline"),
    (CommandIntent::ResetBaseline, "azzera baseline"),
    (CommandIntent::ResetBaseline, "azzera"),
    (CommandIntent::ResetBaseline, "resetta la baseline"),
    (CommandIntent::ResetBaseline, "reimposta la baseline"),
    // Contain.
    (CommandIntent::Contain, "contain"),
    (CommandIntent::Contain, "contain it"),
    (CommandIntent::Contain, "block"),
    (CommandIntent::Contain, "block it"),
    (CommandIntent::Contain, "blocca"),
    (CommandIntent::Contain, "bloccalo"),
    (CommandIntent::Contain, "isolate"),
    (CommandIntent::Contain, "isola"),
    (CommandIntent::Contain, "quarantine"),
    (CommandIntent::Contain, "quarantena"),
    (CommandIntent::Contain, "metti in quarantena"),
    (CommandIntent::Contain, "contieni"),
    // Approve.
    (CommandIntent::Approve, "approve"),
    (CommandIntent::Approve, "approve it"),
    (CommandIntent::Approve, "approva"),
    (CommandIntent::Approve, "approvalo"),
    (CommandIntent::Approve, "confirm"),
    (CommandIntent::Approve, "conferma"),
    (CommandIntent::Approve, "accept"),
    (CommandIntent::Approve, "accetta"),
    // Reject.
    (CommandIntent::Reject, "reject"),
    (CommandIntent::Reject, "reject it"),
    (CommandIntent::Reject, "rifiuta"),
    (CommandIntent::Reject, "rifiutalo"),
    (CommandIntent::Reject, "deny"),
    (CommandIntent::Reject, "nega"),
    (CommandIntent::Reject, "declina"),
    // Stop listening.
    (CommandIntent::StopListening, "stop listening"),
    (CommandIntent::StopListening, "stop"),
    (CommandIntent::StopListening, "ferma"),
    (CommandIntent::StopListening, "ferma l ascolto"),
    (CommandIntent::StopListening, "ferma ascolto"),
    (CommandIntent::StopListening, "smetti di ascoltare"),
    (CommandIntent::StopListening, "non ascoltare"),
    (CommandIntent::StopListening, "disattiva l ascolto"),
    (CommandIntent::StopListening, "disattiva il microfono"),
    (CommandIntent::StopListening, "basta"),
    (CommandIntent::StopListening, "mute"),
    // Status.
    (CommandIntent::Status, "status"),
    (CommandIntent::Status, "system status"),
    (CommandIntent::Status, "status report"),
    (CommandIntent::Status, "come stai"),
    (CommandIntent::Status, "come sta"),
    (CommandIntent::Status, "stato"),
    (CommandIntent::Status, "stato di sicurezza"),
    (CommandIntent::Status, "situazione"),
    (CommandIntent::Status, "how are you"),
    (CommandIntent::Status, "how is it going"),
];

/// One-word answers that only count when they are the whole utterance.
///
/// "Yes" is an approval, but "yes, and scan the network too" is not an
/// approval of anything in particular, so these are held to a higher bar.
const STANDALONE: &[(CommandIntent, &str)] = &[
    (CommandIntent::Approve, "yes"),
    (CommandIntent::Approve, "si"),
    (CommandIntent::Approve, "ok"),
    (CommandIntent::Approve, "okay"),
    (CommandIntent::Reject, "no"),
    (CommandIntent::Reject, "nope"),
    (CommandIntent::Reject, "no thanks"),
];

/// Matches transcripts to intents.
///
/// The grammar holds no state, so one instance can be shared by every
/// thread that needs to read a command.
#[derive(Debug, Clone, Copy, Default)]
pub struct Grammar;

impl Grammar {
    /// A grammar.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// The intent the transcript asks for.
    ///
    /// Anything the grammar does not recognise is
    /// [`CommandIntent::Unknown`].
    #[must_use]
    pub fn match_intent(&self, text: &str) -> CommandIntent {
        self.match_intent_with_confidence(text).0
    }

    /// The intent the transcript asks for, and how sure the grammar is.
    ///
    /// The confidence is 1.0 when a phrase was found exactly, lower when
    /// only part of it was there, and below 0.5 when nothing matched -- in
    /// which case the intent is [`CommandIntent::Unknown`].
    #[must_use]
    pub fn match_intent_with_confidence(&self, text: &str) -> (CommandIntent, f32) {
        let tokens = tokenize(text);
        if tokens.is_empty() {
            return (CommandIntent::Unknown, 0.0);
        }
        let mut best = CommandIntent::Unknown;
        let mut best_score = 0.0f32;
        for (intent, phrase) in PHRASES {
            let score = score_phrase(phrase, &tokens);
            if score > best_score {
                best_score = score;
                best = *intent;
            }
        }
        for (intent, phrase) in STANDALONE {
            let score = score_standalone(phrase, &tokens);
            if score > best_score {
                best_score = score;
                best = *intent;
            }
        }
        if best_score >= MIN_CONFIDENCE {
            return (best, best_score);
        }
        // Nothing matched. The confidence says how close it came, which is
        // how a caller can tell "I heard nothing" from "I heard something I
        // did not understand".
        let confidence = if best_score > 0.0 {
            (best_score * 0.5).min(MIN_CONFIDENCE - 0.05)
        } else {
            0.05
        };
        (CommandIntent::Unknown, confidence)
    }
}

/// Something that turns audio into words.
///
/// This is the seam an acoustic model plugs into. Implementations are
/// expected to be usable from more than one thread.
pub trait Recognizer: Send + Sync {
    /// The name of the backend, for logs and for the settings screen.
    fn name(&self) -> &'static str;

    /// Transcribes the audio.
    ///
    /// # Errors
    ///
    /// Fails when the backend cannot transcribe: no model, a decoding
    /// failure, or an empty recording.
    fn transcribe(&self, audio: &Wav) -> Result<Transcript, VoiceError>;
}

/// A recogniser that replays a fixed list of transcripts.
///
/// It exists so the pipeline above the acoustic model can be built, tested
/// and demonstrated without one. The audio is ignored: the scripted
/// recogniser says what it was told to say, in order, and repeats the last
/// transcript once the script runs out so a test can keep asking.
#[derive(Debug)]
pub struct ScriptedRecognizer {
    state: Mutex<ScriptState>,
}

/// The script, and how far through it the recogniser is.
#[derive(Debug)]
struct ScriptState {
    transcripts: Vec<Transcript>,
    next: usize,
}

impl ScriptedRecognizer {
    /// A recogniser that will say these transcripts, in this order.
    #[must_use]
    pub fn new(scripts: Vec<Transcript>) -> Self {
        Self {
            state: Mutex::new(ScriptState {
                transcripts: scripts,
                next: 0,
            }),
        }
    }
}

impl Recognizer for ScriptedRecognizer {
    fn name(&self) -> &'static str {
        "scripted"
    }

    fn transcribe(&self, _audio: &Wav) -> Result<Transcript, VoiceError> {
        // A poisoned lock means a previous call panicked; the script is
        // still consistent, so the poison is taken rather than propagated.
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(last) = state.transcripts.len().checked_sub(1) else {
            return Err(VoiceError::NoBackend);
        };
        let index = state.next.min(last);
        state.next = index.saturating_add(1);
        Ok(state.transcripts[index].clone())
    }
}

/// Lower-cases the utterance, drops the punctuation and splits it into words.
fn tokenize(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    for character in text.chars() {
        if character.is_alphanumeric() {
            for lowered in character.to_lowercase() {
                current.push(lowered);
            }
        } else if !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// How well a phrase matches the utterance.
fn score_phrase(phrase: &str, tokens: &[String]) -> f32 {
    let words: Vec<&str> = phrase.split(' ').collect();
    if words.len() == 1 {
        let word = words[0];
        if tokens.iter().any(|token| token == word) {
            return SCORE_EXACT;
        }
        if tokens.iter().any(|token| stem_match(word, token)) {
            return SCORE_STEM;
        }
        return 0.0;
    }
    if contains_sequence(tokens, &words) {
        return SCORE_EXACT;
    }
    let present = words
        .iter()
        .filter(|word| tokens.iter().any(|token| token == *word))
        .count();
    if present == words.len() {
        return SCORE_ALL_WORDS;
    }
    if present > 0 {
        return SCORE_PARTIAL;
    }
    0.0
}

/// How well a one-word answer matches, when it has to stand alone.
fn score_standalone(phrase: &str, tokens: &[String]) -> f32 {
    if tokens.len() == 1 && tokens[0] == phrase {
        return SCORE_EXACT;
    }
    0.0
}

/// Whether the words of the phrase appear in the utterance, in order.
fn contains_sequence(tokens: &[String], words: &[&str]) -> bool {
    if words.len() > tokens.len() {
        return false;
    }
    tokens.windows(words.len()).any(|window| {
        window
            .iter()
            .zip(words)
            .all(|(token, word)| token.as_str() == *word)
    })
}

/// Whether two words are the same word, allowing for an ending.
///
/// "alert" and "alerts", "approva" and "approvare": the same word said at
/// two speeds. Short words are left alone, because "no" and "not" are not
/// the same word.
fn stem_match(rule_word: &str, word: &str) -> bool {
    if rule_word == word {
        return true;
    }
    let (short, long) = if rule_word.len() < word.len() {
        (rule_word, word)
    } else {
        (word, rule_word)
    };
    short.len() >= 4 && long.starts_with(short)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transcript(text: &str) -> Transcript {
        Transcript {
            text: text.into(),
            confidence: 0.9,
            language: "en".into(),
        }
    }

    #[test]
    fn every_intent_is_reachable_in_english() {
        let grammar = Grammar::new();
        let cases = [
            ("status", CommandIntent::Status),
            ("scan", CommandIntent::Scan),
            ("list alerts", CommandIntent::ListAlerts),
            ("explain", CommandIntent::Explain),
            ("reset baseline", CommandIntent::ResetBaseline),
            ("contain", CommandIntent::Contain),
            ("approve", CommandIntent::Approve),
            ("reject", CommandIntent::Reject),
            ("stop listening", CommandIntent::StopListening),
        ];
        for (text, expected) in cases {
            assert_eq!(
                grammar.match_intent(text),
                expected,
                "the english phrase '{text}' must map to {expected:?}"
            );
        }
    }

    #[test]
    fn every_intent_is_reachable_in_italian() {
        let grammar = Grammar::new();
        let cases = [
            ("come stai", CommandIntent::Status),
            ("analizza", CommandIntent::Scan),
            ("mostrami gli alert", CommandIntent::ListAlerts),
            ("spiegami", CommandIntent::Explain),
            ("azzera la baseline", CommandIntent::ResetBaseline),
            ("blocca", CommandIntent::Contain),
            ("approva", CommandIntent::Approve),
            ("rifiuta", CommandIntent::Reject),
            ("ferma l'ascolto", CommandIntent::StopListening),
        ];
        for (text, expected) in cases {
            assert_eq!(
                grammar.match_intent(text),
                expected,
                "the italian phrase '{text}' must map to {expected:?}"
            );
        }
    }

    #[test]
    fn matching_ignores_case_and_punctuation() {
        let grammar = Grammar::new();
        for text in [
            "LIST ALERTS",
            "list alerts!",
            "List   Alerts.",
            "  list, alerts?  ",
            "l'iSt Alerts",
        ] {
            assert_eq!(
                grammar.match_intent(text),
                CommandIntent::ListAlerts,
                "'{text}' must still be the alert command"
            );
        }
    }

    #[test]
    fn a_phrase_inside_a_sentence_still_counts() {
        let grammar = Grammar::new();
        assert_eq!(
            grammar.match_intent("per favore, fai una scansione del sistema"),
            CommandIntent::Scan
        );
        assert_eq!(
            grammar.match_intent("heimdall, show me the alerts please"),
            CommandIntent::ListAlerts
        );
    }

    #[test]
    fn nonsense_is_unknown_and_unsure() {
        let grammar = Grammar::new();
        for text in ["asdf qwerty", "the weather is nice today", "xyzzy", "????"] {
            let (intent, confidence) = grammar.match_intent_with_confidence(text);
            assert_eq!(intent, CommandIntent::Unknown, "'{text}' is not a command");
            assert!(
                confidence < 0.5,
                "'{text}' must be reported with a low confidence, got {confidence}"
            );
        }
    }

    #[test]
    fn an_empty_utterance_is_unknown() {
        let grammar = Grammar::new();
        let (intent, confidence) = grammar.match_intent_with_confidence("   ");
        assert_eq!(intent, CommandIntent::Unknown);
        assert!(confidence <= 0.0, "an empty utterance is not a command");
    }

    #[test]
    fn an_exact_match_is_certain() {
        let grammar = Grammar::new();
        let (intent, confidence) = grammar.match_intent_with_confidence("scan");
        assert_eq!(intent, CommandIntent::Scan);
        assert!(
            (confidence - 1.0).abs() < f32::EPSILON,
            "an exact match is certain"
        );
    }

    #[test]
    fn a_one_word_answer_has_to_stand_alone() {
        let grammar = Grammar::new();
        assert_eq!(grammar.match_intent("yes"), CommandIntent::Approve);
        assert_eq!(grammar.match_intent("no"), CommandIntent::Reject);
        // Inside a longer sentence it is not an answer any more.
        assert_ne!(
            grammar.match_intent("yes, scan the disk"),
            CommandIntent::Approve
        );
    }

    #[test]
    fn a_near_miss_still_matches_but_is_less_sure() {
        let grammar = Grammar::new();
        let (intent, confidence) = grammar.match_intent_with_confidence("approvare");
        assert_eq!(intent, CommandIntent::Approve);
        assert!(
            (0.5..1.0).contains(&confidence),
            "a near miss is less certain, got {confidence}"
        );
    }

    #[test]
    fn the_intents_have_labels_and_descriptions() {
        assert_eq!(CommandIntent::Status.label(), "status");
        assert_eq!(CommandIntent::ResetBaseline.label(), "reset-baseline");
        assert_eq!(CommandIntent::Unknown.label(), "unknown");
        assert_ne!(CommandIntent::Scan.describe(), "");
        assert_ne!(
            CommandIntent::Scan.describe(),
            CommandIntent::Status.describe()
        );
    }

    #[test]
    fn the_scripted_recogniser_replays_its_script_in_order() {
        let recognizer =
            ScriptedRecognizer::new(vec![transcript("status"), transcript("scan the disk")]);
        let audio = Wav::silence(16_000, 10);
        let first = recognizer
            .transcribe(&audio)
            .expect("the scripted recogniser must answer");
        let second = recognizer
            .transcribe(&audio)
            .expect("the scripted recogniser must answer");
        let third = recognizer
            .transcribe(&audio)
            .expect("the scripted recogniser must answer");
        assert_eq!(first.text, "status");
        assert_eq!(second.text, "scan the disk");
        assert_eq!(
            third.text, "scan the disk",
            "the last transcript repeats once the script runs out"
        );
        assert_eq!(recognizer.name(), "scripted");
    }

    #[test]
    fn an_empty_script_has_nothing_to_say() {
        let recognizer = ScriptedRecognizer::new(Vec::new());
        let audio = Wav::silence(16_000, 10);
        assert!(matches!(
            recognizer.transcribe(&audio),
            Err(VoiceError::NoBackend)
        ));
    }

    #[test]
    fn a_transcript_becomes_an_intent() {
        let recognizer = ScriptedRecognizer::new(vec![transcript("analizza")]);
        let grammar = Grammar::new();
        let audio = Wav::silence(16_000, 10);
        let heard = recognizer
            .transcribe(&audio)
            .expect("the scripted recogniser must answer");
        assert_eq!(grammar.match_intent(&heard.text), CommandIntent::Scan);
    }
}
