//! Speaking the answer back to the operator.
//!
//! A phone call needs a voice on both ends: the operator speaks a command,
//! Heimdall answers. [`Speaker`] is the seam for the answering half, the
//! same way [`crate::recognizer::Recognizer`] is the seam for the listening
//! half.
//!
//! The only implementation here is [`PlatformSpeaker`], which uses whatever
//! text-to-speech the operating system already has: PowerShell's
//! `System.Speech` on Windows, `say` on macOS, `spd-say` or `espeak` on
//! Linux. That keeps the crate free of dependencies that would have to be
//! downloaded and built.
//!
//! Nothing here blocks: a machine with no voice at all still runs the
//! pipeline, it just answers in text. That is what [`Speaker::available`]
//! is for.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::VoiceError;

/// A way of turning text into sound.
///
/// Implementations are expected to be usable from more than one thread.
pub trait Speaker: Send + Sync {
    /// The name of the backend, for logs and for the settings screen.
    fn name(&self) -> &'static str;

    /// Whether the backend can speak right now.
    ///
    /// False means the platform has no voice program, or the program that
    /// was configured is not installed.
    fn available(&self) -> bool;

    /// Speaks the text.
    ///
    /// # Errors
    ///
    /// Fails when the text could not be spoken: no voice program, or the
    /// program refused the text.
    fn speak(&self, text: &str) -> Result<(), VoiceError>;
}

/// How the voice program is called.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Style {
    /// The text is handed to the program as its last argument.
    ///
    /// What `say`, `espeak` and `spd-say` want.
    Argument,
    /// The program is a PowerShell, and the text is spoken by a script.
    ///
    /// PowerShell takes a script rather than a sentence, and the text has
    /// to be quoted inside it.
    PowerShell,
}

/// Speaks through the voice program the operating system provides.
#[derive(Debug, Clone)]
pub struct PlatformSpeaker {
    /// The voice program.
    program: PathBuf,
    /// How the program is called.
    style: Style,
}

impl PlatformSpeaker {
    /// Finds the voice program of the current platform.
    ///
    /// # Errors
    ///
    /// Fails with [`VoiceError::NoBackend`] when the platform has no voice
    /// program installed, or none of the known ones is on the `PATH`.
    pub fn detect() -> Result<Self, VoiceError> {
        for name in candidate_programs() {
            if let Some(program) = find_program(name) {
                return Ok(Self::with_program(program));
            }
        }
        Err(VoiceError::NoBackend)
    }

    /// A speaker that uses the given program.
    ///
    /// A bare name is looked up on the `PATH`; a path is taken as it is.
    /// A program called `powershell` is spoken to through a script, any
    /// other program takes the text as an argument.
    #[must_use]
    pub fn with_program(program: impl Into<PathBuf>) -> Self {
        let requested = program.into();
        let program = if is_path(&requested) {
            requested
        } else {
            find_program(&requested.to_string_lossy()).unwrap_or(requested)
        };
        let style = if program
            .file_name()
            .is_some_and(|name| name.to_string_lossy().to_lowercase().contains("powershell"))
        {
            Style::PowerShell
        } else {
            Style::Argument
        };
        Self { program, style }
    }

    /// The voice program in use.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// The command that would be run to speak some text.
    ///
    /// Built here rather than in [`Speaker::speak`] so the exact call can
    /// be checked without running anything.
    fn command(&self, text: &str) -> Command {
        let mut command = Command::new(&self.program);
        match self.style {
            Style::Argument => {
                command.arg(text);
            }
            Style::PowerShell => {
                command
                    .arg("-NoProfile")
                    .arg("-NonInteractive")
                    .arg("-Command")
                    .arg(powershell_script(text));
            }
        }
        command
    }
}

impl Speaker for PlatformSpeaker {
    fn name(&self) -> &'static str {
        "platform"
    }

    fn available(&self) -> bool {
        self.program.is_file()
    }

    fn speak(&self, text: &str) -> Result<(), VoiceError> {
        if text.trim().is_empty() {
            // Nothing to say is not a failure.
            return Ok(());
        }
        if !self.available() {
            return Err(VoiceError::NoBackend);
        }
        let output = self.command(text).output().map_err(|error| {
            VoiceError::Backend(format!(
                "could not start the voice program '{}': {error}",
                self.program.display()
            ))
        })?;
        if !output.status.success() {
            return Err(VoiceError::Backend(format!(
                "the voice program '{}' failed with {}",
                self.program.display(),
                output.status
            )));
        }
        Ok(())
    }
}

/// The voice programs worth trying on this platform, best first.
fn candidate_programs() -> &'static [&'static str] {
    #[cfg(target_os = "windows")]
    {
        &["powershell.exe", "powershell", "pwsh.exe", "pwsh"]
    }
    #[cfg(target_os = "macos")]
    {
        &["say"]
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        &["spd-say", "espeak", "espeak-ng", "say"]
    }
}

/// Whether the program name is a path rather than a bare name.
fn is_path(program: &Path) -> bool {
    program.components().count() > 1
}

/// Looks a program up on the `PATH`.
fn find_program(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let extensions: &[&str] = if cfg!(windows) { &["exe"] } else { &[] };
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
        for extension in extensions {
            if candidate.extension().is_some() {
                continue;
            }
            let executable = candidate.with_extension(extension);
            if executable.is_file() {
                return Some(executable);
            }
        }
    }
    None
}

/// The PowerShell script that speaks the text.
fn powershell_script(text: &str) -> String {
    // A single-quoted PowerShell string ends at the next single quote, and
    // a quote inside it is written twice.
    let quoted = text.replace('\'', "''");
    format!(
        "Add-Type -AssemblyName System.Speech\n\
         $synth = New-Object System.Speech.Synthesis.SpeechSynthesizer\n\
         $synth.Speak('{quoted}')\n\
         $synth.Dispose()"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_powershell_program_is_spoken_to_with_a_script() {
        let speaker = PlatformSpeaker::with_program("powershell.exe");
        assert_eq!(speaker.style, Style::PowerShell);
    }

    #[test]
    fn any_other_program_takes_the_text_as_an_argument() {
        let speaker = PlatformSpeaker::with_program("say");
        assert_eq!(speaker.style, Style::Argument);
    }

    #[test]
    fn the_script_quotes_the_text() {
        let script = powershell_script("it's fine");
        assert!(
            script.contains("it''s fine"),
            "a single quote has to be doubled: {script}"
        );
        assert!(script.contains("System.Speech"));
    }

    #[test]
    fn a_program_that_is_not_installed_is_not_available() {
        let speaker = PlatformSpeaker::with_program("heimdall-no-such-voice-program");
        assert!(!speaker.available());
        assert!(matches!(speaker.speak("hello"), Err(VoiceError::NoBackend)));
    }

    #[test]
    fn nothing_to_say_is_not_a_failure() {
        let speaker = PlatformSpeaker::with_program("heimdall-no-such-voice-program");
        assert!(speaker.speak("   ").is_ok());
    }

    #[test]
    fn the_speaker_has_a_name() {
        let speaker = PlatformSpeaker::with_program("say");
        assert_eq!(Speaker::name(&speaker), "platform");
    }

    #[test]
    fn detection_agrees_with_availability() {
        match PlatformSpeaker::detect() {
            Ok(speaker) => assert!(
                speaker.available(),
                "a detected voice program has to be there"
            ),
            Err(error) => assert!(matches!(error, VoiceError::NoBackend)),
        }
    }
}
