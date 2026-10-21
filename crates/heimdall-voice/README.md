# heimdall-voice

The local voice pipeline: microphone capture, voice activity detection,
speech recognition and local speech synthesis, feeding natural-language
commands to the Core AI.

```text
  microphone ──> AudioCapture ──> VoiceActivityDetector ──> Wav
                                                             │
                                                             v
                       CommandIntent <── Grammar ──── Recognizer
```

## What is real, and what is a seam

The signal path is real. `capture` opens the microphone through the platform
audio API, `vad` finds speech in the stream, `wav` carries it around as
16-bit PCM, and `speak` answers through the platform's own speech
synthesiser.

The acoustic model is **not** here. No speech-recognition model ships with
this workspace, and none can be downloaded at build time, so that step is
deliberately a seam: `recognizer::Recognizer` is a trait whose only
implementation today is `recognizer::ScriptedRecognizer`, which replays a
fixed list of transcripts. A Whisper or Vosk backend drops in behind the same
trait, and nothing else in the pipeline changes.

What *is* real on the recognition side is everything around the model: the
command grammar understands English and Italian and turns a transcript into an
intent the rest of Heimdall can act on.

| Module | What it does |
|---|---|
| `wav` | 16-bit PCM `RIFF`/`WAVE` in and out, interleaved, no surprises |
| `vad` | Streaming energy detector with an adaptive noise floor |
| `capture` | Microphone capture through `cpal`, resampled to the wanted rate |
| `recognizer` | The recognition seam, and the command grammar |
| `speak` | The synthesis seam, and the platform voice backends |

## The grammar

`Grammar::match_intent` returns a `CommandIntent` and, with
`match_intent_with_confidence`, how sure it is. Matching ignores case and
punctuation, and a phrase counts wherever it appears in the sentence.

| Intent | Label | English | Italian |
|---|---|---|---|
| `Status` | `status` | status | come stai, stato |
| `Scan` | `scan` | run a scan | analizza, fai una scansione |
| `ListAlerts` | `list-alerts` | list the alerts | mostrami gli alert |
| `Explain` | `explain` | explain this | spiegami, cosa significa |
| `ResetBaseline` | `reset-baseline` | reset the baseline | azzera la baseline |
| `Contain` | `contain` | contain it | blocca, metti in quarantena |
| `Approve` | `approve` | approve it | approva |
| `Reject` | `reject` | reject it | rifiuta |
| `StopListening` | `stop-listening` | stop listening | ferma l'ascolto |

The labels are the same strings the IPC layer already carries, so a voice
command can be forwarded without a translation table.

One-word answers are held to a higher bar: "yes" approves, but "yes, and scan
the disk" is not an approval of anything in particular, so those only count
when they stand alone.

## Capture

Capture is behind the `capture` feature, which is on by default. Without it
the crate still compiles, and `AudioCapture::start` and
`AudioCapture::available_devices` report `VoiceError::Unsupported` rather
than pretending to work.

The device is owned by a background thread, because on Windows the device has
to be closed on the thread that opened it. The samples are resampled to the
rate the pipeline asked for (16 kHz by default) with a linear interpolator
whose phase is kept in a `f64`, so a long recording does not drift.

| Platform | Build requirement | Backend |
|---|---|---|
| Linux | `libasound2-dev` | ALSA |
| macOS | none | CoreAudio |
| Windows | none | WASAPI |

## Speech

`PlatformSpeaker` uses whatever voice the operating system already has:
PowerShell's `System.Speech` on Windows, `say` on macOS, `spd-say` or
`espeak` on Linux. Nothing is downloaded, nothing is built.

`Speaker::available` says whether the machine can speak at all. A machine that
cannot still runs the whole pipeline; it just answers in text.

## Known limitations

Stated plainly, because they are the things most likely to be wrong:

1. **There is no acoustic model.** The pipeline is real, the last step of it
   is a scripted recogniser. Nothing in this crate can transcribe a human
   voice yet.
2. **The detector is an energy detector, not a phonetic one.** It cannot tell
   speech from a loud fan. It answers "was somebody talking", and the
   recogniser downstream answers "what".
3. **A segment is delivered only after the silence that ends it.** The
   hangover keeps a pause inside a sentence from cutting one utterance in
   two, and it means a caller who stops feeding audio while someone is still
   talking leaves that segment pending. Feed a short tail of silence --
   `Wav::silence` makes one -- to collect it.
4. **The grammar has no negation handling.** "do not block" is read as
   "block". It has no notion of arguments either: "scan the network" and
   "scan the disk" are the same intent.
5. **The codec is 16-bit PCM only.** No 24-bit, no float, no compression. A
   file that is not 16-bit PCM is an error, not a panic.
6. **The speaker is the platform's, so its voice and its languages are the
   platform's.** A PowerShell that only has an English voice will not speak
   Italian.

## Tests

```sh
cargo test -p heimdall-voice
cargo clippy -p heimdall-voice --all-targets
```

The tests cover the parts that are easy to get quietly wrong: truncated and
garbage wav files, a segment split across two chunks, a click too short to be
speech, a noise floor that follows the room, the resampler keeping its rate
without drifting, and the whole pipeline from audio to intent.

## Licence

Apache-2.0.
