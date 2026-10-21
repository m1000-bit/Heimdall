# The voice pipeline

Heimdall listens when the operator asks it to, and understands a small
vocabulary. What it can do with what it hears is deliberately smaller than
what it can hear.

## The rule

**A spoken word is a request, never an authority.**

The operator is the one who approves a repair, and the operator is the one
who decides whether something gets contained. Voice can make that decision
easier to reach; it cannot make it. When the pipeline hears something that
would approve, reject or contain, it does not do the thing: it points the
panel that carries the decision at the operator and says so.

The reason is not a preference. A microphone hears the room. If a spoken
"approve" were enough, then anything in earshot -- a television, a colleague,
a playback of a recording -- would be able to authorise a change to the
codebase or a suspension of a process. Ambient speech is not consent, and a
system that treats it as consent has a very large blast radius.

What the grammar understands, and what each of them does:

| Intent | What voice does with it |
|---|---|
| `status` | reports the link state and the last health report |
| `scan` | runs the self-repair scan and lists the findings |
| `list-alerts` | lists the alerts recorded so far |
| `explain` | explains the first finding, with file, line and rule |
| `reset-baseline` | asks Sentinel to forget what it learned |
| `approve` | points at the approval control. **Nothing is approved.** |
| `reject` | points at the rejection control. **Nothing is rejected.** |
| `contain` | points at the containment controls. **Nothing is contained.** |
| `stop-listening` | closes the microphone |

The first five change nothing on the host and nothing in the repository.
`reset-baseline` changes Heimdall's own memory -- the daemon relearns
afterwards -- and it is a request sent over the authenticated channel, not
a change to the machine. The last three are the ones that matter, and they
are the ones that only move attention.

## The stages

```
microphone ──> capture ──> VAD ──> WAV ──> recogniser ──> grammar ──> intent
   cpal        16 kHz mono   speech?  PCM      transcript      EN/IT     request
                            20 ms frames
```

**Capture** is the platform audio API through `cpal`: 16 kHz, mono, 16-bit
PCM, resampled from whatever the device offers. The microphone is opened
only while a capture is in flight, and the handle is dropped when it ends. A
daemon that holds the microphone open for ever is a daemon that is always
listening.

**Voice activity detection** decides whether there was speech at all,
before anything tries to understand it. The detector works in 20 ms frames
against an absolute floor of -35 dBFS and an adaptive noise floor that can
raise the bar in a noisy room but never lower it; a segment shorter than
200 ms is noise. The panel listens for three seconds and closes the
segment 400 ms after the last frame above the floor, because without that
tail the last utterance is never reported and the panel would claim silence
on everything.

The VAD is deliberately conservative. A false "speech" costs the operator an
interruption; a false "silence" costs them a command they meant to give.

**Transcription is the seam.** The acoustic model is not in this build. No
speech-recognition model ships with the workspace and none can be fetched
at build time, so the step is a trait: `heimdall_voice::Recognizer`, whose
only implementation today is `ScriptedRecognizer`, which replays a fixed
list of transcripts. A Whisper or Vosk backend drops in behind that trait
without anything else in the pipeline changing.

The panel makes the same admission to the operator: it reports the speech
it heard and how loud it was, and it says that there is no transcript
because there is no model, rather than inventing a sentence.

**Grammar** maps the transcript to an intent. `Grammar` understands English
and Italian, and the match is exact on the normalised text, so a phrase
that is not one of the known ones is simply not understood rather than
guessed at. The confidence it reports is the grammar's -- how much of the
phrase matched -- which is a different question from how sure a recogniser
is, and the two are not confused.

**Intent** reaches the shell, which routes it. What happens next is the
shell's business, and the shell's rule is the one above.

## The examples

The voice panel offers the example utterances, in both languages, and runs
them through the same path a microphone would use, minus the microphone:

```
"run a scan"                 "esegui una scansione"
"show me the alerts"         "mostrami gli alert"
"explain the last finding"   "spiegami questo"
"reset the baseline"
"approve the change"
"contain the process"
```

They are not a stub: they are the same `Transcript` a recogniser produces,
carried through the same grammar, arriving at the same handler. The test
that matters is the one that says a spoken approval approves nothing, and
it is in the shell's test suite.

`VoicePanel::accept_transcript` is the seam in the shell: it takes a
`Transcript` as if a model had produced it, sets the utterance and asks the
grammar what it means. A recogniser backend feeds the same function.

## What it does not do

- It does not authenticate the speaker. There is no speaker verification
  and no claim that the voice was the operator's.
- It does not run continuously. A capture is a capture; the microphone is
  not open between them.
- It does not act on any command that would change the host or the
  codebase. It points at the control that would.
- It does not work offline with a real model, because this build does not
  ship one. The grammar recogniser is the seam, and the seam is
  documented rather than dressed up.

## Where it lives

| Piece | Location |
|---|---|
| Capture, VAD, WAV, recognition seam, speech | `crates/heimdall-voice` |
| The panel, the state, the grammar, the examples | `crates/heimdall-shell/src/voice.rs` |
| The routing of intents to the panels | `crates/heimdall-shell/src/main.rs` |
