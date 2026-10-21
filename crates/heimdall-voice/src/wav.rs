//! 16-bit PCM RIFF/WAVE, in and out.
//!
//! The format is deliberately the plainest one that exists: uncompressed
//! 16-bit PCM in a `RIFF`/`WAVE` container, little endian, interleaved
//! channels. It is what every audio tool writes and reads, it has no
//! licensing or patent baggage, and it costs nothing to decode -- a wav file
//! is a header plus a byte array.
//!
//! No compression, no 24-bit, no float samples. A recogniser that wants
//! 16 kHz mono gets exactly that, and a caller that wants to look at the
//! bytes by hand can.
//!
//! ## Interleaving
//!
//! [`Wav::samples`] holds *interleaved* samples: for stereo, left, right,
//! left, right. That is the layout the wav format itself uses, so encoding
//! and decoding are a memcpy, and [`Wav::to_mono`] is the only place where
//! the channels are mixed down.

use std::path::Path;

use crate::VoiceError;

/// The size of the canonical 44-byte `RIFF`/`WAVE` header.
const HEADER_LEN: usize = 44;

/// The codec is fixed at 16-bit PCM, so every sample is two bytes.
const BYTES_PER_SAMPLE: usize = 2;

/// The number of bytes in a `fmt ` chunk body that this codec needs.
const FMT_BODY_LEN: usize = 16;

/// `WAVE_FORMAT_PCM`.
const FORMAT_PCM: u16 = 1;

/// `WAVE_FORMAT_EXTENSIBLE`, which is PCM with a format GUID attached.
const FORMAT_EXTENSIBLE: u16 = 0xFFFE;

/// A block of 16-bit PCM audio.
///
/// Samples are interleaved when there is more than one channel, so
/// `samples.len()` is a whole number of frames times the channel count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wav {
    /// Frames per second.
    pub sample_rate: u32,
    /// How many channels are interleaved in [`Wav::samples`]. One is mono.
    pub channels: u16,
    /// The interleaved samples.
    pub samples: Vec<i16>,
}

impl Wav {
    /// A mono block of audio.
    #[must_use]
    pub fn mono(sample_rate: u32, samples: Vec<i16>) -> Self {
        Self {
            sample_rate,
            channels: 1,
            samples,
        }
    }

    /// A block of digital silence.
    ///
    /// Useful as a known-good input for the detector, and as the tail that
    /// closes a speech segment: the detector only reports a segment once it
    /// has heard silence after it.
    #[must_use]
    pub fn silence(sample_rate: u32, millis: u32) -> Self {
        let count = u64::from(sample_rate) * u64::from(millis) / 1000;
        let len = usize::try_from(count).unwrap_or(usize::MAX);
        Self::mono(sample_rate, vec![0; len])
    }

    /// How long the audio lasts, in milliseconds.
    ///
    /// Rounded down: a file that is 10 ms short is not a tenth of a second
    /// long, and rounding down keeps a segment from claiming time it does
    /// not have.
    #[must_use]
    pub fn duration_ms(&self) -> u32 {
        if self.sample_rate == 0 || self.channels == 0 {
            return 0;
        }
        let frames = self.samples.len() / usize::from(self.channels);
        let ms = u64::from(u32::try_from(frames).unwrap_or(u32::MAX)) * 1000
            / u64::from(self.sample_rate);
        u32::try_from(ms).unwrap_or(u32::MAX)
    }

    /// The same audio with every channel mixed down to one.
    ///
    /// The channels are averaged. Averaging rather than picking one channel
    /// keeps a channel that has drifted out of phase from cancelling the
    /// other one into silence.
    #[must_use]
    pub fn to_mono(&self) -> Wav {
        if self.channels <= 1 {
            return self.clone();
        }
        let channels = usize::from(self.channels);
        let frames = self.samples.len() / channels;
        let mut mixed = Vec::with_capacity(frames);
        for frame in self.samples.chunks_exact(channels) {
            let sum: i64 = frame.iter().map(|&s| i64::from(s)).sum();
            mixed.push(clamp_i16(sum / i64::try_from(channels).unwrap_or(1)));
        }
        Wav {
            sample_rate: self.sample_rate,
            channels: 1,
            samples: mixed,
        }
    }

    /// The audio as a canonical 44-byte-header wav file.
    ///
    /// # Errors
    ///
    /// Fails when the block has no channels, no sample rate, or is too large
    /// for the 32-bit size fields the format uses.
    pub fn encode(&self) -> Result<Vec<u8>, VoiceError> {
        if self.channels == 0 {
            return Err(VoiceError::Wav(
                "a wav file needs at least one channel".into(),
            ));
        }
        if self.sample_rate == 0 {
            return Err(VoiceError::Wav(
                "a wav file needs a non-zero sample rate".into(),
            ));
        }
        let block_align = usize::from(self.channels) * BYTES_PER_SAMPLE;
        let data_len = self.samples.len() * BYTES_PER_SAMPLE;
        let riff_len = HEADER_LEN - 8 + data_len;
        let riff_len = u32::try_from(riff_len)
            .map_err(|_| VoiceError::Wav("the audio is too long for a wav file".into()))?;
        let byte_rate = self
            .sample_rate
            .checked_mul(u32::try_from(block_align).unwrap_or(u32::MAX))
            .ok_or_else(|| VoiceError::Wav("the sample rate does not fit a wav header".into()))?;

        let mut out = Vec::with_capacity(HEADER_LEN + data_len);
        out.extend_from_slice(b"RIFF");
        out.extend_from_slice(&riff_len.to_le_bytes());
        out.extend_from_slice(b"WAVE");
        out.extend_from_slice(b"fmt ");
        out.extend_from_slice(&u32::try_from(FMT_BODY_LEN).unwrap_or(16).to_le_bytes());
        out.extend_from_slice(&FORMAT_PCM.to_le_bytes());
        out.extend_from_slice(&self.channels.to_le_bytes());
        out.extend_from_slice(&self.sample_rate.to_le_bytes());
        out.extend_from_slice(&byte_rate.to_le_bytes());
        out.extend_from_slice(&u16::try_from(block_align).unwrap_or(u16::MAX).to_le_bytes());
        out.extend_from_slice(&16u16.to_le_bytes());
        out.extend_from_slice(b"data");
        out.extend_from_slice(
            &u32::try_from(data_len)
                .map_err(|_| VoiceError::Wav("the audio is too long for a wav file".into()))?
                .to_le_bytes(),
        );
        for sample in &self.samples {
            out.extend_from_slice(&sample.to_le_bytes());
        }
        Ok(out)
    }

    /// Reads a wav file.
    ///
    /// Only what this codec writes is accepted: 16-bit PCM, mono or
    /// multichannel, in a `RIFF`/`WAVE` container. Anything else -- a
    /// truncated buffer, a compressed file, random bytes -- is an error, not
    /// a panic.
    ///
    /// # Errors
    ///
    /// Fails with [`VoiceError::Wav`] on anything that is not a well-formed
    /// 16-bit PCM wav file.
    pub fn decode(bytes: &[u8]) -> Result<Wav, VoiceError> {
        if bytes.len() < 12 {
            return Err(VoiceError::Wav(
                "the buffer is too short to be a wav file".into(),
            ));
        }
        if &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
            return Err(VoiceError::Wav("not a RIFF/WAVE file".into()));
        }

        let mut format: Option<Format> = None;
        let mut data: Option<(usize, usize)> = None;
        let mut pos = 12usize;
        while pos + 8 <= bytes.len() {
            let id = &bytes[pos..pos + 4];
            let size = usize::try_from(u32::from_le_bytes(
                bytes[pos + 4..pos + 8]
                    .try_into()
                    .map_err(|_| VoiceError::Wav("the chunk header is truncated".into()))?,
            ))
            .map_err(|_| VoiceError::Wav("the chunk size does not fit this platform".into()))?;
            let body = pos + 8;
            let end = body
                .checked_add(size)
                .ok_or_else(|| VoiceError::Wav("the chunk size overflows".into()))?;
            if end > bytes.len() {
                return Err(VoiceError::Wav(
                    "a chunk extends past the end of the buffer".into(),
                ));
            }
            match id {
                b"fmt " => format = Some(parse_format(&bytes[body..end])?),
                b"data" => data = Some((body, size)),
                _ => {}
            }
            // Chunks are word aligned: an odd-sized chunk is followed by a pad
            // byte that is not part of it.
            pos = end + (size & 1);
        }

        let format = format.ok_or_else(|| VoiceError::Wav("the file has no fmt chunk".into()))?;
        let (offset, len) =
            data.ok_or_else(|| VoiceError::Wav("the file has no data chunk".into()))?;
        if len % BYTES_PER_SAMPLE != 0 {
            return Err(VoiceError::Wav(
                "the data chunk is not a whole number of samples".into(),
            ));
        }
        if len % usize::from(format.block_align) != 0 {
            return Err(VoiceError::Wav(
                "the data chunk is not a whole number of frames".into(),
            ));
        }
        let mut samples = Vec::with_capacity(len / BYTES_PER_SAMPLE);
        for chunk in bytes[offset..offset + len].chunks_exact(BYTES_PER_SAMPLE) {
            let raw = i16::from_le_bytes([chunk[0], chunk[1]]);
            samples.push(raw);
        }
        Ok(Wav {
            sample_rate: format.sample_rate,
            channels: format.channels,
            samples,
        })
    }

    /// Writes the audio to a file.
    ///
    /// # Errors
    ///
    /// Fails when the file cannot be written.
    pub fn write_to(&self, path: &Path) -> Result<(), VoiceError> {
        let bytes = self.encode()?;
        std::fs::write(path, bytes)
            .map_err(|e| VoiceError::Io(format!("cannot write {}: {e}", path.display())))
    }

    /// Reads audio from a file.
    ///
    /// # Errors
    ///
    /// Fails when the file cannot be read, or is not a 16-bit PCM wav file.
    pub fn read_from(path: &Path) -> Result<Wav, VoiceError> {
        let bytes = std::fs::read(path)
            .map_err(|e| VoiceError::Io(format!("cannot read {}: {e}", path.display())))?;
        Wav::decode(&bytes)
    }
}

/// What the `fmt ` chunk said.
struct Format {
    sample_rate: u32,
    channels: u16,
    block_align: u16,
}

/// Reads the `fmt ` chunk body.
fn parse_format(body: &[u8]) -> Result<Format, VoiceError> {
    if body.len() < FMT_BODY_LEN {
        return Err(VoiceError::Wav("the fmt chunk is too short".into()));
    }
    let tag = u16::from_le_bytes([body[0], body[1]]);
    let channels = u16::from_le_bytes([body[2], body[3]]);
    let sample_rate = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
    let block_align = u16::from_le_bytes([body[12], body[13]]);
    let bits = u16::from_le_bytes([body[14], body[15]]);
    if tag != FORMAT_PCM && tag != FORMAT_EXTENSIBLE {
        return Err(VoiceError::Wav(format!(
            "unsupported wav format {tag}: only 16-bit PCM is supported"
        )));
    }
    if bits != 16 {
        return Err(VoiceError::Wav(format!(
            "unsupported sample width {bits}: only 16-bit PCM is supported"
        )));
    }
    if channels == 0 {
        return Err(VoiceError::Wav("the file claims zero channels".into()));
    }
    if sample_rate == 0 {
        return Err(VoiceError::Wav("the file claims a zero sample rate".into()));
    }
    Ok(Format {
        sample_rate,
        channels,
        block_align,
    })
}

/// Fits a value into an `i16`, saturating rather than wrapping.
fn clamp_i16(value: i64) -> i16 {
    i16::try_from(value.clamp(i64::from(i16::MIN), i64::from(i16::MAX))).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RATE: u32 = 16_000;

    fn tone(samples: usize) -> Vec<i16> {
        (0..samples)
            .map(|i| {
                let t = f64::from(u32::try_from(i).unwrap_or(0)) / 8.0;
                (t.sin() * 8_000.0) as i16
            })
            .collect()
    }

    #[test]
    fn a_round_trip_preserves_the_samples_and_the_rate() {
        let original = Wav::mono(RATE, tone(4_000));
        let encoded = original.encode().expect("a wav file must encode");
        let decoded = Wav::decode(&encoded).expect("a wav file must decode");
        assert_eq!(decoded, original);
        assert_eq!(decoded.sample_rate, RATE);
        assert_eq!(decoded.channels, 1);
    }

    #[test]
    fn the_header_is_the_canonical_one() {
        let wav = Wav::mono(RATE, vec![0; 100]);
        let bytes = wav.encode().expect("a wav file must encode");
        assert_eq!(&bytes[0..4], b"RIFF");
        assert_eq!(&bytes[8..12], b"WAVE");
        assert_eq!(&bytes[12..16], b"fmt ");
        assert_eq!(&bytes[36..40], b"data");
        assert_eq!(bytes.len(), 44 + 200);
        // The declared sizes must agree with the buffer.
        let riff = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        assert_eq!(riff as usize, bytes.len() - 8);
        let data = u32::from_le_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]);
        assert_eq!(data as usize, 200);
    }

    #[test]
    fn a_stereo_file_survives_the_round_trip() {
        let original = Wav {
            sample_rate: RATE,
            channels: 2,
            samples: (0..1_000)
                .map(|i| i16::try_from(i % 100).unwrap_or(0))
                .collect(),
        };
        let decoded = Wav::decode(&original.encode().expect("a wav file must encode"))
            .expect("it must decode");
        assert_eq!(decoded, original);
        assert_eq!(decoded.channels, 2);
    }

    #[test]
    fn a_truncated_buffer_is_rejected() {
        let bytes = Wav::mono(RATE, tone(500))
            .encode()
            .expect("a wav file must encode");
        for cut in [1usize, 20, 43, 100, 500] {
            let truncated = &bytes[..bytes.len() - cut];
            assert!(
                Wav::decode(truncated).is_err(),
                "a buffer truncated by {cut} bytes must be rejected"
            );
        }
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(Wav::decode(b"").is_err());
        assert!(Wav::decode(b"not a wav file at all").is_err());
        assert!(Wav::decode(&[0u8; 64]).is_err());
        assert!(Wav::decode(&[0xFFu8; 512]).is_err());
        // A valid header with a data chunk that claims more than it has.
        let mut bytes = Wav::mono(RATE, tone(100))
            .encode()
            .expect("a wav file must encode");
        bytes[40..44].copy_from_slice(&9_999u32.to_le_bytes());
        assert!(Wav::decode(&bytes).is_err());
    }

    #[test]
    fn a_wrong_sample_width_is_rejected() {
        let mut bytes = Wav::mono(RATE, tone(100))
            .encode()
            .expect("a wav file must encode");
        // 8-bit samples in the fmt chunk.
        bytes[34..36].copy_from_slice(&8u16.to_le_bytes());
        assert!(Wav::decode(&bytes).is_err());
    }

    #[test]
    fn silence_has_the_length_it_asked_for() {
        let wav = Wav::silence(RATE, 250);
        assert_eq!(wav.samples.len(), 4_000);
        assert_eq!(wav.duration_ms(), 250);
        assert!(wav.samples.iter().all(|&s| s == 0));
    }

    #[test]
    fn the_duration_counts_frames_not_samples() {
        let wav = Wav {
            sample_rate: RATE,
            channels: 2,
            samples: vec![0; 8_000],
        };
        assert_eq!(wav.duration_ms(), 250);
    }

    #[test]
    fn mixing_to_mono_averages_the_channels() {
        let wav = Wav {
            sample_rate: RATE,
            channels: 2,
            samples: vec![1_000, 3_000, -2_000, 2_000],
        };
        let mono = wav.to_mono();
        assert_eq!(mono.channels, 1);
        assert_eq!(mono.samples, vec![2_000, 0]);
    }

    #[test]
    fn mixing_a_mono_file_to_mono_changes_nothing() {
        let wav = Wav::mono(RATE, tone(100));
        assert_eq!(wav.to_mono(), wav);
    }

    #[test]
    fn a_file_survives_the_round_trip_through_the_disk() {
        let path = std::env::temp_dir().join(format!("heimdall-wav-{}.wav", std::process::id()));
        let original = Wav::mono(RATE, tone(1_000));
        original.write_to(&path).expect("the file must be writable");
        let read = Wav::read_from(&path).expect("the file must be readable");
        let _ = std::fs::remove_file(&path);
        assert_eq!(read, original);
    }

    #[test]
    fn a_missing_file_is_an_io_error() {
        let path = std::env::temp_dir().join("heimdall-does-not-exist.wav");
        assert!(matches!(Wav::read_from(&path), Err(VoiceError::Io(_))));
    }
}
