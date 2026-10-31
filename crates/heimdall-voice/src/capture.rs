//! The microphone.
//!
//! Capture is the one part of the pipeline that touches the hardware, so it
//! is kept deliberately dull: open a device, read samples, hand them over.
//! Everything clever happens further down.
//!
//! ## How it is put together
//!
//! The audio device is owned by a background thread, not by the caller.
//! That matters on Windows, where the audio device is tied to the thread
//! that opened it and has to be closed on that same thread; keeping it in a
//! worker means [`AudioCapture::stop`] and the destructor can ask it to
//! close, and the close happens where it has to.
//!
//! The device hands raw samples to a callback, which converts them to mono
//! `f64` and passes them down a bounded queue. The worker resamples them
//! to the rate the pipeline asked for, converts them to 16-bit PCM, and
//! appends them to a buffer. [`AudioCapture::take`] hands that buffer over
//! and empties it.
//!
//! ## The `capture` feature
//!
//! The platform half is behind the `capture` feature, which is on by
//! default. Without it the crate still compiles, and
//! [`AudioCapture::start`] and [`AudioCapture::available_devices`] report
//! [`VoiceError::Unsupported`] rather than pretending to work.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use crate::{VoiceError, wav::Wav};

/// How the microphone should be opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureConfig {
    /// The sample rate the rest of the pipeline wants.
    ///
    /// The device usually cannot deliver exactly this, so the samples are
    /// resampled on the way in.
    pub sample_rate: u32,
    /// How many channels the device should give.
    ///
    /// Zero means "whatever the device prefers"; anything else asks for
    /// exactly that many, and a device that cannot do it is not used.
    pub channels: u16,
    /// The name of the device to open.
    ///
    /// `None` means the system default input device.
    pub device_name: Option<String>,
    /// How many frames the device should buffer at a time.
    ///
    /// The value is clamped to what the device says it supports.
    pub buffer_frames: u32,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            sample_rate: 16_000,
            channels: 1,
            device_name: None,
            buffer_frames: 1_024,
        }
    }
}

/// What the capture is doing right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureState {
    /// Not capturing.
    Stopped,
    /// Opening the device.
    Starting,
    /// Capturing.
    Listening,
    /// Closing the device.
    Stopping,
}

impl CaptureState {
    /// The code the state is kept as in an atomic.
    fn code(self) -> u8 {
        match self {
            Self::Stopped => 0,
            Self::Starting => 1,
            Self::Listening => 2,
            Self::Stopping => 3,
        }
    }

    /// The state a code stands for.
    fn from_code(code: u8) -> Self {
        match code {
            1 => Self::Starting,
            2 => Self::Listening,
            3 => Self::Stopping,
            _ => Self::Stopped,
        }
    }
}

/// A microphone.
///
/// Cheap to clone around and safe to share: the state is in an atomic, and
/// the audio itself is collected in a buffer that
/// [`AudioCapture::take`] empties.
#[derive(Debug)]
pub struct AudioCapture {
    /// How the device is opened.
    config: CaptureConfig,
    /// The samples captured but not taken yet.
    samples: Arc<Mutex<Vec<i16>>>,
    /// What the capture is doing, readable without the lock.
    state: AtomicU8,
    /// The worker that owns the device.
    inner: Mutex<Inner>,
}

/// The mutable half of the capture.
#[derive(Debug)]
struct Inner {
    /// The thread that owns the device, when there is one.
    #[cfg(feature = "capture")]
    worker: Option<backend::Worker>,
}

impl AudioCapture {
    /// A capture that will open its device as described.
    #[must_use]
    pub fn new(config: CaptureConfig) -> Self {
        Self {
            config,
            samples: Arc::new(Mutex::new(Vec::new())),
            state: AtomicU8::new(CaptureState::Stopped.code()),
            inner: Mutex::new(Inner {
                #[cfg(feature = "capture")]
                worker: None,
            }),
        }
    }

    /// How the device is opened.
    #[must_use]
    pub fn config(&self) -> &CaptureConfig {
        &self.config
    }

    /// What the capture is doing right now.
    #[must_use]
    pub fn state(&self) -> CaptureState {
        CaptureState::from_code(self.state.load(Ordering::Relaxed))
    }

    /// Whether the device is open and capturing.
    #[must_use]
    pub fn is_listening(&self) -> bool {
        self.state() == CaptureState::Listening
    }

    /// Opens the device and starts capturing.
    ///
    /// Starting a capture that is already running does nothing. Opening the
    /// device takes a moment, and [`AudioCapture::state`] says
    /// [`CaptureState::Starting`] while it happens.
    ///
    /// # Errors
    ///
    /// Fails when the device cannot be opened: there is none, it is busy,
    /// it does not support the requested format, or this build has no
    /// microphone support at all.
    pub fn start(&self) -> Result<(), VoiceError> {
        if self.is_listening() {
            return Ok(());
        }
        self.set_state(CaptureState::Starting);
        let mut inner = self.lock();
        match Self::start_backend(&mut inner, &self.config, &self.samples) {
            Ok(()) => {
                self.set_state(CaptureState::Listening);
                Ok(())
            }
            Err(error) => {
                self.set_state(CaptureState::Stopped);
                Err(error)
            }
        }
    }

    /// Closes the device.
    ///
    /// Stopping a capture that is not running does nothing. The device is
    /// closed on the thread that opened it, so this waits for that to
    /// happen.
    ///
    /// # Errors
    ///
    /// Never fails today: the device is closed by the thread that owns it,
    /// and that thread has no way to fail.
    pub fn stop(&self) -> Result<(), VoiceError> {
        self.set_state(CaptureState::Stopping);
        let mut inner = self.lock();
        Self::stop_backend(&mut inner);
        self.set_state(CaptureState::Stopped);
        Ok(())
    }

    /// The audio captured since the last call.
    ///
    /// The samples come out as a mono block at the configured rate. The
    /// buffer is emptied, so two callers never get the same audio twice.
    ///
    /// The buffer holds at most half a minute: a caller that never takes
    /// the audio loses the oldest samples rather than the machine running
    /// out of memory.
    #[must_use]
    pub fn take(&self) -> Wav {
        let samples = {
            let mut buffer = self.samples.lock().unwrap_or_else(PoisonError::into_inner);
            std::mem::take(&mut *buffer)
        };
        Wav::mono(self.config.sample_rate, samples)
    }

    /// The audio captured since the last call, if the device is running.
    ///
    /// The checked version of [`AudioCapture::take`]: it refuses to hand
    /// over audio when the microphone is not open, so a caller that wants
    /// to know whether it is really listening can ask.
    ///
    /// # Errors
    ///
    /// Fails with [`VoiceError::NotListening`] when the capture is not
    /// running.
    pub fn read(&self) -> Result<Wav, VoiceError> {
        if !self.is_listening() {
            return Err(VoiceError::NotListening);
        }
        Ok(self.take())
    }

    /// The names of the input devices on this machine.
    ///
    /// # Errors
    ///
    /// Fails when the devices cannot be listed, or when this build has no
    /// microphone support at all.
    pub fn available_devices() -> Result<Vec<String>, VoiceError> {
        backend::available_devices()
    }

    /// The lock, taking the poison rather than propagating it.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records what the capture is doing.
    fn set_state(&self, state: CaptureState) {
        self.state.store(state.code(), Ordering::Relaxed);
    }

    /// Opens the device.
    #[cfg(feature = "capture")]
    fn start_backend(
        inner: &mut Inner,
        config: &CaptureConfig,
        samples: &Arc<Mutex<Vec<i16>>>,
    ) -> Result<(), VoiceError> {
        let worker = backend::start(config, samples)?;
        inner.worker = Some(worker);
        Ok(())
    }

    /// Opens the device, in a build without microphone support.
    #[cfg(not(feature = "capture"))]
    fn start_backend(
        _inner: &mut Inner,
        _config: &CaptureConfig,
        _samples: &Arc<Mutex<Vec<i16>>>,
    ) -> Result<(), VoiceError> {
        Err(VoiceError::Unsupported(
            "this build was made without the capture feature".into(),
        ))
    }

    /// Closes the device.
    #[cfg(feature = "capture")]
    fn stop_backend(inner: &mut Inner) {
        use std::sync::atomic::Ordering;

        if let Some(worker) = inner.worker.take() {
            worker.stop.store(true, Ordering::Relaxed);
            if let Some(handle) = worker.handle {
                let _ = handle.join();
            }
        }
    }

    /// Closes the device, in a build without microphone support.
    #[cfg(not(feature = "capture"))]
    fn stop_backend(_inner: &mut Inner) {}
}

impl Drop for AudioCapture {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// The platform half of the capture.
#[cfg(feature = "capture")]
mod backend {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::thread::JoinHandle;

    use cpal::traits::{DeviceTrait, HostTrait};

    use super::{CaptureConfig, Resampler, VoiceError};

    /// How long to wait for the device to open before giving up.
    const OPEN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    /// How long the worker waits for a chunk before it checks the stop flag.
    const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);

    /// How many chunks may be in flight between the device and the worker.
    const CHUNK_QUEUE: usize = 64;

    /// How many seconds of audio the buffer holds before the oldest is
    /// dropped.
    const MAX_BUFFER_SECONDS: usize = 30;

    /// The thread that owns the audio device.
    #[derive(Debug)]
    pub(super) struct Worker {
        /// Asks the thread to stop.
        pub(super) stop: Arc<AtomicBool>,
        /// The thread itself.
        pub(super) handle: Option<JoinHandle<()>>,
    }

    /// Opens the device and starts the worker.
    pub(super) fn start(
        config: &CaptureConfig,
        samples: &Arc<Mutex<Vec<i16>>>,
    ) -> Result<Worker, VoiceError> {
        let stop = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), VoiceError>>();
        let worker_stop = Arc::clone(&stop);
        let worker_config = config.clone();
        let worker_samples = Arc::clone(samples);
        let handle = std::thread::Builder::new()
            .name("heimdall-capture".into())
            .spawn(move || {
                run(
                    &worker_config,
                    &worker_stop,
                    Some(ready_tx),
                    &worker_samples,
                );
            })
            .map_err(|error| {
                VoiceError::Backend(format!("cannot start the capture thread: {error}"))
            })?;

        match ready_rx.recv_timeout(OPEN_TIMEOUT) {
            Ok(Ok(())) => Ok(Worker {
                stop,
                handle: Some(handle),
            }),
            Ok(Err(error)) => {
                let _ = handle.join();
                Err(error)
            }
            Err(_) => {
                stop.store(true, Ordering::Relaxed);
                let _ = handle.join();
                Err(VoiceError::Backend(
                    "the capture device did not open in time".into(),
                ))
            }
        }
    }

    /// The names of the input devices on this machine.
    pub(super) fn available_devices() -> Result<Vec<String>, VoiceError> {
        let host = cpal::default_host();
        let devices = host.input_devices().map_err(|error| {
            VoiceError::Backend(format!("cannot list the input devices: {error}"))
        })?;
        let mut names = Vec::new();
        for device in devices {
            if let Ok(description) = device.description() {
                names.push(description.name().to_string());
            }
        }
        Ok(names)
    }

    /// The body of the worker thread.
    fn run(
        config: &CaptureConfig,
        stop: &AtomicBool,
        ready: Option<mpsc::Sender<Result<(), VoiceError>>>,
        samples: &Mutex<Vec<i16>>,
    ) {
        let (audio_tx, audio_rx) = mpsc::sync_channel::<Vec<f64>>(CHUNK_QUEUE);
        match open(config, &audio_tx) {
            Ok((stream, rate)) => {
                if let Some(sender) = ready {
                    let _ = sender.send(Ok(()));
                }
                let mut resampler = Resampler::new(rate, config.sample_rate);
                // The buffer is bounded: a caller that never takes the audio
                // loses the oldest samples instead of the machine running
                // out of memory.
                let cap = usize::try_from(config.sample_rate)
                    .unwrap_or(16_000)
                    .saturating_mul(MAX_BUFFER_SECONDS);
                while !stop.load(Ordering::Relaxed) {
                    match audio_rx.recv_timeout(POLL_INTERVAL) {
                        Ok(chunk) => {
                            let converted = resampler.process(&chunk);
                            if !converted.is_empty() {
                                let mut buffer =
                                    samples.lock().unwrap_or_else(PoisonError::into_inner);
                                buffer.extend_from_slice(&converted);
                                if buffer.len() > cap {
                                    let excess = buffer.len() - cap;
                                    buffer.drain(..excess);
                                }
                            }
                        }
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                }
                // The device is closed on the thread that opened it.
                drop(stream);
            }
            Err(error) => {
                if let Some(sender) = ready {
                    let _ = sender.send(Err(error));
                }
            }
        }
    }

    /// Opens the device and starts streaming into the queue.
    fn open(
        config: &CaptureConfig,
        audio_tx: &SyncSender<Vec<f64>>,
    ) -> Result<(cpal::Stream, u32), VoiceError> {
        let host = cpal::default_host();
        let device = select_device(&host, config.device_name.as_deref())?;
        let supported = pick_config(&device, config)?;
        let channels = supported.channels();
        let rate = supported.sample_rate();
        let buffer_size = match supported.buffer_size() {
            cpal::SupportedBufferSize::Range { min, max } if min <= max => {
                cpal::BufferSize::Fixed(config.buffer_frames.clamp(*min, *max))
            }
            _ => cpal::BufferSize::Default,
        };
        let stream_config = cpal::StreamConfig {
            channels,
            sample_rate: rate,
            buffer_size,
        };
        let sender = audio_tx.clone();
        let stream = device
            .build_input_stream_raw(
                &stream_config,
                supported.sample_format(),
                move |data, _info| {
                    let chunk = convert(data, channels);
                    if chunk.is_empty() {
                        return;
                    }
                    // The queue is bounded: when the worker cannot keep up,
                    // the device waits rather than the audio piling up.
                    let _ = sender.send(chunk);
                },
                |error| {
                    tracing::warn!(%error, "the capture stream reported an error");
                },
                None,
            )
            .map_err(|error| VoiceError::Backend(format!("cannot open the microphone: {error}")))?;
        Ok((stream, rate))
    }

    /// The device to use.
    fn select_device(host: &cpal::Host, wanted: Option<&str>) -> Result<cpal::Device, VoiceError> {
        match wanted {
            None => host
                .default_input_device()
                .ok_or_else(|| VoiceError::Backend("this machine has no input device".into())),
            Some(name) => {
                let devices = host.input_devices().map_err(|error| {
                    VoiceError::Backend(format!("cannot list the input devices: {error}"))
                })?;
                for device in devices {
                    if let Ok(description) = device.description() {
                        if description.name() == name {
                            return Ok(device);
                        }
                    }
                }
                Err(VoiceError::Backend(format!(
                    "there is no input device called '{name}'"
                )))
            }
        }
    }

    /// The format to open the device with.
    fn pick_config(
        device: &cpal::Device,
        config: &CaptureConfig,
    ) -> Result<cpal::SupportedStreamConfig, VoiceError> {
        let ranges = device.supported_input_configs().map_err(|error| {
            VoiceError::Backend(format!("cannot ask the device what it supports: {error}"))
        })?;
        let mut fallback: Option<cpal::SupportedStreamConfig> = None;
        for range in ranges {
            if config.channels != 0 && range.channels() != config.channels {
                continue;
            }
            let Some(supported) = range.try_with_sample_rate(config.sample_rate) else {
                continue;
            };
            // Float and 16-bit samples are the ones every backend gives.
            if matches!(
                supported.sample_format(),
                cpal::SampleFormat::F32 | cpal::SampleFormat::I16
            ) {
                return Ok(supported);
            }
            if fallback.is_none() {
                fallback = Some(supported);
            }
        }
        if let Some(supported) = fallback {
            return Ok(supported);
        }
        // No device format at the wanted rate: take the device's own
        // preference and resample down to it.
        device.default_input_config().map_err(|error| {
            VoiceError::Backend(format!(
                "cannot ask the device for its default format: {error}"
            ))
        })
    }

    /// The samples of one callback, as mono `f64` between -1 and 1.
    fn convert(data: &cpal::Data, channels: u16) -> Vec<f64> {
        let raw: Vec<f64> = match data.sample_format() {
            cpal::SampleFormat::I8 => data
                .as_slice::<i8>()
                .map(|slice| {
                    slice
                        .iter()
                        .map(|&value| f64::from(value) / 128.0)
                        .collect()
                })
                .unwrap_or_default(),
            cpal::SampleFormat::I16 => data
                .as_slice::<i16>()
                .map(|slice| {
                    slice
                        .iter()
                        .map(|&value| f64::from(value) / 32_768.0)
                        .collect()
                })
                .unwrap_or_default(),
            cpal::SampleFormat::I32 => data
                .as_slice::<i32>()
                .map(|slice| {
                    slice
                        .iter()
                        .map(|&value| f64::from(value) / 2_147_483_648.0)
                        .collect()
                })
                .unwrap_or_default(),
            cpal::SampleFormat::U8 => data
                .as_slice::<u8>()
                .map(|slice| {
                    slice
                        .iter()
                        .map(|&value| (f64::from(value) - 128.0) / 128.0)
                        .collect()
                })
                .unwrap_or_default(),
            cpal::SampleFormat::F32 => data
                .as_slice::<f32>()
                .map(|slice| slice.iter().map(|&value| f64::from(value)).collect())
                .unwrap_or_default(),
            cpal::SampleFormat::I24 => twenty_four_bit(data, true),
            cpal::SampleFormat::U24 => twenty_four_bit(data, false),
            // A format this codec does not know about: nothing to convert.
            _ => Vec::new(),
        };
        let channels = usize::from(channels).max(1);
        let divisor = f64::from(u32::try_from(channels).unwrap_or(1));
        raw.chunks_exact(channels)
            .map(|frame| frame.iter().sum::<f64>() / divisor)
            .collect()
    }

    /// The samples of one callback, when they are 24 bits wide.
    fn twenty_four_bit(data: &cpal::Data, signed: bool) -> Vec<f64> {
        let bytes = data.bytes();
        let mut out = Vec::with_capacity(bytes.len() / 3);
        for chunk in bytes.chunks_exact(3) {
            if signed {
                let sign = if chunk[2] & 0x80 == 0 { 0 } else { 0xFF };
                let value = i32::from_le_bytes([chunk[0], chunk[1], chunk[2], sign]);
                out.push(f64::from(value) / 8_388_608.0);
            } else {
                let value = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], 0]);
                out.push(f64::from(value) / 16_777_216.0);
            }
        }
        out
    }
}

/// The platform half of the capture, in a build without microphone support.
#[cfg(not(feature = "capture"))]
mod backend {
    use super::VoiceError;

    /// There are no input devices to list.
    pub(super) fn available_devices() -> Result<Vec<String>, VoiceError> {
        Err(VoiceError::Unsupported(
            "this build was made without the capture feature".into(),
        ))
    }
}

/// Turns the device's samples into the rate the pipeline asked for.
///
/// The interpolation is linear: the position of the next output sample is
/// kept in a `f64` so that a long recording does not drift, and each output
/// sample sits between the two source samples around it.
// The resampler is only used by the capture backend, but it is kept here,
// where its tests live, rather than in the backend module.
#[cfg_attr(not(feature = "capture"), allow(dead_code))]
#[derive(Debug)]
struct Resampler {
    /// How many source samples one output sample takes.
    step: f64,
    /// Where the next output sample sits, counted in source samples.
    position: f64,
    /// The previous source sample.
    previous: Option<f64>,
    /// The index of the previous source sample.
    previous_index: u32,
    /// The index of the next source sample to be read.
    index: u32,
}

#[cfg_attr(not(feature = "capture"), allow(dead_code))]
impl Resampler {
    /// A resampler from one rate to another.
    fn new(from: u32, to: u32) -> Self {
        let to = f64::from(to.max(1));
        let step = f64::from(from.max(1)) / to;
        Self {
            step,
            position: 0.0,
            previous: None,
            previous_index: 0,
            index: 0,
        }
    }

    /// The samples of one chunk, resampled and converted to 16 bits.
    fn process(&mut self, input: &[f64]) -> Vec<i16> {
        let mut out = Vec::new();
        let base = self.index;
        for (offset, &sample) in input.iter().enumerate() {
            let index = base.saturating_add(u32::try_from(offset).unwrap_or(0));
            let current = f64::from(index);
            match self.previous {
                None => {
                    // The first sample is the left edge of the first
                    // interval: an output that sits on it is that sample.
                    if self.position <= current {
                        out.push(to_i16(sample));
                        self.position += self.step;
                    }
                }
                Some(previous) => {
                    // Every output that falls between the previous sample
                    // and this one is interpolated.
                    while self.position <= current {
                        let fraction = self.position - f64::from(self.previous_index);
                        out.push(to_i16(previous + (sample - previous) * fraction));
                        self.position += self.step;
                    }
                }
            }
            self.previous = Some(sample);
            self.previous_index = index;
        }
        self.index = base.saturating_add(u32::try_from(input.len()).unwrap_or(0));
        out
    }
}

/// A normalised sample as 16-bit PCM.
#[cfg_attr(not(feature = "capture"), allow(dead_code))]
fn to_i16(value: f64) -> i16 {
    (value.clamp(-1.0, 1.0) * 32_767.0).round() as i16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_config_asks_for_a_speech_rate() {
        let config = CaptureConfig::default();
        assert_eq!(config.sample_rate, 16_000);
        assert_eq!(config.channels, 1);
        assert_eq!(config.device_name, None);
    }

    #[test]
    fn a_capture_that_never_started_is_stopped() {
        let capture = AudioCapture::new(CaptureConfig::default());
        assert_eq!(capture.state(), CaptureState::Stopped);
        assert!(!capture.is_listening());
    }

    #[test]
    fn taking_before_starting_gives_nothing() {
        let capture = AudioCapture::new(CaptureConfig::default());
        let audio = capture.take();
        assert_eq!(audio.samples.len(), 0);
        assert_eq!(audio.sample_rate, 16_000);
        assert_eq!(audio.channels, 1);
    }

    #[test]
    fn reading_before_starting_says_the_device_is_not_listening() {
        let capture = AudioCapture::new(CaptureConfig::default());
        assert!(matches!(capture.read(), Err(VoiceError::NotListening)));
    }

    #[test]
    fn stopping_a_capture_that_never_started_is_fine() {
        let capture = AudioCapture::new(CaptureConfig::default());
        assert!(capture.stop().is_ok());
        assert_eq!(capture.state(), CaptureState::Stopped);
    }

    #[test]
    fn a_device_that_does_not_exist_cannot_be_opened() {
        let config = CaptureConfig {
            device_name: Some("heimdall-no-such-microphone".into()),
            ..CaptureConfig::default()
        };
        let capture = AudioCapture::new(config);
        assert!(capture.start().is_err());
        assert_eq!(capture.state(), CaptureState::Stopped);
    }

    #[test]
    fn the_resampler_keeps_the_rate() {
        let mut resampler = Resampler::new(48_000, 16_000);
        let input: Vec<f64> = (0..480).map(|i| (f64::from(i) / 48.0).sin()).collect();
        let output = resampler.process(&input);
        assert_eq!(output.len(), 160);
    }

    #[test]
    fn the_resampler_does_not_drift() {
        // A slow ramp: if the phase drifted, the output would stop matching.
        let mut resampler = Resampler::new(44_100, 16_000);
        let input: Vec<f64> = (0..4_410).map(|i| f64::from(i) / 4_410.0).collect();
        let output = resampler.process(&input);
        assert_eq!(output.len(), 1_600);
        assert!(
            (output[0] - output[1_599]).abs() > 10,
            "the ramp has to keep going up"
        );
    }

    #[test]
    fn the_resampler_passes_a_rate_along_untouched() {
        let mut resampler = Resampler::new(16_000, 16_000);
        let input = vec![0.25_f64; 160];
        let output = resampler.process(&input);
        assert_eq!(output.len(), 160);
        assert_eq!(output[0], to_i16(0.25));
    }

    #[test]
    fn samples_are_clamped_rather_than_wrapped() {
        assert_eq!(to_i16(2.0), 32_767);
        assert_eq!(to_i16(-2.0), -32_767);
        assert_eq!(to_i16(0.0), 0);
    }
}
