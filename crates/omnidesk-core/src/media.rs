//! Bounded capture-to-render contracts for the first measurable desktop pipeline.

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    Bgra8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    InvalidDimensions,
    InvalidStride,
    SizeMismatch,
    FrameTooLarge,
    QueueCapacityZero,
    QueueFull,
    AdapterFailure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    width: u32,
    height: u32,
    stride: u32,
    format: PixelFormat,
    data: Vec<u8>,
}

impl Frame {
    /// Creates a bounded BGRA frame.
    ///
    /// # Errors
    ///
    /// Returns an error for zero dimensions, invalid stride, mismatched payload
    /// length, or a payload above the hard frame-size limit.
    pub fn new_bgra(
        width: u32,
        height: u32,
        stride: u32,
        data: Vec<u8>,
    ) -> Result<Self, FrameError> {
        if width == 0 || height == 0 {
            return Err(FrameError::InvalidDimensions);
        }

        let minimum_stride = width.checked_mul(4).ok_or(FrameError::FrameTooLarge)?;
        if stride < minimum_stride {
            return Err(FrameError::InvalidStride);
        }

        let expected = usize::try_from(stride)
            .ok()
            .and_then(|row| usize::try_from(height).ok().and_then(|rows| row.checked_mul(rows)))
            .ok_or(FrameError::FrameTooLarge)?;
        if expected > MAX_FRAME_BYTES {
            return Err(FrameError::FrameTooLarge);
        }
        if data.len() != expected {
            return Err(FrameError::SizeMismatch);
        }

        Ok(Self {
            width,
            height,
            stride,
            format: PixelFormat::Bgra8,
            data,
        })
    }

    #[must_use]
    pub const fn width(&self) -> u32 {
        self.width
    }

    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height
    }

    #[must_use]
    pub const fn stride(&self) -> u32 {
        self.stride
    }

    #[must_use]
    pub const fn format(&self) -> PixelFormat {
        self.format
    }

    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirtyRegion {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedFrame {
    pub payload: Vec<u8>,
    pub regions: Vec<DirtyRegion>,
}

pub trait CaptureAdapter {
    /// Captures the next desktop frame.
    ///
    /// # Errors
    ///
    /// Returns an adapter failure when capture cannot produce a valid frame.
    fn capture(&mut self) -> Result<Frame, FrameError>;
}

pub trait EncoderAdapter {
    /// Encodes a frame and its changed regions.
    ///
    /// # Errors
    ///
    /// Returns an adapter failure when encoding fails.
    fn encode(
        &mut self,
        frame: &Frame,
        regions: &[DirtyRegion],
    ) -> Result<EncodedFrame, FrameError>;
}

pub trait DecoderAdapter {
    /// Decodes one encoded frame.
    ///
    /// # Errors
    ///
    /// Returns an adapter failure when decoding fails or output is invalid.
    fn decode(&mut self, frame: &EncodedFrame) -> Result<Frame, FrameError>;
}

pub trait RenderAdapter {
    /// Renders one decoded frame.
    ///
    /// # Errors
    ///
    /// Returns an adapter failure when rendering fails.
    fn render(&mut self, frame: &Frame) -> Result<(), FrameError>;
}

#[derive(Debug)]
pub struct BoundedFrameQueue {
    capacity: usize,
    frames: VecDeque<Frame>,
}

impl BoundedFrameQueue {
    /// Creates a frame queue with a fixed non-zero capacity.
    ///
    /// # Errors
    ///
    /// Returns `FrameError::QueueCapacityZero` when capacity is zero.
    pub fn new(capacity: usize) -> Result<Self, FrameError> {
        if capacity == 0 {
            return Err(FrameError::QueueCapacityZero);
        }

        Ok(Self {
            capacity,
            frames: VecDeque::with_capacity(capacity),
        })
    }

    /// Adds a frame without allowing unbounded growth.
    ///
    /// # Errors
    ///
    /// Returns `FrameError::QueueFull` when the fixed capacity is exhausted.
    pub fn push(&mut self, frame: Frame) -> Result<(), FrameError> {
        if self.frames.len() >= self.capacity {
            return Err(FrameError::QueueFull);
        }
        self.frames.push_back(frame);
        Ok(())
    }

    pub fn pop(&mut self) -> Option<Frame> {
        self.frames.pop_front()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
}

#[derive(Debug, Default)]
pub struct StaticFrameSuppressor {
    previous: Option<Vec<u8>>,
}

impl StaticFrameSuppressor {
    pub fn should_send(&mut self, frame: &Frame) -> bool {
        if self.previous.as_deref() == Some(frame.data()) {
            return false;
        }

        self.previous = Some(frame.data().to_vec());
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipelineMeasurement {
    pub elapsed: Duration,
    pub input_bytes: usize,
    pub output_bytes: usize,
}

/// Measures one deterministic pipeline operation.
///
/// # Errors
///
/// Returns the adapter error produced by the measured operation.
pub fn measure_pipeline<F>(
    input_bytes: usize,
    operation: F,
) -> Result<PipelineMeasurement, FrameError>
where
    F: FnOnce() -> Result<usize, FrameError>,
{
    let started = Instant::now();
    let output_bytes = operation()?;
    Ok(PipelineMeasurement {
        elapsed: started.elapsed(),
        input_bytes,
        output_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(byte: u8) -> Frame {
        Frame::new_bgra(2, 2, 8, vec![byte; 16]).expect("valid frame")
    }

    #[test]
    fn frame_validation_is_bounded_and_deterministic() {
        assert_eq!(
            Frame::new_bgra(0, 2, 8, vec![0; 16]),
            Err(FrameError::InvalidDimensions)
        );
        assert_eq!(
            Frame::new_bgra(2, 2, 4, vec![0; 8]),
            Err(FrameError::InvalidStride)
        );
        assert_eq!(
            Frame::new_bgra(2, 2, 8, vec![0; 15]),
            Err(FrameError::SizeMismatch)
        );
    }

    #[test]
    fn frame_queue_cannot_grow_past_capacity() {
        let mut queue = BoundedFrameQueue::new(1).expect("queue");
        queue.push(frame(1)).expect("first frame");
        assert_eq!(queue.push(frame(2)), Err(FrameError::QueueFull));
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn identical_static_frame_is_suppressed() {
        let mut suppressor = StaticFrameSuppressor::default();
        let first = frame(7);
        let same = frame(7);
        let changed = frame(8);

        assert!(suppressor.should_send(&first));
        assert!(!suppressor.should_send(&same));
        assert!(suppressor.should_send(&changed));
    }

    #[test]
    fn benchmark_harness_records_bytes_and_elapsed_time() {
        let measurement = measure_pipeline(16, || Ok(8)).expect("measurement");
        assert_eq!(measurement.input_bytes, 16);
        assert_eq!(measurement.output_bytes, 8);
    }
}
