//! One-shot bounded capture-to-render pipeline orchestration.

use std::time::Instant;

use crate::{
    media::{
        CaptureAdapter, DecoderAdapter, DirtyRegion, EncodedFrame, EncoderAdapter, FrameError,
        PipelineMeasurement, RenderAdapter, StaticFrameSuppressor,
    },
    transport::{Transport, TransportError},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineError {
    Frame(FrameError),
    Transport(TransportError),
    MissingTransportPayload,
}

impl From<FrameError> for PipelineError {
    fn from(value: FrameError) -> Self {
        Self::Frame(value)
    }
}

impl From<TransportError> for PipelineError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineOutcome {
    Suppressed,
    Rendered(PipelineMeasurement),
}

/// Runs one bounded capture → encode → transport → decode → render cycle.
///
/// The encoded payload is opaque to this orchestrator. Codec-specific metadata
/// needed by the decoder must therefore travel inside the encoded payload.
///
/// # Errors
///
/// Returns the first capture/codec/render/transport failure, or
/// `MissingTransportPayload` when the transport does not return the frame.
pub fn run_pipeline_once<C, E, D, R, T>(
    capture: &mut C,
    encoder: &mut E,
    transport: &mut T,
    decoder: &mut D,
    renderer: &mut R,
    suppressor: &mut StaticFrameSuppressor,
) -> Result<PipelineOutcome, PipelineError>
where
    C: CaptureAdapter,
    E: EncoderAdapter,
    D: DecoderAdapter,
    R: RenderAdapter,
    T: Transport,
{
    let frame = capture.capture()?;
    if !suppressor.should_send(&frame) {
        return Ok(PipelineOutcome::Suppressed);
    }

    let started = Instant::now();
    let input_bytes = frame.data().len();
    let regions = [DirtyRegion {
        x: 0,
        y: 0,
        width: frame.width(),
        height: frame.height(),
    }];
    let encoded = encoder.encode(&frame, &regions)?;
    let output_bytes = encoded.payload.len();

    transport.send(&encoded.payload)?;
    let payload = transport
        .receive()?
        .ok_or(PipelineError::MissingTransportPayload)?;
    let received = EncodedFrame {
        payload,
        regions: Vec::new(),
    };
    let decoded = decoder.decode(&received)?;
    renderer.render(&decoded)?;

    Ok(PipelineOutcome::Rendered(PipelineMeasurement {
        elapsed: started.elapsed(),
        input_bytes,
        output_bytes,
    }))
}

#[cfg(test)]
mod tests {
    use crate::{
        media::{Frame, PixelFormat},
        transport::LoopbackTransport,
    };

    use super::*;

    struct SyntheticCapture {
        frame: Frame,
    }

    impl CaptureAdapter for SyntheticCapture {
        fn capture(&mut self) -> Result<Frame, FrameError> {
            Ok(self.frame.clone())
        }
    }

    struct RawEncoder;

    impl EncoderAdapter for RawEncoder {
        fn encode(
            &mut self,
            frame: &Frame,
            _regions: &[DirtyRegion],
        ) -> Result<EncodedFrame, FrameError> {
            let mut payload = Vec::with_capacity(12 + frame.data().len());
            payload.extend_from_slice(&frame.width().to_be_bytes());
            payload.extend_from_slice(&frame.height().to_be_bytes());
            payload.extend_from_slice(&frame.stride().to_be_bytes());
            payload.extend_from_slice(frame.data());
            Ok(EncodedFrame {
                payload,
                regions: Vec::new(),
            })
        }
    }

    struct RawDecoder;

    impl DecoderAdapter for RawDecoder {
        fn decode(&mut self, frame: &EncodedFrame) -> Result<Frame, FrameError> {
            if frame.payload.len() < 12 {
                return Err(FrameError::SizeMismatch);
            }
            let width = u32::from_be_bytes(frame.payload[0..4].try_into().expect("width"));
            let height = u32::from_be_bytes(frame.payload[4..8].try_into().expect("height"));
            let stride = u32::from_be_bytes(frame.payload[8..12].try_into().expect("stride"));
            Frame::new_bgra(width, height, stride, frame.payload[12..].to_vec())
        }
    }

    #[derive(Default)]
    struct RecordingRenderer {
        rendered: Option<Frame>,
    }

    impl RenderAdapter for RecordingRenderer {
        fn render(&mut self, frame: &Frame) -> Result<(), FrameError> {
            self.rendered = Some(frame.clone());
            Ok(())
        }
    }

    fn test_frame() -> Frame {
        Frame::new_bgra(2, 2, 8, vec![7_u8; 16]).expect("test frame")
    }

    #[test]
    fn capture_encode_transport_decode_render_round_trip_is_measured() {
        let mut capture = SyntheticCapture {
            frame: test_frame(),
        };
        let mut encoder = RawEncoder;
        let mut transport = LoopbackTransport::default();
        let mut decoder = RawDecoder;
        let mut renderer = RecordingRenderer::default();
        let mut suppressor = StaticFrameSuppressor::default();

        let outcome = run_pipeline_once(
            &mut capture,
            &mut encoder,
            &mut transport,
            &mut decoder,
            &mut renderer,
            &mut suppressor,
        )
        .expect("pipeline");

        let PipelineOutcome::Rendered(measurement) = outcome else {
            panic!("first frame must render");
        };
        assert_eq!(measurement.input_bytes, 16);
        assert_eq!(measurement.output_bytes, 28);
        let rendered = renderer.rendered.expect("rendered frame");
        assert_eq!(rendered.format(), PixelFormat::Bgra8);
        assert_eq!(rendered.data(), &[7_u8; 16]);
    }

    #[test]
    fn unchanged_second_frame_is_suppressed_before_transport() {
        let mut capture = SyntheticCapture {
            frame: test_frame(),
        };
        let mut encoder = RawEncoder;
        let mut transport = LoopbackTransport::default();
        let mut decoder = RawDecoder;
        let mut renderer = RecordingRenderer::default();
        let mut suppressor = StaticFrameSuppressor::default();

        run_pipeline_once(
            &mut capture,
            &mut encoder,
            &mut transport,
            &mut decoder,
            &mut renderer,
            &mut suppressor,
        )
        .expect("first pipeline");

        assert_eq!(
            run_pipeline_once(
                &mut capture,
                &mut encoder,
                &mut transport,
                &mut decoder,
                &mut renderer,
                &mut suppressor,
            )
            .expect("second pipeline"),
            PipelineOutcome::Suppressed
        );
    }
}
