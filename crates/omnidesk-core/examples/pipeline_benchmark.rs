use std::time::Instant;

use omnidesk_core::{
    media::{
        CaptureAdapter, DecoderAdapter, DirtyRegion, EncodedFrame, EncoderAdapter, Frame,
        FrameError, RenderAdapter, StaticFrameSuppressor,
    },
    pipeline::{PipelineOutcome, run_pipeline_once},
    transport::LoopbackTransport,
};

const WIDTH: u32 = 640;
const HEIGHT: u32 = 360;
const ITERATIONS: u32 = 20;

struct SyntheticCapture {
    counter: u8,
}

impl CaptureAdapter for SyntheticCapture {
    fn capture(&mut self) -> Result<Frame, FrameError> {
        self.counter = self.counter.wrapping_add(1);
        let stride = WIDTH * 4;
        let size = usize::try_from(stride * HEIGHT).expect("benchmark frame size");
        Frame::new_bgra(WIDTH, HEIGHT, stride, vec![self.counter; size])
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
struct CountingRenderer {
    frames: u32,
}

impl RenderAdapter for CountingRenderer {
    fn render(&mut self, _frame: &Frame) -> Result<(), FrameError> {
        self.frames += 1;
        Ok(())
    }
}

fn main() {
    let mut capture = SyntheticCapture { counter: 0 };
    let mut encoder = RawEncoder;
    let mut transport = LoopbackTransport::default();
    let mut decoder = RawDecoder;
    let mut renderer = CountingRenderer::default();
    let mut suppressor = StaticFrameSuppressor::default();
    let started = Instant::now();
    let mut input_bytes = 0_usize;
    let mut output_bytes = 0_usize;

    for _ in 0..ITERATIONS {
        match run_pipeline_once(
            &mut capture,
            &mut encoder,
            &mut transport,
            &mut decoder,
            &mut renderer,
            &mut suppressor,
        )
        .expect("benchmark pipeline")
        {
            PipelineOutcome::Rendered(measurement) => {
                input_bytes += measurement.input_bytes;
                output_bytes += measurement.output_bytes;
            }
            PipelineOutcome::Suppressed => panic!("benchmark frames must change"),
        }
    }

    let elapsed = started.elapsed();
    println!(
        "{{\"schema_version\":1,\"kind\":\"synthetic_loopback_reference\",\"width\":{WIDTH},\"height\":{HEIGHT},\"iterations\":{ITERATIONS},\"rendered_frames\":{},\"elapsed_ms\":{},\"input_bytes\":{input_bytes},\"output_bytes\":{output_bytes}}}",
        renderer.frames,
        elapsed.as_millis()
    );
}
