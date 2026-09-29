#[cfg(windows)]
fn main() {
    use omnidesk_core::{
        media::{
            DecoderAdapter, DirtyRegion, EncodedFrame, EncoderAdapter, Frame, FrameError,
            RenderAdapter, StaticFrameSuppressor,
        },
        pipeline::{PipelineOutcome, run_pipeline_once},
        transport::LoopbackTransport,
        windows_capture::WindowsDesktopCapture,
    };

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
    struct MeasuringRenderer {
        width: u32,
        height: u32,
        bytes: usize,
    }

    impl RenderAdapter for MeasuringRenderer {
        fn render(&mut self, frame: &Frame) -> Result<(), FrameError> {
            self.width = frame.width();
            self.height = frame.height();
            self.bytes = frame.data().len();
            Ok(())
        }
    }

    let mut capture = WindowsDesktopCapture;
    let mut encoder = RawEncoder;
    let mut transport = LoopbackTransport::default();
    let mut decoder = RawDecoder;
    let mut renderer = MeasuringRenderer::default();
    let mut suppressor = StaticFrameSuppressor::default();

    let outcome = run_pipeline_once(
        &mut capture,
        &mut encoder,
        &mut transport,
        &mut decoder,
        &mut renderer,
        &mut suppressor,
    )
    .expect("Windows capture-to-render pipeline");

    let PipelineOutcome::Rendered(measurement) = outcome else {
        panic!("first Windows frame must render");
    };
    println!(
        "{{\"schema_version\":1,\"kind\":\"windows_capture_to_render_smoke\",\"width\":{},\"height\":{},\"rendered_bytes\":{},\"input_bytes\":{},\"output_bytes\":{},\"pipeline_elapsed_ms\":{}}}",
        renderer.width,
        renderer.height,
        renderer.bytes,
        measurement.input_bytes,
        measurement.output_bytes,
        measurement.elapsed.as_millis()
    );
}

#[cfg(not(windows))]
fn main() {
    println!(
        "{{\"schema_version\":1,\"kind\":\"windows_capture_to_render_smoke\",\"status\":\"not_windows\"}}"
    );
}
