//! Windows desktop capture adapter for the initial M2 platform path.

use win_screenshot::capture::capture_display;

use crate::media::{CaptureAdapter, Frame, FrameError};

#[derive(Debug, Default)]
pub struct WindowsDesktopCapture;

impl CaptureAdapter for WindowsDesktopCapture {
    fn capture(&mut self) -> Result<Frame, FrameError> {
        let captured = capture_display().map_err(|_| FrameError::AdapterFailure)?;
        rgba_to_bgra_frame(captured.width, captured.height, captured.pixels)
    }
}

fn rgba_to_bgra_frame(width: u32, height: u32, mut pixels: Vec<u8>) -> Result<Frame, FrameError> {
    let expected = usize::try_from(width)
        .ok()
        .and_then(|columns| columns.checked_mul(usize::try_from(height).ok()?))
        .and_then(|pixel_count| pixel_count.checked_mul(4))
        .ok_or(FrameError::FrameTooLarge)?;
    if pixels.len() != expected {
        return Err(FrameError::SizeMismatch);
    }

    for pixel in pixels.chunks_exact_mut(4) {
        pixel.swap(0, 2);
    }

    let stride = width.checked_mul(4).ok_or(FrameError::FrameTooLarge)?;
    Frame::new_bgra(width, height, stride, pixels)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rgba_capture_buffer_converts_to_bgra_frame() {
        let frame =
            rgba_to_bgra_frame(2, 1, vec![10, 20, 30, 255, 40, 50, 60, 128]).expect("frame");

        assert_eq!(frame.width(), 2);
        assert_eq!(frame.height(), 1);
        assert_eq!(frame.stride(), 8);
        assert_eq!(frame.data(), &[30, 20, 10, 255, 60, 50, 40, 128,]);
    }

    #[test]
    fn malformed_capture_buffer_is_rejected() {
        assert_eq!(
            rgba_to_bgra_frame(2, 1, vec![0_u8; 7]),
            Err(FrameError::SizeMismatch)
        );
    }
}
