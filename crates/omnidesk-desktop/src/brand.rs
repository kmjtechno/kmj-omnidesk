use std::sync::OnceLock;

use base64::{Engine as _, engine::general_purpose::STANDARD};

/// Decoded pixels from the official KMJ TECHNO brand mark.
///
/// The source SVG is copied verbatim from the KMJ Main Platform brand assets;
/// this module never redraws or substitutes the logo.
#[derive(Debug)]
pub struct BrandImage {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

#[must_use]
pub fn official_kmj_mark() -> Option<&'static BrandImage> {
    static BRAND: OnceLock<Option<BrandImage>> = OnceLock::new();

    BRAND
        .get_or_init(|| {
            let svg = include_str!("../../../assets/brand/kmj-mark.svg");
            let (_, encoded_and_tail) = svg.split_once("base64,")?;
            let encoded = encoded_and_tail.split('"').next()?;
            let png = STANDARD.decode(encoded).ok()?;
            let image = image::load_from_memory(&png).ok()?.into_rgba8();
            let (width, height) = image.dimensions();

            Some(BrandImage {
                width,
                height,
                rgba: image.into_raw(),
            })
        })
        .as_ref()
}

/// Pixel-exact approved KMJ TECHNO header wordmark, sourced from the
/// owner-locked V5 HTML reference. Decoding happens once, offline; the native
/// app does not download brand assets or substitute an approximation.
#[must_use]
pub fn approved_v5_header_logo() -> Option<&'static BrandImage> {
    static HEADER: OnceLock<Option<BrandImage>> = OnceLock::new();
    HEADER
        .get_or_init(|| {
            let encoded = include_str!("../../../assets/brand/omnidesk-v5-approved-header.png.base64")
                .trim();
            let png = STANDARD.decode(encoded).ok()?;
            let image = image::load_from_memory(&png).ok()?.into_rgba8();
            let (width, height) = image.dimensions();
            Some(BrandImage {
                width,
                height,
                rgba: image.into_raw(),
            })
        })
        .as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_locked_v5_header_asset_is_exact_size_and_decodable() {
        let header = approved_v5_header_logo().expect("locked V5 header logo must decode");
        assert_eq!((header.width, header.height), (190, 52));
        assert_eq!(
            header.rgba.len(),
            usize::try_from(header.width).unwrap()
                .saturating_mul(usize::try_from(header.height).unwrap())
                .saturating_mul(4)
        );
        assert!(header.rgba.chunks_exact(4).any(|pixel| pixel[0] > 128));
    }

    #[test]
    fn official_brand_asset_decodes_to_expected_source_dimensions() {
        let mark = official_kmj_mark().expect("official KMJ mark must decode");
        assert_eq!((mark.width, mark.height), (64, 64));
        assert_eq!(
            mark.rgba.len(),
            usize::try_from(mark.width)
                .unwrap()
                .saturating_mul(usize::try_from(mark.height).unwrap())
                .saturating_mul(4)
        );
        assert!(mark.rgba.chunks_exact(4).any(|pixel| pixel[0] > 128));
        assert!(mark.rgba.chunks_exact(4).any(|pixel| pixel[3] > 0));
    }
}
