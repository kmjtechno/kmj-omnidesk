//! Performance-critical KMJ `OmniDesk` core.
//!
//! The core is intentionally UI-agnostic. Capture, transport, media, session,
//! input, and policy boundaries will evolve behind measured interfaces.

#![forbid(unsafe_code)]

pub mod authentication;
pub mod input;
pub mod licensing;
pub mod media;
pub mod metrics;
pub mod session;
pub mod transport;

pub use omnidesk_protocol::{PRODUCT_ID, PRODUCT_SLUG, PROTOCOL_VERSION};

/// Product maturity exposed by the pre-alpha foundation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Maturity {
    PreAlpha,
}

/// Current repository maturity.
#[must_use]
pub const fn maturity() -> Maturity {
    Maturity::PreAlpha
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_identity_is_stable() {
        assert_eq!(PRODUCT_ID, "KMJ_OMNIDESK");
        assert_eq!(PRODUCT_SLUG, "kmj-omnidesk");
        assert_eq!(PROTOCOL_VERSION, 1);
        assert_eq!(maturity(), Maturity::PreAlpha);
    }
}
