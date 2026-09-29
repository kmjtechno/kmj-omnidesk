//! Versioned, transport-neutral contracts for KMJ `OmniDesk`.
//!
//! Protocol evolution must remain explicit and backwards-aware. Production
//! secrets, licensing signing keys, and machine credentials do not belong here.

#![forbid(unsafe_code)]

/// Current pre-alpha wire-contract version.
///
/// This is deliberately independent from the product release version.
pub const PROTOCOL_VERSION: u16 = 1;

/// Canonical commercial product identity governed by KMJ Main Platform.
pub const PRODUCT_ID: &str = "KMJ_OMNIDESK";

/// Canonical Main Platform product slug.
pub const PRODUCT_SLUG: &str = "kmj-omnidesk";

/// Transport-neutral remote-input payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputPayload {
    KeyDown { key_code: u16 },
    KeyUp { key_code: u16 },
    PointerMove { x: i32, y: i32 },
    PointerButton { button: u8, pressed: bool },
}

/// One ordered input event bound to the fresh authentication challenge of a session.
///
/// Binding every event to the authenticated session nonce prevents a captured event
/// from an earlier connection from being accepted after reconnect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputEvent {
    pub session_nonce: [u8; 32],
    pub sequence: u64,
    pub payload: InputPayload,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_identity_is_stable() {
        assert_eq!(PROTOCOL_VERSION, 1);
        assert_eq!(PRODUCT_ID, "KMJ_OMNIDESK");
        assert_eq!(PRODUCT_SLUG, "kmj-omnidesk");
    }
}
