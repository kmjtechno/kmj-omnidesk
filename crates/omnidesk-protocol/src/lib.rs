//! Versioned, transport-neutral contracts for KMJ OmniDesk.
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
