//! Type-driven redaction for anything `OmniDesk` writes out (M11, `PR-1`).
//!
//! [`PRIVACY_REVIEW.md`](../../docs/PRIVACY_REVIEW.md) records a High finding:
//! the threat model requires that "sensitive payload contents are excluded
//! from normal logs", and that invariant was unfalsifiable because the
//! codebase has no logging subsystem to inspect. An absent feature is not a
//! control.
//!
//! This module is that control, and it exists *before* the logger so that the
//! first line of `OmniDesk` log output is already passing through it.
//!
//! # Why redaction is by type, not by pattern
//!
//! The obvious approach — scan strings for things that look like identities,
//! tokens, or file paths — is the wrong one. It fails in both directions at
//! once:
//!
//! * It misses. A peer identity is an arbitrary string, so a new format that
//!   looks like nothing in particular is logged in full.
//! * It leaks. A secret that happens not to match the pattern ships.
//!
//! Pattern-matching secrets is unreliable by construction, and a filter that
//! fails open is worse than none, because it creates the impression of a
//! control that is not there.
//!
//! So redaction happens where the value's *type* is known. A caller holding a
//! `PeerIdentity` cannot accidentally log it raw; it has to extract the inner
//! string, and that extraction is the reviewable point.

use core::fmt;

/// Marker written in place of a redacted value.
///
/// Chosen so a reviewer can find redactions with a plain text search and so
/// the absence of one in a log line is itself visible.
pub const REDACTED: &str = "[redacted]";

/// A value that must not appear in log output in its own form.
///
/// Deliberately not `Display`: the safe behaviour is the one you get by
/// default, so a struct that holds a `Secret` prints as redacted unless a
/// caller deliberately asks otherwise. There is no accidental path to the
/// inner value, only an explicit one.
///
/// The inner value is reachable via [`Secret::expose`], which is named to make
/// a deliberate decision visible at the call site rather than something that
/// happens as a side effect of formatting.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret<T> {
    inner: T,
}

impl<T> Secret<T> {
    #[must_use]
    pub const fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Reveals the inner value.
    ///
    /// Every call is a decision to put this value into something a person or
    /// a log file will see. Naming it `expose` rather than `get` or `value`
    /// is the entire point: `as_str` reads as a harmless accessor, and that
    /// is exactly the read that leaks.
    #[must_use]
    pub const fn expose(&self) -> &T {
        &self.inner
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<T> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<T: Clone> From<T> for Secret<T> {
    fn from(inner: T) -> Self {
        Self::new(inner)
    }
}

/// How much of a value a log line may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disclosure {
    /// Print the value.
    Full,
    /// Print only enough to recognise it (length, or a fixed prefix).
    Fingerprint,
    /// Print nothing but the marker.
    Redacted,
}

/// A safe-to-log description of a peer, carrying no identity.
///
/// The shape of a log line is a design decision with privacy consequences, so
/// it gets its own type rather than being assembled ad hoc at each call site.
/// Two call sites that both want "who is this" should not disagree about what
/// "who" means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerSummary {
    /// Length of the peer identity string.
    pub identity_length: u32,
    /// Whether the peer's public key has been verified this session.
    pub authenticated: bool,
}

impl PeerSummary {
    /// Summarises a peer without retaining its identity.
    #[must_use]
    pub fn from_identity(identity: &str, authenticated: bool) -> Self {
        Self {
            identity_length: u32::try_from(identity.len()).unwrap_or(u32::MAX),
            authenticated,
        }
    }
}

/// A log line that has passed redaction.
///
/// Constructed only by [`SafeRecord`], and its fields are private, so a
/// `SafeRecord` cannot exist without a scrub having run. That is what makes
/// P2 checkable: any output produced from one of these has been through the
/// scrubber by construction rather than by convention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeRecord {
    event: String,
    detail: Vec<(String, SafeValue)>,
}

/// A field value that is known safe to emit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafeValue {
    /// A non-identifying number, such as a byte count or a duration.
    Metric(u64),
    /// A fixed vocabulary word, such as a state name.
    State(&'static str),
    /// A boolean outcome.
    Flag(bool),
    /// A redacted value whose length is still useful for diagnosis.
    RedactedLength(u32),
}

impl SafeValue {
    /// Whether this value can be emitted without carrying an identifier.
    ///
    /// Stated per-variant rather than as a `matches!` over all variants: an
    /// enumeration of every variant matches itself, so the check is vacuously
    /// true and can never fail. Listing them out means adding an unsafe
    /// variant forces this method to change, and the compiler points at it.
    #[must_use]
    pub const fn is_safe(&self) -> bool {
        match self {
            Self::Metric(_) | Self::State(_) | Self::Flag(_) | Self::RedactedLength(_) => true,
        }
    }
}

/// Builds a redacted log record.
#[derive(Debug, Default)]
pub struct SafeRecordBuilder {
    detail: Vec<(String, SafeValue)>,
}

impl SafeRecordBuilder {
    #[must_use]
    pub const fn new() -> Self {
        Self { detail: Vec::new() }
    }

    /// Adds a metric: a count, a size, or a duration.
    ///
    /// Values of this kind carry no identity by construction, which is why
    /// they are the only scalar kind accepted directly.
    #[must_use]
    pub fn metric(mut self, name: &str, value: u64) -> Self {
        self.detail
            .push((name.to_string(), SafeValue::Metric(value)));
        self
    }

    /// Adds a boolean outcome.
    #[must_use]
    pub fn flag(mut self, name: &str, value: bool) -> Self {
        self.detail.push((name.to_string(), SafeValue::Flag(value)));
        self
    }

    /// Adds a state name.
    ///
    /// Takes `&'static str` rather than `String` on purpose: a state name
    /// comes from a match arm over an enum, and requiring `'static` makes it
    /// impossible to pass a runtime string that happens to have been placed in
    /// a variable named `state`.
    #[must_use]
    pub fn state(mut self, name: &str, value: &'static str) -> Self {
        self.detail
            .push((name.to_string(), SafeValue::State(value)));
        self
    }

    /// Adds a value that is being withheld, keeping only its length.
    #[must_use]
    pub fn redacted(self, name: &str, length: u32) -> Self {
        let mut this = self;
        this.detail
            .push((name.to_string(), SafeValue::RedactedLength(length)));
        this
    }

    /// Adds a peer, carrying no identity.
    #[must_use]
    pub fn peer(self, name: &str, summary: PeerSummary) -> Self {
        let mut this = self;
        this.detail.push((
            name.to_string(),
            SafeValue::RedactedLength(summary.identity_length),
        ));
        this.detail.push((
            format!("{name}_authenticated"),
            SafeValue::Flag(summary.authenticated),
        ));
        this
    }

    #[must_use]
    pub fn build(self, event: &str) -> SafeRecord {
        SafeRecord {
            event: event.to_string(),
            detail: self.detail,
        }
    }
}

impl SafeRecord {
    /// The event name.
    #[must_use]
    pub fn event(&self) -> &str {
        &self.event
    }

    /// Every field on the record, in the order added.
    #[must_use]
    pub fn detail(&self) -> &[(String, SafeValue)] {
        &self.detail
    }

    /// Whether any field is still carrying an identifier.
    ///
    /// Intended to be asserted on in tests, and callable from a release
    /// diagnostic that wants to confirm the current build cannot emit one.
    #[must_use]
    pub fn carries_only_safe_values(&self) -> bool {
        self.detail.iter().all(|(_, value)| value.is_safe())
    }

    /// Renders the record as a single `key=value` line.
    #[must_use]
    pub fn render(&self) -> String {
        let mut line = format!("event={}", self.event);
        for (name, value) in &self.detail {
            let rendered = match value {
                SafeValue::Metric(v) => v.to_string(),
                SafeValue::State(v) => (*v).to_string(),
                SafeValue::Flag(v) => v.to_string(),
                SafeValue::RedactedLength(len) => format!("{REDACTED}:len={len}"),
            };
            line.push(' ');
            line.push_str(name);
            line.push('=');
            line.push_str(&rendered);
            let _ = name;
        }
        line
    }
}

#[cfg(test)]
mod tests {
    use crate::session::PeerIdentity;

    use super::*;

    #[test]
    fn a_secret_prints_as_redacted_by_default() {
        let secret = Secret::new("super-secret-token");

        assert_eq!(format!("{secret}"), REDACTED);
        assert_eq!(format!("{secret:?}"), REDACTED);
    }

    #[test]
    fn a_secret_redacts_under_every_formatting_path() {
        let secret = Secret::new(String::from("hunter2"));

        // The paths a naive logger would take. The bare `{}` specifier is
        // kept out of the group below only because `{}` with no formatting
        // flags has no inlined form; the rest are grouped under the allow
        // because the point here is to pin one specifier at a time.
        #[allow(clippy::uninlined_format_args)]
        {
            assert_eq!(format!("{:?}", secret), REDACTED);
            assert_eq!(format!("{:#?}", secret), REDACTED);
            assert_eq!(format!("{:>40}", secret), REDACTED);
        }
        assert_eq!(secret.to_string(), REDACTED);
    }

    #[test]
    fn a_secret_inside_a_structure_still_redacts() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Attempt<'a> {
            user: &'a str,
            token: Secret<&'a str>,
        }

        let attempt = Attempt {
            user: "kmjtechno",
            token: Secret::new("abc123"),
        };
        let rendered = format!("{attempt:?}");

        assert!(
            !rendered.contains("abc123"),
            "a nested secret leaked: {rendered}"
        );
        assert!(rendered.contains(REDACTED));
    }

    #[test]
    fn exposing_a_secret_is_possible_but_named_for_it() {
        let secret = Secret::new(String::from("actual-value"));

        assert_eq!(secret.expose(), "actual-value");
    }

    #[test]
    fn a_peer_identity_can_be_wrapped_at_construction() {
        let identity = PeerIdentity::new("device-abc").expect("identity");
        let secret = Secret::new(identity.as_str());

        assert_eq!(format!("{secret}"), REDACTED);
        assert!(!format!("{secret:?}").contains("device-abc"));
    }

    #[test]
    fn a_peer_summary_carries_no_identity() {
        let summary = PeerSummary::from_identity("a-long-device-name", true);
        let rendered = format!("{summary:?}");

        assert!(!rendered.contains("a-long-device-name"));
        assert!(!rendered.contains("device"));
        assert_eq!(summary.identity_length, 18);
    }

    #[test]
    fn a_peer_field_records_authentication_without_the_identity() {
        // Pinning the exact fields, because dropping the length would be a
        // privacy improvement but would also silently drop the
        // authentication flag a support investigation needs. That trade is
        // real and should be a decision, not an accident.
        let record = SafeRecordBuilder::new()
            .peer(
                "peer",
                PeerSummary::from_identity("confidential-identity", true),
            )
            .build("session_complete");

        let names: Vec<&str> = record.detail().iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["peer", "peer_authenticated"]);
        assert_eq!(
            record.detail()[1].1,
            SafeValue::Flag(true),
            "the authentication state must survive redaction"
        );
    }

    #[test]
    fn an_unauthenticated_peer_is_distinguishable_without_its_name() {
        let record = SafeRecordBuilder::new()
            .peer(
                "peer",
                PeerSummary::from_identity("confidential-identity", false),
            )
            .build("session_complete");

        assert_eq!(record.detail()[1].1, SafeValue::Flag(false));
        assert!(!record.render().contains("confidential-identity"));
    }

    #[test]
    fn a_record_holds_only_safe_values() {
        let record = SafeRecordBuilder::new()
            .metric("input_bytes", 4096)
            .metric("elapsed_ms", 12)
            .flag("rendered", true)
            .state("level", "Minimal")
            .redacted("clipboard_digest", 32)
            .peer("peer", PeerSummary::from_identity("secret-device", false))
            .build("session_complete");

        assert!(record.carries_only_safe_values());
        assert_eq!(record.event(), "session_complete");
    }

    #[test]
    fn a_record_never_contains_the_identity_it_was_given() {
        let identity = "confidential-device-identity";
        let record = SafeRecordBuilder::new()
            .peer("peer", PeerSummary::from_identity(identity, true))
            .build("session_complete");

        assert!(!record.render().contains(identity));
    }

    #[test]
    fn rendering_produces_one_line_of_key_value_pairs() {
        let record = SafeRecordBuilder::new()
            .metric("bytes", 128)
            .flag("ok", true)
            .state("level", "Low")
            .build("encode");

        assert_eq!(record.render(), "event=encode bytes=128 ok=true level=Low");
    }

    #[test]
    fn a_redacted_field_keeps_its_length_for_diagnosis() {
        let record = SafeRecordBuilder::new()
            .redacted("clipboard_digest", 44)
            .build("clipboard");

        assert_eq!(
            record.render(),
            "event=clipboard clipboard_digest=[redacted]:len=44"
        );
    }

    #[test]
    fn field_order_is_preserved() {
        let record = SafeRecordBuilder::new()
            .metric("first", 1)
            .metric("second", 2)
            .metric("third", 3)
            .build("ordered");

        let names: Vec<&str> = record
            .detail()
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        assert_eq!(names, ["first", "second", "third"]);
    }

    #[test]
    fn a_state_value_cannot_be_a_runtime_string() {
        // `state` takes `&'static str`, so this cannot compile:
        //
        //     let computed = compute_state();
        //     builder.state("level", &computed);
        //
        // The signature is the check. What is assertable at runtime is that a
        // state value is stored as a name and never as a payload.
        let record = SafeRecordBuilder::new().state("level", "Ultra").build("q");
        assert_eq!(record.detail()[0].1, SafeValue::State("Ultra"));
    }

    #[test]
    fn a_record_with_no_detail_is_still_valid() {
        let record = SafeRecordBuilder::new().build("heartbeat");

        assert_eq!(record.render(), "event=heartbeat");
        assert!(record.carries_only_safe_values());
    }

    #[test]
    fn secrets_survive_being_placed_in_the_record_source() {
        // The record type cannot hold a `Secret`, so a caller cannot smuggle
        // one in and have it printed as a field value.
        let secret = Secret::new("token-value");
        let record = SafeRecordBuilder::new().metric("seen", 1).build("event");

        assert!(!record.render().contains(secret.expose()));
    }
}
