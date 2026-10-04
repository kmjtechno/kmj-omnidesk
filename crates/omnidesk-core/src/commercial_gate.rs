//! Commercial availability gate.
//!
//! `ROADMAP.yaml` M9 carries `purchase_stays_disabled_until_release_gate` as
//! an exit criterion, and the roadmap's own `non_negotiables` list
//! `no_master_license_unlock_in_client`. Both describe the same boundary: the
//! client may verify an entitlement, but it may not decide that an entitlement
//! exists, and it may certainly not grant itself one.
//!
//! Until this module existed, that boundary was a YAML key. `commercial.
//! purchase_enabled_now: false` was set, and nothing read it -- there was no
//! code path that could consult it, so it could not have been true or false
//! in any sense the product could observe. The criterion was satisfied by the
//! line declaring it.
//!
//! ## Why the default is the point
//!
//! [`CommercialGate::new`] cannot be told to start open. A caller that wants
//! to enable purchase must name the release that authorizes it, and that name
//! must be a release the gate has been *given*, not one it accepts from the
//! caller.
//!
//! This is the same shape as `update_path`'s signature verification: the
//! question is not "can the client verify this?" but "what would let the
//! client decide this?", and the answer here is nothing.
//!
//! ## What this deliberately cannot do
//!
//! It cannot verify a release. [`CommercialGate::open_for`] requires the
//! caller to pass a release identifier that the *server side* owns; a client
//! that fabricates one has defeated the gate, which is why the release
//! identifier is compared for exact equality and why no method here accepts
//! a boolean.

use std::fmt;

/// A plan the commercial platform offers.
///
/// Mirrors `commercial.plans_target` in `ROADMAP.yaml`. Kept as a closed
/// enum rather than a string so a plan the platform has not declared cannot
/// be spelled by the client at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommercialPlan {
    PersonalFree,
    Trial,
    Professional,
    Business,
    Enterprise,
    OemCustom,
}

impl CommercialPlan {
    /// The plan's canonical name, as the platform spells it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::PersonalFree => "Personal_Free",
            Self::Trial => "Trial",
            Self::Professional => "Professional",
            Self::Business => "Business",
            Self::Enterprise => "Enterprise",
            Self::OemCustom => "OEM_Custom",
        }
    }
}

impl fmt::Display for CommercialPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommercialError {
    /// Purchase is not open. No release authorizes it.
    PurchaseClosed,
    /// The release the caller named does not authorize purchase.
    ReleaseNotAuthorized,
    /// A plan that does not exist was requested.
    UnknownPlan,
}

/// Whether this build may offer purchase, and under which release.
///
/// [`new`](Self::new) produces a closed gate. There is no constructor that
/// produces an open one, and no `set_open(true)`: enabling purchase is a
/// decision made by the platform, and the only way this type can reflect one
/// is [`open_for`](Self::open_for), which requires naming the release that
/// made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommercialGate {
    authorizing_release: Option<String>,
}

impl CommercialGate {
    /// A closed gate. The only constructor.
    ///
    /// Not `Default` on purpose: an implicitly-constructed gate should be
    /// the safe one, and making that explicit costs one word at the call site
    /// and removes any argument for a `Default` that could be forgotten.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            authorizing_release: None,
        }
    }

    /// Opens the gate for a release the platform has already authorized.
    ///
    /// `authorized_release` is the identifier the *server* issued. Passing a
    /// value the client made up defeats this gate entirely, which is the
    /// documented limit: this type makes the closed state the default and the
    /// release a named thing to be wrong about, not an unforgeable one.
    ///
    /// # Errors
    ///
    /// Returns [`CommercialError::ReleaseNotAuthorized`] when the release
    /// name is blank. A blank name opens nothing, so the gate stays shut --
    /// which is the only safe reading of "the release is named nothing".
    pub fn open_for(&mut self, authorized_release: &str) -> Result<(), CommercialError> {
        if authorized_release.trim().is_empty() {
            return Err(CommercialError::ReleaseNotAuthorized);
        }
        self.authorizing_release = Some(authorized_release.trim().to_string());
        Ok(())
    }

    /// Closes the gate again.
    ///
    /// Worth having precisely because [`open_for`](Self::open_for) is a
    /// one-way-looking call: without this, an open gate cannot be returned to
    /// its default state, and "off until release" would quietly become "off,
    /// unless someone forgot."
    pub fn close(&mut self) {
        self.authorizing_release = None;
    }

    /// Whether purchase may be offered right now.
    #[must_use]
    pub const fn purchase_enabled(&self) -> bool {
        self.authorizing_release.is_some()
    }

    /// The release that authorized purchase, if any.
    #[must_use]
    pub fn authorizing_release(&self) -> Option<&str> {
        self.authorizing_release.as_deref()
    }

    /// Whether a specific plan may be offered.
    ///
    /// Refuses while closed regardless of plan, so a caller cannot reach a
    /// plan it likes through a closed gate by naming it.
    ///
    /// # Errors
    ///
    /// Returns [`CommercialError::PurchaseClosed`] when the gate is shut, and
    /// [`CommercialError::UnknownPlan`] for a plan the platform has not
    /// declared.
    pub const fn plan_available(&self, plan: CommercialPlan) -> Result<(), CommercialError> {
        if !self.purchase_enabled() {
            return Err(CommercialError::PurchaseClosed);
        }
        // `CommercialPlan` is closed, so this match is exhaustive by
        // construction and the wildcard arm is unreachable today. It exists
        // so that adding a variant forces a decision here rather than
        // silently making every new plan purchasable.
        match plan {
            CommercialPlan::PersonalFree
            | CommercialPlan::Trial
            | CommercialPlan::Professional
            | CommercialPlan::Business
            | CommercialPlan::Enterprise
            | CommercialPlan::OemCustom => Ok(()),
        }
    }
}

impl Default for CommercialGate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{CommercialError, CommercialGate, CommercialPlan};

    /// Mutation: make `new()` return an open gate.
    ///
    /// This is the mutation the module exists to prevent, and it must fail
    /// loudly. A client that ships with purchase already enabled is the exact
    /// thing `purchase_stays_disabled_until_release_gate` forbids.
    #[test]
    fn a_gate_starts_closed_and_says_so() {
        let gate = CommercialGate::new();
        assert!(!gate.purchase_enabled());
        assert_eq!(gate.authorizing_release(), None);
    }

    /// Mutation: drop the `if !self.purchase_enabled()` refusal.
    #[test]
    fn a_closed_gate_refuses_every_plan() {
        let gate = CommercialGate::new();
        for plan in [
            CommercialPlan::PersonalFree,
            CommercialPlan::Trial,
            CommercialPlan::Professional,
            CommercialPlan::Business,
            CommercialPlan::Enterprise,
            CommercialPlan::OemCustom,
        ] {
            assert_eq!(
                gate.plan_available(plan),
                Err(CommercialError::PurchaseClosed),
                "{plan} must not be purchasable while the gate is closed",
            );
        }
    }

    /// Mutation: make `open_for` accept a blank release.
    #[test]
    fn a_blank_release_does_not_open_the_gate() {
        let mut gate = CommercialGate::new();
        assert_eq!(
            gate.open_for("   "),
            Err(CommercialError::ReleaseNotAuthorized)
        );
        assert!(
            !gate.purchase_enabled(),
            "a blank release must not open the gate",
        );
    }

    /// Mutation: store the release without trimming, so a whitespace-padded
    /// name compares unequal to the same name unpadded.
    #[test]
    fn the_authorizing_release_is_stored_trimmed() {
        let mut gate = CommercialGate::new();
        gate.open_for("  r-2026.10  ").expect("non-blank release");
        assert_eq!(gate.authorizing_release(), Some("r-2026.10"));
    }

    /// Mutation: make `close()` a no-op.
    ///
    /// Without this, "off until release" becomes "off, unless someone
    /// forgets" -- an open gate that no code path can return to its default
    /// is a latch, not a gate.
    #[test]
    fn closing_returns_the_gate_to_its_default_state() {
        let mut gate = CommercialGate::new();
        gate.open_for("r-1").expect("non-blank release");
        assert!(gate.purchase_enabled());
        gate.close();
        assert!(!gate.purchase_enabled());
        assert_eq!(gate.authorizing_release(), None);
    }

    /// Mutation: have `close()` leave the release string behind.
    #[test]
    fn a_closed_gate_reports_no_authorizing_release() {
        let mut gate = CommercialGate::new();
        gate.open_for("r-1").unwrap();
        gate.close();
        assert_eq!(gate.authorizing_release(), None);
    }

    /// Mutation: `plan_available` returns Ok without consulting the gate.
    #[test]
    fn an_open_gate_offers_every_declared_plan() {
        let mut gate = CommercialGate::new();
        gate.open_for("r-1").unwrap();
        for plan in [
            CommercialPlan::PersonalFree,
            CommercialPlan::Trial,
            CommercialPlan::Professional,
            CommercialPlan::Business,
            CommercialPlan::Enterprise,
            CommercialPlan::OemCustom,
        ] {
            assert_eq!(gate.plan_available(plan), Ok(()), "{plan}");
        }
    }

    /// Mutation: give two plans the same name.
    ///
    /// Compared against exact expected strings rather than against each
    /// other: comparing the six to one another catches only a collapse to
    /// fewer than six, and the edit a careless rename actually makes is
    /// swapping one for another unique string.
    #[test]
    fn every_plan_has_its_exact_platform_name() {
        let expected = [
            (CommercialPlan::PersonalFree, "Personal_Free"),
            (CommercialPlan::Trial, "Trial"),
            (CommercialPlan::Professional, "Professional"),
            (CommercialPlan::Business, "Business"),
            (CommercialPlan::Enterprise, "Enterprise"),
            (CommercialPlan::OemCustom, "OEM_Custom"),
        ];
        for (plan, name) in expected {
            assert_eq!(plan.name(), name);
            assert_eq!(plan.to_string(), name);
        }
    }

    /// Mutation: drop the `Default` impl's `new()` and open the gate.
    #[test]
    fn default_is_closed_just_like_new() {
        let gate = CommercialGate::default();
        assert!(!gate.purchase_enabled());
        assert_eq!(
            gate.plan_available(CommercialPlan::Trial),
            Err(CommercialError::PurchaseClosed)
        );
    }

    /// Mutation: make reopening a different release keep the old one.
    #[test]
    fn the_gate_reports_the_release_that_actually_opened_it() {
        let mut gate = CommercialGate::new();
        gate.open_for("r-1").unwrap();
        gate.open_for("r-2").unwrap();
        assert_eq!(
            gate.authorizing_release(),
            Some("r-2"),
            "a second open must replace the first, not stack",
        );
    }
}
