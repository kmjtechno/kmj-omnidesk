//! Owner-controlled policy for interactive and future unattended sessions.
//!
//! This module does NOT authenticate passwords and must not be interpreted
//! as a completed credential protocol. Unattended access stays disabled
//! until a separate, mutually authenticated and encrypted proof is verified.

/// Connection policy chosen locally on the machine being controlled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessMode {
    /// The controlling peer must wait for an explicit local Accept decision.
    #[default]
    AskPermission,
    /// Owner has enabled unattended access. A secure credential exchange is
    /// still required before the session may be authorized.
    PasswordRequired,
}

/// What the host must do before any control permission is granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationStep {
    Reject,
    AwaitLocalConsent,
    AwaitVerifiedPasswordProof,
}

/// Inputs verified independently of the UI; none authorize control by themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessPreflight {
    pub authenticated_transport: bool,
    pub trusted_peer: bool,
    pub tenant_matches: bool,
    pub peer_revoked: bool,
    pub session_encrypted: bool,
}

impl AccessPreflight {
    /// Fail closed before user consent or unattended password verification.
    #[must_use]
    pub const fn next_step(self, mode: AccessMode) -> AuthorizationStep {
        if !self.authenticated_transport
            || !self.trusted_peer
            || !self.tenant_matches
            || self.peer_revoked
        {
            return AuthorizationStep::Reject;
        }
        match mode {
            AccessMode::AskPermission => AuthorizationStep::AwaitLocalConsent,
            AccessMode::PasswordRequired => {
                if self.session_encrypted {
                    AuthorizationStep::AwaitVerifiedPasswordProof
                } else {
                    AuthorizationStep::Reject
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECURE: AccessPreflight = AccessPreflight {
        authenticated_transport: true,
        trusted_peer: true,
        tenant_matches: true,
        peer_revoked: false,
        session_encrypted: true,
    };

    #[test]
    fn interactive_is_default_and_requires_local_permission() {
        assert_eq!(AccessMode::default(), AccessMode::AskPermission);
        assert_eq!(
            SECURE.next_step(AccessMode::default()),
            AuthorizationStep::AwaitLocalConsent
        );
    }

    #[test]
    fn unattended_requires_verified_password_proof_not_auto_authorization() {
        assert_eq!(
            SECURE.next_step(AccessMode::PasswordRequired),
            AuthorizationStep::AwaitVerifiedPasswordProof
        );
        let not_encrypted = AccessPreflight {
            session_encrypted: false,
            ..SECURE
        };
        assert_eq!(
            not_encrypted.next_step(AccessMode::PasswordRequired),
            AuthorizationStep::Reject
        );
        assert_eq!(
            not_encrypted.next_step(AccessMode::AskPermission),
            AuthorizationStep::AwaitLocalConsent
        );
    }

    #[test]
    fn invalid_trust_or_tenant_is_rejected_for_both_modes() {
        for invalid in [
            AccessPreflight {
                authenticated_transport: false,
                ..SECURE
            },
            AccessPreflight {
                trusted_peer: false,
                ..SECURE
            },
            AccessPreflight {
                tenant_matches: false,
                ..SECURE
            },
            AccessPreflight {
                peer_revoked: true,
                ..SECURE
            },
        ] {
            for mode in [AccessMode::AskPermission, AccessMode::PasswordRequired] {
                assert_eq!(invalid.next_step(mode), AuthorizationStep::Reject);
            }
        }
    }
}
