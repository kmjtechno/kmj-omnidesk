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
    pub transport: TransportTrust,
    pub peer: PeerTrust,
    pub tenant: TenantTrust,
    pub encryption: EncryptionState,
    /// The controlled PC's owner must explicitly enable unattended access.
    pub unattended: UnattendedAvailability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportTrust {
    Authenticated,
    Unauthenticated,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTrust {
    Trusted,
    Untrusted,
    Revoked,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantTrust {
    Matching,
    Mismatched,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionState {
    Encrypted,
    Unencrypted,
}

/// Owner-local setting, never inferred from the caller's request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnattendedAvailability {
    #[default]
    Disabled,
    OwnerEnabled,
}

impl AccessPreflight {
    /// Fail closed before user consent or unattended password verification.
    #[must_use]
    pub fn next_step(self, mode: AccessMode) -> AuthorizationStep {
        if self.transport != TransportTrust::Authenticated
            || self.peer != PeerTrust::Trusted
            || self.tenant != TenantTrust::Matching
        {
            return AuthorizationStep::Reject;
        }
        match mode {
            AccessMode::AskPermission => AuthorizationStep::AwaitLocalConsent,
            AccessMode::PasswordRequired => {
                if self.encryption == EncryptionState::Encrypted
                    && self.unattended == UnattendedAvailability::OwnerEnabled
                {
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
        transport: TransportTrust::Authenticated,
        peer: PeerTrust::Trusted,
        tenant: TenantTrust::Matching,
        encryption: EncryptionState::Encrypted,
        unattended: UnattendedAvailability::OwnerEnabled,
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
            encryption: EncryptionState::Unencrypted,
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
    fn unattended_is_off_by_default_even_for_a_trusted_encrypted_peer() {
        assert_eq!(
            UnattendedAvailability::default(),
            UnattendedAvailability::Disabled
        );
        let disabled = AccessPreflight {
            unattended: UnattendedAvailability::default(),
            ..SECURE
        };
        assert_eq!(
            disabled.next_step(AccessMode::PasswordRequired),
            AuthorizationStep::Reject
        );
        assert_eq!(
            disabled.next_step(AccessMode::AskPermission),
            AuthorizationStep::AwaitLocalConsent
        );
    }

    #[test]
    fn invalid_trust_or_tenant_is_rejected_for_both_modes() {
        for invalid in [
            AccessPreflight {
                transport: TransportTrust::Unauthenticated,
                ..SECURE
            },
            AccessPreflight {
                peer: PeerTrust::Untrusted,
                ..SECURE
            },
            AccessPreflight {
                tenant: TenantTrust::Mismatched,
                ..SECURE
            },
            AccessPreflight {
                peer: PeerTrust::Revoked,
                ..SECURE
            },
        ] {
            for mode in [AccessMode::AskPermission, AccessMode::PasswordRequired] {
                assert_eq!(invalid.next_step(mode), AuthorizationStep::Reject);
            }
        }
    }
}
