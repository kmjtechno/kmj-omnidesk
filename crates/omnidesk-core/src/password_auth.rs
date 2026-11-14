//! Cryptographic password authentication, lifecycle, and rate-limiting for KMJ `OmniDesk` V5.
//!
//! Provides human-readable, high-entropy session passwords, replay-protected
//! proof-of-knowledge authentication over encrypted transport, and fail-closed
//! brute-force rate-limiting. Plaintext passwords are never transmitted on the wire.

use crate::device_enrollment::generate_csprng_nonce;
use sha2::{Digest, Sha256};
use std::fmt;

/// Unambiguous alphanumeric alphabet (excludes 0, O, 1, l, I to prevent visual confusion).
const PASSWORD_ALPHABET: &[u8] = b"23456789abcdefghjkmnpqrstuvwxyz";

/// Maximum failed password attempts before locking out connections.
pub const MAX_FAILED_PASSWORD_ATTEMPTS: u32 = 5;

/// Lockout penalty in seconds after exceeding maximum failed attempts.
pub const LOCKOUT_DURATION_SECS: u64 = 600; // 10 minutes

/// Default password validity duration (24 hours).
pub const DEFAULT_PASSWORD_TTL_SECS: u64 = 86_400;

/// Generates an 8-character human-friendly session password formatted as `xxxx-xxxx`.
#[must_use]
pub fn generate_session_password(now_epoch_secs: u64) -> String {
    let entropy = generate_csprng_nonce(now_epoch_secs);
    let mut chars = String::with_capacity(9);
    for (i, &byte) in entropy.iter().take(8).enumerate() {
        if i == 4 {
            chars.push('-');
        }
        let idx = (byte as usize) % PASSWORD_ALPHABET.len();
        chars.push(PASSWORD_ALPHABET[idx] as char);
    }
    chars
}

/// Normalizes a user-entered password by removing hyphens and whitespace and lowercasing.
#[must_use]
pub fn normalize_password(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

/// Computes an HMAC-SHA256 password proof bound to the host ID, client ID, and session challenge nonce.
///
/// `HMAC-SHA256(key = SHA256(normalize(password)), message = "KMJ_OMNIDESK_PW_AUTH_V1" || host_id || client_id || nonce)`
#[must_use]
#[allow(clippy::similar_names)]
pub fn compute_password_proof(
    password: &str,
    host_id: &str,
    client_id: &str,
    nonce: &[u8; 32],
) -> [u8; 32] {
    let norm = normalize_password(password);
    let pw_hash = Sha256::digest(norm.as_bytes());

    let mut k_ipad = [0x36_u8; 64];
    let mut k_opad = [0x5c_u8; 64];
    for (i, &b) in pw_hash.iter().enumerate() {
        k_ipad[i] ^= b;
        k_opad[i] ^= b;
    }

    let mut inner = Sha256::new();
    inner.update(k_ipad);
    inner.update(b"KMJ_OMNIDESK_PW_AUTH_V1");
    inner.update(host_id.as_bytes());
    inner.update(client_id.as_bytes());
    inner.update(nonce);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(k_opad);
    outer.update(inner_hash);
    let result = outer.finalize();

    let mut proof = [0_u8; 32];
    proof.copy_from_slice(&result);
    proof
}

/// Constant-time 32-byte equality comparison to prevent timing attacks.
#[must_use]
pub fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0_u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordAuthError {
    RateLimited { locked_until_secs: u64 },
    ProofMismatch,
    PasswordExpired,
    Unconfigured,
}

impl fmt::Display for PasswordAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RateLimited { locked_until_secs } => {
                write!(
                    f,
                    "Too many failed attempts. Locked until {locked_until_secs}"
                )
            }
            Self::ProofMismatch => write!(f, "Invalid session password proof"),
            Self::PasswordExpired => write!(f, "Session password has expired"),
            Self::Unconfigured => write!(f, "No session password configured"),
        }
    }
}

impl std::error::Error for PasswordAuthError {}

/// Session password manager maintaining local session secret lifecycle,
/// masking, rotation, and rate-limiting against brute force.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionPasswordManager {
    password: Option<String>,
    created_at_secs: u64,
    expires_at_secs: u64,
    revealed: bool,
    failed_attempts: u32,
    lockout_until_secs: u64,
}

impl fmt::Debug for SessionPasswordManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionPasswordManager")
            .field("is_configured", &self.password.is_some())
            .field("revealed", &self.revealed)
            .field("created_at_secs", &self.created_at_secs)
            .field("expires_at_secs", &self.expires_at_secs)
            .field("failed_attempts", &self.failed_attempts)
            .field("lockout_until_secs", &self.lockout_until_secs)
            .finish()
    }
}

impl SessionPasswordManager {
    /// Creates a new password manager initialized with a fresh secure password.
    #[must_use]
    pub fn new(now_epoch_secs: u64) -> Self {
        let password = generate_session_password(now_epoch_secs);
        Self {
            password: Some(password),
            created_at_secs: now_epoch_secs,
            expires_at_secs: now_epoch_secs.saturating_add(DEFAULT_PASSWORD_TTL_SECS),
            revealed: false,
            failed_attempts: 0,
            lockout_until_secs: 0,
        }
    }

    /// Creates an unconfigured manager (no password active).
    #[must_use]
    pub const fn unconfigured() -> Self {
        Self {
            password: None,
            created_at_secs: 0,
            expires_at_secs: 0,
            revealed: false,
            failed_attempts: 0,
            lockout_until_secs: 0,
        }
    }

    /// Returns whether a valid password is currently active.
    #[must_use]
    pub const fn is_active(&self, now_epoch_secs: u64) -> bool {
        self.password.is_some() && now_epoch_secs < self.expires_at_secs
    }

    /// Rotates the session password to a fresh cryptographically random value.
    pub fn rotate(&mut self, now_epoch_secs: u64) -> &str {
        let new_pw = generate_session_password(now_epoch_secs);
        self.password = Some(new_pw);
        self.created_at_secs = now_epoch_secs;
        self.expires_at_secs = now_epoch_secs.saturating_add(DEFAULT_PASSWORD_TTL_SECS);
        self.failed_attempts = 0;
        self.lockout_until_secs = 0;
        self.password.as_deref().unwrap_or("")
    }

    /// Toggles the masked vs revealed state for the local UI.
    pub const fn toggle_reveal(&mut self) {
        self.revealed = !self.revealed;
    }

    /// Sets the reveal state explicitly.
    pub const fn set_revealed(&mut self, revealed: bool) {
        self.revealed = revealed;
    }

    /// Returns whether the password is currently revealed.
    #[must_use]
    pub const fn is_revealed(&self) -> bool {
        self.revealed
    }

    /// Returns the UI display string: masked bullets (`••••••••`) if hidden,
    /// or actual password if revealed. Returns `"NOT CONFIGURED"` if none.
    #[must_use]
    pub fn display_text(&self) -> String {
        self.password.as_ref().map_or_else(
            || "NOT CONFIGURED".to_owned(),
            |pw| {
                if self.revealed {
                    pw.clone()
                } else {
                    "••••••••".to_owned()
                }
            },
        )
    }

    /// Returns the raw password for clipboard copy or programmatic check.
    #[must_use]
    pub fn raw_password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    /// Verifies a client's password proof against the local active password.
    ///
    /// Rate limits and locks out on repeated failures.
    ///
    /// # Errors
    /// Returns [`PasswordAuthError`] if rate-limited, expired, unconfigured, or mismatched.
    pub fn verify_proof(
        &mut self,
        host_id: &str,
        client_id: &str,
        nonce: &[u8; 32],
        client_proof: &[u8; 32],
        now_epoch_secs: u64,
    ) -> Result<(), PasswordAuthError> {
        if now_epoch_secs < self.lockout_until_secs {
            return Err(PasswordAuthError::RateLimited {
                locked_until_secs: self.lockout_until_secs,
            });
        }

        let Some(password) = &self.password else {
            return Err(PasswordAuthError::Unconfigured);
        };

        if now_epoch_secs >= self.expires_at_secs {
            return Err(PasswordAuthError::PasswordExpired);
        }

        let expected_proof = compute_password_proof(password, host_id, client_id, nonce);
        if constant_time_eq_32(&expected_proof, client_proof) {
            // Successful authentication resets the failure count
            self.failed_attempts = 0;
            Ok(())
        } else {
            self.failed_attempts = self.failed_attempts.saturating_add(1);
            if self.failed_attempts >= MAX_FAILED_PASSWORD_ATTEMPTS {
                self.lockout_until_secs = now_epoch_secs.saturating_add(LOCKOUT_DURATION_SECS);
                Err(PasswordAuthError::RateLimited {
                    locked_until_secs: self.lockout_until_secs,
                })
            } else {
                Err(PasswordAuthError::ProofMismatch)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_generation_has_correct_format_and_entropy() {
        let p1 = generate_session_password(1_700_000_000);
        let p2 = generate_session_password(1_700_000_001);
        assert_eq!(p1.len(), 9);
        assert_eq!(&p1[4..5], "-");
        assert_ne!(p1, p2);
        for (i, c) in p1.chars().enumerate() {
            if i == 4 {
                assert_eq!(c, '-');
            } else {
                assert!(PASSWORD_ALPHABET.contains(&(c as u8)));
            }
        }
    }

    #[test]
    fn normalization_handles_hyphens_spaces_and_case() {
        assert_eq!(normalize_password("7K2M-9P4W"), "7k2m9p4w");
        assert_eq!(normalize_password(" 7k2m 9p4w "), "7k2m9p4w");
        assert_eq!(normalize_password("7k2m-9p4w"), "7k2m9p4w");
    }

    #[test]
    fn proof_computation_is_deterministic_and_binds_all_parameters() {
        let pw = "7k2m-9p4w";
        let host = "KMJ-571-752-800";
        let client = "KMJ-123-456-789";
        let nonce = [42_u8; 32];

        let proof1 = compute_password_proof(pw, host, client, &nonce);
        let proof2 = compute_password_proof(pw, host, client, &nonce);
        assert_eq!(proof1, proof2);

        // Different password yields different proof
        let proof_diff_pw = compute_password_proof("9p4w-7k2m", host, client, &nonce);
        assert_ne!(proof1, proof_diff_pw);

        // Different host yields different proof
        let proof_diff_host = compute_password_proof(pw, "KMJ-999-999-999", client, &nonce);
        assert_ne!(proof1, proof_diff_host);

        // Different nonce yields different proof
        let mut diff_nonce = nonce;
        diff_nonce[0] ^= 1;
        let proof_diff_nonce = compute_password_proof(pw, host, client, &diff_nonce);
        assert_ne!(proof1, proof_diff_nonce);
    }

    #[test]
    fn verification_and_rate_limiting_workflow() {
        let now = 1_700_000_000;
        let mut manager = SessionPasswordManager::new(now);
        let host = "KMJ-571-752-800";
        let client = "KMJ-123-456-789";
        let nonce = [7_u8; 32];

        let pw = manager.raw_password().unwrap().to_owned();
        let valid_proof = compute_password_proof(&pw, host, client, &nonce);
        let bad_proof = [0_u8; 32];

        // Valid proof succeeds
        assert!(
            manager
                .verify_proof(host, client, &nonce, &valid_proof, now)
                .is_ok()
        );

        // Failed attempts trigger rate limiting
        for _ in 0..4 {
            assert_eq!(
                manager.verify_proof(host, client, &nonce, &bad_proof, now),
                Err(PasswordAuthError::ProofMismatch)
            );
        }

        // 5th failed attempt locks out
        assert_eq!(
            manager.verify_proof(host, client, &nonce, &bad_proof, now),
            Err(PasswordAuthError::RateLimited {
                locked_until_secs: now + LOCKOUT_DURATION_SECS
            })
        );

        // Even valid proof is refused during lockout
        assert_eq!(
            manager.verify_proof(host, client, &nonce, &valid_proof, now + 10),
            Err(PasswordAuthError::RateLimited {
                locked_until_secs: now + LOCKOUT_DURATION_SECS
            })
        );

        // After lockout passes, rotation resets lockout
        manager.rotate(now + LOCKOUT_DURATION_SECS + 1);
        let new_pw = manager.raw_password().unwrap().to_owned();
        let new_proof = compute_password_proof(&new_pw, host, client, &nonce);
        assert!(
            manager
                .verify_proof(
                    host,
                    client,
                    &nonce,
                    &new_proof,
                    now + LOCKOUT_DURATION_SECS + 2
                )
                .is_ok()
        );
    }

    #[test]
    fn masking_and_display_text() {
        let now = 1_700_000_000;
        let mut manager = SessionPasswordManager::new(now);
        assert_eq!(manager.display_text(), "••••••••");
        assert!(!manager.is_revealed());

        manager.toggle_reveal();
        assert!(manager.is_revealed());
        assert_eq!(manager.display_text(), manager.raw_password().unwrap());

        manager.toggle_reveal();
        assert_eq!(manager.display_text(), "••••••••");
    }
}
