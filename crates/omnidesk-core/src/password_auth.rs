//! Secure attended password authentication for KMJ `OmniDesk` V7.
//!
//! Provides cryptographically secure temporary password generation,
//! expiring credential lifecycle, brute-force lockout, and cryptographic
//! password proof binding over an authenticated encrypted transport.

use sha2::{Digest, Sha256};

pub const DEFAULT_PASSWORD_LIFETIME_SECS: u64 = 3600; // 1 hour
pub const MAX_FAILED_ATTEMPTS: u32 = 5;
pub const LOCKOUT_DURATION_SECS: u64 = 300; // 5 minutes
const CHARSET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

// Never silently strip arbitrary punctuation, control codes, or Unicode from
// an attended credential. Only the displayed hyphen/space separators are
// allowed. A malformed attempt must still consume the host's attempt budget.
fn normalize_password_input(candidate: &str) -> Option<String> {
    if !candidate
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == ' ')
    {
        return None;
    }
    let normalized: String = candidate
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect();
    (normalized.len() == 8).then_some(normalized)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordVerificationError {
    RemoteControlDisabled,
    Expired,
    LockedOut { remaining_secs: u64 },
    InvalidPassword { remaining_attempts: u32 },
    ChallengeConsumed,
    InvalidBinding,
}

impl std::fmt::Display for PasswordVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RemoteControlDisabled => write!(f, "Host has remote control disabled"),
            Self::Expired => write!(f, "Temporary session password has expired"),
            Self::LockedOut { remaining_secs } => {
                write!(
                    f,
                    "Too many failed attempts - locked out for {remaining_secs}s"
                )
            }
            Self::InvalidPassword { remaining_attempts } => {
                write!(
                    f,
                    "Invalid session password - {remaining_attempts} attempts remaining"
                )
            }
            Self::ChallengeConsumed => write!(f, "Password proof challenge already consumed"),
            Self::InvalidBinding => write!(f, "Invalid host proof session binding"),
        }
    }
}

impl std::error::Error for PasswordVerificationError {}

/// Host-only one-use password challenge.
///
/// The SHA-256 password proof is NOT a PAKE: use only after independently
/// authenticating both peers and establishing encryption, never raw TCP.
#[derive(Debug)]
pub struct HostProofChallenge {
    host_device_id: String,
    session_id: [u8; 16],
    nonce: [u8; 32],
    client_public_key: [u8; 32],
    host_public_key: [u8; 32],
    issued_at: u64,
    expires_at: u64,
    rotation_count: u64,
    policy_revision: u64,
    bound_to_noise: bool,
    consumed: bool,
}

impl HostProofChallenge {
    /// Expected remote host ID.
    #[must_use]
    pub fn host_device_id(&self) -> &str {
        &self.host_device_id
    }
    /// Per-session identifier.
    #[must_use]
    pub const fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }
    /// One-use OS-generated challenge.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }
    /// Authenticated client public key.
    #[must_use]
    pub const fn client_public_key(&self) -> &[u8; 32] {
        &self.client_public_key
    }
    /// Authenticated host public key.
    #[must_use]
    pub const fn host_public_key(&self) -> &[u8; 32] {
        &self.host_public_key
    }
    /// Bind a fresh host challenge to the exact encrypted Noise transcript.
    ///
    /// Called once *after* mutual enrolled Ed25519 identity proof. The
    /// transcript hash is mixed into the OS-random nonce before the password
    /// proof is generated; a credential response from any other encrypted
    /// channel cannot satisfy the pending host verifier.
    ///
    /// # Errors
    /// Rejects missing/zero hashes, reuse and already-consumed challenges.
    pub fn bind_noise_hash(
        &mut self,
        handshake_hash: &[u8; 32],
    ) -> Result<(), PasswordVerificationError> {
        if self.consumed {
            return Err(PasswordVerificationError::ChallengeConsumed);
        }
        if self.bound_to_noise || *handshake_hash == [0_u8; 32] {
            return Err(PasswordVerificationError::InvalidBinding);
        }
        let mut digest = Sha256::new();
        digest.update(b"KMJ_OMNIDESK_ATTENDED_NOISE_BIND_V1");
        digest.update(self.nonce);
        digest.update(handshake_hash);
        self.nonce.copy_from_slice(&digest.finalize());
        self.bound_to_noise = true;
        Ok(())
    }

    /// Whether this host challenge has been spent.
    #[must_use]
    pub const fn is_consumed(&self) -> bool {
        self.consumed
    }
}

/// Host-managed session password and incoming authorization control state.
#[derive(Clone, PartialEq, Eq)]
pub struct HostPasswordManager {
    password: String,
    salt: [u8; 16],
    hash: [u8; 32],
    created_at_epoch_secs: u64,
    expires_at_epoch_secs: u64,
    failed_attempts: u32,
    lockout_until_epoch_secs: u64,
    allow_remote_control: bool,
    rotation_count: u64,
    policy_revision: u64,
}

// Redact credential values in diagnostic output.
impl std::fmt::Debug for HostPasswordManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostPasswordManager")
            .field("credential_present", &!self.password.is_empty())
            .field("expires_at_epoch_secs", &self.expires_at_epoch_secs)
            .field("failed_attempts", &self.failed_attempts)
            .field("allow_remote_control", &self.allow_remote_control)
            .finish_non_exhaustive()
    }
}

impl HostPasswordManager {
    /// Creates an empty host password manager (for const initialization).
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            password: String::new(),
            salt: [0_u8; 16],
            hash: [0_u8; 32],
            created_at_epoch_secs: 0,
            expires_at_epoch_secs: 0,
            failed_attempts: 0,
            lockout_until_epoch_secs: 0,
            allow_remote_control: false,
            rotation_count: 0,
            policy_revision: 0,
        }
    }

    /// Creates a new host password manager with a fresh temporary password.
    #[must_use]
    pub fn new(now_epoch_secs: u64) -> Self {
        let mut manager = Self {
            password: String::new(),
            salt: [0_u8; 16],
            hash: [0_u8; 32],
            created_at_epoch_secs: now_epoch_secs,
            expires_at_epoch_secs: now_epoch_secs.saturating_add(DEFAULT_PASSWORD_LIFETIME_SECS),
            failed_attempts: 0,
            lockout_until_epoch_secs: 0,
            allow_remote_control: false,
            rotation_count: 0,
            policy_revision: 0,
        };
        manager.rotate(now_epoch_secs);
        manager
    }

    /// Returns the current plaintext temporary password.
    #[must_use]
    pub fn password(&self) -> &str {
        &self.password
    }

    /// Formats the password with a hyphen for readability (e.g. `7342-8905`).
    #[must_use]
    pub fn formatted_password(&self) -> String {
        if self.password.len() == 8 {
            format!("{}-{}", &self.password[..4], &self.password[4..])
        } else {
            self.password.clone()
        }
    }

    #[must_use]
    pub const fn expires_at_epoch_secs(&self) -> u64 {
        self.expires_at_epoch_secs
    }

    #[must_use]
    pub const fn allow_remote_control(&self) -> bool {
        self.allow_remote_control
    }

    pub const fn set_allow_remote_control(&mut self, allow: bool) {
        if self.allow_remote_control != allow {
            self.policy_revision = self.policy_revision.wrapping_add(1);
            self.allow_remote_control = allow;
        }
    }

    pub const fn toggle_allow_remote_control(&mut self) {
        self.policy_revision = self.policy_revision.wrapping_add(1);
        self.allow_remote_control = !self.allow_remote_control;
    }

    #[must_use]
    pub const fn is_expired(&self, now_epoch_secs: u64) -> bool {
        now_epoch_secs >= self.expires_at_epoch_secs
    }

    #[must_use]
    pub const fn is_locked_out(&self, now_epoch_secs: u64) -> bool {
        now_epoch_secs < self.lockout_until_epoch_secs
    }

    /// Rotates the temporary session password, resetting failed attempts and lockout.
    ///
    /// # Panics
    /// Panics if the OS cryptographic random source is unavailable. No new
    /// temporary credential is issued in that case.
    pub fn rotate(&mut self, now_epoch_secs: u64) {
        self.rotation_count = self.rotation_count.wrapping_add(1);
        // OS cryptographic randomness, never clock/PID-derived entropy.
        // Fail closed if no secure source is available.
        debug_assert_eq!(CHARSET.len(), 32);
        let mut entropy = [0_u8; 24];
        getrandom::fill(&mut entropy)
            .expect("OS cryptographic randomness unavailable: credential refused");

        let mut salt = [0_u8; 16];
        salt.copy_from_slice(&entropy[..16]);

        // Since the alphabet is 32 symbols, modulo 32 is unbiased.
        let mut pwd = String::with_capacity(8);
        for byte in &entropy[16..] {
            let idx = usize::from(*byte) % CHARSET.len();
            pwd.push(CHARSET[idx] as char);
        }

        self.password = pwd;
        self.salt = salt;
        self.hash = compute_password_hash(&self.password, &self.salt);
        self.created_at_epoch_secs = now_epoch_secs;
        self.expires_at_epoch_secs = now_epoch_secs.saturating_add(DEFAULT_PASSWORD_LIFETIME_SECS);
        self.failed_attempts = 0;
        self.lockout_until_epoch_secs = 0;
    }

    /// Create one OS-random challenge on an authenticated encrypted host.
    ///
    /// This is host-side proof state, NOT a wire protocol or authorization.
    ///
    /// # Errors
    /// Refuses disabled, expired, locked-out or malformed key binding.
    ///
    /// # Panics
    /// Fails closed if the operating system CSPRNG is unavailable.
    pub fn issue_proof_challenge(
        &self,
        host_device_id: &str,
        client_public_key: [u8; 32],
        host_public_key: [u8; 32],
        now_epoch_secs: u64,
    ) -> Result<HostProofChallenge, PasswordVerificationError> {
        if host_device_id.trim().is_empty()
            || client_public_key == [0_u8; 32]
            || host_public_key == [0_u8; 32]
            || client_public_key == host_public_key
        {
            return Err(PasswordVerificationError::InvalidBinding);
        }
        self.ensure_password_usable(now_epoch_secs)?;
        let mut entropy = [0_u8; 48];
        getrandom::fill(&mut entropy).expect("OS CSPRNG unavailable: host proof challenge refused");
        let mut session_id = [0_u8; 16];
        let mut nonce = [0_u8; 32];
        session_id.copy_from_slice(&entropy[..16]);
        nonce.copy_from_slice(&entropy[16..]);
        if session_id == [0_u8; 16] || nonce == [0_u8; 32] {
            return Err(PasswordVerificationError::InvalidBinding);
        }
        Ok(HostProofChallenge {
            host_device_id: host_device_id.to_owned(),
            session_id,
            nonce,
            client_public_key,
            host_public_key,
            issued_at: now_epoch_secs,
            expires_at: now_epoch_secs.saturating_add(60),
            rotation_count: self.rotation_count,
            policy_revision: self.policy_revision,
            bound_to_noise: false,
            consumed: false,
        })
    }

    /// Verify and consume an attended-password challenge exactly once.
    ///
    /// Password rotation, sharing-policy changes, expiry and replay reject.
    /// Each wrong proof counts toward the host lockout. Separate encrypted
    /// transport, authenticated device identity and visible consent remain
    /// mandatory before remote input may be authorized.
    ///
    /// # Errors
    /// Rejects replay, stale challenge, disabled host and wrong proof.
    pub fn verify_proof_once(
        &mut self,
        challenge: &mut HostProofChallenge,
        proof: &[u8; 32],
        now_epoch_secs: u64,
    ) -> Result<(), PasswordVerificationError> {
        if challenge.consumed {
            return Err(PasswordVerificationError::ChallengeConsumed);
        }
        challenge.consumed = true;
        self.ensure_password_usable(now_epoch_secs)?;
        if now_epoch_secs < challenge.issued_at
            || now_epoch_secs >= challenge.expires_at
            || challenge.rotation_count != self.rotation_count
            || challenge.policy_revision != self.policy_revision
        {
            return Err(PasswordVerificationError::Expired);
        }
        if verify_password_proof(
            proof,
            &self.password,
            &challenge.host_device_id,
            &challenge.session_id,
            &challenge.nonce,
            &challenge.client_public_key,
            &challenge.host_public_key,
        ) {
            self.failed_attempts = 0;
            Ok(())
        } else {
            Err(self.record_failed_attempt(now_epoch_secs))
        }
    }

    const fn ensure_password_usable(
        &self,
        now_epoch_secs: u64,
    ) -> Result<(), PasswordVerificationError> {
        if !self.allow_remote_control {
            return Err(PasswordVerificationError::RemoteControlDisabled);
        }
        if self.is_locked_out(now_epoch_secs) {
            return Err(PasswordVerificationError::LockedOut {
                remaining_secs: self.lockout_until_epoch_secs.saturating_sub(now_epoch_secs),
            });
        }
        if self.is_expired(now_epoch_secs) {
            return Err(PasswordVerificationError::Expired);
        }
        Ok(())
    }

    const fn record_failed_attempt(&mut self, now_epoch_secs: u64) -> PasswordVerificationError {
        self.failed_attempts = self.failed_attempts.saturating_add(1);
        if self.failed_attempts >= MAX_FAILED_ATTEMPTS {
            self.lockout_until_epoch_secs = now_epoch_secs.saturating_add(LOCKOUT_DURATION_SECS);
            PasswordVerificationError::LockedOut {
                remaining_secs: LOCKOUT_DURATION_SECS,
            }
        } else {
            PasswordVerificationError::InvalidPassword {
                remaining_attempts: MAX_FAILED_ATTEMPTS.saturating_sub(self.failed_attempts),
            }
        }
    }

    /// Verifies a candidate password against the host's active session credential.
    ///
    /// # Errors
    /// Returns [`PasswordVerificationError`] if remote control is disabled, the password
    /// is expired, the host is in lockout, or the candidate is invalid.
    pub fn verify_candidate(
        &mut self,
        candidate: &str,
        now_epoch_secs: u64,
    ) -> Result<(), PasswordVerificationError> {
        self.ensure_password_usable(now_epoch_secs)?;

        // Hash even malformed attempts so they cannot sidestep the
        // brute-force counter. An empty normalized string never matches the
        // host's generated eight-character password.
        let normalized = normalize_password_input(candidate);
        let candidate_hash = compute_password_hash(normalized.as_deref().unwrap_or(""), &self.salt);
        if normalized.is_some() && constant_time_eq_32(&candidate_hash, &self.hash) {
            self.failed_attempts = 0;
            Ok(())
        } else {
            Err(self.record_failed_attempt(now_epoch_secs))
        }
    }
}

/// Computes a salted hash of the password.
#[must_use]
pub fn compute_password_hash(password: &str, salt: &[u8; 16]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"KMJ_OMNIDESK_PASSWORD_HASH_V1");
    hasher.update(salt);
    hasher.update(password.as_bytes());
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(&hasher.finalize());
    hash
}

/// Generates a cryptographic password proof for an authenticated session.
///
/// Binds the proof to the session ID, single-use nonce, and both client and host
/// public keys to prevent credential leakage, replay attacks, and downgrade attacks.
#[must_use]
pub fn generate_password_proof(
    password: &str,
    host_device_id: &str,
    session_id: &[u8; 16],
    nonce: &[u8; 32],
    client_public_key: &[u8; 32],
    host_public_key: &[u8; 32],
) -> [u8; 32] {
    // A malformed client spelling must not silently become a valid proof
    // after punctuation/Unicode stripping. The all-zero sentinel is always
    // rejected against a real generated host password; no proof is issued.
    let Some(normalized) = normalize_password_input(password) else {
        return [0_u8; 32];
    };

    let mut key_hasher = Sha256::new();
    key_hasher.update(b"KMJ_OMNIDESK_PROOF_KEY");
    key_hasher.update(normalized.as_bytes());
    key_hasher.update(host_device_id.as_bytes());
    let proof_key = key_hasher.finalize();

    let mut msg_hasher = Sha256::new();
    msg_hasher.update(b"KMJ_OMNIDESK_V7_PASSWORD_PROOF");
    msg_hasher.update(proof_key);
    msg_hasher.update(session_id);
    msg_hasher.update(nonce);
    msg_hasher.update(client_public_key);
    msg_hasher.update(host_public_key);

    let mut proof = [0_u8; 32];
    proof.copy_from_slice(&msg_hasher.finalize());
    proof
}

/// Verifies a received password proof against expected parameters.
#[must_use]
pub fn verify_password_proof(
    proof: &[u8; 32],
    expected_password: &str,
    host_device_id: &str,
    session_id: &[u8; 16],
    nonce: &[u8; 32],
    client_public_key: &[u8; 32],
    host_public_key: &[u8; 32],
) -> bool {
    if normalize_password_input(expected_password).is_none() {
        return false;
    }
    let expected = generate_password_proof(
        expected_password,
        host_device_id,
        session_id,
        nonce,
        client_public_key,
        host_public_key,
    );
    constant_time_eq_32(proof, &expected)
}

/// Constant-time comparison of two 32-byte arrays to prevent timing side channels.
#[inline]
#[must_use]
pub fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_proof_succeeds_once_and_replay_cannot_reauthorize() {
        let now = 1_000;
        let mut host = HostPasswordManager::new(now);
        host.set_allow_remote_control(true);
        let password = host.password().to_owned();
        let mut challenge = host
            .issue_proof_challenge("host-p520", [3_u8; 32], [4_u8; 32], now)
            .expect("issue host challenge");
        let proof = generate_password_proof(
            &password,
            challenge.host_device_id(),
            challenge.session_id(),
            challenge.nonce(),
            challenge.client_public_key(),
            challenge.host_public_key(),
        );
        assert_eq!(host.verify_proof_once(&mut challenge, &proof, now), Ok(()));
        assert!(challenge.is_consumed());
        assert_eq!(
            host.verify_proof_once(&mut challenge, &proof, now),
            Err(PasswordVerificationError::ChallengeConsumed)
        );
        let mut next = host
            .issue_proof_challenge("host-p520", [3_u8; 32], [4_u8; 32], now)
            .expect("new challenge");
        assert_ne!(next.nonce(), challenge.nonce());
        assert!(matches!(
            host.verify_proof_once(&mut next, &proof, now),
            Err(PasswordVerificationError::InvalidPassword { .. })
        ));
    }

    #[test]
    fn host_proof_expiry_rotation_and_toggle_revoke_pending_challenge() {
        let now = 2_000;
        let mut host = HostPasswordManager::new(now);
        host.set_allow_remote_control(true);
        let password = host.password().to_owned();
        let mut expired = host
            .issue_proof_challenge("host-p520", [3_u8; 32], [4_u8; 32], now)
            .expect("issue");
        let proof = generate_password_proof(
            &password,
            expired.host_device_id(),
            expired.session_id(),
            expired.nonce(),
            expired.client_public_key(),
            expired.host_public_key(),
        );
        assert_eq!(
            host.verify_proof_once(&mut expired, &proof, now + 60),
            Err(PasswordVerificationError::Expired)
        );
        let mut rotated = host
            .issue_proof_challenge("host-p520", [3_u8; 32], [4_u8; 32], now)
            .expect("issue");
        host.rotate(now + 1);
        assert_eq!(
            host.verify_proof_once(&mut rotated, &proof, now + 1),
            Err(PasswordVerificationError::Expired)
        );
        let mut policy = host
            .issue_proof_challenge("host-p520", [3_u8; 32], [4_u8; 32], now + 1)
            .expect("issue");
        host.set_allow_remote_control(false);
        host.set_allow_remote_control(true);
        assert_eq!(
            host.verify_proof_once(&mut policy, &proof, now + 2),
            Err(PasswordVerificationError::Expired)
        );
    }

    #[test]
    fn wrong_host_proofs_consume_lockout_budget_across_fresh_challenges() {
        let now = 3_000;
        let mut host = HostPasswordManager::new(now);
        host.set_allow_remote_control(true);
        for attempt in 1..=MAX_FAILED_ATTEMPTS {
            let mut challenge = host
                .issue_proof_challenge("host-p520", [3_u8; 32], [4_u8; 32], now)
                .expect("fresh nonce");
            let result = host.verify_proof_once(&mut challenge, &[0_u8; 32], now);
            if attempt == MAX_FAILED_ATTEMPTS {
                assert_eq!(
                    result,
                    Err(PasswordVerificationError::LockedOut {
                        remaining_secs: LOCKOUT_DURATION_SECS
                    })
                );
            } else {
                assert_eq!(
                    result,
                    Err(PasswordVerificationError::InvalidPassword {
                        remaining_attempts: MAX_FAILED_ATTEMPTS - attempt
                    })
                );
            }
        }
        assert!(matches!(
            host.issue_proof_challenge("host-p520", [3_u8; 32], [4_u8; 32], now),
            Err(PasswordVerificationError::LockedOut { .. })
        ));
    }

    #[test]
    fn proof_challenge_rejects_missing_identity_or_unverified_host_policy() {
        let now = 4_000;
        let mut host = HostPasswordManager::new(now);
        assert!(matches!(
            host.issue_proof_challenge("host-p520", [1_u8; 32], [2_u8; 32], now),
            Err(PasswordVerificationError::RemoteControlDisabled)
        ));
        host.set_allow_remote_control(true);
        assert!(matches!(
            host.issue_proof_challenge("", [1_u8; 32], [2_u8; 32], now),
            Err(PasswordVerificationError::InvalidBinding)
        ));
        assert!(matches!(
            host.issue_proof_challenge("host-p520", [0_u8; 32], [2_u8; 32], now),
            Err(PasswordVerificationError::InvalidBinding)
        ));
        assert!(matches!(
            host.issue_proof_challenge("host-p520", [1_u8; 32], [1_u8; 32], now),
            Err(PasswordVerificationError::InvalidBinding)
        ));
    }

    #[test]
    fn noise_bound_host_proof_refuses_cross_channel_and_double_binding() {
        let now = 2_600;
        let mut host = HostPasswordManager::new(now);
        host.set_allow_remote_control(true);
        let password = host.password().to_owned();
        let mut one = host
            .issue_proof_challenge("kmj-host", [6_u8; 32], [7_u8; 32], now)
            .expect("challenge");
        let initial_nonce = *one.nonce();
        let mut another = host
            .issue_proof_challenge("kmj-host", [6_u8; 32], [7_u8; 32], now)
            .expect("second challenge");
        one.bind_noise_hash(&[31_u8; 32]).expect("bind one");
        another.bind_noise_hash(&[32_u8; 32]).expect("bind another");
        assert_ne!(*one.nonce(), initial_nonce);
        assert_ne!(one.nonce(), another.nonce());
        assert_eq!(
            one.bind_noise_hash(&[31_u8; 32]),
            Err(PasswordVerificationError::InvalidBinding)
        );
        let invalid = generate_password_proof(
            &password, one.host_device_id(), one.session_id(),
            &initial_nonce, one.client_public_key(), one.host_public_key(),
        );
        assert!(matches!(
            host.verify_proof_once(&mut one, &invalid, now),
            Err(PasswordVerificationError::InvalidPassword { .. })
        ));
        assert_eq!(
            one.bind_noise_hash(&[31_u8; 32]),
            Err(PasswordVerificationError::ChallengeConsumed)
        );
    }

    #[test]
    fn host_password_generates_and_formats_cleanly() {
        let mgr = HostPasswordManager::new(1000);
        assert_eq!(mgr.password().len(), 8);
        let formatted = mgr.formatted_password();
        assert_eq!(formatted.len(), 9);
        assert_eq!(&formatted[4..5], "-");
        assert!(!mgr.allow_remote_control());
        assert!(!mgr.is_expired(1000));
        assert!(!mgr.is_locked_out(1000));
    }

    #[test]
    fn candidate_verification_succeeds_with_normalized_input() {
        let mut mgr = HostPasswordManager::new(1000);
        mgr.set_allow_remote_control(true);
        let pwd = mgr.password().to_owned();

        // Matches verbatim
        assert!(mgr.verify_candidate(&pwd, 1000).is_ok());

        // Matches with lowercase and hyphens
        let lower_hyphen = format!(
            "{}-{}",
            pwd[..4].to_ascii_lowercase(),
            pwd[4..].to_ascii_lowercase()
        );
        assert!(mgr.verify_candidate(&lower_hyphen, 1000).is_ok());
    }

    #[test]
    fn failed_verification_decrements_attempts_and_triggers_lockout() {
        let mut mgr = HostPasswordManager::new(1000);
        mgr.set_allow_remote_control(true);
        for remaining in (1..5).rev() {
            let res = mgr.verify_candidate("WRONGPWD", 1000);
            assert_eq!(
                res,
                Err(PasswordVerificationError::InvalidPassword {
                    remaining_attempts: remaining
                })
            );
        }
        // 5th failure triggers lockout
        let res = mgr.verify_candidate("WRONGPWD", 1000);
        assert_eq!(
            res,
            Err(PasswordVerificationError::LockedOut {
                remaining_secs: LOCKOUT_DURATION_SECS
            })
        );
        assert!(mgr.is_locked_out(1000));

        // During lockout, even correct password is rejected
        let pwd = mgr.password().to_owned();
        assert!(matches!(
            mgr.verify_candidate(&pwd, 1050),
            Err(PasswordVerificationError::LockedOut { .. })
        ));

        // After lockout duration elapses, correct password succeeds
        assert!(
            mgr.verify_candidate(&pwd, 1000 + LOCKOUT_DURATION_SECS + 1)
                .is_ok()
        );
    }

    #[test]
    fn rotation_uses_fresh_os_entropy() {
        let mut manager = HostPasswordManager::new(1000);
        let previous_password = manager.password.clone();
        let previous_salt = manager.salt;
        manager.rotate(1001);
        assert_ne!(previous_password, manager.password);
        assert_ne!(previous_salt, manager.salt);
        assert!(!manager.allow_remote_control());
    }

    #[test]
    fn debugging_never_exposes_credential_material() {
        let manager = HostPasswordManager::new(1000);
        let report = format!("{manager:?}");
        assert!(report.contains("credential_present"));
        assert!(!report.contains(manager.password()));
        assert!(!report.contains(&format!("{:?}", manager.hash)));
        assert!(!report.contains(&format!("{:?}", manager.salt)));
    }

    #[test]
    fn remote_control_toggle_refuses_verification_when_disabled() {
        let mut mgr = HostPasswordManager::new(1000);
        let pwd = mgr.password().to_owned();
        mgr.set_allow_remote_control(false);
        assert_eq!(
            mgr.verify_candidate(&pwd, 1000),
            Err(PasswordVerificationError::RemoteControlDisabled)
        );
        mgr.set_allow_remote_control(true);
        assert!(mgr.verify_candidate(&pwd, 1000).is_ok());
    }

    #[test]
    fn password_proof_binds_to_all_session_parameters() {
        let pwd = "KMJ7-9421";
        let host_id = "734 281 905";
        let session_id = [1_u8; 16];
        let nonce = [2_u8; 32];
        let client_pub = [3_u8; 32];
        let host_pub = [4_u8; 32];

        let proof =
            generate_password_proof(pwd, host_id, &session_id, &nonce, &client_pub, &host_pub);
        assert!(verify_password_proof(
            &proof,
            pwd,
            host_id,
            &session_id,
            &nonce,
            &client_pub,
            &host_pub
        ));

        // Wrong password fails
        assert!(!verify_password_proof(
            &proof,
            "WRONGPWD",
            host_id,
            &session_id,
            &nonce,
            &client_pub,
            &host_pub
        ));
        // Wrong host ID fails
        assert!(!verify_password_proof(
            &proof,
            pwd,
            "999 888 777",
            &session_id,
            &nonce,
            &client_pub,
            &host_pub
        ));
        // Replay on different session ID fails
        let other_session = [9_u8; 16];
        assert!(!verify_password_proof(
            &proof,
            pwd,
            host_id,
            &other_session,
            &nonce,
            &client_pub,
            &host_pub
        ));
        // Replay on different nonce fails
        let other_nonce = [9_u8; 32];
        assert!(!verify_password_proof(
            &proof,
            pwd,
            host_id,
            &session_id,
            &other_nonce,
            &client_pub,
            &host_pub
        ));
        // Substituted client public key fails
        let other_client = [9_u8; 32];
        assert!(!verify_password_proof(
            &proof,
            pwd,
            host_id,
            &session_id,
            &nonce,
            &other_client,
            &host_pub
        ));
    }
    #[test]
    fn password_is_rejected_at_exact_expiry_instant() {
        let mut manager = HostPasswordManager::new(1000);
        manager.set_allow_remote_control(true);
        let secret = manager.password().to_owned();
        let expires = manager.expires_at_epoch_secs();
        assert!(!manager.is_expired(expires - 1));
        assert!(manager.verify_candidate(&secret, expires - 1).is_ok());
        assert!(manager.is_expired(expires));
        assert_eq!(
            manager.verify_candidate(&secret, expires),
            Err(PasswordVerificationError::Expired)
        );
    }

    #[test]
    fn malformed_pasted_credentials_are_counted_and_never_silently_normalized() {
        let mut manager = HostPasswordManager::new(2000);
        manager.set_allow_remote_control(true);
        let secret = manager.password().to_owned();
        let malformed = [
            format!("{secret}!"),
            format!("{secret}\\n"),
            format!("{secret}💥"),
            secret[..7].to_owned(),
        ];
        for (index, input) in malformed.iter().enumerate() {
            assert_eq!(
                manager.verify_candidate(input, 2001),
                Err(PasswordVerificationError::InvalidPassword {
                    remaining_attempts: 4 - u32::try_from(index).unwrap()
                })
            );
        }
        assert_eq!(
            manager.verify_candidate(&format!("{secret}#"), 2001),
            Err(PasswordVerificationError::LockedOut {
                remaining_secs: LOCKOUT_DURATION_SECS
            })
        );
        assert!(matches!(
            manager.verify_candidate(&secret, 2002),
            Err(PasswordVerificationError::LockedOut { .. })
        ));
    }

    #[test]
    fn proof_verifier_rejects_malformed_credential_spellings() {
        let password = "KMJ7-9421";
        let session = [1_u8; 16];
        let nonce = [2_u8; 32];
        let client = [3_u8; 32];
        let host = [4_u8; 32];
        let proof = generate_password_proof(password, "host", &session, &nonce, &client, &host);
        assert!(verify_password_proof(
            &proof, password, "host", &session, &nonce, &client, &host
        ));
        for input in ["KMJ7-9421!", "KMJ7-9421💥", "KMJ7-9421\\n", "KMJ7-942"] {
            assert_eq!(
                generate_password_proof(input, "host", &session, &nonce, &client, &host),
                [0_u8; 32],
                "malformed client credentials must not produce a valid proof"
            );
            assert!(!verify_password_proof(
                &proof, input, "host", &session, &nonce, &client, &host
            ));
        }
    }
}
