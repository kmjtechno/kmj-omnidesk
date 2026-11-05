//! Untrusted remote-ID text entry and fail-closed target selection for the
//! future unified `OmniDesk` connection UI.
//!
//! Entry is only a locator. Neither completed input nor a trusted-store hit
//! authorizes transport establishment, password login, screen or input control.

use crate::{
    public_device_id::{DEVICE_ID_LENGTH, PublicDeviceId, PublicDeviceIdError},
    trusted_device_store::TrustedDeviceStore,
};

/// Bounded text entry shared by keyboard and paste inputs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemoteIdEntry {
    text: String,
}

/// Connection target selected only after strict ID, self and trust checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedRemoteTarget {
    id: PublicDeviceId,
    enrolled_device_id: String,
}

impl SelectedRemoteTarget {
    #[must_use]
    pub fn public_id(&self) -> &PublicDeviceId {
        &self.id
    }

    #[must_use]
    pub fn enrolled_device_id(&self) -> &str {
        &self.enrolled_device_id
    }
}

impl RemoteIdEntry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn clear(&mut self) {
        self.text.clear();
    }

    pub fn backspace(&mut self) {
        self.text.pop();
    }

    /// Reject non-ASCII, controls, overlong and invalid characters without
    /// modifying the existing entry. Full canonical format is checked later.
    ///
    /// # Errors
    /// Returns `InvalidFormat` for invalid input or an overlong buffer.
    pub fn push(&mut self, character: char) -> Result<(), PublicDeviceIdError> {
        if !character.is_ascii()
            || !(character.is_ascii_digit()
                || ('A'..='F').contains(&character)
                || matches!(character, 'K' | 'M' | 'J' | '-'))
            || self.text.len() >= DEVICE_ID_LENGTH
        {
            return Err(PublicDeviceIdError::InvalidFormat);
        }
        self.text.push(character);
        Ok(())
    }

    /// Atomic paste: a rejected value leaves existing typed input unchanged.
    ///
    /// # Errors
    /// Rejects malformed, overlong, Unicode or otherwise noncanonical IDs.
    pub fn paste(&mut self, candidate: &str) -> Result<(), PublicDeviceIdError> {
        let id = PublicDeviceId::parse(candidate)?;
        self.text = id.as_str().to_owned();
        Ok(())
    }

    /// Resolve an enrolled trusted target. Does not initiate a connection.
    ///
    /// # Errors
    /// Rejects malformed/self/unknown/revoked/expired/ambiguous targets.
    pub fn select_trusted(
        &self,
        own_id: &PublicDeviceId,
        trusted: &TrustedDeviceStore,
        now_epoch_secs: u64,
    ) -> Result<SelectedRemoteTarget, PublicDeviceIdError> {
        let id = PublicDeviceId::parse(&self.text)?;
        id.require_remote(own_id)?;
        let record = id.resolve_trusted_peer(trusted, now_epoch_secs)?;
        Ok(SelectedRemoteTarget {
            id,
            enrolled_device_id: record.device_id.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trusted_device_store::{PersistedDeviceStatus, TrustedDeviceRecord};
    use ed25519_dalek::SigningKey;

    fn id_for(seed: u8) -> PublicDeviceId {
        let key = SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        PublicDeviceId::from_public_key(&key).unwrap()
    }

    #[test]
    fn keyboard_entry_matches_paste_and_is_bounded() {
        let id = id_for(7);
        let mut typed = RemoteIdEntry::new();
        for c in id.as_str().chars() {
            typed.push(c).unwrap();
        }
        let mut pasted = RemoteIdEntry::new();
        pasted.paste(id.as_str()).unwrap();
        assert_eq!(typed, pasted);
        assert_eq!(typed.text().len(), DEVICE_ID_LENGTH);
        assert_eq!(typed.push('A'), Err(PublicDeviceIdError::InvalidFormat));
        typed.backspace();
        assert_eq!(typed.text().len(), DEVICE_ID_LENGTH - 1);
        typed.push(id.as_str().chars().last().unwrap()).unwrap();
        assert_eq!(typed, pasted);
        typed.clear();
        assert!(typed.text().is_empty());
    }

    #[test]
    fn invalid_paste_and_control_input_cannot_mutate_valid_entry() {
        let id = id_for(7);
        let mut entry = RemoteIdEntry::new();
        entry.paste(id.as_str()).unwrap();
        for invalid in ["", "KMJ-abc", "KMJ-💻", "KMJ-\n", " KMJ-"] {
            assert_eq!(
                entry.paste(invalid),
                Err(PublicDeviceIdError::InvalidFormat)
            );
            assert_eq!(entry.text(), id.as_str());
        }
        for invalid in ['💻', '\n', 'a', ' '] {
            assert_eq!(entry.push(invalid), Err(PublicDeviceIdError::InvalidFormat));
            assert_eq!(entry.text(), id.as_str());
        }
    }

    #[test]
    fn cannot_select_untrusted_self_or_revoked_remote() {
        let own = id_for(7);
        let remote = id_for(8);
        let mut entry = RemoteIdEntry::new();
        let mut store = TrustedDeviceStore::new();
        entry.paste(own.as_str()).unwrap();
        assert_eq!(
            entry.select_trusted(&own, &store, 100).err(),
            Some(PublicDeviceIdError::OwnDevice)
        );
        entry.paste(remote.as_str()).unwrap();
        assert_eq!(
            entry.select_trusted(&own, &store, 100).err(),
            Some(PublicDeviceIdError::UntrustedPeer)
        );
        store
            .add(TrustedDeviceRecord {
                device_id: "remote-8".to_owned(),
                display_name: "Remote PC".to_owned(),
                public_key: SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
                enrolled_at_epoch_secs: 10,
                trust_expires_at_epoch_secs: 200,
                managed: false,
                revoked: false,
                status: PersistedDeviceStatus::Offline,
            })
            .unwrap();
        let selected = entry.select_trusted(&own, &store, 100).unwrap();
        assert_eq!(selected.public_id(), &remote);
        assert_eq!(selected.enrolled_device_id(), "remote-8");
        assert!(store.revoke("remote-8"));
        assert_eq!(
            entry.select_trusted(&own, &store, 100).err(),
            Some(PublicDeviceIdError::UntrustedPeer)
        );
    }
}
