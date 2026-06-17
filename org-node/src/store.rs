//! Encrypted-at-rest persistence for personas and org records (spec §4.2–4.5).
//! PoC simplification S9: passphrase-derived key, not OS keychain.
use std::path::PathBuf;

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::ids::OrgId;
use crate::OrgNodeError;

/// A locally-held identity, one per org (spec §4.2). Keys stored as 32-byte seeds.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersonaRecord {
    pub persona_id: String,
    pub org_id: Option<OrgId>,
    pub handle: String,
    pub name: String,
    pub surname: String,
    pub member_seed: [u8; 32],
    pub device_seed: [u8; 32],
    pub member_id: Option<[u8; 32]>,
    pub status: PersonaStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersonaStatus {
    Proposed,
    Active,
    Revoked,
}

/// A member's local view of an org (spec §4.3).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrgRecord {
    pub org_id: OrgId,
    pub root_hash: [u8; 32],
    pub org_pub_key: [u8; 32],
    pub epoch: u64,
    pub org_secret: Option<[u8; 32]>,
    pub last_seq: u64,
    pub admin_member_key: [u8; 32],
    pub trie_members: Vec<MemberSnapshot>,
    /// Pure-proxy AccountId32 `P` persisted at genesis so `submit_update` can
    /// build the `proxied(P, ...)` call after a restart.  `None` on member-side
    /// records (only the admin that called `create_organisation` stores P).
    /// Defaults to `None` so stores written before this field was added still
    /// decode correctly.
    #[serde(default)]
    pub proxy_account: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberSnapshot {
    pub id: [u8; 32],
    pub handle: String,
    pub name: String,
    pub surname: String,
    pub member_key: [u8; 32],
    pub device_keys: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StoreData {
    pub personas: Vec<PersonaRecord>,
    pub orgs: Vec<OrgRecord>,
    /// Invites imported by B before first admission.  Keyed by org_id so
    /// `receive_and_verify` can cross-check the sender's device key against
    /// the admin_device_key the invite asserts.  Cleared after first commit.
    pub pending_invites: Vec<PendingInvite>,
}

/// Minimal fields from an `Invite` that must survive store round-trips.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingInvite {
    pub org_id: crate::ids::OrgId,
    pub admin_device_key: [u8; 32],
    pub admin_member_key: [u8; 32],
    pub org_pub_key: [u8; 32],
}

/// Encrypted file store. On-disk layout: `nonce(24) ‖ ciphertext`.
pub struct PersonaStore {
    path: PathBuf,
    key: XChaCha20Poly1305,
    data: StoreData,
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], OrgNodeError> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| OrgNodeError::Chain(format!("kdf failed: {e}")))?;
    Ok(key)
}

impl PersonaStore {
    /// Open or create a store at `path` using `passphrase`.
    /// PoC uses a fixed application salt constant (simplification S9).
    pub fn open(path: PathBuf, passphrase: &str) -> Result<Self, OrgNodeError> {
        // 32-byte fixed app salt — PoC simplification S9.
        const APP_SALT: &[u8] = b"ods-phase2-personastore-v1______";
        let key_bytes = derive_key(passphrase, APP_SALT)?;
        let key = XChaCha20Poly1305::new_from_slice(&key_bytes)
            .map_err(|e| OrgNodeError::Chain(format!("bad key length: {e}")))?;
        let data = if path.exists() {
            let blob =
                std::fs::read(&path).map_err(|e| OrgNodeError::Chain(e.to_string()))?;
            if blob.len() < 24 {
                return Err(OrgNodeError::Chain("store file too short".into()));
            }
            let (nonce_bytes, ct) = blob.split_at(24);
            let pt = key
                .decrypt(XNonce::from_slice(nonce_bytes), ct)
                .map_err(|_| {
                    OrgNodeError::Chain("decrypt failed (wrong passphrase?)".into())
                })?;
            postcard::from_bytes(&pt)
                .map_err(|e| OrgNodeError::Chain(format!("store decode: {e}")))?
        } else {
            StoreData::default()
        };
        Ok(Self { path, key, data })
    }

    pub fn data(&self) -> &StoreData {
        &self.data
    }

    pub fn data_mut(&mut self) -> &mut StoreData {
        &mut self.data
    }

    /// Encrypt and write the store. Generates a fresh 24-byte random nonce per save.
    pub fn save<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<(), OrgNodeError> {
        let mut nonce = [0u8; 24];
        rng.fill_bytes(&mut nonce);
        let pt = postcard::to_allocvec(&self.data)
            .map_err(|e| OrgNodeError::Chain(format!("store encode: {e}")))?;
        let ct = self
            .key
            .encrypt(XNonce::from_slice(&nonce), pt.as_slice())
            .map_err(|e| OrgNodeError::Chain(format!("encrypt failed: {e}")))?;
        let mut out = Vec::with_capacity(24 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        std::fs::write(&self.path, out).map_err(|e| OrgNodeError::Chain(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn round_trips_encrypted_through_disk() {
        let dir =
            std::env::temp_dir().join(format!("ods-store-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.bin");
        let _ = std::fs::remove_file(&path);

        let mut s = PersonaStore::open(path.clone(), "hunter2").unwrap();
        s.data_mut().personas.push(PersonaRecord {
            persona_id: "p1".into(),
            org_id: None,
            handle: "alice".into(),
            name: "A".into(),
            surname: "U".into(),
            member_seed: [1u8; 32],
            device_seed: [2u8; 32],
            member_id: None,
            status: PersonaStatus::Proposed,
        });
        s.save(&mut OsRng).unwrap();

        // Reopen with the correct passphrase.
        let s2 = PersonaStore::open(path.clone(), "hunter2").unwrap();
        assert_eq!(s2.data().personas.len(), 1);
        assert_eq!(s2.data().personas[0].handle, "alice");

        // Wrong passphrase must fail.
        assert!(PersonaStore::open(path.clone(), "wrong").is_err());

        let _ = std::fs::remove_file(&path);
    }
}
