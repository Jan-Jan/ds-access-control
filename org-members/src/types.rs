use core::fmt;

use unicode_normalization::UnicodeNormalization;
use unicode_security::GeneralSecurityProfile;
use unicode_security::MixedScript;

use crate::error::OrgMembersError;
use crate::normalize::to_nfc;

/// Maximum number of devices per member.
pub const MAX_DEVICES: usize = 4;

/// Validates a handle string and returns the NFC-normalized form.
///
/// Rules:
/// - Non-empty
/// - NFC normalized (applied automatically)
/// - All characters must be UTS#39 `GeneralSecurityProfile` allowed, or `-`
/// - No `.` characters
/// - No uppercase characters
/// - Single-script (no script mixing per UTS#39)
pub fn validate_handle(handle: &str) -> Result<String, OrgMembersError> {
    if handle.is_empty() {
        return Err(OrgMembersError::InvalidHandle(
            "handle must not be empty".into(),
        ));
    }

    let normalized: String = handle.nfc().collect();

    for ch in normalized.chars() {
        if ch.is_uppercase() {
            return Err(OrgMembersError::InvalidHandle(
                "handle must be lowercase".into(),
            ));
        }
        if ch == '.' {
            return Err(OrgMembersError::InvalidHandle(
                "handle must not contain '.'".into(),
            ));
        }
        if ch == '-' {
            continue;
        }
        if !ch.identifier_allowed() {
            return Err(OrgMembersError::InvalidHandle(format!(
                "character {:?} not allowed by UTS#39",
                ch
            )));
        }
    }

    if !normalized.is_single_script() {
        return Err(OrgMembersError::InvalidHandle(
            "handle must not mix scripts".into(),
        ));
    }

    Ok(normalized)
}

/// Derives a 32-byte member id from a validated handle string.
pub fn derive_id(handle: &str) -> [u8; 32] {
    blake3::hash(handle.as_bytes()).into()
}

/// Returns the UTS#39 skeleton form of a handle string.
/// Used to detect confusable/homoglyph handles.
pub fn handle_skeleton(handle: &str) -> String {
    use unicode_security::confusable_detection::skeleton;
    skeleton(handle).collect()
}

/// Returns the bit at the given index of a 32-byte key.
/// (0 = MSB of byte 0, 255 = LSB of byte 31).
/// Used for SMT path traversal.
pub fn bit_at(key: &[u8; 32], index: u16) -> bool {
    let byte_idx = (index / 8) as usize;
    let bit_idx = 7 - (index % 8);
    (key[byte_idx] >> bit_idx) & 1 == 1
}

/// Merkle root hash. 32-byte hash output.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RootHash(pub(crate) [u8; 32]);

impl RootHash {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RootHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RootHash({:02x}{:02x}{:02x}{:02x}..)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

/// Device slots for a member. Fixed depth-2 sub-trie (max 4 devices).
/// Devices are ed25519 public keys, stored sorted.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DeviceSlots {
    slots: Vec<[u8; 32]>,
}

impl DeviceSlots {
    pub fn new(mut devices: Vec<[u8; 32]>) -> Result<Self, OrgMembersError> {
        if devices.is_empty() {
            return Err(OrgMembersError::EmptyDeviceList);
        }
        if devices.len() > MAX_DEVICES {
            return Err(OrgMembersError::DeviceSlotsFull);
        }
        devices.sort();
        for i in 1..devices.len() {
            if devices[i] == devices[i - 1] {
                return Err(OrgMembersError::DuplicateDevice);
            }
        }
        Ok(Self { slots: devices })
    }

    pub fn devices(&self) -> &[[u8; 32]] {
        &self.slots
    }

    pub fn has_device(&self, ed25519_pk: &[u8; 32]) -> bool {
        self.slots.binary_search(ed25519_pk).is_ok()
    }

    pub fn device_count(&self) -> usize {
        self.slots.len()
    }

    pub fn add_device(&self, ed25519_pk: [u8; 32]) -> Result<Self, OrgMembersError> {
        if self.slots.len() >= MAX_DEVICES {
            return Err(OrgMembersError::DeviceSlotsFull);
        }
        if self.has_device(&ed25519_pk) {
            return Err(OrgMembersError::DuplicateDevice);
        }
        let mut new_slots = self.slots.clone();
        new_slots.push(ed25519_pk);
        new_slots.sort();
        Ok(Self { slots: new_slots })
    }

    pub fn remove_device(&self, ed25519_pk: &[u8; 32]) -> Result<Self, OrgMembersError> {
        let idx = self
            .slots
            .binary_search(ed25519_pk)
            .map_err(|_| OrgMembersError::DeviceNotFound)?;
        let mut new_slots = self.slots.clone();
        new_slots.remove(idx);
        if new_slots.is_empty() {
            return Err(OrgMembersError::EmptyDeviceList);
        }
        Ok(Self { slots: new_slots })
    }

    pub fn to_fixed_slots(&self) -> [Option<[u8; 32]>; MAX_DEVICES] {
        let mut fixed = [None; MAX_DEVICES];
        for (i, device) in self.slots.iter().enumerate() {
            fixed[i] = Some(*device);
        }
        fixed
    }
}

impl fmt::Debug for DeviceSlots {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceSlots({})", self.slots.len())
    }
}

/// A single member leaf in the trie. All PII fields are redacted in Debug.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MemberLeaf {
    /// Hash-derived identifier used as the SMT key.
    id: [u8; 32],
    /// Validated, NFC-normalized handle string (PII).
    handle: String,
    name: String,
    surname: String,
    group_pk: [u8; 32],
    devices: DeviceSlots,
}

impl MemberLeaf {
    /// Constructs a new member leaf.
    ///
    /// The handle is validated (UTS#39, lowercase, single-script, NFC)
    /// and the id is derived from it. Name and surname are NFC-normalized.
    pub fn new(
        handle: &str,
        name: &str,
        surname: &str,
        group_pk: [u8; 32],
        devices: Vec<[u8; 32]>,
    ) -> Result<Self, OrgMembersError> {
        let validated_handle = validate_handle(handle)?;
        let id = derive_id(&validated_handle);
        let device_slots = DeviceSlots::new(devices)?;
        Ok(Self {
            id,
            handle: validated_handle,
            name: to_nfc(name),
            surname: to_nfc(surname),
            group_pk,
            devices: device_slots,
        })
    }

    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    pub fn handle(&self) -> &str {
        &self.handle
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn surname(&self) -> &str {
        &self.surname
    }

    pub fn group_pk(&self) -> &[u8; 32] {
        &self.group_pk
    }

    pub fn devices(&self) -> &[[u8; 32]] {
        self.devices.devices()
    }

    pub fn has_device(&self, ed25519_pk: &[u8; 32]) -> bool {
        self.devices.has_device(ed25519_pk)
    }

    pub fn device_count(&self) -> usize {
        self.devices.device_count()
    }

    pub(crate) fn device_slots(&self) -> &DeviceSlots {
        &self.devices
    }

    /// Canonical byte encoding for hashing.
    pub fn canonical_bytes(&self, device_sub_trie_root: &[u8; 32]) -> Vec<u8> {
        let mut buf = Vec::new();
        // id: 32 bytes raw
        buf.extend_from_slice(&self.id);
        // handle_len + handle bytes
        let handle_bytes = self.handle.as_bytes();
        buf.extend_from_slice(&(handle_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(handle_bytes);
        // name_len + name bytes
        let name_bytes = self.name.as_bytes();
        buf.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(name_bytes);
        // surname_len + surname bytes
        let surname_bytes = self.surname.as_bytes();
        buf.extend_from_slice(&(surname_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(surname_bytes);
        // group_pk: 32 bytes raw
        buf.extend_from_slice(&self.group_pk);
        // device_sub_trie_root: 32 bytes raw
        buf.extend_from_slice(device_sub_trie_root);
        buf
    }
}

impl fmt::Debug for MemberLeaf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemberLeaf")
            .field("id", &format_args!("<32 bytes>"))
            .field("handle", &"[REDACTED]")
            .field("name", &"[REDACTED]")
            .field("surname", &"[REDACTED]")
            .field("group_pk", &format_args!("<32 bytes>"))
            .field("devices", &self.devices)
            .finish()
    }
}
