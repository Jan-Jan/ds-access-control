use core::fmt;

use crate::error::OrgMembersError;
use crate::normalize::to_nfc;

/// Reserved handle value (all zeros). Cannot be used as a member handle.
pub const RESERVED_HANDLE: [u8; 32] = [0u8; 32];

/// Maximum number of devices per member.
pub const MAX_DEVICES: usize = 4;

/// 32-byte opaque member identifier. Unique within an org.
/// This is PII -- Debug output is redacted.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Handle(pub(crate) [u8; 32]);

impl Handle {
    pub fn new(bytes: [u8; 32]) -> Result<Self, OrgMembersError> {
        if bytes == RESERVED_HANDLE {
            return Err(OrgMembersError::ReservedHandle);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the bit at the given index (0 = MSB of byte 0, 255 = LSB of byte 31).
    /// Used for SMT path traversal.
    pub fn bit(&self, index: u8) -> bool {
        let byte_idx = (index / 8) as usize;
        let bit_idx = 7 - (index % 8);
        (self.0[byte_idx] >> bit_idx) & 1 == 1
    }
}

impl fmt::Debug for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Handle([REDACTED])")
    }
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
        // Check for duplicates after sorting
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

    /// Returns the 4 slots for the depth-2 sub-trie (padded with None for empty slots).
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
    handle: Handle,
    name: String,
    surname: String,
    group_pk: [u8; 32],
    devices: DeviceSlots,
}

impl MemberLeaf {
    /// Constructs a new member leaf. Name and surname are NFC-normalized.
    pub fn new(
        handle: Handle,
        name: &str,
        surname: &str,
        group_pk: [u8; 32],
        devices: Vec<[u8; 32]>,
    ) -> Result<Self, OrgMembersError> {
        let device_slots = DeviceSlots::new(devices)?;
        Ok(Self {
            handle,
            name: to_nfc(name),
            surname: to_nfc(surname),
            group_pk,
            devices: device_slots,
        })
    }

    pub fn handle(&self) -> &Handle {
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
        // handle: 32 bytes raw
        buf.extend_from_slice(&self.handle.0);
        // name_len: 4 bytes LE u32, then name bytes
        let name_bytes = self.name.as_bytes();
        buf.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(name_bytes);
        // surname_len: 4 bytes LE u32, then surname bytes
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
            .field("handle", &"[REDACTED]")
            .field("name", &"[REDACTED]")
            .field("surname", &"[REDACTED]")
            .field("group_pk", &format_args!("<32 bytes>"))
            .field("devices", &self.devices)
            .finish()
    }
}
