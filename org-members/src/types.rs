use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use ed25519_dalek::VerifyingKey;
use unicode_normalization::UnicodeNormalization;
use unicode_security::GeneralSecurityProfile;
use unicode_security::MixedScript;

use crate::error::OrgMembersError;
use crate::normalize::to_nfc;

/// Maximum number of devices per member.
pub const MAX_DEVICES: usize = 4;

/// Immutable member identifier. Used as the SMT key and as a stable reference
/// to a member regardless of changes to their handle or CGKA key.
///
/// The 32 bytes are opaque -- the caller is responsible for generating unique,
/// immutable values (e.g., random bytes, or a hash of a stable input).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MemberId(pub(crate) [u8; 32]);

impl MemberId {
    /// Wraps 32 opaque bytes as a member id.
    ///
    /// The library does NOT validate these bytes -- the caller is responsible
    /// for ensuring ids are unique within the organisation and effectively
    /// random (so the SMT tree stays well-distributed across the 256-bit
    /// keyspace). Suggested generators: cryptographic random bytes, or a hash
    /// of a stable per-member input (e.g. an enrollment artifact).
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the bit at the given index (0 = MSB of byte 0, 255 = LSB of byte 31).
    /// Used for SMT path traversal.
    pub fn bit(&self, index: u16) -> bool {
        let byte_idx = (index / 8) as usize;
        let bit_idx = 7 - (index % 8);
        (self.0[byte_idx] >> bit_idx) & 1 == 1
    }
}

impl fmt::Debug for MemberId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MemberId({:02x}{:02x}{:02x}{:02x}..)", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

/// A member's ed25519 public key, used for CGKA (Continuous Group Key Agreement)
/// by the local-first collaboration layer. Can change over time (e.g., upon
/// device rotation or key compromise) -- distinct from the immutable `MemberId`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemberKey(VerifyingKey);

impl MemberKey {
    pub fn new(key: VerifyingKey) -> Self {
        Self(key)
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl PartialOrd for MemberKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MemberKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl fmt::Debug for MemberKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.as_bytes();
        write!(f, "MemberKey({:02x}{:02x}{:02x}{:02x}..)", b[0], b[1], b[2], b[3])
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for MemberKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.as_bytes().serialize(s)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for MemberKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = <[u8; 32]>::deserialize(d)?;
        let vk = VerifyingKey::from_bytes(&bytes).map_err(serde::de::Error::custom)?;
        Ok(Self(vk))
    }
}

/// A device's ed25519 public key. Serves as both the device's identity and
/// signing key. (For devices, key and id are the same thing.)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceKey(VerifyingKey);

impl DeviceKey {
    pub fn new(key: VerifyingKey) -> Self {
        Self(key)
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl PartialOrd for DeviceKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DeviceKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.as_bytes();
        write!(f, "DeviceKey({:02x}{:02x}{:02x}{:02x}..)", b[0], b[1], b[2], b[3])
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for DeviceKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.as_bytes().serialize(s)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for DeviceKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = <[u8; 32]>::deserialize(d)?;
        let vk = VerifyingKey::from_bytes(&bytes).map_err(serde::de::Error::custom)?;
        Ok(Self(vk))
    }
}

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
            "handle must not be empty".to_string(),
        ));
    }

    let normalized: String = handle.nfc().collect();

    for ch in normalized.chars() {
        if ch.is_uppercase() {
            return Err(OrgMembersError::InvalidHandle(
                "handle must be lowercase".to_string(),
            ));
        }
        if ch == '.' {
            return Err(OrgMembersError::InvalidHandle(
                "handle must not contain '.'".to_string(),
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
            "handle must not mix scripts".to_string(),
        ));
    }

    Ok(normalized)
}

/// Returns the UTS#39 skeleton form of a handle string.
/// Used to detect confusable/homoglyph handles.
pub fn handle_skeleton(handle: &str) -> String {
    use unicode_security::confusable_detection::skeleton;
    skeleton(handle).collect()
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
pub struct DeviceSlots {
    slots: Vec<DeviceKey>,
}

#[cfg(feature = "serde")]
impl serde::Serialize for DeviceSlots {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.slots.serialize(s)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for DeviceSlots {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let slots = Vec::<DeviceKey>::deserialize(d)?;
        // Re-run constructor validation so an attacker-supplied wire format
        // cannot bypass invariants (empty list, exceeds MAX_DEVICES, duplicates,
        // unsorted). `DeviceSlots::new` sorts and checks all of these.
        DeviceSlots::new(slots).map_err(serde::de::Error::custom)
    }
}

impl DeviceSlots {
    pub fn new(mut devices: Vec<DeviceKey>) -> Result<Self, OrgMembersError> {
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

    pub fn devices(&self) -> &[DeviceKey] {
        &self.slots
    }

    pub fn has_device(&self, device: &DeviceKey) -> bool {
        self.slots.binary_search(device).is_ok()
    }

    pub fn device_count(&self) -> usize {
        self.slots.len()
    }

    pub fn add_device(&self, device: DeviceKey) -> Result<Self, OrgMembersError> {
        if self.slots.len() >= MAX_DEVICES {
            return Err(OrgMembersError::DeviceSlotsFull);
        }
        if self.has_device(&device) {
            return Err(OrgMembersError::DuplicateDevice);
        }
        let mut new_slots = self.slots.clone();
        new_slots.push(device);
        new_slots.sort();
        Ok(Self { slots: new_slots })
    }

    pub fn remove_device(&self, device: &DeviceKey) -> Result<Self, OrgMembersError> {
        let idx = self
            .slots
            .binary_search(device)
            .map_err(|_| OrgMembersError::DeviceNotFound)?;
        let mut new_slots = self.slots.clone();
        new_slots.remove(idx);
        if new_slots.is_empty() {
            return Err(OrgMembersError::EmptyDeviceList);
        }
        Ok(Self { slots: new_slots })
    }

    pub fn to_fixed_slots(&self) -> [Option<DeviceKey>; MAX_DEVICES] {
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
pub struct MemberLeaf {
    /// Immutable member id. Used as the SMT key.
    id: MemberId,
    /// Validated, NFC-normalized handle string (PII). Can change rarely.
    handle: String,
    /// The member's CGKA key. Can change over time.
    key: MemberKey,
    name: String,
    surname: String,
    group_pk: [u8; 32],
    devices: DeviceSlots,
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct MemberLeafSerde {
    id: MemberId,
    handle: String,
    key: MemberKey,
    name: String,
    surname: String,
    group_pk: [u8; 32],
    devices: DeviceSlots,
}

#[cfg(feature = "serde")]
impl serde::Serialize for MemberLeaf {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        MemberLeafSerde {
            id: self.id,
            handle: self.handle.clone(),
            key: self.key,
            name: self.name.clone(),
            surname: self.surname.clone(),
            group_pk: self.group_pk,
            devices: self.devices.clone(),
        }
        .serialize(s)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for MemberLeaf {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = MemberLeafSerde::deserialize(d)?;
        // Re-validate the handle so an attacker-supplied wire format cannot
        // bypass NFC normalization, lowercase, single-script, no-`.`, or UTS#39
        // restrictions. `validate_handle` also returns the NFC-normalized form,
        // so the stored handle is canonical even if the wire payload wasn't.
        let validated_handle = validate_handle(&raw.handle).map_err(serde::de::Error::custom)?;
        // Normalize name and surname to NFC for hash determinism.
        let name = to_nfc(&raw.name);
        let surname = to_nfc(&raw.surname);
        Ok(Self {
            id: raw.id,
            handle: validated_handle,
            key: raw.key,
            name,
            surname,
            group_pk: raw.group_pk,
            devices: raw.devices,
        })
    }
}

impl MemberLeaf {
    /// Constructs a new member leaf.
    ///
    /// The handle is validated (UTS#39, lowercase, single-script, NFC).
    /// Name and surname are NFC-normalized.
    pub fn new(
        id: MemberId,
        handle: &str,
        key: MemberKey,
        name: &str,
        surname: &str,
        group_pk: [u8; 32],
        devices: Vec<DeviceKey>,
    ) -> Result<Self, OrgMembersError> {
        let validated_handle = validate_handle(handle)?;
        let device_slots = DeviceSlots::new(devices)?;
        Ok(Self {
            id,
            handle: validated_handle,
            key,
            name: to_nfc(name),
            surname: to_nfc(surname),
            group_pk,
            devices: device_slots,
        })
    }

    pub fn id(&self) -> &MemberId {
        &self.id
    }

    pub fn key(&self) -> &MemberKey {
        &self.key
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

    pub fn devices(&self) -> &[DeviceKey] {
        self.devices.devices()
    }

    pub fn has_device(&self, device: &DeviceKey) -> bool {
        self.devices.has_device(device)
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
        buf.extend_from_slice(self.id.as_bytes());
        // handle_len + handle bytes
        let handle_bytes = self.handle.as_bytes();
        buf.extend_from_slice(&(handle_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(handle_bytes);
        // member key: 32 bytes raw
        buf.extend_from_slice(self.key.as_bytes());
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
            .field("id", &self.id)
            .field("handle", &"[REDACTED]")
            .field("key", &self.key)
            .field("name", &"[REDACTED]")
            .field("surname", &"[REDACTED]")
            .field("group_pk", &format_args!("<32 bytes>"))
            .field("devices", &self.devices)
            .finish()
    }
}
