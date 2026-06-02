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

/// Maximum byte length of a handle (after NFC normalization). Caps memory
/// exposure from adversarial wire-format inputs. Email local-parts are
/// limited to 64 octets by RFC 5321; 128 leaves headroom for legitimate
/// non-ASCII handles after NFC expansion.
pub const MAX_HANDLE_LEN: usize = 128;

/// Maximum byte length of `name` after NFC normalization. Matches
/// `MAX_HANDLE_LEN` and is generous for typical names (KYC standards
/// cap at 50–100 chars; 128 bytes accommodates non-ASCII expansion).
pub const MAX_NAME_LEN: usize = 128;

/// Maximum byte length of `surname` after NFC normalization. See `MAX_NAME_LEN`.
pub const MAX_SURNAME_LEN: usize = 128;

/// Immutable member identifier. Used as the SMT key and as a stable reference
/// to a member regardless of changes to their handle or p2p key.
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
    ///
    /// **Uniqueness is the caller's responsibility.** Two members independently
    /// constructed with the same byte pattern (including `[0u8; 32]`) will
    /// collide -- `add_member` will reject the second one with `DuplicateId`,
    /// but the situation should be avoided. Don't hard-code id values.
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

/// A member's ed25519 public key. In the local-first collaboration layer this
/// represents the member as a single principal (the "member-as-a-group" key):
/// when an Organisation grants access to a member, that grant is encoded
/// against this key, and the member's devices share access derived from it.
/// Can change over time (e.g., upon device rotation or compromise) -- distinct
/// from the immutable `MemberId`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct P2pMemberKey(VerifyingKey);

impl P2pMemberKey {
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

impl PartialOrd for P2pMemberKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for P2pMemberKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl fmt::Debug for P2pMemberKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.as_bytes();
        write!(f, "P2pMemberKey({:02x}{:02x}{:02x}{:02x}..)", b[0], b[1], b[2], b[3])
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for P2pMemberKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.as_bytes().serialize(s)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for P2pMemberKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = <[u8; 32]>::deserialize(d)?;
        let vk = VerifyingKey::from_bytes(&bytes).map_err(serde::de::Error::custom)?;
        Ok(Self(vk))
    }
}

/// A device's ed25519 public key. Serves as both the device's identity and
/// signing key. (For devices, key and id are the same thing.)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct P2pDeviceKey(VerifyingKey);

impl P2pDeviceKey {
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

impl PartialOrd for P2pDeviceKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for P2pDeviceKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl fmt::Debug for P2pDeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.as_bytes();
        write!(f, "P2pDeviceKey({:02x}{:02x}{:02x}{:02x}..)", b[0], b[1], b[2], b[3])
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for P2pDeviceKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.as_bytes().serialize(s)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for P2pDeviceKey {
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

    if normalized.len() > MAX_HANDLE_LEN {
        return Err(OrgMembersError::InvalidHandle(format!(
            "handle exceeds {} bytes after NFC normalization",
            MAX_HANDLE_LEN
        )));
    }

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

/// A 32-byte hash output. The fundamental hash unit produced by the
/// `TrieHasher` trait -- used for member leaf hashes, internal node hashes,
/// device leaf hashes, and device internal node hashes.
///
/// Distinct from `RootHash` for type safety: a `NodeHash` is the hash of some
/// subtree; a `RootHash` is the externally-meaningful root of the whole org
/// trie. They share the same byte representation but the distinction prevents
/// accidentally using an intermediate hash where a root hash is expected.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NodeHash(pub(crate) [u8; 32]);

impl NodeHash {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for NodeHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NodeHash({:02x}{:02x}{:02x}{:02x}..)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

/// The externally-meaningful root of an org trie. Wraps the same bytes as
/// `NodeHash` but is type-distinct: only the trie root is a `RootHash`,
/// intermediate node hashes are `NodeHash`.
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

impl From<NodeHash> for RootHash {
    fn from(h: NodeHash) -> Self {
        Self(h.0)
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
/// Devices are ed25519 public keys, stored sorted and deduplicated.
/// The serde wire form is canonical (strictly increasing); non-canonical
/// encodings are rejected on deserialize.
#[derive(Clone, PartialEq, Eq)]
pub struct P2pDeviceSlots {
    slots: Vec<P2pDeviceKey>,
}

#[cfg(feature = "serde")]
impl serde::Serialize for P2pDeviceSlots {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.slots.serialize(s)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for P2pDeviceSlots {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let slots = Vec::<P2pDeviceKey>::deserialize(d)?;
        // Reject (do not normalize) non-canonical wire forms so postcard bytes
        // have a unique encoding per logical device set. See Hyperbridge S1-16
        // (proof canonicality) and review finding H-2.
        if slots.len() > MAX_DEVICES {
            return Err(serde::de::Error::custom("device slots exceed MAX_DEVICES"));
        }
        for pair in slots.windows(2) {
            if pair[0] >= pair[1] {
                return Err(serde::de::Error::custom(
                    "device slots must be strictly increasing (sorted, no duplicates)",
                ));
            }
        }
        // Empty is still allowed (isolated state).
        Ok(Self { slots })
    }
}

impl P2pDeviceSlots {
    /// Constructs a P2pDeviceSlots from a list of device keys.
    /// Accepts 0..=MAX_DEVICES devices: an empty list is allowed because
    /// `emergency_isolate_member` produces a member with zero devices. Normal
    /// member creation (via `MemberLeaf::new`) requires ≥1 device.
    pub fn new(mut devices: Vec<P2pDeviceKey>) -> Result<Self, OrgMembersError> {
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

    pub fn devices(&self) -> &[P2pDeviceKey] {
        &self.slots
    }

    pub fn has_device(&self, device: &P2pDeviceKey) -> bool {
        self.slots.binary_search(device).is_ok()
    }

    pub fn device_count(&self) -> usize {
        self.slots.len()
    }

    /// Adds a device. Crate-private because external code must go through
    /// `OrgTrie::add_p2p_device`, which has the correct atomicity guarantees.
    pub(crate) fn add_device(&self, device: P2pDeviceKey) -> Result<Self, OrgMembersError> {
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

    /// Removes a device. Crate-private because external code must go through
    /// `OrgTrie::delete_p2p_device`, which requires a `new_p2p_key` to be
    /// supplied in the same call (the deleted device had access to the old
    /// key). Exposing this directly would let callers bypass the rotation.
    pub(crate) fn remove_device(&self, device: &P2pDeviceKey) -> Result<Self, OrgMembersError> {
        let idx = self
            .slots
            .binary_search(device)
            .map_err(|_| OrgMembersError::DeviceNotFound)?;
        let mut new_slots = self.slots.clone();
        new_slots.remove(idx);
        // Empty is allowed: removing the last device leaves the member in an
        // isolated state (no devices). Callers that need to enforce ≥1 should
        // check the result.
        Ok(Self { slots: new_slots })
    }

    /// Internal helper: returns the slot array padded with None up to MAX_DEVICES.
    /// Used by the device sub-trie hash computation.
    pub(crate) fn to_fixed_slots(&self) -> [Option<P2pDeviceKey>; MAX_DEVICES] {
        let mut fixed = [None; MAX_DEVICES];
        for (i, device) in self.slots.iter().enumerate() {
            fixed[i] = Some(*device);
        }
        fixed
    }
}

impl fmt::Debug for P2pDeviceSlots {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "P2pDeviceSlots({})", self.slots.len())
    }
}

/// A single member leaf in the trie. All PII fields are redacted in Debug.
#[derive(Clone, PartialEq, Eq)]
pub struct MemberLeaf {
    /// Immutable member id. Used as the SMT key.
    id: MemberId,
    /// Validated, NFC-normalized handle string (PII). Can change rarely.
    handle: String,
    /// The member's peer-to-peer key -- the "member-as-a-group" key used by
    /// the local-first software to grant access at the member level. Can
    /// change over time. Future versions may also add an on-chain key.
    p2p_key: P2pMemberKey,
    name: String,
    surname: String,
    p2p_devices: P2pDeviceSlots,
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct MemberLeafSerde {
    id: MemberId,
    handle: String,
    p2p_key: P2pMemberKey,
    name: String,
    surname: String,
    p2p_devices: P2pDeviceSlots,
}

#[cfg(feature = "serde")]
impl serde::Serialize for MemberLeaf {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        MemberLeafSerde {
            id: self.id,
            handle: self.handle.clone(),
            p2p_key: self.p2p_key,
            name: self.name.clone(),
            surname: self.surname.clone(),
            p2p_devices: self.p2p_devices.clone(),
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
        let name = to_nfc(&raw.name);
        if name.len() > MAX_NAME_LEN {
            return Err(serde::de::Error::custom(
                OrgMembersError::FieldTooLong { field: "name", max: MAX_NAME_LEN },
            ));
        }
        let surname = to_nfc(&raw.surname);
        if surname.len() > MAX_SURNAME_LEN {
            return Err(serde::de::Error::custom(
                OrgMembersError::FieldTooLong { field: "surname", max: MAX_SURNAME_LEN },
            ));
        }
        Ok(Self {
            id: raw.id,
            handle: validated_handle,
            p2p_key: raw.p2p_key,
            name,
            surname,
            p2p_devices: raw.p2p_devices,
        })
    }
}

impl MemberLeaf {
    /// Constructs a new member leaf.
    ///
    /// The handle is validated (UTS#39, lowercase, single-script, NFC).
    /// Name and surname are NFC-normalized. Requires ≥1 device -- new members
    /// must have at least one device. (An existing member can be reduced to
    /// zero devices via `emergency_isolate_member` on the trie.)
    pub fn new(
        id: MemberId,
        handle: &str,
        p2p_key: P2pMemberKey,
        name: &str,
        surname: &str,
        p2p_devices: Vec<P2pDeviceKey>,
    ) -> Result<Self, OrgMembersError> {
        if p2p_devices.is_empty() {
            return Err(OrgMembersError::EmptyDeviceList);
        }
        let validated_handle = validate_handle(handle)?;
        let nfc_name = to_nfc(name);
        if nfc_name.len() > MAX_NAME_LEN {
            return Err(OrgMembersError::FieldTooLong { field: "name", max: MAX_NAME_LEN });
        }
        let nfc_surname = to_nfc(surname);
        if nfc_surname.len() > MAX_SURNAME_LEN {
            return Err(OrgMembersError::FieldTooLong { field: "surname", max: MAX_SURNAME_LEN });
        }
        let device_slots = P2pDeviceSlots::new(p2p_devices)?;
        Ok(Self {
            id,
            handle: validated_handle,
            p2p_key,
            name: nfc_name,
            surname: nfc_surname,
            p2p_devices: device_slots,
        })
    }

    // === Crate-private field modifiers ===
    //
    // These produce modified copies of `self`. They bypass MemberLeaf::new's
    // invariants and are intended for use by the trie's domain operations
    // (update_name_surname, update_handle, rotate_p2p_key, add/delete p2p_device,
    // emergency_isolate_member). They do NOT validate the handle -- callers
    // must validate before calling `with_handle`.

    pub(crate) fn with_name_surname(mut self, name: String, surname: String) -> Self {
        self.name = name;
        self.surname = surname;
        self
    }

    pub(crate) fn with_handle(mut self, validated_handle: String) -> Self {
        self.handle = validated_handle;
        self
    }

    pub(crate) fn with_p2p_key(mut self, key: P2pMemberKey) -> Self {
        self.p2p_key = key;
        self
    }

    pub(crate) fn with_p2p_device_slots(mut self, slots: P2pDeviceSlots) -> Self {
        self.p2p_devices = slots;
        self
    }

    pub fn id(&self) -> &MemberId {
        &self.id
    }

    pub fn p2p_key(&self) -> &P2pMemberKey {
        &self.p2p_key
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

    pub fn p2p_devices(&self) -> &[P2pDeviceKey] {
        self.p2p_devices.devices()
    }

    pub fn has_p2p_device(&self, device: &P2pDeviceKey) -> bool {
        self.p2p_devices.has_device(device)
    }

    pub fn p2p_device_count(&self) -> usize {
        self.p2p_devices.device_count()
    }

    pub(crate) fn p2p_device_slots(&self) -> &P2pDeviceSlots {
        &self.p2p_devices
    }

    /// Canonical byte encoding for hashing. Crate-private because external
    /// callers cannot meaningfully compute `p2p_device_sub_trie_root` without
    /// invoking internal device-trie hashing -- exposing this would invite
    /// callers to produce bytes that don't match what the trie actually hashes.
    pub(crate) fn canonical_bytes(&self, p2p_device_sub_trie_root: &NodeHash) -> Vec<u8> {
        let mut buf = Vec::new();
        // id: 32 bytes raw
        buf.extend_from_slice(self.id.as_bytes());
        // handle_len + handle bytes
        let handle_bytes = self.handle.as_bytes();
        buf.extend_from_slice(&(handle_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(handle_bytes);
        // p2p_key: 32 bytes raw
        buf.extend_from_slice(self.p2p_key.as_bytes());
        // name_len + name bytes
        let name_bytes = self.name.as_bytes();
        buf.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(name_bytes);
        // surname_len + surname bytes
        let surname_bytes = self.surname.as_bytes();
        buf.extend_from_slice(&(surname_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(surname_bytes);
        // p2p_device_sub_trie_root: 32 bytes raw
        buf.extend_from_slice(p2p_device_sub_trie_root.as_bytes());
        buf
    }
}

impl fmt::Debug for MemberLeaf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemberLeaf")
            .field("id", &self.id)
            .field("handle", &"[REDACTED]")
            .field("p2p_key", &self.p2p_key)
            .field("name", &"[REDACTED]")
            .field("surname", &"[REDACTED]")
            .field("p2p_devices", &self.p2p_devices)
            .finish()
    }
}
