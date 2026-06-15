//! Model-based conformance test: replays membership traces generated from
//! `quint/membership_mbt.qnt` against the real `OrgTrie`, asserting that the
//! crate's Ok/Err results AND its root-hash equality classes match the model.
//!
//! Requires the `quint` CLI on PATH. Gated so a plain `cargo test` without
//! quint installed does not fail to build the binary but skips at runtime.

use quint_connect::*;
use serde::Deserialize;

use anyhow::anyhow;
use ed25519_dalek::SigningKey;
use org_members::hasher::Blake3Hasher;
use org_members::trie::OrgTrie;
use org_members::types::{MemberId, MemberLeaf, P2pDeviceKey, P2pMemberKey};
use org_members::OrgMembersError;
use std::collections::{BTreeMap, BTreeSet};

type Trie = OrgTrie<Blake3Hasher>;

const IDS: [&str; 3] = ["a", "b", "c"];
const GENS: [i64; 3] = [0, 1, 2];

/// Mirror of the Quint `Key` record.
//
// `Ord`/`PartialOrd` added beyond the original skeleton: `Leaf.devices` is a
// `BTreeSet<Key>`, and `BTreeSet<T>: Deserialize` requires `T: Ord`.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Deserialize, Debug, serde::Serialize)]
struct Key {
    owner: String,
    gen: i64,
}

/// Mirror of the Quint `Leaf` record.
#[derive(Clone, Eq, PartialEq, Deserialize, Debug, serde::Serialize)]
struct Leaf {
    id: String,
    handle: String,
    skeleton: String,
    name: String,
    surname: String,
    #[serde(rename = "pKey")]
    p_key: Key,
    devices: std::collections::BTreeSet<Key>,
}

/// The verifiable model state: the trie (id -> leaf) and the last error tag.
#[derive(Eq, PartialEq, Deserialize, Debug)]
struct MembershipState {
    trie: std::collections::BTreeMap<String, Leaf>,
    #[serde(rename = "lastError")]
    last_error: String,
}

fn real_id(model_id: &str) -> MemberId {
    MemberId::new(blake3::hash(format!("id:{model_id}").as_bytes()).into())
}
fn real_member_key(k: &Key) -> P2pMemberKey {
    let seed: [u8; 32] = blake3::hash(format!("mk:{}:{}", k.owner, k.gen).as_bytes()).into();
    P2pMemberKey::new(SigningKey::from_bytes(&seed).verifying_key())
}
fn real_device_key(k: &Key) -> P2pDeviceKey {
    let seed: [u8; 32] = blake3::hash(format!("dk:{}:{}", k.owner, k.gen).as_bytes()).into();
    P2pDeviceKey::new(SigningKey::from_bytes(&seed).verifying_key())
}

// --- inverse maps (domains are tiny, so brute force) ---
fn model_id_of(id: &MemberId) -> Option<String> {
    IDS.iter().find(|m| real_id(m) == *id).map(|m| m.to_string())
}
fn gen_of_member_key(owner: &str, key: &P2pMemberKey) -> Option<i64> {
    GENS.iter().copied().find(|g| {
        real_member_key(&Key {
            owner: owner.to_string(),
            gen: *g,
        }) == *key
    })
}
fn model_device_of(owner: &str, d: &P2pDeviceKey) -> Option<Key> {
    GENS.iter()
        .copied()
        .find(|g| {
            real_device_key(&Key {
                owner: owner.to_string(),
                gen: *g,
            }) == *d
        })
        .map(|g| Key {
            owner: owner.to_string(),
            gen: g,
        })
}

/// Map a crate error to the model's error tag (model collapses all handle
/// collisions to "ConfusableHandle"). Unmapped -> "Other:<debug>" forces a
/// visible mismatch.
fn err_tag(e: &OrgMembersError) -> String {
    match e {
        OrgMembersError::IdNotFound => "IdNotFound",
        OrgMembersError::DuplicateId => "DuplicateId",
        OrgMembersError::ConfusableHandle => "ConfusableHandle",
        OrgMembersError::DuplicateHandle => "ConfusableHandle",
        OrgMembersError::DuplicateDevice => "DuplicateDevice",
        OrgMembersError::DeviceNotFound => "DeviceNotFound",
        OrgMembersError::DeviceSlotsFull => "DeviceSlotsFull",
        OrgMembersError::EmptyDeviceList => "EmptyDeviceList",
        OrgMembersError::DeltaBaseMismatch => "DeltaBaseMismatch",
        other => return format!("Other:{other:?}"),
    }
    .to_string()
}

#[derive(Default)]
struct MembershipDriver {
    trie: Option<Trie>,
    last_error: String,
    // root-hash equality classes: canonical model-state bytes -> root hex
    root_classes: std::collections::HashMap<Vec<u8>, String>,
}

impl MembershipDriver {
    fn commit(&mut self, res: core::result::Result<Trie, OrgMembersError>) {
        match res {
            Ok(t) => {
                // Mutations leave the trie with uncalculated hashes; recalculate
                // so `root_hash()` succeeds. This does not change observable
                // model state (member contents), only fills the hash cache.
                let t = match t.recalculate() {
                    Ok((t2, _delta)) => t2,
                    Err(_) => t,
                };
                self.trie = Some(t);
                self.last_error = String::new();
            }
            Err(e) => {
                self.last_error = err_tag(&e);
            }
        }
    }

    fn cur(&self) -> core::result::Result<Trie, OrgMembersError> {
        self.trie.clone().ok_or(OrgMembersError::IdNotFound)
    }

    /// Reconstruct the model trie from the real OrgTrie via inverse maps.
    fn model_trie(&self) -> Result<BTreeMap<String, Leaf>> {
        let mut out = BTreeMap::new();
        if let Some(t) = &self.trie {
            for m in t.members() {
                let mid = model_id_of(m.id()).ok_or_else(|| anyhow!("unknown member id"))?;
                let gen = gen_of_member_key(&mid, m.p2p_key())
                    .ok_or_else(|| anyhow!("unknown member key gen for {mid}"))?;
                let mut devices = BTreeSet::new();
                for d in m.p2p_devices() {
                    devices.insert(
                        model_device_of(&mid, d)
                            .ok_or_else(|| anyhow!("unknown device for {mid}"))?,
                    );
                }
                out.insert(
                    mid.clone(),
                    Leaf {
                        id: mid.clone(),
                        handle: m.handle().to_string(),
                        skeleton: m.handle().to_string(), // model invariant: skeleton == handle
                        name: m.name().to_string(),
                        surname: m.surname().to_string(),
                        p_key: Key {
                            owner: mid.clone(),
                            gen,
                        },
                        devices,
                    },
                );
            }
        }
        Ok(out)
    }
}

impl State<MembershipDriver> for MembershipState {
    fn from_driver(driver: &MembershipDriver) -> Result<Self> {
        Ok(MembershipState {
            trie: driver.model_trie()?,
            last_error: driver.last_error.clone(),
        })
    }
}

impl Driver for MembershipDriver {
    type State = MembershipState;

    fn step(&mut self, step: &Step) -> Result {
        let switch_result: Result = (|| {
            switch!(step {
            init => {
                self.trie = Some(Trie::genesis(Vec::new()).map_err(|e| anyhow!("{e:?}"))?);
                self.last_error = String::new();
            },
            AddMember(id: String, h: String) => {
                let key = Key { owner: id.clone(), gen: 0 };
                let leaf = MemberLeaf::new(
                    real_id(&id), &h, real_member_key(&key), "n", "s",
                    vec![real_device_key(&key)],
                );
                let res = match (leaf, self.trie.clone()) {
                    (Ok(l), Some(t)) => t.add_member(l),
                    (Ok(l), None) => Trie::genesis(Vec::new()).and_then(|t| t.add_member(l)),
                    (Err(e), _) => Err(e),
                };
                self.commit(res);
            },
            DeleteMember(id: String) => {
                let res = self.cur().and_then(|t| t.delete_member(&real_id(&id)));
                self.commit(res);
            },
            UpdateHandle(id: String, h: String) => {
                let res = self.cur().and_then(|t| t.update_handle(&real_id(&id), &h));
                self.commit(res);
            },
            RotateKey(id: String, g: i64) => {
                let nk = real_member_key(&Key { owner: id.clone(), gen: g });
                let res = self.cur().and_then(|t| t.rotate_p2p_key(&real_id(&id), nk));
                self.commit(res);
            },
            AddDevice(id: String, g: i64) => {
                let d = real_device_key(&Key { owner: id.clone(), gen: g });
                let res = self.cur().and_then(|t| t.add_p2p_device(&real_id(&id), d));
                self.commit(res);
            },
            DeleteDevice(id: String, g: i64) => {
                let d = real_device_key(&Key { owner: id.clone(), gen: 0 });
                let nk = real_member_key(&Key { owner: id.clone(), gen: g });
                let res = self.cur().and_then(|t| t.delete_p2p_device(&real_id(&id), &d, nk));
                self.commit(res);
            },
            Isolate(id: String, g: i64) => {
                let nk = real_member_key(&Key { owner: id.clone(), gen: g });
                let res = self.cur().and_then(|t| t.emergency_isolate_member(&real_id(&id), nk));
                self.commit(res);
            }
        })
        })();
        switch_result?;

        // Root-hash equality-class check: equal model state <=> equal real root.
        if self.last_error.is_empty() {
            if let Some(t) = &self.trie {
                let root = t.root_hash().map_err(|e| anyhow!("root_hash: {e:?}"))?;
                let root_hex = hex::encode(root.as_bytes());
                let key = serde_json::to_vec(&self.model_trie()?).unwrap_or_default();
                match self.root_classes.get(&key) {
                    Some(prev) if *prev != root_hex => {
                        return Err(anyhow!(
                            "abstraction violated: equal model state, different roots"
                        ))
                    }
                    None => {
                        if self.root_classes.values().any(|v| v == &root_hex) {
                            return Err(anyhow!(
                                "abstraction violated: distinct model states share a root"
                            ));
                        }
                        self.root_classes.insert(key, root_hex);
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }
}

#[quint_run(spec = "../quint/membership_mbt.qnt", max_samples = 50)]
fn membership_conformance() -> impl Driver {
    MembershipDriver::default()
}
