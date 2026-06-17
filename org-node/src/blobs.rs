//! Out-of-band exchange blobs (spec story 2). Base64(postcard(..)) for copy/paste.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};

use crate::ids::OrgId;
use crate::OrgNodeError;

/// A → B: enough for B to read the org slot and to dial / authenticate A.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    pub org_id: OrgId,
    pub org_pub_key: [u8; 32],
    pub admin_member_key: [u8; 32],
    pub admin_device_key: [u8; 32],
    /// postcard-encoded iroh EndpointAddr for dialing A.
    pub admin_node_addr: Vec<u8>,
}

/// B → A: B's proposed persona, so A can mint a member_id and add B.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRequest {
    pub handle: String,
    pub name: String,
    pub surname: String,
    pub member_key: [u8; 32],
    pub device_key: [u8; 32],
    /// postcard-encoded iroh EndpointAddr for dialing B.
    pub node_addr: Vec<u8>,
}

/// Encode a blob to a Base64 string (STANDARD alphabet, padded).
pub fn encode<T: Serialize>(v: &T) -> Result<String, OrgNodeError> {
    let bytes = postcard::to_allocvec(v)
        .map_err(|e| OrgNodeError::Chain(format!("blob encode: {e}")))?;
    Ok(STANDARD.encode(&bytes))
}

/// Decode a blob from a Base64 string.
pub fn decode<T: for<'de> Deserialize<'de>>(s: &str) -> Result<T, OrgNodeError> {
    let bytes = STANDARD
        .decode(s)
        .map_err(|e| OrgNodeError::Chain(format!("blob base64: {e}")))?;
    postcard::from_bytes(&bytes)
        .map_err(|e| OrgNodeError::Chain(format!("blob decode: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_org_id() -> OrgId {
        OrgId::new([0xabu8; 20])
    }

    #[test]
    fn invite_round_trips() {
        let inv = Invite {
            org_id: dummy_org_id(),
            org_pub_key: [1u8; 32],
            admin_member_key: [2u8; 32],
            admin_device_key: [3u8; 32],
            admin_node_addr: vec![4, 5, 6],
        };
        let s = encode(&inv).unwrap();
        let back: Invite = decode(&s).unwrap();
        assert_eq!(inv, back);
    }

    #[test]
    fn join_request_round_trips() {
        let jr = JoinRequest {
            handle: "bob".into(),
            name: "Bob".into(),
            surname: "Builder".into(),
            member_key: [7u8; 32],
            device_key: [8u8; 32],
            node_addr: vec![9, 10],
        };
        let s = encode(&jr).unwrap();
        let back: JoinRequest = decode(&s).unwrap();
        assert_eq!(jr, back);
    }

    #[test]
    fn bad_base64_is_rejected() {
        let result: Result<Invite, _> = decode("not!valid!base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn bad_postcard_is_rejected() {
        // Valid base64 but garbage postcard payload.
        let s = STANDARD.encode(b"garbage bytes that are not valid postcard");
        let result: Result<Invite, _> = decode(&s);
        assert!(result.is_err());
    }
}
