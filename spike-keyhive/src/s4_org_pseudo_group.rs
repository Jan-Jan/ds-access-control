//! Gate 4 substitution: organisation-as-pseudo-group via `Agent::Group(...)`.
//!
//! Keyhive models groups as first-class agents:
//!
//! ```text
//! Agent::Group(GroupId, Arc<Mutex<Group<...>>>)
//! ```
//!
//! `Keyhive::add_member(to_add: Agent<...>, ...)` accepts ANY variant
//! with identical call signature. Granting an "org" access to a document
//! is one call:
//!
//! ```ignore
//! keyhive.add_member(
//!     Agent::Group(org_id, org_group_arc),
//!     &Membered::Document(doc_id, doc_arc),
//!     Access::Edit,
//!     &[],
//! ).await?;
//! ```
//!
//! `Document::transitive_members()` auto-resolves nested groups, so the
//! effective member set of a doc that has the org as a member is the
//! org's individual members (transitively).
//!
//! This is the strongest single Keyhive-vs-p2panda differentiator: in
//! p2panda the equivalent flow required a fork patch (`pub use
//! types::AuthGroupState`) to bypass the spaces-layer ActorId
//! gatekeeper.
//!
//! See `evidence/s4.md` for full API surface citations.

use std::sync::Arc;

use futures::lock::Mutex;
use keyhive_core::access::Access;
use keyhive_core::contact_card::ContactCard;
use keyhive_core::principal::agent::Agent;
use keyhive_core::principal::document::Document;
use keyhive_core::principal::group::Group;
use keyhive_core::principal::membered::Membered;

use crate::s1_stable_id_acl::SpikeKeyhive;

type SpikeGroup = Group<
    future_form::Sendable,
    keyhive_crypto::signer::memory::MemorySigner,
    [u8; 32],
    keyhive_core::listener::no_listener::NoListener,
>;

type SpikeDocument = Document<
    future_form::Sendable,
    keyhive_crypto::signer::memory::MemorySigner,
    [u8; 32],
    keyhive_core::listener::no_listener::NoListener,
>;

/// Create an "organisation" group inside a Keyhive instance.
///
/// Returns the group as `Arc<Mutex<...>>` ready to be referenced via
/// `Agent::Group(group.lock().await.group_id(), group.clone())`.
pub async fn generate_org_group(
    keyhive: &SpikeKeyhive,
) -> Result<Arc<Mutex<SpikeGroup>>, GroupError> {
    keyhive
        .generate_group(vec![])
        .await
        .map_err(|_| GroupError::Generate)
}

/// Add a member to the organisation group.
pub async fn add_member_to_org(
    keyhive: &SpikeKeyhive,
    org: &Arc<Mutex<SpikeGroup>>,
    peer_card: &ContactCard,
) -> Result<(), GroupError> {
    let peer_individual = keyhive
        .receive_contact_card(peer_card)
        .await
        .map_err(|_| GroupError::ReceiveCard)?;
    let org_id = org.lock().await.group_id();
    let peer_agent = Agent::Individual(peer_card.id(), peer_individual);
    keyhive
        .add_member(
            peer_agent,
            &Membered::Group(org_id, org.clone()),
            Access::Edit,
            &[],
        )
        .await
        .map_err(|_| GroupError::AddMember)?;
    Ok(())
}

/// Grant the organisation pseudo-group access to a document.
///
/// This is the gate-4 flow: instead of adding individual members to
/// the doc, add the *group* (as `Agent::Group`). The doc's
/// `transitive_members()` will auto-resolve to include every current
/// member of the org.
pub async fn grant_org_to_doc(
    keyhive: &SpikeKeyhive,
    org: &Arc<Mutex<SpikeGroup>>,
    doc: &Arc<Mutex<SpikeDocument>>,
    access: Access,
) -> Result<(), GroupError> {
    let org_id = org.lock().await.group_id();
    let doc_id = doc.lock().await.doc_id();
    keyhive
        .add_member(
            Agent::Group(org_id, org.clone()),
            &Membered::Document(doc_id, doc.clone()),
            access,
            &[],
        )
        .await
        .map_err(|_| GroupError::AddMember)?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum GroupError {
    #[error("generate_group failed")]
    Generate,
    #[error("receive_contact_card failed")]
    ReceiveCard,
    #[error("add_member failed")]
    AddMember,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s1_stable_id_acl::generate_spike_keyhive;

    #[tokio::test]
    async fn org_as_pseudo_group_grants_transitive_access() {
        let alice = generate_spike_keyhive().await.unwrap();
        let bob = generate_spike_keyhive().await.unwrap();

        // alice creates an "org" group and adds bob to it.
        let org = generate_org_group(&alice).await.unwrap();
        let bob_card = bob.contact_card().await.unwrap();
        add_member_to_org(&alice, &org, &bob_card).await.unwrap();

        // alice creates a doc and grants the org Read access.
        let doc = alice
            .generate_doc(vec![], nonempty::nonempty![[42u8; 32]])
            .await
            .unwrap();
        grant_org_to_doc(&alice, &org, &doc, Access::Read)
            .await
            .unwrap();

        // bob (as a member of the org) should appear in the doc's
        // transitive_members — the headline gate-4 invariant.
        let members = doc.lock().await.transitive_members().await;
        let bob_id = bob_card.id();
        assert!(
            members.contains_key(&bob_id.into()),
            "bob (via org) must be in doc's transitive_members; got keys: {:?}",
            members.keys().collect::<Vec<_>>()
        );
    }
}
