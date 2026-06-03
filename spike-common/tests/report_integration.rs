#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use spike_common::report::{
    Effort, FixPath, GapEntry, GapMatrix, Library, PrincipalKind, Severity, SubFlow,
};

fn sample_matrix() -> GapMatrix {
    let mut m = GapMatrix::default();
    m.upsert(GapEntry {
        library: Library::Keyhive,
        gate: 0,
        sub_flow: SubFlow::A,
        principal: PrincipalKind::NA,
        severity: Severity::None,
        failing_subcrate: None,
        fix_path: FixPath::None,
        fix_effort: None,
        phase3_effort: Effort::Small,
        evidence: vec!["WASM build matrix in CI".to_string()],
        escape_hatch: None,
        salvage_notes: String::new(),
        notes: "compiles cleanly".to_string(),
    });
    m.upsert(GapEntry {
        library: Library::Panda,
        gate: 1,
        sub_flow: SubFlow::A,
        principal: PrincipalKind::Member,
        severity: Severity::Soft,
        failing_subcrate: Some("p2panda-auth".to_string()),
        fix_path: FixPath::TraitImpl,
        fix_effort: Some(Effort::Small),
        phase3_effort: Effort::Medium,
        evidence: vec!["spike_p2panda::s1::test_member_delegation".to_string()],
        escape_hatch: Some("wrap raw VerifyingKey in our Principal type".to_string()),
        salvage_notes: "p2panda-auth's Subject trait is public".to_string(),
        notes: "passes after thin shim".to_string(),
    });
    m
}

#[test]
fn markdown_render_contains_each_row() {
    let m = sample_matrix();
    let md = spike_common::report::render_markdown(&m);
    assert!(md.contains("Keyhive"), "markdown should mention Keyhive");
    assert!(md.contains("Panda"), "markdown should mention p2panda");
    assert!(md.contains("p2panda-auth"), "failing subcrate should appear");
    assert!(md.contains("TraitImpl"), "fix path should appear");
}

#[test]
#[cfg(feature = "json")]
fn json_render_roundtrips() {
    let m = sample_matrix();
    let json = spike_common::report::render_json(&m).expect("serialize ok");
    let back: GapMatrix = serde_json::from_str(&json).expect("deserialize ok");
    assert_eq!(m, back);
}
