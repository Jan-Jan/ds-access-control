//! Gap matrix types and renderers. Schema follows the design doc verbatim;
//! see §Gap matrix and decision rubric.

use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Library {
    Keyhive,
    Panda,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum SubFlow {
    A,
    B,
    C,
    D,
    E1,
    E2,
    F1,
    F2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum PrincipalKind {
    Member,
    Org,
    NA,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Severity {
    Hard,
    Soft,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum FixPath {
    UpstreamPR,
    TraitImpl,
    Fork,
    Replace,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Effort {
    Small,
    Medium,
    Large,
    XL,
}

impl Effort {
    /// Super-linear weighting used in tie-break step 2 and override-on-cost
    /// annotation. `XL` is meant as effective veto, so it gets a very large
    /// number — but it's still finite so totals remain comparable.
    pub fn weight(&self) -> u32 {
        match self {
            Effort::Small => 1,
            Effort::Medium => 3,
            Effort::Large => 9,
            Effort::XL => 81,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GapEntry {
    pub library: Library,
    pub gate: u8,
    pub sub_flow: SubFlow,
    pub principal: PrincipalKind,
    pub severity: Severity,
    pub failing_subcrate: Option<String>,
    pub fix_path: FixPath,
    pub fix_effort: Option<Effort>,
    pub phase3_effort: Effort,
    pub evidence: Vec<String>,
    pub escape_hatch: Option<String>,
    pub salvage_notes: String,
    pub notes: String,
}

impl GapEntry {
    pub fn row_key(&self) -> RowKey {
        RowKey {
            library: self.library,
            gate: self.gate,
            sub_flow: self.sub_flow,
            principal: self.principal,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RowKey {
    pub library: Library,
    pub gate: u8,
    pub sub_flow: SubFlow,
    pub principal: PrincipalKind,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GapMatrix {
    pub rows: Vec<GapEntry>,
}

impl GapMatrix {
    pub fn upsert(&mut self, entry: GapEntry) {
        let key = entry.row_key();
        if let Some(existing) = self.rows.iter_mut().find(|r| r.row_key() == key) {
            *existing = entry;
        } else {
            self.rows.push(entry);
        }
    }

    pub fn has_hard(&self, library: Library) -> bool {
        self.rows.iter().any(|r| r.library == library && r.severity == Severity::Hard)
    }

    pub fn soft_count(&self, library: Library) -> usize {
        self.rows.iter().filter(|r| r.library == library && r.severity == Severity::Soft).count()
    }

    /// Total burden = sum over Soft+Hard rows of (phase3_effort + fix_effort).
    /// Used by the override-on-cost annotation in the decision doc.
    /// `None`-severity rows do not contribute. `fix_effort` of `None` contributes zero.
    pub fn total_burden(&self, library: Library) -> u32 {
        let mut total = 0u32;
        for r in self.rows.iter().filter(|r| {
            r.library == library
                && matches!(r.severity, Severity::Soft | Severity::Hard)
        }) {
            total = total.saturating_add(r.phase3_effort.weight());
            if let Some(fe) = r.fix_effort {
                total = total.saturating_add(fe.weight());
            }
        }
        total
    }
}

#[cfg(feature = "std")]
pub fn render_markdown(matrix: &GapMatrix) -> String {
    use core::fmt::Write;

    let mut out = String::new();
    let _ = writeln!(out, "# Phase 1.d gap matrix");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| Library | Gate | Flow | Principal | Severity | Subcrate | Fix path | Fix effort | Phase 3 effort | Notes |"
    );
    let _ = writeln!(out, "|---|---|---|---|---|---|---|---|---|---|");
    for r in &matrix.rows {
        let _ = writeln!(
            out,
            "| {:?} | {} | {:?} | {:?} | {:?} | {} | {:?} | {} | {:?} | {} |",
            r.library,
            r.gate,
            r.sub_flow,
            r.principal,
            r.severity,
            r.failing_subcrate.as_deref().unwrap_or(""),
            r.fix_path,
            r.fix_effort.map(|e| alloc::format!("{e:?}")).unwrap_or_default(),
            r.phase3_effort,
            r.notes,
        );
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "## Per-library summary");
    let _ = writeln!(out);
    for lib in [Library::Keyhive, Library::Panda] {
        let _ = writeln!(
            out,
            "- **{:?}** — hard: {}, soft: {}, total burden: {}",
            lib,
            matrix.rows.iter().filter(|r| r.library == lib && r.severity == Severity::Hard).count(),
            matrix.soft_count(lib),
            matrix.total_burden(lib),
        );
    }
    out
}

#[cfg(feature = "json")]
pub fn render_json(matrix: &GapMatrix) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(matrix)
}

#[cfg(test)]
#[cfg(feature = "serde")]
mod tests {
    use super::*;

    extern crate alloc;
    use alloc::string::ToString;
    use alloc::vec;

    fn sample_entry() -> GapEntry {
        GapEntry {
            library: Library::Keyhive,
            gate: 1,
            sub_flow: SubFlow::A,
            principal: PrincipalKind::Member,
            severity: Severity::Soft,
            failing_subcrate: Some("keyhive_core".to_string()),
            fix_path: FixPath::TraitImpl,
            fix_effort: Some(Effort::Small),
            phase3_effort: Effort::Medium,
            evidence: vec!["spike_keyhive::s1_stable_id_acl::test_delegation".to_string()],
            escape_hatch: None,
            salvage_notes: "keyhive_core::Capability trait is public; impl size ~50 LOC".to_string(),
            notes: "passed L1, L2 needs a thin adapter".to_string(),
        }
    }

    #[test]
    fn gap_entry_postcard_roundtrip() {
        let e = sample_entry();
        let bytes = postcard::to_allocvec(&e).unwrap();
        let back: GapEntry = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn gap_matrix_inserts_and_upserts() {
        let mut m = GapMatrix::default();
        m.upsert(sample_entry());
        assert_eq!(m.rows.len(), 1);

        // Same row key (library, gate, sub_flow, principal) -> replace
        let mut e2 = sample_entry();
        e2.severity = Severity::None;
        m.upsert(e2.clone());
        assert_eq!(m.rows.len(), 1);
        assert_eq!(m.rows[0].severity, Severity::None);
    }

    #[test]
    fn library_has_hard_row() {
        let mut m = GapMatrix::default();
        let mut e = sample_entry();
        e.severity = Severity::Hard;
        m.upsert(e);
        assert!(m.has_hard(Library::Keyhive));
        assert!(!m.has_hard(Library::Panda));
    }

    #[test]
    fn total_burden_only_counts_soft_and_hard_rows() {
        let mut m = GapMatrix::default();

        // None-severity row: should NOT contribute.
        let mut none_row = sample_entry();
        none_row.severity = Severity::None;
        none_row.phase3_effort = Effort::Large;  // weight 9
        none_row.fix_effort = Some(Effort::Large);
        none_row.sub_flow = SubFlow::A;
        m.upsert(none_row);

        // Soft row with fix_effort: should contribute phase3 + fix_effort.
        let mut soft_row = sample_entry();
        soft_row.severity = Severity::Soft;
        soft_row.phase3_effort = Effort::Small;  // weight 1
        soft_row.fix_effort = Some(Effort::Medium);  // weight 3
        soft_row.sub_flow = SubFlow::B;
        m.upsert(soft_row);

        // Hard row with fix_effort: should contribute phase3 + fix_effort.
        let mut hard_row = sample_entry();
        hard_row.severity = Severity::Hard;
        hard_row.phase3_effort = Effort::Small;  // weight 1
        hard_row.fix_effort = Some(Effort::Small);  // weight 1
        hard_row.sub_flow = SubFlow::C;
        m.upsert(hard_row);

        // Expected: Soft(1+3) + Hard(1+1) = 6. None contributes 0.
        assert_eq!(m.total_burden(Library::Keyhive), 6);
        assert_eq!(m.total_burden(Library::Panda), 0);
    }
}
