//! gap-update — updates docs/phase-1d/gap-matrix.{md,json} from stdin.
//!
//! Usage:
//!   echo '<single GapEntry as JSON>' | cargo run --bin gap-update --features json
//!
//! The entry is upserted into the matrix at docs/phase-1d/gap-matrix.json
//! (loaded fresh if the file doesn't exist). Both .json and .md are rewritten.
//! Empty stdin re-renders the existing matrix (useful for refreshing the
//! markdown after a manual JSON edit).

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use spike_common::report::{render_json, render_markdown, GapEntry, GapMatrix};

fn main() -> ExitCode {
    let docs_dir: PathBuf = std::env::var("PHASE_1D_DOCS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("docs/phase-1d"));

    match run(&docs_dir) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("gap-update failed: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(docs_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(docs_dir)?;

    let json_path = docs_dir.join("gap-matrix.json");
    let md_path = docs_dir.join("gap-matrix.md");

    let mut matrix: GapMatrix = if json_path.exists() {
        let raw = fs::read_to_string(&json_path)?;
        serde_json::from_str(&raw)?
    } else {
        GapMatrix::default()
    };

    let mut stdin_buf = String::new();
    io::stdin().read_to_string(&mut stdin_buf)?;
    let stdin_trimmed = stdin_buf.trim();

    if !stdin_trimmed.is_empty() {
        let entry: GapEntry = serde_json::from_str(stdin_trimmed)?;
        matrix.upsert(entry);
    }
    // Empty stdin is allowed: just re-render existing matrix.

    fs::write(&json_path, render_json(&matrix)?)?;
    fs::write(&md_path, render_markdown(&matrix))?;

    println!(
        "gap-update: wrote {} rows to {} and {}",
        matrix.rows.len(),
        json_path.display(),
        md_path.display(),
    );
    Ok(())
}
