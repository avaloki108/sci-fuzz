//! Integration tests for the EF/CF benchmark matrix ([`chimera_fuzz::benchmark_matrix`]).

use chimera_fuzz::benchmark_matrix::*;

#[test]
fn benchmark_matrix_has_entries() {
    let matrix = benchmark_matrix();
    assert!(
        matrix.len() >= 30,
        "benchmark matrix should have at least 30 entries, got {}",
        matrix.len(),
    );
}

#[test]
fn all_contract_files_exist() {
    let matrix = benchmark_matrix();
    for entry in &matrix {
        assert!(
            std::path::Path::new(entry.contract_file).exists(),
            "Contract file missing: {} ({})",
            entry.contract_file,
            entry.description,
        );
    }
}

#[test]
fn no_duplicate_contract_files() {
    let matrix = benchmark_matrix();
    let mut seen = std::collections::HashSet::new();
    for entry in &matrix {
        assert!(
            seen.insert(entry.contract_file),
            "Duplicate contract file in benchmark matrix: {}",
            entry.contract_file,
        );
    }
}

#[test]
fn all_bug_categories_represented() {
    let matrix = benchmark_matrix();

    let has = |bug: ExpectedBug| matrix.iter().any(|e| e.expected_bug == bug);

    assert!(has(ExpectedBug::EtherDrain), "missing EtherDrain entries");
    assert!(
        has(ExpectedBug::Selfdestruct),
        "missing Selfdestruct entries"
    );
    assert!(has(ExpectedBug::Reentrancy), "missing Reentrancy entries");
    assert!(
        has(ExpectedBug::IntegerOverflow),
        "missing IntegerOverflow entries"
    );
    assert!(
        has(ExpectedBug::PropertyViolation),
        "missing PropertyViolation entries"
    );
    assert!(
        has(ExpectedBug::AccessControl),
        "missing AccessControl entries"
    );
}
