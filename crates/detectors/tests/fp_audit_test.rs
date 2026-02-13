/// FP Audit Test — ensures no enabled detector produces findings on known-secure files.
///
/// This test gates on false positive count: if any enabled detector fires on a
/// secure/clean contract, the test fails. This prevents FP regressions.
///
/// Uses the real Solidity parser to create per-contract AnalysisContexts, matching
/// the production scanner's behavior. This eliminates false alarms from the test
/// infrastructure that occurred when using synthetic single-context-per-file analysis.
use detectors::registry::DetectorRegistry;
use detectors::types::AnalysisContext;
use std::fs;
use std::path::PathBuf;

/// Get the project root (two parents up from crates/detectors/)
fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Create a fallback AnalysisContext for files that fail to parse.
/// Uses a synthetic contract so text-based detectors still run.
fn create_fallback_context(source: &str, file_path: &str) -> AnalysisContext<'static> {
    use ast::arena::AstArena;
    use ast::{Identifier, Position, SourceLocation};
    use bumpalo::collections::Vec as BumpVec;
    use semantic::SymbolTable;

    let symbols = SymbolTable::new();
    let arena = Box::leak(Box::new(AstArena::new()));

    let name = arena.alloc_str("TestContract");
    let identifier = Identifier {
        name,
        location: SourceLocation::new(
            PathBuf::from(file_path),
            Position::new(1, 1, 0),
            Position::new(1, 12, 11),
        ),
    };

    let contract = Box::leak(Box::new(ast::Contract {
        name: identifier,
        contract_type: ast::ContractType::Contract,
        inheritance: BumpVec::new_in(&arena.bump),
        using_for_directives: BumpVec::new_in(&arena.bump),
        state_variables: BumpVec::new_in(&arena.bump),
        functions: BumpVec::new_in(&arena.bump),
        modifiers: BumpVec::new_in(&arena.bump),
        events: BumpVec::new_in(&arena.bump),
        errors: BumpVec::new_in(&arena.bump),
        structs: BumpVec::new_in(&arena.bump),
        enums: BumpVec::new_in(&arena.bump),
        location: SourceLocation::new(
            PathBuf::from(file_path),
            Position::new(1, 1, 0),
            Position::new(1, 12, 11),
        ),
    }));

    AnalysisContext::new(contract, symbols, source.to_string(), file_path.to_string())
}

/// Parse a Solidity file and run all detectors on each contract, returning findings.
/// Uses the real parser for per-contract analysis matching the production scanner.
fn analyze_file(
    source: &str,
    file_path: &str,
    registry: &DetectorRegistry,
) -> Vec<detectors::types::Finding> {
    use ast::arena::AstArena;
    use parser::Parser;
    use semantic::SymbolTable;

    let arena = Box::leak(Box::new(AstArena::new()));
    let parser = Parser::new();

    match parser.parse(arena, source, file_path) {
        Ok(source_file) if !source_file.contracts.is_empty() => {
            let mut all_findings = Vec::new();
            for contract in &source_file.contracts {
                let ctx = AnalysisContext::new(
                    contract,
                    SymbolTable::new(),
                    source.to_string(),
                    file_path.to_string(),
                );
                if let Ok(result) = registry.run_analysis(&ctx) {
                    all_findings.extend(result.findings);
                }
            }
            all_findings
        }
        _ => {
            // Parse error or no contracts found — fall back to synthetic context
            let ctx = create_fallback_context(source, file_path);
            if let Ok(result) = registry.run_analysis(&ctx) {
                result.findings
            } else {
                Vec::new()
            }
        }
    }
}

/// Collect all secure/clean .sol files from the test suite
fn collect_secure_files() -> Vec<PathBuf> {
    let root = project_root();
    let mut files = Vec::new();

    let contracts_dir = root.join("tests").join("contracts");

    // Pattern 1: tests/contracts/*/secure/*.sol
    if let Ok(entries) = fs::read_dir(&contracts_dir) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let secure_dir = entry.path().join("secure");
                if secure_dir.is_dir() {
                    if let Ok(sol_files) = fs::read_dir(&secure_dir) {
                        for sol_file in sol_files.flatten() {
                            let path = sol_file.path();
                            if path.extension().map(|e| e == "sol").unwrap_or(false) {
                                files.push(path);
                            }
                        }
                    }
                }
            }
        }
    }

    // Pattern 2: tests/contracts/fp_benchmarks/*.sol
    let fp_dir = contracts_dir.join("fp_benchmarks");
    if fp_dir.is_dir() {
        if let Ok(sol_files) = fs::read_dir(&fp_dir) {
            for sol_file in sol_files.flatten() {
                let path = sol_file.path();
                if path.extension().map(|e| e == "sol").unwrap_or(false) {
                    files.push(path);
                }
            }
        }
    }

    // Pattern 3: tests/contracts/clean_examples/*.sol
    let clean_dir = contracts_dir.join("clean_examples");
    if clean_dir.is_dir() {
        if let Ok(sol_files) = fs::read_dir(&clean_dir) {
            for sol_file in sol_files.flatten() {
                let path = sol_file.path();
                if path.extension().map(|e| e == "sol").unwrap_or(false) {
                    files.push(path);
                }
            }
        }
    }

    files.sort();
    files
}

#[test]
fn test_no_findings_on_secure_files() {
    let secure_files = collect_secure_files();
    assert!(
        !secure_files.is_empty(),
        "No secure test files found — test infrastructure broken"
    );

    let registry = DetectorRegistry::with_all_detectors();
    let mut total_fps = 0;
    let mut fp_details: Vec<String> = Vec::new();

    for file_path in &secure_files {
        let source = match fs::read_to_string(file_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Warning: Could not read {}: {}", file_path.display(), e);
                continue;
            }
        };

        let file_path_str = file_path.to_string_lossy();
        let findings = analyze_file(&source, &file_path_str, &registry);

        if !findings.is_empty() {
            total_fps += findings.len();
            let file_name = file_path.file_name().unwrap_or_default().to_string_lossy();
            for finding in &findings {
                fp_details.push(format!(
                    "  {} [{}]: {}",
                    file_name, finding.detector_id, finding.message
                ));
            }
        }
    }

    if total_fps > 0 {
        eprintln!(
            "\n=== FP AUDIT ===\n\
             {} false positives found on {} secure files:\n{}",
            total_fps,
            secure_files.len(),
            fp_details.join("\n")
        );
    }

    // Gate: zero tolerance for FPs on secure files.
    // Uses real parser for per-contract analysis matching the production scanner.
    let max_allowed_fps = 0;
    assert!(
        total_fps <= max_allowed_fps,
        "FP regression: expected <= {} findings on secure files, got {}. See stderr for details.",
        max_allowed_fps,
        total_fps
    );
}

#[test]
fn test_secure_files_exist() {
    let secure_files = collect_secure_files();
    assert!(
        secure_files.len() >= 5,
        "Expected at least 5 secure test files, found {}",
        secure_files.len()
    );

    // Verify key secure files exist
    let file_names: Vec<String> = secure_files
        .iter()
        .filter_map(|p| p.file_name().map(|f| f.to_string_lossy().to_string()))
        .collect();

    let expected_files = [
        "safe_erc4626_vault.sol",
        "safe_chainlink_consumer.sol",
        "safe_flash_loan_provider.sol",
        "safe_amm_pool.sol",
    ];

    for expected in expected_files {
        assert!(
            file_names.contains(&expected.to_string()),
            "Missing expected secure file: {}",
            expected
        );
    }
}
