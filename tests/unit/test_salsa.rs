use std::sync::Arc;
use db::{Database, SourceFileId};
use ast::{AstArena, SourceFile};
use parser::Parser;

/// Unit tests for Salsa database integration
/// These tests verify incremental computation and query caching functionality

#[test]
fn test_salsa_database_creation() {
    let db = Database::new();
    assert!(db.is_empty(), "Database should be empty on creation");
}

#[test]
fn test_source_file_input() {
    let mut db = Database::new();
    let file_path = "test.sol";
    let source_content = r#"
        pragma solidity ^0.8.0;
        contract TestContract {
            uint256 public value;
        }
    "#;

    let file_id = db.add_source_file(file_path, source_content);
    assert_eq!(db.source_file_count(), 1);
    assert_eq!(db.get_source_content(file_id), source_content);
    assert_eq!(db.get_source_path(file_id), file_path);
}

#[test]
fn test_incremental_parsing() {
    let mut db = Database::new();
    let file_path = "test.sol";

    // Initial parse
    let initial_source = r#"
        contract Test {
            uint256 value;
        }
    "#;

    let file_id = db.add_source_file(file_path, initial_source);
    let initial_ast = db.parse_source_file(file_id);
    assert!(initial_ast.is_ok());
    assert_eq!(initial_ast.unwrap().contracts.len(), 1);

    // Update content and verify incremental parse
    let updated_source = r#"
        contract Test {
            uint256 value;
            uint256 newValue;
        }
    "#;

    db.update_source_file(file_id, updated_source);
    let updated_ast = db.parse_source_file(file_id);
    assert!(updated_ast.is_ok());
    assert_eq!(updated_ast.unwrap().contracts.len(), 1);
}

#[test]
fn test_query_caching() {
    let mut db = Database::new();
    let file_path = "test.sol";
    let source_content = r#"
        contract TestContract {
            function testFunction() public {}
        }
    "#;

    let file_id = db.add_source_file(file_path, source_content);

    // First query should compute result
    let first_result = db.parse_source_file(file_id);
    assert!(first_result.is_ok());

    // Second query should use cached result
    let second_result = db.parse_source_file(file_id);
    assert!(second_result.is_ok());

    // Verify cache hit was recorded
    assert!(db.get_cache_hit_rate() > 0.0);
}

#[test]
fn test_cache_invalidation() {
    let mut db = Database::new();
    let file_path = "test.sol";

    let initial_source = "contract Test {}";
    let file_id = db.add_source_file(file_path, initial_source);

    // Initial parse
    let _ = db.parse_source_file(file_id);

    // Update content - should invalidate cache
    let updated_source = "contract Test { uint256 value; }";
    db.update_source_file(file_id, updated_source);

    // Next query should recompute
    let result = db.parse_source_file(file_id);
    assert!(result.is_ok());

    // Verify cache was invalidated
    assert_eq!(db.get_invalidation_count(), 1);
}

#[test]
fn test_multi_file_database() {
    let mut db = Database::new();

    let file1_content = "contract Contract1 {}";
    let file2_content = "contract Contract2 {}";

    let file1_id = db.add_source_file("file1.sol", file1_content);
    let file2_id = db.add_source_file("file2.sol", file2_content);

    assert_eq!(db.source_file_count(), 2);

    let result1 = db.parse_source_file(file1_id);
    let result2 = db.parse_source_file(file2_id);

    assert!(result1.is_ok());
    assert!(result2.is_ok());

    assert_eq!(result1.unwrap().contracts[0].name.name, "Contract1");
    assert_eq!(result2.unwrap().contracts[0].name.name, "Contract2");
}

#[test]
fn test_derived_queries() {
    let mut db = Database::new();
    let file_path = "test.sol";
    let source_content = r#"
        contract TestContract {
            function publicFunc() public {}
            function privateFunc() private {}
        }
    "#;

    let file_id = db.add_source_file(file_path, source_content);

    // Test derived query for public functions
    let public_functions = db.get_public_functions(file_id);
    assert!(public_functions.is_ok());
    assert_eq!(public_functions.unwrap().len(), 1);

    // Test derived query for all functions
    let all_functions = db.get_all_functions(file_id);
    assert!(all_functions.is_ok());
    assert_eq!(all_functions.unwrap().len(), 2);
}

#[test]
fn test_error_handling() {
    let mut db = Database::new();

    // Test invalid source file ID
    let invalid_id = SourceFileId::new(999);
    let result = db.parse_source_file(invalid_id);
    assert!(result.is_err());

    // Test malformed Solidity code
    let file_id = db.add_source_file("invalid.sol", "contract Test { invalid syntax");
    let result = db.parse_source_file(file_id);
    assert!(result.is_err());
}

#[test]
fn test_dependency_tracking() {
    let mut db = Database::new();

    let base_contract = r#"
        contract Base {
            uint256 public baseValue;
        }
    "#;

    let derived_contract = r#"
        import "./base.sol";
        contract Derived is Base {
            uint256 public derivedValue;
        }
    "#;

    let base_id = db.add_source_file("base.sol", base_contract);
    let derived_id = db.add_source_file("derived.sol", derived_contract);

    // Parse both files
    let _ = db.parse_source_file(base_id);
    let _ = db.parse_source_file(derived_id);

    // Update base contract - should invalidate derived
    let updated_base = r#"
        contract Base {
            uint256 public baseValue;
            uint256 public newBaseValue;
        }
    "#;

    db.update_source_file(base_id, updated_base);

    // Verify dependency invalidation
    assert!(db.has_dependency(derived_id, base_id));
    assert_eq!(db.get_invalidation_count(), 2); // Both base and derived invalidated
}

#[test]
fn test_performance_metrics() {
    let mut db = Database::new();
    let file_path = "test.sol";
    let source_content = "contract Test { function func() public {} }";

    let file_id = db.add_source_file(file_path, source_content);

    // Perform multiple queries
    for _ in 0..10 {
        let _ = db.parse_source_file(file_id);
    }

    // Verify performance metrics
    assert!(db.get_total_queries() >= 10);
    assert!(db.get_cache_hit_rate() > 0.8); // Should have high cache hit rate
    assert!(db.get_average_query_time() > 0.0);
}