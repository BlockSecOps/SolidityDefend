/// Query implementations for Salsa database
///
/// This module contains the implementation functions for derived queries
/// that are called by the Salsa framework for incremental computation.

use anyhow::Result;
use std::sync::Arc;
use ast::SourceFile;
use crate::database::{Database, SourceFileId};

/// Helper function to extract functions from a database query result
pub fn extract_functions_from_parse_result(db: &mut Database, id: SourceFileId) -> Result<Vec<String>> {
    db.get_all_functions(id)
}

/// Helper function to extract public functions
pub fn extract_public_functions(db: &mut Database, id: SourceFileId) -> Result<Vec<String>> {
    db.get_public_functions(id)
}

/// Helper function to analyze dependencies
pub fn analyze_dependencies(db: &Database, id: SourceFileId) -> Result<Vec<SourceFileId>> {
    db.get_contract_dependencies(id)
}

/// Query to get contract metadata (name, type, etc.)
pub fn get_contract_metadata_query(db: &mut Database, id: SourceFileId) -> Result<Vec<ContractMetadata>> {
    // Note: This would require access to parsed AST
    // For now, return basic metadata from file content
    let content = db.get_source_content(id);

    let mut metadata = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("contract ") || trimmed.starts_with("interface ") || trimmed.starts_with("library ") {
            if let Some(name_start) = trimmed.find(' ') {
                let rest = &trimmed[name_start + 1..];
                if let Some(name_end) = rest.find(' ') {
                    let name = &rest[..name_end];
                    metadata.push(ContractMetadata {
                        name: name.to_string(),
                        contract_type: if trimmed.starts_with("contract") {
                            "Contract".to_string()
                        } else if trimmed.starts_with("interface") {
                            "Interface".to_string()
                        } else {
                            "Library".to_string()
                        },
                        function_count: 0, // Would need full parsing to determine
                        location: "1:1".to_string(), // Would need line tracking
                    });
                }
            }
        }
    }

    Ok(metadata)
}

/// Metadata about a contract extracted from the AST
#[derive(Debug, Clone)]
pub struct ContractMetadata {
    pub name: String,
    pub contract_type: String,
    pub function_count: usize,
    pub location: String,
}

/// Query to check if a file has changed based on content hash
pub fn file_content_changed_query(db: &Database, id: SourceFileId, expected_hash: &str) -> bool {
    if let Some(input) = db.get_source_file_input(id) {
        input.content_hash != expected_hash
    } else {
        true // File not found, consider it changed
    }
}

/// Query to get file statistics
pub fn get_file_stats_query(db: &mut Database, id: SourceFileId) -> Result<FileStats> {
    let content = db.get_source_content(id);

    let line_count = content.lines().count();
    let char_count = content.chars().count();
    let byte_count = content.len();

    // Count contracts and functions
    let mut contract_count = 0;
    let mut function_count = 0;

    // Simple parsing to count contracts and functions
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("contract ") || trimmed.starts_with("interface ") || trimmed.starts_with("library ") {
            contract_count += 1;
        } else if trimmed.starts_with("function ") {
            function_count += 1;
        }
    }

    Ok(FileStats {
        line_count,
        char_count,
        byte_count,
        contract_count,
        function_count,
    })
}

/// Statistics about a source file
#[derive(Debug, Clone)]
pub struct FileStats {
    pub line_count: usize,
    pub char_count: usize,
    pub byte_count: usize,
    pub contract_count: usize,
    pub function_count: usize,
}
