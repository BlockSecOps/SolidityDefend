// tests/common/test_utils.rs
// Common test utilities and helper functions

use std::fs;
use std::path::Path;

/// Test utility functions
pub fn read_test_file(path: &Path) -> String {
    fs::read_to_string(path).expect("Failed to read test file")
}

/// Create a temporary test directory
pub fn create_temp_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("Failed to create temporary directory")
}

/// Test fixture utilities
pub struct TestFixture {
    pub name: String,
    pub content: String,
}

impl TestFixture {
    pub fn new(name: &str, content: &str) -> Self {
        Self {
            name: name.to_string(),
            content: content.to_string(),
        }
    }
}
