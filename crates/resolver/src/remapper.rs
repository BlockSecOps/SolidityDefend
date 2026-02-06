//! Import remapping for Solidity projects
//!
//! Handles Foundry and Hardhat style import remappings.

use std::path::{Path, PathBuf};

/// Import remapper that applies remappings to import paths
#[derive(Debug, Clone)]
pub struct ImportRemapper {
    /// Remappings sorted by prefix length (longest first)
    remappings: Vec<(String, String)>,
    /// Project root directory
    root: PathBuf,
}

impl ImportRemapper {
    /// Create a new import remapper with the given remappings
    pub fn new(root: impl AsRef<Path>, remappings: Vec<(String, String)>) -> Self {
        let mut sorted_remappings = remappings;
        // Sort by prefix length descending (longest match wins)
        sorted_remappings.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        Self {
            remappings: sorted_remappings,
            root: root.as_ref().to_path_buf(),
        }
    }

    /// Apply remappings to an import path
    ///
    /// Returns the remapped path, or the original path if no remapping matches.
    pub fn remap(&self, import_path: &str) -> String {
        for (prefix, target) in &self.remappings {
            if import_path.starts_with(prefix) {
                let remainder = &import_path[prefix.len()..];
                return format!("{}{}", target, remainder);
            }
        }
        import_path.to_string()
    }

    /// Get the absolute path for a remapped import
    pub fn resolve(&self, import_path: &str) -> PathBuf {
        let remapped = self.remap(import_path);
        self.root.join(&remapped)
    }

    /// Check if an import path matches any remapping
    pub fn has_remapping(&self, import_path: &str) -> bool {
        self.remappings
            .iter()
            .any(|(prefix, _)| import_path.starts_with(prefix))
    }

    /// Get all remappings
    pub fn remappings(&self) -> &[(String, String)] {
        &self.remappings
    }

    /// Add a remapping
    pub fn add_remapping(&mut self, prefix: String, target: String) {
        self.remappings.push((prefix, target));
        // Re-sort after adding
        self.remappings.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_remapping() {
        let remapper = ImportRemapper::new(
            "/project",
            vec![
                (
                    "@openzeppelin/".to_string(),
                    "lib/openzeppelin-contracts/".to_string(),
                ),
                ("forge-std/".to_string(), "lib/forge-std/src/".to_string()),
            ],
        );

        assert_eq!(
            remapper.remap("@openzeppelin/contracts/token/ERC20/ERC20.sol"),
            "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol"
        );

        assert_eq!(
            remapper.remap("forge-std/Test.sol"),
            "lib/forge-std/src/Test.sol"
        );
    }

    #[test]
    fn test_no_matching_remapping() {
        let remapper = ImportRemapper::new(
            "/project",
            vec![(
                "@openzeppelin/".to_string(),
                "lib/openzeppelin/".to_string(),
            )],
        );

        // Should return original path when no remapping matches
        assert_eq!(
            remapper.remap("./local/Contract.sol"),
            "./local/Contract.sol"
        );
    }

    #[test]
    fn test_longest_prefix_wins() {
        let remapper = ImportRemapper::new(
            "/project",
            vec![
                ("@org/".to_string(), "lib/org/".to_string()),
                ("@org/special/".to_string(), "lib/org-special/".to_string()),
            ],
        );

        // Should match the longer prefix
        assert_eq!(
            remapper.remap("@org/special/Token.sol"),
            "lib/org-special/Token.sol"
        );

        // Should match the shorter prefix
        assert_eq!(
            remapper.remap("@org/other/Token.sol"),
            "lib/org/other/Token.sol"
        );
    }

    #[test]
    fn test_resolve_path() {
        let remapper = ImportRemapper::new(
            "/project",
            vec![("@oz/".to_string(), "lib/oz/".to_string())],
        );

        let resolved = remapper.resolve("@oz/Token.sol");
        assert_eq!(resolved, PathBuf::from("/project/lib/oz/Token.sol"));
    }

    #[test]
    fn test_has_remapping() {
        let remapper = ImportRemapper::new(
            "/project",
            vec![("@openzeppelin/".to_string(), "lib/oz/".to_string())],
        );

        assert!(remapper.has_remapping("@openzeppelin/contracts/ERC20.sol"));
        assert!(!remapper.has_remapping("./local/Contract.sol"));
    }
}
