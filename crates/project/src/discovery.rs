//! Solidity file discovery for projects
//!
//! Recursively finds .sol files while respecting project configuration.

use crate::ProjectError;
use crate::config::ProjectConfig;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Project file discovery
pub struct ProjectDiscovery<'a> {
    root: &'a Path,
    config: &'a ProjectConfig,
}

impl<'a> ProjectDiscovery<'a> {
    /// Create a new project discovery instance
    pub fn new(root: &'a Path, config: &'a ProjectConfig) -> Self {
        Self { root, config }
    }

    /// Discover all Solidity files in the project
    pub fn discover_solidity_files(&self) -> Result<Vec<PathBuf>, ProjectError> {
        let source_dir_str = self.config.source_dir();
        // Handle "." as source directory specially - just use the root
        let source_dir = if source_dir_str == "." {
            self.root.to_path_buf()
        } else {
            self.root.join(source_dir_str)
        };
        let exclude_dirs = self.config.exclude_dirs();

        tracing::debug!("Discovering Solidity files in: {:?}", source_dir);
        tracing::debug!("Excluding directories: {:?}", exclude_dirs);

        let mut solidity_files = Vec::new();

        // If source directory exists, search it
        if source_dir.exists() {
            self.discover_in_dir(&source_dir, &exclude_dirs, &mut solidity_files)?;
        } else {
            // Fall back to project root if source dir doesn't exist
            tracing::warn!(
                "Source directory {:?} not found, searching project root",
                source_dir
            );
            self.discover_in_dir(self.root, &exclude_dirs, &mut solidity_files)?;
        }

        // Sort files for deterministic order
        solidity_files.sort();

        Ok(solidity_files)
    }

    /// Discover all Solidity files including tests and scripts
    pub fn discover_all_solidity_files(&self) -> Result<Vec<PathBuf>, ProjectError> {
        let mut solidity_files = Vec::new();

        // Get library directories to exclude
        let lib_dirs = self.config.lib_dirs();

        self.discover_in_dir(self.root, &lib_dirs, &mut solidity_files)?;

        // Sort files for deterministic order
        solidity_files.sort();

        Ok(solidity_files)
    }

    /// Recursively discover Solidity files in a directory
    fn discover_in_dir(
        &self,
        dir: &Path,
        exclude_dirs: &[&str],
        files: &mut Vec<PathBuf>,
    ) -> Result<(), ProjectError> {
        if !dir.exists() {
            return Ok(());
        }

        for entry in WalkDir::new(dir)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                // Never exclude the root directory we're searching
                if e.path() == dir {
                    return true;
                }
                !self.should_exclude(e.path(), exclude_dirs)
            })
        {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "sol" {
                        files.push(path.to_path_buf());
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if a path should be excluded
    fn should_exclude(&self, path: &Path, exclude_dirs: &[&str]) -> bool {
        // Only check components relative to the search root, not the full path
        // Get the file/dir name to check
        if let Some(name) = path.file_name() {
            let name_str = name.to_string_lossy();

            // Skip hidden directories/files (but not . and ..)
            if name_str.starts_with('.') && name_str != "." && name_str != ".." {
                return true;
            }

            // Skip excluded directories
            if exclude_dirs.contains(&name_str.as_ref()) {
                return true;
            }

            // Always skip node_modules
            if name_str == "node_modules" {
                return true;
            }
        }

        false
    }
}

impl From<walkdir::Error> for ProjectError {
    fn from(err: walkdir::Error) -> Self {
        ProjectError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            err.to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_project() -> TempDir {
        let temp = TempDir::new().unwrap();

        // Create directory structure
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        std::fs::create_dir_all(temp.path().join("test")).unwrap();
        std::fs::create_dir_all(temp.path().join("lib/forge-std/src")).unwrap();

        // Create Solidity files
        std::fs::write(temp.path().join("src/Contract.sol"), "// Contract").unwrap();
        std::fs::write(temp.path().join("src/Token.sol"), "// Token").unwrap();
        std::fs::write(temp.path().join("test/Contract.t.sol"), "// Test").unwrap();
        std::fs::write(
            temp.path().join("lib/forge-std/src/Test.sol"),
            "// Forge Test",
        )
        .unwrap();

        temp
    }

    #[test]
    fn test_discover_source_files_plain() {
        let temp = TempDir::new().unwrap();
        // Create a simple structure for Plain config
        std::fs::write(temp.path().join("Contract.sol"), "// Contract").unwrap();
        std::fs::write(temp.path().join("Token.sol"), "// Token").unwrap();

        let config = ProjectConfig::Plain;
        let discovery = ProjectDiscovery::new(temp.path(), &config);

        let files = discovery.discover_solidity_files().unwrap();

        // Should find files in root (Plain config uses . as source)
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_discover_source_files_foundry() {
        let temp = create_test_project();

        // Create a mock Foundry config
        use crate::config::foundry::FoundryConfig;
        let foundry_config = FoundryConfig {
            src: "src".to_string(),
            libs: vec!["lib".to_string()],
            ..Default::default()
        };
        let config = ProjectConfig::Foundry(foundry_config);

        let discovery = ProjectDiscovery::new(temp.path(), &config);
        let files = discovery.discover_solidity_files().unwrap();

        // Should find only source files (src directory)
        assert_eq!(files.len(), 2);
        assert!(files.iter().any(|f| f.ends_with("Contract.sol")));
        assert!(files.iter().any(|f| f.ends_with("Token.sol")));
    }

    #[test]
    fn test_discover_all_files() {
        let temp = create_test_project();

        use crate::config::foundry::FoundryConfig;
        let foundry_config = FoundryConfig {
            src: "src".to_string(),
            libs: vec!["lib".to_string()],
            ..Default::default()
        };
        let config = ProjectConfig::Foundry(foundry_config);

        let discovery = ProjectDiscovery::new(temp.path(), &config);
        let files = discovery.discover_all_solidity_files().unwrap();

        // Should find source and test files, but not lib files
        assert!(files.iter().any(|f| f.ends_with("Contract.sol")));
        assert!(files.iter().any(|f| f.ends_with("Token.sol")));
        assert!(files.iter().any(|f| f.ends_with("Contract.t.sol")));
        // Library files should still be excluded
        assert!(
            !files
                .iter()
                .any(|f| f.to_string_lossy().contains("lib/forge-std"))
        );
    }

    #[test]
    fn test_should_exclude_hidden_dirs() {
        let temp = TempDir::new().unwrap();
        std::fs::create_dir_all(temp.path().join(".git")).unwrap();
        std::fs::write(temp.path().join(".git/config.sol"), "// hidden").unwrap();
        std::fs::write(temp.path().join("Contract.sol"), "// visible").unwrap();

        let config = ProjectConfig::Plain;
        let discovery = ProjectDiscovery::new(temp.path(), &config);
        let files = discovery.discover_solidity_files().unwrap();

        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("Contract.sol"));
    }
}
