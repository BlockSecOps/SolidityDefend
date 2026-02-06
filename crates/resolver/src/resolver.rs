//! Path resolution for Solidity imports
//!
//! Resolves import paths to absolute file paths.

use crate::ResolverError;
use crate::remapper::ImportRemapper;
use std::path::{Path, PathBuf};

/// Resolves import paths to absolute file paths
pub struct PathResolver {
    /// Import remapper
    remapper: ImportRemapper,
    /// Project root directory
    root: PathBuf,
    /// Library directories to search
    lib_dirs: Vec<PathBuf>,
}

impl PathResolver {
    /// Create a new path resolver
    pub fn new(
        root: impl AsRef<Path>,
        remappings: Vec<(String, String)>,
        lib_dirs: Vec<PathBuf>,
    ) -> Self {
        Self {
            remapper: ImportRemapper::new(&root, remappings),
            root: root.as_ref().to_path_buf(),
            lib_dirs,
        }
    }

    /// Resolve an import path relative to a source file
    pub fn resolve(&self, import_path: &str, from_file: &Path) -> Result<PathBuf, ResolverError> {
        // 1. Try remapping first
        if self.remapper.has_remapping(import_path) {
            let resolved = self.remapper.resolve(import_path);
            if resolved.exists() {
                return Ok(resolved.canonicalize()?);
            }
        }

        // 2. Try relative path resolution
        if import_path.starts_with("./") || import_path.starts_with("../") {
            let from_dir = from_file.parent().unwrap_or(&self.root);
            let resolved = from_dir.join(import_path);
            if resolved.exists() {
                return Ok(resolved.canonicalize()?);
            }
        }

        // 3. Try library paths
        for lib_dir in &self.lib_dirs {
            let resolved = lib_dir.join(import_path);
            if resolved.exists() {
                return Ok(resolved.canonicalize()?);
            }
        }

        // 4. Try as absolute path from project root
        let from_root = self.root.join(import_path);
        if from_root.exists() {
            return Ok(from_root.canonicalize()?);
        }

        // 5. Try with .sol extension if not present
        if !import_path.ends_with(".sol") {
            let with_ext = format!("{}.sol", import_path);
            if let Ok(resolved) = self.resolve(&with_ext, from_file) {
                return Ok(resolved);
            }
        }

        Err(ResolverError::UnresolvedImport {
            import: import_path.to_string(),
            from_file: from_file.to_path_buf(),
        })
    }

    /// Resolve an import path without a source file context (from project root)
    pub fn resolve_from_root(&self, import_path: &str) -> Result<PathBuf, ResolverError> {
        self.resolve(import_path, &self.root)
    }

    /// Get the project root
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Get the remapper
    pub fn remapper(&self) -> &ImportRemapper {
        &self.remapper
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
        std::fs::create_dir_all(temp.path().join("lib/openzeppelin/contracts/token/ERC20"))
            .unwrap();

        // Create source files
        std::fs::write(temp.path().join("src/Token.sol"), "// Token").unwrap();
        std::fs::write(temp.path().join("src/Utils.sol"), "// Utils").unwrap();
        std::fs::write(
            temp.path()
                .join("lib/openzeppelin/contracts/token/ERC20/ERC20.sol"),
            "// ERC20",
        )
        .unwrap();

        temp
    }

    #[test]
    fn test_resolve_relative_import() {
        let temp = create_test_project();
        let resolver = PathResolver::new(temp.path(), vec![], vec![temp.path().join("lib")]);

        let from_file = temp.path().join("src/Token.sol");
        let resolved = resolver.resolve("./Utils.sol", &from_file).unwrap();

        assert!(resolved.ends_with("Utils.sol"));
    }

    #[test]
    fn test_resolve_with_remapping() {
        let temp = create_test_project();
        let resolver = PathResolver::new(
            temp.path(),
            vec![(
                "@openzeppelin/".to_string(),
                "lib/openzeppelin/".to_string(),
            )],
            vec![],
        );

        let from_file = temp.path().join("src/Token.sol");
        let resolved = resolver
            .resolve("@openzeppelin/contracts/token/ERC20/ERC20.sol", &from_file)
            .unwrap();

        assert!(resolved.ends_with("ERC20.sol"));
    }

    #[test]
    fn test_resolve_library_import() {
        let temp = create_test_project();
        let resolver = PathResolver::new(temp.path(), vec![], vec![temp.path().join("lib")]);

        let from_file = temp.path().join("src/Token.sol");
        let resolved = resolver
            .resolve("openzeppelin/contracts/token/ERC20/ERC20.sol", &from_file)
            .unwrap();

        assert!(resolved.ends_with("ERC20.sol"));
    }

    #[test]
    fn test_unresolved_import_error() {
        let temp = create_test_project();
        let resolver = PathResolver::new(temp.path(), vec![], vec![]);

        let from_file = temp.path().join("src/Token.sol");
        let result = resolver.resolve("nonexistent.sol", &from_file);

        assert!(result.is_err());
        if let Err(ResolverError::UnresolvedImport { import, .. }) = result {
            assert_eq!(import, "nonexistent.sol");
        } else {
            panic!("Expected UnresolvedImport error");
        }
    }
}
