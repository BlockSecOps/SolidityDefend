//! Hardhat configuration parser
//!
//! Uses regex-based parsing for JavaScript/TypeScript config files.

use crate::ProjectError;
use regex::Regex;
use std::path::Path;

/// Hardhat project configuration
#[derive(Debug, Clone, Default)]
pub struct HardhatConfig {
    /// Source directory (default: "contracts")
    pub sources: String,
    /// Test directory (default: "test")
    pub tests: String,
    /// Artifacts directory (default: "artifacts")
    pub artifacts: String,
    /// Cache directory (default: "cache")
    pub cache: String,
    /// Solidity compiler version
    pub solidity_version: Option<String>,
    /// Import remappings (from hardhat.config or package.json)
    pub remappings: Vec<(String, String)>,
}

impl HardhatConfig {
    /// Load Hardhat configuration from a project directory
    pub fn load(project_root: &Path) -> Result<Self, ProjectError> {
        let mut config = Self::default();

        // Set defaults
        config.sources = "contracts".to_string();
        config.tests = "test".to_string();
        config.artifacts = "artifacts".to_string();
        config.cache = "cache".to_string();

        // Try to find hardhat.config.js or hardhat.config.ts
        let config_paths = [
            project_root.join("hardhat.config.ts"),
            project_root.join("hardhat.config.js"),
            project_root.join("hardhat.config.cjs"),
            project_root.join("hardhat.config.mjs"),
        ];

        for config_path in &config_paths {
            if config_path.exists() {
                let content = std::fs::read_to_string(config_path)?;
                config.parse_config_content(&content);
                break;
            }
        }

        // Generate remappings from node_modules
        config.remappings = Self::discover_node_modules_remappings(project_root);

        tracing::debug!("Loaded Hardhat config: {:?}", config);
        Ok(config)
    }

    /// Parse configuration from file content using regex
    fn parse_config_content(&mut self, content: &str) {
        // Extract solidity version
        // Patterns: solidity: "0.8.20" or version: "0.8.20"
        let version_patterns = [
            r#"solidity:\s*["']([0-9]+\.[0-9]+\.[0-9]+)["']"#,
            r#"version:\s*["']([0-9]+\.[0-9]+\.[0-9]+)["']"#,
            r#"solidity:\s*\{\s*version:\s*["']([0-9]+\.[0-9]+\.[0-9]+)["']"#,
        ];

        for pattern in &version_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(caps) = re.captures(content) {
                    if let Some(version) = caps.get(1) {
                        self.solidity_version = Some(version.as_str().to_string());
                        break;
                    }
                }
            }
        }

        // Extract paths configuration
        // Pattern: paths: { sources: "contracts", tests: "test", ... }
        if let Ok(re) = Regex::new(r#"sources:\s*["']([^"']+)["']"#) {
            if let Some(caps) = re.captures(content) {
                if let Some(sources) = caps.get(1) {
                    self.sources = sources.as_str().to_string();
                }
            }
        }

        if let Ok(re) = Regex::new(r#"tests:\s*["']([^"']+)["']"#) {
            if let Some(caps) = re.captures(content) {
                if let Some(tests) = caps.get(1) {
                    self.tests = tests.as_str().to_string();
                }
            }
        }

        if let Ok(re) = Regex::new(r#"artifacts:\s*["']([^"']+)["']"#) {
            if let Some(caps) = re.captures(content) {
                if let Some(artifacts) = caps.get(1) {
                    self.artifacts = artifacts.as_str().to_string();
                }
            }
        }

        if let Ok(re) = Regex::new(r#"cache:\s*["']([^"']+)["']"#) {
            if let Some(caps) = re.captures(content) {
                if let Some(cache) = caps.get(1) {
                    self.cache = cache.as_str().to_string();
                }
            }
        }
    }

    /// Discover remappings from node_modules
    fn discover_node_modules_remappings(project_root: &Path) -> Vec<(String, String)> {
        let mut remappings = Vec::new();
        let node_modules = project_root.join("node_modules");

        if !node_modules.is_dir() {
            return remappings;
        }

        // Common Solidity libraries to look for
        let common_libs = [
            "@openzeppelin/contracts",
            "@openzeppelin/contracts-upgradeable",
            "@chainlink/contracts",
            "@uniswap/v2-core",
            "@uniswap/v2-periphery",
            "@uniswap/v3-core",
            "@uniswap/v3-periphery",
            "solmate",
            "solady",
        ];

        for lib in &common_libs {
            let lib_path = node_modules.join(lib);
            if lib_path.is_dir() {
                let prefix = format!("{}/", lib);
                let target = format!("node_modules/{}/", lib);
                remappings.push((prefix, target));
            }
        }

        // Also check for @-scoped packages
        if let Ok(entries) = std::fs::read_dir(&node_modules) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with('@') {
                    // Scoped package, check subdirectories
                    if let Ok(scope_entries) = std::fs::read_dir(entry.path()) {
                        for scope_entry in scope_entries.flatten() {
                            let pkg_name = scope_entry.file_name().to_string_lossy().to_string();
                            let full_name = format!("{}/{}", name, pkg_name);

                            // Check if it contains Solidity files
                            let pkg_path = scope_entry.path();
                            if Self::contains_solidity(&pkg_path) {
                                let prefix = format!("{}/", full_name);
                                let target = format!("node_modules/{}/", full_name);
                                if !remappings.iter().any(|(p, _)| p == &prefix) {
                                    remappings.push((prefix, target));
                                }
                            }
                        }
                    }
                }
            }
        }

        remappings
    }

    /// Check if a directory contains Solidity files
    fn contains_solidity(path: &Path) -> bool {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let entry_path = entry.path();
                if entry_path.is_file() {
                    if let Some(ext) = entry_path.extension() {
                        if ext == "sol" {
                            return true;
                        }
                    }
                } else if entry_path.is_dir() {
                    let dir_name = entry.file_name().to_string_lossy().to_string();
                    // Check contracts or src directories
                    if dir_name == "contracts" || dir_name == "src" {
                        if Self::contains_solidity(&entry_path) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_load_default_config() {
        let temp = TempDir::new().unwrap();
        let config_content = r#"
module.exports = {
    solidity: "0.8.20",
};
"#;
        std::fs::write(temp.path().join("hardhat.config.js"), config_content).unwrap();

        let config = HardhatConfig::load(temp.path()).unwrap();
        assert_eq!(config.sources, "contracts");
        assert_eq!(config.solidity_version, Some("0.8.20".to_string()));
    }

    #[test]
    fn test_load_typescript_config() {
        let temp = TempDir::new().unwrap();
        let config_content = r#"
import { HardhatUserConfig } from "hardhat/config";

const config: HardhatUserConfig = {
    solidity: {
        version: "0.8.19",
        settings: {
            optimizer: {
                enabled: true,
                runs: 200,
            },
        },
    },
    paths: {
        sources: "./src",
        tests: "./tests",
        artifacts: "./build",
    },
};

export default config;
"#;
        std::fs::write(temp.path().join("hardhat.config.ts"), config_content).unwrap();

        let config = HardhatConfig::load(temp.path()).unwrap();
        assert_eq!(config.sources, "./src");
        assert_eq!(config.tests, "./tests");
        assert_eq!(config.artifacts, "./build");
        assert_eq!(config.solidity_version, Some("0.8.19".to_string()));
    }

    #[test]
    fn test_parse_solidity_version() {
        let mut config = HardhatConfig::default();

        // Test simple version
        config.parse_config_content(r#"solidity: "0.8.20""#);
        assert_eq!(config.solidity_version, Some("0.8.20".to_string()));

        // Test object version
        config.solidity_version = None;
        config.parse_config_content(r#"solidity: { version: "0.8.19" }"#);
        assert_eq!(config.solidity_version, Some("0.8.19".to_string()));
    }

    #[test]
    fn test_no_config_file() {
        let temp = TempDir::new().unwrap();
        // No config file present

        let config = HardhatConfig::load(temp.path()).unwrap();
        assert_eq!(config.sources, "contracts");
        assert_eq!(config.solidity_version, None);
    }
}
