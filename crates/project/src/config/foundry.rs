//! Foundry configuration parser
//!
//! Parses foundry.toml and remappings.txt files.

use crate::ProjectError;
use serde::Deserialize;
use std::path::Path;

/// Foundry project configuration
#[derive(Debug, Clone, Default)]
pub struct FoundryConfig {
    /// Source directory (default: "src")
    pub src: String,
    /// Test directory (default: "test")
    pub test: String,
    /// Script directory (default: "script")
    pub script: String,
    /// Output directory (default: "out")
    pub out: String,
    /// Library directories (default: ["lib"])
    pub libs: Vec<String>,
    /// Import remappings
    pub remappings: Vec<(String, String)>,
    /// Solidity compiler version
    pub solc_version: Option<String>,
    /// EVM version
    pub evm_version: Option<String>,
    /// Optimizer enabled
    pub optimizer: bool,
    /// Optimizer runs
    pub optimizer_runs: u32,
}

/// Raw TOML structure for foundry.toml
#[derive(Debug, Deserialize)]
struct FoundryToml {
    profile: Option<ProfileSection>,
}

#[derive(Debug, Deserialize)]
struct ProfileSection {
    default: Option<ProfileConfig>,
}

/// Optimizer configuration - can be a boolean or a table
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OptimizerConfig {
    Bool(bool),
    Table(OptimizerTable),
}

#[derive(Debug, Deserialize)]
struct OptimizerTable {
    enabled: Option<bool>,
    runs: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct ProfileConfig {
    src: Option<String>,
    test: Option<String>,
    script: Option<String>,
    out: Option<String>,
    libs: Option<Vec<String>>,
    remappings: Option<Vec<String>>,
    solc_version: Option<String>,
    solc: Option<String>,
    evm_version: Option<String>,
    optimizer: Option<OptimizerConfig>,
    optimizer_runs: Option<u32>,
}

impl FoundryConfig {
    /// Load Foundry configuration from a project directory
    pub fn load(project_root: &Path) -> Result<Self, ProjectError> {
        let config_path = project_root.join("foundry.toml");
        let mut config = Self::default();

        // Set defaults
        config.src = "src".to_string();
        config.test = "test".to_string();
        config.script = "script".to_string();
        config.out = "out".to_string();
        config.libs = vec!["lib".to_string()];
        config.optimizer = false;
        config.optimizer_runs = 200;

        // Parse foundry.toml if it exists
        if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)?;
            let toml: FoundryToml = toml::from_str(&content).map_err(|e| {
                ProjectError::ConfigParse(format!("Failed to parse foundry.toml: {}", e))
            })?;

            if let Some(profile) = toml.profile {
                if let Some(default) = profile.default {
                    if let Some(src) = default.src {
                        config.src = src;
                    }
                    if let Some(test) = default.test {
                        config.test = test;
                    }
                    if let Some(script) = default.script {
                        config.script = script;
                    }
                    if let Some(out) = default.out {
                        config.out = out;
                    }
                    if let Some(libs) = default.libs {
                        config.libs = libs;
                    }
                    if let Some(remappings) = default.remappings {
                        config.remappings = parse_remappings(&remappings);
                    }
                    // solc_version takes precedence over solc
                    config.solc_version = default.solc_version.or(default.solc);
                    config.evm_version = default.evm_version;

                    // Handle optimizer config - can be bool or table
                    if let Some(opt) = default.optimizer {
                        match opt {
                            OptimizerConfig::Bool(enabled) => {
                                config.optimizer = enabled;
                            }
                            OptimizerConfig::Table(table) => {
                                if let Some(enabled) = table.enabled {
                                    config.optimizer = enabled;
                                }
                                if let Some(runs) = table.runs {
                                    config.optimizer_runs = runs;
                                }
                            }
                        }
                    }

                    // optimizer_runs at profile level takes precedence
                    if let Some(runs) = default.optimizer_runs {
                        config.optimizer_runs = runs;
                    }
                }
            }
        }

        // Load remappings from remappings.txt (appends to config remappings)
        let remappings_path = project_root.join("remappings.txt");
        if remappings_path.exists() {
            let content = std::fs::read_to_string(&remappings_path)?;
            let file_remappings: Vec<String> = content
                .lines()
                .filter(|line| !line.trim().is_empty() && !line.trim().starts_with('#'))
                .map(|s| s.to_string())
                .collect();
            config.remappings.extend(parse_remappings(&file_remappings));
        }

        // Auto-discover remappings from lib directory
        for lib_dir in &config.libs {
            let lib_path = project_root.join(lib_dir);
            if lib_path.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&lib_path) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            let lib_name = entry.file_name().to_string_lossy().to_string();
                            // Check if this lib has a src directory
                            let src_path = path.join("src");
                            let target = if src_path.is_dir() {
                                format!("{}/{}/src/", lib_dir, lib_name)
                            } else {
                                format!("{}/{}/", lib_dir, lib_name)
                            };

                            // Add remapping if not already present
                            let prefix = format!("{}@", lib_name);
                            let alt_prefix = format!("{}/", lib_name);

                            if !config.remappings.iter().any(|(p, _)| p == &prefix || p == &alt_prefix) {
                                config.remappings.push((alt_prefix, target));
                            }
                        }
                    }
                }
            }
        }

        tracing::debug!("Loaded Foundry config: {:?}", config);
        Ok(config)
    }
}

/// Parse remapping strings into (prefix, target) tuples
fn parse_remappings(remappings: &[String]) -> Vec<(String, String)> {
    remappings
        .iter()
        .filter_map(|r| {
            let parts: Vec<&str> = r.splitn(2, '=').collect();
            if parts.len() == 2 {
                Some((parts[0].to_string(), parts[1].to_string()))
            } else {
                tracing::warn!("Invalid remapping format: {}", r);
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_load_default_config() {
        let temp = TempDir::new().unwrap();
        std::fs::write(temp.path().join("foundry.toml"), "[profile.default]").unwrap();

        let config = FoundryConfig::load(temp.path()).unwrap();
        assert_eq!(config.src, "src");
        assert_eq!(config.test, "test");
        assert_eq!(config.libs, vec!["lib"]);
    }

    #[test]
    fn test_load_custom_config() {
        let temp = TempDir::new().unwrap();
        let toml_content = r#"
[profile.default]
src = "contracts"
test = "tests"
libs = ["lib", "node_modules"]
solc_version = "0.8.20"
optimizer = true
optimizer_runs = 1000
remappings = [
    "@openzeppelin/=lib/openzeppelin-contracts/",
    "forge-std/=lib/forge-std/src/"
]
"#;
        std::fs::write(temp.path().join("foundry.toml"), toml_content).unwrap();

        let config = FoundryConfig::load(temp.path()).unwrap();
        assert_eq!(config.src, "contracts");
        assert_eq!(config.test, "tests");
        assert_eq!(config.libs, vec!["lib", "node_modules"]);
        assert_eq!(config.solc_version, Some("0.8.20".to_string()));
        assert!(config.optimizer);
        assert_eq!(config.optimizer_runs, 1000);
        assert_eq!(config.remappings.len(), 2);
    }

    #[test]
    fn test_load_remappings_txt() {
        let temp = TempDir::new().unwrap();
        std::fs::write(temp.path().join("foundry.toml"), "[profile.default]").unwrap();
        let remappings = r#"
# Comment line
@openzeppelin/=lib/openzeppelin-contracts/
forge-std/=lib/forge-std/src/
"#;
        std::fs::write(temp.path().join("remappings.txt"), remappings).unwrap();

        let config = FoundryConfig::load(temp.path()).unwrap();
        assert_eq!(config.remappings.len(), 2);
        assert!(config.remappings.contains(&(
            "@openzeppelin/".to_string(),
            "lib/openzeppelin-contracts/".to_string()
        )));
    }

    #[test]
    fn test_parse_remappings() {
        let remappings = vec![
            "@openzeppelin/=lib/openzeppelin/".to_string(),
            "forge-std/=lib/forge-std/src/".to_string(),
            "invalid_no_equals".to_string(),
        ];

        let parsed = parse_remappings(&remappings);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], ("@openzeppelin/".to_string(), "lib/openzeppelin/".to_string()));
        assert_eq!(parsed[1], ("forge-std/".to_string(), "lib/forge-std/src/".to_string()));
    }
}
