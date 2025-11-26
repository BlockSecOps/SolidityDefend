//! Configuration parsing for Solidity project frameworks
//!
//! Supports Foundry (TOML) and Hardhat (JavaScript) configurations.

pub mod foundry;
pub mod hardhat;

pub use foundry::FoundryConfig;
pub use hardhat::HardhatConfig;

/// Project configuration abstraction
#[derive(Debug, Clone)]
pub enum ProjectConfig {
    /// Foundry project configuration
    Foundry(FoundryConfig),
    /// Hardhat project configuration
    Hardhat(HardhatConfig),
    /// Plain Solidity project (no framework)
    Plain,
}

impl ProjectConfig {
    /// Get the source directory for this project
    pub fn source_dir(&self) -> &str {
        match self {
            ProjectConfig::Foundry(config) => &config.src,
            ProjectConfig::Hardhat(config) => &config.sources,
            ProjectConfig::Plain => ".",
        }
    }

    /// Get the library directories for this project
    pub fn lib_dirs(&self) -> Vec<&str> {
        match self {
            ProjectConfig::Foundry(config) => config.libs.iter().map(|s| s.as_str()).collect(),
            ProjectConfig::Hardhat(_) => vec!["node_modules"],
            ProjectConfig::Plain => vec![],
        }
    }

    /// Get import remappings for this project
    pub fn remappings(&self) -> Vec<(String, String)> {
        match self {
            ProjectConfig::Foundry(config) => config.remappings.clone(),
            ProjectConfig::Hardhat(config) => config.remappings.clone(),
            ProjectConfig::Plain => vec![],
        }
    }

    /// Get the Solidity compiler version if specified
    pub fn solc_version(&self) -> Option<&str> {
        match self {
            ProjectConfig::Foundry(config) => config.solc_version.as_deref(),
            ProjectConfig::Hardhat(config) => config.solidity_version.as_deref(),
            ProjectConfig::Plain => None,
        }
    }

    /// Get directories to exclude from analysis
    pub fn exclude_dirs(&self) -> Vec<&str> {
        match self {
            ProjectConfig::Foundry(config) => {
                let mut dirs = vec!["test", "script"];
                dirs.extend(config.libs.iter().map(|s| s.as_str()));
                dirs
            }
            ProjectConfig::Hardhat(_) => vec!["test", "tests", "node_modules"],
            ProjectConfig::Plain => vec![],
        }
    }
}
