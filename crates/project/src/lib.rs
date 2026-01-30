//! Project mode support for SolidityDefend
//!
//! This crate provides support for analyzing Foundry and Hardhat projects,
//! including framework detection, configuration parsing, and file discovery.

pub mod config;
pub mod detector;
pub mod discovery;

pub use config::{FoundryConfig, HardhatConfig, ProjectConfig};
pub use detector::{detect_framework, Framework};
pub use discovery::ProjectDiscovery;

use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors that can occur during project analysis
#[derive(Error, Debug)]
pub enum ProjectError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Config parse error: {0}")]
    ConfigParse(String),

    #[error("No Solidity files found in project")]
    NoSolidityFiles,

    #[error("Invalid project structure: {0}")]
    InvalidStructure(String),

    #[error("Unsupported framework: {0}")]
    UnsupportedFramework(String),
}

/// Result type for project operations
pub type ProjectResult<T> = Result<T, ProjectError>;

/// Represents a Solidity project with its configuration and files
#[derive(Debug, Clone)]
pub struct Project {
    /// Root directory of the project
    pub root: PathBuf,
    /// Detected framework type
    pub framework: Framework,
    /// Project configuration
    pub config: ProjectConfig,
    /// Discovered Solidity files
    pub solidity_files: Vec<PathBuf>,
    /// Import remappings
    pub remappings: Vec<(String, String)>,
}

impl Project {
    /// Load a project from the given path
    pub fn load(path: impl AsRef<Path>) -> ProjectResult<Self> {
        let root = path.as_ref().to_path_buf();

        if !root.exists() {
            return Err(ProjectError::InvalidStructure(format!(
                "Project path does not exist: {}",
                root.display()
            )));
        }

        // Detect framework
        let framework = detect_framework(&root);
        tracing::info!("Detected framework: {:?}", framework);

        // Parse configuration
        let config = match framework {
            Framework::Foundry => {
                let foundry_config = FoundryConfig::load(&root)?;
                ProjectConfig::Foundry(foundry_config)
            }
            Framework::Hardhat => {
                let hardhat_config = HardhatConfig::load(&root)?;
                ProjectConfig::Hardhat(hardhat_config)
            }
            Framework::Plain => ProjectConfig::Plain,
        };

        // Get remappings
        let remappings = config.remappings();

        // Discover Solidity files
        let discovery = ProjectDiscovery::new(&root, &config);
        let solidity_files = discovery.discover_solidity_files()?;

        if solidity_files.is_empty() {
            return Err(ProjectError::NoSolidityFiles);
        }

        tracing::info!("Found {} Solidity files", solidity_files.len());

        Ok(Self {
            root,
            framework,
            config,
            solidity_files,
            remappings,
        })
    }

    /// Get the source directory for this project
    pub fn source_dir(&self) -> PathBuf {
        match &self.config {
            ProjectConfig::Foundry(config) => self.root.join(&config.src),
            ProjectConfig::Hardhat(config) => self.root.join(&config.sources),
            ProjectConfig::Plain => self.root.clone(),
        }
    }

    /// Get the library directories for this project
    pub fn lib_dirs(&self) -> Vec<PathBuf> {
        match &self.config {
            ProjectConfig::Foundry(config) => {
                config.libs.iter().map(|lib| self.root.join(lib)).collect()
            }
            ProjectConfig::Hardhat(_) => vec![self.root.join("node_modules")],
            ProjectConfig::Plain => vec![],
        }
    }

    /// Get the Solidity compiler version for this project
    pub fn solc_version(&self) -> Option<&str> {
        match &self.config {
            ProjectConfig::Foundry(config) => config.solc_version.as_deref(),
            ProjectConfig::Hardhat(config) => config.solidity_version.as_deref(),
            ProjectConfig::Plain => None,
        }
    }

    /// Get the root directory of the project
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Get the detected framework
    pub fn framework(&self) -> Framework {
        self.framework
    }

    /// Get the project configuration
    pub fn project_config(&self) -> &ProjectConfig {
        &self.config
    }

    /// Get directories that are excluded from analysis
    pub fn excluded_dirs(&self) -> Vec<&str> {
        self.config.exclude_dirs()
    }

    /// Get library directory paths as strings
    pub fn lib_dir_names(&self) -> Vec<String> {
        match &self.config {
            ProjectConfig::Foundry(config) => config.libs.clone(),
            ProjectConfig::Hardhat(_) => vec!["node_modules".to_string()],
            ProjectConfig::Plain => vec![],
        }
    }

    /// Get remappings for the project
    pub fn remappings(&self) -> &[(String, String)] {
        &self.remappings
    }
}
