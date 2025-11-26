//! Framework detection for Solidity projects
//!
//! Detects whether a project uses Foundry, Hardhat, or is a plain Solidity project.

use std::path::Path;

/// Supported project frameworks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framework {
    /// Foundry project (foundry.toml)
    Foundry,
    /// Hardhat project (hardhat.config.js/ts)
    Hardhat,
    /// Plain Solidity files (no framework)
    Plain,
}

impl std::fmt::Display for Framework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Framework::Foundry => write!(f, "foundry"),
            Framework::Hardhat => write!(f, "hardhat"),
            Framework::Plain => write!(f, "plain"),
        }
    }
}

impl Framework {
    /// Parse framework from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "foundry" | "forge" => Some(Framework::Foundry),
            "hardhat" | "hh" => Some(Framework::Hardhat),
            "plain" | "none" => Some(Framework::Plain),
            _ => None,
        }
    }
}

/// Detect the framework used by a project at the given path
pub fn detect_framework(path: &Path) -> Framework {
    // Check for Foundry first (foundry.toml)
    if path.join("foundry.toml").exists() {
        return Framework::Foundry;
    }

    // Check for Hardhat (hardhat.config.js or hardhat.config.ts)
    if path.join("hardhat.config.js").exists() || path.join("hardhat.config.ts").exists() {
        return Framework::Hardhat;
    }

    // Check for Foundry in parent directories (for monorepos)
    if let Some(parent) = path.parent() {
        if parent.join("foundry.toml").exists() {
            return Framework::Foundry;
        }
    }

    // Check for common framework indicators
    if path.join("forge.toml").exists() {
        return Framework::Foundry;
    }

    // Check for Hardhat-specific files
    if path.join("hardhat.config.cjs").exists() || path.join("hardhat.config.mjs").exists() {
        return Framework::Hardhat;
    }

    // Check for package.json with hardhat dependency
    if let Ok(content) = std::fs::read_to_string(path.join("package.json")) {
        if content.contains("\"hardhat\"") {
            return Framework::Hardhat;
        }
    }

    // Default to Plain if no framework detected
    Framework::Plain
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_detect_foundry() {
        let temp = TempDir::new().unwrap();
        std::fs::write(temp.path().join("foundry.toml"), "[profile.default]").unwrap();

        assert_eq!(detect_framework(temp.path()), Framework::Foundry);
    }

    #[test]
    fn test_detect_hardhat_js() {
        let temp = TempDir::new().unwrap();
        std::fs::write(temp.path().join("hardhat.config.js"), "module.exports = {}").unwrap();

        assert_eq!(detect_framework(temp.path()), Framework::Hardhat);
    }

    #[test]
    fn test_detect_hardhat_ts() {
        let temp = TempDir::new().unwrap();
        std::fs::write(temp.path().join("hardhat.config.ts"), "export default {}").unwrap();

        assert_eq!(detect_framework(temp.path()), Framework::Hardhat);
    }

    #[test]
    fn test_detect_plain() {
        let temp = TempDir::new().unwrap();
        // No framework files

        assert_eq!(detect_framework(temp.path()), Framework::Plain);
    }

    #[test]
    fn test_framework_from_str() {
        assert_eq!(Framework::from_str("foundry"), Some(Framework::Foundry));
        assert_eq!(Framework::from_str("Foundry"), Some(Framework::Foundry));
        assert_eq!(Framework::from_str("forge"), Some(Framework::Foundry));
        assert_eq!(Framework::from_str("hardhat"), Some(Framework::Hardhat));
        assert_eq!(Framework::from_str("hh"), Some(Framework::Hardhat));
        assert_eq!(Framework::from_str("plain"), Some(Framework::Plain));
        assert_eq!(Framework::from_str("unknown"), None);
    }
}
