// version.rs - Comprehensive version information

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Comprehensive version information for SolidityDefend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    /// Semantic version (e.g., "0.1.0")
    pub version: String,
    /// Full version with build metadata (e.g., "0.1.0-dev.a1b2c3d4+build.123")
    pub full_version: String,
    /// Git commit hash (short)
    pub git_hash: String,
    /// Git branch name
    pub git_branch: String,
    /// Whether git workspace was dirty during build
    pub git_dirty: bool,
    /// Build timestamp
    pub build_timestamp: DateTime<Utc>,
    /// Build number (commits since last tag)
    pub build_number: u64,
    /// Rust compiler version used
    pub rust_version: String,
    /// Target triple
    pub target: String,
    /// Build profile (debug/release)
    pub profile: String,
    /// API version for compatibility checking
    pub api_version: String,
}

#[allow(dead_code)]
impl VersionInfo {
    /// Get the current version information
    pub fn current() -> Self {
        let version = env!("CARGO_PKG_VERSION").to_string();
        let git_hash = env!("GIT_HASH").to_string();
        let git_branch = env!("GIT_BRANCH").to_string();
        let git_dirty = env!("GIT_DIRTY").parse().unwrap_or(false);
        let build_number = env!("BUILD_NUMBER").parse().unwrap_or(0);
        let rust_version = env!("RUST_VERSION").to_string();
        let target = env!("TARGET").to_string();
        let profile = env!("PROFILE").to_string();

        let build_timestamp = env!("BUILD_TIMESTAMP")
            .parse::<DateTime<Utc>>()
            .unwrap_or_else(|_| Utc::now());

        // Generate full version string
        let mut full_version = version.clone();

        // Add pre-release suffix if available
        if let Ok(suffix) = std::env::var("VERSION_SUFFIX") {
            if !suffix.is_empty() {
                full_version.push_str(&suffix);
            }
        }

        // Add build metadata
        let mut build_metadata = Vec::new();
        if build_number > 0 {
            build_metadata.push(format!("build.{}", build_number));
        }
        if !git_hash.is_empty() && git_hash != "unknown" {
            build_metadata.push(format!("git.{}", git_hash));
        }
        if git_dirty {
            build_metadata.push("dirty".to_string());
        }

        if !build_metadata.is_empty() {
            full_version.push('+');
            full_version.push_str(&build_metadata.join("."));
        }

        // API version for compatibility (major.minor)
        let api_version = version.split('.').take(2).collect::<Vec<_>>().join(".");

        Self {
            version,
            full_version,
            git_hash,
            git_branch,
            git_dirty,
            build_timestamp,
            build_number,
            rust_version,
            target,
            profile,
            api_version,
        }
    }

    /// Get a short version string for display
    pub fn short(&self) -> String {
        if self.git_dirty {
            format!("{}-dirty", self.version)
        } else {
            self.version.clone()
        }
    }

    /// Get a medium version string with git info
    pub fn medium(&self) -> String {
        if self.git_hash == "unknown" {
            self.version.clone()
        } else {
            format!("{} ({})", self.version, self.git_hash)
        }
    }

    /// Get the full version string
    pub fn long(&self) -> &str {
        &self.full_version
    }

    /// Check if this is a development build
    pub fn is_development(&self) -> bool {
        self.profile == "debug" || self.git_branch != "main" || self.git_dirty
    }

    /// Check if this is a release build
    pub fn is_release(&self) -> bool {
        self.profile == "release" && !self.git_dirty
    }

    /// Check if this is a pre-release version
    pub fn is_prerelease(&self) -> bool {
        self.version.contains('-')
    }

    /// Get build age in days
    pub fn build_age_days(&self) -> i64 {
        let now = Utc::now();
        (now - self.build_timestamp).num_days()
    }

    /// Check API compatibility with another version
    pub fn is_api_compatible(&self, other: &str) -> bool {
        let other_api = other.split('.').take(2).collect::<Vec<_>>().join(".");
        self.api_version == other_api
    }

    /// Generate a user-agent string
    pub fn user_agent(&self) -> String {
        format!(
            "SolidityDefend/{} ({}) rust/{}",
            self.version, self.target, self.rust_version
        )
    }

    /// Generate build information for debugging
    pub fn build_info(&self) -> String {
        format!(
            "Version: {}\nGit: {} ({})\nBuilt: {} with Rust {}\nTarget: {} ({})",
            self.full_version,
            self.git_hash,
            self.git_branch,
            self.build_timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            self.rust_version,
            self.target,
            self.profile
        )
    }
}

impl fmt::Display for VersionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.version)
    }
}

/// Version constants for easy access
pub mod constants {
    use super::VersionInfo;
    use std::sync::OnceLock;

    #[allow(dead_code)]
    static VERSION_INFO: OnceLock<VersionInfo> = OnceLock::new();

    /// Get the global version info instance
    #[allow(dead_code)]
    pub fn version() -> &'static VersionInfo {
        VERSION_INFO.get_or_init(VersionInfo::current)
    }

    /// Version string
    #[allow(dead_code)]
    pub fn version_string() -> &'static str {
        &version().version
    }

    /// Full version with build metadata
    #[allow(dead_code)]
    pub fn full_version_string() -> &'static str {
        &version().full_version
    }

    /// Git commit hash
    #[allow(dead_code)]
    pub fn git_hash() -> &'static str {
        &version().git_hash
    }

    /// Git branch
    #[allow(dead_code)]
    pub fn git_branch() -> &'static str {
        &version().git_branch
    }
}

/// Version comparison utilities
pub mod compare {
    use std::cmp::Ordering;

    /// Parse a semantic version string
    #[allow(dead_code)]
    fn parse_version(version: &str) -> Result<(u32, u32, u32), String> {
        let clean_version = version.split('-').next().unwrap_or(version);
        let parts: Vec<&str> = clean_version.split('.').collect();

        if parts.len() != 3 {
            return Err(format!("Invalid version format: {}", version));
        }

        let major = parts[0]
            .parse()
            .map_err(|_| format!("Invalid major version: {}", parts[0]))?;
        let minor = parts[1]
            .parse()
            .map_err(|_| format!("Invalid minor version: {}", parts[1]))?;
        let patch = parts[2]
            .parse()
            .map_err(|_| format!("Invalid patch version: {}", parts[2]))?;

        Ok((major, minor, patch))
    }

    /// Compare two semantic versions
    #[allow(dead_code)]
    pub fn compare_versions(v1: &str, v2: &str) -> Result<Ordering, String> {
        let (maj1, min1, pat1) = parse_version(v1)?;
        let (maj2, min2, pat2) = parse_version(v2)?;

        Ok((maj1, min1, pat1).cmp(&(maj2, min2, pat2)))
    }

    /// Check if version1 is compatible with version2 (same major.minor)
    #[allow(dead_code)]
    pub fn is_compatible(v1: &str, v2: &str) -> Result<bool, String> {
        let (maj1, min1, _) = parse_version(v1)?;
        let (maj2, min2, _) = parse_version(v2)?;

        Ok(maj1 == maj2 && min1 == min2)
    }

    /// Check if version1 is newer than version2
    #[allow(dead_code)]
    pub fn is_newer(v1: &str, v2: &str) -> Result<bool, String> {
        Ok(compare_versions(v1, v2)? == Ordering::Greater)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_info_creation() {
        let version = VersionInfo::current();
        assert!(!version.version.is_empty());
        assert!(!version.full_version.is_empty());
    }

    #[test]
    fn test_version_comparison() {
        use crate::version::compare::*;

        assert!(is_newer("1.1.0", "1.0.0").unwrap());
        assert!(!is_newer("1.0.0", "1.1.0").unwrap());
        assert!(is_compatible("1.0.0", "1.0.5").unwrap());
        assert!(!is_compatible("1.0.0", "1.1.0").unwrap());
    }

    #[test]
    fn test_api_compatibility() {
        let version = VersionInfo::current();
        // Current version is 1.10.x, so 1.10.x should be compatible
        assert!(version.is_api_compatible("1.10.0"));
        assert!(version.is_api_compatible("1.10.8"));
        // But 1.9.x and 1.11.x should not be compatible (different minor version)
        assert!(!version.is_api_compatible("1.9.0"));
        assert!(!version.is_api_compatible("1.11.0"));
    }
}
