use anyhow::{Result, anyhow, Context};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::collections::HashMap;

use detectors::registry::RegistryConfig;
use detectors::types::{Severity, Confidence};
use detectors::detector::DetectorCategory;
use cache::CacheConfig;
use output::OutputFormat;

/// Main configuration structure for SolidityDefend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolidityDefendConfig {
    /// General settings
    #[serde(default)]
    pub general: GeneralConfig,

    /// Detector configuration
    #[serde(default)]
    pub detectors: DetectorConfig,

    /// Cache configuration
    #[serde(default)]
    pub cache: CacheSettings,

    /// Output configuration
    #[serde(default)]
    pub output: OutputConfig,

    /// Performance settings
    #[serde(default)]
    pub performance: PerformanceConfig,
}

impl Default for SolidityDefendConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            detectors: DetectorConfig::default(),
            cache: CacheSettings::default(),
            output: OutputConfig::default(),
            performance: PerformanceConfig::default(),
        }
    }
}

/// General application settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Minimum severity level to report
    pub min_severity: Severity,

    /// Enable verbose logging
    pub verbose: bool,

    /// Enable quiet mode (minimal output)
    pub quiet: bool,

    /// Custom include patterns for file scanning
    pub include_patterns: Vec<String>,

    /// Custom exclude patterns for file scanning
    pub exclude_patterns: Vec<String>,

    /// Maximum file size to analyze (in bytes)
    pub max_file_size: usize,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            min_severity: Severity::Info,
            verbose: false,
            quiet: false,
            include_patterns: vec!["**/*.sol".to_string()],
            exclude_patterns: vec![
                "**/node_modules/**".to_string(),
                "**/test/**".to_string(),
                "**/tests/**".to_string(),
                "**/.git/**".to_string(),
            ],
            max_file_size: 10 * 1024 * 1024, // 10MB
        }
    }
}

/// Detector-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorConfig {
    /// Minimum severity level for detectors
    pub min_severity: Severity,

    /// Minimum confidence level for detectors
    pub min_confidence: Confidence,

    /// Detector categories to enable (empty = all)
    pub enabled_categories: Vec<DetectorCategory>,

    /// Specific detectors to disable
    pub disabled_detectors: Vec<String>,

    /// Specific detectors to enable (overrides disabled)
    pub enabled_detectors: Vec<String>,

    /// Maximum execution time per detector (seconds)
    pub detector_timeout: u64,

    /// Stop analysis on first critical finding
    pub fail_fast: bool,

    /// Custom detector settings
    pub custom_settings: HashMap<String, serde_yaml::Value>,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            min_severity: Severity::Info,
            min_confidence: Confidence::Low,
            enabled_categories: Vec::new(),
            disabled_detectors: Vec::new(),
            enabled_detectors: Vec::new(),
            detector_timeout: 30,
            fail_fast: false,
            custom_settings: HashMap::new(),
        }
    }
}

/// Cache settings (wrapper around CacheConfig for YAML serialization)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheSettings {
    /// Enable caching
    pub enabled: bool,

    /// Maximum memory usage in MB
    pub max_memory_mb: usize,

    /// Maximum cache entries
    pub max_entries: usize,

    /// Cache directory path
    pub cache_dir: Option<PathBuf>,

    /// Enable persistent cache
    pub persistent: bool,

    /// Cache TTL in hours
    pub ttl_hours: u64,
}

impl Default for CacheSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            max_memory_mb: 256,
            max_entries: 10000,
            cache_dir: None, // Will use default temp dir
            persistent: true,
            ttl_hours: 1,
        }
    }
}

impl From<&CacheSettings> for CacheConfig {
    fn from(settings: &CacheSettings) -> Self {
        CacheConfig {
            max_memory_usage: settings.max_memory_mb * 1024 * 1024,
            max_entries: settings.max_entries,
            cache_dir: settings.cache_dir.clone()
                .unwrap_or_else(|| std::env::temp_dir().join("soliditydefend_cache")),
            persistent: settings.persistent,
            ttl_seconds: settings.ttl_hours * 3600,
        }
    }
}

/// Output configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Default output format
    pub format: OutputFormatSetting,

    /// Enable colors in console output
    pub colors: bool,

    /// Show fix suggestions
    pub show_fixes: bool,

    /// Show code snippets in output
    pub show_snippets: bool,

    /// Maximum lines to show in snippets
    pub snippet_lines: usize,

    /// Sort findings by severity
    pub sort_by_severity: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: OutputFormatSetting::Console,
            colors: true,
            show_fixes: true,
            show_snippets: true,
            snippet_lines: 3,
            sort_by_severity: true,
        }
    }
}

/// Output format setting for serialization
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormatSetting {
    Console,
    Json,
}

impl From<OutputFormatSetting> for OutputFormat {
    fn from(setting: OutputFormatSetting) -> Self {
        match setting {
            OutputFormatSetting::Console => OutputFormat::Console,
            OutputFormatSetting::Json => OutputFormat::Json,
        }
    }
}

impl From<OutputFormat> for OutputFormatSetting {
    fn from(format: OutputFormat) -> Self {
        match format {
            OutputFormat::Console => OutputFormatSetting::Console,
            OutputFormat::Json => OutputFormatSetting::Json,
        }
    }
}

/// Performance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Maximum number of parallel threads
    pub max_threads: usize,

    /// Enable parallel analysis
    pub parallel_analysis: bool,

    /// Batch size for processing multiple files
    pub batch_size: usize,

    /// Memory limit per analysis (MB)
    pub memory_limit_mb: usize,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            max_threads: num_cpus::get().min(8), // Use available CPUs but cap at 8
            parallel_analysis: true,
            batch_size: 10,
            memory_limit_mb: 512,
        }
    }
}

impl From<&DetectorConfig> for RegistryConfig {
    fn from(config: &DetectorConfig) -> Self {
        RegistryConfig {
            max_threads: 1, // Controlled by PerformanceConfig
            detector_timeout_secs: config.detector_timeout,
            fail_fast: config.fail_fast,
            min_severity: config.min_severity,
            min_confidence: config.min_confidence,
            enabled_categories: config.enabled_categories.clone(),
        }
    }
}

impl SolidityDefendConfig {
    /// Load configuration from file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let config: SolidityDefendConfig = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

        Ok(config)
    }

    /// Save configuration to file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();

        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory: {}", parent.display()))?;
        }

        let content = serde_yaml::to_string(self)
            .context("Failed to serialize configuration")?;

        std::fs::write(path, content)
            .with_context(|| format!("Failed to write config file: {}", path.display()))?;

        Ok(())
    }

    /// Load configuration with fallback chain
    pub fn load_from_defaults_and_file(config_file: Option<&Path>) -> Result<Self> {
        let mut config = Self::default();

        // Try to load from various locations in order of preference
        let config_paths = if let Some(file) = config_file {
            vec![file.to_path_buf()]
        } else {
            vec![
                PathBuf::from(".soliditydefend.yml"),
                PathBuf::from(".soliditydefend.yaml"),
                dirs::config_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("soliditydefend")
                    .join("config.yml"),
                dirs::home_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join(".soliditydefend.yml"),
            ]
        };

        for path in config_paths {
            if path.exists() {
                match Self::load_from_file(&path) {
                    Ok(loaded_config) => {
                        // Merge loaded config with defaults
                        config = Self::merge_configs(config, loaded_config);
                        println!("Loaded configuration from: {}", path.display());
                        break;
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to load config from {}: {}", path.display(), e);
                        continue;
                    }
                }
            }
        }

        Ok(config)
    }

    /// Merge two configurations (loaded overrides defaults)
    fn merge_configs(_defaults: Self, loaded: Self) -> Self {
        // For simplicity, loaded config completely overrides defaults
        // In a more sophisticated implementation, we might merge individual fields
        loaded
    }

    /// Create a default configuration file
    pub fn create_default_config_file<P: AsRef<Path>>(path: P) -> Result<()> {
        let config = Self::default();
        config.save_to_file(path)?;
        Ok(())
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        // Validate detector timeout
        if self.detectors.detector_timeout == 0 {
            return Err(anyhow!("Detector timeout must be greater than 0"));
        }

        // Validate cache settings
        if self.cache.max_memory_mb == 0 {
            return Err(anyhow!("Cache memory limit must be greater than 0"));
        }

        // Validate performance settings
        if self.performance.max_threads == 0 {
            return Err(anyhow!("Max threads must be greater than 0"));
        }

        // Validate file size limit
        if self.general.max_file_size == 0 {
            return Err(anyhow!("Max file size must be greater than 0"));
        }

        Ok(())
    }

    /// Convert to detector registry config
    pub fn to_registry_config(&self) -> RegistryConfig {
        RegistryConfig::from(&self.detectors)
    }

    /// Convert to cache config
    pub fn to_cache_config(&self) -> CacheConfig {
        CacheConfig::from(&self.cache)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_config() {
        let config = SolidityDefendConfig::default();
        assert_eq!(config.general.min_severity, Severity::Info);
        assert!(config.cache.enabled);
        assert_eq!(config.output.format, OutputFormatSetting::Console);
    }

    #[test]
    fn test_config_serialization() {
        let config = SolidityDefendConfig::default();
        let yaml = serde_yaml::to_string(&config).unwrap();
        assert!(yaml.contains("min_severity"));
        assert!(yaml.contains("enabled"));

        let deserialized: SolidityDefendConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(deserialized.general.min_severity, config.general.min_severity);
    }

    #[test]
    fn test_config_file_operations() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("test_config.yml");

        let config = SolidityDefendConfig::default();
        config.save_to_file(&config_path)?;

        assert!(config_path.exists());

        let loaded_config = SolidityDefendConfig::load_from_file(&config_path)?;
        assert_eq!(loaded_config.general.min_severity, config.general.min_severity);

        Ok(())
    }

    #[test]
    fn test_config_validation() {
        let mut config = SolidityDefendConfig::default();
        assert!(config.validate().is_ok());

        config.detectors.detector_timeout = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_conversion_to_registry_config() {
        let config = SolidityDefendConfig::default();
        let registry_config = config.to_registry_config();
        assert_eq!(registry_config.min_severity, config.detectors.min_severity);
        assert_eq!(registry_config.min_confidence, config.detectors.min_confidence);
    }
}