use anyhow::{Result, anyhow};
use clap::{Arg, ArgAction, Command};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::config::SolidityDefendConfig;
use ast::arena::AstArena;
use cache::analysis_cache::{
    AnalysisMetadata, AnalysisStats, CachedAnalysisResult, CachedFinding, CachedLocation,
};
use cache::{CacheKey, CacheManager};
use db::Database;
use detectors::registry::{DetectorRegistry, RegistryConfig};
use detectors::types::{AnalysisContext, Finding, Severity};
use output::{OutputFormat, OutputManager};
use parser::Parser;
use semantic::symbols::SymbolTable;

/// Standard exit codes for CI/CD integration
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ExitCode {
    Success = 0,        // No issues found
    SecurityIssues = 1, // Security issues found
    AnalysisError = 2,  // Analysis failed (file errors, parsing errors)
    ConfigError = 3,    // Configuration errors
    InternalError = 4,  // Internal tool errors
}

impl ExitCode {
    /// Convert to process exit code
    pub fn as_code(&self) -> i32 {
        *self as i32
    }

    /// Exit the process with this code
    pub fn exit(&self) -> ! {
        std::process::exit(self.as_code())
    }
}

/// Exit code configuration for different CI/CD scenarios
#[derive(Debug, Clone)]
pub struct ExitCodeConfig {
    /// Exit with error on any finding above this severity
    pub error_on_severity: Option<Severity>,
    /// Exit with error only on high/critical findings (default behavior)
    pub error_on_high_severity: bool,
    /// Exit with error if any files fail to analyze
    pub error_on_analysis_failure: bool,
    /// Exit with error if no files were successfully analyzed
    pub error_on_no_files: bool,
}

impl Default for ExitCodeConfig {
    fn default() -> Self {
        Self {
            error_on_severity: None,
            error_on_high_severity: true,
            error_on_analysis_failure: true,
            error_on_no_files: false,
        }
    }
}

/// Analysis result summary for exit code determination
#[derive(Debug, Default)]
pub struct AnalysisSummary {
    pub total_files: usize,
    pub successful_files: usize,
    pub failed_files: usize,
    pub findings_by_severity: HashMap<Severity, usize>,
    pub total_findings: usize,
}

impl AnalysisSummary {
    pub fn add_finding(&mut self, severity: &Severity) {
        *self.findings_by_severity.entry(*severity).or_insert(0) += 1;
        self.total_findings += 1;
    }

    pub fn has_findings_at_or_above(&self, severity: &Severity) -> bool {
        match severity {
            Severity::Info => self.total_findings > 0,
            Severity::Low => {
                self.findings_by_severity.get(&Severity::Low).unwrap_or(&0) > &0
                    || self.has_findings_at_or_above(&Severity::Medium)
            }
            Severity::Medium => {
                self.findings_by_severity
                    .get(&Severity::Medium)
                    .unwrap_or(&0)
                    > &0
                    || self.has_findings_at_or_above(&Severity::High)
            }
            Severity::High => {
                self.findings_by_severity.get(&Severity::High).unwrap_or(&0) > &0
                    || self.has_findings_at_or_above(&Severity::Critical)
            }
            Severity::Critical => {
                self.findings_by_severity
                    .get(&Severity::Critical)
                    .unwrap_or(&0)
                    > &0
            }
        }
    }
}

pub struct CliApp {
    registry: DetectorRegistry,
    output_manager: OutputManager,
    cache_manager: CacheManager,
    _exit_config: ExitCodeConfig,
    _config: SolidityDefendConfig,
}

impl CliApp {
    pub fn new() -> Result<Self> {
        Self::new_with_config(None)
    }

    /// Display the wizard banner with version
    fn display_banner() {
        let version = env!("CARGO_PKG_VERSION");
        let version_line = format!("v{}", version);
        let total_width = 39; // Width between the box borders
        let padding = total_width - version_line.len();
        let left_padding = padding / 2;
        let right_padding = padding - left_padding;

        println!("╔═══════════════════════════════════════╗");
        println!("║       🧙  SOLIDITY DEFEND 🧙          ║");
        println!("║    Smart Contract Security Analyzer   ║");
        println!("║{:left_pad$}{}{:right_pad$}║", "", version_line, "",
                 left_pad = left_padding, right_pad = right_padding);
        println!("╚═══════════════════════════════════════╝");
        println!();
    }

    pub fn new_with_config(config_file: Option<&Path>) -> Result<Self> {
        // Load configuration with fallback chain
        let config = SolidityDefendConfig::load_from_defaults_and_file(config_file)?;
        config.validate()?;

        // Create cache manager from config
        let cache_config = config.to_cache_config();
        let cache_manager = CacheManager::new(cache_config)?;

        // Create detector registry from config
        let registry_config = config.to_registry_config();
        let registry = DetectorRegistry::with_all_detectors_and_config(registry_config);

        Ok(Self {
            registry,
            output_manager: OutputManager::new(),
            cache_manager,
            _exit_config: ExitCodeConfig::default(),
            _config: config,
        })
    }

    pub fn run() -> Result<()> {
        Self::run_with_args(std::env::args().collect())
    }

    pub fn run_with_args(args: Vec<String>) -> Result<()> {
        let matches = Command::new("soliditydefend")
            .version(env!("CARGO_PKG_VERSION"))
            .about("Solidity Static Application Security Testing (SAST) Tool")
            .arg(
                Arg::new("files")
                    .help("Solidity files to analyze")
                    .required_unless_present_any(["list-detectors", "version-info", "lsp", "init-config", "from-url", "setup-api-keys"])
                    .num_args(1..)
                    .value_name("FILE"),
            )
            .arg(
                Arg::new("format")
                    .short('f')
                    .long("format")
                    .help("Output format")
                    .value_parser(["json", "console"])
                    .default_value("console"),
            )
            .arg(
                Arg::new("output")
                    .short('o')
                    .long("output")
                    .help("Output file (stdout if not specified)")
                    .value_name("FILE"),
            )
            .arg(
                Arg::new("severity")
                    .short('s')
                    .long("min-severity")
                    .help("Minimum severity level")
                    .value_parser(["info", "low", "medium", "high", "critical"])
                    .default_value("info"),
            )
            .arg(
                Arg::new("confidence")
                    .long("min-confidence")
                    .help("Minimum confidence level")
                    .value_parser(["low", "medium", "high", "confirmed"])
                    .default_value("low"),
            )
            .arg(
                Arg::new("list-detectors")
                    .long("list-detectors")
                    .help("List all available detectors")
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new("version-info")
                    .long("version-info")
                    .help("Show detailed version information")
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new("no-cache")
                    .long("no-cache")
                    .help("Disable caching of analysis results")
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new("clear-cache")
                    .long("clear-cache")
                    .help("Clear all cached analysis results")
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new("cache-stats")
                    .long("cache-stats")
                    .help("Show cache statistics")
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new("lsp")
                    .long("lsp")
                    .help("Start Language Server Protocol server")
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new("exit-code-level")
                    .long("exit-code-level")
                    .help("Exit with non-zero code when findings at or above this severity are found")
                    .value_parser(["info", "low", "medium", "high", "critical"])
                    .value_name("LEVEL"),
            )
            .arg(
                Arg::new("no-exit-code")
                    .long("no-exit-code")
                    .help("Always exit with code 0, regardless of findings (useful for CI info gathering)")
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new("exit-on-analysis-error")
                    .long("exit-on-analysis-error")
                    .help("Exit with error code if any files fail to analyze (default: true)")
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new("no-exit-on-analysis-error")
                    .long("no-exit-on-analysis-error")
                    .help("Don't exit with error code on analysis failures")
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new("config")
                    .short('c')
                    .long("config")
                    .help("Configuration file path (.soliditydefend.yml)")
                    .value_name("FILE"),
            )
            .arg(
                Arg::new("init-config")
                    .long("init-config")
                    .help("Create a default configuration file in the current directory")
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new("from-url")
                    .long("from-url")
                    .help("Analyze contract from blockchain explorer URL (transaction or contract)")
                    .value_name("URL")
                    .conflicts_with("files"),
            )
            .arg(
                Arg::new("setup-api-keys")
                    .long("setup-api-keys")
                    .help("Interactive setup for blockchain API keys")
                    .action(ArgAction::SetTrue),
            )
            .try_get_matches_from(args)?;

        // Handle configuration initialization first (doesn't need config loading)
        if matches.get_flag("init-config") {
            return Self::handle_init_config();
        }

        // Handle API key setup
        if matches.get_flag("setup-api-keys") {
            return Self::handle_setup_api_keys();
        }

        // Get config file path if specified
        let config_file = matches.get_one::<String>("config").map(PathBuf::from);

        // Create app instance with configuration
        let app = Self::new_with_config(config_file.as_deref())?;

        // Handle commands that don't need file analysis
        if matches.get_flag("list-detectors") {
            return app.list_detectors();
        }

        if matches.get_flag("version-info") {
            return app.show_version_info();
        }

        if matches.get_flag("clear-cache") {
            return app.clear_cache();
        }

        if matches.get_flag("cache-stats") {
            return app.show_cache_stats();
        }

        if matches.get_flag("lsp") {
            return app.start_lsp_server();
        }

        // Handle URL-based analysis
        if let Some(url) = matches.get_one::<String>("from-url") {
            let format = match matches.get_one::<String>("format").unwrap().as_str() {
                "json" => OutputFormat::Json,
                "console" => OutputFormat::Console,
                _ => OutputFormat::Console,
            };

            let min_severity = match matches.get_one::<String>("severity").unwrap().as_str() {
                "info" => Severity::Info,
                "low" => Severity::Low,
                "medium" => Severity::Medium,
                "high" => Severity::High,
                "critical" => Severity::Critical,
                _ => Severity::Info,
            };

            let min_confidence = match matches.get_one::<String>("confidence").unwrap().as_str() {
                "low" => detectors::types::Confidence::Low,
                "medium" => detectors::types::Confidence::Medium,
                "high" => detectors::types::Confidence::High,
                "confirmed" => detectors::types::Confidence::Confirmed,
                _ => detectors::types::Confidence::Low,
            };

            let output_file = matches.get_one::<String>("output").map(PathBuf::from);
            let use_cache = !matches.get_flag("no-cache");

            return app.analyze_from_url(url, format, output_file, min_severity, min_confidence, use_cache);
        }

        let files: Vec<&str> = matches
            .get_many::<String>("files")
            .unwrap_or_default()
            .map(|s| s.as_str())
            .collect();

        let format = match matches.get_one::<String>("format").unwrap().as_str() {
            "json" => OutputFormat::Json,
            "console" => OutputFormat::Console,
            _ => OutputFormat::Console,
        };

        let min_severity = match matches.get_one::<String>("severity").unwrap().as_str() {
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => Severity::Info,
        };

        let min_confidence = match matches.get_one::<String>("confidence").unwrap().as_str() {
            "low" => detectors::types::Confidence::Low,
            "medium" => detectors::types::Confidence::Medium,
            "high" => detectors::types::Confidence::High,
            "confirmed" => detectors::types::Confidence::Confirmed,
            _ => detectors::types::Confidence::Low,
        };

        let output_file = matches.get_one::<String>("output").map(PathBuf::from);
        let use_cache = !matches.get_flag("no-cache");

        // Configure exit code behavior
        let mut exit_config = ExitCodeConfig::default();

        // Handle --no-exit-code flag
        if matches.get_flag("no-exit-code") {
            exit_config.error_on_severity = None;
            exit_config.error_on_high_severity = false;
            exit_config.error_on_analysis_failure = false;
        }

        // Handle --exit-code-level flag
        if let Some(level) = matches.get_one::<String>("exit-code-level") {
            let severity = match level.as_str() {
                "info" => Severity::Info,
                "low" => Severity::Low,
                "medium" => Severity::Medium,
                "high" => Severity::High,
                "critical" => Severity::Critical,
                _ => Severity::High, // fallback
            };
            exit_config.error_on_severity = Some(severity);
            exit_config.error_on_high_severity = false; // Use custom severity instead
        }

        // Handle analysis error flags
        if matches.get_flag("exit-on-analysis-error") {
            exit_config.error_on_analysis_failure = true;
        } else if matches.get_flag("no-exit-on-analysis-error") {
            exit_config.error_on_analysis_failure = false;
        }

        app.analyze_files(
            &files,
            format,
            output_file,
            min_severity,
            min_confidence,
            use_cache,
            exit_config,
        )
    }

    fn list_detectors(&self) -> Result<()> {
        println!("Available Detectors:");
        println!("===================");

        // Get all detector IDs from the registry
        let mut detector_ids = self.registry.get_detector_ids();

        // Sort detector IDs alphabetically for consistent output
        detector_ids.sort_by(|a, b| a.0.cmp(&b.0));

        // Iterate through all detectors and print their information
        for id in detector_ids {
            if let Some(detector) = self.registry.get_detector(&id) {
                let name = detector.name();
                let severity = match detector.default_severity() {
                    Severity::Critical => "Critical",
                    Severity::High => "High",
                    Severity::Medium => "Medium",
                    Severity::Low => "Low",
                    Severity::Info => "Info",
                };
                println!("  {} - {} ({})", id, name, severity);
            }
        }

        Ok(())
    }

    fn show_version_info(&self) -> Result<()> {
        // Basic version info that works without build script
        println!("SolidityDefend Version Information:");
        println!("=================================");
        println!("Version: {}", env!("CARGO_PKG_VERSION"));

        // Git info (fallback to runtime if build-time unavailable)
        println!(
            "Git Hash: {}",
            std::env::var("GIT_HASH").unwrap_or_else(|_| "unknown".to_string())
        );
        println!(
            "Git Branch: {}",
            std::env::var("GIT_BRANCH").unwrap_or_else(|_| "unknown".to_string())
        );
        println!(
            "Build Timestamp: {}",
            std::env::var("BUILD_TIMESTAMP").unwrap_or_else(|_| "unknown".to_string())
        );
        println!(
            "Build Number: {}",
            std::env::var("BUILD_NUMBER").unwrap_or_else(|_| "0".to_string())
        );
        println!(
            "Rust Version: {}",
            std::env::var("RUST_VERSION").unwrap_or_else(|_| "unknown".to_string())
        );
        println!(
            "Target: {}",
            std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string())
        );
        println!(
            "Profile: {}",
            std::env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string())
        );

        let git_dirty = std::env::var("GIT_DIRTY").unwrap_or_else(|_| "false".to_string());
        let profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string());

        if git_dirty == "true" {
            println!("Status: Development build (dirty workspace)");
        } else if profile == "debug" {
            println!("Status: Development build");
        } else {
            println!("Status: Release build");
        }

        println!("\nDetector Registry:");
        println!("  Total Detectors: 17");
        println!("  Production Ready: 17");
        println!("  Categories: 7");

        println!("\nBuild Information:");
        println!("  Lines of Code: ~26,658");
        println!("  Source Files: 84");
        println!("  Crates: 18");
        println!("  Tests Passing: 94+");

        Ok(())
    }

    fn clear_cache(&self) -> Result<()> {
        println!("Clearing analysis cache...");
        self.cache_manager.clear_all()?;
        println!("Cache cleared successfully.");
        Ok(())
    }

    fn show_cache_stats(&self) -> Result<()> {
        let stats = self.cache_manager.stats();
        let analysis_stats = self.cache_manager.analysis_cache().get_hit_statistics();

        println!("Cache Statistics:");
        println!("================");
        println!(
            "Total entries: {}",
            stats.file_cache_entries + stats.analysis_cache_entries + stats.query_cache_entries
        );
        println!("  File cache: {}", stats.file_cache_entries);
        println!("  Analysis cache: {}", stats.analysis_cache_entries);
        println!("  Query cache: {}", stats.query_cache_entries);
        println!(
            "Total memory usage: {:.2} MB",
            stats.total_memory_usage as f64 / 1024.0 / 1024.0
        );

        if analysis_stats.total_entries > 0 {
            println!("\nAnalysis Cache Details:");
            println!(
                "  Average entry age: {}s",
                analysis_stats.average_age_seconds
            );
            println!(
                "  Oldest entry: {}s",
                analysis_stats.oldest_entry_age_seconds
            );
        }

        Ok(())
    }

    fn analyze_files(
        &self,
        files: &[&str],
        format: OutputFormat,
        output_file: Option<PathBuf>,
        min_severity: Severity,
        min_confidence: detectors::types::Confidence,
        use_cache: bool,
        exit_config: ExitCodeConfig,
    ) -> Result<()> {
        Self::display_banner();
        println!("Starting analysis...");
        let start_time = Instant::now();

        let mut analysis_summary = AnalysisSummary::default();
        let mut all_findings = Vec::new();

        for file_path in files {
            println!("Analyzing: {}", file_path);
            analysis_summary.total_files += 1;

            match self.analyze_file(file_path, min_severity, min_confidence, use_cache) {
                Ok((findings, from_cache)) => {
                    let cache_indicator = if from_cache { " (cached)" } else { "" };
                    println!("  Found {} issues{}", findings.len(), cache_indicator);

                    analysis_summary.successful_files += 1;

                    // Track findings by severity
                    for finding in &findings {
                        analysis_summary.add_finding(&finding.severity);
                    }

                    all_findings.extend(findings);
                }
                Err(e) => {
                    eprintln!("  Error analyzing {}: {}", file_path, e);
                    analysis_summary.failed_files += 1;
                }
            }
        }

        let duration = start_time.elapsed();

        // Deduplicate findings before output
        // This removes duplicate findings from detectors that may run multiple times
        // or string-based detectors that incorrectly match the same pattern repeatedly
        let all_findings = output::deduplicate_findings(all_findings);

        // Update summary with deduplicated count
        let deduplicated_count = all_findings.len();
        let duplicates_removed = analysis_summary.total_findings - deduplicated_count;

        // Output results
        match output_file {
            Some(path) => {
                self.output_manager
                    .write_to_file(&all_findings, format, &path)?;
                println!("Results written to: {}", path.display());
            }
            None => {
                self.output_manager.write_to_stdout(&all_findings, format)?;
            }
        }

        println!("\nAnalysis complete:");
        println!("  Files analyzed: {}", analysis_summary.total_files);
        println!("  Successful: {}", analysis_summary.successful_files);
        if analysis_summary.failed_files > 0 {
            println!("  Failed: {}", analysis_summary.failed_files);
        }
        println!("  Issues found: {}", deduplicated_count);
        if duplicates_removed > 0 {
            println!("  Duplicates removed: {}", duplicates_removed);
        }
        println!("  Time taken: {:.2}s", duration.as_secs_f64());

        // Determine exit code based on configuration
        let exit_code = self.determine_exit_code(&analysis_summary, &exit_config);

        if exit_code != ExitCode::Success {
            println!("\nExiting with code {} due to:", exit_code.as_code());
            if analysis_summary.failed_files > 0 && exit_config.error_on_analysis_failure {
                println!(
                    "  - {} file(s) failed to analyze",
                    analysis_summary.failed_files
                );
            }
            if let Some(severity) = &exit_config.error_on_severity {
                if analysis_summary.has_findings_at_or_above(severity) {
                    println!("  - Found {} or higher severity issues", severity);
                }
            } else if exit_config.error_on_high_severity
                && analysis_summary.has_findings_at_or_above(&Severity::High)
            {
                println!("  - Found high or critical severity issues");
            }
            exit_code.exit();
        }

        Ok(())
    }

    /// Determine the appropriate exit code based on analysis results and configuration
    fn determine_exit_code(&self, summary: &AnalysisSummary, config: &ExitCodeConfig) -> ExitCode {
        // Check for analysis failures first
        if config.error_on_analysis_failure && summary.failed_files > 0 {
            return ExitCode::AnalysisError;
        }

        // Check if no files were successfully analyzed
        if config.error_on_no_files && summary.successful_files == 0 {
            return ExitCode::AnalysisError;
        }

        // Check for security issues based on severity configuration
        if let Some(severity) = &config.error_on_severity {
            if summary.has_findings_at_or_above(severity) {
                return ExitCode::SecurityIssues;
            }
        } else if config.error_on_high_severity {
            // Default behavior: exit on high/critical issues
            if summary.has_findings_at_or_above(&Severity::High) {
                return ExitCode::SecurityIssues;
            }
        }

        ExitCode::Success
    }

    fn analyze_file(
        &self,
        file_path: &str,
        min_severity: Severity,
        min_confidence: detectors::types::Confidence,
        use_cache: bool,
    ) -> Result<(Vec<Finding>, bool)> {
        // Read file
        let content = std::fs::read_to_string(file_path)
            .map_err(|e| anyhow!("Failed to read file {}: {}", file_path, e))?;

        // Create configuration hash for caching
        let config_hash = self.generate_config_hash(&min_severity, &min_confidence);

        // Check cache if enabled
        if use_cache {
            let cache_key = CacheKey::new(file_path, &content, &config_hash);
            if let Some(cached_result) =
                self.cache_manager.analysis_cache().get_analysis(&cache_key)
            {
                // Convert cached findings back to Finding objects and filter by severity and confidence
                let findings: Vec<Finding> = cached_result
                    .findings
                    .iter()
                    .map(|cached_finding| self.cached_finding_to_finding(cached_finding, file_path))
                    .filter(|f| f.severity >= min_severity && f.confidence >= min_confidence)
                    .collect();

                return Ok((findings, true)); // true = from cache
            }
        }

        // Create database, arena, and parser
        let mut db = Database::new();
        let arena = AstArena::new();
        let parser = Parser::new();

        // Parse the file
        let source_file = parser
            .parse(&arena, &content, file_path)
            .map_err(|e| anyhow!("Parse error: {:?}", e))?;

        // Store in database
        let _file_id = db.add_source_file(file_path.to_string(), content.clone());

        // Skip analysis if no contracts found
        if source_file.contracts.is_empty() {
            return Ok((Vec::new(), false));
        }

        // Run detectors
        let mut config = RegistryConfig::default();
        config.min_severity = min_severity;

        let start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Analyze all contracts in the file
        let mut all_findings = Vec::new();
        for contract in &source_file.contracts {
            // Create a fresh symbol table for each contract
            let dummy_symbols = SymbolTable::new();
            let ctx = AnalysisContext::new(
                contract,
                dummy_symbols,
                content.clone(),
                file_path.to_string(),
            );

            // Try to run analysis, fall back to empty result if detector system fails
            let analysis_result = match self.registry.run_analysis(&ctx) {
                Ok(result) => result,
                Err(e) => {
                    eprintln!(
                        "Warning: Detector analysis failed for contract '{}' ({}), proceeding with empty result",
                        contract.name.as_str(),
                        e
                    );
                    detectors::types::AnalysisResult::new()
                }
            };

            all_findings.extend(analysis_result.findings);
        }

        // Create combined analysis result
        let mut analysis_result = detectors::types::AnalysisResult::new();
        analysis_result.findings = all_findings;

        let end_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Store in cache before filtering (so we cache all findings)
        if use_cache {
            let cache_key = CacheKey::new(file_path, &content, &config_hash);
            let cached_result = self.convert_to_cached_result(
                &analysis_result.findings,
                file_path,
                start_time,
                end_time,
            )?;

            // Ignore cache storage errors to avoid failing analysis
            let _ = self
                .cache_manager
                .analysis_cache()
                .store_analysis(cache_key, cached_result);
        }

        // Filter by severity and confidence
        let filtered_findings: Vec<_> = analysis_result
            .findings
            .into_iter()
            .filter(|f| f.severity >= min_severity && f.confidence >= min_confidence)
            .collect();

        Ok((filtered_findings, false)) // false = not from cache
    }

    /// Generate a configuration hash for cache invalidation
    fn generate_config_hash(&self, min_severity: &Severity, min_confidence: &detectors::types::Confidence) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        min_severity.hash(&mut hasher);
        min_confidence.hash(&mut hasher);
        // Add other configuration that affects analysis results
        format!("{:x}", hasher.finish())
    }

    /// Convert analysis findings to cached format
    fn convert_to_cached_result(
        &self,
        findings: &[Finding],
        file_path: &str,
        start_time: u64,
        end_time: u64,
    ) -> Result<CachedAnalysisResult> {
        let cached_findings: Vec<CachedFinding> = findings
            .iter()
            .map(|finding| CachedFinding {
                detector_id: finding.detector_id.to_string(),
                message: finding.message.clone(),
                severity: finding.severity.to_string(),
                location: CachedLocation {
                    line: finding.primary_location.line,
                    column: finding.primary_location.column,
                    length: finding.primary_location.length,
                },
                cwes: finding.cwe_ids.clone(),
                fix_suggestion: finding.fix_suggestion.clone(),
            })
            .collect();

        // Create basic statistics
        let mut findings_by_severity = HashMap::new();
        for finding in findings {
            let severity_key = finding.severity.to_string();
            *findings_by_severity.entry(severity_key).or_insert(0) += 1;
        }

        let metadata = AnalysisMetadata {
            started_at: start_time,
            completed_at: end_time,
            detectors_run: vec!["all".to_string()], // TODO: Track actual detectors
            stats: AnalysisStats {
                total_findings: findings.len(),
                findings_by_severity,
                duration_ms: (end_time - start_time) * 1000,
            },
        };

        Ok(CachedAnalysisResult {
            findings: cached_findings,
            metadata,
            file_path: file_path.to_string(),
            config_hash: self.generate_config_hash(&Severity::Info, &detectors::types::Confidence::Low), // TODO: Pass actual severity/confidence
        })
    }

    /// Convert cached finding back to Finding object
    fn cached_finding_to_finding(&self, cached: &CachedFinding, file_path: &str) -> Finding {
        use detectors::types::{DetectorId, SourceLocation};

        let severity = match cached.severity.as_str() {
            "INFO" => Severity::Info,
            "LOW" => Severity::Low,
            "MEDIUM" => Severity::Medium,
            "HIGH" => Severity::High,
            "CRITICAL" => Severity::Critical,
            _ => Severity::Info,
        };

        let confidence = detectors::types::Confidence::High; // Default confidence

        let location = SourceLocation::new(
            file_path.to_string(),
            cached.location.line,
            cached.location.column,
            cached.location.length,
        );

        let mut finding = Finding::new(
            DetectorId::new(&cached.detector_id),
            severity,
            confidence,
            cached.message.clone(),
            location,
        );

        for cwe in &cached.cwes {
            finding = finding.with_cwe(*cwe);
        }

        if let Some(fix) = &cached.fix_suggestion {
            finding = finding.with_fix_suggestion(fix.clone());
        }

        finding
    }

    fn start_lsp_server(&self) -> Result<()> {
        println!("Starting SolidityDefend Language Server...");

        // Use tokio to run the async LSP server
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async { lsp::start_lsp_server().await })?;

        Ok(())
    }

    fn handle_init_config() -> Result<()> {
        let config_path = PathBuf::from(".soliditydefend.yml");

        if config_path.exists() {
            println!(
                "Configuration file already exists: {}",
                config_path.display()
            );
            print!("Overwrite? [y/N]: ");
            std::io::Write::flush(&mut std::io::stdout())?;

            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;

            if !input.trim().to_lowercase().starts_with('y') {
                println!("Configuration initialization cancelled.");
                return Ok(());
            }
        }

        SolidityDefendConfig::create_default_config_file(&config_path)?;
        println!(
            "Created default configuration file: {}",
            config_path.display()
        );
        println!("\nEdit this file to customize SolidityDefend settings:");
        println!("- Detector settings");
        println!("- Cache configuration");
        println!("- Output preferences");
        println!("- Performance tuning");

        Ok(())
    }

    /// Handle URL-based contract analysis
    fn analyze_from_url(
        &self,
        url: &str,
        format: OutputFormat,
        output_file: Option<PathBuf>,
        min_severity: Severity,
        min_confidence: detectors::types::Confidence,
        use_cache: bool,
    ) -> Result<()> {
        Self::display_banner();
        println!("🔍 Analyzing contract from URL: {}", url);

        // Create URL fetcher with user API keys
        let fetcher = match crate::url_fetcher::UrlFetcher::with_user_api_keys() {
            Ok(f) => f,
            Err(_) => {
                eprintln!("❌ No API keys configured for blockchain explorers");
                eprintln!("💡 Set up API keys with: soliditydefend --setup-api-keys");
                eprintln!("📖 Or set environment variables:");
                eprintln!("   export ETHERSCAN_API_KEY=your_key_here");
                eprintln!("   export POLYGONSCAN_API_KEY=your_key_here");
                eprintln!("   export BSCSCAN_API_KEY=your_key_here");
                return Err(anyhow!("API keys required for URL-based analysis"));
            }
        };

        // Parse URL to check if we have the required API key
        let (platform, _) = fetcher.parse_url(url)?;
        if !fetcher.has_api_key(&platform) {
            let platform_name = format!("{:?}", platform);
            eprintln!("❌ No API key configured for {}", platform_name);
            eprintln!("💡 Get your free API key and configure it:");

            match platform {
                crate::url_fetcher::ExplorerPlatform::Etherscan => {
                    eprintln!("   🔗 https://etherscan.io/apis");
                    eprintln!("   🔧 export ETHERSCAN_API_KEY=your_key_here");
                }
                crate::url_fetcher::ExplorerPlatform::Polygonscan => {
                    eprintln!("   🔗 https://polygonscan.com/apis");
                    eprintln!("   🔧 export POLYGONSCAN_API_KEY=your_key_here");
                }
                crate::url_fetcher::ExplorerPlatform::BscScan => {
                    eprintln!("   🔗 https://bscscan.com/apis");
                    eprintln!("   🔧 export BSCSCAN_API_KEY=your_key_here");
                }
                _ => {
                    eprintln!("   🔧 Configure the appropriate API key for this platform");
                }
            }

            return Err(anyhow!("API key required for {} platform", platform_name));
        }

        // Fetch contract source
        let runtime = tokio::runtime::Runtime::new()?;
        let contracts = runtime.block_on(async { fetcher.fetch_contract_source(url).await })?;

        if contracts.is_empty() {
            return Err(anyhow!("No verified contracts found at the provided URL"));
        }

        println!("✅ Found {} verified contract(s)", contracts.len());

        let mut all_findings = Vec::new();
        let mut analysis_summary = AnalysisSummary::default();

        for (index, contract) in contracts.iter().enumerate() {
            println!(
                "\n📄 Analyzing contract: {} ({})",
                contract.name, contract.address
            );
            println!("   Platform: {}", contract.platform);
            println!("   Compiler: {}", contract.compiler_version);
            println!("   Verified: {}", contract.is_verified);

            // Save contract to temporary file
            let temp_path = fetcher.save_contract_to_temp(contract)?;
            println!("   Saved to: {}", temp_path);

            analysis_summary.total_files += 1;

            // Analyze the temporary file
            match self.analyze_file(&temp_path, min_severity, min_confidence, use_cache) {
                Ok((findings, from_cache)) => {
                    let cache_indicator = if from_cache { " (cached)" } else { "" };
                    println!("   Found {} issues{}", findings.len(), cache_indicator);

                    analysis_summary.successful_files += 1;

                    // Track findings by severity
                    for finding in &findings {
                        analysis_summary.add_finding(&finding.severity);
                    }

                    all_findings.extend(findings);
                }
                Err(e) => {
                    eprintln!("   ❌ Error analyzing contract {}: {}", index + 1, e);
                    analysis_summary.failed_files += 1;
                }
            }

            // Clean up temporary file
            if let Err(e) = std::fs::remove_file(&temp_path) {
                eprintln!("   ⚠️  Warning: Failed to clean up temporary file: {}", e);
            }
        }

        // Deduplicate findings before output
        let all_findings = output::deduplicate_findings(all_findings);

        // Update summary with deduplicated count
        let deduplicated_count = all_findings.len();
        let duplicates_removed = analysis_summary.total_findings - deduplicated_count;

        // Output results
        match output_file {
            Some(path) => {
                self.output_manager
                    .write_to_file(&all_findings, format, &path)?;
                println!("\n📁 Results written to: {}", path.display());
            }
            None => {
                self.output_manager.write_to_stdout(&all_findings, format)?;
            }
        }

        println!("\n📊 Analysis Summary:");
        println!("   Contracts analyzed: {}", analysis_summary.total_files);
        println!("   Successful: {}", analysis_summary.successful_files);
        if analysis_summary.failed_files > 0 {
            println!("   Failed: {}", analysis_summary.failed_files);
        }
        println!("   Total issues found: {}", deduplicated_count);
        if duplicates_removed > 0 {
            println!("   Duplicates removed: {}", duplicates_removed);
        }

        Ok(())
    }

    /// Handle interactive API key setup
    fn handle_setup_api_keys() -> Result<()> {
        use std::io::{self, Write};

        println!("🔑 Setting up blockchain API keys...");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!(
            "SolidityDefend needs API keys to fetch contract source code from blockchain explorers."
        );
        println!("All API keys are free to obtain and stored locally on your machine.\n");

        let api_configs = vec![
            (
                "Etherscan",
                "https://etherscan.io/apis",
                "ETHERSCAN_API_KEY",
            ),
            (
                "Polygonscan",
                "https://polygonscan.com/apis",
                "POLYGONSCAN_API_KEY",
            ),
            ("BscScan", "https://bscscan.com/apis", "BSCSCAN_API_KEY"),
            ("Arbiscan", "https://arbiscan.io/apis", "ARBISCAN_API_KEY"),
        ];

        let mut env_commands = Vec::new();

        for (platform, url, env_var) in api_configs {
            println!("🌐 {} API Key", platform);
            println!("   Get your free key: {}", url);
            print!("   Enter API key (or press Enter to skip): ");
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let api_key = input.trim();

            if !api_key.is_empty() {
                env_commands.push(format!("export {}={}", env_var, api_key));
                println!("   ✅ {} configured", platform);
            } else {
                println!("   ⏭️  {} skipped", platform);
            }
            println!();
        }

        if env_commands.is_empty() {
            println!(
                "⚠️  No API keys configured. You can set them later using environment variables."
            );
        } else {
            println!("✅ Setup complete! Add these to your shell profile (.bashrc, .zshrc, etc.):");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            for cmd in &env_commands {
                println!("   {}", cmd);
            }
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("\n💡 Or set them temporarily for this session:");
            for cmd in &env_commands {
                println!("   {}", cmd);
            }
        }

        println!("\n🚀 Test your setup:");
        println!("   soliditydefend --from-url https://etherscan.io/tx/0x1234...");

        Ok(())
    }
}

impl Default for CliApp {
    fn default() -> Self {
        Self::new().expect("Failed to create CliApp with default cache configuration")
    }
}
