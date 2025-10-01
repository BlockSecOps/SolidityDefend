use detectors::types::{Finding, Severity};
use std::collections::HashMap;

/// Exit code configuration for CI/CD integration
#[derive(Debug, Clone)]
pub struct ExitCodeConfig {
    /// Minimum severity level that causes non-zero exit
    pub severity_threshold: Severity,
    /// Whether to fail on any new findings (baseline mode)
    pub fail_on_new_findings: bool,
    /// Whether to fail if total findings exceed threshold
    pub fail_on_finding_count: Option<usize>,
    /// Custom exit codes for different severities
    pub custom_exit_codes: HashMap<Severity, i32>,
    /// Maximum exit code to return (clamped)
    pub max_exit_code: i32,
}

impl Default for ExitCodeConfig {
    fn default() -> Self {
        let mut custom_exit_codes = HashMap::new();
        custom_exit_codes.insert(Severity::Critical, 1);
        custom_exit_codes.insert(Severity::High, 1);
        custom_exit_codes.insert(Severity::Medium, 1);
        custom_exit_codes.insert(Severity::Low, 0);
        custom_exit_codes.insert(Severity::Info, 0);

        Self {
            severity_threshold: Severity::Medium,
            fail_on_new_findings: false,
            fail_on_finding_count: None,
            custom_exit_codes,
            max_exit_code: 1,
        }
    }
}

/// Standard exit codes for different scenarios
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandardExitCode {
    /// No issues found - success
    Success = 0,
    /// Security issues found
    SecurityIssues = 1,
    /// Critical security issues found
    CriticalIssues = 2,
    /// Analysis failed due to errors
    AnalysisError = 3,
    /// Configuration error
    ConfigError = 4,
    /// File not found or access error
    FileError = 5,
    /// Invalid command line arguments
    InvalidArgs = 6,
    /// Internal tool error
    InternalError = 127,
}

impl From<StandardExitCode> for i32 {
    fn from(code: StandardExitCode) -> Self {
        code as i32
    }
}

/// Exit code manager for determining appropriate exit codes
pub struct ExitCodeManager {
    config: ExitCodeConfig,
}

impl ExitCodeManager {
    /// Create a new exit code manager
    pub fn new(config: ExitCodeConfig) -> Self {
        Self { config }
    }

    /// Create manager with default configuration
    pub fn default() -> Self {
        Self::new(ExitCodeConfig::default())
    }

    /// Determine exit code based on findings
    pub fn determine_exit_code(&self, findings: &[Finding]) -> i32 {
        self.determine_exit_code_with_context(findings, &AnalysisContext::default())
    }

    /// Determine exit code with additional context
    pub fn determine_exit_code_with_context(&self, findings: &[Finding], context: &AnalysisContext) -> i32 {
        // Check for analysis errors first
        if context.has_errors {
            return StandardExitCode::AnalysisError.into();
        }

        // If no findings, return success
        if findings.is_empty() {
            return StandardExitCode::Success.into();
        }

        // Check finding count threshold
        if let Some(threshold) = self.config.fail_on_finding_count {
            if findings.len() > threshold {
                return self.config.max_exit_code.min(1);
            }
        }

        // Check for new findings in baseline mode
        if self.config.fail_on_new_findings {
            let new_findings = findings.iter().filter(|f| context.is_new_finding(f)).count();
            if new_findings > 0 {
                return self.config.max_exit_code.min(1);
            }
        }

        // Determine worst severity level
        let worst_severity = self.get_worst_severity(findings);

        // Check if worst severity meets threshold
        if self.should_fail_for_severity(&worst_severity) {
            // Use custom exit code if configured
            if let Some(&custom_code) = self.config.custom_exit_codes.get(&worst_severity) {
                return custom_code.min(self.config.max_exit_code);
            }

            // Use standard exit codes based on severity
            match worst_severity {
                Severity::Critical => StandardExitCode::CriticalIssues.into(),
                Severity::High => StandardExitCode::SecurityIssues.into(),
                Severity::Medium => StandardExitCode::SecurityIssues.into(),
                Severity::Low => StandardExitCode::Success.into(),
                Severity::Info => StandardExitCode::Success.into(),
            }
        } else {
            StandardExitCode::Success.into()
        }
    }

    /// Get detailed exit code explanation
    pub fn get_exit_explanation(&self, exit_code: i32, findings: &[Finding]) -> String {
        match exit_code {
            0 => "No security issues found or issues below threshold".to_string(),
            1 => {
                let critical_count = findings.iter().filter(|f| f.severity == Severity::Critical).count();
                let high_count = findings.iter().filter(|f| f.severity == Severity::High).count();
                let medium_count = findings.iter().filter(|f| f.severity == Severity::Medium).count();

                format!(
                    "Security issues found: {} critical, {} high, {} medium",
                    critical_count, high_count, medium_count
                )
            }
            2 => format!("Critical security issues found: {} critical vulnerabilities",
                findings.iter().filter(|f| f.severity == Severity::Critical).count()),
            3 => "Analysis failed due to errors".to_string(),
            4 => "Configuration error".to_string(),
            5 => "File access error".to_string(),
            6 => "Invalid command line arguments".to_string(),
            127 => "Internal tool error".to_string(),
            _ => format!("Custom exit code: {}", exit_code),
        }
    }

    /// Get statistics for the current analysis
    pub fn get_analysis_statistics(&self, findings: &[Finding]) -> AnalysisStatistics {
        let mut stats = AnalysisStatistics::default();

        for finding in findings {
            stats.total_findings += 1;
            match finding.severity {
                Severity::Critical => stats.critical_count += 1,
                Severity::High => stats.high_count += 1,
                Severity::Medium => stats.medium_count += 1,
                Severity::Low => stats.low_count += 1,
                Severity::Info => stats.info_count += 1,
            }
        }

        stats
    }

    /// Check if findings exceed any configured thresholds
    pub fn check_thresholds(&self, findings: &[Finding]) -> ThresholdCheckResult {
        let stats = self.get_analysis_statistics(findings);
        let mut violations = Vec::new();

        // Check severity threshold
        let worst_severity = self.get_worst_severity(findings);
        if self.should_fail_for_severity(&worst_severity) {
            violations.push(ThresholdViolation::SeverityThreshold {
                found: worst_severity,
                threshold: self.config.severity_threshold,
            });
        }

        // Check finding count threshold
        if let Some(threshold) = self.config.fail_on_finding_count {
            if findings.len() > threshold {
                violations.push(ThresholdViolation::FindingCount {
                    found: findings.len(),
                    threshold,
                });
            }
        }

        ThresholdCheckResult {
            passed: violations.is_empty(),
            violations,
            statistics: stats,
        }
    }

    /// Configure exit codes for specific CI/CD platforms
    pub fn configure_for_platform(&mut self, platform: CiPlatform) {
        match platform {
            CiPlatform::GitHubActions => {
                // GitHub Actions: 0 = success, 1 = failure
                self.config.max_exit_code = 1;
                self.config.custom_exit_codes.clear();
                for severity in [Severity::Critical, Severity::High, Severity::Medium] {
                    self.config.custom_exit_codes.insert(severity, 1);
                }
            }
            CiPlatform::GitLabCI => {
                // GitLab CI: supports more granular exit codes
                self.config.max_exit_code = 2;
                self.config.custom_exit_codes.insert(Severity::Critical, 2);
                self.config.custom_exit_codes.insert(Severity::High, 1);
                self.config.custom_exit_codes.insert(Severity::Medium, 1);
            }
            CiPlatform::Jenkins => {
                // Jenkins: traditional Unix exit codes
                self.config.max_exit_code = 127;
                self.config.custom_exit_codes.insert(Severity::Critical, 2);
                self.config.custom_exit_codes.insert(Severity::High, 1);
                self.config.custom_exit_codes.insert(Severity::Medium, 1);
            }
            CiPlatform::Generic => {
                // Use default configuration
                *self = Self::default();
            }
        }
    }

    /// Get worst severity from findings
    fn get_worst_severity(&self, findings: &[Finding]) -> Severity {
        findings.iter()
            .map(|f| &f.severity)
            .max_by_key(|s| self.severity_order(s))
            .cloned()
            .unwrap_or(Severity::Info)
    }

    /// Check if we should fail for given severity
    fn should_fail_for_severity(&self, severity: &Severity) -> bool {
        self.severity_order(severity) >= self.severity_order(&self.config.severity_threshold)
    }

    /// Get numeric order for severity comparison
    fn severity_order(&self, severity: &Severity) -> u8 {
        match severity {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            Severity::Info => 1,
        }
    }
}

/// Analysis context for exit code determination
#[derive(Debug, Default)]
pub struct AnalysisContext {
    /// Whether analysis encountered errors
    pub has_errors: bool,
    /// Baseline findings for comparison
    pub baseline_findings: Vec<Finding>,
    /// Files that failed to analyze
    pub failed_files: Vec<String>,
}

impl AnalysisContext {
    /// Check if a finding is new compared to baseline
    pub fn is_new_finding(&self, finding: &Finding) -> bool {
        !self.baseline_findings.iter().any(|baseline| {
            baseline.detector_id == finding.detector_id &&
            baseline.line == finding.line &&
            baseline.column == finding.column
        })
    }
}

/// Statistics about the analysis run
#[derive(Debug, Default)]
pub struct AnalysisStatistics {
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
}

impl AnalysisStatistics {
    /// Get count for specific severity
    pub fn count_for_severity(&self, severity: &Severity) -> usize {
        match severity {
            Severity::Critical => self.critical_count,
            Severity::High => self.high_count,
            Severity::Medium => self.medium_count,
            Severity::Low => self.low_count,
            Severity::Info => self.info_count,
        }
    }

    /// Get counts for severity and above
    pub fn count_for_severity_and_above(&self, severity: &Severity) -> usize {
        match severity {
            Severity::Critical => self.critical_count,
            Severity::High => self.critical_count + self.high_count,
            Severity::Medium => self.critical_count + self.high_count + self.medium_count,
            Severity::Low => self.total_findings - self.info_count,
            Severity::Info => self.total_findings,
        }
    }
}

/// Result of threshold checking
#[derive(Debug)]
pub struct ThresholdCheckResult {
    pub passed: bool,
    pub violations: Vec<ThresholdViolation>,
    pub statistics: AnalysisStatistics,
}

/// Types of threshold violations
#[derive(Debug)]
pub enum ThresholdViolation {
    SeverityThreshold {
        found: Severity,
        threshold: Severity,
    },
    FindingCount {
        found: usize,
        threshold: usize,
    },
}

/// Supported CI/CD platforms
#[derive(Debug, Clone, Copy)]
pub enum CiPlatform {
    GitHubActions,
    GitLabCI,
    Jenkins,
    Generic,
}

impl std::str::FromStr for CiPlatform {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "github" | "github-actions" => Ok(CiPlatform::GitHubActions),
            "gitlab" | "gitlab-ci" => Ok(CiPlatform::GitLabCI),
            "jenkins" => Ok(CiPlatform::Jenkins),
            "generic" => Ok(CiPlatform::Generic),
            _ => Err(format!("Unknown CI platform: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use detectors::types::DetectorId;

    fn create_finding(severity: Severity) -> Finding {
        Finding {
            detector_id: DetectorId::new("test-detector"),
            message: "Test finding".to_string(),
            severity,
            line: 1,
            column: 1,
            length: 10,
            cwe: None,
            fix_suggestion: None,
        }
    }

    #[test]
    fn test_exit_code_determination() {
        let manager = ExitCodeManager::default();

        // No findings = success
        assert_eq!(manager.determine_exit_code(&[]), 0);

        // Critical finding = exit code 2
        let critical_finding = create_finding(Severity::Critical);
        assert_eq!(manager.determine_exit_code(&[critical_finding]), 2);

        // High finding = exit code 1
        let high_finding = create_finding(Severity::High);
        assert_eq!(manager.determine_exit_code(&[high_finding]), 1);

        // Low finding with medium threshold = success
        let low_finding = create_finding(Severity::Low);
        assert_eq!(manager.determine_exit_code(&[low_finding]), 0);
    }

    #[test]
    fn test_severity_threshold() {
        let mut config = ExitCodeConfig::default();
        config.severity_threshold = Severity::High;
        let manager = ExitCodeManager::new(config);

        // Medium finding with high threshold = success
        let medium_finding = create_finding(Severity::Medium);
        assert_eq!(manager.determine_exit_code(&[medium_finding]), 0);

        // High finding with high threshold = failure
        let high_finding = create_finding(Severity::High);
        assert_eq!(manager.determine_exit_code(&[high_finding]), 1);
    }

    #[test]
    fn test_finding_count_threshold() {
        let mut config = ExitCodeConfig::default();
        config.fail_on_finding_count = Some(2);
        config.severity_threshold = Severity::Info; // Allow all severities
        let manager = ExitCodeManager::new(config);

        // 2 findings at threshold = success
        let findings = vec![
            create_finding(Severity::Low),
            create_finding(Severity::Low),
        ];
        assert_eq!(manager.determine_exit_code(&findings), 0);

        // 3 findings above threshold = failure
        let findings = vec![
            create_finding(Severity::Low),
            create_finding(Severity::Low),
            create_finding(Severity::Low),
        ];
        assert_eq!(manager.determine_exit_code(&findings), 1);
    }

    #[test]
    fn test_custom_exit_codes() {
        let mut config = ExitCodeConfig::default();
        config.custom_exit_codes.insert(Severity::Critical, 42);
        let manager = ExitCodeManager::new(config);

        let critical_finding = create_finding(Severity::Critical);
        assert_eq!(manager.determine_exit_code(&[critical_finding]), 42);
    }

    #[test]
    fn test_ci_platform_configuration() {
        let mut manager = ExitCodeManager::default();

        // GitHub Actions should use binary exit codes
        manager.configure_for_platform(CiPlatform::GitHubActions);
        let critical_finding = create_finding(Severity::Critical);
        assert_eq!(manager.determine_exit_code(&[critical_finding]), 1);

        // GitLab CI can use exit code 2 for critical
        manager.configure_for_platform(CiPlatform::GitLabCI);
        assert_eq!(manager.determine_exit_code(&[critical_finding]), 2);
    }

    #[test]
    fn test_analysis_statistics() {
        let manager = ExitCodeManager::default();
        let findings = vec![
            create_finding(Severity::Critical),
            create_finding(Severity::Critical),
            create_finding(Severity::High),
            create_finding(Severity::Medium),
            create_finding(Severity::Low),
        ];

        let stats = manager.get_analysis_statistics(&findings);
        assert_eq!(stats.total_findings, 5);
        assert_eq!(stats.critical_count, 2);
        assert_eq!(stats.high_count, 1);
        assert_eq!(stats.medium_count, 1);
        assert_eq!(stats.low_count, 1);
        assert_eq!(stats.info_count, 0);

        // Test severity and above counts
        assert_eq!(stats.count_for_severity_and_above(&Severity::Critical), 2);
        assert_eq!(stats.count_for_severity_and_above(&Severity::High), 3);
        assert_eq!(stats.count_for_severity_and_above(&Severity::Medium), 4);
    }

    #[test]
    fn test_threshold_checking() {
        let manager = ExitCodeManager::default();
        let findings = vec![
            create_finding(Severity::Critical),
            create_finding(Severity::High),
        ];

        let result = manager.check_thresholds(&findings);
        assert!(!result.passed); // Should fail due to severity threshold
        assert!(!result.violations.is_empty());
    }
}
