use anyhow::Result;
use std::any::Any;

use crate::types::{AnalysisContext, DetectorId, Finding};

/// Core trait that all vulnerability detectors must implement
pub trait Detector: Send + Sync {
    /// Unique identifier for this detector
    fn id(&self) -> DetectorId;

    /// Human-readable name of the detector
    fn name(&self) -> &str;

    /// Description of what this detector finds
    fn description(&self) -> &str;

    /// Categories this detector belongs to
    fn categories(&self) -> Vec<DetectorCategory>;

    /// Severity level this detector typically reports
    fn default_severity(&self) -> crate::types::Severity;

    /// Run the detector on the given analysis context
    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>>;

    /// Check if this detector is enabled (default: true)
    fn is_enabled(&self) -> bool {
        true
    }

    /// Get the confidence level this detector typically produces
    fn default_confidence(&self) -> crate::types::Confidence {
        crate::types::Confidence::Medium
    }

    /// Get execution priority (higher values run first)
    fn priority(&self) -> u8 {
        50 // Default medium priority
    }

    /// Whether this detector requires data flow analysis
    fn requires_dataflow(&self) -> bool {
        false
    }

    /// Whether this detector requires taint analysis
    fn requires_taint_analysis(&self) -> bool {
        false
    }

    /// Whether this detector requires control flow graphs
    fn requires_cfg(&self) -> bool {
        false
    }

    /// Get the detector as Any for downcasting
    fn as_any(&self) -> &dyn Any;
}

/// Categories of vulnerability detectors
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum DetectorCategory {
    /// Access control and authorization issues
    AccessControl,
    /// Reentrancy vulnerabilities
    Reentrancy,
    /// Reentrancy attack patterns
    ReentrancyAttacks,
    /// Oracle manipulation and price attacks
    Oracle,
    /// Flash loan attack vectors
    FlashLoan,
    /// Flash loan attack patterns
    FlashLoanAttacks,
    /// MEV and front-running issues
    MEV,
    /// External call vulnerabilities
    ExternalCalls,
    /// Input validation problems
    Validation,
    /// Logic bugs and business logic issues
    Logic,
    /// Timestamp dependencies
    Timestamp,
    /// Authentication and authorization
    Auth,
    /// General security best practices
    BestPractices,
    /// Cross-chain bridge vulnerabilities
    CrossChain,
    /// DeFi protocol vulnerabilities
    DeFi,
    /// Layer 2 and rollup vulnerabilities
    L2,
    /// ZK rollup specific vulnerabilities
    ZKRollup,
    /// Data availability issues
    DataAvailability,
    /// Diamond proxy (ERC-2535) vulnerabilities
    Diamond,
    /// Upgradeable contract vulnerabilities
    Upgradeable,
}

impl DetectorCategory {
    /// Get all detector categories
    pub fn all() -> Vec<Self> {
        vec![
            Self::AccessControl,
            Self::Reentrancy,
            Self::ReentrancyAttacks,
            Self::Oracle,
            Self::FlashLoan,
            Self::FlashLoanAttacks,
            Self::MEV,
            Self::ExternalCalls,
            Self::Validation,
            Self::Logic,
            Self::Timestamp,
            Self::Auth,
            Self::BestPractices,
            Self::CrossChain,
            Self::DeFi,
            Self::L2,
            Self::ZKRollup,
            Self::DataAvailability,
            Self::Diamond,
            Self::Upgradeable,
        ]
    }

    /// Get the display name for this category
    pub fn display_name(&self) -> &str {
        match self {
            Self::AccessControl => "Access Control",
            Self::Reentrancy => "Reentrancy",
            Self::ReentrancyAttacks => "Reentrancy Attacks",
            Self::Oracle => "Oracle Manipulation",
            Self::FlashLoan => "Flash Loan Attacks",
            Self::FlashLoanAttacks => "Flash Loan Attack Patterns",
            Self::MEV => "MEV & Front-running",
            Self::ExternalCalls => "External Calls",
            Self::Validation => "Input Validation",
            Self::Logic => "Logic Bugs",
            Self::Timestamp => "Timestamp Dependencies",
            Self::Auth => "Authentication",
            Self::BestPractices => "Best Practices",
            Self::CrossChain => "Cross-Chain Bridges",
            Self::DeFi => "DeFi Protocols",
            Self::L2 => "Layer 2 Rollups",
            Self::ZKRollup => "ZK Rollups",
            Self::DataAvailability => "Data Availability",
            Self::Diamond => "Diamond Proxy (ERC-2535)",
            Self::Upgradeable => "Upgradeable Contracts",
        }
    }
}

impl std::fmt::Display for DetectorCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Trait for detectors that can be configured
pub trait ConfigurableDetector: Detector {
    /// Type representing the configuration for this detector
    type Config;

    /// Configure the detector with the given configuration
    fn configure(&mut self, config: Self::Config) -> Result<()>;

    /// Get the current configuration
    fn get_config(&self) -> &Self::Config;
}

/// Trait for detectors that provide performance metrics
pub trait MetricsDetector: Detector {
    /// Get performance metrics for the last run
    fn get_metrics(&self) -> DetectorMetrics;

    /// Reset performance metrics
    fn reset_metrics(&mut self);
}

/// Performance metrics for a detector
#[derive(Debug, Clone)]
pub struct DetectorMetrics {
    /// Number of times the detector has been run
    pub runs: u64,
    /// Total execution time in microseconds
    pub total_time_us: u64,
    /// Average execution time in microseconds
    pub avg_time_us: u64,
    /// Number of findings produced
    pub findings_count: u64,
    /// Number of false positives (if known)
    pub false_positives: u64,
}

impl DetectorMetrics {
    pub fn new() -> Self {
        Self {
            runs: 0,
            total_time_us: 0,
            avg_time_us: 0,
            findings_count: 0,
            false_positives: 0,
        }
    }

    /// Record a new run
    pub fn record_run(&mut self, duration_us: u64, findings: usize) {
        self.runs += 1;
        self.total_time_us += duration_us;
        self.avg_time_us = self.total_time_us / self.runs;
        self.findings_count += findings as u64;
    }

    /// Record a false positive
    pub fn record_false_positive(&mut self) {
        self.false_positives += 1;
    }

    /// Get the false positive rate (0.0 to 1.0)
    pub fn false_positive_rate(&self) -> f64 {
        if self.findings_count == 0 {
            0.0
        } else {
            self.false_positives as f64 / self.findings_count as f64
        }
    }
}

impl Default for DetectorMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Base implementation for detectors with common functionality
pub struct BaseDetector {
    pub id: DetectorId,
    pub name: String,
    pub description: String,
    pub categories: Vec<DetectorCategory>,
    pub default_severity: crate::types::Severity,
    pub enabled: bool,
    pub metrics: DetectorMetrics,
}

impl BaseDetector {
    pub fn new(
        id: DetectorId,
        name: String,
        description: String,
        categories: Vec<DetectorCategory>,
        default_severity: crate::types::Severity,
    ) -> Self {
        Self {
            id,
            name,
            description,
            categories,
            default_severity,
            enabled: true,
            metrics: DetectorMetrics::new(),
        }
    }

    /// Helper method to create a finding with default values
    pub fn create_finding(
        &self,
        ctx: &AnalysisContext<'_>,
        message: String,
        line: u32,
        column: u32,
        length: u32,
    ) -> Finding {
        Finding::new(
            self.id.clone(),
            self.default_severity,
            crate::types::Confidence::Medium,
            message,
            ctx.create_location(line, column, length),
        )
    }

    /// Helper method to create a finding with custom severity
    pub fn create_finding_with_severity(
        &self,
        ctx: &AnalysisContext<'_>,
        message: String,
        line: u32,
        column: u32,
        length: u32,
        severity: crate::types::Severity,
    ) -> Finding {
        Finding::new(
            self.id.clone(),
            severity,
            crate::types::Confidence::Medium,
            message,
            ctx.create_location(line, column, length),
        )
    }
}

/// Macro to help implement the Detector trait for structs that contain BaseDetector
#[allow(unused_macros)]
macro_rules! impl_detector_base {
    ($struct_name:ty) => {
        impl Detector for $struct_name {
            fn id(&self) -> DetectorId {
                self.base.id.clone()
            }

            fn name(&self) -> &str {
                &self.base.name
            }

            fn description(&self) -> &str {
                &self.base.description
            }

            fn categories(&self) -> Vec<DetectorCategory> {
                self.base.categories.clone()
            }

            fn default_severity(&self) -> crate::types::Severity {
                self.base.default_severity
            }

            fn is_enabled(&self) -> bool {
                self.base.enabled
            }

            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        impl MetricsDetector for $struct_name {
            fn get_metrics(&self) -> DetectorMetrics {
                self.base.metrics.clone()
            }

            fn reset_metrics(&mut self) {
                self.base.metrics = DetectorMetrics::new();
            }
        }
    };
}

/// Helper trait for detectors that analyze specific AST nodes
pub trait AstAnalyzer {
    /// Analyze a function for vulnerabilities
    fn analyze_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>>;

    /// Analyze a statement for vulnerabilities
    fn analyze_statement(
        &self,
        statement: &ast::Statement<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>>;

    /// Analyze an expression for vulnerabilities
    fn analyze_expression(
        &self,
        expression: &ast::Expression<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>>;

    /// Analyze a modifier for vulnerabilities
    fn analyze_modifier(
        &self,
        modifier: &ast::Modifier<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>>;
}

/// Helper trait for detectors that use data flow analysis
pub trait DataFlowAnalyzer {
    /// Analyze data flow patterns for vulnerabilities
    fn analyze_dataflow(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>>;
}

/// Helper trait for detectors that use taint analysis
pub trait TaintAnalyzer {
    /// Analyze taint propagation for vulnerabilities
    fn analyze_taint(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>>;
}
