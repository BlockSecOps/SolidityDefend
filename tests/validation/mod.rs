pub mod smartbugs;
pub mod false_positive_analysis;
pub mod golden_file_testing;
pub mod integration_runner;

pub use smartbugs::SmartBugsIntegration;
pub use false_positive_analysis::{
    FalsePositiveAnalyzer,
    FalsePositiveAnalysis,
    Finding as FPFinding,
    GroundTruth,
    Severity
};
pub use golden_file_testing::{
    GoldenFileRegression,
    GoldenFile,
    AnalysisOutput,
    RegressionTestResult,
    ToleranceConfig
};
pub use integration_runner::{
    ValidationSuite,
    ValidationConfig,
    ValidationReport,
    run_comprehensive_validation
};