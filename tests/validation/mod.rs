pub mod false_positive_analysis;
pub mod golden_file_testing;
pub mod integration_runner;
pub mod smartbugs;

pub use false_positive_analysis::{
    FalsePositiveAnalysis, FalsePositiveAnalyzer, Finding as FPFinding, GroundTruth, Severity,
};
pub use golden_file_testing::{
    AnalysisOutput, GoldenFile, GoldenFileRegression, RegressionTestResult, ToleranceConfig,
};
pub use integration_runner::{
    ValidationConfig, ValidationReport, ValidationSuite, run_comprehensive_validation,
};
pub use smartbugs::SmartBugsDataset;
