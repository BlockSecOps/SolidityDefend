pub mod false_positive_analysis;
pub mod golden_file_testing;
pub mod ground_truth;
pub mod integration_runner;
pub mod regression_tests;
pub mod smartbugs;

pub use false_positive_analysis::{
    FalsePositiveAnalysis, FalsePositiveAnalyzer, Finding as FPFinding, GroundTruth, Severity,
};
pub use golden_file_testing::{
    AnalysisOutput, GoldenFile, GoldenFileRegression, RegressionTestResult, ToleranceConfig,
};
pub use ground_truth::{
    ActualFinding, ContractGroundTruth, DetectorMetrics, ExpectedFinding, GroundTruthDataset,
    GroundTruthValidator, ValidationResult, ValidationSummary,
};
pub use integration_runner::{
    ValidationConfig, ValidationReport, ValidationSuite, run_comprehensive_validation,
};
pub use regression_tests::{MustDetectTest, RegressionTestSuite};
pub use smartbugs::SmartBugsDataset;
