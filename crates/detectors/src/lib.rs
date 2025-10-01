// Core detector framework
pub mod detector;
pub mod registry;
pub mod types;

// Detector implementations
pub mod access_control;
pub mod auth;
pub mod confidence;
pub mod external;
pub mod flashloan;
pub mod logic;
pub mod mev;
pub mod oracle;
pub mod reentrancy;
pub mod timestamp;
pub mod validation;

// Re-export core types and traits
pub use detector::{
    Detector, DetectorCategory, ConfigurableDetector, MetricsDetector,
    BaseDetector, AstAnalyzer, DataFlowAnalyzer, TaintAnalyzer
};
pub use registry::{DetectorRegistry, DetectorRegistryBuilder, RegistryConfig};
pub use types::{
    DetectorId, Severity, Confidence, SourceLocation, Finding,
    AnalysisContext, AnalysisResult, AnalysisStats
};

// Convenience macro for implementing the Detector trait is defined in detector.rs
