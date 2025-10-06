// Core detector framework
pub mod detector;
pub mod registry;
pub mod types;

// Detector implementations
pub mod access_control;
pub mod auction_timing;
pub mod auth;
pub mod confidence;
pub mod cross_chain_replay;
pub mod delegation_loop;
pub mod external;
pub mod flash_loan_staking;
pub mod flashloan;
pub mod governance;
pub mod logic;
pub mod mev;
pub mod oracle;
pub mod oracle_manipulation;
pub mod reentrancy;
pub mod slippage_protection;
pub mod timestamp;
pub mod validation;
pub mod weak_signature_validation;

// DeFi-specific detectors
pub mod defi;

// Cross-contract analysis
pub mod cross_contract;

// Advanced taint analysis
pub mod taint;

// Advanced security engine integrating all advanced features
pub mod advanced_security_engine;

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
