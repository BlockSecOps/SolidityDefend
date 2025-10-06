// Core detector framework
pub mod detector;
pub mod registry;
pub mod types;

// Detector implementations
pub mod access_control;
pub mod amm_liquidity_manipulation;
pub mod auction_timing;
pub mod auth;
pub mod block_stuffing_vulnerable;
pub mod confidence;
pub mod cross_chain_replay;
pub mod dangerous_delegatecall;
pub mod deadline_manipulation;
pub mod delegation_loop;
pub mod emergency_function_abuse;
pub mod emergency_withdrawal_abuse;
pub mod external;
pub mod flash_loan_staking;
pub mod flashloan;
pub mod gas_price_manipulation;
pub mod governance;
pub mod integer_overflow;
pub mod lending_liquidation_abuse;
pub mod liquidity_bootstrapping_abuse;
pub mod logic;
pub mod mev;
pub mod mev_extractable_value;
pub mod nonce_reuse;
pub mod oracle;
pub mod oracle_manipulation;
pub mod price_impact_manipulation;
pub mod reentrancy;
pub mod reward_calculation;
pub mod sandwich_resistant_swap;
pub mod selfdestruct_abuse;
pub mod signature_malleability;
pub mod slippage_protection;
pub mod storage_collision;
pub mod timestamp;
pub mod timestamp_manipulation;
pub mod uninitialized_storage;
pub mod validation;
pub mod vault_share_inflation;
pub mod weak_commit_reveal;
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
