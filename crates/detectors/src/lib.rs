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
pub mod centralization_risk;
pub mod circular_dependency;
pub mod confidence;
pub mod cross_chain_replay;
pub mod dangerous_delegatecall;
pub mod deadline_manipulation;
pub mod delegation_loop;
pub mod deprecated_functions;
pub mod dos_unbounded_operation;
pub mod emergency_function_abuse;
pub mod emergency_withdrawal_abuse;
pub mod excessive_gas_usage;
pub mod external;
pub mod flash_loan_staking;
pub mod flashloan;
pub mod front_running_mitigation;
pub mod gas_griefing;
pub mod gas_price_manipulation;
pub mod governance;
pub mod inefficient_storage;
pub mod insufficient_randomness;
pub mod integer_overflow;
pub mod lending_liquidation_abuse;
pub mod liquidity_bootstrapping_abuse;
pub mod logic;
pub mod mev;
pub mod mev_extractable_value;
pub mod missing_input_validation;
pub mod nonce_reuse;
pub mod oracle;
pub mod oracle_manipulation;
pub mod price_impact_manipulation;
pub mod price_oracle_stale;
pub mod reentrancy;
pub mod reward_calculation;
pub mod redundant_checks;
pub mod sandwich_resistant_swap;
pub mod selfdestruct_abuse;
pub mod shadowing_variables;
pub mod signature_malleability;
pub mod slashing_mechanism;
pub mod slippage_protection;
pub mod storage_collision;
pub mod timestamp;
pub mod timestamp_manipulation;
pub mod token_supply_manipulation;
pub mod unchecked_math;
pub mod uninitialized_storage;
pub mod unsafe_type_casting;
pub mod upgradeable_proxy_issues;
pub mod validation;
pub mod validator_front_running;
pub mod validator_griefing;
pub mod vault_share_inflation;
pub mod weak_commit_reveal;
pub mod weak_signature_validation;
pub mod withdrawal_delay;

// Phase 12: Account Abstraction & ERC-4337 (2025)
pub mod erc4337_entrypoint_trust;
pub mod aa_initialization_vulnerability;
pub mod aa_account_takeover;
pub mod aa_bundler_dos;
pub mod hardware_wallet_delegation;

// Phase 13: Cross-Chain Intent & Bridge Security (2025)
pub mod erc7683_settlement_validation;
pub mod erc7683_replay_attack;
pub mod erc7683_filler_frontrunning;
pub mod erc7683_oracle_dependency;
pub mod erc7683_permit2_integration;
pub mod bridge_token_minting;
pub mod bridge_message_verification;
pub mod bridge_chain_id_validation;

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
