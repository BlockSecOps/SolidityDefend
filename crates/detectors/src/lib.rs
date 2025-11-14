// Core detector framework
pub mod detector;
pub mod registry;
pub mod types;

// Utility functions for context detection and pattern recognition
pub mod utils;

// Safe pattern recognition library
pub mod safe_patterns;

// Detector implementations
pub mod access_control;
pub mod amm_liquidity_manipulation;
pub mod array_length_mismatch;
pub mod auction_timing;
pub mod auth;
pub mod batch_transfer_overflow;
pub mod block_stuffing_vulnerable;
pub mod centralization_risk;
pub mod circular_dependency;
pub mod confidence;
pub mod cross_chain_replay;
pub mod dangerous_delegatecall;
pub mod delegatecall_in_constructor;
pub mod delegatecall_return_ignored;
pub mod delegatecall_untrusted_library;
pub mod delegatecall_user_controlled;
pub mod deadline_manipulation;
pub mod delegation_loop;
pub mod deprecated_functions;
pub mod dos_failed_transfer;
pub mod dos_unbounded_operation;
pub mod emergency_function_abuse;
pub mod emergency_withdrawal_abuse;
pub mod excessive_gas_usage;
pub mod external;
pub mod fallback_delegatecall_unprotected;
pub mod fallback_function_shadowing;
pub mod flash_loan_staking;
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
pub mod redundant_checks;
pub mod reentrancy;
pub mod reward_calculation;
pub mod sandwich_resistant_swap;
pub mod selfdestruct_abuse;
pub mod shadowing_variables;
pub mod short_address;
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
pub mod proxy_upgrade_unprotected;
pub mod proxy_storage_collision;
pub mod validation;
pub mod validator_front_running;
pub mod validator_griefing;
pub mod vault_donation_attack;
pub mod vault_fee_manipulation;
pub mod vault_hook_reentrancy;
pub mod vault_share_inflation;
pub mod vault_withdrawal_dos;
pub mod weak_commit_reveal;
pub mod weak_signature_validation;
pub mod withdrawal_delay;

// Phase 12: Account Abstraction & ERC-4337 (2025)
pub mod aa_account_takeover;
pub mod aa_bundler_dos;
pub mod aa_initialization_vulnerability;
pub mod aa_session_key_vulnerabilities;
pub mod aa_social_recovery;
pub mod erc4337_entrypoint_trust;
pub mod hardware_wallet_delegation;

// Phase 13: Cross-Chain Intent & Bridge Security (2025)
pub mod bridge_chain_id_validation;
pub mod bridge_message_verification;
pub mod bridge_token_minting;
// pub mod erc7683_filler_frontrunning;
// pub mod erc7683_oracle_dependency;
// pub mod erc7683_permit2_integration;
// pub mod erc7683_replay_attack;
// pub mod erc7683_settlement_validation;

// Phase 13 v0.9.0: Comprehensive ERC-7683 Intent Detectors (2025) - TODO: Add to v0.12.0
// pub mod erc7683;

// Phase 31: Restaking & LRT Security (v0.17.0)
pub mod restaking;

// Phase 32: Advanced Access Control (v0.18.0)
pub mod access_control_advanced;

// Phase 33: ERC-4337 AA Advanced (v0.19.0)
pub mod aa_advanced;

// Phase 34: Flash Loan Enhanced (v0.20.0)
pub mod flashloan_enhanced;

// Phase 35: Token Standards Extended (v0.21.0)
pub mod token_standards_extended;

// Phase 36: MEV Protection Enhanced (v0.22.0)
pub mod mev_enhanced;

// Phase 37: Zero-Knowledge Proofs (v1.0.0)
pub mod zk_proofs;

// Phase 38: Modular Blockchain (v1.0.0)
pub mod modular_blockchain;

// Phase 39: AI Agent Security (v1.0.0)
pub mod ai_agent;

// Phase 24 v0.11.0: Account Abstraction Advanced & Enhanced Flash Loans (2025)
pub mod aa;
pub mod flashloan;

// Phase 15: DeFi Protocol Security (2025)
pub mod defi_jit_liquidity;
pub mod defi_liquidity_pool_manipulation;
pub mod defi_yield_farming;

// Phase 17: Token Standard Edge Cases (2025)
pub mod erc20_approve_race;
pub mod token_transfer_frontrun;
pub mod allowance_toctou;
pub mod price_manipulation_frontrun;
pub mod missing_transaction_deadline;
pub mod erc20_infinite_approval;
pub mod erc721_callback_reentrancy;
pub mod erc777_reentrancy_hooks;

// Phase 18: DeFi Protocol-Specific (2025)
pub mod amm_k_invariant_violation;
pub mod lending_borrow_bypass;
pub mod uniswapv4_hook_issues;

// Phase 19: Code Quality & Best Practices (2025)
pub mod floating_pragma;
pub mod unused_state_variables;

// Phase 20: L2/Rollup Security (2025)
pub mod l2_bridge_message_validation;
pub mod l2_data_availability;
pub mod l2_fee_manipulation;
pub mod optimistic_challenge_bypass;
pub mod zk_proof_bypass;

// Phase 21: Diamond Proxy & Advanced Upgrades (2025)
pub mod diamond_delegatecall_zero;
pub mod diamond_init_reentrancy;
pub mod diamond_loupe_violation;
pub mod diamond_selector_collision;
pub mod diamond_storage_collision;

// Phase 22: Metamorphic Contracts & CREATE2 (2025)
pub mod create2_frontrunning;
pub mod extcodesize_bypass;
pub mod metamorphic_contract;
pub mod selfdestruct_recipient;

// Phase 23: v1.0 Milestone - Final Detectors (2025)
pub mod multisig_bypass;
pub mod permit_signature_exploit;
pub mod storage_layout_upgrade;

// Phase 24: EIP-1153 Transient Storage Security (2025)
pub mod transient;

// Phase 25: EIP-7702 Account Delegation Security (2025)
pub mod eip7702;

// Phase 26: ERC-7821 Batch Executor Security (2025)
pub mod erc7821;

// Phase 27: ERC-7683 Intent-Based Security (2025)
pub mod erc7683;

// Phase 28: Private Data & Storage Security (2025)
pub mod privacy;

// Phase 29: OWASP 2025 Top 10 Gap Detectors (2025)
pub mod owasp2025;

// Phase 30: Advanced DeFi Patterns (v1.0 Milestone - 2025)
pub mod defi_advanced;

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
    AstAnalyzer, BaseDetector, ConfigurableDetector, DataFlowAnalyzer, Detector, DetectorCategory,
    MetricsDetector, TaintAnalyzer,
};
pub use registry::{DetectorRegistry, DetectorRegistryBuilder, RegistryConfig};
pub use types::{
    AnalysisContext, AnalysisResult, AnalysisStats, Confidence, DetectorId, Finding, Severity,
    SourceLocation,
};

// Convenience macro for implementing the Detector trait is defined in detector.rs
