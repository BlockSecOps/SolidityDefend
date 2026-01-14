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
pub mod missing_eip712_domain;
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

// Phase 40: SWC Coverage Expansion (v1.5.0 - 2026)
pub mod swc105_unprotected_ether_withdrawal;
pub mod swc106_unprotected_selfdestruct;
pub mod swc132_unexpected_ether_balance;
pub mod swc133_hash_collision_varlen;

// Phase 41: Proxy & Upgradeable Contract Security (v1.6.0 - 2026)
pub mod beacon_upgrade_unprotected;
pub mod eip1967_slot_compliance;
pub mod function_selector_clash;
pub mod immutable_in_upgradeable;
pub mod implementation_not_initialized;
pub mod implementation_selfdestruct;
pub mod initializer_reentrancy;
pub mod minimal_proxy_clone_issues;
pub mod missing_storage_gap;
pub mod transparent_proxy_admin_issues;
pub mod uups_missing_disable_initializers;
pub mod uups_upgrade_unsafe;

// Phase 42: Advanced Proxy Security & Vulnerability Patterns (v1.7.0 - 2026)
pub mod reinitializer_vulnerability;
pub mod storage_layout_inheritance_shift;
pub mod beacon_single_point_of_failure;
pub mod clones_immutable_args_bypass;
pub mod upgrade_abi_incompatibility;
pub mod diamond_facet_code_existence;
pub mod proxy_context_visibility_mismatch;
pub mod upgrade_event_missing;
pub mod delegatecall_in_loop;
pub mod fallback_delegatecall_pattern;
pub mod unchecked_send_return;
pub mod transaction_ordering_dependence;
pub mod l2_sequencer_dependency;
pub mod cross_chain_replay_protection;

// Phase 43: EIP-7702 & EIP-1153 New Standards (v1.8.0 - 2026)
pub mod eip7702_delegation_phishing;
pub mod eip7702_storage_corruption;
pub mod eip7702_sweeper_attack;
pub mod eip7702_authorization_bypass;
pub mod eip7702_replay_vulnerability;
pub mod eip1153_transient_reentrancy;
pub mod eip1153_cross_tx_assumption;
pub mod eip1153_callback_manipulation;
pub mod eip1153_composability_risk;
pub mod eip1153_guard_bypass;

// Phase 44: Advanced MEV & Front-Running (v1.8.1 - 2026)
pub mod sandwich_conditional_swap;
pub mod jit_liquidity_extraction;
pub mod backrunning_opportunity;
pub mod bundle_inclusion_leak;
pub mod order_flow_auction_abuse;
pub mod encrypted_mempool_timing;
pub mod cross_domain_mev;
pub mod liquidation_mev;
pub mod oracle_update_mev;
pub mod governance_proposal_mev;
pub mod token_launch_mev;
pub mod nft_mint_mev;

// Phase 45: Metamorphic & CREATE2 Patterns (v1.8.2 - 2026)
pub mod metamorphic_contract_risk;
pub mod create2_salt_frontrunning;
pub mod create2_address_collision;
pub mod extcodesize_check_bypass;
pub mod selfdestruct_recipient_control;
pub mod contract_recreation_attack;
pub mod constructor_reentrancy;
pub mod initcode_injection;

// Phase 46: Callback Chains & Multicall (v1.8.3 - 2026)
pub mod nested_callback_reentrancy;
pub mod callback_in_callback_loop;
pub mod multicall_msgvalue_reuse;
pub mod multicall_partial_revert;
pub mod batch_cross_function_reentrancy;
pub mod flash_callback_manipulation;
pub mod erc721_safemint_callback;
pub mod erc1155_callback_reentrancy;
pub mod uniswap_v4_hook_callback;
pub mod compound_callback_chain;

// Phase 47: Governance & Access Control (v1.8.4 - 2026)
pub mod governance_parameter_bypass;
pub mod voting_snapshot_manipulation;
pub mod quorum_calculation_overflow;
pub mod proposal_frontrunning;
pub mod governor_refund_drain;
pub mod timelock_bypass_delegatecall;
pub mod role_escalation_upgrade;
pub mod accesscontrol_race_condition;
pub mod operator_whitelist_inheritance;
pub mod cross_contract_role_confusion;

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
