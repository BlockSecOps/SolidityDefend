// Safe pattern recognition library for reducing false positives
//
// This module provides functions to detect defensive programming patterns
// that protect against vulnerabilities. Detectors can use these functions
// to lower confidence when safe patterns are present.

// Existing pattern modules
pub mod contract_classification;
pub mod erc_standard_compliance;
pub mod mev_protection_patterns;
pub mod reentrancy_patterns;
pub mod safe_call_patterns;
pub mod vault_patterns;

// New comprehensive pattern modules (Phase 1 FP Reduction)
pub mod access_control_patterns;
pub mod advanced_patterns;
pub mod cross_chain_patterns;
pub mod flash_loan_patterns;
pub mod modern_eip_patterns;
pub mod oracle_patterns;
pub mod restaking_patterns;

// Re-export all pattern functions
pub use access_control_patterns::*;
pub use advanced_patterns::*;
pub use contract_classification::*;
pub use cross_chain_patterns::*;
pub use erc_standard_compliance::*;
pub use flash_loan_patterns::*;
pub use mev_protection_patterns::*;
pub use modern_eip_patterns::*;
pub use oracle_patterns::*;
pub use reentrancy_patterns::*;
pub use restaking_patterns::*;
pub use safe_call_patterns::*;
pub use vault_patterns::*;
