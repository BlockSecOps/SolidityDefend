// Safe pattern recognition library for reducing false positives
//
// This module provides functions to detect defensive programming patterns
// that protect against vulnerabilities. Detectors can use these functions
// to lower confidence when safe patterns are present.

// Existing pattern modules
pub mod vault_patterns;
pub mod reentrancy_patterns;
pub mod contract_classification;
pub mod erc_standard_compliance;
pub mod safe_call_patterns;
pub mod mev_protection_patterns;

// New comprehensive pattern modules (Phase 1 FP Reduction)
pub mod access_control_patterns;
pub mod cross_chain_patterns;
pub mod modern_eip_patterns;
pub mod advanced_patterns;

// Re-export all pattern functions
pub use vault_patterns::*;
pub use reentrancy_patterns::*;
pub use contract_classification::*;
pub use erc_standard_compliance::*;
pub use safe_call_patterns::*;
pub use mev_protection_patterns::*;
pub use access_control_patterns::*;
pub use cross_chain_patterns::*;
pub use modern_eip_patterns::*;
pub use advanced_patterns::*;
