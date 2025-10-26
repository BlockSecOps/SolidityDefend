// Safe pattern recognition library for reducing false positives
//
// This module provides functions to detect defensive programming patterns
// that protect against vulnerabilities. Detectors can use these functions
// to lower confidence when safe patterns are present.

pub mod vault_patterns;
pub mod reentrancy_patterns;
pub mod contract_classification;
pub mod erc_standard_compliance;
pub mod safe_call_patterns;
pub mod mev_protection_patterns;

pub use vault_patterns::*;
pub use reentrancy_patterns::*;
pub use contract_classification::*;
pub use erc_standard_compliance::*;
pub use safe_call_patterns::*;
pub use mev_protection_patterns::*;
