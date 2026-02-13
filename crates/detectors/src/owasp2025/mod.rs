//! OWASP 2025 Top 10 Gap Detectors (Phase 29)
//!
//! Detectors addressing specific gaps in OWASP Smart Contract Top 10 (2025) coverage.
//! Based on analysis of $1.42B in losses across 149 incidents in 2024.
//!
//! ## Detectors Included (Phase 29)
//!
//! 1. **Logic Error Patterns** (HIGH)
//!    - Faulty reward distribution ($63.8M)
//!    - Division before multiplication
//!    - Rounding errors
//!
//! 2. **Oracle Time Window Attack** (HIGH)
//!    - Time-window manipulation
//!    - Missing TWAP implementation
//!
//! 3. **Oracle Staleness Heartbeat** (MEDIUM)
//!    - Chainlink heartbeat validation
//!    - Stale price usage
//!
//! 4. **Enhanced Input Validation** (HIGH)
//!    - Comprehensive bounds checking ($14.6M)
//!    - Array length validation
//!
//! 5. **Post-0.8.0 Overflow** (MEDIUM)
//!    - Unchecked block overflows
//!    - Assembly arithmetic ($223M Cetus)
//!
//! 6. **Enhanced Access Control** (CRITICAL)
//!    - Role management flaws ($953M)
//!    - Privilege escalation

pub mod enhanced_input_validation;
pub mod oracle_staleness;

pub use enhanced_input_validation::EnhancedInputValidationDetector;
pub use oracle_staleness::OracleStalenesDetector;
