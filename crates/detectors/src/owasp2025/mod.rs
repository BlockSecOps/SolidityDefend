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

pub mod enhanced_access_control;
pub mod enhanced_input_validation;
pub mod logic_error_patterns;
pub mod oracle_staleness;
pub mod oracle_time_window;
pub mod post_080_overflow;

pub use enhanced_access_control::EnhancedAccessControlDetector;
pub use enhanced_input_validation::EnhancedInputValidationDetector;
pub use logic_error_patterns::LogicErrorPatternsDetector;
pub use oracle_staleness::OracleStalenesDetector;
pub use oracle_time_window::OracleTimeWindowAttackDetector;
pub use post_080_overflow::Post080OverflowDetector;
