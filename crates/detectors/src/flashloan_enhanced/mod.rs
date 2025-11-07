//! Flash Loan Enhanced Security Detectors
//!
//! This module provides advanced flash loan security analysis addressing $33.8M
//! in losses from 2024 flash loan exploits, including the Penpie $27M attack.
//!
//! ## Detectors (4 total)
//!
//! 1. **flash-loan-price-manipulation-advanced** (CRITICAL)
//!    - Multi-protocol price manipulation chains
//!    - Real-world: Cascading liquidations
//!
//! 2. **flash-loan-governance-attack** (CRITICAL)
//!    - DAO takeover via flash-borrowed governance tokens
//!    - Real-world: Temporary voting power exploits
//!
//! 3. **flash-loan-reentrancy-combo** (CRITICAL)
//!    - Combined flash loan + reentrancy
//!    - Real-world: Penpie $27M exploit pattern
//!
//! 4. **flash-loan-collateral-swap** (HIGH)
//!    - Collateral ratio manipulation
//!    - Real-world: Unfair liquidation triggering

pub mod collateral_swap;
pub mod governance_attack;
pub mod price_manipulation_advanced;
pub mod reentrancy_combo;

// Re-export detectors
pub use collateral_swap::FlashLoanCollateralSwapDetector;
pub use governance_attack::FlashLoanGovernanceAttackDetector;
pub use price_manipulation_advanced::FlashLoanPriceManipulationAdvancedDetector;
pub use reentrancy_combo::FlashLoanReentrancyComboDetector;
