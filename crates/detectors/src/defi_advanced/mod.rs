//! Phase 30: Advanced DeFi Security Detectors
//!
//! This module contains advanced DeFi security detectors that complete the v1.0 milestone.
//! These detectors focus on sophisticated attack patterns in modern DeFi protocols.

// Detectors - added incrementally
pub mod amm_invariant_manipulation;
pub mod hook_reentrancy_enhanced;
pub mod jit_liquidity_sandwich;
pub mod pool_donation_enhanced;
pub mod yield_farming_manipulation;

// Re-exports
pub use amm_invariant_manipulation::AmmInvariantManipulationDetector;
pub use hook_reentrancy_enhanced::HookReentrancyEnhancedDetector;
pub use jit_liquidity_sandwich::JitLiquiditySandwichDetector;
pub use pool_donation_enhanced::PoolDonationEnhancedDetector;
pub use yield_farming_manipulation::YieldFarmingManipulationDetector;
