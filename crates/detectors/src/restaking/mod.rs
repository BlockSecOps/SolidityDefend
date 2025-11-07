//! Restaking & Liquid Restaking Token (LRT) Security Detectors
//!
//! This module provides comprehensive security analysis for EigenLayer-based restaking protocols
//! and Liquid Restaking Tokens (LRTs). Targets $15B+ TVL in restaking ecosystem.
//!
//! ## Detectors (6 total)
//!
//! 1. **restaking-delegation-manipulation** (CRITICAL)
//!    - Detects improper operator validation and allocation manipulation
//!    - Real-world: EigenLayer operator centralization risk
//!
//! 2. **restaking-slashing-conditions** (CRITICAL)
//!    - Detects missing slashing protection and compound slashing risks
//!    - Real-world: EigenLayer slashing launched April 2025 (new attack surface)
//!
//! 3. **lrt-share-inflation** (CRITICAL)
//!    - Detects ERC-4626-style first depositor attacks
//!    - Real-world: Kelp DAO HIGH severity finding (Nov 2023)
//!
//! 4. **restaking-withdrawal-delays** (HIGH)
//!    - Detects missing withdrawal delay enforcement
//!    - Real-world: Renzo ezETH depeg $65M+ liquidations (April 2024)
//!
//! 5. **avs-validation-bypass** (HIGH)
//!    - Detects AVS registration without security validation
//!    - Real-world: Malicious AVS can slash operator stakes
//!
//! 6. **restaking-rewards-manipulation** (MEDIUM)
//!    - Detects reward calculation exploits and point system gaming
//!    - Real-world: Renzo airdrop farming controversy
//!
//! ## Architecture
//!
//! ```text
//! restaking/
//! ├── mod.rs                      # This file (module exports)
//! ├── classification.rs           # Shared utilities (~20 functions)
//! ├── delegation_manipulation.rs  # Detector 1
//! ├── slashing_conditions.rs      # Detector 2
//! ├── lrt_share_inflation.rs      # Detector 3
//! ├── withdrawal_delays.rs        # Detector 4
//! ├── avs_validation.rs           # Detector 5
//! └── rewards_manipulation.rs     # Detector 6
//! ```
//!
//! ## References
//!
//! - EigenLayer: https://docs.eigencloud.xyz
//! - Kelp DAO Audit: https://code4rena.com/reports/2023-11-kelp
//! - Renzo Protocol: https://docs.renzoprotocol.com
//! - ERC-4626 Vault Standard: https://eips.ethereum.org/EIPS/eip-4626

pub mod avs_validation;
pub mod classification;
pub mod delegation_manipulation;
pub mod lrt_share_inflation;
pub mod rewards_manipulation;
pub mod slashing_conditions;
pub mod withdrawal_delays;

// Re-export classification utilities for use by all detectors
pub use classification::*;

// Re-export detectors
pub use avs_validation::AVSValidationBypassDetector;
pub use delegation_manipulation::RestakingDelegationManipulationDetector;
pub use lrt_share_inflation::LRTShareInflationDetector;
pub use rewards_manipulation::RestakingRewardsManipulationDetector;
pub use slashing_conditions::RestakingSlashingConditionsDetector;
pub use withdrawal_delays::RestakingWithdrawalDelaysDetector;
