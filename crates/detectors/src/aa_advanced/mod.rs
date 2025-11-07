//! ERC-4337 Account Abstraction Advanced Security Detectors
//!
//! This module provides advanced security analysis for ERC-4337 Account Abstraction,
//! addressing sophisticated vulnerabilities discovered in production AA wallets (2024).
//!
//! ## Detectors (6 total)
//!
//! 1. **aa-calldata-encoding-exploit** (CRITICAL)
//!    - Detects calldata manipulation after signature validation
//!    - Real-world: 2024 AA wallet vulnerability
//!
//! 2. **aa-paymaster-fund-drain** (CRITICAL)
//!    - Detects paymaster sponsorship abuse patterns
//!    - Real-world: Paymaster wallet drainage
//!
//! 3. **aa-signature-aggregation-bypass** (HIGH)
//!    - Detects signature aggregation vulnerabilities
//!    - Real-world: Unauthorized batch operation execution
//!
//! 4. **aa-user-operation-replay** (HIGH)
//!    - Detects UserOperation replay across bundlers/chains
//!    - Real-world: Double-spending of user operations
//!
//! 5. **aa-entry-point-reentrancy** (MEDIUM)
//!    - Detects reentrancy in handleOps/validateUserOp
//!    - Real-world: AA-specific reentrancy vector
//!
//! 6. **aa-bundler-dos-enhanced** (HIGH)
//!    - Enhanced bundler DOS detection (2024 patterns)
//!    - Real-world: Production bundler attacks

pub mod bundler_dos_enhanced;
pub mod calldata_encoding_exploit;
pub mod entry_point_reentrancy;
pub mod paymaster_fund_drain;
pub mod signature_aggregation_bypass;
pub mod user_operation_replay;

// Re-export detectors
pub use bundler_dos_enhanced::AABundlerDosEnhancedDetector;
pub use calldata_encoding_exploit::AACalldataEncodingExploitDetector;
pub use entry_point_reentrancy::AAEntryPointReentrancyDetector;
pub use paymaster_fund_drain::AAPaymasterFundDrainDetector;
pub use signature_aggregation_bypass::AASignatureAggregationBypassDetector;
pub use user_operation_replay::AAUserOperationReplayDetector;
