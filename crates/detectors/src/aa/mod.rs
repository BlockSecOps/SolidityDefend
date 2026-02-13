//! Account Abstraction (ERC-4337) Advanced Security Detectors
//!
//! This module provides comprehensive security analysis for ERC-4337 Account Abstraction
//! implementations, detecting vulnerabilities in paymasters, nonce management, session keys,
//! signature aggregation, social recovery, and gas griefing.
//!
//! ## Detectors Included (v0.11.0)
//!
//! 1. **ERC-4337 Paymaster Abuse** (CRITICAL)
//!    - Replay attacks via nonce bypass (Biconomy exploit)
//!    - Gas estimation manipulation
//!    - Arbitrary transaction sponsorship
//!    - Missing spending limits
//!
//! 2. **AA Nonce Management** (HIGH)
//!    - Nonce key collision
//!    - Manual nonce tracking (not using EntryPoint)
//!    - Non-sequential nonce validation
//!    - Missing nonce key isolation for session keys
//!
//! 3. **AA Session Key Vulnerabilities** (HIGH)
//!    - Unlimited session key permissions
//!    - No expiration time
//!    - Missing target/function restrictions
//!    - No spending limits
//!    - No emergency pause mechanism
//!
//! 4. **AA Signature Aggregation** (MEDIUM)
//!    - No aggregator validation
//!    - Missing signature count verification
//!    - No signer deduplication
//!    - Threshold bypass
//!
//! 5. **AA Social Recovery** (MEDIUM)
//!    - No recovery delay (instant takeover)
//!    - Insufficient guardian threshold
//!    - No recovery cancellation
//!
//! 6. **ERC-4337 Gas Griefing** (LOW)
//!    - Large error messages
//!    - Unbounded loops in validation
//!    - Storage writes in validation phase
//!
//! ## Real-World Exploit References
//!
//! - **Biconomy Nonce Bypass (2024)**: Replay attack drained paymaster via nonce bypass
//! - **UniPass Vulnerability (Oct 2023)**: EntryPoint manipulation for account takeover
//! - **Gas Estimation Drain**: ~0.05 ETH per exploit via gas manipulation
//! - **Alchemy Audit (2025)**: Compromised signer API can withdraw full approval

pub mod classification;
pub mod paymaster_abuse;
pub mod session_key_vulnerabilities;
pub mod signature_aggregation;
pub mod social_recovery;

// Re-export classification utilities
pub use classification::*;

// Re-export detectors
pub use paymaster_abuse::ERC4337PaymasterAbuseDetector;
pub use session_key_vulnerabilities::AASessionKeyVulnerabilitiesDetector;
pub use signature_aggregation::AASignatureAggregationDetector;
pub use social_recovery::AASocialRecoveryDetector;
