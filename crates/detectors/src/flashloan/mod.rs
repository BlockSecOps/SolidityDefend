//! Enhanced Flash Loan Security Detectors
//!
//! This module provides comprehensive security analysis for flash loan implementations,
//! detecting oracle manipulation, governance attacks, flash mint vulnerabilities, and
//! callback reentrancy.
//!
//! ## Detectors Included (v0.11.0)
//!
//! 1. **Flash Loan Price Oracle Manipulation** (CRITICAL)
//!    - Single-source spot price oracles (Polter Finance $7M exploit)
//!    - No TWAP protection
//!    - Missing flash loan detection
//!    - No multi-source oracle validation
//!
//! 2. **Flash Loan Governance Attack** (HIGH)
//!    - Current balance voting (Beanstalk $182M exploit)
//!    - No snapshot-based voting
//!    - Instant execution without timelock (Compound Proposal 289)
//!    - No quorum requirement
//!
//! 3. **Flash Mint Token Inflation** (HIGH)
//!    - Uncapped flash mint amounts
//!    - No flash mint fees
//!    - Missing rate limiting
//!
//! 4. **Flash Loan Callback Reentrancy** (MEDIUM)
//!    - State changes after external calls
//!    - No reentrancy guards
//!    - Unchecked callback returns
//!
//! ## Real-World Exploit References
//!
//! - **Polter Finance - $7M (2024)**: Flash loan oracle manipulation via BOO tokens
//! - **Shibarium Bridge - $2.4M (2024)**: Flash loan governance takeover with 4.6M BONE
//! - **Compound Proposal 289**: 682k flash-loaned votes passed malicious proposal
//! - **Euler Finance - $200M (2023)**: $30M DAI flash loan exploit
//! - **Beanstalk Farms - $182M (2022)**: $1B flash loan instant governance execution

pub mod callback_reentrancy;
pub mod flashmint_token_inflation;
pub mod price_oracle_manipulation;

// Re-export detectors
pub use callback_reentrancy::FlashloanCallbackReentrancyDetector;
pub use flashmint_token_inflation::FlashmintTokenInflationDetector;
pub use price_oracle_manipulation::FlashloanPriceOracleManipulationDetector;
