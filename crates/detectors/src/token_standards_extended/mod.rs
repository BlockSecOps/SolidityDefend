//! Token Standards Extended Security Detectors
//!
//! This module provides advanced token standard security analysis covering
//! edge cases and attack vectors in ERC-20, ERC-721, and ERC-1155 implementations.
//!
//! ## Detectors (5 total)
//!
//! 1. **erc20-transfer-return-bomb** (MEDIUM)
//!    - Return data bombs causing DOS
//!    - Real-world: Gas exhaustion attacks
//!
//! 2. **erc721-enumeration-dos** (MEDIUM)
//!    - Enumeration gas bombs
//!    - Real-world: Unbounded loops in NFT enumeration
//!
//! 3. **erc1155-batch-validation** (MEDIUM)
//!    - Missing batch validation
//!    - Real-world: Array length mismatch exploits
//!
//! 4. **token-decimal-confusion** (HIGH)
//!    - Decimal mismatch errors
//!    - Real-world: Loss of funds due to decimal assumptions
//!
//! 5. **token-permit-front-running** (MEDIUM)
//!    - ERC-2612 permit griefing
//!    - Real-world: Front-running permit signatures

pub mod batch_validation;
pub mod decimal_confusion;
pub mod enumeration_dos;
pub mod permit_front_running;
pub mod transfer_return_bomb;

// Re-export detectors
pub use batch_validation::ERC1155BatchValidationDetector;
pub use decimal_confusion::TokenDecimalConfusionDetector;
pub use enumeration_dos::ERC721EnumerationDosDetector;
pub use permit_front_running::TokenPermitFrontRunningDetector;
pub use transfer_return_bomb::ERC20TransferReturnBombDetector;
