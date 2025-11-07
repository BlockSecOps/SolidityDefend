//! Private Data & Storage Visibility Detectors (Phase 28)
//!
//! This module provides educational detectors for common privacy mistakes in smart contracts.
//!
//! ## Detectors Included (Phase 28)
//!
//! 1. **Private Variable Exposure** (HIGH)
//!    - Sensitive data in "private" variables
//!    - Passwords, keys in storage
//!
//! 2. **Storage Slot Predictability** (MEDIUM)
//!    - Predictable storage for secrets
//!    - Seed visibility
//!
//! 3. **Missing Commit-Reveal** (MEDIUM)
//!    - Auction/bidding without commitment
//!    - Front-running risks
//!
//! 4. **Plaintext Secret Storage** (HIGH)
//!    - Unhashed secrets on-chain
//!    - Credential exposure

pub mod missing_commit_reveal;
pub mod plaintext_secret_storage;
pub mod private_variable_exposure;
pub mod storage_slot_predictability;

pub use missing_commit_reveal::MissingCommitRevealDetector;
pub use plaintext_secret_storage::PlaintextSecretStorageDetector;
pub use private_variable_exposure::PrivateVariableExposureDetector;
pub use storage_slot_predictability::StorageSlotPredictabilityDetector;
