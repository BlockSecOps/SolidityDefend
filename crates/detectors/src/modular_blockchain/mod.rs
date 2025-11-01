//! Modular Blockchain Security Detectors
//!
//! This module provides security analysis for modular blockchain architectures
//! including Celestia, Avail, EigenDA, and cross-rollup interactions.
//!
//! ## Detectors (5 total)
//!
//! 1. **celestia-data-availability** (HIGH)
//!    - Data availability layer issues
//!    - Real-world: Celestia DA validation
//!
//! 2. **cross-rollup-atomicity** (CRITICAL)
//!    - Cross-rollup atomic operations
//!    - Real-world: Multi-rollup transaction coordination
//!
//! 3. **optimistic-fraud-proof-timing** (HIGH)
//!    - Fraud proof timing issues
//!    - Real-world: Challenge period manipulation
//!
//! 4. **cross-chain-message-ordering** (HIGH)
//!    - Message ordering across chains
//!    - Real-world: Sequencer/relayer manipulation
//!
//! 5. **sovereign-rollup-validation** (MEDIUM)
//!    - Sovereign rollup security
//!    - Real-world: State transition validation

pub mod data_availability;
pub mod cross_rollup_atomicity;
pub mod fraud_proof_timing;
pub mod message_ordering;
pub mod sovereign_rollup;

// Re-export detectors
pub use data_availability::CelestiaDataAvailabilityDetector;
pub use cross_rollup_atomicity::CrossRollupAtomicityDetector;
pub use fraud_proof_timing::OptimisticFraudProofTimingDetector;
pub use message_ordering::CrossChainMessageOrderingDetector;
pub use sovereign_rollup::SovereignRollupValidationDetector;
