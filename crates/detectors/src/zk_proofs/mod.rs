//! Zero-Knowledge Proofs Security Detectors
//!
//! This module provides security analysis for zero-knowledge proof systems
//! used in zkSync, Scroll, Polygon zkEVM, and other ZK rollups.
//!
//! ## Detectors (4 total)
//!
//! 1. **zk-proof-malleability** (CRITICAL)
//!    - Proof malleability attacks
//!    - Real-world: Proof forgery vulnerabilities
//!
//! 2. **zk-trusted-setup-bypass** (HIGH)
//!    - Compromised trusted setup detection
//!    - Real-world: Setup ceremony validation
//!
//! 3. **zk-circuit-under-constrained** (CRITICAL)
//!    - Under-constrained circuits
//!    - Real-world: Missing constraint validation
//!
//! 4. **zk-recursive-proof-validation** (HIGH)
//!    - Recursive proof validation issues
//!    - Real-world: Proof aggregation vulnerabilities

pub mod proof_malleability;
pub mod trusted_setup_bypass;
pub mod circuit_constraints;
pub mod recursive_proof;

// Re-export detectors
pub use proof_malleability::ZKProofMalleabilityDetector;
pub use trusted_setup_bypass::ZKTrustedSetupBypassDetector;
pub use circuit_constraints::ZKCircuitUnderConstrainedDetector;
pub use recursive_proof::ZKRecursiveProofValidationDetector;
