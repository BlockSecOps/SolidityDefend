// ERC-7683 Cross-Chain Intent Security Detectors
//
// This module contains comprehensive security detectors for ERC-7683 intent-based
// cross-chain systems. These detectors address vulnerabilities in protocols like
// Uniswap X, 1inch Fusion+, and CoW Swap.
//
// Version: 0.9.0
// Date: October 2025

pub mod classification;
pub mod signature_replay;
pub mod solver_manipulation;
pub mod nonce_management;
pub mod settlement_validation;

pub use classification::*;
pub use signature_replay::IntentSignatureReplayDetector;
pub use solver_manipulation::IntentSolverManipulationDetector;
pub use nonce_management::IntentNonceManagementDetector;
pub use settlement_validation::IntentSettlementValidationDetector;
