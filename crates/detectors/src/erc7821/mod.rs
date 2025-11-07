//! ERC-7821 Batch Executor Security Detectors (Phase 26)
//!
//! This module provides comprehensive security analysis for ERC-7821 Minimal Batch Executor
//! implementations, detecting vulnerabilities in batch execution patterns.
//!
//! ## Detectors Included (Phase 26)
//!
//! 1. **ERC-7821 Batch Authorization** (HIGH)
//!    - Missing batch executor authorization
//!    - Unprotected execution paths
//!
//! 2. **ERC-7821 Token Approval** (CRITICAL)
//!    - Token approval decoupling risks
//!    - Permit2 integration requirements
//!
//! 3. **ERC-7821 Replay Protection** (HIGH)
//!    - Missing nonce/replay protection
//!    - Order replay attacks
//!
//! 4. **ERC-7821 msg.sender Validation** (MEDIUM)
//!    - msg.sender authentication bypass
//!    - Settler context issues
//!
//! ## Background
//!
//! ERC-7821 defines a minimal batch executor interface for executing multiple operations
//! atomically. Security is critical as batch executors handle token approvals and transfers.
//!
//! ## References
//!
//! - ERC-7821: https://eips.ethereum.org/EIPS/eip-7821
//! - Permit2 documentation

pub mod batch_authorization;
pub mod msg_sender_validation;
pub mod replay_protection;
pub mod token_approval;

// Re-export detectors
pub use batch_authorization::ERC7821BatchAuthorizationDetector;
pub use msg_sender_validation::ERC7821MsgSenderValidationDetector;
pub use replay_protection::ERC7821ReplayProtectionDetector;
pub use token_approval::ERC7821TokenApprovalDetector;

/// Helper function to detect if contract implements ERC-7821
pub fn is_erc7821_executor(ctx: &crate::types::AnalysisContext) -> bool {
    let source = &ctx.source_code.to_lowercase();

    // Check for ERC-7821 specific patterns
    source.contains("execute") && source.contains("batch")
        || source.contains("ierc7821")
        || source.contains("executebatch")
}
