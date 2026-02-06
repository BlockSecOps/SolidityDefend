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
    let source = &ctx.source_code;
    let source_lower = source.to_lowercase();

    // Strong signal: explicit ERC-7821 interface reference
    if source.contains("IERC7821")
        || source.contains("ERC7821")
        || source_lower.contains("erc-7821")
        || source_lower.contains("eip-7821")
    {
        return true;
    }

    // Strong signal: ERC-7821 specific function signature patterns
    // ERC-7821 defines execute(bytes32 mode, bytes calldata executionData)
    if source.contains("execute(bytes32") && source_lower.contains("executiondata") {
        return true;
    }

    // Strong signal: opData pattern specific to ERC-7821
    if source_lower.contains("opdata") && source_lower.contains("executebatch") {
        return true;
    }

    // Moderate signal: executeBatch with call/delegatecall patterns (batch executor)
    // but NOT plain delegatecall wrappers. Require executeBatch as an actual function name
    // combined with array-based execution (multiple targets/calls)
    if source_lower.contains("executebatch") {
        // Must also have batch execution patterns (arrays of targets or calls)
        let has_batch_pattern = source_lower.contains("targets.length")
            || source_lower.contains("calls.length")
            || source_lower.contains("operations.length")
            || source_lower.contains("executions.length")
            || (source.contains("[]") && source_lower.contains("executebatch"));

        if has_batch_pattern {
            return true;
        }
    }

    false
}
