//! EIP-1153 Transient Storage Security Detectors
//!
//! This module provides comprehensive security analysis for EIP-1153 transient storage usage,
//! detecting new attack vectors and vulnerabilities introduced by transient storage opcodes
//! (TSTORE/TLOAD) in Solidity 0.8.24+.
//!
//! ## Detectors Included (Phase 24)
//!
//! 1. **Transient Storage Reentrancy** (CRITICAL)
//!    - Low-gas reentrancy via TSTORE/TLOAD
//!    - Breaks transfer()/send() 2300 gas assumption
//!    - ChainSecurity research validation
//!
//! 2. **Transient Storage Composability** (HIGH)
//!    - Multi-call transaction state issues
//!    - Missing cleanup between calls
//!    - Atomic transaction group failures
//!
//! 3. **Transient Storage State Leak** (MEDIUM)
//!    - Intentional skip cleanup blocking interactions
//!    - Gas optimization misuse
//!    - Denial of service via state poisoning
//!
//! 4. **Transient Storage Misuse** (MEDIUM)
//!    - Persistent data in transient storage
//!    - Wrong storage type for data lifetime
//!    - Loss of critical state across transactions
//!
//! 5. **Transient Reentrancy Guard** (MEDIUM)
//!    - Transient guards with low-gas calls
//!    - New attack vectors bypassing traditional guards
//!    - Read-only reentrancy with transient state
//!
//! ## Background
//!
//! EIP-1153 introduces transient storage opcodes (TSTORE/TLOAD) in Solidity 0.8.24+:
//! - Storage cleared at end of transaction
//! - Much cheaper than SSTORE/SLOAD (100 gas vs 2900+ gas)
//! - Breaks decade-old security assumptions
//!
//! ## Key Security Implications
//!
//! **Breaking Changes:**
//! - transfer() and send() no longer safe against reentrancy
//! - 2300 gas stipend can now modify state via TSTORE
//! - Traditional reentrancy guards may be bypassed
//!
//! **New Attack Surface:**
//! - Low-gas reentrancy attacks (100 gas per TSTORE)
//! - State pollution across multi-call transactions
//! - Read-only reentrancy with transient state
//!
//! ## Real-World Research References
//!
//! - **ChainSecurity (2024)**: TSTORE Low Gas Reentrancy research
//! - **EIP-1153**: https://eips.ethereum.org/EIPS/eip-1153
//! - **Solidity 0.8.24+**: Native transient storage support

pub mod composability;
pub mod guard;
pub mod misuse;
pub mod reentrancy;
pub mod state_leak;

// Re-export detectors
pub use composability::TransientStorageComposabilityDetector;
pub use guard::TransientReentrancyGuardDetector;
pub use misuse::TransientStorageMisuseDetector;
pub use reentrancy::TransientStorageReentrancyDetector;
pub use state_leak::TransientStorageStateLeakDetector;

/// Helper function to detect if contract uses transient storage.
///
/// FP Reduction: Only match actual transient storage usage in code lines,
/// not just mentions in comments/docstrings. Many non-transient contracts
/// have comments like "// Simulates transient storage" or "// See EIP-1153".
pub fn uses_transient_storage(ctx: &crate::types::AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Check for inline assembly TSTORE/TLOAD (definitive)
    let lower = source.to_lowercase();
    if lower.contains("assembly") && (lower.contains("tstore") || lower.contains("tload")) {
        return true;
    }

    // Check for "transient" keyword in CODE lines (not comments)
    for line in source.lines() {
        let trimmed = line.trim();
        // Skip comment-only lines
        if trimmed.starts_with("//")
            || trimmed.starts_with("*")
            || trimmed.starts_with("/*")
            || trimmed.starts_with("/**")
        {
            continue;
        }
        let line_lower = trimmed.to_lowercase();
        if line_lower.contains("transient") {
            return true;
        }
    }

    false
}

/// Helper to detect transient storage declarations.
///
/// FP Reduction: Only match actual transient variable declarations in code,
/// not comment mentions.
pub fn has_transient_storage_declarations(ctx: &crate::types::AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Check non-comment lines for transient + type keyword on the same line
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("//")
            || trimmed.starts_with("*")
            || trimmed.starts_with("/*")
            || trimmed.starts_with("/**")
        {
            continue;
        }
        let line_lower = trimmed.to_lowercase();
        // Match: `uint256 transient foo;` or `mapping(...) transient bar;`
        if line_lower.contains("transient")
            && (line_lower.contains("uint")
                || line_lower.contains("mapping")
                || line_lower.contains("struct")
                || line_lower.contains("bool")
                || line_lower.contains("address"))
        {
            return true;
        }
    }

    // Also check for TSTORE/TLOAD in assembly
    let lower = source.to_lowercase();
    lower.contains("assembly") && (lower.contains("tstore") || lower.contains("tload"))
}
