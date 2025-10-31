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

pub mod reentrancy;
pub mod composability;
pub mod state_leak;
pub mod misuse;
pub mod guard;

// Re-export detectors
pub use reentrancy::TransientStorageReentrancyDetector;
pub use composability::TransientStorageComposabilityDetector;
pub use state_leak::TransientStorageStateLeakDetector;
pub use misuse::TransientStorageMisuseDetector;
pub use guard::TransientReentrancyGuardDetector;

/// Helper function to detect if contract uses transient storage
pub fn uses_transient_storage(ctx: &crate::types::AnalysisContext) -> bool {
    let source = &ctx.source_code.to_lowercase();

    // Check for explicit transient keyword (Solidity 0.8.24+)
    if source.contains("transient") {
        return true;
    }

    // Check for inline assembly TSTORE/TLOAD
    if source.contains("assembly") && (source.contains("tstore") || source.contains("tload")) {
        return true;
    }

    false
}

/// Helper to detect transient storage declarations
pub fn has_transient_storage_declarations(ctx: &crate::types::AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Match patterns like:
    // - uint256 transient counter;
    // - mapping(address => uint256) transient balances;
    source.contains("transient") &&
    (source.contains("uint") || source.contains("mapping") || source.contains("struct"))
}
