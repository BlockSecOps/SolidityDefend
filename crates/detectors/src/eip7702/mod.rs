//! EIP-7702 Account Delegation Security Detectors
//!
//! This module provides comprehensive security analysis for EIP-7702 Set EOA account code,
//! detecting vulnerabilities responsible for $12M+ in 2025 phishing attacks.
//!
//! ## Detectors Included (Phase 25)
//!
//! 1. **EIP-7702 Initialization Front-Running** (CRITICAL)
//!    - Front-running initialization attacks ($1.54M August 2025)
//!    - Account takeover via unprotected setCode
//!    - Delegation hijacking
//!
//! 2. **EIP-7702 Delegate Access Control** (CRITICAL)
//!    - Missing authorization in delegate contracts
//!    - Arbitrary execution risks
//!    - Token drainage patterns
//!
//! 3. **EIP-7702 Storage Collision** (HIGH)
//!    - Storage layout mismatches between EOA and delegate
//!    - State corruption risks
//!    - Data integrity violations
//!
//! 4. **EIP-7702 tx.origin Bypass** (HIGH)
//!    - tx.origin == msg.sender assumption bypass
//!    - Breaking authentication patterns
//!    - Legacy contract incompatibility
//!
//! 5. **EIP-7702 Sweeper Detection** (CRITICAL)
//!    - Malicious sweeper contract patterns
//!    - 97% of 2025 delegations were malicious sweepers
//!    - Automatic fund drainage signatures
//!
//! 6. **EIP-7702 Batch Phishing** (HIGH)
//!    - Batch execution phishing attacks
//!    - Multi-asset drainage
//!    - UI misrepresentation
//!
//! ## Background
//!
//! EIP-7702 introduces EOA code delegation (Pectra upgrade):
//! - EOAs can temporarily set code via authorization list
//! - Enables account abstraction without contract wallets
//! - Creates new phishing attack surface
//!
//! ## Real-World Impact (2025)
//!
//! **$12M+ in phishing losses:**
//! - August 2025: $1.54M single transaction
//! - 15,000+ wallets drained
//! - 90% malicious delegation rate (Wintermute analysis)
//! - 97% of delegations were sweeper contracts
//!
//! **Attack Pattern:**
//! 1. Phishing site prompts "upgrade" transaction
//! 2. User signs EIP-7702 authorization (looks like normal tx)
//! 3. Authorization delegates to malicious contract
//! 4. Malicious contract drains all assets
//! 5. Difficult to detect without security tools
//!
//! ## References
//!
//! - EIP-7702: https://eips.ethereum.org/EIPS/eip-7702
//! - Wintermute: 90% malicious delegation analysis (2025)
//! - Nethermind: EIP-7702 Attack Surfaces
//! - Fireblocks: Security First Approach to EIP-7702

pub mod init_frontrun;
pub mod delegate_access_control;
pub mod storage_collision;
pub mod txorigin_bypass;
pub mod sweeper_detection;
pub mod batch_phishing;

// Re-export detectors
pub use init_frontrun::EIP7702InitFrontrunDetector;
pub use delegate_access_control::EIP7702DelegateAccessControlDetector;
pub use storage_collision::EIP7702StorageCollisionDetector;
pub use txorigin_bypass::EIP7702TxOriginBypassDetector;
pub use sweeper_detection::EIP7702SweeperDetectionDetector;
pub use batch_phishing::EIP7702BatchPhishingDetector;

/// Helper function to detect if contract might be EIP-7702 delegate
pub fn is_eip7702_delegate(ctx: &crate::types::AnalysisContext) -> bool {
    let source = &ctx.source_code.to_lowercase();

    // Check for EIP-7702 specific patterns
    source.contains("delegatecall") ||
    source.contains("execute") && (source.contains("call") || source.contains("batch")) ||
    source.contains("eip7702") ||
    source.contains("setcode") ||
    source.contains("authorization")
}

/// Helper to detect sweeper patterns (drain all assets)
pub fn has_sweeper_pattern(ctx: &crate::types::AnalysisContext) -> bool {
    let source = &ctx.source_code.to_lowercase();

    let has_transfer_all = source.contains("transfer") &&
        (source.contains("balance") || source.contains("this").to_string().contains("balance"));

    let has_batch_transfer = source.contains("batch") || source.contains("multi");

    let has_token_sweep = source.contains("token") &&
        (source.contains("transfer") || source.contains("approve"));

    has_transfer_all || (has_batch_transfer && has_token_sweep)
}
