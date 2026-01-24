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

pub mod batch_phishing;
pub mod delegate_access_control;
pub mod init_frontrun;
pub mod storage_collision;
pub mod sweeper_detection;
pub mod txorigin_bypass;

// Re-export detectors
pub use batch_phishing::EIP7702BatchPhishingDetector;
pub use delegate_access_control::EIP7702DelegateAccessControlDetector;
pub use init_frontrun::EIP7702InitFrontrunDetector;
pub use storage_collision::EIP7702StorageCollisionDetector;
pub use sweeper_detection::EIP7702SweeperDetectionDetector;
pub use txorigin_bypass::EIP7702TxOriginBypassDetector;

/// Helper function to detect if contract might be EIP-7702 delegate
pub fn is_eip7702_delegate(ctx: &crate::types::AnalysisContext) -> bool {
    let source = &ctx.source_code.to_lowercase();
    let file_path = ctx.file_path.to_lowercase();

    // Phase 15 FP Reduction: Skip known pre-7702 contracts
    // Safe Smart Account predates EIP-7702 (Pectra upgrade)
    let is_safe = file_path.contains("safe-smart-account")
        || file_path.contains("safe-contracts")
        || file_path.contains("/safe/")
        || source.contains("@author stefan george")
        || source.contains("@author richard meissner")
        || source.contains("gnosis safe");

    // OpenZeppelin contracts predate EIP-7702
    let is_openzeppelin = file_path.contains("openzeppelin")
        || source.contains("@openzeppelin")
        || source.contains("openzeppelin-contracts");

    // Aave contracts predate EIP-7702
    let is_aave = source.contains("@author aave")
        || file_path.contains("aave-v3")
        || file_path.contains("aave-v2");

    // Solmate is a library that predates EIP-7702
    let is_solmate = file_path.contains("/solmate/")
        || source.contains("solmate");

    // Skip all pre-7702 known contracts
    if is_safe || is_openzeppelin || is_aave || is_solmate {
        return false;
    }

    // Require explicit EIP-7702 references - not just delegatecall
    // EIP-7702 is about EOA code delegation (Pectra upgrade 2025+)
    let has_explicit_7702 = source.contains("eip7702")
        || source.contains("eip-7702")
        || source.contains("7702")
        || source.contains("setcode")
        || source.contains("eoa delegation")
        || source.contains("eoa code");

    // If explicit 7702 reference, definitely a delegate
    if has_explicit_7702 {
        return true;
    }

    // For contracts without explicit 7702 reference, require BOTH:
    // 1. delegatecall pattern AND
    // 2. Account abstraction / EOA pattern (not just regular proxy)
    let has_delegatecall = source.contains("delegatecall");
    let has_aa_pattern = source.contains("account abstraction")
        || source.contains("smart account")
        || source.contains("eoa")
        || (source.contains("execute") && source.contains("authorization"));

    has_delegatecall && has_aa_pattern
}

/// Helper to detect sweeper patterns (drain all assets)
pub fn has_sweeper_pattern(ctx: &crate::types::AnalysisContext) -> bool {
    let source = &ctx.source_code.to_lowercase();

    let has_transfer_all = source.contains("transfer")
        && (source.contains("balance") || source.contains("this").to_string().contains("balance"));

    let has_batch_transfer = source.contains("batch") || source.contains("multi");

    let has_token_sweep =
        source.contains("token") && (source.contains("transfer") || source.contains("approve"));

    has_transfer_all || (has_batch_transfer && has_token_sweep)
}
