/// Shared utility functions for context detection and pattern recognition

use crate::types::AnalysisContext;

/// Detects if the contract is an ERC-4626 compliant vault
///
/// ERC-4626 vaults have specific characteristics:
/// - Mint/burn shares (not tokens) - shares don't need max supply caps
/// - Must have deposit/withdraw/redeem functions
/// - Transfers underlying assets via external calls (normal behavior)
pub fn is_erc4626_vault(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();

    // Check for ERC-4626 interface functions
    let has_deposit = source.contains("function deposit(");
    let has_withdraw = source.contains("function withdraw(");
    let has_redeem = source.contains("function redeem(");
    let has_total_assets = source.contains("function totalAssets(")
        || source.contains("function totalAssets() ");

    // Check for share token characteristics
    let has_shares = source.contains("shares") || source.contains("_shares");
    let has_assets = source.contains("asset") || source.contains("_asset");

    // Must have at least 3 of the 4 core functions + share/asset mentions
    let function_count = [has_deposit, has_withdraw, has_redeem, has_total_assets]
        .iter()
        .filter(|&&x| x)
        .count();

    function_count >= 3 && has_shares && has_assets
}

/// Detects if the contract is an ERC-3156 flash loan provider
///
/// ERC-3156 flash loans have specific characteristics:
/// - flashLoan() function for borrowing
/// - onFlashLoan() callback for repayment validation
/// - Balance-based repayment verification
/// - Flash loan operations manipulate liquidity/state by design
pub fn is_erc3156_flash_loan(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();

    // Check for ERC-3156 flash loan functions
    let has_flash_loan = source.contains("function flashLoan(");
    let has_on_flash_loan = source.contains("onFlashLoan")
        || source.contains("IFlashBorrower")
        || source.contains("IERC3156FlashBorrower");

    // Check for ERC-3156 specific patterns
    let has_erc3156_marker = source.contains("ERC3156")
        || source.contains("ERC-3156")
        || source.contains("flashFee")
        || source.contains("maxFlashLoan");

    // Check for flash loan callback validation pattern
    let has_callback_validation = source.contains("ERC3156FlashBorrower.onFlashLoan")
        || (source.contains("keccak256") && source.contains("onFlashLoan"));

    // Check for balance-based repayment validation (common pattern)
    let has_balance_check = (source.contains("balanceBefore") && source.contains("balanceAfter"))
        || source.contains("repaid")
        || (source.contains("balance") && source.contains("flashLoan"));

    // Must have flashLoan function + at least 2 other indicators
    let indicator_count = [
        has_on_flash_loan,
        has_erc3156_marker,
        has_callback_validation,
        has_balance_check,
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    has_flash_loan && indicator_count >= 2
}

/// Detects if the contract uses OpenZeppelin libraries
///
/// OpenZeppelin contracts are audited and generally safe
pub fn uses_openzeppelin(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();

    source.contains("@openzeppelin")
        || source.contains("import \"@openzeppelin")
        || source.contains("Ownable")
        || source.contains("AccessControl")
        || source.contains("ReentrancyGuard")
}

/// Detects if the function or contract has reentrancy guards
pub fn has_reentrancy_guard(function_source: &str, contract_source: &str) -> bool {
    function_source.contains("nonReentrant")
        || function_source.contains("ReentrancyGuard")
        || contract_source.contains("ReentrancyGuard")
        || function_source.contains("_reentrancyGuard")
}

/// Detects if the contract uses SafeERC20 for token transfers
pub fn uses_safe_erc20(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();

    source.contains("SafeERC20")
        || source.contains("safeTransfer")
        || source.contains("safeTransferFrom")
}

/// Detects if an address parameter has zero-address validation
pub fn has_zero_address_check(function_source: &str, param_name: &str) -> bool {
    // Check for explicit zero address validation
    let patterns = [
        format!("require({} != address(0)", param_name),
        format!("require(address(0) != {}", param_name),
        format!("if ({} == address(0))", param_name),
        format!("if (address(0) == {})", param_name),
        format!("assert({} != address(0)", param_name),
    ];

    patterns.iter().any(|pattern| function_source.contains(pattern))
}

/// Detects if the contract implements a pull-over-push pattern
///
/// Pull-over-push is a safe pattern where users must claim funds
/// rather than having funds pushed to them
pub fn has_pull_pattern(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();

    (source.contains("claim") || source.contains("Claim"))
        && (source.contains("pending") || source.contains("claimable") || source.contains("owed"))
}

/// Detects if the function has actual delay mechanisms (not just asset transfers)
pub fn has_actual_delay_mechanism(function_source: &str) -> bool {
    // True delay indicators (time-based locks, not just external calls)
    let delay_indicators = [
        "delay",
        "lock",
        "lockTime",
        "unlockTime",
        "cooldown",
        "vestingPeriod",
        "block.timestamp +",
        "block.number +",
    ];

    delay_indicators.iter().any(|indicator| function_source.contains(indicator))
}

/// Detects if the contract is an ERC-4337 Account Abstraction contract
///
/// ERC-4337 contracts (Paymasters, Smart Accounts) have specific characteristics:
/// - validatePaymasterUserOp() or validateUserOp() for validation
/// - Session key management (temporary permissions)
/// - Nonce management for replay protection
/// - Social recovery patterns with guardians
/// - Functions use msg.sender checks instead of access modifiers (pattern is intentional)
pub fn is_erc4337_paymaster(ctx: &AnalysisContext) -> bool {
    let source = ctx.source_code.as_str();

    // Check for ERC-4337 validation functions
    let has_paymaster_validation = source.contains("function validatePaymasterUserOp(")
        || source.contains("function validateUserOp(");

    // Check for UserOperation type usage
    let has_user_op = source.contains("UserOp")
        || source.contains("userOp")
        || source.contains("UserOperation");

    // Check for ERC-4337 specific markers
    let has_erc4337_marker = source.contains("ERC4337")
        || source.contains("ERC-4337")
        || source.contains("IPaymaster")
        || source.contains("EntryPoint");

    // Check for session key patterns
    let has_session_keys = (source.contains("sessionKey") || source.contains("SessionKey"))
        && (source.contains("addSessionKey") || source.contains("revokeSessionKey"));

    // Check for nonce management (ERC-4337 specific patterns)
    let has_nonce_management = (source.contains("function getNonce(")
        || source.contains("function incrementNonce("))
        && (source.contains("nonces") || source.contains("nonceSequenceNumber"));

    // Check for social recovery patterns
    let has_social_recovery = source.contains("guardian")
        && (source.contains("initiateRecovery")
            || source.contains("approveRecovery")
            || source.contains("completeRecovery"));

    // Must have validation function + at least 2 other indicators
    let indicator_count = [
        has_user_op,
        has_erc4337_marker,
        has_session_keys,
        has_nonce_management,
        has_social_recovery,
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    has_paymaster_validation && indicator_count >= 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_erc4626_detection() {
        // This would need a proper AnalysisContext mock
        // Placeholder for future tests
    }
}
