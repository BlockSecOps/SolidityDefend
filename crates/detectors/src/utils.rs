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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_erc4626_detection() {
        // This would need a proper AnalysisContext mock
        // Placeholder for future tests
    }
}
