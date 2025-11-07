use crate::types::AnalysisContext;

/// Detect ReentrancyGuard pattern (OpenZeppelin)
///
/// ReentrancyGuard is a modifier that prevents reentrancy attacks by
/// setting a lock during function execution.
///
/// Patterns detected:
/// - `nonReentrant` modifier usage
/// - `ReentrancyGuard` contract inheritance
/// - `_nonReentrantBefore()` / `_nonReentrantAfter()` calls
/// - Custom reentrancy lock patterns
pub fn has_reentrancy_guard(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: nonReentrant modifier
    if source.contains("nonReentrant") {
        return true;
    }

    // Pattern 2: ReentrancyGuard inheritance
    if source.contains("ReentrancyGuard") {
        return true;
    }

    // Pattern 3: OpenZeppelin internal functions
    if source.contains("_nonReentrantBefore") || source.contains("_nonReentrantAfter") {
        return true;
    }

    // Pattern 4: Custom reentrancy lock
    if source.contains("reentrancyLock") || source.contains("_lock") {
        return true;
    }

    // Pattern 5: locked state variable with checks
    if source.contains("locked") && source.contains("require(!locked") {
        return true;
    }

    // Pattern 6: mutex pattern
    if source.contains("mutex") || source.contains("_mutex") {
        return true;
    }

    false
}

/// Detect Checks-Effects-Interactions (CEI) pattern compliance
///
/// CEI pattern requires that:
/// 1. Checks (require statements, conditions) come first
/// 2. Effects (state updates) come second
/// 3. Interactions (external calls) come last
///
/// This is a heuristic check - looks for state updates before external calls.
pub fn follows_cei_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // This is a simplified heuristic check
    // Ideally, we'd parse the AST to verify ordering

    // Look for common patterns that suggest CEI compliance:
    // 1. State updates followed by external calls (good)
    // 2. External calls followed by state updates (bad)

    // Check if the contract has comments about CEI
    if source.contains("Checks-Effects-Interactions")
        || source.contains("CEI pattern")
        || source.contains("follows CEI")
    {
        return true;
    }

    // Check for explicit CEI structure in comments
    if source.contains("// Checks")
        && source.contains("// Effects")
        && source.contains("// Interactions")
    {
        return true;
    }

    // Look for state updates before external calls
    // This is a weak heuristic but can help
    let has_balance_update = source.contains("balanceOf[") || source.contains("balances[");
    let has_external_call = source.contains(".transfer(")
        || source.contains(".transferFrom(")
        || source.contains(".call{");

    if has_balance_update && has_external_call {
        // Try to determine order (very rough heuristic)
        if let Some(balance_pos) = source.find("balanceOf[") {
            if let Some(call_pos) = source.find(".transfer(") {
                // If balance update appears before transfer, likely CEI compliant
                return balance_pos < call_pos;
            }
        }
    }

    false
}

/// Detect standard ERC20 token (no callback hooks)
///
/// Standard ERC20 tokens don't have callback mechanisms, so they're
/// safe from reentrancy through token transfers.
///
/// ERC777 and ERC1363 have callbacks and are risky.
pub fn is_standard_erc20(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Check for ERC777 (has hooks - NOT safe)
    if source.contains("ERC777")
        || source.contains("tokensReceived")
        || source.contains("_callTokensReceived")
    {
        return false;
    }

    // Check for ERC1363 (has hooks - NOT safe)
    if source.contains("ERC1363")
        || source.contains("onTransferReceived")
        || source.contains("_checkOnTransferReceived")
    {
        return false;
    }

    // Check for ERC20 (standard - safe)
    if source.contains("ERC20") || source.contains("IERC20") {
        return true;
    }

    // Check for basic ERC20 functions (likely standard ERC20)
    let has_transfer = source.contains("function transfer(");
    let has_approve = source.contains("function approve(");
    let has_transfer_from = source.contains("function transferFrom(");

    if has_transfer && has_approve && has_transfer_from {
        // Has ERC20 interface, check if it has hook functions
        let has_hooks = source.contains("tokensReceived")
            || source.contains("onTransferReceived")
            || source.contains("_callTokens");

        return !has_hooks;
    }

    false
}

/// Detect read-only reentrancy protection
///
/// Read-only reentrancy is when view functions are called during
/// reentrancy. Some patterns protect against this.
pub fn has_read_only_reentrancy_protection(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Check for explicit read-only reentrancy guards
    if source.contains("readOnlyReentrancyGuard") || source.contains("viewNonReentrant") {
        return true;
    }

    // Check if view functions also have nonReentrant
    if source.contains("view") && source.contains("nonReentrant") {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_context(source: &str) -> AnalysisContext<'static> {
        crate::types::test_utils::create_test_context(source)
    }

    #[test]
    fn test_reentrancy_guard_modifier() {
        let source = r#"
            function deposit() public nonReentrant {
                // ...
            }
        "#;
        let ctx = create_context(source);
        assert!(has_reentrancy_guard(&ctx));
    }

    #[test]
    fn test_reentrancy_guard_inheritance() {
        let source = r#"
            contract Vault is ReentrancyGuard {
                // ...
            }
        "#;
        let ctx = create_context(source);
        assert!(has_reentrancy_guard(&ctx));
    }

    #[test]
    fn test_cei_pattern_comments() {
        let source = r#"
            function withdraw() public {
                // Checks
                require(balances[msg.sender] > 0);

                // Effects
                uint256 amount = balances[msg.sender];
                balances[msg.sender] = 0;

                // Interactions
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success);
            }
        "#;
        let ctx = create_context(source);
        assert!(follows_cei_pattern(&ctx));
    }

    #[test]
    fn test_standard_erc20() {
        let source = r#"
            import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

            contract Token is ERC20 {
                // ...
            }
        "#;
        let ctx = create_context(source);
        assert!(is_standard_erc20(&ctx));
    }

    #[test]
    fn test_erc777_not_safe() {
        let source = r#"
            import "@openzeppelin/contracts/token/ERC777/ERC777.sol";

            contract Token is ERC777 {
                // ...
            }
        "#;
        let ctx = create_context(source);
        assert!(!is_standard_erc20(&ctx));
    }

    #[test]
    fn test_no_reentrancy_protection() {
        let source = r#"
            function withdraw() public {
                uint256 amount = balances[msg.sender];
                (bool success, ) = msg.sender.call{value: amount}("");
                balances[msg.sender] = 0;  // State update after external call!
            }
        "#;
        let ctx = create_context(source);
        assert!(!has_reentrancy_guard(&ctx));
        // CEI not followed (state update after call)
    }
}
