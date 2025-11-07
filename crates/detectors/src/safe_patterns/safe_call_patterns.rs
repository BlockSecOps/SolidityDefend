use crate::types::AnalysisContext;

/// Check if a function is a safe view/pure function (read-only, no circular risk)
pub fn is_view_or_pure_function(function: &ast::Function<'_>) -> bool {
    function.mutability == ast::StateMutability::View
        || function.mutability == ast::StateMutability::Pure
}

/// Check if function makes safe ERC20 token calls (standard transfers/approvals)
pub fn makes_safe_erc20_calls(func_source: &str, ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Check if this uses standard ERC20 patterns
    let has_erc20 = source.contains("ERC20")
        || source.contains("IERC20")
        || source.contains("// ERC-20")
        || source.contains("// ERC20");

    if !has_erc20 {
        return false;
    }

    // Safe ERC20 calls that don't create circular dependencies
    let safe_calls = [
        ".transfer(",
        ".transferFrom(",
        ".approve(",
        ".balanceOf(",
        ".allowance(",
        ".totalSupply(",
    ];

    // Check if function only makes safe ERC20 calls
    let only_safe_calls = safe_calls.iter().any(|&call| func_source.contains(call));

    // Not safe if it has callbacks or hooks (case-insensitive check)
    let func_lower = func_source.to_lowercase();
    let has_callbacks = func_lower.contains("callback")
        || func_lower.contains("ontransfer")
        || func_lower.contains("beforetransfer");

    only_safe_calls && !has_callbacks
}

/// Check if function makes safe oracle calls (price feeds, read-only data)
pub fn makes_safe_oracle_calls(func_source: &str) -> bool {
    // Oracle patterns (read-only, no circular risk)
    let oracle_patterns = [
        ".getPrice(",
        ".latestAnswer(",
        ".latestRoundData(",
        ".decimals(",
        ".description(",
        "oracle.",
        "priceFeed.",
        "AggregatorV3Interface",
    ];

    oracle_patterns
        .iter()
        .any(|&pattern| func_source.contains(pattern))
}

/// Check if function has reentrancy protection (source-based check)
pub fn has_reentrancy_protection(func_source: &str) -> bool {
    func_source.contains("nonReentrant")
        || func_source.contains("ReentrancyGuard")
        || func_source.contains("locked")
        || func_source.contains("require(!_locked")
        || func_source.contains("_status")
}

/// Check if function has reentrancy protection via modifiers (AST-based check)
pub fn has_reentrancy_modifier(function: &ast::Function<'_>) -> bool {
    function.modifiers.iter().any(|m| {
        let name = m.name.name.to_lowercase();
        name.contains("nonreentrant") || name.contains("locked") || name.contains("guard")
    })
}

/// Check if function has access control modifier (limits who can call it)
pub fn has_access_control_modifier(function: &ast::Function<'_>) -> bool {
    function.modifiers.iter().any(|m| {
        let name = m.name.name.to_lowercase();
        name.contains("only")          // onlyOwner, onlyAdmin, etc.
            || name.contains("authorized")
            || name.contains("restricted")
            || name.contains("admin")
    })
}

/// Check if function has depth/recursion limits
pub fn has_depth_limit(func_source: &str) -> bool {
    (func_source.contains("depth")
        || func_source.contains("level")
        || func_source.contains("count"))
        && (func_source.contains("require(") || func_source.contains("if ("))
}

/// Check if function has cycle detection (visited tracking)
pub fn has_cycle_detection(func_source: &str) -> bool {
    (func_source.contains("visited")
        || func_source.contains("checked")
        || func_source.contains("seen"))
        && func_source.contains("[")
}

/// Check if function is a standard ERC721 callback (safe pattern)
pub fn is_safe_erc721_callback(func_source: &str, function_name: &str) -> bool {
    let erc721_callbacks = [
        "onERC721Received",
        "onERC1155Received",
        "onERC1155BatchReceived",
        "tokensReceived", // ERC777
    ];

    erc721_callbacks
        .iter()
        .any(|&callback| function_name.contains(callback))
        || (func_source.contains("ERC721") && func_source.contains("Received"))
}

/// Check if function makes only view/pure external calls
pub fn makes_only_view_calls(func_source: &str) -> bool {
    // Check for explicit view/pure modifiers or common view functions
    let view_patterns = [
        ".view",
        "view returns",
        "pure returns",
        ".balanceOf(",
        ".totalSupply(",
        ".decimals(",
        ".symbol(",
        ".name(",
        ".getPrice(",
        ".allowance(",
    ];

    let has_view_patterns = view_patterns
        .iter()
        .any(|&pattern| func_source.contains(pattern));

    // Check for state-changing calls
    let has_state_changes = func_source.contains(".call{")
        || func_source.contains("delegatecall")
        || func_source.contains("transfer(")  && !func_source.contains("transferFrom") // transfer ETH, not ERC20
        || func_source.contains("send(");

    has_view_patterns && !has_state_changes
}

/// Check if calls are protected by try-catch (prevents circular failure propagation)
pub fn has_try_catch_protection(func_source: &str) -> bool {
    func_source.contains("try ") && func_source.contains("catch")
}

/// Check if function is part of a standard callback pattern (EIP-777, EIP-1363, etc.)
pub fn is_standard_callback_pattern(func_source: &str, function_name: &str) -> bool {
    // Standard token callback patterns that are designed to be safe
    let safe_callbacks = [
        "tokensReceived",     // ERC777
        "tokensToSend",       // ERC777
        "onTransferReceived", // ERC1363
        "onApprovalReceived", // ERC1363
        "onERC721Received",   // ERC721
        "onERC1155Received",  // ERC1155
    ];

    let is_callback = safe_callbacks.contains(&function_name);

    // If it's a standard callback, check if it's properly implemented
    if is_callback {
        // Standard callbacks should return magic value
        return func_source.contains("return ") || func_source.contains("returns");
    }

    false
}

/// Check if function is a getter/view function (no circular risk)
pub fn is_getter_function(function_name: &str, func_source: &str) -> bool {
    // Common getter patterns
    let getter_prefixes = ["get", "is", "has", "can", "should"];

    let name_lower = function_name.to_lowercase();
    let is_getter_name = getter_prefixes
        .iter()
        .any(|&prefix| name_lower.starts_with(prefix));

    // Getters typically have no state changes
    let no_state_changes = !func_source.contains(" = ")
        && !func_source.contains("+=")
        && !func_source.contains("-=")
        && !func_source.contains("delete ");

    is_getter_name && no_state_changes
}

/// Comprehensive check if function is safe from circular dependencies
pub fn is_safe_from_circular_deps(
    function: &ast::Function<'_>,
    func_source: &str,
    ctx: &AnalysisContext,
) -> bool {
    // Safe if view/pure (read-only)
    if is_view_or_pure_function(function) {
        return true;
    }

    // Safe if only makes ERC20 calls
    if makes_safe_erc20_calls(func_source, ctx) {
        return true;
    }

    // Safe if only reads from oracles
    if makes_safe_oracle_calls(func_source) && makes_only_view_calls(func_source) {
        return true;
    }

    // Safe if has reentrancy protection (check both source and modifiers)
    if has_reentrancy_protection(func_source) || has_reentrancy_modifier(function) {
        return true;
    }

    // Safe if has access control (only authorized callers, limits circular attack surface)
    if has_access_control_modifier(function) {
        return true;
    }

    // Safe if has depth limits
    if has_depth_limit(func_source) {
        return true;
    }

    // Safe if has cycle detection
    if has_cycle_detection(func_source) {
        return true;
    }

    // Safe if standard callback with proper return
    if is_standard_callback_pattern(func_source, function.name.name) {
        return true;
    }

    // Safe if getter function
    if is_getter_function(function.name.name, func_source) {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::test_utils::create_test_context;

    #[test]
    fn test_safe_erc20_calls() {
        let ctx_source = "contract Token is ERC20 {}";
        let ctx = create_mock_context(ctx_source);

        let safe_func = "token.transfer(recipient, amount);";
        assert!(makes_safe_erc20_calls(safe_func, &ctx));

        let unsafe_func = "token.transfer(recipient, amount); someCallback();";
        assert!(!makes_safe_erc20_calls(unsafe_func, &ctx));
    }

    #[test]
    fn test_safe_oracle_calls() {
        let oracle_func = "uint256 price = oracle.getPrice();";
        assert!(makes_safe_oracle_calls(oracle_func));

        let non_oracle = "someContract.doSomething();";
        assert!(!makes_safe_oracle_calls(non_oracle));
    }

    #[test]
    fn test_reentrancy_protection() {
        let protected = "function withdraw() external nonReentrant { }";
        assert!(has_reentrancy_protection(protected));

        let unprotected = "function withdraw() external { }";
        assert!(!has_reentrancy_protection(unprotected));
    }

    #[test]
    fn test_depth_limit() {
        let with_limit = "require(depth < MAX_DEPTH);";
        assert!(has_depth_limit(with_limit));

        let without_limit = "someCall();";
        assert!(!has_depth_limit(without_limit));
    }

    #[test]
    fn test_cycle_detection() {
        let with_detection = "require(!visited[address]); visited[address] = true;";
        assert!(has_cycle_detection(with_detection));

        let without_detection = "someCall();";
        assert!(!has_cycle_detection(without_detection));
    }

    fn create_mock_context(source: &str) -> AnalysisContext<'static> {
        create_test_context(source)
    }
}
