use crate::types::AnalysisContext;

/// Check if function has slippage protection (MEV protection for swaps/trades)
pub fn has_slippage_protection(func_source: &str) -> bool {
    // Common slippage protection parameter names - must be specific to output amounts
    let slippage_params = [
        "minAmountOut",
        "amountOutMin",
        "minOutput",
        "minimumAmount",
        "minReturn",
        "minReceived",
        "minAmountReceived",
        "amountOutMinimum",
        "minTokensOut",
    ];

    // Check for parameter existence
    let has_param = slippage_params
        .iter()
        .any(|&param| func_source.contains(param));

    if has_param {
        return true;
    }

    // Phase 16 FN Recovery: More precise require check for slippage
    // Must be checking OUTPUT amount, not just any amount
    // Pattern: require(amountOut >= minAmount) or require(received >= expected)
    let source_lower = func_source.to_lowercase();
    let has_output_check = func_source.contains("require(")
        && (func_source.contains(">=") || func_source.contains(">"))
        && (source_lower.contains("amountout")
            || source_lower.contains("outputamount")
            || source_lower.contains("received")
            || source_lower.contains("tokensout")
            || (source_lower.contains("out") && source_lower.contains("min")));

    // Also check for slippage tolerance patterns
    let has_slippage_calc = func_source.contains("slippage")
        || func_source.contains("tolerance")
        || (func_source.contains("* 99") || func_source.contains("* 995") || func_source.contains("/ 100"));

    has_output_check || has_slippage_calc
}

/// Check if function has deadline protection (prevents stale transactions)
pub fn has_deadline_protection(func_source: &str) -> bool {
    // Common deadline parameter patterns
    let has_deadline_param = func_source.contains("deadline")
        || func_source.contains("validUntil")
        || func_source.contains("expiry")
        || func_source.contains("expirationTime");

    // Check for timestamp comparison
    let has_timestamp_check = func_source.contains("block.timestamp")
        && (func_source.contains("<=") || func_source.contains("<"))
        && func_source.contains("require");

    has_deadline_param || has_timestamp_check
}

/// Check if function has commit-reveal protection
pub fn has_commit_reveal_protection(func_source: &str) -> bool {
    let has_commit = func_source.contains("commit") || func_source.contains("commitment");

    let has_reveal = func_source.contains("reveal");

    let has_hash = func_source.contains("keccak256")
        || func_source.contains("sha256")
        || func_source.contains("hash");

    // Need at least commit + hash, or reveal
    (has_commit && has_hash) || has_reveal
}

/// Check if function has auction mechanism (prevents priority gas auctions)
pub fn has_auction_mechanism(func_source: &str) -> bool {
    func_source.contains("auction")
        || func_source.contains("bid")
        || func_source.contains("dutch")
        || func_source.contains("vickrey")
        || func_source.contains("batchAuction")
}

/// Check if function has time-weighted mechanism (TWAP, VWAP, etc.)
pub fn has_time_weighted_mechanism(func_source: &str) -> bool {
    func_source.contains("TWAP")
        || func_source.contains("VWAP")
        || func_source.contains("timeWeighted")
        || func_source.contains("timeAverage")
        || func_source.contains("cumulativePrice")
}

/// Check if function uses oracle for pricing (reduces MEV from spot prices)
pub fn uses_oracle_pricing(func_source: &str) -> bool {
    func_source.contains("oracle")
        || func_source.contains("priceFeed")
        || func_source.contains("Chainlink")
        || func_source.contains("AggregatorV3")
        || func_source.contains("latestAnswer")
        || func_source.contains("latestRoundData")
}

/// Check if function has batch processing (reduces MEV surface)
pub fn has_batch_processing(func_source: &str) -> bool {
    func_source.contains("batch")
        || func_source.contains("Batch")
        || (func_source.contains("[]") && func_source.contains("for"))
}

/// Check if function has private transaction support (Flashbots, etc.)
pub fn has_private_transaction_support(func_source: &str) -> bool {
    func_source.contains("flashbots")
        || func_source.contains("Flashbots")
        || func_source.contains("private")
        || func_source.contains("encrypted")
        || func_source.contains("mevProtected")
}

/// Check if function is user-facing (operates on caller's own funds)
/// These are less vulnerable to MEV as users control their own transactions
pub fn is_user_operation(func_source: &str, function_name: &str) -> bool {
    // Check for msg.sender balance operations
    let accesses_own_balance = func_source.contains("balances[msg.sender]")
        || func_source.contains("balanceOf[msg.sender]")
        || func_source.contains("_balances[msg.sender]")
        || func_source.contains("shares[msg.sender]");

    // Check for authorization via msg.sender
    let checks_sender = func_source.contains("require(msg.sender")
        || func_source.contains("msg.sender ==")
        || func_source.contains("== msg.sender");

    // User-facing function names
    let user_function_names = ["deposit", "withdraw", "claim", "stake", "unstake", "redeem"];

    let is_user_function = user_function_names
        .iter()
        .any(|&name| function_name.to_lowercase().contains(name));

    (accesses_own_balance || checks_sender) && is_user_function
}

/// Check if function has access control (limits who can call, reducing MEV surface)
pub fn has_mev_limiting_access_control(function: &ast::Function<'_>) -> bool {
    // Access control modifiers that limit who can call function
    function.modifiers.iter().any(|m| {
        let name = m.name.name.to_lowercase();
        name.contains("only")          // onlyOwner, onlyAdmin
            || name.contains("authorized")
            || name.contains("restricted")
            || name.contains("operator")
            || name.contains("keeper")
    })
}

/// Check if function is a liquidation with protections
pub fn is_protected_liquidation(func_source: &str) -> bool {
    let is_liquidation = func_source.contains("liquidat");

    if !is_liquidation {
        return false;
    }

    // Check for liquidation protections
    let has_health_check = func_source.contains("healthFactor")
        || func_source.contains("health")
        || func_source.contains("collateralizationRatio");

    let has_liquidation_threshold =
        func_source.contains("liquidationThreshold") || func_source.contains("threshold");

    let has_penalty_check = func_source.contains("penalty")
        || func_source.contains("liquidationPenalty")
        || func_source.contains("bonus");

    // Protected if has proper checks
    has_health_check || has_liquidation_threshold || has_penalty_check
}

/// Check if swap function has MEV protections
pub fn is_protected_swap(func_source: &str) -> bool {
    let is_swap = func_source.contains("swap")
        || func_source.contains("exchange")
        || func_source.contains("trade");

    if !is_swap {
        return false;
    }

    // Count protections
    let mut protection_count = 0;

    if has_slippage_protection(func_source) {
        protection_count += 1;
    }

    if has_deadline_protection(func_source) {
        protection_count += 1;
    }

    if uses_oracle_pricing(func_source) || has_time_weighted_mechanism(func_source) {
        protection_count += 1;
    }

    // Protected if has 2+ protections
    protection_count >= 2
}

/// Check if function is an ERC4626 vault function (protected by standard design)
pub fn is_erc4626_vault_function(
    _func_source: &str,
    function_name: &str,
    ctx: &AnalysisContext,
) -> bool {
    let source = &ctx.source_code;

    // Check if this is an ERC4626 vault
    let is_erc4626 = source.contains("ERC4626")
        || source.contains("IERC4626")
        || (source.contains("deposit")
            && source.contains("redeem")
            && source.contains("totalAssets"));

    if !is_erc4626 {
        return false;
    }

    // ERC4626 standard functions (users control their own assets)
    let erc4626_functions = [
        "deposit",
        "mint",
        "withdraw",
        "redeem",
        "previewDeposit",
        "previewMint",
        "previewWithdraw",
        "previewRedeem",
    ];

    let name_lower = function_name.to_lowercase();
    erc4626_functions.iter().any(|&f| name_lower == f)
}

/// Comprehensive check if function has sufficient MEV protection
pub fn has_sufficient_mev_protection(
    function: &ast::Function<'_>,
    func_source: &str,
    ctx: &AnalysisContext,
) -> bool {
    // View/Pure functions don't change state - no MEV risk
    if function.mutability == ast::StateMutability::View
        || function.mutability == ast::StateMutability::Pure
    {
        return true;
    }

    // ERC4626 vault functions are protected by standard design
    if is_erc4626_vault_function(func_source, function.name.name, ctx) {
        return true;
    }

    // Access control is strong MEV protection (limits who can call)
    if has_mev_limiting_access_control(function) {
        return true;
    }

    // User operations are less vulnerable (users control timing)
    if is_user_operation(func_source, function.name.name) {
        return true;
    }

    // Protected swaps with multiple mechanisms
    if is_protected_swap(func_source) {
        return true;
    }

    // Protected liquidations
    if is_protected_liquidation(func_source) {
        return true;
    }

    // Private transaction support
    if has_private_transaction_support(func_source) {
        return true;
    }

    // Commit-reveal scheme
    if has_commit_reveal_protection(func_source) {
        return true;
    }

    // Batch processing with auction
    if has_batch_processing(func_source) && has_auction_mechanism(func_source) {
        return true;
    }

    false
}

/// Calculate number of MEV protections present
pub fn count_mev_protections(function: &ast::Function<'_>, func_source: &str) -> u8 {
    let mut count = 0;

    if has_slippage_protection(func_source) {
        count += 1;
    }

    if has_deadline_protection(func_source) {
        count += 1;
    }

    if has_commit_reveal_protection(func_source) {
        count += 1;
    }

    if has_auction_mechanism(func_source) {
        count += 1;
    }

    if has_time_weighted_mechanism(func_source) {
        count += 1;
    }

    if uses_oracle_pricing(func_source) {
        count += 1;
    }

    if has_batch_processing(func_source) {
        count += 1;
    }

    if has_private_transaction_support(func_source) {
        count += 1;
    }

    if has_mev_limiting_access_control(function) {
        count += 1;
    }

    if is_user_operation(func_source, function.name.name) {
        count += 1;
    }

    count
}

/// Phase 16 Recall Recovery: Score-based MEV protection assessment
/// Returns a weighted score based on protection strength
/// Higher score = stronger protection, lower MEV risk
pub fn get_mev_protection_score(function: &ast::Function<'_>, func_source: &str) -> u8 {
    let mut score: u8 = 0;

    // Strong protections (2 points each)
    if has_slippage_protection(func_source) {
        score = score.saturating_add(2);
    }

    if has_deadline_protection(func_source) {
        score = score.saturating_add(2);
    }

    if has_commit_reveal_protection(func_source) {
        score = score.saturating_add(2);
    }

    if has_auction_mechanism(func_source) {
        score = score.saturating_add(2);
    }

    if has_time_weighted_mechanism(func_source) {
        score = score.saturating_add(2);
    }

    // Medium protections (1 point each)
    if has_mev_limiting_access_control(function) {
        score = score.saturating_add(1);
    }

    if uses_oracle_pricing(func_source) {
        score = score.saturating_add(1);
    }

    if function.visibility == ast::Visibility::Private
        || function.visibility == ast::Visibility::Internal
    {
        score = score.saturating_add(1);
    }

    // Weak protections (1 point, but combined still helpful)
    if has_batch_processing(func_source) {
        score = score.saturating_add(1);
    }

    if has_private_transaction_support(func_source) {
        score = score.saturating_add(1);
    }

    if is_user_operation(func_source, function.name.name) {
        score = score.saturating_add(1);
    }

    score
}

/// Phase 16 Recall Recovery: Check if function is a trading/arbitrage function
/// These require stronger MEV protection (score >= 3)
pub fn is_trading_function(func_source: &str, func_name: &str) -> bool {
    let name_lower = func_name.to_lowercase();

    // Direct trading function names
    let trading_names = [
        "swap", "trade", "exchange", "arbitrage", "liquidat",
        "flashloan", "flash", "leverage", "margin",
    ];

    if trading_names.iter().any(|t| name_lower.contains(t)) {
        return true;
    }

    // Source code patterns indicating trading
    let trading_patterns = [
        "getAmountOut", "getAmountsOut", "getAmountIn",
        "swapExact", "flashLoan", "arbitrage",
        "liquidation", "leverage", "margin",
        "IUniswap", "IPancake", "ISushiSwap",
        "sandwich", "frontrun", "backrun",
    ];

    trading_patterns.iter().any(|p| func_source.contains(p))
}

/// Phase 16 Recall Recovery: Determines if trading function has sufficient protection
/// Trading functions require higher protection score than regular functions
/// CRITICAL: For trading functions, slippage protection is MANDATORY
pub fn is_adequately_protected_for_trading(function: &ast::Function<'_>, func_source: &str) -> bool {
    // Phase 16 FN Recovery: Trading functions MUST have slippage protection
    // Deadline and access control alone don't protect against sandwich attacks
    if !has_slippage_protection(func_source) {
        // Check if the function performs swaps with zero/missing minAmount
        // If it has swap calls without slippage params, it's vulnerable
        if func_source.contains("swapExact") || func_source.contains(".swap(") {
            // Look for the actual swap call and check if minAmount is 0
            if func_source.contains(", 0,") || func_source.contains(",0,") {
                return false; // Vulnerable - swap with 0 minAmount
            }
        }
        // No slippage protection detected - not adequately protected for trading
        return false;
    }

    let score = get_mev_protection_score(function, func_source);

    // Trading functions need score >= 3 (at least one strong + one medium, or multiple mediums)
    // AND slippage protection (checked above)
    score >= 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slippage_protection() {
        let with_slippage = "function swap(uint amountIn, uint minAmountOut) external {}";
        assert!(has_slippage_protection(with_slippage));

        let without_slippage = "function swap(uint amountIn) external {}";
        assert!(!has_slippage_protection(without_slippage));
    }

    #[test]
    fn test_deadline_protection() {
        let with_deadline = "require(block.timestamp <= deadline);";
        assert!(has_deadline_protection(with_deadline));

        let without_deadline = "require(amount > 0);";
        assert!(!has_deadline_protection(without_deadline));
    }

    #[test]
    fn test_user_operation() {
        let user_op = "function withdraw(uint amount) external { balances[msg.sender] -= amount; }";
        assert!(is_user_operation(user_op, "withdraw"));

        let non_user_op = "function distribute() external { }";
        assert!(!is_user_operation(non_user_op, "distribute"));
    }

    #[test]
    fn test_protected_swap() {
        let protected = r#"
            function swap(uint amountIn, uint minAmountOut, uint deadline) external {
                require(block.timestamp <= deadline);
                require(amountOut >= minAmountOut);
            }
        "#;
        assert!(is_protected_swap(protected));

        let unprotected = "function swap(uint amountIn) external {}";
        assert!(!is_protected_swap(unprotected));
    }

    #[test]
    fn test_is_trading_function() {
        assert!(is_trading_function("IUniswapV2Router.swapExactTokensForTokens", "swap"));
        assert!(is_trading_function("flashLoan(amount)", "executeArbitrage"));
        assert!(is_trading_function("liquidation bonus", "liquidate"));
        assert!(!is_trading_function("transfer(to, amount)", "transfer"));
        assert!(!is_trading_function("deposit(amount)", "deposit"));
    }

    #[test]
    fn test_mev_protection_score() {
        // Well protected with slippage + deadline = 4 points (passes threshold)
        let well_protected = r#"
            function swap(uint amountIn, uint minAmountOut, uint deadline) external {
                require(block.timestamp <= deadline);
                require(amountOut >= minAmountOut);
            }
        "#;
        // Should have score >= 3 for slippage (2) + deadline (2)
        assert!(has_slippage_protection(well_protected));
        assert!(has_deadline_protection(well_protected));

        // Weakly protected with only access control = 1 point (fails threshold for trading)
        let weakly_protected = "function swap() external onlyOwner {}";
        // Only access control gives 1 point, not enough for trading
        assert!(!has_slippage_protection(weakly_protected));
        assert!(!has_deadline_protection(weakly_protected));
    }
}
