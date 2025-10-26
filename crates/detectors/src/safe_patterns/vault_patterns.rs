use crate::types::AnalysisContext;

/// Detect dead shares protection pattern (Uniswap V2 style)
///
/// Dead shares are initial shares minted to address(0) to prevent first depositor
/// from manipulating share price through inflation attack.
///
/// Patterns detected:
/// - `_mint(address(0), amount)`
/// - `balanceOf[address(0)] = MINIMUM_LIQUIDITY`
/// - `mint(DEAD, amount)`
/// - Constants named MINIMUM_LIQUIDITY with address(0) operations
pub fn has_dead_shares_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: _mint(address(0), ...)
    if source.contains("_mint(address(0)") || source.contains("_mint(address(0x0)") {
        return true;
    }

    // Pattern 2: balanceOf[address(0)] = amount (direct assignment)
    if source.contains("balanceOf[address(0)]") && source.contains("= ") {
        return true;
    }

    // Pattern 3: mint to DEAD address
    if source.contains("mint(DEAD") || source.contains("mint(address(DEAD") {
        return true;
    }

    // Pattern 4: deadShares variable
    if source.contains("deadShares") && source.contains("address(0)") {
        return true;
    }

    // Pattern 5: MINIMUM_LIQUIDITY constant + address(0) operations
    if source.contains("MINIMUM_LIQUIDITY") {
        // Check if used with address(0)
        let has_zero_address = source.contains("address(0)") || source.contains("address(0x0)");
        if has_zero_address {
            return true;
        }
    }

    // Pattern 6: totalSupply initialization with non-zero value
    // This is a weaker indicator but can help
    if source.contains("totalSupply = ") && source.contains("MINIMUM") {
        return true;
    }

    false
}

/// Detect virtual shares/assets protection pattern (OpenZeppelin style)
///
/// Virtual shares add an offset to share calculations to prevent first depositor
/// from manipulating share price.
///
/// Patterns detected:
/// - `VIRTUAL_SHARES_OFFSET` or `VIRTUAL_ASSETS_OFFSET` constants
/// - `totalSupply + OFFSET` pattern
/// - `decimalsOffset()` function (OpenZeppelin ERC4626)
/// - Helper functions with virtual offset logic
pub fn has_virtual_shares_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: VIRTUAL_SHARES or VIRTUAL_ASSETS constants
    if source.contains("VIRTUAL_SHARES") || source.contains("VIRTUAL_ASSETS") {
        return true;
    }

    // Pattern 2: totalSupply + OFFSET pattern
    if (source.contains("totalSupply +") || source.contains("totalSupply+"))
        && source.contains("OFFSET")
    {
        return true;
    }

    // Pattern 3: totalAssets() + OFFSET pattern
    if (source.contains("totalAssets() +") || source.contains("totalAssets()+"))
        && source.contains("OFFSET")
    {
        return true;
    }

    // Pattern 4: decimalsOffset() function (OpenZeppelin pattern)
    if source.contains("decimalsOffset()") || source.contains("_decimalsOffset()")  {
        return true;
    }

    // Pattern 5: _convertToShares or _convertToAssets with offset logic
    if source.contains("_convertToShares") || source.contains("_convertToAssets") {
        // Check if the function uses offset pattern
        if source.contains("+ ") && (source.contains("10**") || source.contains("1e")) {
            return true;
        }
    }

    // Pattern 6: supply + 1 pattern (minimal offset)
    if source.contains("supply + 1") || source.contains("supply+1") {
        return true;
    }

    false
}

/// Detect minimum deposit protection
///
/// Minimum deposit requirements make inflation attacks economically infeasible
/// by requiring the attacker to lock significant capital.
///
/// Patterns detected:
/// - `require(assets >= MINIMUM_DEPOSIT)`
/// - `require(amount >= MIN_DEPOSIT)`
/// - Implicit minimum from dead shares subtraction
pub fn has_minimum_deposit_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: Explicit minimum deposit check
    if source.contains("require(assets >=") && source.contains("MINIMUM") {
        return true;
    }

    if source.contains("require(amount >=") && source.contains("MIN") {
        return true;
    }

    // Pattern 2: MIN_DEPOSIT or MINIMUM_DEPOSIT constant
    if source.contains("MIN_DEPOSIT") || source.contains("MINIMUM_DEPOSIT") {
        // Verify it's used in a require statement
        if source.contains("require(") {
            return true;
        }
    }

    // Pattern 3: Implicit minimum from dead shares subtraction
    // Pattern: assets - MINIMUM_LIQUIDITY with require(shares > 0)
    if source.contains("assets - MINIMUM") || source.contains("amount - MINIMUM") {
        if source.contains("require(shares > 0") || source.contains("require(amount > 0") {
            return true;
        }
    }

    // Pattern 4: First deposit minimum
    if source.contains("if (totalSupply == 0)") || source.contains("if (totalSupply() == 0)") {
        if source.contains("require(") && (source.contains("MINIMUM") || source.contains("MIN_")) {
            return true;
        }
    }

    false
}

/// Check if vault has ANY inflation protection
///
/// Returns true if dead shares, virtual shares, or minimum deposit is detected.
/// If any protection is present, inflation attacks are mitigated.
pub fn has_inflation_protection(ctx: &AnalysisContext) -> bool {
    has_dead_shares_pattern(ctx)
        || has_virtual_shares_pattern(ctx)
        || has_minimum_deposit_pattern(ctx)
}

/// Detect internal balance tracking
///
/// Internal balance tracking prevents donation attacks by maintaining
/// accounting separate from token.balanceOf(address(this)).
///
/// Patterns detected:
/// - `totalDeposited` variable
/// - `internalBalance` variable
/// - `trackedAssets` variable
/// - `_updateBalance()` function
pub fn has_internal_balance_tracking(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Common internal balance variable names
    let tracking_vars = [
        "totalDeposited",
        "internalBalance",
        "trackedAssets",
        "accountedBalance",
        "_totalAssets",
        "storedBalance",
    ];

    for var in &tracking_vars {
        if source.contains(var) {
            return true;
        }
    }

    // Check for balance update functions
    if source.contains("_updateBalance") || source.contains("updateBalance") {
        return true;
    }

    false
}

/// Detect donation guards
///
/// Donation guards explicitly check for unexpected balance increases.
///
/// Patterns detected:
/// - `expectedBalance` comparison
/// - `require(asset.balanceOf(address(this)) == expected)`
/// - `donationGuard` modifier or function
pub fn has_donation_guard(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: expectedBalance variable
    if source.contains("expectedBalance") {
        return true;
    }

    // Pattern 2: Balance equality check
    if source.contains("balanceOf(address(this)) ==") {
        return true;
    }

    // Pattern 3: donationGuard
    if source.contains("donationGuard") {
        return true;
    }

    // Pattern 4: Balance validation
    if source.contains("validateBalance") || source.contains("checkBalance") {
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
    fn test_dead_shares_pattern_mint() {
        let source = r#"
            function deposit() public {
                _mint(address(0), MINIMUM_LIQUIDITY);
            }
        "#;
        let ctx = create_context(source);
        assert!(has_dead_shares_pattern(&ctx));
    }

    #[test]
    fn test_dead_shares_pattern_balance_assignment() {
        let source = r#"
            function deposit() public {
                balanceOf[address(0)] = MINIMUM_LIQUIDITY;
                totalSupply = MINIMUM_LIQUIDITY;
            }
        "#;
        let ctx = create_context(source);
        assert!(has_dead_shares_pattern(&ctx));
    }

    #[test]
    fn test_virtual_shares_pattern() {
        let source = r#"
            uint256 private constant VIRTUAL_SHARES_OFFSET = 10**3;
            uint256 private constant VIRTUAL_ASSETS_OFFSET = 1;

            function _convertToShares(uint256 assets) internal view returns (uint256) {
                uint256 supply = totalSupply + VIRTUAL_SHARES_OFFSET;
                uint256 assetBalance = totalAssets() + VIRTUAL_ASSETS_OFFSET;
                return (assets * supply) / assetBalance;
            }
        "#;
        let ctx = create_context(source);
        assert!(has_virtual_shares_pattern(&ctx));
    }

    #[test]
    fn test_minimum_deposit_pattern() {
        let source = r#"
            uint256 private constant MINIMUM_DEPOSIT = 10**6;

            function deposit(uint256 assets) public {
                if (totalSupply == 0) {
                    require(assets >= MINIMUM_DEPOSIT, "First deposit too small");
                }
            }
        "#;
        let ctx = create_context(source);
        assert!(has_minimum_deposit_pattern(&ctx));
    }

    #[test]
    fn test_no_protections() {
        let source = r#"
            function deposit(uint256 assets) public {
                shares = assets * totalSupply / totalAssets();
            }
        "#;
        let ctx = create_context(source);
        assert!(!has_dead_shares_pattern(&ctx));
        assert!(!has_virtual_shares_pattern(&ctx));
        assert!(!has_minimum_deposit_pattern(&ctx));
        assert!(!has_inflation_protection(&ctx));
    }

    #[test]
    fn test_inflation_protection_any() {
        let dead_shares = r#"balanceOf[address(0)] = 1000;"#;
        let ctx = create_context(dead_shares);
        assert!(has_inflation_protection(&ctx));

        let virtual_shares = r#"totalSupply + VIRTUAL_SHARES_OFFSET"#;
        let ctx = create_context(virtual_shares);
        assert!(has_inflation_protection(&ctx));

        let min_deposit = r#"require(assets >= MINIMUM_DEPOSIT)"#;
        let ctx = create_context(min_deposit);
        assert!(has_inflation_protection(&ctx));
    }
}
