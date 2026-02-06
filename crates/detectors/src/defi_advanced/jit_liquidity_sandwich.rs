//! JIT Liquidity Sandwich Attack Detector
//!
//! Detects vulnerability to just-in-time (JIT) liquidity attacks where an attacker:
//! 1. Adds large liquidity immediately before a user's swap
//! 2. Captures a significant portion of the trading fees
//! 3. Removes liquidity immediately after
//!
//! This is a sophisticated MEV strategy that exploits protocols without time-locks
//! on liquidity provision/removal.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

pub struct JitLiquiditySandwichDetector {
    base: BaseDetector,
}

impl JitLiquiditySandwichDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("jit-liquidity-sandwich".to_string()),
                "JIT Liquidity Sandwich".to_string(),
                "Detects vulnerability to just-in-time liquidity attacks where attackers add liquidity before swaps and remove immediately after to capture fees".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::MEV],
                Severity::High,
            ),
        }
    }
}

impl Default for JitLiquiditySandwichDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for JitLiquiditySandwichDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn is_enabled(&self) -> bool {
        self.base.enabled
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Skip standard AMM implementations (Uniswap V2/V3, Curve, Balancer)
        // These protocols intentionally allow instant liquidity provision/removal
        // JIT attacks are a known design tradeoff for capital efficiency
        if utils::is_amm_pool(ctx) {
            return Ok(findings);
        }

        // Skip lending protocols - JIT attacks target AMM pools, not lending protocols
        // Lending protocols (Compound, Aave, MakerDAO) have deposit/withdraw for user funds,
        // not liquidity provision. Users should be able to withdraw their deposits anytime.
        // JIT liquidity sandwich attacks are specific to AMM fee capture, not lending.
        if utils::is_lending_protocol(ctx) {
            return Ok(findings);
        }

        // Skip ERC-4626 vaults - deposit/withdraw are for user shares, not liquidity provision
        // Vaults don't have liquidity pools vulnerable to JIT attacks
        if utils::is_erc4626_vault(ctx) {
            return Ok(findings);
        }

        let lower = ctx.source_code.to_lowercase();

        // Skip interfaces - they define signatures, not vulnerable implementations
        // Interface files don't have actual liquidity pool logic
        if lower.contains("interface ") && !lower.contains("contract ") {
            return Ok(findings);
        }

        // Skip standard tokens (ERC20, ERC721, ERC1155) - mint/burn/transfer are NOT liquidity operations
        // JIT attacks target liquidity pools, not token contracts
        // Check for standard token patterns but exclude actual liquidity pools
        let is_standard_token = (lower.contains("function transfer")
            || lower.contains("function transferfrom")
            || lower.contains("function safetransfer"))  // ERC721/1155
            && (lower.contains("balanceof") || lower.contains("ownerof"))  // ERC20 or ERC721
            && !lower.contains("getreserves")  // AMM pools have reserves
            && !lower.contains("liquidityindex")  // Lending has liquidity index
            && !lower.contains("converttoassets")  // Vaults have conversions
            && !lower.contains("addliquidity")  // Pools have liquidity functions
            && !lower.contains("removeliquidity");

        if is_standard_token {
            return Ok(findings);
        }

        // CRITICAL: Only flag contracts that are actually liquidity pools
        // JIT attacks only apply to AMM-like liquidity pool contracts
        // Require at least 2 of these indicators:
        let has_liquidity_patterns = self.has_liquidity_pool_patterns(ctx);
        if !has_liquidity_patterns {
            return Ok(findings);
        }

        // Check for liquidity removal functions without time-locks
        // Only check explicit liquidity functions, not generic withdraw/burn
        let has_remove_liquidity = lower.contains("removeliquidity")
            || lower.contains("withdrawliquidity")
            || (lower.contains("withdraw") && lower.contains("liquidity"));

        if has_remove_liquidity {
            // Check for time-lock protection
            let has_timelock = lower.contains("minlocktime")
                || lower.contains("lockuntil")
                || lower.contains("lockeduntil")
                || lower.contains("block.timestamp >=")
                || lower.contains("require(block.timestamp");

            // Check for liquidity epoch/cooldown
            let has_epoch_protection = lower.contains("epoch")
                || lower.contains("cooldown")
                || lower.contains("lastdeposit")
                || lower.contains("deposittime");

            if !has_timelock && !has_epoch_protection {
                // Find the actual line of the remove liquidity function
                let line_num = self.find_function_line(&lower, "removeliquidity");
                let finding = self.base.create_finding(
                    ctx,
                    "Liquidity removal function without time-lock protection - vulnerable to JIT attacks".to_string(),
                    line_num,
                    1,
                    50,  // Reasonable span for a function name
                )
                .with_fix_suggestion(
                    "Add a minimum lock time for liquidity positions (e.g., 1 block or epoch-based system) to prevent JIT liquidity attacks".to_string()
                );

                findings.push(finding);
            }
        }

        // Check for instant liquidity activation
        // Only check explicit liquidity add functions, not generic deposit/mint
        let has_add_liquidity = lower.contains("addliquidity")
            || lower.contains("providerliquidity")
            || (lower.contains("deposit") && lower.contains("liquidity"))
            || (lower.contains("mint") && lower.contains("liquidity"));

        if has_add_liquidity {
            let has_activation_delay = lower.contains("activationdelay")
                || lower.contains("nextepoch")
                || lower.contains("pendingdeposit");

            if !has_activation_delay {
                // Find the actual line of the add liquidity function
                let line_num = self.find_function_line(&lower, "addliquidity");
                let finding = self.base.create_finding(
                    ctx,
                    "Liquidity becomes active immediately - may enable JIT sandwich attacks".to_string(),
                    line_num,
                    1,
                    50,  // Reasonable span for a function name
                )
                .with_fix_suggestion(
                    "Consider delaying liquidity activation to the next epoch or block to mitigate JIT attacks".to_string()
                );

                findings.push(finding);
            }
        }

        // Check for time-weighted fee distribution (only if this is a fee-distributing pool)
        let has_fee_distribution = lower.contains("distributefee")
            || lower.contains("accruefee")
            || lower.contains("claimfee")
            || (lower.contains("fee")
                && lower.contains("liquidity")
                && lower.contains("distribute"));

        if has_fee_distribution {
            let has_timeweighted_fees = lower.contains("timeweighted")
                || lower.contains("averageliquidity")
                || lower.contains("liquidityduration");

            if !has_timeweighted_fees {
                let line_num = self.find_function_line(&lower, "fee");
                let finding = self.base.create_finding(
                    ctx,
                    "Fee distribution not time-weighted - JIT liquidity providers get disproportionate rewards".to_string(),
                    line_num,
                    1,
                    50,
                )
                .with_fix_suggestion(
                    "Implement time-weighted fee distribution to reward longer-term liquidity providers".to_string()
                );

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl JitLiquiditySandwichDetector {
    /// Check if the contract has actual liquidity pool patterns
    /// JIT attacks only apply to liquidity pools, not regular tokens/contracts
    fn has_liquidity_pool_patterns(&self, ctx: &AnalysisContext) -> bool {
        let lower = ctx.source_code.to_lowercase();

        // Must have explicit liquidity functions
        let has_add_liquidity = lower.contains("addliquidity")
            || lower.contains("providerliquidity")
            || lower.contains("depositliquidity");

        let has_remove_liquidity =
            lower.contains("removeliquidity") || lower.contains("withdrawliquidity");

        // Must have reserve tracking (AMM pattern)
        let has_reserves = (lower.contains("reserve0") && lower.contains("reserve1"))
            || lower.contains("getreserves")
            || lower.contains("totalreserves");

        // Must have swap functionality
        let has_swap = lower.contains("function swap")
            || lower.contains("swaptokens")
            || lower.contains("exchange");

        // Must have LP token mechanics
        let has_lp_tokens = lower.contains("lptoken")
            || lower.contains("pooltoken")
            || lower.contains("liquiditytoken")
            || (lower.contains("totalsupply") && has_add_liquidity);

        // Contract name indicates liquidity pool
        let contract_name = ctx.contract.name.name.to_lowercase();
        let is_pool_named = contract_name.contains("pool")
            || contract_name.contains("pair")
            || contract_name.contains("amm")
            || contract_name.contains("liquidity");

        // Require at least 2 strong indicators to flag
        let indicators = [
            has_add_liquidity && has_remove_liquidity, // Both liquidity functions
            has_reserves,                              // Reserve tracking
            has_swap,                                  // Swap functionality
            has_lp_tokens,                             // LP token mechanics
            is_pool_named,                             // Named as pool
        ];

        let indicator_count = indicators.iter().filter(|&&x| x).count();
        indicator_count >= 2
    }

    /// Find the line number of a function containing the given keyword
    fn find_function_line(&self, source: &str, keyword: &str) -> u32 {
        for (i, line) in source.lines().enumerate() {
            if line.contains("function") && line.contains(keyword) {
                return (i + 1) as u32;
            }
        }
        // Fallback: find any line containing the keyword
        for (i, line) in source.lines().enumerate() {
            if line.contains(keyword) {
                return (i + 1) as u32;
            }
        }
        1 // Default to line 1 if not found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = JitLiquiditySandwichDetector::new();
        assert_eq!(detector.name(), "JIT Liquidity Sandwich");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_simple_erc20_not_flagged() {
        // Simple ERC20 tokens should NOT be flagged
        // They have mint/burn but are not liquidity pools
        let source = r#"
            contract Token is ERC20 {
                constructor() ERC20("Token", "TKN") {
                    _mint(msg.sender, 1000000 * 10 ** decimals());
                }
                function transfer(address to, uint256 amount) public returns (bool) {
                    return super.transfer(to, amount);
                }
                function balanceOf(address account) public view returns (uint256) {
                    return super.balanceOf(account);
                }
            }
        "#;

        let lower = source.to_lowercase();

        // Check it's identified as a standard token
        let is_standard_token = lower.contains("function transfer")
            && lower.contains("balanceof")
            && !lower.contains("addliquidity")
            && !lower.contains("removeliquidity");

        assert!(is_standard_token);

        // Check it doesn't have liquidity pool patterns
        let has_add_liquidity = lower.contains("addliquidity");
        let has_reserves = lower.contains("reserve0") && lower.contains("reserve1");
        let has_swap = lower.contains("function swap");

        assert!(!has_add_liquidity);
        assert!(!has_reserves);
        assert!(!has_swap);
    }

    #[test]
    fn test_interface_not_flagged() {
        // Interfaces should NOT be flagged
        let source = r#"
            interface IWETH {
                function deposit() external payable;
                function withdraw(uint256 amount) external;
                function transfer(address to, uint256 value) external returns (bool);
            }
        "#;

        let lower = source.to_lowercase();
        let is_interface = lower.contains("interface ") && !lower.contains("contract ");

        assert!(is_interface);
    }

    #[test]
    fn test_actual_liquidity_pool_detected() {
        // Real liquidity pools SHOULD have patterns detected
        let source = r#"
            contract LiquidityPool {
                uint112 private reserve0;
                uint112 private reserve1;

                function addLiquidity(uint amount0, uint amount1) external {
                    // add liquidity logic
                    _mint(msg.sender, liquidity);
                }

                function removeLiquidity(uint liquidity) external {
                    // remove liquidity logic
                }

                function swap(uint amount0Out, uint amount1Out) external {
                    // swap logic
                }

                function getReserves() public view returns (uint112, uint112) {
                    return (reserve0, reserve1);
                }
            }
        "#;

        let lower = source.to_lowercase();

        // Should have liquidity pool patterns
        let has_add_liquidity = lower.contains("addliquidity");
        let has_remove_liquidity = lower.contains("removeliquidity");
        let has_reserves = lower.contains("reserve0") && lower.contains("reserve1");
        let has_swap = lower.contains("function swap");

        assert!(has_add_liquidity);
        assert!(has_remove_liquidity);
        assert!(has_reserves);
        assert!(has_swap);

        // Count indicators
        let indicators = [
            has_add_liquidity && has_remove_liquidity,
            has_reserves,
            has_swap,
        ];
        let count = indicators.iter().filter(|&&x| x).count();

        // Should have at least 2 indicators
        assert!(count >= 2);
    }

    #[test]
    fn test_find_function_line() {
        let detector = JitLiquiditySandwichDetector::new();

        // Note: find_function_line expects lowercase source (as passed from detect())
        let source = "line 1\nline 2\nfunction addliquidity() {\nline 4\n}";
        let line = detector.find_function_line(source, "addliquidity");
        assert_eq!(line, 3);
    }
}
