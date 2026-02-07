//! DeFi Liquidity Pool Manipulation Detector
//!
//! Context-aware false-positive reduction (v1.10.15):
//!   - Per-function source analysis instead of whole-file matching
//!   - Skip view/pure functions for state-mutation checks
//!   - Skip internal/private helper functions
//!   - Skip non-pool contracts (governance, proxies, bridges, staking, NFTs, vaults)
//!   - Recognize safe pool implementations (lock modifier, K-invariant, TWAP)
//!   - Require pool-specific context for mint/burn (must reference reserves/liquidity)

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct LiquidityPoolManipulationDetector {
    base: BaseDetector,
}

impl LiquidityPoolManipulationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("defi-liquidity-pool-manipulation".to_string()),
                "Liquidity Pool Manipulation".to_string(),
                "Detects missing K-value validation, price oracle manipulation, and flash loan attacks on AMM invariants".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::Oracle],
                Severity::Critical,
            ),
        }
    }

    /// Check whether the contract is actually an AMM/DEX liquidity pool.
    /// Requires strong pool indicators -- not just any contract that happens
    /// to mention "swap" or "balance".
    fn is_amm_pool(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code.to_lowercase();

        // Exclude non-pool contract types that frequently mention pool-like keywords
        if self.is_non_pool_contract(source) {
            return false;
        }

        // Require at least one core pool operation AND pool state variables
        let has_pool_operation = source.contains("swap")
            || source.contains("addliquidity")
            || source.contains("removeliquidity");

        let has_pool_state = (source.contains("reserve0") || source.contains("reserve1"))
            || (source.contains("reserve") && source.contains("liquidity"))
            || (source.contains("token0")
                && source.contains("token1")
                && source.contains("reserve"));

        has_pool_operation && has_pool_state
    }

    /// Detect contracts that are not liquidity pools but share similar keywords.
    fn is_non_pool_contract(&self, source_lower: &str) -> bool {
        // ERC-4626 vaults: share-based deposit/withdraw, not AMM pools
        let is_vault = (source_lower.contains("erc4626") || source_lower.contains("erc-4626"))
            || (source_lower.contains("totalsupply")
                && source_lower.contains("totalassets")
                && source_lower.contains("shares"));

        // Governance contracts
        let is_governance = source_lower.contains("propose(")
            || source_lower.contains("castvoteforsig")
            || (source_lower.contains("proposal") && source_lower.contains("vote"));

        // Bridge / cross-chain contracts
        let is_bridge = source_lower.contains("bridgemessage")
            || source_lower.contains("relaychain")
            || (source_lower.contains("bridge") && source_lower.contains("chainid"));

        // Pure staking contracts (no swap/AMM operations)
        let is_staking = source_lower.contains("delegationmanager")
            || source_lower.contains("strategymanager")
            || (source_lower.contains("stake(")
                && source_lower.contains("unstake(")
                && !source_lower.contains("swap("));

        // NFT minting contracts
        let is_nft = (source_lower.contains("erc721")
            || source_lower.contains("erc1155")
            || source_lower.contains("nft"))
            && !source_lower.contains("reserve0")
            && !source_lower.contains("reserve1");

        // Phishing / delegation attack contracts (EIP-7702 test contracts)
        let is_delegation = source_lower.contains("delegatephishing")
            || source_lower.contains("sweepcontract")
            || (source_lower.contains("eip7702") || source_lower.contains("eip-7702"));

        is_vault || is_governance || is_bridge || is_staking || is_nft || is_delegation
    }

    /// Extract source code for a specific function from the file source.
    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();
        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            source_lines[start..=end].join("\n")
        } else {
            String::new()
        }
    }

    /// Check if a function is a pool-context mint/burn (operates on reserves/liquidity),
    /// as opposed to an NFT mint or token mint.
    fn is_pool_mint_or_burn(&self, name: &str, func_source: &str) -> bool {
        let s = func_source.to_lowercase();
        // Must reference reserves or liquidity token amounts -- signals pool context
        let has_pool_refs = s.contains("reserve")
            || s.contains("liquidity")
            || (s.contains("amount0") && s.contains("amount1"))
            || (s.contains("balance0") && s.contains("balance1"))
            || (s.contains("token0") && s.contains("token1"));

        // For "mint", also exclude pure token/NFT minting patterns
        if name.contains("mint") {
            let is_nft_or_token_mint = s.contains("tokenid")
                || s.contains("nft")
                || s.contains("mintprice")
                || s.contains("_mintnft")
                || (s.contains("transferfrom") && !has_pool_refs);
            return has_pool_refs && !is_nft_or_token_mint;
        }

        has_pool_refs
    }

    /// Check if the contract has a lock-style reentrancy guard (Uniswap V2 pattern).
    fn has_lock_modifier(&self, source_lower: &str) -> bool {
        // Uniswap V2: `modifier lock()` with `unlocked` state variable
        (source_lower.contains("modifier lock") && source_lower.contains("unlocked"))
            || source_lower.contains("nonreentrant")
            || source_lower.contains("reentrancyguard")
    }

    /// Check if the contract has K-invariant validation at the contract level.
    fn has_contract_level_k_check(&self, source_lower: &str) -> bool {
        // Check for K-invariant patterns used in the contract source
        // Uniswap V2: balance0 * balance1 >= reserve0 * reserve1
        let k_patterns = [
            "balance0 * balance1 >=",
            "balance0 * balance1 >",
            "require(balance0 * balance1",
            "reserve0 * reserve1",
            "uniswapv2: k",
        ];
        k_patterns.iter().any(|p| source_lower.contains(p))
    }

    fn check_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Vec<(String, Severity, String)> {
        let name = function.name.name.to_lowercase();
        let mut issues = Vec::new();

        // FP Reduction: Skip view/pure functions -- they cannot manipulate state
        if function.mutability == ast::StateMutability::View
            || function.mutability == ast::StateMutability::Pure
        {
            return issues;
        }

        // FP Reduction: Skip internal/private functions
        if function.visibility == ast::Visibility::Internal
            || function.visibility == ast::Visibility::Private
        {
            return issues;
        }

        // Get per-function source for precise matching
        let func_source = self.get_function_source(function, ctx);
        let func_lower = func_source.to_lowercase();
        let source_lower = ctx.source_code.to_lowercase();

        // Check swap functions
        if name.contains("swap") {
            // FP Reduction: Skip swap functions that are just router/consumer wrappers
            // (they delegate to an actual pool and do not implement the invariant themselves)
            let is_router_call = func_lower.contains(".swap(")
                || func_lower.contains("router.")
                || func_lower.contains("pair.")
                || func_lower.contains("pool.");
            let has_own_reserves = func_lower.contains("reserve0")
                || func_lower.contains("reserve1")
                || func_lower.contains("getreserves");

            // Check for K-value validation (x * y = k invariant)
            // Only flag if this function directly manages reserves (not a router wrapper)
            if !is_router_call || has_own_reserves {
                let has_k_check = self.has_contract_level_k_check(&source_lower)
                    || func_lower.contains("invariant")
                    || func_lower.contains("constant");

                if !has_k_check {
                    issues.push((
                        "Missing K-value invariant validation (x * y >= k)".to_string(),
                        Severity::Critical,
                        "Validate invariant: require(reserve0After * reserve1After >= reserve0Before * reserve1Before, \"K\");".to_string()
                    ));
                }
            }

            // Check for flash loan manipulation protection
            // FP Reduction: Recognize lock() modifier (Uniswap V2 pattern) as reentrancy guard
            let has_reentrancy_guard = self.has_lock_modifier(&source_lower)
                || func_lower.contains("lock")
                || func_lower.contains("nonreentrant");

            if !has_reentrancy_guard {
                issues.push((
                    "No reentrancy protection (flash loan attack risk)".to_string(),
                    Severity::Critical,
                    "Add reentrancy guard: modifier nonReentrant or use ReentrancyGuard from OpenZeppelin".to_string()
                ));
            }

            // Check for balance validation (only for pool-internal swap functions)
            if !is_router_call || has_own_reserves {
                let has_balance_check = func_lower.contains("balanceof(address(this))")
                    || (func_lower.contains("balance") && func_lower.contains("require"));

                if !has_balance_check {
                    issues.push((
                        "Missing balance validation before swap".to_string(),
                        Severity::High,
                        "Validate balances: uint balance0 = IERC20(token0).balanceOf(address(this)); require(balance0 >= reserve0 + amount0In);".to_string()
                    ));
                }
            }

            // Check for price manipulation via single-block oracle
            let has_twap = source_lower.contains("twap")
                || source_lower.contains("timeweighted")
                || source_lower.contains("gettwap");
            let has_cumulative =
                source_lower.contains("cumulative") || source_lower.contains("price0cumulative");
            let uses_spot_price =
                func_lower.contains("getamountout") && !has_twap && !has_cumulative;

            if uses_spot_price {
                issues.push((
                    "Using spot price for swaps (manipulation risk)".to_string(),
                    Severity::High,
                    "Use TWAP: Implement time-weighted average price over multiple blocks instead of spot price".to_string()
                ));
            }

            // Check for slippage protection
            let has_min_output = func_lower.contains("minamount")
                || func_lower.contains("amountoutmin")
                || func_lower.contains("amountmin")
                || (func_lower.contains("amount") && func_lower.contains(">="));

            if !has_min_output {
                issues.push((
                    "No slippage protection (frontrunning risk)".to_string(),
                    Severity::High,
                    "Add slippage: require(amountOut >= amountOutMin, \"Insufficient output\");"
                        .to_string(),
                ));
            }

            // Check for deadline validation
            let has_deadline = func_lower.contains("deadline")
                && (func_lower.contains("block.timestamp") || func_lower.contains("timestamp"));

            if !has_deadline {
                issues.push((
                    "Missing deadline parameter (stuck transaction risk)".to_string(),
                    Severity::Medium,
                    "Add deadline: require(block.timestamp <= deadline, \"Transaction expired\");"
                        .to_string(),
                ));
            }
        }

        // Check liquidity addition/removal
        // FP Reduction: "mint" must be in pool context (references reserves), not NFT/token mint
        if name.contains("addliquidity")
            || (name.contains("mint") && self.is_pool_mint_or_burn(&name, &func_source))
        {
            // Check for minimum liquidity lock
            let has_min_liquidity = source_lower.contains("minimum_liquidity")
                || (source_lower.contains("1000") && source_lower.contains("mint"));

            if name.contains("addliquidity") && !has_min_liquidity {
                issues.push((
                    "No minimum liquidity lock (pool initialization attack)".to_string(),
                    Severity::High,
                    "Lock minimum: if (totalSupply == 0) { liquidity = sqrt(amount0 * amount1) - MINIMUM_LIQUIDITY; _mint(address(0), MINIMUM_LIQUIDITY); }".to_string()
                ));
            }

            // Check for balanced liquidity provision
            let has_ratio_check = source_lower.contains("amount0")
                && source_lower.contains("amount1")
                && (source_lower.contains("reserve0") || source_lower.contains("reserve1"));

            if !has_ratio_check {
                issues.push((
                    "No ratio validation for liquidity provision".to_string(),
                    Severity::Medium,
                    "Validate ratio: require(amount0 * reserve1 == amount1 * reserve0, \"Invalid ratio\");".to_string()
                ));
            }
        }

        // FP Reduction: "burn" must be in pool context
        if name.contains("removeliquidity")
            || (name.contains("burn") && self.is_pool_mint_or_burn(&name, &func_source))
        {
            // Check for sandwich attack protection
            let has_min_amounts = (source_lower.contains("amount0min")
                && source_lower.contains("amount1min"))
                || source_lower.contains("minamount");

            if !has_min_amounts {
                issues.push((
                    "No minimum amount protection on liquidity removal".to_string(),
                    Severity::High,
                    "Add minimums: require(amount0 >= amount0Min && amount1 >= amount1Min, \"Insufficient output\");".to_string()
                ));
            }
        }

        // Check price getter functions -- skip view/pure already handled above,
        // but getPrice/getAmountOut are typically view and will be filtered out.

        // Check for reserve synchronization
        if name.contains("sync") || name.contains("skim") {
            let has_access_control = source_lower.contains("onlyowner")
                || source_lower.contains("require")
                || source_lower.contains("internal");

            if name.contains("skim") && !has_access_control {
                issues.push((
                    "Public skim function (reserve manipulation risk)".to_string(),
                    Severity::Medium,
                    "Add access control: function skim() external onlyOwner or make it internal"
                        .to_string(),
                ));
            }
        }

        issues
    }
}

impl Default for LiquidityPoolManipulationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for LiquidityPoolManipulationDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn is_enabled(&self) -> bool {
        self.base.enabled
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }


        if !self.is_amm_pool(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            let issues = self.check_function(function, ctx);
            for (message, severity, remediation) in issues {
                let finding = self
                    .base
                    .create_finding_with_severity(
                        ctx,
                        format!("{} in '{}'", message, function.name.name),
                        function.name.location.start().line() as u32,
                        0,
                        20,
                        severity,
                    )
                    .with_cwe(682) // CWE-682: Incorrect Calculation
                    .with_cwe(20) // CWE-20: Improper Input Validation
                    .with_fix_suggestion(remediation);

                findings.push(finding);
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::Detector;

    fn create_context(source: &str) -> AnalysisContext<'static> {
        crate::types::test_utils::create_test_context(source)
    }

    #[test]
    fn test_detector_properties() {
        let detector = LiquidityPoolManipulationDetector::new();
        assert_eq!(detector.name(), "Liquidity Pool Manipulation");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }

    // -- is_amm_pool context filtering tests --

    #[test]
    fn test_amm_pool_detected() {
        let detector = LiquidityPoolManipulationDetector::new();
        let ctx = create_context(
            "contract Pair { \
             uint112 reserve0; uint112 reserve1; \
             function swap(uint a, uint b) external { } \
             function addLiquidity() external { } \
             }",
        );
        assert!(detector.is_amm_pool(&ctx));
    }

    #[test]
    fn test_erc4626_vault_excluded() {
        let detector = LiquidityPoolManipulationDetector::new();
        let ctx = create_context(
            "contract Vault is ERC4626 { \
             uint256 totalAssets; uint256 totalSupply; uint256 shares; \
             function swap(address token) external { } \
             function deposit(uint256 amount) external { } \
             uint256 reserve; uint256 balance; uint256 liquidity; \
             }",
        );
        assert!(!detector.is_amm_pool(&ctx));
    }

    #[test]
    fn test_governance_contract_excluded() {
        let detector = LiquidityPoolManipulationDetector::new();
        let ctx = create_context(
            "contract Governor { \
             function propose(address[] targets) external { } \
             function swap(uint a) external { } \
             uint256 reserve; uint256 liquidity; \
             }",
        );
        assert!(!detector.is_amm_pool(&ctx));
    }

    #[test]
    fn test_bridge_contract_excluded() {
        let detector = LiquidityPoolManipulationDetector::new();
        let ctx = create_context(
            "contract Bridge { \
             uint256 chainId; \
             function bridgeMessage(bytes data) external { } \
             function swap(uint a) external { } \
             uint256 reserve; uint256 liquidity; \
             }",
        );
        assert!(!detector.is_amm_pool(&ctx));
    }

    #[test]
    fn test_nft_contract_excluded() {
        let detector = LiquidityPoolManipulationDetector::new();
        let ctx = create_context(
            "contract MyNFT is ERC721 { \
             function mint(address to) external { } \
             function swap(address token) external { } \
             uint256 balance; uint256 liquidity; \
             }",
        );
        assert!(!detector.is_amm_pool(&ctx));
    }

    #[test]
    fn test_staking_contract_excluded() {
        let detector = LiquidityPoolManipulationDetector::new();
        let ctx = create_context(
            "contract DelegationManager { \
             function stake(uint amount) external { } \
             function swap(uint a) external { } \
             uint256 reserve; uint256 liquidity; \
             }",
        );
        assert!(!detector.is_amm_pool(&ctx));
    }

    #[test]
    fn test_simple_contract_not_pool() {
        let detector = LiquidityPoolManipulationDetector::new();
        let ctx = create_context(
            "contract Token { function transfer(address to, uint256 amount) external { } }",
        );
        assert!(!detector.is_amm_pool(&ctx));
    }

    // -- is_non_pool_contract tests --

    #[test]
    fn test_eip7702_delegation_excluded() {
        let detector = LiquidityPoolManipulationDetector::new();
        let source = "contract EIP7702Delegate { function optimizedSwap() external { } }";
        assert!(detector.is_non_pool_contract(&source.to_lowercase()));
    }

    // -- is_pool_mint_or_burn tests --

    #[test]
    fn test_pool_mint_with_reserves_detected() {
        let detector = LiquidityPoolManipulationDetector::new();
        let func_source = "function mint(address to) external {
            uint balance0 = IERC20(token0).balanceOf(address(this));
            uint balance1 = IERC20(token1).balanceOf(address(this));
            uint amount0 = balance0 - reserve0;
        }";
        assert!(detector.is_pool_mint_or_burn("mint", func_source));
    }

    #[test]
    fn test_nft_mint_excluded() {
        let detector = LiquidityPoolManipulationDetector::new();
        let func_source = "function mint(uint256 tokenId) external {
            require(mintPrice > 0);
            paymentToken.transferFrom(msg.sender, address(this), mintPrice);
            _mintNFT(msg.sender);
        }";
        assert!(!detector.is_pool_mint_or_burn("mint", func_source));
    }

    #[test]
    fn test_vault_mint_excluded() {
        let detector = LiquidityPoolManipulationDetector::new();
        let func_source = "function mint(uint256 shares) public returns (uint256 assets) {
            assets = totalSupply == 0 ? shares : (shares * asset.balanceOf(address(this))) / totalSupply;
            require(asset.transferFrom(msg.sender, address(this), assets));
            balanceOf[msg.sender] += shares;
        }";
        assert!(!detector.is_pool_mint_or_burn("mint", func_source));
    }

    #[test]
    fn test_pool_burn_with_reserves_detected() {
        let detector = LiquidityPoolManipulationDetector::new();
        let func_source = "function burn(address to) external {
            uint balance0 = IERC20(token0).balanceOf(address(this));
            uint balance1 = IERC20(token1).balanceOf(address(this));
            uint liquidity = balanceOf[address(this)];
        }";
        assert!(detector.is_pool_mint_or_burn("burn", func_source));
    }

    #[test]
    fn test_token_burn_excluded() {
        let detector = LiquidityPoolManipulationDetector::new();
        let func_source = "function burn(uint256 amount) external {
            _burn(msg.sender, amount);
        }";
        assert!(!detector.is_pool_mint_or_burn("burn", func_source));
    }

    // -- has_lock_modifier tests --

    #[test]
    fn test_uniswap_lock_modifier_recognized() {
        let detector = LiquidityPoolManipulationDetector::new();
        let source = "modifier lock() { require(unlocked == 1); unlocked = 0; _; unlocked = 1; }";
        assert!(detector.has_lock_modifier(&source.to_lowercase()));
    }

    #[test]
    fn test_openzeppelin_nonreentrant_recognized() {
        let detector = LiquidityPoolManipulationDetector::new();
        let source =
            "contract Pool is ReentrancyGuard { function swap() nonReentrant external { } }";
        assert!(detector.has_lock_modifier(&source.to_lowercase()));
    }

    #[test]
    fn test_no_guard_not_recognized() {
        let detector = LiquidityPoolManipulationDetector::new();
        let source = "contract Pool { function swap() external { } }";
        assert!(!detector.has_lock_modifier(&source.to_lowercase()));
    }

    // -- has_contract_level_k_check tests --

    #[test]
    fn test_k_invariant_check_recognized() {
        let detector = LiquidityPoolManipulationDetector::new();
        let source = "require(balance0 * balance1 >= uint(reserve0) * uint(reserve1), 'K');";
        assert!(detector.has_contract_level_k_check(&source.to_lowercase()));
    }

    #[test]
    fn test_uniswap_k_string_recognized() {
        let detector = LiquidityPoolManipulationDetector::new();
        let source = "require(ok, 'UniswapV2: K');";
        assert!(detector.has_contract_level_k_check(&source.to_lowercase()));
    }

    #[test]
    fn test_no_k_check() {
        let detector = LiquidityPoolManipulationDetector::new();
        let source = "function swap() external { transfer(to, amount); }";
        assert!(!detector.has_contract_level_k_check(&source.to_lowercase()));
    }
}
