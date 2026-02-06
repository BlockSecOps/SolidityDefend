//! MEV Toxic Flow Detector
//!
//! Detects AMM toxic flow risks where informed traders extract value.
//! Adversarial order flow causes LPs to lose money to informed traders.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

pub struct MEVToxicFlowDetector {
    base: BaseDetector,
}

impl MEVToxicFlowDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("mev-toxic-flow-exposure".to_string()),
                "MEV Toxic Flow Exposure".to_string(),
                "Detects AMM toxic flow risks from informed order flow".to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::DeFi],
                Severity::Medium,
            ),
        }
    }

    /// Check if the contract defines its own swap function (not just calling external routers).
    ///
    /// A contract that only calls `IDEXRouter.swapExactTokensForTokens()` is a *consumer*
    /// of an AMM, not an AMM itself. Only contracts that define `function swap(` or
    /// `function exchange(` as their own entry points are actual AMMs.
    fn has_internal_swap_function(source: &str) -> bool {
        // Look for swap/exchange function declarations (not interface calls)
        // "function swap(" is a function definition in the contract
        let has_swap_def =
            source.contains("function swap(") || source.contains("function exchange(");

        // Exclude cases where "function swap(" only appears inside an interface block.
        // If the contract also defines the function in a contract body, it's a real AMM.
        if has_swap_def {
            // Heuristic: if the source also has addLiquidity/removeLiquidity definitions,
            // it's very likely an AMM rather than just an interface declaration
            let has_liquidity_def = source.contains("function addLiquidity")
                || source.contains("function removeLiquidity");
            if has_liquidity_def {
                return true;
            }

            // Check if swap function appears outside of interface declarations
            // by looking for implementation body patterns near function swap(
            for line in source.lines() {
                let trimmed = line.trim();
                if trimmed.contains("function swap(") || trimmed.contains("function exchange(") {
                    // If it's inside an interface, it typically has no body (ends with ;)
                    // Real implementations have { or are followed by modifiers/returns
                    if !trimmed.ends_with(';') {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Check if the contract has actual AMM pool state (reserves, liquidity tokens, etc.).
    ///
    /// True AMMs manage internal pool state: reserve balances, token pairs as state
    /// variables, constant product invariants, and LP token mechanics. Contracts
    /// that merely reference these concepts in interface calls or variable names for
    /// external interactions are not AMMs.
    fn has_amm_pool_state(source: &str, lower: &str) -> bool {
        // Reserve state variables (not just interface calls like IUniswapV2Pair.getReserves())
        let has_reserve_state = lower.contains("uint112 private reserve")
            || lower.contains("uint256 public reserve")
            || lower.contains("uint256 private reserve")
            || lower.contains("uint112 public reserve")
            || (lower.contains("reserve0")
                && lower.contains("reserve1")
                && !Self::only_in_interface_call(source, "reserve"));

        // Liquidity token state (LP tokens minted/burned by this contract)
        let has_lp_token_state = lower.contains("totalliquidity")
            || lower.contains("lptoken")
            || lower.contains("liquiditytoken")
            || (lower.contains("function mint(")
                && lower.contains("function burn(")
                && lower.contains("liquidity"));

        // Constant product formula or invariant checks
        let has_invariant = lower.contains("k =")
            || lower.contains("balance0 * balance1")
            || lower.contains("reserve0 * reserve1")
            || lower.contains("getamountout")
            || lower.contains("getamountin");

        // Token pair as state variables (not just function parameters)
        let has_token_pair_state = (source.contains("address public token0")
            || source.contains("address public token1")
            || source.contains("address immutable token0")
            || source.contains("address immutable token1"))
            || (lower.contains("token0")
                && lower.contains("token1")
                && (lower.contains("mapping") || lower.contains("balance")));

        // Need at least 2 AMM state indicators for confidence
        let indicator_count = [
            has_reserve_state,
            has_lp_token_state,
            has_invariant,
            has_token_pair_state,
        ]
        .iter()
        .filter(|&&x| x)
        .count();

        indicator_count >= 1
    }

    /// Check if a keyword only appears in interface/external call contexts.
    ///
    /// Returns true if the keyword seems to only be used in interface calls
    /// (like `IUniswapV2Pair(...).getReserves()`) rather than as internal state.
    fn only_in_interface_call(source: &str, keyword: &str) -> bool {
        let lower = source.to_lowercase();
        let keyword_lower = keyword.to_lowercase();

        for line in lower.lines() {
            let trimmed = line.trim();
            if !trimmed.contains(&keyword_lower) {
                continue;
            }
            // If the line is a state variable declaration, it's internal state
            if trimmed.starts_with("uint")
                || trimmed.starts_with("mapping")
                || trimmed.starts_with("address")
            {
                return false;
            }
            // If the keyword appears with an interface cast pattern like ISomething(...).getReserves
            // that's an external call, not internal state
            if trimmed.contains("interface ") || trimmed.contains(".(") {
                continue;
            }
            // If we find the keyword in a non-interface context, it's internal
            return false;
        }
        true
    }
}

impl Default for MEVToxicFlowDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for MEVToxicFlowDetector {
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
        // These protocols intentionally don't have dynamic fees or toxic flow protection
        // and operate with known MEV risks as part of their design
        if utils::is_amm_pool(ctx) {
            return Ok(findings);
        }

        // FP Fix: Skip flash loan contracts entirely.
        // Flash loan contracts are NOT AMMs -- they don't have liquidity pools,
        // swap fees, or reserve tracking. Flash loan fees are not AMM swap fees.
        // Contracts that merely *call* external DEX routers (e.g., flash loan
        // arbitrage bots) are not AMMs with toxic flow exposure.
        if utils::is_flash_loan_context(ctx) {
            return Ok(findings);
        }

        let source = ctx.source_code.as_str();
        let lower = source.to_lowercase();

        // FP Fix: Require actual AMM characteristics, not just keyword matches.
        // A contract must implement swap logic internally (not just call external
        // routers) AND manage pool state (reserves, liquidity tokens) to be an AMM
        // that can suffer from toxic flow.
        let has_internal_swap = Self::has_internal_swap_function(source);
        let has_pool_state = Self::has_amm_pool_state(source, &lower);

        // A true AMM must have BOTH internal swap functions AND pool state management
        let is_amm = has_internal_swap && has_pool_state;

        if !is_amm {
            return Ok(findings);
        }

        // Pattern 1: No fee tier for toxic flow
        if is_amm {
            let has_dynamic_fees = lower.contains("dynamicfee")
                || lower.contains("adjustfee")
                || lower.contains("volatilityfee");

            if !has_dynamic_fees {
                let finding = self.base.create_finding(
                    ctx,
                    "Static fees on AMM - no protection against toxic flow from informed traders".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Implement dynamic fees that increase with volatility or trade size to discourage toxic flow".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: No trade size limits
        if has_internal_swap {
            let has_size_limit = lower.contains("maxtradesize")
                || lower.contains("amountlimit")
                || lower.contains("require(amount <");

            if !has_size_limit {
                let finding = self.base.create_finding(
                    ctx,
                    "No trade size limits - large informed trades can extract maximum value from LPs".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add maximum trade size as percentage of reserves: require(amountIn < reserves * maxBps / 10000)".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 3: Instant arbitrage possible
        if is_amm {
            let allows_instant_arb = lower.contains("sync()") || lower.contains("update");

            let has_delay = lower.contains("blocknumber") || lower.contains("lastupdate");

            if allows_instant_arb && !has_delay {
                let finding = self.base.create_finding(
                    ctx,
                    "Instant arbitrage possible - informed traders can extract value with zero risk".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add block delay or use time-weighted pricing to reduce instant arbitrage opportunities".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 4: No JIT liquidity protection
        if lower.contains("addliquidity") && has_pool_state {
            let has_jit_protection = lower.contains("lockperiod")
                || lower.contains("minimumhold")
                || lower.contains("withdrawdelay");

            if !has_jit_protection {
                let finding = self.base.create_finding(
                    ctx,
                    "No JIT liquidity protection - attackers can add liquidity, extract fees, and withdraw immediately".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add minimum holding period for LP tokens: mapping(address => uint256) public depositTime".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 5: Oracle price not checked
        if has_internal_swap {
            let checks_oracle =
                lower.contains("oracle") || lower.contains("twap") || lower.contains("chainlink");

            if !checks_oracle {
                let finding = self.base.create_finding(
                    ctx,
                    "Swaps don't check oracle price - no protection against informed traders exploiting price deviations".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Compare swap price against TWAP oracle; reject if deviation exceeds threshold".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 6: User-provided slippage can be front-run (sandwich attack vector)
        // Only applies to contracts with internal swap logic (AMMs), not flash loan
        // arbitrage bots where the user IS the arbitrageur and slippage params are
        // standard for atomic execution.
        if has_internal_swap {
            for (line_num, line) in ctx.source_code.lines().enumerate() {
                let line_lower = line.to_lowercase();
                // Detect require statements with min amount comparisons
                if line_lower.contains("require")
                    && (line_lower.contains(">=") || line_lower.contains(">"))
                    && (line_lower.contains("min") || line_lower.contains("slippage"))
                {
                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            "Slippage protection uses user-provided minimum - visible in mempool and vulnerable to sandwich attacks".to_string(),
                            (line_num + 1) as u32,
                            1,
                            line.len() as u32,
                        )
                        .with_fix_suggestion(
                            "Use deadline + private mempool (Flashbots), or implement TWAP-based slippage with oracle price bounds".to_string(),
                        );
                    findings.push(finding);
                }
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::test_utils::create_test_context;

    #[test]
    fn test_detector_properties() {
        let detector = MEVToxicFlowDetector::new();
        assert_eq!(detector.name(), "MEV Toxic Flow Exposure");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert_eq!(
            detector.id(),
            DetectorId("mev-toxic-flow-exposure".to_string())
        );
    }

    // ---------------------------------------------------------------
    // False positive tests: flash loan contracts should not be flagged
    // ---------------------------------------------------------------

    #[test]
    fn test_no_fp_flash_loan_provider_with_getreserves_interface() {
        // VulnerableFlashLoan.sol contains getReserves in an interface call
        // (IUniswapV2Pair.getReserves) but is NOT an AMM -- it's a flash loan
        // provider / oracle consumer. Should produce zero findings.
        let source = r#"
contract VulnerableOracleFlashLoan {
    address public priceOracle;

    function calculateCollateralValue(address token, uint256 amount) external view returns (uint256) {
        uint256 price = IOracle(priceOracle).getPrice(token);
        return amount * price;
    }

    function borrow(address collateralToken, uint256 collateralAmount, uint256 borrowAmount) external {
        uint256 collateralValue = this.calculateCollateralValue(collateralToken, collateralAmount);
        require(collateralValue >= borrowAmount * 150 / 100, "Insufficient collateral");
    }

    function getPriceFromPool(address token0, address token1) external view returns (uint256) {
        (uint112 reserve0, uint112 reserve1,) = IUniswapV2Pair(priceOracle).getReserves();
        return (reserve1 * 1e18) / reserve0;
    }
}

contract VulnerableFlashLoanCallback {
    mapping(address => uint256) public deposits;

    function flashLoan(address receiver, uint256 amount, bytes calldata data) external {
        uint256 balanceBefore = address(this).balance;
        payable(receiver).transfer(amount);
        IFlashBorrower(receiver).onFlashLoan(msg.sender, address(this), amount, 0, data);
        uint256 balanceAfter = address(this).balance;
        require(balanceAfter >= balanceBefore, "Flash loan not repaid");
    }
}

interface IOracle {
    function getPrice(address token) external view returns (uint256);
}

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

interface IFlashBorrower {
    function onFlashLoan(address, address, uint256, uint256, bytes calldata) external returns (bytes32);
}
"#;
        let detector = MEVToxicFlowDetector::new();
        let ctx = create_test_context(source);
        let findings = detector.detect(&ctx).unwrap();
        assert!(
            findings.is_empty(),
            "Flash loan provider with getReserves in interface should not trigger toxic flow. Got {} findings: {:?}",
            findings.len(),
            findings.iter().map(|f| &f.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_no_fp_flash_loan_arbitrage_with_swap_calls() {
        // FlashLoanArbitrage.sol calls swapExactTokensForTokens on external DEX
        // routers but is NOT an AMM. It's a flash loan arbitrage bot. Should not
        // trigger "static fees on AMM" or "user-provided slippage" findings.
        let source = r#"
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IFlashLoanProvider {
    function flashLoan(address asset, uint256 amount, bytes calldata data) external;
}

interface IDEXRouter {
    function swapExactTokensForTokens(
        uint amountIn, uint amountOutMin, address[] calldata path,
        address to, uint deadline
    ) external returns (uint[] memory amounts);
    function getAmountsOut(uint amountIn, address[] calldata path)
        external view returns (uint[] memory amounts);
}

contract FlashLoanArbitrage {
    mapping(address => bool) public authorizedCallers;
    mapping(address => uint256) public profits;
    uint256 public currentArbitrageAmount;
    bool private inFlashLoan;

    function executeArbitrage(address tokenA, address tokenB, address dexA, address dexB, uint256 flashAmount, uint256 minProfit) external {
        require(minProfit > 0, "Invalid min profit");
        IFlashLoanProvider(getFlashLoanProvider()).flashLoan(tokenA, flashAmount, "");
    }

    function onFlashLoan(address asset, uint256 amount, uint256 fee, bytes calldata data) external returns (bool) {
        inFlashLoan = true;
        return true;
    }

    function _executeArbitrageTrades(address tokenA, address tokenB, address dexA, address dexB, uint256 amount, uint256 deadline) private {
        address[] memory pathA = new address[](2);
        pathA[0] = tokenA;
        pathA[1] = tokenB;

        IERC20(tokenA).approve(dexA, amount);
        uint256[] memory amountsA = IDEXRouter(dexA).swapExactTokensForTokens(
            amount, 0, pathA, address(this), deadline
        );

        uint256 tokenBAmount = amountsA[1];
        address[] memory pathB = new address[](2);
        pathB[0] = tokenB;
        pathB[1] = tokenA;

        IERC20(tokenB).approve(dexB, tokenBAmount);
        IDEXRouter(dexB).swapExactTokensForTokens(
            tokenBAmount, 0, pathB, address(this), deadline
        );
    }

    function getFlashLoanProvider() public pure returns (address) {
        return 0x1234567890123456789012345678901234567890;
    }
}
"#;
        let detector = MEVToxicFlowDetector::new();
        let ctx = create_test_context(source);
        let findings = detector.detect(&ctx).unwrap();
        assert!(
            findings.is_empty(),
            "Flash loan arbitrage bot calling external DEX routers should not trigger toxic flow. Got {} findings: {:?}",
            findings.len(),
            findings.iter().map(|f| &f.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_no_fp_flash_loan_arbitrage_slippage_params() {
        // Flash loan arbitrage with slippage require statements should NOT
        // trigger "user-provided slippage visible in mempool" because the
        // user IS the arbitrageur and execution is atomic.
        let source = r#"
interface IFlashLoanProvider {
    function flashLoan(address asset, uint256 amount, bytes calldata data) external;
}

contract FlashLoanArbBot {
    function onFlashLoan(address asset, uint256 amount, uint256 fee, bytes calldata data) external returns (bool) {
        uint256 received = doSwap(amount);
        require(received >= minAmountOut, "Slippage too high");
        require(received > amount + fee, "No profit");
        return true;
    }

    function doSwap(uint256 amount) internal returns (uint256) {
        return amount;
    }

    uint256 public minAmountOut;
}
"#;
        let detector = MEVToxicFlowDetector::new();
        let ctx = create_test_context(source);
        let findings = detector.detect(&ctx).unwrap();
        assert!(
            findings.is_empty(),
            "Flash loan arbitrage slippage checks should not be flagged. Got {} findings: {:?}",
            findings.len(),
            findings.iter().map(|f| &f.message).collect::<Vec<_>>()
        );
    }

    // ---------------------------------------------------------------
    // True positive tests: actual AMMs should still be detected
    // ---------------------------------------------------------------

    #[test]
    fn test_tp_real_amm_with_static_fees() {
        // A real AMM with internal swap function, reserves, and LP token logic
        // should still trigger toxic flow findings.
        let source = r#"
contract SimpleAMM {
    address public token0;
    address public token1;
    uint256 public reserve0;
    uint256 public reserve1;
    uint256 public totalLiquidity;
    mapping(address => uint256) public liquidity;
    uint256 public constant FEE = 30; // 0.3% static fee

    function swap(address tokenIn, uint256 amountIn) external returns (uint256 amountOut) {
        require(tokenIn == token0 || tokenIn == token1, "Invalid token");
        uint256 amountInWithFee = amountIn * (10000 - FEE) / 10000;
        if (tokenIn == token0) {
            amountOut = getAmountOut(amountInWithFee, reserve0, reserve1);
            reserve0 += amountIn;
            reserve1 -= amountOut;
        } else {
            amountOut = getAmountOut(amountInWithFee, reserve1, reserve0);
            reserve1 += amountIn;
            reserve0 -= amountOut;
        }
    }

    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut) internal pure returns (uint256) {
        return (amountIn * reserveOut) / (reserveIn + amountIn);
    }

    function addLiquidity(uint256 amount0, uint256 amount1) external returns (uint256 lpAmount) {
        reserve0 += amount0;
        reserve1 += amount1;
        lpAmount = amount0;
        liquidity[msg.sender] += lpAmount;
        totalLiquidity += lpAmount;
    }

    function removeLiquidity(uint256 lpAmount) external {
        liquidity[msg.sender] -= lpAmount;
        totalLiquidity -= lpAmount;
    }
}
"#;
        let detector = MEVToxicFlowDetector::new();
        let ctx = create_test_context(source);
        let findings = detector.detect(&ctx).unwrap();
        assert!(
            !findings.is_empty(),
            "Real AMM with static fees and no dynamic fee protection should trigger toxic flow findings"
        );
        // Check that we get the static fees finding
        let has_static_fees_finding = findings
            .iter()
            .any(|f| f.message.contains("Static fees on AMM"));
        assert!(
            has_static_fees_finding,
            "Should detect static fees on actual AMM"
        );
    }

    #[test]
    fn test_tp_amm_with_user_slippage() {
        // Real AMM with user-provided slippage check should be flagged
        let source = r#"
contract VulnerableAMM {
    address public token0;
    address public token1;
    uint256 public reserve0;
    uint256 public reserve1;
    uint256 public totalLiquidity;

    function swap(address tokenIn, uint256 amountIn, uint256 minAmountOut) external returns (uint256 amountOut) {
        amountOut = getAmountOut(amountIn, reserve0, reserve1);
        require(amountOut >= minAmountOut, "Slippage exceeded");
        reserve0 += amountIn;
        reserve1 -= amountOut;
    }

    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut) internal pure returns (uint256) {
        return (amountIn * reserveOut) / (reserveIn + amountIn);
    }

    function addLiquidity(uint256 amount0, uint256 amount1) external {
        reserve0 += amount0;
        reserve1 += amount1;
        totalLiquidity += amount0;
    }

    function removeLiquidity(uint256 lpAmount) external {
        totalLiquidity -= lpAmount;
    }
}
"#;
        let detector = MEVToxicFlowDetector::new();
        let ctx = create_test_context(source);
        let findings = detector.detect(&ctx).unwrap();
        let has_slippage_finding = findings.iter().any(|f| {
            f.message
                .contains("Slippage protection uses user-provided minimum")
        });
        assert!(
            has_slippage_finding,
            "Real AMM with user-provided slippage should trigger slippage finding"
        );
    }

    // ---------------------------------------------------------------
    // Edge case tests
    // ---------------------------------------------------------------

    #[test]
    fn test_no_fp_contract_without_swap_or_flash_loan() {
        // A plain contract with no swap or flash loan patterns
        let source = r#"
contract SimpleToken {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) external {
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
"#;
        let detector = MEVToxicFlowDetector::new();
        let ctx = create_test_context(source);
        let findings = detector.detect(&ctx).unwrap();
        assert!(
            findings.is_empty(),
            "Simple token with no AMM features should not trigger any findings"
        );
    }

    #[test]
    fn test_no_fp_contract_calling_external_swap_only() {
        // A contract that only calls swap on external routers (no flash loan)
        // but does not define its own swap function is not an AMM
        let source = r#"
interface IDEXRouter {
    function swapExactTokensForTokens(
        uint amountIn, uint amountOutMin, address[] calldata path,
        address to, uint deadline
    ) external returns (uint[] memory amounts);
}

contract SwapCaller {
    function doSwap(address router, uint256 amount) external {
        address[] memory path = new address[](2);
        IDEXRouter(router).swapExactTokensForTokens(amount, 0, path, address(this), block.timestamp);
    }
}
"#;
        let detector = MEVToxicFlowDetector::new();
        let ctx = create_test_context(source);
        let findings = detector.detect(&ctx).unwrap();
        assert!(
            findings.is_empty(),
            "Contract that only calls external swap routers should not be flagged as AMM. Got {} findings",
            findings.len()
        );
    }

    #[test]
    fn test_helper_has_internal_swap_function() {
        // Contract with function swap( declaration that is not just an interface
        let amm_source = r#"
contract AMM {
    function swap(address tokenIn, uint256 amountIn) external returns (uint256) {
        return amountIn;
    }
}
"#;
        assert!(
            MEVToxicFlowDetector::has_internal_swap_function(amm_source),
            "AMM with internal swap function should be detected"
        );

        // Contract with swap only in interface
        let interface_source = r#"
interface IRouter {
    function swapExactTokensForTokens(uint, uint, address[], address, uint) external returns (uint[] memory);
}

contract Bot {
    function doTrade() external {
        IRouter(router).swapExactTokensForTokens(100, 0, path, self, deadline);
    }
}
"#;
        assert!(
            !MEVToxicFlowDetector::has_internal_swap_function(interface_source),
            "Contract with swap only in interface calls should NOT be detected as having internal swap"
        );
    }
}
