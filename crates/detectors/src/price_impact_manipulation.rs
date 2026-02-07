use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for price impact manipulation in DeFi swaps
///
/// Identifies swap/trade functions that lack adequate protection against large
/// trades causing excessive price impact and slippage.
///
/// **Context-aware FP reduction:**
/// - Skips view/pure functions (read-only, cannot be exploited)
/// - Skips internal/private functions (not directly callable)
/// - Recognizes AMM pool contracts with proper invariant checks
/// - Recognizes slippage protection patterns (minAmountOut, amountOutMin, etc.)
/// - Recognizes deadline checks as MEV/pinning protection
/// - Recognizes K-invariant validation as implicit price impact protection
/// - Counts cumulative protections: contracts with sufficient safeguards are not flagged
pub struct PriceImpactManipulationDetector {
    base: BaseDetector,
}

impl Default for PriceImpactManipulationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PriceImpactManipulationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("price-impact-manipulation".to_string()),
                "Price Impact Manipulation".to_string(),
                "Detects swap functions that don't protect against large trades causing excessive price impact and slippage".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }
}

impl Detector for PriceImpactManipulationDetector {
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


        // Contract-level check: if this is a well-formed AMM pool with proper
        // protections at the contract level, skip entirely. AMM pools ARE the
        // price mechanism; they protect via K-invariant, not trade size caps.
        if self.is_well_protected_amm_contract(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            if let Some(impact_issue) = self.check_price_impact(function, ctx) {
                let message = format!(
                    "Function '{}' vulnerable to price impact manipulation. {} \
                    Large trades without size limits or impact checks can drain liquidity, \
                    manipulate prices, and cause excessive slippage for other users.",
                    function.name.name, impact_issue
                );

                let finding = self
                    .base
                    .create_finding(
                        ctx,
                        message,
                        function.name.location.start().line() as u32,
                        function.name.location.start().column() as u32,
                        function.name.name.len() as u32,
                    )
                    .with_cwe(682) // CWE-682: Incorrect Calculation
                    .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                    .with_fix_suggestion(format!(
                        "Add price impact protection to '{}'. \
                    Implement maximum trade size limits (e.g., max 10% of pool), \
                    calculate and validate price impact percentage, \
                    enforce minimum output amounts with slippage tolerance, \
                    or split large trades across multiple blocks.",
                        function.name.name
                    ));

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

impl PriceImpactManipulationDetector {
    /// Check if the contract is a well-protected AMM pool that should be skipped entirely.
    ///
    /// AMM pool contracts (Uniswap V2 pairs, etc.) protect against price manipulation
    /// through the K-invariant check, not through explicit trade size caps. Flagging
    /// every swap function in a properly implemented AMM pool is a false positive.
    ///
    /// A well-protected AMM contract must have:
    /// 1. AMM pool structure (reserves, token pairs, swap+mint+burn)
    /// 2. K-invariant or equivalent price validation
    /// 3. At least one of: slippage protection, deadline checks, or reentrancy guard
    fn is_well_protected_amm_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = ctx.source_code.as_str();

        // Check if it is recognized as an AMM pool by the shared utility
        let is_amm = utils::is_amm_pool(ctx);

        // Also detect AMM-like contracts by structural indicators even if the
        // utility does not match (e.g. simplified pool implementations)
        let has_reserve_tracking = source.contains("reserve0") && source.contains("reserve1");
        let has_token_pair = source.contains("token0") && source.contains("token1");
        let has_swap_function = source.contains("function swap(");
        let has_liquidity_ops =
            source.contains("function mint(") && source.contains("function burn(");

        let is_amm_like = is_amm
            || (has_reserve_tracking && has_token_pair && has_swap_function && has_liquidity_ops);

        if !is_amm_like {
            return false;
        }

        // Must have K-invariant or equivalent price validation
        let has_k_invariant = source.contains("balance0 * balance1")
            || source.contains("balance0Adjusted * balance1Adjusted")
            || source.contains("_reserve0) * _reserve1")
            || source.contains("reserve0 * reserve1")
            || source.contains("x * y = k")
            || source.contains("InvariantViolation");

        if !has_k_invariant {
            return false;
        }

        // Must have at least one protective mechanism
        let has_slippage_protection = source.contains("minAmountOut")
            || source.contains("amountOutMin")
            || source.contains("minReturn")
            || source.contains("minOutput")
            || source.contains("SlippageExceeded");

        let has_deadline = source.contains("deadline")
            || source.contains("DeadlineExpired")
            || source.contains("validUntil")
            || source.contains("expiry");

        let has_reentrancy_guard = source.contains("nonReentrant")
            || source.contains("ReentrancyGuard")
            || source.contains("LOCKED")
            || source.contains("unlocked");

        has_slippage_protection || has_deadline || has_reentrancy_guard
    }

    /// Check for price impact manipulation vulnerabilities in a function.
    ///
    /// Uses a multi-layered approach:
    /// 1. Pre-filter: skip functions that cannot be exploited (view/pure, internal/private)
    /// 2. Identify: only analyze swap/trade functions
    /// 3. Evaluate protections: count how many protective patterns exist
    /// 4. Report: only flag functions with genuinely insufficient protection
    fn check_price_impact(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        // --- Pre-filter: skip functions that cannot be exploited ---

        // View/pure functions are read-only and cannot cause state changes,
        // so they cannot be used for price impact manipulation
        if function.mutability == ast::StateMutability::View
            || function.mutability == ast::StateMutability::Pure
        {
            return None;
        }

        // Internal/private functions are not directly callable by external actors
        if function.visibility == ast::Visibility::Internal
            || function.visibility == ast::Visibility::Private
        {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);
        let func_name_lower = function.name.name.to_lowercase();

        // --- Identify: only analyze swap/trade functions ---
        let is_swap_function = func_name_lower.contains("swap")
            || func_name_lower.contains("trade")
            || func_name_lower.contains("exchange")
            || func_source.contains("getAmountOut")
            || func_source.contains("swapExactTokensFor");

        if !is_swap_function {
            return None;
        }

        // --- Evaluate protections at the function level ---
        // Count protective patterns. A function with sufficient protections
        // should not be flagged.

        let has_slippage_protection = func_source.contains("minAmountOut")
            || func_source.contains("amountOutMin")
            || func_source.contains("minReturn")
            || func_source.contains("minOutput")
            || func_source.contains("SlippageExceeded")
            || func_source.contains("Slippage too high")
            || func_source.contains("require(amountOut >=");

        let has_deadline_check = func_source.contains("deadline")
            || func_source.contains("DeadlineExpired")
            || func_source.contains("validUntil")
            || func_source.contains("expiry");

        let has_invariant_check = func_source.contains("balance0Adjusted * balance1Adjusted")
            || func_source.contains("balance0 * balance1")
            || func_source.contains("InvariantViolation")
            || func_source.contains("x * y = k");

        let has_max_trade_size = func_source.contains("maxTradeSize")
            || func_source.contains("MAX_TRADE")
            || func_source.contains("require(amount <")
            || func_source.contains("require(amountIn <");

        let has_impact_calculation = func_source.contains("priceImpact")
            || func_source.contains("MAX_IMPACT")
            || func_source.contains("maxSlippage")
            || func_source.contains("require(impact");

        let has_reserve_bound_check = func_source.contains("/ reserve")
            || func_source.contains("* reserve")
            || func_source.contains("/ 100")
            || func_source.contains("percentage");

        let has_twap = func_source.contains("TWAP")
            || func_source.contains("twap")
            || func_source.contains("CumulativeLast")
            || func_source.contains("observe(");

        let has_deviation_check = func_source.contains("deviation")
            || func_source.contains("MAX_DEVIATION")
            || func_source.contains("circuit");

        // Count total protections
        let protection_count = [
            has_slippage_protection,
            has_deadline_check,
            has_invariant_check,
            has_max_trade_size,
            has_impact_calculation,
            has_reserve_bound_check,
            has_twap,
            has_deviation_check,
        ]
        .iter()
        .filter(|&&x| x)
        .count();

        // If the function has 2 or more protections, it is sufficiently protected.
        // A properly implemented swap with slippage + deadline, or slippage + invariant,
        // or invariant + deadline, etc. should not be flagged.
        if protection_count >= 2 {
            return None;
        }

        // If the function has at least one protection, it is partially protected.
        // Still skip if it has slippage protection (the most critical one) since
        // minAmountOut directly prevents price impact exploitation.
        if has_slippage_protection {
            return None;
        }

        // --- Report the most relevant missing protection ---

        if !has_max_trade_size && !has_reserve_bound_check && !has_invariant_check {
            return Some(
                "No maximum trade size limit enforced, allowing trades of any size \
                that can cause extreme price impact and drain pool liquidity"
                    .to_string(),
            );
        }

        if !has_impact_calculation
            && !func_source.contains("impact")
            && !func_source.contains("slippage")
            && !func_source.contains("price")
            && !func_source.contains("before")
            && !func_source.contains("after")
        {
            return Some(
                "No price impact calculation performed before executing trade, \
                users cannot assess cost and attackers can manipulate prices"
                    .to_string(),
            );
        }

        // Check for missing minimum output validation
        let has_output = func_source.contains("amountOut")
            || func_source.contains("output")
            || func_source.contains("return");

        if has_output && !has_slippage_protection {
            return Some(
                "No minimum output amount validation, users have no slippage protection \
                and can receive much less than expected"
                    .to_string(),
            );
        }

        // Missing deadline
        if !has_deadline_check {
            return Some(
                "No transaction deadline parameter, trades can be held and executed \
                when price moves against user (transaction pinning)"
                    .to_string(),
            );
        }

        // Pattern: Uses constant product formula without impact limits
        let uses_constant_product = func_source.contains("* reserve1")
            || func_source.contains("reserve0 * reserve1")
            || func_source.contains("x * y = k");

        if uses_constant_product && !has_impact_calculation && !has_slippage_protection {
            return Some(
                "Uses constant product formula (x*y=k) without maximum impact limits, \
                allowing trades that drastically move the price"
                    .to_string(),
            );
        }

        // Pattern: No multi-hop path validation
        let is_multi_hop = func_source.contains("path")
            || func_source.contains("route")
            || func_source.contains("[]");

        let lacks_path_validation = is_multi_hop
            && !func_source.contains("require(path.length")
            && !func_source.contains("MAX_HOPS")
            && !func_source.contains("validatePath");

        if lacks_path_validation {
            return Some(
                "Multi-hop swap path not validated for length or composition, \
                allowing complex routes that amplify price impact"
                    .to_string(),
            );
        }

        // Pattern: Explicit vulnerability marker
        if func_source.contains("VULNERABILITY")
            && (func_source.contains("price impact")
                || func_source.contains("slippage")
                || func_source.contains("large trade"))
        {
            return Some("Price impact manipulation vulnerability marker detected".to_string());
        }

        None
    }

    /// Get function source code
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::test_utils::{create_mock_ast_contract, create_mock_ast_function};

    #[test]
    fn test_detector_properties() {
        let detector = PriceImpactManipulationDetector::new();
        assert_eq!(detector.name(), "Price Impact Manipulation");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_well_protected_amm_contract_skipped() {
        let detector = PriceImpactManipulationDetector::new();
        let arena = ast::AstArena::new();

        // Source code mimicking safe_amm_pool.sol structure
        let source = r#"
contract SafeAMMPool is ReentrancyGuard {
    uint112 private reserve0;
    uint112 private reserve1;
    IERC20 public immutable token0;
    IERC20 public immutable token1;
    error SlippageExceeded();
    error DeadlineExpired();
    error InvariantViolation();

    function mint(address to) external nonReentrant returns (uint256 liquidity) {
        // mint logic
    }

    function burn(address to) external nonReentrant returns (uint256 amount0, uint256 amount1) {
        // burn logic
    }

    function swap(
        uint256 amount0Out,
        uint256 amount1Out,
        address to,
        uint256 minAmountOut,
        uint256 deadline
    ) external nonReentrant {
        if (block.timestamp > deadline) revert DeadlineExpired();
        if (totalOut < minAmountOut) revert SlippageExceeded();
        // K invariant check
        if (balance0Adjusted * balance1Adjusted < uint256(_reserve0) * _reserve1 * 1000000) {
            revert InvariantViolation();
        }
    }
}
"#;

        let contract = create_mock_ast_contract(&arena, "SafeAMMPool", vec![]);

        let ctx = AnalysisContext::new(
            &contract,
            semantic::SymbolTable::new(),
            source.to_string(),
            "test.sol".to_string(),
        );

        assert!(
            detector.is_well_protected_amm_contract(&ctx),
            "Should recognize safe AMM pool as well-protected"
        );
    }

    #[test]
    fn test_vulnerable_dex_not_skipped_at_contract_level() {
        let detector = PriceImpactManipulationDetector::new();
        let arena = ast::AstArena::new();

        // Source code mimicking VulnerableDEX -- no invariant, no slippage, no deadline
        let source = r#"
contract VulnerableDEX {
    IERC20 public tokenA;
    IERC20 public tokenB;
    uint256 public reserveA;
    uint256 public reserveB;

    function swap(uint256 amountIn, bool aToB) external {
        uint256 amountOut;
        if (aToB) {
            amountOut = amountIn * reserveB / reserveA;
            reserveA += amountIn;
            reserveB -= amountOut;
            tokenA.transferFrom(msg.sender, address(this), amountIn);
            tokenB.transfer(msg.sender, amountOut);
        }
    }
}
"#;

        let contract = create_mock_ast_contract(&arena, "VulnerableDEX", vec![]);

        let ctx = AnalysisContext::new(
            &contract,
            semantic::SymbolTable::new(),
            source.to_string(),
            "test.sol".to_string(),
        );

        assert!(
            !detector.is_well_protected_amm_contract(&ctx),
            "Should NOT recognize vulnerable DEX as well-protected (no K invariant, no protections)"
        );
    }

    #[test]
    fn test_view_function_skipped() {
        let detector = PriceImpactManipulationDetector::new();
        let arena = ast::AstArena::new();

        let source = r#"
contract Pool {
    function getTWAP() external view returns (uint256) {
        // TWAP calculation using swap observations
        return price;
    }
}
"#;

        let mut func = create_mock_ast_function(
            &arena,
            "getTWAP",
            ast::Visibility::External,
            ast::StateMutability::View,
        );
        func.body = Some(ast::Block::new(&arena, ast::SourceLocation::default()));

        let contract = create_mock_ast_contract(&arena, "Pool", vec![]);

        let ctx = AnalysisContext::new(
            &contract,
            semantic::SymbolTable::new(),
            source.to_string(),
            "test.sol".to_string(),
        );

        assert!(
            detector.check_price_impact(&func, &ctx).is_none(),
            "View functions should not be flagged"
        );
    }

    #[test]
    fn test_pure_function_skipped() {
        let detector = PriceImpactManipulationDetector::new();
        let arena = ast::AstArena::new();

        let source = r#"
contract Pool {
    function calculateSwapOutput(uint256 amountIn) external pure returns (uint256) {
        return amountIn * 997 / 1000;
    }
}
"#;

        let mut func = create_mock_ast_function(
            &arena,
            "calculateSwapOutput",
            ast::Visibility::External,
            ast::StateMutability::Pure,
        );
        func.body = Some(ast::Block::new(&arena, ast::SourceLocation::default()));

        let contract = create_mock_ast_contract(&arena, "Pool", vec![]);

        let ctx = AnalysisContext::new(
            &contract,
            semantic::SymbolTable::new(),
            source.to_string(),
            "test.sol".to_string(),
        );

        assert!(
            detector.check_price_impact(&func, &ctx).is_none(),
            "Pure functions should not be flagged"
        );
    }

    #[test]
    fn test_internal_function_skipped() {
        let detector = PriceImpactManipulationDetector::new();
        let arena = ast::AstArena::new();

        let source = r#"
contract Pool {
    function _internalSwap(uint256 amountIn) internal {
        // swap logic
    }
}
"#;

        let mut func = create_mock_ast_function(
            &arena,
            "_internalSwap",
            ast::Visibility::Internal,
            ast::StateMutability::NonPayable,
        );
        func.body = Some(ast::Block::new(&arena, ast::SourceLocation::default()));

        let contract = create_mock_ast_contract(&arena, "Pool", vec![]);

        let ctx = AnalysisContext::new(
            &contract,
            semantic::SymbolTable::new(),
            source.to_string(),
            "test.sol".to_string(),
        );

        assert!(
            detector.check_price_impact(&func, &ctx).is_none(),
            "Internal functions should not be flagged"
        );
    }

    #[test]
    fn test_non_swap_function_skipped() {
        let detector = PriceImpactManipulationDetector::new();
        let arena = ast::AstArena::new();

        let source = r#"
contract Token {
    function transfer(address to, uint256 amount) external returns (bool) {
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }
}
"#;

        let mut func = create_mock_ast_function(
            &arena,
            "transfer",
            ast::Visibility::External,
            ast::StateMutability::NonPayable,
        );
        func.body = Some(ast::Block::new(&arena, ast::SourceLocation::default()));

        let contract = create_mock_ast_contract(&arena, "Token", vec![]);

        let ctx = AnalysisContext::new(
            &contract,
            semantic::SymbolTable::new(),
            source.to_string(),
            "test.sol".to_string(),
        );

        assert!(
            detector.check_price_impact(&func, &ctx).is_none(),
            "Non-swap functions (transfer) should not be flagged"
        );
    }

    #[test]
    fn test_swap_with_slippage_protection_skipped() {
        let detector = PriceImpactManipulationDetector::new();
        let arena = ast::AstArena::new();

        // Source where line 1 (0-indexed) has the function
        let source = "contract SecureDEX {\n\
            function swap(uint256 amountIn, uint256 minAmountOut, bool aToB) external returns (uint256) {\n\
                uint256 amountOut = amountIn * reserveB / reserveA;\n\
                require(amountOut >= minAmountOut, \"Slippage too high\");\n\
                return amountOut;\n\
            }\n\
        }";

        // Use function location matching lines 1-5 (0-indexed) in source
        let start_pos = ast::Position::new(1, 1, 0);
        let end_pos = ast::Position::new(6, 1, 0);
        let loc =
            ast::SourceLocation::new(std::path::PathBuf::from("test.sol"), start_pos, end_pos);
        let ident = ast::Identifier::new("swap", loc.clone());

        let mut func = ast::Function::new(&arena, ident, loc);
        func.mutability = ast::StateMutability::NonPayable;
        func.visibility = ast::Visibility::External;
        func.body = Some(ast::Block::new(&arena, ast::SourceLocation::default()));

        let contract = create_mock_ast_contract(&arena, "SecureDEX", vec![]);

        let ctx = AnalysisContext::new(
            &contract,
            semantic::SymbolTable::new(),
            source.to_string(),
            "test.sol".to_string(),
        );

        assert!(
            detector.check_price_impact(&func, &ctx).is_none(),
            "Swap with slippage protection (minAmountOut) should not be flagged"
        );
    }

    #[test]
    fn test_swap_with_deadline_and_invariant_skipped() {
        let detector = PriceImpactManipulationDetector::new();
        let arena = ast::AstArena::new();

        // Function with deadline + K invariant (2 protections = skip)
        let source = "contract Pool {\n\
            function swap(uint256 amount0Out, uint256 amount1Out, address to, uint256 deadline) external {\n\
                require(block.timestamp <= deadline, \"Expired\");\n\
                // transfer tokens\n\
                // K invariant check\n\
                require(balance0 * balance1 >= _reserve0 * _reserve1, \"K\");\n\
            }\n\
        }";

        let start_pos = ast::Position::new(1, 1, 0);
        let end_pos = ast::Position::new(7, 1, 0);
        let loc =
            ast::SourceLocation::new(std::path::PathBuf::from("test.sol"), start_pos, end_pos);
        let ident = ast::Identifier::new("swap", loc.clone());

        let mut func = ast::Function::new(&arena, ident, loc);
        func.mutability = ast::StateMutability::NonPayable;
        func.visibility = ast::Visibility::External;
        func.body = Some(ast::Block::new(&arena, ast::SourceLocation::default()));

        let contract = create_mock_ast_contract(&arena, "Pool", vec![]);

        let ctx = AnalysisContext::new(
            &contract,
            semantic::SymbolTable::new(),
            source.to_string(),
            "test.sol".to_string(),
        );

        assert!(
            detector.check_price_impact(&func, &ctx).is_none(),
            "Swap with deadline + invariant (2 protections) should not be flagged"
        );
    }

    #[test]
    fn test_vulnerable_swap_no_protections_flagged() {
        let detector = PriceImpactManipulationDetector::new();
        let arena = ast::AstArena::new();

        // Vulnerable swap: no slippage, no deadline, no invariant
        let source = "contract VulnerableDEX {\n\
            function swap(uint256 amountIn, bool aToB) external {\n\
                uint256 amountOut;\n\
                amountOut = amountIn * reserveB / reserveA;\n\
                tokenA.transferFrom(msg.sender, address(this), amountIn);\n\
                tokenB.transfer(msg.sender, amountOut);\n\
            }\n\
        }";

        let start_pos = ast::Position::new(1, 1, 0);
        let end_pos = ast::Position::new(7, 1, 0);
        let loc =
            ast::SourceLocation::new(std::path::PathBuf::from("test.sol"), start_pos, end_pos);
        let ident = ast::Identifier::new("swap", loc.clone());

        let mut func = ast::Function::new(&arena, ident, loc);
        func.mutability = ast::StateMutability::NonPayable;
        func.visibility = ast::Visibility::External;
        func.body = Some(ast::Block::new(&arena, ast::SourceLocation::default()));

        let contract = create_mock_ast_contract(&arena, "VulnerableDEX", vec![]);

        let ctx = AnalysisContext::new(
            &contract,
            semantic::SymbolTable::new(),
            source.to_string(),
            "test.sol".to_string(),
        );

        let result = detector.check_price_impact(&func, &ctx);
        assert!(
            result.is_some(),
            "Vulnerable swap with no protections should be flagged"
        );
    }
}
