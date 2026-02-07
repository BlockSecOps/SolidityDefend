use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for missing input parameter validation
pub struct MissingInputValidationDetector {
    base: BaseDetector,
}

impl Default for MissingInputValidationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MissingInputValidationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("missing-input-validation".to_string()),
                "Missing Input Validation".to_string(),
                "Detects functions missing critical input parameter validation like zero address checks or bounds validation".to_string(),
                vec![DetectorCategory::Validation],
                Severity::Medium,
            ),
        }
    }
}

impl Detector for MissingInputValidationDetector {
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

        for function in ctx.get_functions() {
            if let Some(validation_issue) = self.check_missing_validation(function, ctx) {
                let message = format!(
                    "Function '{}' missing input validation. {} \
                    Missing validation can lead to unexpected behavior, zero address transfers, or invalid state.",
                    function.name.name, validation_issue
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
                    .with_cwe(20) // CWE-20: Improper Input Validation
                    .with_cwe(1284) // CWE-1284: Improper Validation of Specified Quantity in Input
                    .with_fix_suggestion(format!(
                        "Add input validation to '{}'. \
                    Implement: (1) Zero address checks for address parameters, \
                    (2) Bounds validation for numeric inputs, \
                    (3) Array length validation, \
                    (4) require() statements at function start, \
                    (5) OpenZeppelin Address library for address validation.",
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

impl MissingInputValidationDetector {
    fn check_missing_validation(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        // Skip view/pure functions: they cannot modify state, so missing
        // input validation is informational at best and not a security risk.
        if matches!(
            function.mutability,
            ast::StateMutability::View | ast::StateMutability::Pure
        ) {
            return None;
        }

        // Skip internal/private functions: they are only callable from
        // within the contract or derived contracts, where the caller is
        // expected to have already validated inputs.
        if matches!(
            function.visibility,
            ast::Visibility::Internal | ast::Visibility::Private
        ) {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);
        let func_name = &function.name.name;

        // Detect whether the function body contains any form of input validation.
        // This includes require(), revert statements, assert(), and if-revert patterns.
        let has_any_validation = self.source_has_validation(&func_source);

        // Detect AMM pool patterns: functions that enforce K-invariant or use
        // balance-based accounting inherently validate their numeric inputs
        // through the invariant check rather than explicit per-parameter checks.
        let is_amm_pattern = self.is_amm_invariant_pattern(&func_source);

        // Pattern 1: Function signature has address parameter but no validation
        if self.has_address_param_in_signature(&func_source) {
            let has_address_validation = func_source.contains("!= address(0)")
                || func_source.contains("== address(0)")
                || func_source.contains("Address.isContract")
                || has_any_validation
                || is_amm_pattern;

            if !has_address_validation && self.is_critical_function(func_name) {
                return Some(
                    "Critical function with address parameter lacks zero address validation"
                        .to_string(),
                );
            }
        }

        // Pattern 2: Transfer/withdraw functions without amount validation
        if (func_name.contains("transfer") || func_name.contains("withdraw"))
            && func_source.contains("uint")
        {
            let has_amount_check = has_any_validation
                || func_source.contains("amount > 0")
                || func_source.contains("value > 0")
                || func_source.contains("amount != 0")
                || func_source.contains("value != 0")
                || is_amm_pattern;

            if !has_amount_check {
                return Some("Transfer/withdraw function lacks amount validation".to_string());
            }
        }

        // Pattern 3: Array parameter without length check
        if func_source.contains("memory") && func_source.contains("[]") {
            let has_length_check = func_source.contains(".length")
                && (func_source.contains("require") || func_source.contains("if"));

            if !has_length_check && self.is_critical_function(func_name) {
                return Some("Function with array parameter lacks length validation".to_string());
            }
        }

        None
    }

    /// Check whether the function source contains any form of input validation.
    /// Recognizes: require(), revert (custom errors and string), assert(),
    /// if-conditions with revert/require, and modifier-based guards.
    fn source_has_validation(&self, func_source: &str) -> bool {
        // Direct validation statements
        if func_source.contains("require(") || func_source.contains("assert(") {
            return true;
        }

        // Custom error reverts: `revert SomeError()` or `revert("...")`
        if func_source.contains("revert ") || func_source.contains("revert(") {
            return true;
        }

        // if-condition followed by revert (common Solidity 0.8.4+ pattern)
        if func_source.contains("if (") || func_source.contains("if(") {
            // If there are if-statements combined with revert/require/return,
            // that constitutes input validation
            if func_source.contains("revert")
                || func_source.contains("require")
                || func_source.contains("return")
            {
                return true;
            }
        }

        false
    }

    /// Detect AMM pool patterns that inherently validate inputs through
    /// K-invariant enforcement. When a swap function checks that
    /// `x * y >= k` (the constant product formula), individual parameter
    /// bounds are implicitly validated by the invariant.
    fn is_amm_invariant_pattern(&self, func_source: &str) -> bool {
        // K-invariant pattern: balance * balance compared against reserve product
        let has_invariant_check = func_source.contains("Invariant")
            || func_source.contains("invariant")
            || (func_source.contains("reserve") && func_source.contains("balance"));

        // Common AMM patterns: fee-adjusted balance checks
        let has_fee_adjusted = func_source.contains("Adjusted")
            || func_source.contains("adjusted")
            || (func_source.contains("* 1000") && func_source.contains("* 3"));

        // Uniswap-style getAmountOut / K formula
        let has_k_formula = func_source.contains("getAmountOut")
            || func_source.contains("getAmountIn")
            || func_source.contains("_reserve0") && func_source.contains("_reserve1");

        has_invariant_check || has_fee_adjusted || has_k_formula
    }

    /// Check whether the function signature (not the body or returns) contains
    /// an address parameter. This avoids matching `returns (address ...)`.
    fn has_address_param_in_signature(&self, func_source: &str) -> bool {
        // Find the function signature portion before the body
        // Look for address parameters in the parameter list, not in returns
        let lines: Vec<&str> = func_source.lines().collect();
        let mut in_params = false;
        let mut past_returns = false;
        let mut paren_depth: i32 = 0;

        for line in &lines {
            let trimmed = line.trim();

            // Track if we're inside the function parameter list
            if trimmed.starts_with("function ") || trimmed.contains("function ") {
                in_params = true;
            }

            if in_params {
                for ch in trimmed.chars() {
                    if ch == '(' {
                        paren_depth += 1;
                    } else if ch == ')' {
                        paren_depth -= 1;
                        if paren_depth == 0 {
                            in_params = false;
                            break;
                        }
                    }
                }

                // Check for "returns" keyword -- parameters after this are return values
                if trimmed.contains("returns") {
                    past_returns = true;
                }

                // Only flag address params that are in the input parameter list
                if !past_returns && trimmed.contains("address ") {
                    return true;
                }
            }

            // Once we hit the function body opening brace, stop scanning signature
            if trimmed.contains('{') && !in_params {
                break;
            }
        }

        false
    }

    fn is_critical_function(&self, func_name: &str) -> bool {
        let critical_names = [
            "transfer",
            "transferFrom",
            "approve",
            "mint",
            "burn",
            "withdraw",
            "deposit",
            "swap",
            "stake",
            "unstake",
            "claim",
            "redeem",
            "liquidate",
            "borrow",
            "repay",
        ];

        let name_lower = func_name.to_lowercase();
        critical_names
            .iter()
            .any(|&critical| name_lower.contains(critical))
    }

    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            let raw_source = source_lines[start..=end].join("\n");
            // Clean source to avoid FPs from comments/strings
            utils::clean_source_for_search(&raw_source)
        } else {
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = MissingInputValidationDetector::new();
        assert_eq!(detector.name(), "Missing Input Validation");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_source_has_validation_require() {
        let detector = MissingInputValidationDetector::new();
        assert!(detector.source_has_validation("require(amount > 0);"));
        assert!(detector.source_has_validation("require(msg.sender == owner, \"not owner\");"));
    }

    #[test]
    fn test_source_has_validation_revert() {
        let detector = MissingInputValidationDetector::new();
        // Custom error revert (Solidity 0.8.4+)
        assert!(detector.source_has_validation("if (amount == 0) revert InsufficientAmount();"));
        // String revert
        assert!(detector.source_has_validation("revert(\"invalid input\");"));
        // Bare revert with custom error
        assert!(detector.source_has_validation("revert InsufficientLiquidity();"));
    }

    #[test]
    fn test_source_has_validation_if_revert_pattern() {
        let detector = MissingInputValidationDetector::new();
        let source = "if (block.timestamp > deadline) { revert DeadlineExpired(); }";
        assert!(detector.source_has_validation(source));
    }

    #[test]
    fn test_source_has_no_validation() {
        let detector = MissingInputValidationDetector::new();
        assert!(!detector.source_has_validation("balances[msg.sender] -= amount;"));
        assert!(!detector.source_has_validation("token.transfer(to, amount);"));
    }

    #[test]
    fn test_amm_invariant_pattern_detected() {
        let detector = MissingInputValidationDetector::new();

        // K-invariant with reserve/balance pattern
        let source = "uint256 balance0Adjusted = balance0 * 1000 - amount0In * 3;\n\
                       if (balance0Adjusted * balance1Adjusted < uint256(_reserve0) * _reserve1 * 1000000) {\n\
                           revert InvariantViolation();\n\
                       }";
        assert!(detector.is_amm_invariant_pattern(source));

        // Uniswap-style reserves
        let source2 = "uint112 _reserve0 = reserve0; uint112 _reserve1 = reserve1;";
        assert!(detector.is_amm_invariant_pattern(source2));
    }

    #[test]
    fn test_amm_invariant_pattern_not_detected() {
        let detector = MissingInputValidationDetector::new();
        let source = "uint256 amount = balances[msg.sender]; token.transfer(to, amount);";
        assert!(!detector.is_amm_invariant_pattern(source));
    }

    #[test]
    fn test_has_address_param_in_signature() {
        let detector = MissingInputValidationDetector::new();

        // Address in parameters
        let source = "function swap(uint256 amount, address to) external {";
        assert!(detector.has_address_param_in_signature(source));

        // Address only in returns -- should NOT match
        let source2 = "function getOwner() external returns (address owner) {";
        assert!(!detector.has_address_param_in_signature(source2));
    }

    #[test]
    fn test_has_address_param_multiline_signature() {
        let detector = MissingInputValidationDetector::new();

        let source = "function swap(\n\
                           uint256 amount0Out,\n\
                           uint256 amount1Out,\n\
                           address to,\n\
                           uint256 minAmountOut,\n\
                           uint256 deadline\n\
                       ) external nonReentrant {";
        assert!(detector.has_address_param_in_signature(source));
    }

    #[test]
    fn test_swap_with_revert_validation_not_flagged() {
        let detector = MissingInputValidationDetector::new();

        // Simulates the safe_amm_pool.sol swap function body
        let source = "function swap(\n\
                           uint256 amount0Out,\n\
                           uint256 amount1Out,\n\
                           address to,\n\
                           uint256 minAmountOut,\n\
                           uint256 deadline\n\
                       ) external nonReentrant {\n\
                           if (block.timestamp > deadline) {\n\
                               revert DeadlineExpired();\n\
                           }\n\
                           if (totalOut < minAmountOut) {\n\
                               revert SlippageExceeded();\n\
                           }\n\
                           uint256 balance0Adjusted = balance0 * 1000 - amount0In * 3;\n\
                           if (balance0Adjusted * balance1Adjusted < uint256(_reserve0) * _reserve1 * 1000000) {\n\
                               revert InvariantViolation();\n\
                           }\n\
                       }";

        // This should be recognized as having validation
        assert!(detector.source_has_validation(source));
        // This should be recognized as an AMM invariant pattern
        assert!(detector.is_amm_invariant_pattern(source));
    }
}
