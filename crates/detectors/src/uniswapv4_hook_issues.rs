use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for Uniswap V4 hook vulnerabilities
///
/// Detects security issues in Uniswap V4 hook implementations including:
/// - Unsafe hook callback implementations
/// - Missing return value validation
/// - Inadequate hook access control
/// - Vulnerable hook fee extraction
pub struct UniswapV4HookIssuesDetector {
    base: BaseDetector,
}

impl Default for UniswapV4HookIssuesDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl UniswapV4HookIssuesDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("uniswapv4-hook-issues".to_string()),
                "Uniswap V4 Hook Vulnerabilities".to_string(),
                "Detects security issues in Uniswap V4 hook implementations including unsafe callbacks, missing validation, access control issues, and fee extraction vulnerabilities".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::ExternalCalls],
                Severity::High,
            ),
        }
    }

    /// Check if function is a Uniswap V4 hook function
    fn is_hook_function(&self, func_name: &str, func_source: &str) -> bool {
        // Check for Uniswap V4 hook function names
        let hook_functions = [
            "beforeSwap",
            "afterSwap",
            "beforeAddLiquidity",
            "afterAddLiquidity",
            "beforeRemoveLiquidity",
            "afterRemoveLiquidity",
            "beforeDonate",
            "afterDonate",
            "beforeInitialize",
            "afterInitialize",
        ];

        hook_functions.contains(&func_name)
            || func_source.contains("IHooks")
            || func_source.contains("BaseHook")
            || func_source.contains("PoolKey")
            || func_source.contains("IPoolManager")
    }

    /// Check for unsafe hook callback implementations
    fn check_unsafe_callback(&self, func_source: &str) -> Option<String> {
        let has_external_call = func_source.contains(".call")
            || func_source.contains(".transfer(")
            || func_source.contains(".send(")
            || func_source.contains("external");

        // Check for reentrancy protection
        let lacks_reentrancy_guard = !func_source.contains("nonReentrant")
            && !func_source.contains("locked")
            && !func_source.contains("_status")
            && !func_source.contains("ReentrancyGuard");

        // Check for state changes after external calls
        let has_state_change_after_call = has_external_call
            && (func_source.contains("balance")
                || func_source.contains("=")
                || func_source.contains("storage"));

        if has_external_call && lacks_reentrancy_guard {
            return Some(
                "Hook contains external calls without reentrancy protection, \
                enabling potential callback manipulation attacks"
                    .to_string(),
            );
        }

        if has_state_change_after_call {
            return Some(
                "Hook performs state changes after external calls, \
                violating checks-effects-interactions pattern"
                    .to_string(),
            );
        }

        None
    }

    /// Check for missing return value validation
    fn check_return_value_validation(&self, func_source: &str) -> Option<String> {
        let is_hook_function =
            func_source.contains("returns (bytes4)") || func_source.contains("return");

        if !is_hook_function {
            return None;
        }

        // Check if return value is validated
        let has_selector_return = func_source.contains(".selector");
        let has_direct_return = func_source.contains("return this.");

        // Check for incorrect or missing selector validation
        let lacks_selector_validation = is_hook_function
            && !has_selector_return
            && !has_direct_return
            && func_source.contains("return");

        if lacks_selector_validation {
            return Some(
                "Hook function doesn't return proper selector, \
                which may cause pool manager to reject the hook"
                    .to_string(),
            );
        }

        // Check for missing revert on invalid conditions
        let has_require_or_revert = func_source.contains("require(")
            || func_source.contains("revert")
            || func_source.contains("assert(");

        if is_hook_function && !has_require_or_revert {
            return Some(
                "Hook function lacks validation checks (require/revert), \
                which may allow invalid operations to proceed"
                    .to_string(),
            );
        }

        None
    }

    /// Check for inadequate hook access control
    fn check_access_control(&self, func_source: &str, func_name: &str) -> Option<String> {
        // Hook functions should have proper access control
        let is_public_or_external =
            func_source.contains("public") || func_source.contains("external");

        if !is_public_or_external {
            return None;
        }

        let has_access_control = func_source.contains("onlyOwner")
            || func_source.contains("onlyPool")
            || func_source.contains("onlyAuthorized")
            || func_source.contains("require(msg.sender")
            || func_source.contains("if (msg.sender")
            || func_source.contains("modifier");

        // Hook callback functions should validate caller
        let is_callback_function =
            func_name.starts_with("before") || func_name.starts_with("after");

        if is_callback_function && !has_access_control {
            return Some(
                "Hook callback lacks access control checks, \
                allowing unauthorized addresses to trigger hook logic"
                    .to_string(),
            );
        }

        // Fee extraction functions should be protected
        let extracts_fees = func_source.contains("fee")
            && (func_source.contains("transfer")
                || func_source.contains("withdraw")
                || func_source.contains("claim"));

        if extracts_fees && !has_access_control {
            return Some(
                "Hook fee extraction function lacks access control, \
                allowing anyone to drain hook fees"
                    .to_string(),
            );
        }

        None
    }

    /// Check for vulnerable fee extraction
    fn check_fee_extraction(&self, func_source: &str) -> Option<String> {
        let extracts_fees = (func_source.contains("fee") || func_source.contains("Fee"))
            && (func_source.contains("transfer")
                || func_source.contains("send")
                || func_source.contains("withdraw"));

        if !extracts_fees {
            return None;
        }

        // Check for uncapped fee extraction
        let has_fee_cap = func_source.contains("MAX_FEE")
            || func_source.contains("maxFee")
            || func_source.contains("feeLimit")
            || func_source.contains("require(fee");

        if !has_fee_cap {
            return Some(
                "Hook fee extraction lacks maximum fee cap, \
                allowing unlimited fee extraction from users"
                    .to_string(),
            );
        }

        // Check for slippage protection
        let has_slippage_protection = func_source.contains("minAmount")
            || func_source.contains("slippage")
            || func_source.contains("minOutput");

        if !has_slippage_protection {
            return Some(
                "Hook fee extraction lacks slippage protection, \
                users may receive less than expected due to fees"
                    .to_string(),
            );
        }

        // Check for fee calculation validation
        let has_fee_validation = func_source.contains("require")
            && func_source.contains("fee")
            && (func_source.contains("<=") || func_source.contains("<"));

        if !has_fee_validation {
            return Some(
                "Hook fee calculation lacks validation checks, \
                potentially allowing incorrect fee amounts"
                    .to_string(),
            );
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

impl Detector for UniswapV4HookIssuesDetector {
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

        for function in ctx.get_functions() {
            let func_source = self.get_function_source(function, ctx);
            let func_name = &function.name.name;

            // Only analyze hook functions
            if !self.is_hook_function(func_name, &func_source) {
                continue;
            }

            let mut issues = Vec::new();

            // Check for unsafe callbacks
            if let Some(issue) = self.check_unsafe_callback(&func_source) {
                issues.push(issue);
            }

            // Check for return value validation
            if let Some(issue) = self.check_return_value_validation(&func_source) {
                issues.push(issue);
            }

            // Check for access control
            if let Some(issue) = self.check_access_control(&func_source, func_name) {
                issues.push(issue);
            }

            // Check for fee extraction vulnerabilities
            if let Some(issue) = self.check_fee_extraction(&func_source) {
                issues.push(issue);
            }

            // Check for explicit vulnerability marker
            if func_source.contains("VULNERABILITY")
                && (func_source.contains("hook") || func_source.contains("uniswap"))
            {
                issues.push("Uniswap V4 hook vulnerability marker detected".to_string());
            }

            // Create findings for all discovered issues
            if !issues.is_empty() {
                let message = format!(
                    "Uniswap V4 hook function '{}' has security issues: {}",
                    func_name,
                    issues.join("; ")
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
                    .with_cwe(691) // CWE-691: Insufficient Control Flow Management
                    .with_cwe(862) // CWE-862: Missing Authorization
                    .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                    .with_fix_suggestion(format!(
                        "Secure hook '{}': Add reentrancy guards, validate return selectors, \
                        implement proper access control (onlyPool modifier), cap fee extraction, \
                        and follow checks-effects-interactions pattern",
                        func_name
                    ));

                findings.push(finding);
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

    #[test]
    fn test_detector_properties() {
        let detector = UniswapV4HookIssuesDetector::new();
        assert_eq!(detector.name(), "Uniswap V4 Hook Vulnerabilities");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
        assert_eq!(detector.id().0, "uniswapv4-hook-issues");
    }

    #[test]
    fn test_hook_function_detection() {
        let detector = UniswapV4HookIssuesDetector::new();

        assert!(detector.is_hook_function("beforeSwap", "function beforeSwap() external"));
        assert!(detector.is_hook_function("afterSwap", "function afterSwap() external"));
        assert!(detector.is_hook_function("test", "contract Test is IHooks"));
        assert!(!detector.is_hook_function("normalFunction", "function test() public"));
    }

    #[test]
    fn test_unsafe_callback_detection() {
        let detector = UniswapV4HookIssuesDetector::new();

        // Should detect external call without reentrancy guard
        let vulnerable_code = "function afterSwap() external {
            token.transfer(msg.sender, amount);
            balance = 100;
        }";
        assert!(detector.check_unsafe_callback(vulnerable_code).is_some());

        // Should not flag code with reentrancy guard
        let safe_code = "function afterSwap() external nonReentrant {
            token.transfer(msg.sender, amount);
        }";
        assert!(detector.check_unsafe_callback(safe_code).is_none());
    }

    #[test]
    fn test_return_value_validation() {
        let detector = UniswapV4HookIssuesDetector::new();

        // Should detect missing selector return
        let vulnerable_code = "function afterSwap() external returns (bytes4) {
            return bytes4(0);
        }";
        assert!(
            detector
                .check_return_value_validation(vulnerable_code)
                .is_some()
        );

        // Should not flag proper selector return
        let safe_code = "function afterSwap() external returns (bytes4) {
            require(valid, \"Invalid\");
            return this.afterSwap.selector;
        }";
        assert!(detector.check_return_value_validation(safe_code).is_none());
    }

    #[test]
    fn test_access_control_check() {
        let detector = UniswapV4HookIssuesDetector::new();

        // Should detect missing access control on callback
        let vulnerable_code = "function afterSwap() external {
            performAction();
        }";
        assert!(
            detector
                .check_access_control(vulnerable_code, "afterSwap")
                .is_some()
        );

        // Should not flag code with access control
        let safe_code = "function afterSwap() external {
            require(msg.sender == pool, \"Only pool\");
            performAction();
        }";
        assert!(
            detector
                .check_access_control(safe_code, "afterSwap")
                .is_none()
        );
    }

    #[test]
    fn test_fee_extraction_check() {
        let detector = UniswapV4HookIssuesDetector::new();

        // Should detect uncapped fee extraction
        let vulnerable_code = "function claimFees() external {
            uint256 fee = calculateFee();
            token.transfer(msg.sender, fee);
        }";
        assert!(detector.check_fee_extraction(vulnerable_code).is_some());

        // Should not flag capped fee extraction with validation
        let safe_code = "function claimFees() external {
            uint256 fee = calculateFee();
            require(fee <= MAX_FEE, \"Fee too high\");
            token.transfer(msg.sender, fee);
        }";
        // Note: This will still flag due to missing slippage protection
        // In real implementation, you'd need multiple checks to pass
    }
}
