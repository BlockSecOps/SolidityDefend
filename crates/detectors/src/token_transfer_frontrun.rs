use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for token transfer front-running vulnerabilities
///
/// This detector identifies transferFrom() operations in price-dependent contexts
/// that lack slippage protection or deadline checks, making them vulnerable to
/// front-running attacks.
///
/// **Vulnerability:** CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)
/// **Severity:** Medium
///
/// ## Description
///
/// Token transfer front-running occurs when:
/// 1. User submits transaction to buy tokens/NFTs at current price
/// 2. Price oracle or exchange rate changes before transaction executes
/// 3. Attacker front-runs by buying first, causing price increase
/// 4. User's transaction executes at worse price
/// 5. Attacker sells at profit (sandwich attack)
///
/// Common vulnerable patterns:
/// - Token purchases without slippage limits
/// - NFT minting without price locks
/// - DEX swaps without minimum output amounts
/// - Operations without deadline parameters
///
pub struct TokenTransferFrontrunDetector {
    base: BaseDetector,
}

impl Default for TokenTransferFrontrunDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenTransferFrontrunDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("token-transfer-frontrun".to_string()),
                "Token Transfer Front-Running".to_string(),
                "Detects transferFrom() operations vulnerable to front-running due to lack of slippage protection"
                    .to_string(),
                vec![
                    DetectorCategory::MEV,
                    DetectorCategory::Logic,
                    DetectorCategory::DeFi,
                ],
                Severity::Medium,
            ),
        }
    }

    /// Checks if function contains price-dependent token transfers
    fn has_vulnerable_transfer(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        let func_source = self.get_function_source(function, ctx);
        let func_name_lower = function.name.name.to_lowercase();

        // Skip if function is internal/private
        if function.visibility != ast::Visibility::Public
            && function.visibility != ast::Visibility::External
        {
            return None;
        }

        // Look for transferFrom calls
        let has_transfer_from = func_source.contains("transferFrom");
        if !has_transfer_from {
            return None;
        }

        // Check for price-dependent operations
        let is_price_dependent = func_name_lower.contains("buy")
            || func_name_lower.contains("purchase")
            || func_name_lower.contains("swap")
            || func_name_lower.contains("mint")
            || func_name_lower.contains("trade")
            || func_source.contains("getPrice")
            || func_source.contains("price")
            || func_source.contains("calculateAmount")
            || func_source.contains("getAmountOut");

        if !is_price_dependent {
            return None;
        }

        // Check for slippage protection (multiple forms)
        let has_slippage_protection = self.has_min_amount_param(function)
            || self.has_slippage_check(&func_source)
            || self.has_deadline_param(function)
            || self.has_deadline_validation(&func_source)
            || self.has_price_protection(&func_source);

        if !has_slippage_protection {
            return Some(format!(
                "Price-dependent transfer without slippage protection. \
                Function '{}' performs transferFrom in price-dependent context but lacks \
                minAmountOut/slippage parameters or deadline checks",
                function.name.name
            ));
        }

        None
    }

    /// Checks if function has minimum amount output parameter
    fn has_min_amount_param(&self, function: &ast::Function<'_>) -> bool {
        function.parameters.iter().any(|param| {
            if let Some(name) = &param.name {
                let name_lower = name.name.to_lowercase();
                name_lower.contains("min")
                    && (name_lower.contains("amount") || name_lower.contains("out"))
            } else {
                false
            }
        })
    }

    /// Checks if function has deadline parameter
    fn has_deadline_param(&self, function: &ast::Function<'_>) -> bool {
        function.parameters.iter().any(|param| {
            if let Some(name) = &param.name {
                let name_lower = name.name.to_lowercase();
                name_lower.contains("deadline") || name_lower.contains("expiry")
            } else {
                false
            }
        })
    }

    /// Checks source code for slippage protection patterns
    fn has_slippage_check(&self, source: &str) -> bool {
        (source.contains("require") || source.contains("revert"))
            && (source.contains("minAmount")
                || source.contains("minOut")
                || source.contains("slippage")
                || source.contains(">=")
                    && (source.contains("amount") || source.contains("output")))
    }

    /// Checks source code for deadline validation patterns
    fn has_deadline_validation(&self, source: &str) -> bool {
        // Look for timestamp checks with expiration/deadline
        (source.contains("block.timestamp") || source.contains("block.number"))
            && (source.contains("<=") || source.contains("<"))
            && (source.contains("expiration")
                || source.contains("deadline")
                || source.contains("expiry"))
    }

    /// Checks source code for price protection patterns
    fn has_price_protection(&self, source: &str) -> bool {
        // Look for price limit checks
        (source.contains("require") || source.contains("revert"))
            && (source.contains("price") || source.contains("Price"))
            && (source.contains("<=")
                || source.contains(">=")
                || source.contains("<")
                || source.contains(">"))
            && (source.contains("target")
                || source.contains("max")
                || source.contains("min")
                || source.contains("limit"))
    }

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

impl Detector for TokenTransferFrontrunDetector {
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
            if let Some(issue) = self.has_vulnerable_transfer(function, ctx) {
                let message = format!(
                    "Function '{}' has token transfer front-running vulnerability. {} \
                    This enables sandwich attacks where attackers can front-run user transactions \
                    to extract MEV by manipulating prices",
                    function.name.name, issue
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
                    .with_cwe(362) // CWE-362: Concurrent Execution
                    .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                    .with_fix_suggestion(format!(
                        "Add slippage protection to '{}'. Implement: \
                        (1) Add minAmountOut parameter and validate: require(amountOut >= minAmountOut, 'Slippage'); \
                        (2) Add deadline parameter: require(block.timestamp <= deadline, 'Expired'); \
                        (3) Use TWAP oracles instead of spot prices; \
                        (4) Implement commit-reveal for sensitive operations; \
                        (5) Consider private transaction pools (Flashbots) for MEV protection",
                        function.name.name
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
    fn test_detector_metadata() {
        let detector = TokenTransferFrontrunDetector::new();
        assert_eq!(detector.id().0, "token-transfer-frontrun");
        assert_eq!(detector.name(), "Token Transfer Front-Running");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_detector_categories() {
        let detector = TokenTransferFrontrunDetector::new();
        let categories = detector.categories();
        assert!(categories.contains(&DetectorCategory::MEV));
        assert!(categories.contains(&DetectorCategory::Logic));
        assert!(categories.contains(&DetectorCategory::DeFi));
    }
}
