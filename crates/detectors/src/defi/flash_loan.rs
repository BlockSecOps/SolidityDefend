use crate::types::{DetectorResult, AnalysisContext, Severity, Finding};
use crate::defi::{DeFiDetector, DeFiPatterns};

/// Detector for flash loan vulnerabilities
pub struct FlashLoanDetector;

impl DeFiDetector for FlashLoanDetector {
    fn detect_defi_vulnerabilities(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        // Only analyze contracts that use flash loans
        if !DeFiPatterns::uses_flash_loans(ctx) {
            return results;
        }

        // Check for common flash loan vulnerabilities
        results.extend(self.detect_reentrancy_in_flash_loan(ctx));
        results.extend(self.detect_price_manipulation_via_flash_loan(ctx));
        results.extend(self.detect_insufficient_validation(ctx));
        results.extend(self.detect_flash_loan_arbitrage_risks(ctx));
        results.extend(self.detect_callback_validation_issues(ctx));

        results
    }

    fn name(&self) -> &'static str {
        "flash-loan-detector"
    }

    fn description(&self) -> &'static str {
        "Detects vulnerabilities related to flash loan implementations and usage"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn applies_to_contract(&self, ctx: &AnalysisContext) -> bool {
        DeFiPatterns::uses_flash_loans(ctx)
    }
}

impl FlashLoanDetector {
    /// Detect reentrancy vulnerabilities in flash loan implementations
    fn detect_reentrancy_in_flash_loan(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            // Check for flash loan callback functions
            if self.is_flash_loan_callback(func.name.as_str()) {
                // Look for external calls without reentrancy protection
                if self.has_unprotected_external_calls(ctx, func) &&
                   !self.has_reentrancy_guard(ctx, func) {
                    results.push(DetectorResult {
                        finding: Finding {
                            detector: self.name().to_string(),
                            severity: Severity::Critical,
                            title: "Flash loan reentrancy vulnerability".to_string(),
                            description: format!(
                                "Function '{}' handles flash loan callbacks but lacks reentrancy protection. \
                                This could allow attackers to drain funds through reentrancy during flash loan execution.",
                                func.name
                            ),
                            file_path: ctx.file_path.clone(),
                            line_number: func.line_number,
                            column: 0,
                            confidence: 0.85,
                        },
                        gas_impact: Some("High - Multiple external calls in vulnerable pattern".to_string()),
                        suggested_fix: Some(
                            "Add reentrancy guards using OpenZeppelin's ReentrancyGuard or implement \
                            checks-effects-interactions pattern".to_string()
                        ),
                    });
                }
            }
        }

        results
    }

    /// Detect price manipulation through flash loans
    fn detect_price_manipulation_via_flash_loan(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.is_flash_loan_function(func.name.as_str()) {
                // Check if function affects pricing without proper safeguards
                if self.affects_pricing(ctx, func) && !self.has_price_manipulation_protection(ctx, func) {
                    results.push(DetectorResult {
                        finding: Finding {
                            detector: self.name().to_string(),
                            severity: Severity::High,
                            title: "Flash loan price manipulation vulnerability".to_string(),
                            description: format!(
                                "Function '{}' uses flash loans and affects pricing mechanisms. \
                                This could enable attackers to manipulate prices temporarily using borrowed funds.",
                                func.name
                            ),
                            file_path: ctx.file_path.clone(),
                            line_number: func.line_number,
                            column: 0,
                            confidence: 0.75,
                        },
                        gas_impact: Some("High - Complex pricing calculations".to_string()),
                        suggested_fix: Some(
                            "Implement time-weighted average pricing (TWAP) or use multiple price oracles \
                            to prevent single-transaction price manipulation".to_string()
                        ),
                    });
                }
            }
        }

        results
    }

    /// Detect insufficient validation in flash loan implementations
    fn detect_insufficient_validation(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.is_flash_loan_function(func.name.as_str()) {
                let mut validation_issues = Vec::new();

                // Check for missing amount validation
                if !self.validates_loan_amount(ctx, func) {
                    validation_issues.push("Missing loan amount validation");
                }

                // Check for missing recipient validation
                if !self.validates_recipient(ctx, func) {
                    validation_issues.push("Missing recipient address validation");
                }

                // Check for missing fee calculation
                if !self.calculates_fees_properly(ctx, func) {
                    validation_issues.push("Missing or improper fee calculation");
                }

                // Check for missing balance verification
                if !self.verifies_repayment(ctx, func) {
                    validation_issues.push("Missing repayment verification");
                }

                if !validation_issues.is_empty() {
                    results.push(DetectorResult {
                        finding: Finding {
                            detector: self.name().to_string(),
                            severity: Severity::High,
                            title: "Insufficient flash loan validation".to_string(),
                            description: format!(
                                "Flash loan function '{}' has insufficient validation: {}",
                                func.name,
                                validation_issues.join(", ")
                            ),
                            file_path: ctx.file_path.clone(),
                            line_number: func.line_number,
                            column: 0,
                            confidence: 0.80,
                        },
                        gas_impact: Some("Medium - Additional validation checks required".to_string()),
                        suggested_fix: Some(
                            "Add comprehensive validation for loan amounts, recipients, fees, and repayment verification".to_string()
                        ),
                    });
                }
            }
        }

        results
    }

    /// Detect flash loan arbitrage risks
    fn detect_flash_loan_arbitrage_risks(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        // Check if contract allows arbitrary external calls during flash loans
        for func in &ctx.contract.functions {
            if self.is_flash_loan_callback(func.name.as_str()) {
                if self.allows_arbitrary_calls(ctx, func) {
                    results.push(DetectorResult {
                        finding: Finding {
                            detector: self.name().to_string(),
                            severity: Severity::Medium,
                            title: "Flash loan arbitrage manipulation risk".to_string(),
                            description: format!(
                                "Function '{}' allows arbitrary external calls during flash loan execution. \
                                This could be exploited for complex arbitrage attacks.",
                                func.name
                            ),
                            file_path: ctx.file_path.clone(),
                            line_number: func.line_number,
                            column: 0,
                            confidence: 0.70,
                        },
                        gas_impact: Some("Variable - Depends on external call complexity".to_string()),
                        suggested_fix: Some(
                            "Restrict external calls to whitelisted contracts or implement \
                            strict validation of call targets and data".to_string()
                        ),
                    });
                }
            }
        }

        results
    }

    /// Detect callback validation issues
    fn detect_callback_validation_issues(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.is_flash_loan_callback(func.name.as_str()) {
                // Check if callback validates the caller
                if !self.validates_flash_loan_caller(ctx, func) {
                    results.push(DetectorResult {
                        finding: Finding {
                            detector: self.name().to_string(),
                            severity: Severity::High,
                            title: "Flash loan callback lacks caller validation".to_string(),
                            description: format!(
                                "Flash loan callback '{}' does not validate the caller. \
                                This could allow unauthorized parties to trigger the callback.",
                                func.name
                            ),
                            file_path: ctx.file_path.clone(),
                            line_number: func.line_number,
                            column: 0,
                            confidence: 0.90,
                        },
                        gas_impact: Some("Low - Simple address validation".to_string()),
                        suggested_fix: Some(
                            "Add validation to ensure the callback is only called by authorized flash loan providers".to_string()
                        ),
                    });
                }
            }
        }

        results
    }

    // Helper methods for pattern detection

    fn is_flash_loan_function(&self, name: &str) -> bool {
        let flash_loan_patterns = [
            "flashLoan", "flashBorrow", "flashSwap", "flashBorrowAndCall"
        ];
        flash_loan_patterns.iter().any(|&pattern| name.contains(pattern))
    }

    fn is_flash_loan_callback(&self, name: &str) -> bool {
        let callback_patterns = [
            "onFlashLoan", "receiveFlashLoan", "executeOperation", "flashLoanCallback"
        ];
        callback_patterns.iter().any(|&pattern| name.contains(pattern))
    }

    fn has_unprotected_external_calls(&self, ctx: &AnalysisContext, func: &crate::types::Function) -> bool {
        // Look for external calls in the function
        // This would require deeper AST analysis
        ctx.source_code.contains("call(") || ctx.source_code.contains(".transfer(")
    }

    fn has_reentrancy_guard(&self, ctx: &AnalysisContext, func: &crate::types::Function) -> bool {
        // Check for reentrancy guard patterns
        let guard_patterns = [
            "nonReentrant", "ReentrancyGuard", "_nonReentrantBefore", "_nonReentrantAfter"
        ];
        guard_patterns.iter().any(|&pattern| ctx.source_code.contains(pattern))
    }

    fn affects_pricing(&self, ctx: &AnalysisContext, func: &crate::types::Function) -> bool {
        let pricing_indicators = [
            "price", "rate", "exchange", "swap", "getAmountOut", "getAmountIn"
        ];
        pricing_indicators.iter().any(|&indicator|
            func.name.contains(indicator) || ctx.source_code.contains(indicator)
        )
    }

    fn has_price_manipulation_protection(&self, ctx: &AnalysisContext, func: &crate::types::Function) -> bool {
        let protection_patterns = [
            "TWAP", "timeWeighted", "oracle", "priceCheck", "slippage"
        ];
        protection_patterns.iter().any(|&pattern| ctx.source_code.contains(pattern))
    }

    fn validates_loan_amount(&self, ctx: &AnalysisContext, func: &crate::types::Function) -> bool {
        let validation_patterns = [
            "require(amount", "assert(amount", "amount > 0", "amount != 0"
        ];
        validation_patterns.iter().any(|&pattern| ctx.source_code.contains(pattern))
    }

    fn validates_recipient(&self, ctx: &AnalysisContext, func: &crate::types::Function) -> bool {
        let validation_patterns = [
            "require(to", "require(recipient", "to != address(0)", "recipient != address(0)"
        ];
        validation_patterns.iter().any(|&pattern| ctx.source_code.contains(pattern))
    }

    fn calculates_fees_properly(&self, ctx: &AnalysisContext, func: &crate::types::Function) -> bool {
        let fee_patterns = [
            "fee", "premium", "flashLoanFee", "calculateFee"
        ];
        fee_patterns.iter().any(|&pattern| ctx.source_code.contains(pattern))
    }

    fn verifies_repayment(&self, ctx: &AnalysisContext, func: &crate::types::Function) -> bool {
        let repayment_patterns = [
            "balanceAfter", "repayAmount", "totalDebt", "require(balance"
        ];
        repayment_patterns.iter().any(|&pattern| ctx.source_code.contains(pattern))
    }

    fn allows_arbitrary_calls(&self, ctx: &AnalysisContext, func: &crate::types::Function) -> bool {
        let arbitrary_call_patterns = [
            "call(data)", "delegatecall(", "staticcall(", "target.call"
        ];
        arbitrary_call_patterns.iter().any(|&pattern| ctx.source_code.contains(pattern))
    }

    fn validates_flash_loan_caller(&self, ctx: &AnalysisContext, func: &crate::types::Function) -> bool {
        let caller_validation_patterns = [
            "msg.sender ==", "require(msg.sender", "onlyFlashLoanProvider", "isAuthorizedCaller"
        ];
        caller_validation_patterns.iter().any(|&pattern| ctx.source_code.contains(pattern))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Contract, Function};

    #[test]
    fn test_flash_loan_function_detection() {
        let detector = FlashLoanDetector;
        assert!(detector.is_flash_loan_function("flashLoan"));
        assert!(detector.is_flash_loan_function("flashBorrow"));
        assert!(detector.is_flash_loan_function("myFlashLoanFunction"));
        assert!(!detector.is_flash_loan_function("normalFunction"));
    }

    #[test]
    fn test_flash_loan_callback_detection() {
        let detector = FlashLoanDetector;
        assert!(detector.is_flash_loan_callback("onFlashLoan"));
        assert!(detector.is_flash_loan_callback("receiveFlashLoan"));
        assert!(detector.is_flash_loan_callback("executeOperation"));
        assert!(!detector.is_flash_loan_callback("normalCallback"));
    }

    #[test]
    fn test_detector_properties() {
        let detector = FlashLoanDetector;
        assert_eq!(detector.name(), "flash-loan-detector");
        assert_eq!(detector.severity(), Severity::High);
        assert!(!detector.description().is_empty());
    }
}