use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for SWC-132: Unexpected Ether Balance
///
/// Detects contracts that rely on exact ether balance assumptions which can be
/// broken by force-sending ether via selfdestruct or coinbase transactions.
///
/// Vulnerable patterns:
/// - `require(address(this).balance == expectedAmount)`
/// - `assert(address(this).balance >= someValue)` without internal accounting
/// - Logic dependent on exact contract balance
///
/// Attack vector:
/// An attacker can force-send ether to any contract using:
/// - selfdestruct(targetAddress) - sends all ether to target
/// - Mining coinbase reward to contract address (pre-merge)
/// - CREATE2 predictions before deployment
pub struct UnexpectedEtherBalanceDetector {
    base: BaseDetector,
}

impl Default for UnexpectedEtherBalanceDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl UnexpectedEtherBalanceDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("swc132-unexpected-ether-balance"),
                "Unexpected Ether Balance (SWC-132)".to_string(),
                "Detects contracts that rely on exact ether balance assumptions \
                 which can be manipulated via force-sending ether"
                    .to_string(),
                vec![DetectorCategory::Logic],
                Severity::Medium,
            ),
        }
    }

    /// Find patterns that rely on exact balance checks
    fn find_exact_balance_checks(&self, source: &str) -> Vec<(usize, String)> {
        let mut issues = Vec::new();

        for (line_idx, line) in source.lines().enumerate() {
            if let Some(issue) = self.analyze_line_for_balance_issues(line) {
                issues.push((line_idx + 1, issue));
            }
        }

        issues
    }

    /// Analyze a single line for balance-related issues
    fn analyze_line_for_balance_issues(&self, line: &str) -> Option<String> {
        // Pattern 1: Exact balance equality checks
        if (line.contains("address(this).balance ==")
            || line.contains("address(this).balance==")
            || line.contains(".balance ==")
            || line.contains("balance =="))
            && (line.contains("require(") || line.contains("assert(") || line.contains("if ("))
        {
            return Some(
                "Exact balance equality check detected. Ether can be force-sent to the contract \
                 via selfdestruct, breaking this assumption."
                    .to_string(),
            );
        }

        // Pattern 2: Balance used in equality comparison
        if line.contains("this.balance")
            && (line.contains(" == ") || line.contains("=="))
            && !line.contains(">=")
            && !line.contains("<=")
        {
            return Some(
                "Contract balance used in equality comparison. \
                 Consider using internal accounting instead."
                    .to_string(),
            );
        }

        // Pattern 3: Balance-dependent state transitions
        if (line.contains("address(this).balance") || line.contains("this.balance"))
            && (line.contains("if (") || line.contains("require("))
            && !self.has_internal_accounting(line)
        {
            // Check for exact comparisons
            if line.contains(" == ") || line.contains("==") {
                return Some(
                    "Balance-dependent logic without internal accounting. \
                     Contract state can be manipulated by force-sending ether."
                        .to_string(),
                );
            }
        }

        None
    }

    /// Check if the contract uses internal accounting
    fn has_internal_accounting(&self, line: &str) -> bool {
        line.contains("totalDeposited")
            || line.contains("totalDeposits")
            || line.contains("internalBalance")
            || line.contains("trackedBalance")
            || line.contains("deposited")
            || line.contains("deposits[")
            || line.contains("balances[")
    }

    /// Check entire source for internal accounting patterns
    fn source_has_internal_accounting(&self, source: &str) -> bool {
        source.contains("totalDeposited")
            || source.contains("totalDeposits")
            || source.contains("internalBalance")
            || source.contains("trackedBalance")
            || (source.contains("mapping") && source.contains("deposits"))
            || (source.contains("mapping") && source.contains("balances"))
    }

    /// Check if function uses balance for critical operations
    fn is_critical_balance_usage(&self, source: &str) -> bool {
        // Balance used in transfer calculations
        let transfer_dependent = (source.contains("address(this).balance")
            || source.contains("this.balance"))
            && (source.contains(".transfer(")
                || source.contains(".send(")
                || source.contains(".call{value:"));

        // Balance used in state changes
        let state_dependent = source.contains("address(this).balance")
            && (source.contains("status =")
                || source.contains("state =")
                || source.contains("phase =")
                || source.contains("stage ="));

        // Balance used in payouts/distributions
        let payout_dependent = source.contains("address(this).balance")
            && (source.contains("payout")
                || source.contains("distribute")
                || source.contains("dividend")
                || source.contains("reward"));

        transfer_dependent || state_dependent || payout_dependent
    }
}

impl Detector for UnexpectedEtherBalanceDetector {
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

        // Check if the contract uses internal accounting (reduces severity if so)
        let has_accounting = self.source_has_internal_accounting(&ctx.source_code);

        // Find exact balance check patterns
        let issues = self.find_exact_balance_checks(&ctx.source_code);

        for (line_num, issue) in issues {
            let line = ctx.source_code.lines().nth(line_num - 1).unwrap_or("");

            // Determine severity and confidence
            let is_critical = self.is_critical_balance_usage(line);
            let is_exact_check = line.contains(" == ") || line.contains("==");

            let (severity, confidence) = if is_exact_check && is_critical {
                (Severity::High, Confidence::High)
            } else if is_exact_check {
                (Severity::Medium, Confidence::High)
            } else if has_accounting {
                (Severity::Low, Confidence::Low)
            } else {
                (Severity::Medium, Confidence::Medium)
            };

            let message = format!("Line {}: {}", line_num, issue);

            let mut finding = self
                .base
                .create_finding(ctx, message, line_num as u32, 1, line.len() as u32)
                .with_swc("SWC-132")
                .with_cwe(670) // CWE-670: Always-Incorrect Control Flow Implementation
                .with_confidence(confidence)
                .with_fix_suggestion(
                    "Avoid relying on exact ether balance. Implement these fixes:\n\
                     1. Use internal accounting (track deposits/withdrawals separately):\n\
                        uint256 public totalDeposited;\n\
                        function deposit() external payable {\n\
                            totalDeposited += msg.value;\n\
                        }\n\
                     2. Use >= instead of == for balance checks when appropriate\n\
                     3. Be aware that ether can be force-sent via:\n\
                        - selfdestruct(contractAddress)\n\
                        - Pre-deployment via CREATE2 address prediction\n\
                     4. Never use balance for access control or critical state transitions"
                        .to_string(),
                );

            finding.severity = severity;
            findings.push(finding);
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
        let detector = UnexpectedEtherBalanceDetector::new();
        assert_eq!(detector.name(), "Unexpected Ether Balance (SWC-132)");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_exact_balance_check_detection() {
        let detector = UnexpectedEtherBalanceDetector::new();

        // Vulnerable: exact equality check
        let vulnerable = r#"
            require(address(this).balance == expectedAmount, "Invalid balance");
        "#;
        let results = detector.find_exact_balance_checks(vulnerable);
        assert!(!results.is_empty());

        // Safe: using >= instead
        let safe = r#"
            require(address(this).balance >= minimumAmount, "Insufficient balance");
        "#;
        let results = detector.find_exact_balance_checks(safe);
        assert!(results.is_empty());
    }

    #[test]
    fn test_internal_accounting_detection() {
        let detector = UnexpectedEtherBalanceDetector::new();
        assert!(detector.source_has_internal_accounting("uint256 totalDeposited;"));
        assert!(detector.source_has_internal_accounting("mapping(address => uint256) balances;"));
        assert!(!detector.source_has_internal_accounting("function withdraw() external {}"));
    }
}
