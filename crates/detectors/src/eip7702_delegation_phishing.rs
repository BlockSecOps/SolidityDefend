use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for EIP-7702 delegation phishing vulnerabilities
///
/// Detects contracts that could be used to phish users into delegating
/// their EOA code execution to malicious contracts via SET_CODE.
///
/// Vulnerable pattern:
/// ```solidity
/// // Contract tricks user into signing EIP-7702 authorization
/// contract PhishingTarget {
///     function executeOnBehalf(address victim) external {
///         // Attacker gains full control of victim's EOA
///         // Can drain all assets, sign arbitrary transactions
///     }
/// }
/// ```
pub struct Eip7702DelegationPhishingDetector {
    base: BaseDetector,
}

impl Default for Eip7702DelegationPhishingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Eip7702DelegationPhishingDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("eip7702-delegation-phishing"),
                "EIP-7702 Delegation Phishing".to_string(),
                "Detects contracts that could be used to phish users into delegating \
                 their EOA code execution via EIP-7702 SET_CODE authorization. Once \
                 delegated, the contract has full control over the user's account."
                    .to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Logic],
                Severity::Critical,
            ),
        }
    }

    /// Check for patterns that suggest delegation target
    fn is_delegation_target(&self, source: &str) -> bool {
        // Look for EIP-7702 related patterns
        source.contains("AUTH")
            || source.contains("AUTHCALL")
            || source.contains("setCode")
            || source.contains("SET_CODE")
            || source.contains("delegateCode")
            || source.contains("executeAs")
            || source.contains("executeOnBehalf")
            || source.contains("actAs")
            || source.contains("impersonate")
    }

    /// Find functions that execute on behalf of another address
    fn find_execute_on_behalf(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for functions that take an address and execute actions
            if trimmed.contains("function ")
                && (trimmed.contains("onBehalf")
                    || trimmed.contains("OnBehalf")
                    || trimmed.contains("executeAs")
                    || trimmed.contains("ExecuteAs")
                    || trimmed.contains("actAs")
                    || trimmed.contains("forUser")
                    || trimmed.contains("ForUser"))
            {
                let func_name = self.extract_function_name(trimmed);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    /// Find contracts with sweeper-like patterns
    fn find_sweeper_patterns(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for transfer patterns that could drain accounts
            if trimmed.contains("transfer(") || trimmed.contains("transferFrom(") {
                // Check context for suspicious patterns
                let context_start = if line_num > 10 { line_num - 10 } else { 0 };
                let context_end = std::cmp::min(line_num + 5, lines.len());
                let context: String = lines[context_start..context_end].join("\n");

                // Suspicious if transfers entire balance or uses address(this).balance
                if context.contains("address(this).balance")
                    || context.contains("balanceOf(")
                    || context.contains("type(uint256).max")
                {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find unlimited approval patterns
    fn find_unlimited_approval(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for approve with max value
            if trimmed.contains("approve(")
                && (trimmed.contains("type(uint256).max")
                    || trimmed.contains("uint256(-1)")
                    || trimmed.contains("0xffffffff"))
            {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    /// Extract function name from declaration
    fn extract_function_name(&self, line: &str) -> String {
        if let Some(func_start) = line.find("function ") {
            let after_func = &line[func_start + 9..];
            if let Some(paren_pos) = after_func.find('(') {
                return after_func[..paren_pos].trim().to_string();
            }
        }
        "unknown".to_string()
    }

    /// Find containing function name
    fn find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return self.extract_function_name(trimmed);
            }
        }
        "unknown".to_string()
    }

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for Eip7702DelegationPhishingDetector {
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
        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        // Check if this could be a delegation target
        if !self.is_delegation_target(source) {
            // Still check for phishing-like patterns
        }

        // Find execute-on-behalf patterns
        let on_behalf = self.find_execute_on_behalf(source);
        for (line, func_name) in &on_behalf {
            let message = format!(
                "Function '{}' in contract '{}' appears to execute actions on behalf of another \
                 address. In EIP-7702 context, this pattern could be used to phish users into \
                 delegating their EOA execution, giving the contract full control.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, *line, 1, 50)
                .with_cwe(284) // CWE-284: Improper Access Control
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "If implementing EIP-7702 delegation:\n\n\
                     1. Clearly document the delegation scope and permissions\n\
                     2. Implement strict access controls on delegated functions\n\
                     3. Add explicit user consent mechanisms\n\
                     4. Consider time-limited delegations\n\
                     5. Emit events for all delegated operations\n\n\
                     Users should be warned about the risks of EIP-7702 delegation."
                        .to_string(),
                );

            findings.push(finding);
        }

        // Find sweeper patterns
        let sweepers = self.find_sweeper_patterns(source);
        for (line, func_name) in sweepers {
            // Skip if already reported
            if on_behalf.iter().any(|(l, _)| *l == line) {
                continue;
            }

            let message = format!(
                "Function '{}' in contract '{}' contains transfer patterns that could drain \
                 an account's balance. If used as an EIP-7702 delegation target, this could \
                 allow attackers to steal all user funds.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(284) // CWE-284: Improper Access Control
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Review transfer logic to ensure it cannot be abused:\n\n\
                     1. Add explicit amount limits\n\
                     2. Require user confirmation for large transfers\n\
                     3. Implement withdrawal patterns instead of push patterns\n\
                     4. Add rate limiting for transfers"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Find unlimited approval patterns
        let approvals = self.find_unlimited_approval(source);
        for (line, func_name) in approvals {
            let message = format!(
                "Function '{}' in contract '{}' grants unlimited token approval. In EIP-7702 \
                 context, a delegated contract could grant approvals on the user's behalf, \
                 enabling token theft.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(284) // CWE-284: Improper Access Control
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Avoid unlimited approvals in delegation contexts:\n\n\
                     1. Use exact amounts instead of type(uint256).max\n\
                     2. Implement approval revocation mechanisms\n\
                     3. Add time-limited approvals where possible"
                        .to_string(),
                );

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
        let detector = Eip7702DelegationPhishingDetector::new();
        assert_eq!(detector.name(), "EIP-7702 Delegation Phishing");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_execute_on_behalf() {
        let detector = Eip7702DelegationPhishingDetector::new();

        let vulnerable = r#"
            contract DelegationTarget {
                function executeOnBehalf(address user, bytes calldata data) external {
                    // Execute arbitrary code
                }
            }
        "#;
        let findings = detector.find_execute_on_behalf(vulnerable);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_sweeper_pattern() {
        let detector = Eip7702DelegationPhishingDetector::new();

        let vulnerable = r#"
            contract Sweeper {
                function sweep(address token) external {
                    uint256 balance = IERC20(token).balanceOf(address(this));
                    IERC20(token).transfer(attacker, balance);
                }
            }
        "#;
        let findings = detector.find_sweeper_patterns(vulnerable);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_unlimited_approval() {
        let detector = Eip7702DelegationPhishingDetector::new();

        let vulnerable = r#"
            contract Approver {
                function approveMax(address token, address spender) external {
                    IERC20(token).approve(spender, type(uint256).max);
                }
            }
        "#;
        let findings = detector.find_unlimited_approval(vulnerable);
        assert!(!findings.is_empty());
    }
}
