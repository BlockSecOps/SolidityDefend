use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for unchecked send() return value
///
/// Detects send() calls where the return value is ignored.
/// send() returns false on failure instead of reverting.
///
/// Vulnerable pattern:
/// ```solidity
/// function withdraw() external {
///     payable(msg.sender).send(balance); // Return not checked!
///     balance = 0; // Happens even if send failed
/// }
/// ```
pub struct UncheckedSendReturnDetector {
    base: BaseDetector,
}

impl Default for UncheckedSendReturnDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl UncheckedSendReturnDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("unchecked-send-return"),
                "Unchecked send() Return Value".to_string(),
                "Detects send() calls where the return value is not checked. Unlike transfer(), \
                 send() returns false on failure instead of reverting. Ignoring this can lead \
                 to funds being locked or state inconsistency."
                    .to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::AccessControl],
                Severity::Medium,
            ),
        }
    }

    /// Find unchecked send() calls
    fn find_unchecked_send(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for .send( pattern
            if trimmed.contains(".send(") {
                // Check if return value is used
                let is_checked =
                    // Assigned to variable
                    trimmed.contains("= ") && trimmed.contains(".send(")
                    // Used in require
                    || trimmed.contains("require(")
                    // Used in if
                    || trimmed.starts_with("if ")
                    || trimmed.starts_with("if(")
                    // Used in assert
                    || trimmed.contains("assert(");

                // Also check next line for if statement checking result
                let next_line_checks = if line_num + 1 < lines.len() {
                    let next = lines[line_num + 1].trim();
                    next.starts_with("require(") || next.starts_with("if ")
                } else {
                    false
                };

                if !is_checked && !next_line_checks {
                    // Get function context
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find patterns where send failure doesn't prevent state change
    fn find_send_state_inconsistency(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for send followed by state change
            if trimmed.contains(".send(") {
                // Check following lines for state changes
                for i in (line_num + 1)..std::cmp::min(line_num + 5, lines.len()) {
                    let next_line = lines[i].trim();

                    // Look for state changes
                    if (next_line.contains("=")
                        && !next_line.contains("==")
                        && !next_line.contains("!="))
                        || next_line.contains("delete ")
                        || next_line.contains("++")
                        || next_line.contains("--")
                    {
                        // Check if there's a revert/require between send and state change
                        let intermediate: String = lines[line_num..=i].join("\n");
                        if !intermediate.contains("require(")
                            && !intermediate.contains("revert")
                            && !intermediate.contains("if (")
                            && !intermediate.contains("if(")
                        {
                            let func_name = self.find_containing_function(&lines, line_num);
                            findings.push((line_num as u32 + 1, func_name));
                            break;
                        }
                    }
                }
            }
        }

        findings
    }

    /// Find containing function name
    fn find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                if let Some(func_start) = trimmed.find("function ") {
                    let after_func = &trimmed[func_start + 9..];
                    if let Some(paren_pos) = after_func.find('(') {
                        return after_func[..paren_pos].trim().to_string();
                    }
                }
            }
        }
        "unknown".to_string()
    }

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for UncheckedSendReturnDetector {
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

        // Phase 52 FP Reduction: Skip test contracts
        if crate::utils::is_test_contract(ctx) {
            return Ok(findings);
        }

        // Phase 52 FP Reduction: Skip if contract uses Address library
        if source.contains("Address.sendValue") || source.contains("using Address for address") {
            return Ok(findings);
        }

        // Find unchecked send calls
        let unchecked = self.find_unchecked_send(source);
        for (line, func_name) in &unchecked {
            let message = format!(
                "Function '{}' in contract '{}' calls send() without checking the return value. \
                 send() returns false on failure instead of reverting. The transaction will \
                 continue even if the ETH transfer failed.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, *line, 1, 30)
                .with_cwe(252) // CWE-252: Unchecked Return Value
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Check send() return value or use transfer()/call():\n\n\
                     // Option 1: Check return value\n\
                     bool success = payable(to).send(amount);\n\
                     require(success, \"Send failed\");\n\n\
                     // Option 2: Use transfer (reverts on failure)\n\
                     payable(to).transfer(amount);\n\n\
                     // Option 3: Use call (recommended)\n\
                     (bool success, ) = payable(to).call{value: amount}(\"\");\n\
                     require(success, \"Transfer failed\");"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Find send with state inconsistency
        let inconsistent = self.find_send_state_inconsistency(source);
        for (line, func_name) in inconsistent {
            // Avoid duplicate if already reported as unchecked
            if unchecked.iter().any(|(l, _)| *l == line) {
                continue;
            }

            let message = format!(
                "Function '{}' in contract '{}' modifies state after send() without checking \
                 if send succeeded. State will change even if ETH transfer failed.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 30)
                .with_cwe(252) // CWE-252: Unchecked Return Value
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Check send result before modifying state:\n\n\
                     bool success = payable(to).send(amount);\n\
                     require(success, \"Send failed\");\n\
                     // Now safe to modify state\n\
                     balance = 0;"
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
        let detector = UncheckedSendReturnDetector::new();
        assert_eq!(detector.name(), "Unchecked send() Return Value");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_unchecked_send() {
        let detector = UncheckedSendReturnDetector::new();

        let vulnerable = r#"
            contract Wallet {
                function withdraw() external {
                    payable(msg.sender).send(balance);
                    balance = 0;
                }
            }
        "#;
        let findings = detector.find_unchecked_send(vulnerable);
        assert!(!findings.is_empty());

        let checked = r#"
            contract Wallet {
                function withdraw() external {
                    bool success = payable(msg.sender).send(balance);
                    require(success);
                    balance = 0;
                }
            }
        "#;
        let findings = detector.find_unchecked_send(checked);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_send_in_require() {
        let detector = UncheckedSendReturnDetector::new();

        let safe = r#"
            contract Wallet {
                function withdraw() external {
                    require(payable(msg.sender).send(balance), "Failed");
                    balance = 0;
                }
            }
        "#;
        let findings = detector.find_unchecked_send(safe);
        assert!(findings.is_empty());
    }
}
