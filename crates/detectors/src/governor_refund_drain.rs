use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for governor refund drain vulnerabilities
///
/// Detects patterns where governance refund parameters can be manipulated
/// to drain the treasury through excessive refunds.
pub struct GovernorRefundDrainDetector {
    base: BaseDetector,
}

impl Default for GovernorRefundDrainDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl GovernorRefundDrainDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("governor-refund-drain"),
                "Governor Refund Drain".to_string(),
                "Detects governance systems where refund parameters can be changed \
                 to drain the treasury through excessive gas refunds or bounties."
                    .to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Logic],
                Severity::Critical,
            ),
        }
    }

    /// Find refund parameter vulnerabilities
    fn find_refund_issues(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for refund-related functions
            if trimmed.contains("function ")
                && (trimmed.contains("refund")
                    || trimmed.contains("Refund")
                    || trimmed.contains("compensate")
                    || trimmed.contains("reimburse"))
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for unbounded refund amounts
                if !func_body.contains("maxRefund")
                    && !func_body.contains("MAX_REFUND")
                    && !func_body.contains("refundCap")
                {
                    let issue = "No maximum refund cap".to_string();
                    findings.push((line_num as u32 + 1, func_name.clone(), issue));
                }

                // Check for timelock protection on refund params
                if (func_body.contains("refundRate") || func_body.contains("gasPrice"))
                    && !func_body.contains("onlyTimelock")
                    && !func_body.contains("onlyGovernance")
                {
                    let issue = "Refund rate changeable without governance".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }

            // Look for setter functions for refund params
            if trimmed.contains("function set")
                && (trimmed.contains("Refund") || trimmed.contains("Gas"))
                && (trimmed.contains("external") || trimmed.contains("public"))
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for access control
                let has_access_control = func_body.contains("onlyOwner")
                    || func_body.contains("onlyGovernance")
                    || func_body.contains("onlyTimelock")
                    || func_body.contains("onlyAdmin");

                if !has_access_control {
                    let issue = "Refund parameter setter lacks access control".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    /// Find treasury drain patterns
    fn find_treasury_drain(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for direct treasury transfers
            if (trimmed.contains("treasury.transfer")
                || trimmed.contains("treasury.call")
                || trimmed.contains("_treasury.transfer"))
                && !trimmed.starts_with("//")
            {
                // Check for amount validation
                let context_start = if line_num > 10 { line_num - 10 } else { 0 };
                let context_end = (line_num + 1).min(lines.len());
                let context: String = lines[context_start..context_end].join("\n");

                let has_validation = context.contains("require")
                    || context.contains("<=")
                    || context.contains("maxAmount");

                if !has_validation {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find gas price manipulation
    fn find_gas_manipulation(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for user-controlled gas price in refunds
            if trimmed.contains("tx.gasprice") && !trimmed.starts_with("//") {
                // Check for gas price caps
                let context_start = if line_num > 5 { line_num - 5 } else { 0 };
                let context_end = (line_num + 5).min(lines.len());
                let context: String = lines[context_start..context_end].join("\n");

                let has_cap = context.contains("maxGasPrice")
                    || context.contains("MAX_GAS_PRICE")
                    || context.contains("gasLimit");

                if !has_cap {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    fn extract_function_name(&self, line: &str) -> String {
        if let Some(func_start) = line.find("function ") {
            let after_func = &line[func_start + 9..];
            if let Some(paren_pos) = after_func.find('(') {
                return after_func[..paren_pos].trim().to_string();
            }
        }
        "unknown".to_string()
    }

    fn find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return self.extract_function_name(trimmed);
            }
        }
        "unknown".to_string()
    }

    fn find_function_end(&self, lines: &[&str], start: usize) -> usize {
        let mut depth = 0;
        let mut started = false;

        for (i, line) in lines.iter().enumerate().skip(start) {
            for c in line.chars() {
                match c {
                    '{' => {
                        depth += 1;
                        started = true;
                    }
                    '}' => {
                        depth -= 1;
                        if started && depth == 0 {
                            return i + 1;
                        }
                    }
                    _ => {}
                }
            }
        }
        lines.len()
    }

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for GovernorRefundDrainDetector {
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        for (line, func_name, issue) in self.find_refund_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' has refund vulnerability. {}. \
                 Attackers may drain treasury through excessive refund claims.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(284)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Protect refund mechanisms:\n\n\
                     1. Set maximum refund cap per transaction\n\
                     2. Implement daily/weekly refund limits\n\
                     3. Use timelock for refund parameter changes\n\
                     4. Cap gas price used in refund calculations\n\n\
                     Example:\n\
                     uint256 constant MAX_REFUND = 0.1 ether;\n\
                     uint256 refundAmount = min(gasUsed * tx.gasprice, MAX_REFUND);"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_treasury_drain(source) {
            let message = format!(
                "Treasury transfer in '{}' of contract '{}' lacks proper validation. \
                 Unrestricted treasury access can lead to fund drainage.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(284)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Protect treasury access:\n\n\
                     1. Implement multi-sig for large transfers\n\
                     2. Set maximum transfer limits\n\
                     3. Use timelock for fund movements\n\
                     4. Emit events for all treasury operations"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_gas_manipulation(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses tx.gasprice without cap. \
                 Attackers can set high gas prices to drain refund pools.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(284)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Cap gas price in refunds:\n\n\
                     uint256 constant MAX_GAS_PRICE = 100 gwei;\n\
                     uint256 effectiveGasPrice = min(tx.gasprice, MAX_GAS_PRICE);\n\
                     uint256 refund = gasUsed * effectiveGasPrice;"
                        .to_string(),
                );

            findings.push(finding);
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

    #[test]
    fn test_detector_properties() {
        let detector = GovernorRefundDrainDetector::new();
        assert_eq!(detector.name(), "Governor Refund Drain");
        assert_eq!(detector.default_severity(), Severity::Critical);
    }
}
