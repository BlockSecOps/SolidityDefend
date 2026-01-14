use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for EXTCODESIZE check bypass vulnerabilities
///
/// Detects patterns where EXTCODESIZE checks can be bypassed during
/// contract construction when code size is 0.
pub struct ExtcodesizeCheckBypassDetector {
    base: BaseDetector,
}

impl Default for ExtcodesizeCheckBypassDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtcodesizeCheckBypassDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("extcodesize-check-bypass"),
                "EXTCODESIZE Check Bypass".to_string(),
                "Detects EXTCODESIZE checks that can be bypassed during contract \
                 construction when the code size is temporarily zero."
                    .to_string(),
                vec![DetectorCategory::Validation, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    /// Find EXTCODESIZE checks used for EOA detection
    fn find_extcodesize_checks(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for extcodesize checks
            if trimmed.contains("extcodesize")
                || trimmed.contains(".code.length")
                || trimmed.contains("codesize")
            {
                // Check if it's used for EOA detection
                let context_end = std::cmp::min(line_num + 5, lines.len());
                let context: String = lines[line_num..context_end].join("\n");

                if context.contains("== 0") || context.contains("!= 0") {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find isContract patterns
    fn find_is_contract_pattern(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("isContract") || trimmed.contains("_isContract") {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    /// Find contract-only modifiers that can be bypassed
    fn find_contract_only_modifier(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("modifier ")
                && (trimmed.contains("onlyEOA")
                    || trimmed.contains("noContract")
                    || trimmed.contains("notContract"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check if it relies on extcodesize
                if func_body.contains("extcodesize")
                    || func_body.contains(".code.length")
                    || func_body.contains("codesize")
                {
                    let modifier_name = self.extract_modifier_name(trimmed);
                    findings.push((line_num as u32 + 1, modifier_name));
                }
            }
        }

        findings
    }

    /// Find tx.origin != msg.sender as alternative check
    fn find_txorigin_sender_check(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // tx.origin == msg.sender is also bypassable in some scenarios
            if trimmed.contains("tx.origin") && trimmed.contains("msg.sender") {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    fn extract_modifier_name(&self, line: &str) -> String {
        if let Some(mod_start) = line.find("modifier ") {
            let after_mod = &line[mod_start + 9..];
            if let Some(paren_pos) = after_mod.find('(') {
                return after_mod[..paren_pos].trim().to_string();
            }
            if let Some(brace_pos) = after_mod.find('{') {
                return after_mod[..brace_pos].trim().to_string();
            }
        }
        "unknown".to_string()
    }

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

impl Detector for ExtcodesizeCheckBypassDetector {
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

        for (line, func_name) in self.find_extcodesize_checks(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses EXTCODESIZE to detect contracts. \
                 This check returns 0 during contract construction and can be bypassed.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(670)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "EXTCODESIZE is unreliable for contract detection:\n\n\
                     // During constructor, extcodesize == 0\n\
                     // Alternatives:\n\
                     1. Use tx.origin == msg.sender (also has limitations)\n\
                     2. Use codehash check: account.codehash != keccak256(\"\")\n\
                     3. Accept that EOA-only is not enforceable\n\
                     4. Use reentrancy guards instead of contract checks"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_is_contract_pattern(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses isContract() check. \
                 This is bypassable during contract construction.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(670)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "isContract() is unreliable:\n\n\
                     // Returns false during constructor execution\n\
                     // Consider alternative approaches:\n\
                     1. Re-evaluate if contract check is necessary\n\
                     2. Use callback mechanisms instead\n\
                     3. Implement proper access control"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, modifier_name) in self.find_contract_only_modifier(source) {
            let message = format!(
                "Modifier '{}' in contract '{}' attempts to restrict to EOA using code size. \
                 Contracts can bypass this during construction.",
                modifier_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(670)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "EOA-only modifiers are bypassable:\n\n\
                     // Attacker contract constructor can call your function\n\
                     // while extcodesize(attacker) == 0\n\n\
                     Consider:\n\
                     1. Removing the EOA restriction\n\
                     2. Using additional validation\n\
                     3. Implementing rate limiting instead"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_txorigin_sender_check(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses tx.origin for authentication. \
                 This has its own security implications and may be deprecated.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(670)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "tx.origin has security implications:\n\n\
                     1. Vulnerable to phishing attacks\n\
                     2. Incompatible with smart wallets/AA\n\
                     3. May be deprecated in future EIPs\n\n\
                     Consider alternative security mechanisms."
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
        let detector = ExtcodesizeCheckBypassDetector::new();
        assert_eq!(detector.name(), "EXTCODESIZE Check Bypass");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
