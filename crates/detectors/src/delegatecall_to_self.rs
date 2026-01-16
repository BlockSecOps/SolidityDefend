use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for delegatecall to self vulnerabilities
///
/// Detects patterns where contracts make delegatecall to themselves,
/// which can cause unexpected behavior or enable attack vectors.
pub struct DelegatecallToSelfDetector {
    base: BaseDetector,
}

impl Default for DelegatecallToSelfDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DelegatecallToSelfDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("delegatecall-to-self"),
                "Delegatecall to Self".to_string(),
                "Detects patterns where contracts make delegatecall to themselves (address(this)), \
                 which can cause infinite loops, storage corruption, or unexpected behavior."
                    .to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::Reentrancy],
                Severity::High,
            ),
        }
    }

    fn find_self_delegatecall(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }

            // Direct delegatecall to this
            if trimmed.contains("delegatecall") && trimmed.contains("address(this)") {
                let func_name = self.find_containing_function(&lines, line_num);
                let issue = "Direct delegatecall to address(this)".to_string();
                findings.push((line_num as u32 + 1, func_name, issue));
            }

            // Delegatecall via stored self reference
            if trimmed.contains("delegatecall") {
                let func_name = self.find_containing_function(&lines, line_num);
                let func_start = self.find_function_start(&lines, line_num);
                let func_body = self.get_function_body(&lines, func_start);

                // Check for patterns like: address target = address(this); target.delegatecall
                if func_body.contains("= address(this)") ||
                   func_body.contains("selfAddress") ||
                   func_body.contains("_self")
                {
                    // Check if the delegatecall might use this variable
                    if trimmed.contains("target.delegatecall") ||
                       trimmed.contains("selfAddress.delegatecall") ||
                       trimmed.contains("_self.delegatecall")
                    {
                        let issue = "Possible delegatecall to self via stored address".to_string();
                        findings.push((line_num as u32 + 1, func_name, issue));
                    }
                }
            }

            // Multicall/batch patterns with self-delegation
            if (trimmed.contains("multicall") || trimmed.contains("batch")) &&
               trimmed.contains("delegatecall")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                let issue = "Multicall with delegatecall may enable self-delegation".to_string();
                findings.push((line_num as u32 + 1, func_name, issue));
            }
        }

        findings
    }

    fn find_recursive_delegation(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect function that calls itself via delegatecall
            if trimmed.contains("function ") {
                let func_name = self.extract_function_name(trimmed);
                let func_body = self.get_function_body(&lines, line_num);

                // Check if function makes delegatecall that could call itself
                if func_body.contains("delegatecall") {
                    // Look for selector that matches this function
                    let selector_pattern = format!("{}(", func_name);
                    if func_body.contains(&selector_pattern) ||
                       func_body.contains("msg.sig") ||
                       func_body.contains("this.") && func_body.contains(&func_name)
                    {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    fn find_fallback_self_delegation(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect fallback/receive with delegatecall
            if (trimmed.contains("fallback") || trimmed.contains("receive")) &&
               trimmed.contains("function")
            {
                let func_body = self.get_function_body(&lines, line_num);

                if func_body.contains("delegatecall") {
                    // Check if target could be self
                    if func_body.contains("address(this)") ||
                       !func_body.contains("require(") ||
                       func_body.contains("implementation")
                    {
                        let func_name = if trimmed.contains("fallback") {
                            "fallback".to_string()
                        } else {
                            "receive".to_string()
                        };
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    fn find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return self.extract_function_name(trimmed);
            }
            if trimmed.contains("fallback") {
                return "fallback".to_string();
            }
            if trimmed.contains("receive") {
                return "receive".to_string();
            }
        }
        "unknown".to_string()
    }

    fn find_function_start(&self, lines: &[&str], line_num: usize) -> usize {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") ||
               trimmed.contains("fallback") ||
               trimmed.contains("receive")
            {
                return i;
            }
        }
        0
    }

    fn get_function_body(&self, lines: &[&str], start: usize) -> String {
        let mut depth = 0;
        let mut started = false;
        let mut end = lines.len();

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
                            end = i + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if started && depth == 0 {
                break;
            }
        }

        lines[start..end].join("\n")
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

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for DelegatecallToSelfDetector {
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

        for (line, func_name, issue) in self.find_self_delegatecall(source) {
            let message = format!(
                "Function '{}' in contract '{}' has delegatecall to self: {}. \
                 This can cause infinite loops or unexpected state changes.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(829)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Avoid delegatecall to self:\n\n\
                     1. Never use address(this) as delegatecall target\n\
                     2. Validate target != address(this) before delegatecall\n\
                     3. Use direct internal calls instead\n\
                     4. If multicall needed, use call instead of delegatecall"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_recursive_delegation(source) {
            let message = format!(
                "Function '{}' in contract '{}' may recursively call itself via delegatecall. \
                 This can cause stack overflow or gas exhaustion.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(674)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Prevent recursive delegatecall:\n\n\
                     1. Add reentrancy guard for delegatecall functions\n\
                     2. Validate selector before delegatecall\n\
                     3. Use a depth counter to limit recursion\n\
                     4. Consider using staticcall for read-only operations"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_fallback_self_delegation(source) {
            let message = format!(
                "{} function in contract '{}' uses delegatecall which may target self. \
                 This can be exploited via crafted calldata.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(829)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Secure fallback delegatecall:\n\n\
                     1. Validate implementation address is external\n\
                     2. Add require(target != address(this))\n\
                     3. Use immutable implementation address\n\
                     4. Consider using EIP-1967 proxy pattern"
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
        let detector = DelegatecallToSelfDetector::new();
        assert_eq!(detector.name(), "Delegatecall to Self");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
