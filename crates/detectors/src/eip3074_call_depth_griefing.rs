use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for EIP-3074 call depth griefing vulnerabilities
///
/// AUTHCALL inherits the current call depth. Attackers can:
/// 1. Nest calls to approach the 1024 call depth limit
/// 2. Cause AUTHCALL to fail due to insufficient depth
/// 3. Grief users by making their authorized transactions fail
///
/// Vulnerable pattern:
/// ```solidity
/// function execute(bytes calldata sig, address to, bytes calldata data) external {
///     // No call depth check - can fail if called at high depth
///     assembly {
///         let success := authcall(gas(), to, 0, ...)
///     }
/// }
/// ```
pub struct Eip3074CallDepthGriefingDetector {
    base: BaseDetector,
}

impl Default for Eip3074CallDepthGriefingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Eip3074CallDepthGriefingDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("eip3074-call-depth-griefing"),
                "EIP-3074 Call Depth Griefing".to_string(),
                "Detects AUTHCALL usage without call depth validation. \
                 Attackers can grief users by calling invokers at high call \
                 depths, causing authorized transactions to fail."
                    .to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::BestPractices],
                Severity::Medium,
            ),
        }
    }

    /// Check for AUTHCALL without depth protection
    fn find_unprotected_authcall(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Check if contract has any call depth protection
        let has_depth_check = source.contains("depth")
            || source.contains("DEPTH")
            || source.contains("1024")
            || source.contains("call depth");

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }

            // Find AUTHCALL usage
            if trimmed.contains("authcall(") || trimmed.contains("AUTHCALL") {
                if !has_depth_check {
                    findings.push((line_num as u32 + 1, "AUTHCALL without depth check".to_string()));
                }
            }
        }

        findings
    }

    /// Check for nested call patterns that could increase depth
    fn find_nested_call_risks(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let has_authcall = source.contains("authcall") || source.contains("AUTHCALL");
        if !has_authcall {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }

            // Check for external calls that could be used to increase depth
            if trimmed.contains(".call{") || trimmed.contains(".delegatecall(") {
                // Look for authcall in the same function
                let func_start = self.find_function_start(&lines, line_num);
                let func_end = self.find_function_end(&lines, func_start);
                let func_body: String = lines[func_start..func_end].join("\n");

                if func_body.contains("authcall") || func_body.contains("AUTHCALL") {
                    findings.push((
                        line_num as u32 + 1,
                        "external call before AUTHCALL in same function".to_string(),
                    ));
                }
            }

            // Check for recursive patterns
            if trimmed.contains("function") {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check if function calls itself and uses authcall
                if func_body.contains(&func_name) &&
                   (func_body.contains("authcall") || func_body.contains("AUTHCALL")) {
                    findings.push((
                        line_num as u32 + 1,
                        "recursive function with AUTHCALL".to_string(),
                    ));
                }
            }
        }

        findings
    }

    /// Find function start
    fn find_function_start(&self, lines: &[&str], line_num: usize) -> usize {
        for i in (0..=line_num).rev() {
            if lines[i].contains("function ") {
                return i;
            }
        }
        0
    }

    /// Find function end
    fn find_function_end(&self, lines: &[&str], start: usize) -> usize {
        let mut brace_count = 0;
        let mut found_open = false;

        for (i, line) in lines.iter().enumerate().skip(start) {
            for c in line.chars() {
                match c {
                    '{' => {
                        brace_count += 1;
                        found_open = true;
                    }
                    '}' => {
                        brace_count -= 1;
                        if found_open && brace_count == 0 {
                            return i + 1;
                        }
                    }
                    _ => {}
                }
            }
        }
        lines.len()
    }

    /// Extract function name
    fn extract_function_name(&self, line: &str) -> String {
        if let Some(start) = line.find("function ") {
            let after = &line[start + 9..];
            if let Some(end) = after.find('(') {
                return after[..end].trim().to_string();
            }
        }
        String::new()
    }

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for Eip3074CallDepthGriefingDetector {
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

        // Check for unprotected AUTHCALL
        let unprotected = self.find_unprotected_authcall(source);
        for (line, issue) in unprotected {
            let message = format!(
                "{} in contract '{}'. AUTHCALL can fail if called at high \
                 call depth (near 1024 limit). Attackers can grief users by \
                 nesting calls before invoking the authorized transaction.",
                issue, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400) // CWE-400: Uncontrolled Resource Consumption
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add call depth validation before AUTHCALL:\n\n\
                     // Check call depth has room for nested calls\n\
                     uint256 depth;\n\
                     assembly { depth := add(1, sub(gas(), gasleft())) } // Approximate\n\
                     require(depth < 1000, \"Call depth too high\");\n\n\
                     // Or use a dedicated depth checking contract\n\
                     // Or document the call depth requirements for users"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Check for nested call risks
        let nested_risks = self.find_nested_call_risks(source);
        for (line, issue) in nested_risks {
            let message = format!(
                "Call depth risk in contract '{}': {}. This pattern can \
                 increase call depth before AUTHCALL, making it more likely \
                 to fail or be griefed.",
                contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400) // CWE-400: Uncontrolled Resource Consumption
                .with_confidence(Confidence::Low)
                .with_fix_suggestion(
                    "Consider restructuring to minimize call depth before AUTHCALL. \
                     Avoid external calls or recursive patterns before AUTHCALL."
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
        let detector = Eip3074CallDepthGriefingDetector::new();
        assert_eq!(detector.name(), "EIP-3074 Call Depth Griefing");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_unprotected_authcall() {
        let detector = Eip3074CallDepthGriefingDetector::new();

        let vulnerable = r#"
            contract Invoker {
                function execute() external {
                    assembly { authcall(gas(), to, 0, 0, 0, 0, 0) }
                }
            }
        "#;
        let issues = detector.find_unprotected_authcall(vulnerable);
        assert!(!issues.is_empty());

        let safe = r#"
            contract Invoker {
                function execute() external {
                    require(getDepth() < 1024, "depth");
                    assembly { authcall(gas(), to, 0, 0, 0, 0, 0) }
                }
            }
        "#;
        let issues = detector.find_unprotected_authcall(safe);
        assert!(issues.is_empty());
    }
}
