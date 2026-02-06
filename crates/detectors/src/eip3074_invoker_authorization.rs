use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for EIP-3074 invoker authorization vulnerabilities
///
/// Invoker contracts must properly validate:
/// 1. Who can trigger authorized actions
/// 2. What actions are authorized
/// 3. That the authorization matches the signed commit
///
/// Vulnerable pattern:
/// ```solidity
/// function execute(bytes calldata sig, address to, bytes calldata data) external {
///     // VULNERABLE: Anyone can call, no validation of 'to' or 'data'
///     assembly {
///         let success := authcall(gas(), to, 0, add(data, 32), mload(data), 0, 0)
///     }
/// }
/// ```
pub struct Eip3074InvokerAuthorizationDetector {
    base: BaseDetector,
}

impl Default for Eip3074InvokerAuthorizationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Eip3074InvokerAuthorizationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("eip3074-invoker-authorization"),
                "EIP-3074 Invoker Authorization".to_string(),
                "Detects missing authorization checks in EIP-3074 invokers. \
                 Invokers must validate callers, target addresses, and call data \
                 to prevent unauthorized use of AUTH signatures."
                    .to_string(),
                vec![DetectorCategory::AccessControl],
                Severity::High,
            ),
        }
    }

    /// Check for missing authorization patterns
    fn find_authorization_issues(&self, source: &str) -> Vec<(u32, String, Vec<String>)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Track what authorization exists
        let has_caller_check = source.contains("msg.sender ==")
            || source.contains("msg.sender !=")
            || source.contains("onlyOwner")
            || source.contains("onlyAuthorized")
            || source.contains("allowlist")
            || source.contains("whitelist");

        let has_target_validation = source.contains("allowedTargets")
            || source.contains("validTarget")
            || source.contains("isAllowed")
            || (source.contains("to !=") && source.contains("address(0)"));

        let has_data_validation = source.contains("allowedSelectors")
            || source.contains("functionSelector")
            || source.contains("bytes4(data)")
            || source.contains("sig ==");

        let has_value_limits = source.contains("maxValue")
            || source.contains("value <=")
            || source.contains("value <");

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }

            // Find execute/invoke functions with AUTHCALL
            if trimmed.contains("function")
                && (trimmed.contains("execute")
                    || trimmed.contains("invoke")
                    || trimmed.contains("call"))
            {
                // Look for authcall in function body
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                if func_body.contains("authcall") || func_body.contains("AUTHCALL") {
                    let mut missing = Vec::new();

                    if !has_caller_check {
                        missing.push("caller authorization".to_string());
                    }
                    if !has_target_validation {
                        missing.push("target address validation".to_string());
                    }
                    if !has_data_validation {
                        missing.push("function selector validation".to_string());
                    }
                    if !has_value_limits {
                        missing.push("value limits".to_string());
                    }

                    // Check if function is external/public without access control
                    if (trimmed.contains("external") || trimmed.contains("public"))
                        && !trimmed.contains("onlyOwner")
                        && !trimmed.contains("onlyAuthorized")
                        && !func_body.contains("msg.sender ==")
                    {
                        missing.push("function access control".to_string());
                    }

                    if !missing.is_empty() {
                        findings.push((
                            line_num as u32 + 1,
                            self.extract_function_name(trimmed),
                            missing,
                        ));
                    }
                }
            }
        }

        findings
    }

    /// Check for open invoker patterns
    fn find_open_invoker_patterns(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Check for completely unrestricted execute
            if trimmed.contains("function execute") && trimmed.contains("external") {
                // Look ahead for any restrictions
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check if there are NO restrictions at all
                if !func_body.contains("require")
                    && !func_body.contains("revert")
                    && !func_body.contains("if (")
                    && !func_body.contains("onlyOwner")
                    && (func_body.contains("authcall") || func_body.contains("AUTHCALL"))
                {
                    findings.push((
                        line_num as u32 + 1,
                        "completely unrestricted AUTHCALL function".to_string(),
                    ));
                }
            }

            // Check for arbitrary target
            if trimmed.contains("authcall") && trimmed.contains("to,") {
                // Check if 'to' comes from function parameter without validation
                let func_start = self.find_function_start(&lines, line_num);
                let func_header = lines[func_start];
                if func_header.contains("address to") || func_header.contains("address _to") {
                    let func_body: String = lines[func_start..line_num].join("\n");
                    if !func_body.contains("require(to")
                        && !func_body.contains("require(_to")
                        && !func_body.contains("allowedTargets")
                        && !func_body.contains("isValidTarget")
                    {
                        findings.push((
                            line_num as u32 + 1,
                            "AUTHCALL to unvalidated target address".to_string(),
                        ));
                    }
                }
            }
        }

        findings
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
                            return (i + 1).min(lines.len());
                        }
                    }
                    _ => {}
                }
            }
        }
        lines.len()
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

    /// Extract function name
    fn extract_function_name(&self, line: &str) -> String {
        if let Some(start) = line.find("function ") {
            let after = &line[start + 9..];
            if let Some(end) = after.find('(') {
                return after[..end].trim().to_string();
            }
        }
        "unknown".to_string()
    }

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for Eip3074InvokerAuthorizationDetector {
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

        // Only check EIP-3074 related contracts
        if !source.contains("authcall")
            && !source.contains("AUTHCALL")
            && !source.contains("invoker")
        {
            return Ok(findings);
        }

        // Check for missing authorization
        let auth_issues = self.find_authorization_issues(source);
        for (line, func_name, missing) in auth_issues {
            let message = format!(
                "EIP-3074 invoker function '{}' in contract '{}' is missing: {}. \
                 Without proper authorization, attackers can abuse AUTH signatures \
                 for unintended actions.",
                func_name,
                contract_name,
                missing.join(", ")
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(862) // CWE-862: Missing Authorization
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Implement comprehensive authorization:\n\n\
                     1. Caller restrictions:\n\
                        require(msg.sender == authorizedCaller, \"Unauthorized\");\n\n\
                     2. Target validation:\n\
                        require(allowedTargets[to], \"Invalid target\");\n\n\
                     3. Function selector validation:\n\
                        bytes4 selector = bytes4(data);\n\
                        require(allowedSelectors[selector], \"Invalid function\");\n\n\
                     4. Value limits:\n\
                        require(value <= maxValue, \"Value too high\");"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Check for open invoker patterns
        let open_patterns = self.find_open_invoker_patterns(source);
        for (line, issue) in open_patterns {
            let message = format!(
                "Critical authorization issue in contract '{}': {}. \
                 This allows anyone to use AUTH signatures for arbitrary actions.",
                contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(862) // CWE-862: Missing Authorization
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Add authorization checks before AUTHCALL. Never allow arbitrary \
                     targets or call data without explicit user approval."
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
        let detector = Eip3074InvokerAuthorizationDetector::new();
        assert_eq!(detector.name(), "EIP-3074 Invoker Authorization");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
