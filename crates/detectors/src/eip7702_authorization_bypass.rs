use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};
use crate::utils::{is_eip7702_context, is_test_contract};

/// Detector for EIP-7702 authorization bypass vulnerabilities
///
/// Detects contracts that fail to properly verify EIP-7702 authorization
/// before executing delegated operations.
///
/// Vulnerable pattern:
/// ```solidity
/// // Missing authorization checks for EIP-7702 delegation
/// contract BadDelegationTarget {
///     function execute(bytes calldata data) external {
///         // No check if caller is authorized via EIP-7702
///         // Executes arbitrary code on behalf of delegating EOA
///         (bool success,) = address(this).call(data);
///     }
/// }
/// ```
pub struct Eip7702AuthorizationBypassDetector {
    base: BaseDetector,
}

impl Default for Eip7702AuthorizationBypassDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Eip7702AuthorizationBypassDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("eip7702-authorization-bypass"),
                "EIP-7702 Authorization Bypass".to_string(),
                "Detects contracts that fail to properly verify EIP-7702 authorization \
                 before executing delegated operations. Missing authorization checks \
                 can allow unauthorized parties to execute code on behalf of delegating EOAs."
                    .to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    /// Find functions that execute arbitrary calls without auth checks
    fn find_unprotected_execute(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for function declarations with execute/call patterns
            if trimmed.contains("function ") {
                let lower = trimmed.to_lowercase();
                if lower.contains("execute")
                    || lower.contains("call")
                    || lower.contains("invoke")
                    || lower.contains("perform")
                    || lower.contains("run")
                {
                    // Check if function has external/public visibility
                    if trimmed.contains("external") || trimmed.contains("public") {
                        // Check function body for authorization
                        let func_end = self.find_function_end(&lines, line_num);
                        let func_body: String = lines[line_num..func_end].join("\n");

                        // Missing common authorization patterns
                        if !func_body.contains("onlyOwner")
                            && !func_body.contains("onlyAuthorized")
                            && !func_body.contains("require(msg.sender")
                            && !func_body.contains("_checkAuthorization")
                            && !func_body.contains("isAuthorized")
                            && !func_body.contains("hasRole")
                            && !func_body.contains("AUTH")
                        {
                            // Has a call pattern
                            if func_body.contains(".call(")
                                || func_body.contains(".delegatecall(")
                                || func_body.contains("(bool success")
                            {
                                let func_name = self.extract_function_name(trimmed);
                                findings.push((line_num as u32 + 1, func_name));
                            }
                        }
                    }
                }
            }
        }

        findings
    }

    /// Find missing msg.sender validation for delegation
    fn find_missing_sender_check(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for functions that operate on behalf of addresses
            if trimmed.contains("function ") && trimmed.contains("address") {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check if it takes an address parameter but doesn't validate sender
                if (func_body.contains("address user")
                    || func_body.contains("address account")
                    || func_body.contains("address target")
                    || func_body.contains("address from"))
                    && (func_body.contains("transfer(")
                        || func_body.contains(".call{value:")
                        || func_body.contains("safeTransfer"))
                {
                    // Missing sender validation
                    if !func_body.contains("require(msg.sender ==")
                        && !func_body.contains("require(_msgSender() ==")
                        && !func_body.contains("if (msg.sender !=")
                    {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find fallback/receive without authorization
    fn find_unprotected_fallback(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Check fallback and receive functions
            if trimmed.contains("fallback()")
                || trimmed.contains("receive()")
                || trimmed.contains("fallback ()")
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Dangerous if fallback forwards calls without checks
                if func_body.contains(".delegatecall(") || func_body.contains(".call(") {
                    if !func_body.contains("require(") && !func_body.contains("onlyOwner") {
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

    /// Extract function name
    fn extract_function_name(&self, line: &str) -> String {
        if let Some(func_start) = line.find("function ") {
            let after_func = &line[func_start + 9..];
            if let Some(paren_pos) = after_func.find('(') {
                return after_func[..paren_pos].trim().to_string();
            }
        }
        "unknown".to_string()
    }

    /// Find end of a function
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

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for Eip7702AuthorizationBypassDetector {
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

        // Phase 9 FP Reduction: Skip test contracts
        if is_test_contract(ctx) {
            return Ok(findings);
        }

        // Phase 9 FP Reduction: Use shared EIP-7702 context detection (requires 2+ indicators)
        if !is_eip7702_context(ctx) {
            return Ok(findings);
        }

        // Find unprotected execute functions
        let unprotected = self.find_unprotected_execute(source);
        for (line, func_name) in &unprotected {
            let message = format!(
                "Function '{}' in contract '{}' executes calls without proper authorization \
                 checks. In EIP-7702 context, this could allow unauthorized parties to \
                 execute arbitrary operations on delegating EOAs.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, *line, 1, 50)
                .with_cwe(862) // CWE-862: Missing Authorization
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Add authorization checks before executing calls:\n\n\
                     1. Verify msg.sender is the authorized caller:\n\
                     require(msg.sender == authorizedExecutor, \"Unauthorized\");\n\n\
                     2. Use role-based access control:\n\
                     require(hasRole(EXECUTOR_ROLE, msg.sender), \"Missing role\");\n\n\
                     3. Implement EIP-7702 specific authorization:\n\
                     require(isAuthorizedDelegation(msg.sender), \"Invalid delegation\");"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Find missing sender checks
        let missing_checks = self.find_missing_sender_check(source);
        for (line, func_name) in missing_checks {
            if unprotected.iter().any(|(l, _)| *l == line) {
                continue;
            }

            let message = format!(
                "Function '{}' in contract '{}' operates on an address parameter without \
                 validating msg.sender. This could allow attackers to perform operations \
                 on behalf of arbitrary addresses in EIP-7702 delegation.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(862) // CWE-862: Missing Authorization
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Validate that msg.sender is authorized to act on the address:\n\n\
                     require(msg.sender == user || isApprovedFor(msg.sender, user), \
                     \"Not authorized for user\");"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Find unprotected fallback
        let fallbacks = self.find_unprotected_fallback(source);
        for (line, func_name) in fallbacks {
            let message = format!(
                "The {} function in contract '{}' forwards calls without authorization. \
                 In EIP-7702 delegation, this allows any caller to execute arbitrary \
                 operations through the delegating EOA.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(862) // CWE-862: Missing Authorization
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Add authorization to fallback/receive functions:\n\n\
                     fallback() external payable {\n\
                         require(msg.sender == authorizedCaller, \"Unauthorized\");\n\
                         // ... forwarding logic\n\
                     }"
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
        let detector = Eip7702AuthorizationBypassDetector::new();
        assert_eq!(detector.name(), "EIP-7702 Authorization Bypass");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_unprotected_execute() {
        let detector = Eip7702AuthorizationBypassDetector::new();

        let vulnerable = r#"
            contract Executor {
                function execute(bytes calldata data) external {
                    (bool success,) = address(this).call(data);
                    require(success);
                }
            }
        "#;
        let findings = detector.find_unprotected_execute(vulnerable);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_protected_execute() {
        let detector = Eip7702AuthorizationBypassDetector::new();

        let safe = r#"
            contract SafeExecutor {
                function execute(bytes calldata data) external onlyOwner {
                    (bool success,) = address(this).call(data);
                    require(success);
                }
            }
        "#;
        let findings = detector.find_unprotected_execute(safe);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_unprotected_fallback() {
        let detector = Eip7702AuthorizationBypassDetector::new();

        let vulnerable = r#"
            contract Proxy {
                fallback() external payable {
                    address impl = implementation;
                    (bool success,) = impl.delegatecall(msg.data);
                }
            }
        "#;
        let findings = detector.find_unprotected_fallback(vulnerable);
        assert!(!findings.is_empty());
    }
}
