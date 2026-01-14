use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for access control race condition vulnerabilities
///
/// Detects patterns where role grant/revoke operations can race between
/// transactions, leading to unintended access states.
pub struct AccessControlRaceConditionDetector {
    base: BaseDetector,
}

impl Default for AccessControlRaceConditionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AccessControlRaceConditionDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("accesscontrol-race-condition"),
                "Access Control Race Condition".to_string(),
                "Detects access control patterns vulnerable to race conditions where \
                 concurrent grant/revoke operations can lead to privilege confusion."
                    .to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    /// Find grant/revoke race conditions
    fn find_grant_revoke_races(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for batch role operations
            if trimmed.contains("function ")
                && (trimmed.contains("batch") || trimmed.contains("Batch"))
                && (trimmed.contains("Role") || trimmed.contains("role"))
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for atomic operations
                if !func_body.contains("nonReentrant") && !func_body.contains("lock") {
                    let issue = "Batch role operation lacks atomicity protection".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }

            // Look for separate grant and revoke in sequence
            if trimmed.contains("grantRole") && !trimmed.starts_with("//") {
                let context_end = (line_num + 10).min(lines.len());
                let context: String = lines[line_num..context_end].join("\n");

                // Check if revoke follows without atomicity
                if context.contains("revokeRole") && !context.contains("atomic") {
                    let func_name = self.find_containing_function(&lines, line_num);
                    let issue = "Grant and revoke operations not atomic".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    /// Find role check timing issues
    fn find_role_check_timing(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for hasRole checks followed by state changes
            if trimmed.contains("hasRole") && !trimmed.starts_with("//") {
                let context_end = (line_num + 15).min(lines.len());
                let context: String = lines[line_num..context_end].join("\n");

                // Check if role can be revoked during execution
                if context.contains(".call") || context.contains("transfer") {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find role transition vulnerabilities
    fn find_role_transition_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for admin role transfers
            if trimmed.contains("DEFAULT_ADMIN_ROLE") && trimmed.contains("grantRole") {
                let func_name = self.find_containing_function(&lines, line_num);

                // Check if old admin is revoked atomically
                let context_start = if line_num > 5 { line_num - 5 } else { 0 };
                let context_end = (line_num + 5).min(lines.len());
                let context: String = lines[context_start..context_end].join("\n");

                if !context.contains("revokeRole") {
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

impl Detector for AccessControlRaceConditionDetector {
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

        for (line, func_name, issue) in self.find_grant_revoke_races(source) {
            let message = format!(
                "Function '{}' in contract '{}' has access control race condition. {}. \
                 Concurrent transactions may result in unintended privilege states.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Protect role operations from races:\n\n\
                     1. Use atomic role transitions (grant + revoke in same tx)\n\
                     2. Add reentrancy guards to role management functions\n\
                     3. Implement role transition delays\n\n\
                     Example:\n\
                     function transferAdmin(address newAdmin) external onlyRole(DEFAULT_ADMIN_ROLE) {\n\
                         _grantRole(DEFAULT_ADMIN_ROLE, newAdmin);\n\
                         _revokeRole(DEFAULT_ADMIN_ROLE, msg.sender);\n\
                     }"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_role_check_timing(source) {
            let message = format!(
                "Role check in '{}' of contract '{}' may be stale during execution. \
                 External calls after hasRole can be exploited if role is revoked mid-tx.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Low)
                .with_fix_suggestion(
                    "Prevent role check bypass:\n\n\
                     1. Verify role at transaction end, not just beginning\n\
                     2. Use onlyRole modifier which checks per-call\n\
                     3. Cache role state with ReentrancyGuard"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_role_transition_issues(source) {
            let message = format!(
                "Admin role grant in '{}' of contract '{}' without corresponding revoke. \
                 Multiple admin accounts create confusion and security risks.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Implement proper admin transfer:\n\n\
                     1. Grant to new admin and revoke from old atomically\n\
                     2. Use 2-step transfer pattern (propose + accept)\n\
                     3. Emit events for admin changes"
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
        let detector = AccessControlRaceConditionDetector::new();
        assert_eq!(detector.name(), "Access Control Race Condition");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
