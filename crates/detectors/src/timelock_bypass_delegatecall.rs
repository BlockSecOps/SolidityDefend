use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for timelock bypass via delegatecall vulnerabilities
///
/// Detects patterns where timelock guards can be bypassed through
/// delegatecall via proxy contracts.
pub struct TimelockBypassDelegatecallDetector {
    base: BaseDetector,
}

impl Default for TimelockBypassDelegatecallDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl TimelockBypassDelegatecallDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("timelock-bypass-delegatecall"),
                "Timelock Bypass via Delegatecall".to_string(),
                "Detects patterns where timelock restrictions can be bypassed by \
                 routing calls through proxy contracts with delegatecall."
                    .to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Upgradeable],
                Severity::Critical,
            ),
        }
    }

    /// Find delegatecall timelock bypass patterns
    fn find_delegatecall_bypass(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Check if contract has timelock
        let has_timelock = source.contains("TimelockController")
            || source.contains("onlyTimelock")
            || source.contains("timelock");

        if !has_timelock {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for delegatecall patterns
            if trimmed.contains("delegatecall") && !trimmed.starts_with("//") {
                let func_name = self.find_containing_function(&lines, line_num);

                // Check if the delegatecall bypasses timelock
                let context_start = if line_num > 20 { line_num - 20 } else { 0 };
                let context_end = (line_num + 10).min(lines.len());
                let context: String = lines[context_start..context_end].join("\n");

                let has_timelock_check = context.contains("onlyTimelock")
                    || context.contains("require(msg.sender == timelock");

                if !has_timelock_check {
                    let issue = "Delegatecall without timelock verification".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }

            // Look for execute functions that might bypass timelock
            if trimmed.contains("function execute")
                && (trimmed.contains("external") || trimmed.contains("public"))
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check if execute uses delegatecall without timelock
                if func_body.contains("delegatecall") && !func_body.contains("onlyTimelock") {
                    let issue = "Execute function with delegatecall lacks timelock".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    /// Find proxy pattern vulnerabilities
    fn find_proxy_bypass(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for fallback functions with delegatecall
            if (trimmed.contains("fallback()") || trimmed.contains("receive()"))
                && (trimmed.contains("external") || trimmed.contains("payable"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for delegatecall to implementation
                if func_body.contains("delegatecall") {
                    // Check if implementation can be changed without timelock
                    let has_timelock_upgrade = source.contains("onlyTimelock")
                        && (source.contains("upgradeTo") || source.contains("setImplementation"));

                    if !has_timelock_upgrade {
                        findings.push((line_num as u32 + 1, "fallback".to_string()));
                    }
                }
            }
        }

        findings
    }

    /// Find msg.sender confusion in delegatecall
    fn find_sender_confusion(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for timelock checks that might be bypassed
            if trimmed.contains("msg.sender == timelock")
                || trimmed.contains("msg.sender == address(timelock)")
            {
                // Check for delegatecall context
                let context_start = if line_num > 30 { line_num - 30 } else { 0 };
                let context: String = lines[context_start..line_num].join("\n");

                // If this check is in a function that can be delegatecalled to
                if context.contains("delegatecall") || source.contains("Proxy") {
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

impl Detector for TimelockBypassDelegatecallDetector {
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

        for (line, func_name, issue) in self.find_delegatecall_bypass(source) {
            let message = format!(
                "Function '{}' in contract '{}' may bypass timelock via delegatecall. {}. \
                 Attackers can route timelocked operations through proxy to skip delays.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(863)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Prevent timelock bypass via delegatecall:\n\n\
                     1. Apply timelock checks to all entry points\n\
                     2. Verify msg.sender in implementation, not just proxy\n\
                     3. Disable delegatecall for timelocked functions\n\
                     4. Use explicit function calls instead of delegatecall\n\n\
                     Example:\n\
                     modifier onlyTimelock() {\n\
                         require(msg.sender == address(timelock), \"Not timelock\");\n\
                         require(address(this) == implementation, \"No delegatecall\");\n\
                         _;\n\
                     }"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_proxy_bypass(source) {
            let message = format!(
                "Proxy {} in contract '{}' can bypass timelock through implementation switch. \
                 Admins can change implementation to bypass timelocked functions.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(863)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Protect proxy implementation changes:\n\n\
                     1. Require timelock for implementation upgrades\n\
                     2. Add upgrade delay longer than max proposal timelock\n\
                     3. Emit events for all implementation changes"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_sender_confusion(source) {
            let message = format!(
                "Timelock check in '{}' of contract '{}' may be confused in delegatecall context. \
                 msg.sender preservation in delegatecall can bypass authorization.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(863)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Verify delegatecall context:\n\n\
                     require(address(this) == expectedAddress, \"Direct call only\");"
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
        let detector = TimelockBypassDelegatecallDetector::new();
        assert_eq!(detector.name(), "Timelock Bypass via Delegatecall");
        assert_eq!(detector.default_severity(), Severity::Critical);
    }
}
