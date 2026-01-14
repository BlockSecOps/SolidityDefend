use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for governance parameter bypass vulnerabilities
///
/// Detects patterns where governance parameters can be changed before
/// timelock restrictions take effect, bypassing governance controls.
pub struct GovernanceParameterBypassDetector {
    base: BaseDetector,
}

impl Default for GovernanceParameterBypassDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl GovernanceParameterBypassDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("governance-parameter-bypass"),
                "Governance Parameter Bypass".to_string(),
                "Detects governance parameters that can be changed before timelock \
                 restrictions apply, enabling admins to bypass governance controls."
                    .to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Logic],
                Severity::Critical,
            ),
        }
    }

    /// Find parameter changes without timelock
    fn find_untimelocked_params(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Track if contract has timelock
        let has_timelock = source.contains("TimelockController")
            || source.contains("timelock")
            || source.contains("Timelock");

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for setter functions for governance parameters
            if trimmed.contains("function set")
                && (trimmed.contains("external") || trimmed.contains("public"))
            {
                let func_name = self.extract_function_name(trimmed);

                // Check if it's a governance parameter
                let is_gov_param = func_name.to_lowercase().contains("quorum")
                    || func_name.to_lowercase().contains("threshold")
                    || func_name.to_lowercase().contains("delay")
                    || func_name.to_lowercase().contains("period")
                    || func_name.to_lowercase().contains("fee")
                    || func_name.to_lowercase().contains("rate")
                    || func_name.to_lowercase().contains("limit");

                if is_gov_param {
                    let func_end = self.find_function_end(&lines, line_num);
                    let func_body: String = lines[line_num..func_end].join("\n");

                    // Check for timelock protection
                    let has_timelock_check = func_body.contains("onlyTimelock")
                        || func_body.contains("timelockController")
                        || func_body.contains("require(msg.sender == timelock")
                        || func_body.contains("_checkTimelock");

                    if !has_timelock_check && !has_timelock {
                        let issue = "No timelock protection on governance parameter setter"
                            .to_string();
                        findings.push((line_num as u32 + 1, func_name, issue));
                    }
                }
            }

            // Look for direct state changes to governance variables
            if (trimmed.contains("votingDelay =")
                || trimmed.contains("votingPeriod =")
                || trimmed.contains("quorumNumerator =")
                || trimmed.contains("proposalThreshold ="))
                && !trimmed.starts_with("//")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                let issue = "Direct governance parameter modification".to_string();
                findings.push((line_num as u32 + 1, func_name, issue));
            }
        }

        findings
    }

    /// Find emergency parameter changes
    fn find_emergency_bypasses(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for emergency functions that bypass governance
            if trimmed.contains("function ")
                && (trimmed.contains("emergency") || trimmed.contains("Emergency"))
                && (trimmed.contains("external") || trimmed.contains("public"))
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check if emergency function modifies governance params
                if func_body.contains("votingDelay")
                    || func_body.contains("votingPeriod")
                    || func_body.contains("quorum")
                    || func_body.contains("threshold")
                {
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

impl Detector for GovernanceParameterBypassDetector {
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

        for (line, func_name, issue) in self.find_untimelocked_params(source) {
            let message = format!(
                "Function '{}' in contract '{}' allows governance parameter changes without \
                 timelock protection. {}. Admins can bypass governance by changing parameters \
                 before proposals execute.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(284)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Protect governance parameter changes:\n\n\
                     1. Route all parameter changes through timelock\n\
                     2. Use onlyTimelock modifier for setters\n\
                     3. Implement parameter change proposals\n\
                     4. Add minimum delay before changes take effect\n\n\
                     Example:\n\
                     function setVotingDelay(uint256 newDelay) external onlyTimelock {\n\
                         _setVotingDelay(newDelay);\n\
                     }"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_emergency_bypasses(source) {
            let message = format!(
                "Emergency function '{}' in contract '{}' can modify governance parameters, \
                 potentially bypassing governance controls during emergencies.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(284)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Limit emergency function scope:\n\n\
                     1. Emergency functions should only pause, not modify parameters\n\
                     2. Require multi-sig for emergency parameter changes\n\
                     3. Log all emergency actions with events\n\
                     4. Add cool-down periods after emergency use"
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
        let detector = GovernanceParameterBypassDetector::new();
        assert_eq!(detector.name(), "Governance Parameter Bypass");
        assert_eq!(detector.default_severity(), Severity::Critical);
    }
}
