use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for over-reliance on L1 escape hatch mechanisms
///
/// Detects patterns where contracts excessively depend on L1 escape mechanisms
/// without proper fallback handling or timeout considerations.
pub struct EscapeHatchDependencyDetector {
    base: BaseDetector,
}

impl Default for EscapeHatchDependencyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl EscapeHatchDependencyDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("escape-hatch-dependency"),
                "Escape Hatch Dependency".to_string(),
                "Detects over-reliance on L1 escape hatch mechanisms in L2 contracts \
                 without proper timeout handling or alternative recovery paths."
                    .to_string(),
                vec![DetectorCategory::L2, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    /// Find escape hatch patterns without proper timeouts
    fn find_escape_hatch_issues(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect escape hatch function patterns
            if trimmed.contains("function ")
                && (trimmed.contains("escape")
                    || trimmed.contains("Escape")
                    || trimmed.contains("emergencyWithdraw")
                    || trimmed.contains("forceWithdraw")
                    || trimmed.contains("l1Withdraw"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for timeout/deadline validation
                if !func_body.contains("deadline")
                    && !func_body.contains("timeout")
                    && !func_body.contains("block.timestamp")
                    && !func_body.contains("block.number")
                {
                    let issue = "Escape hatch without timeout validation".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }

            // Detect L1 message dependencies
            if (trimmed.contains("sendToL1") || trimmed.contains("sendMessage"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end.min(line_num + 30)].join("\n");

                // Check for retry/fallback logic
                if !func_body.contains("retry")
                    && !func_body.contains("fallback")
                    && !func_body.contains("alternative")
                {
                    let issue = "L1 message without retry mechanism".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    /// Find forced withdrawal patterns
    fn find_forced_withdrawal_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect forced withdrawal without sequencer status check
            if trimmed.contains("function ")
                && (trimmed.contains("forceInclude") || trimmed.contains("forcedWithdrawal"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Should check sequencer status
                if !func_body.contains("sequencerUp")
                    && !func_body.contains("isSequencerActive")
                    && !func_body.contains("sequencerStatus")
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find L1 bridge dependency issues
    fn find_bridge_dependency_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let has_l1_bridge = source.contains("L1Bridge")
            || source.contains("CrossDomainMessenger")
            || source.contains("Inbox");

        if !has_l1_bridge {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect critical functions that only work via L1
            if trimmed.contains("function ")
                && (trimmed.contains("onlyL1") || trimmed.contains("onlyBridge"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);

                // Check if there's an emergency bypass
                let func_end = self.find_function_end(&lines, line_num);
                let remaining_code: String = lines[func_end..].join("\n");

                if !remaining_code.contains(&format!("emergency{}", func_name))
                    && !remaining_code.contains("emergencyOverride")
                {
                    findings.push((line_num as u32 + 1, func_name));
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
        }
        "unknown".to_string()
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

impl Detector for EscapeHatchDependencyDetector {
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

        // CRITICAL FP FIX: Only analyze L2/cross-chain contracts
        // This detector is for L2 escape hatch mechanisms, NOT simple emergency withdrawals.
        // A regular onlyOwner emergencyWithdraw on an L1 contract is NOT an L2 escape hatch.
        if !utils::is_l2_contract(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        for (line, func_name, issue) in self.find_escape_hatch_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' has escape hatch issue: {}. \
                 Users may be unable to recover funds if L1 mechanisms are congested or unavailable.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(754)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Improve escape hatch reliability:\n\n\
                     1. Add timeout-based automatic unlocks\n\
                     2. Implement retry mechanisms for L1 messages\n\
                     3. Provide alternative withdrawal paths\n\
                     4. Add sequencer downtime detection\n\
                     5. Consider L1 gas price caps for escape transactions"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_forced_withdrawal_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' implements forced withdrawal without \
                 checking sequencer status. May fail during sequencer outages.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(754)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add sequencer status checks:\n\n\
                     1. Integrate Chainlink sequencer uptime feed\n\
                     2. Implement grace period after sequencer recovery\n\
                     3. Allow forced inclusion only after sequencer downtime threshold"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_bridge_dependency_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' only accessible via L1 bridge without \
                 emergency override. Critical operations may be inaccessible during bridge issues.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(754)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add emergency access paths:\n\n\
                     1. Implement time-delayed emergency functions\n\
                     2. Add multi-sig override capability\n\
                     3. Consider governance-based emergency access\n\
                     4. Document recovery procedures"
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
        let detector = EscapeHatchDependencyDetector::new();
        assert_eq!(detector.name(), "Escape Hatch Dependency");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
