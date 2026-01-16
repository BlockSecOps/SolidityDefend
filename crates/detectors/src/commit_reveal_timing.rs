use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for commit-reveal timing vulnerabilities
///
/// Detects commit-reveal schemes with predictable timing or insufficient
/// delay between phases that can be exploited.
pub struct CommitRevealTimingDetector {
    base: BaseDetector,
}

impl Default for CommitRevealTimingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitRevealTimingDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("commit-reveal-timing"),
                "Commit-Reveal Timing".to_string(),
                "Detects commit-reveal schemes with timing vulnerabilities such as \
                 insufficient delays, predictable deadlines, or missing time bounds."
                    .to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::Timestamp],
                Severity::High,
            ),
        }
    }

    /// Find commit-reveal without proper timing
    fn find_timing_issues(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Check if contract has commit-reveal pattern
        let has_commit = source.contains("commit") || source.contains("Commit");
        let has_reveal = source.contains("reveal") || source.contains("Reveal");

        if !has_commit || !has_reveal {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect commit function
            if trimmed.contains("function ") &&
               (trimmed.contains("commit") || trimmed.contains("Commit"))
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for timestamp storage
                if !func_body.contains("block.timestamp") && !func_body.contains("block.number") {
                    let issue = "Commit without timestamp recording".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }

            // Detect reveal function
            if trimmed.contains("function ") &&
               (trimmed.contains("reveal") || trimmed.contains("Reveal"))
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for time validation
                if !func_body.contains("block.timestamp") && !func_body.contains("block.number")
                   && !func_body.contains("deadline") && !func_body.contains("expiry")
                {
                    let issue = "Reveal without time validation".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    /// Find same-block commit-reveal vulnerability
    fn find_same_block_vulnerability(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect reveal function
            if trimmed.contains("function ") &&
               (trimmed.contains("reveal") || trimmed.contains("Reveal"))
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check if it allows same-block reveal
                // Look for proper time delay patterns
                let has_block_check = func_body.contains("commitBlock") ||
                    func_body.contains("block.number >") ||
                    func_body.contains("block.number >=");

                let has_timestamp_check = func_body.contains("block.timestamp >") ||
                    func_body.contains("block.timestamp >=") ||
                    func_body.contains("commitTime") ||
                    func_body.contains("commit_time");

                let has_delay_pattern = func_body.contains("MIN_DELAY") ||
                    func_body.contains("REVEAL_DELAY") ||
                    func_body.contains("_DELAY") ||
                    func_body.contains("DELAY");

                if !has_block_check && !has_timestamp_check && !has_delay_pattern {
                    // Check if there's any commit storage pattern
                    if func_body.contains("commits[") || func_body.contains("commitment") {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find predictable deadline patterns
    fn find_predictable_deadlines(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect deadline assignments with small values
            if (trimmed.contains("deadline") || trimmed.contains("Deadline") ||
                trimmed.contains("revealPeriod") || trimmed.contains("commitPeriod"))
               && trimmed.contains("=")
            {
                // Check for small constant values (less than 1 hour in seconds)
                let has_small_value = trimmed.contains("= 60") ||
                    trimmed.contains("= 120") ||
                    trimmed.contains("= 300") ||
                    trimmed.contains("= 600") ||
                    trimmed.contains("minutes");

                if has_small_value {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find missing commit hash validation
    fn find_hash_validation_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect reveal function
            if trimmed.contains("function ") &&
               (trimmed.contains("reveal") || trimmed.contains("Reveal"))
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for proper hash verification
                if !func_body.contains("keccak256") && !func_body.contains("sha256") {
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

impl Detector for CommitRevealTimingDetector {
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

        for (line, func_name, issue) in self.find_timing_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' has commit-reveal timing issue: {}. \
                 Without proper timing, attackers can observe commits and act before reveals.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(330)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Implement proper commit-reveal timing:\n\n\
                     1. Record commit timestamp/block\n\
                     2. Require minimum delay before reveal (1+ blocks)\n\
                     3. Add maximum reveal deadline\n\
                     4. Prevent same-block commit and reveal"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_same_block_vulnerability(source) {
            let message = format!(
                "Function '{}' in contract '{}' may allow same-block commit and reveal. \
                 Attackers can see commits in mempool and reveal in same block.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(330)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Prevent same-block reveals:\n\n\
                     require(\n\
                         block.number > commits[msg.sender].blockNumber,\n\
                         \"Must wait at least 1 block\"\n\
                     );"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_predictable_deadlines(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses short commit-reveal deadline. \
                 Short deadlines may not provide sufficient protection.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(330)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Use appropriate timing parameters:\n\n\
                     - Minimum delay: At least 1-2 blocks\n\
                     - Reveal window: Long enough for honest users\n\
                     - Consider network congestion scenarios"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_hash_validation_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' reveals without hash verification. \
                 Revealed values must be checked against committed hash.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(330)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Verify revealed values:\n\n\
                     require(\n\
                         keccak256(abi.encodePacked(value, salt)) == commits[msg.sender].hash,\n\
                         \"Invalid reveal\"\n\
                     );"
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
        let detector = CommitRevealTimingDetector::new();
        assert_eq!(detector.name(), "Commit-Reveal Timing");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
