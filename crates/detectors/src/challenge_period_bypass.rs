use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for challenge period bypass vulnerabilities
///
/// Detects patterns where withdrawals or state transitions can bypass
/// the challenge period in optimistic rollups.
pub struct ChallengePeriodBypassDetector {
    base: BaseDetector,
}

impl Default for ChallengePeriodBypassDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ChallengePeriodBypassDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("challenge-period-bypass"),
                "Challenge Period Bypass".to_string(),
                "Detects vulnerabilities allowing premature withdrawals or state \
                 finalization before the challenge period expires."
                    .to_string(),
                vec![DetectorCategory::L2, DetectorCategory::Timestamp],
                Severity::Critical,
            ),
        }
    }

    /// Find premature finalization patterns
    fn find_premature_finalization(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect finalization functions
            if trimmed.contains("function ")
                && (trimmed.contains("finalize")
                    || trimmed.contains("Finalize")
                    || trimmed.contains("completeWithdrawal")
                    || trimmed.contains("proveAndFinalize"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for challenge period validation
                if !func_body.contains("challengePeriod")
                    && !func_body.contains("finalizationPeriod")
                    && !func_body.contains("CHALLENGE_PERIOD")
                    && !func_body.contains("block.timestamp")
                {
                    let issue = "Finalization without challenge period check".to_string();
                    findings.push((line_num as u32 + 1, func_name.clone(), issue));
                }

                // Check for proper time comparison
                if func_body.contains("block.timestamp")
                    && !func_body.contains(">=")
                    && !func_body.contains(">")
                {
                    let issue = "Weak timestamp comparison in finalization".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    /// Find instant withdrawal patterns
    fn find_instant_withdrawal_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect withdrawal initiation and completion in same transaction
            if trimmed.contains("function ")
                && trimmed.contains("withdraw")
                && (trimmed.contains("external") || trimmed.contains("public"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for immediate transfer after withdrawal request
                if (func_body.contains("transfer(") || func_body.contains("safeTransfer"))
                    && !func_body.contains("pendingWithdrawals")
                    && !func_body.contains("withdrawalQueue")
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find challenge period manipulation vectors
    fn find_period_manipulation(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect modifiable challenge period
            if trimmed.contains("function ")
                && (trimmed.contains("setChallengePeriod")
                    || trimmed.contains("updatePeriod")
                    || trimmed.contains("setFinalizationPeriod"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for minimum period enforcement
                if !func_body.contains("MIN_") && !func_body.contains("minimum") {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }

            // Detect zero challenge period
            if (trimmed.contains("challengePeriod = 0")
                || trimmed.contains("CHALLENGE_PERIOD = 0")
                || trimmed.contains("finalizationPeriod = 0"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    /// Find dispute bypass patterns
    fn find_dispute_bypass(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect state root acceptance without dispute window
            if trimmed.contains("function ")
                && (trimmed.contains("acceptStateRoot") || trimmed.contains("confirmStateRoot"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for dispute window
                if !func_body.contains("disputed")
                    && !func_body.contains("challenged")
                    && !func_body.contains("fraud")
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }

            // Detect emergency bypass mechanisms
            if trimmed.contains("function ")
                && trimmed.contains("emergency")
                && trimmed.contains("finalize")
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                findings.push((line_num as u32 + 1, func_name));
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

impl Detector for ChallengePeriodBypassDetector {
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

        for (line, func_name, issue) in self.find_premature_finalization(source) {
            let message = format!(
                "Function '{}' in contract '{}' has challenge period bypass: {}. \
                 Withdrawals may be finalized before the challenge period expires, \
                 allowing fraudulent transactions to be accepted.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(367)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Enforce challenge period:\n\n\
                     1. Require block.timestamp >= proposalTime + CHALLENGE_PERIOD\n\
                     2. Use strict timestamp comparisons (>=, not >)\n\
                     3. Store proposal timestamp at initiation\n\
                     4. Verify no pending challenges before finalization\n\
                     5. Add minimum challenge period constant (e.g., 7 days)"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_instant_withdrawal_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' allows instant withdrawals without \
                 queuing. This bypasses the challenge/dispute mechanism.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(367)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Implement withdrawal queue:\n\n\
                     1. Separate withdrawal request from finalization\n\
                     2. Queue withdrawals with timestamp\n\
                     3. Require challenge period before claiming\n\
                     4. Track pending withdrawals per user"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_period_manipulation(source) {
            let message = format!(
                "Function '{}' in contract '{}' allows challenge period manipulation. \
                 Setting period to zero would disable fraud proofs.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(367)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Protect challenge period configuration:\n\n\
                     1. Enforce minimum challenge period (MIN_CHALLENGE_PERIOD)\n\
                     2. Use timelock for period changes\n\
                     3. Require governance approval for changes\n\
                     4. Never allow zero challenge period"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_dispute_bypass(source) {
            let message = format!(
                "Function '{}' in contract '{}' accepts state without dispute verification. \
                 Fraudulent state roots could be finalized without challenge.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(367)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Add dispute verification:\n\n\
                     1. Check for pending disputes before acceptance\n\
                     2. Require dispute resolution before finalization\n\
                     3. Track challenged proposals separately\n\
                     4. Emergency functions should pause, not bypass"
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
        let detector = ChallengePeriodBypassDetector::new();
        assert_eq!(detector.name(), "Challenge Period Bypass");
        assert_eq!(detector.default_severity(), Severity::Critical);
    }
}
