use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};
use crate::utils::{is_secure_example_file, is_standard_token, is_test_contract};

/// Detector for encrypted mempool timing attacks
///
/// Detects patterns vulnerable to timing attacks even when using
/// encrypted mempools or commit-reveal schemes.
pub struct EncryptedMempoolTimingDetector {
    base: BaseDetector,
}

impl Default for EncryptedMempoolTimingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl EncryptedMempoolTimingDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("encrypted-mempool-timing"),
                "Encrypted Mempool Timing Attack".to_string(),
                "Detects timing vulnerabilities in encrypted mempool or commit-reveal \
                 implementations where transaction timing can leak information."
                    .to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::Logic],
                Severity::Medium,
            ),
        }
    }

    /// Find commit-reveal with timing issues
    fn find_timing_vulnerable_commit_reveal(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let has_commit = source.contains("commit") || source.contains("Commit");
        let has_reveal = source.contains("reveal") || source.contains("Reveal");

        if has_commit && has_reveal {
            for (line_num, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                if trimmed.contains("function ") && trimmed.contains("reveal") {
                    let func_end = self.find_function_end(&lines, line_num);
                    let func_body: String = lines[line_num..func_end].join("\n");
                    let func_name = self.extract_function_name(trimmed);

                    // Check for timing protection
                    let has_random_delay =
                        func_body.contains("randomDelay") || func_body.contains("minRevealTime");

                    let has_batch_reveal =
                        func_body.contains("batch") || func_body.contains("Batch");

                    if !has_random_delay && !has_batch_reveal {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find gas-based timing leaks
    fn find_gas_timing_leaks(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Variable gas consumption based on input
            if trimmed.contains("for") || trimmed.contains("while") {
                let context_end = std::cmp::min(line_num + 10, lines.len());
                let context: String = lines[line_num..context_end].join("\n");

                // Loop with encrypted/hidden data
                if context.contains("encrypted")
                    || context.contains("hash")
                    || context.contains("commit")
                {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find deadline-based timing attacks
    fn find_deadline_timing(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Fixed deadlines are predictable
            if trimmed.contains("deadline")
                && (trimmed.contains("+ 1")
                    || trimmed.contains("+ 2")
                    || trimmed.contains("hours")
                    || trimmed.contains("minutes"))
            {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
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

    /// Phase 51 FP Reduction: Check if contract is MEV-sensitive
    /// Only contracts with auction, voting, or commit-reveal should be checked
    fn is_mev_sensitive_contract(&self, source: &str) -> bool {
        let lower = source.to_lowercase();

        // Auction patterns
        let has_auction = lower.contains("auction")
            || lower.contains("bid")
            || lower.contains("highest")
            || lower.contains("sealed");

        // Voting/governance patterns
        let has_voting =
            lower.contains("vote") || lower.contains("ballot") || lower.contains("proposal");

        // Commit-reveal patterns
        let has_commit_reveal = (lower.contains("commit") && lower.contains("reveal"))
            || lower.contains("commitment")
            || lower.contains("sealed");

        // Game/lottery patterns
        let has_game = lower.contains("lottery")
            || lower.contains("raffle")
            || lower.contains("randomness")
            || lower.contains("game");

        has_auction || has_voting || has_commit_reveal || has_game
    }
}

impl Detector for EncryptedMempoolTimingDetector {
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        // Phase 10: Skip test contracts, secure examples, and standard tokens
        // This detector is for MEV-sensitive commit-reveal patterns, not regular contracts
        if is_test_contract(ctx) || is_secure_example_file(ctx) || is_standard_token(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        // Phase 51 FP Reduction: Skip contracts without MEV-sensitive patterns
        // This detector should only apply to auction, voting, or commit-reveal systems
        if !self.is_mev_sensitive_contract(source) {
            return Ok(findings);
        }

        for (line, func_name) in self.find_timing_vulnerable_commit_reveal(source) {
            let message = format!(
                "Function '{}' in contract '{}' implements commit-reveal without timing protection. \
                 The reveal timing can leak information about the committed value.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(208)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add timing protection to commit-reveal:\n\n\
                     1. Use batch reveal periods\n\
                     2. Add minimum time between commit and reveal\n\
                     3. Randomize reveal ordering\n\
                     4. Use threshold decryption schemes"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Phase 51 FP Reduction: Skip gas timing leaks - too many FPs
        // This check was flagging normal loops with hashing operations
        // which are extremely common and usually not MEV-sensitive

        for (line, func_name) in self.find_deadline_timing(source) {
            // Phase 51 FP Reduction: Only flag deadlines in MEV-sensitive contexts
            // Skip deadline checks in normal swap/transfer patterns
            if func_name.to_lowercase().contains("swap")
                || func_name.to_lowercase().contains("transfer")
                || func_name.to_lowercase().contains("deposit")
                || func_name.to_lowercase().contains("withdraw")
            {
                continue;
            }

            let message = format!(
                "Function '{}' in contract '{}' uses predictable deadline timing. \
                 Attackers can time their actions around known deadlines.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(208)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Use variable or hidden deadlines:\n\n\
                     1. Add randomness to deadline calculation\n\
                     2. Use commit-reveal for deadline selection\n\
                     3. Implement gradual deadline mechanisms"
                        .to_string(),
                );

            findings.push(finding);
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
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
        let detector = EncryptedMempoolTimingDetector::new();
        assert_eq!(detector.name(), "Encrypted Mempool Timing Attack");
        assert_eq!(detector.default_severity(), Severity::Medium);
    }
}
