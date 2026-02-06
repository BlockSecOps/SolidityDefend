use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for proposal front-running vulnerabilities
///
/// Detects patterns where governance proposals can be front-run with
/// counter-proposals in the same block to manipulate voting outcomes.
pub struct ProposalFrontrunningDetector {
    base: BaseDetector,
}

impl Default for ProposalFrontrunningDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProposalFrontrunningDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("proposal-frontrunning"),
                "Proposal Front-running".to_string(),
                "Detects governance systems vulnerable to proposal front-running where \
                 attackers can submit counter-proposals in the same block."
                    .to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::AccessControl],
                Severity::High,
            ),
        }
    }

    /// Find proposal front-running vulnerabilities
    fn find_frontrun_issues(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for proposal creation functions
            if trimmed.contains("function ")
                && (trimmed.contains("propose") || trimmed.contains("createProposal"))
                && (trimmed.contains("external") || trimmed.contains("public"))
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for same-block proposal prevention
                let has_block_protection = func_body.contains("lastProposalBlock")
                    || func_body.contains("block.number >")
                    || func_body.contains("proposalCooldown");

                if !has_block_protection {
                    let issue = "No same-block proposal prevention".to_string();
                    findings.push((line_num as u32 + 1, func_name.clone(), issue));
                }

                // Check for commit-reveal protection
                let has_commit_reveal = func_body.contains("commit")
                    || func_body.contains("reveal")
                    || func_body.contains("sealed");

                if !has_commit_reveal {
                    let issue = "No commit-reveal scheme for proposal content".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    /// Find proposal ID prediction vulnerabilities
    fn find_proposal_id_prediction(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for predictable proposal ID generation
            if trimmed.contains("proposalId") && trimmed.contains("keccak256") {
                // Check if hash includes unpredictable components
                let context_end = (line_num + 3).min(lines.len());
                let context: String = lines[line_num..context_end].join("\n");

                let has_randomness = context.contains("block.prevrandao")
                    || context.contains("chainlink")
                    || context.contains("VRF");

                if !has_randomness && !context.contains("msg.sender") && !context.contains("nonce")
                {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find voting delay issues
    fn find_voting_delay_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Check for zero or very low voting delay
        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if (trimmed.contains("votingDelay") || trimmed.contains("VOTING_DELAY"))
                && trimmed.contains("=")
            {
                // Check for zero or very low delay
                if trimmed.contains("= 0") || trimmed.contains("= 1") {
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
        "constructor".to_string()
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

impl Detector for ProposalFrontrunningDetector {
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

        for (line, func_name, issue) in self.find_frontrun_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' is vulnerable to proposal front-running. {}. \
                 Attackers can observe proposals in mempool and submit counter-proposals first.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Protect against proposal front-running:\n\n\
                     1. Implement commit-reveal for proposals\n\
                     2. Add minimum delay between proposals from same proposer\n\
                     3. Prevent multiple proposals in same block\n\
                     4. Use private mempool (Flashbots) for submission\n\n\
                     Example:\n\
                     require(block.number > lastProposalBlock[msg.sender] + 1, \
                     \"Wait before next proposal\");\n\
                     lastProposalBlock[msg.sender] = block.number;"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_proposal_id_prediction(source) {
            let message = format!(
                "Proposal ID in '{}' of contract '{}' is predictable. \
                 Attackers can pre-compute IDs and prepare front-running attacks.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Low)
                .with_fix_suggestion(
                    "Make proposal IDs less predictable:\n\n\
                     1. Include msg.sender in ID hash\n\
                     2. Add incrementing nonce per proposer\n\
                     3. Include previous proposal ID in hash chain"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_voting_delay_issues(source) {
            let message = format!(
                "Voting delay in '{}' of contract '{}' is zero or very low. \
                 This allows immediate voting after proposal, enabling front-running.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Set appropriate voting delay:\n\n\
                     1. Use minimum 1-day delay for mainnet\n\
                     2. Allow users time to review proposals\n\
                     3. Delay prevents same-block voting manipulation\n\n\
                     Example: uint256 public constant VOTING_DELAY = 7200; // ~1 day"
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
        let detector = ProposalFrontrunningDetector::new();
        assert_eq!(detector.name(), "Proposal Front-running");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
