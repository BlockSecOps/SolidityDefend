use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for governance proposal MEV vulnerabilities
///
/// Detects patterns where governance proposal submissions can be
/// front-run to influence outcomes or extract value.
pub struct GovernanceProposalMevDetector {
    base: BaseDetector,
}

impl Default for GovernanceProposalMevDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl GovernanceProposalMevDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("governance-proposal-mev"),
                "Governance Proposal MEV".to_string(),
                "Detects governance proposal patterns vulnerable to front-running where \
                 attackers can submit counter-proposals or acquire voting power before \
                 proposal execution."
                    .to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::AccessControl],
                Severity::High,
            ),
        }
    }

    /// Find proposal submission vulnerabilities
    fn find_proposal_submission(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ")
                && (trimmed.contains("propose") || trimmed.contains("createProposal"))
                && (trimmed.contains("external") || trimmed.contains("public"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for MEV protection
                let has_protection = func_body.contains("commit")
                    || func_body.contains("delay")
                    || func_body.contains("snapshot");

                if !has_protection {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find voting power acquisition vulnerabilities
    fn find_voting_power_acquisition(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for voting power being used immediately
            if trimmed.contains("getVotes") || trimmed.contains("getPriorVotes") {
                let context_start = if line_num > 10 { line_num - 10 } else { 0 };
                let context_end = (line_num + 5).min(lines.len());
                let context: String = lines[context_start..context_end].join("\n");

                // Check if snapshot is at current block (vulnerable)
                if context.contains("block.number") && !context.contains("- 1") {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find execution front-running vulnerabilities
    fn find_execution_frontrun(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ")
                && (trimmed.contains("execute") || trimmed.contains("queue"))
                && (trimmed.contains("external") || trimmed.contains("public"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for state-dependent execution
                if func_body.contains("balance")
                    || func_body.contains("price")
                    || func_body.contains("oracle")
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find flash loan governance attacks
    fn find_flash_governance(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let has_flash = source.contains("flash") || source.contains("Flash");
        let has_governance =
            source.contains("vote") || source.contains("propose") || source.contains("delegate");

        if has_flash && has_governance {
            for (line_num, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                if trimmed.contains("function ") && trimmed.contains("vote") {
                    let func_name = self.extract_function_name(trimmed);
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

impl Detector for GovernanceProposalMevDetector {
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

        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        for (line, func_name) in self.find_proposal_submission(source) {
            let message = format!(
                "Function '{}' in contract '{}' allows proposal submission without MEV protection. \
                 Attackers can front-run with counter-proposals or acquire voting power.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Protect proposal submission from front-running:\n\n\
                     1. Use commit-reveal for proposals\n\
                     2. Snapshot voting power before proposal is public\n\
                     3. Add proposal submission delays\n\
                     4. Require minimum token holding period"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_voting_power_acquisition(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses current block for voting snapshot. \
                 Attackers can acquire tokens in the same block to influence votes.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Use historical snapshots for voting power:\n\n\
                     // Use prior block for snapshot\n\
                     uint256 votes = getPriorVotes(voter, block.number - 1);\n\n\
                     // Or use proposal creation block\n\
                     uint256 votes = getPriorVotes(voter, proposal.startBlock);"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_execution_frontrun(source) {
            let message = format!(
                "Function '{}' in contract '{}' executes proposals with state-dependent logic. \
                 Attackers can manipulate state before execution.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Protect proposal execution:\n\n\
                     1. Lock relevant state during execution\n\
                     2. Use TWAP for price-dependent actions\n\
                     3. Add slippage protection to executed transactions\n\
                     4. Consider batched/atomic execution"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_flash_governance(source) {
            let message = format!(
                "Function '{}' in contract '{}' may be vulnerable to flash loan governance attacks. \
                 Attackers can borrow tokens, vote, and return in one transaction.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Prevent flash loan governance attacks:\n\n\
                     1. Require tokens to be held for minimum time\n\
                     2. Use historical snapshots (getPriorVotes)\n\
                     3. Add vote escrow requirements\n\
                     4. Implement checkpointing at transfer time"
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
        let detector = GovernanceProposalMevDetector::new();
        assert_eq!(detector.name(), "Governance Proposal MEV");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
