use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for voting snapshot manipulation vulnerabilities
///
/// Detects patterns where voting snapshots are taken after delegation
/// transactions, allowing flash loan or just-in-time voting attacks.
pub struct VotingSnapshotManipulationDetector {
    base: BaseDetector,
}

impl Default for VotingSnapshotManipulationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl VotingSnapshotManipulationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("voting-snapshot-manipulation"),
                "Voting Snapshot Manipulation".to_string(),
                "Detects voting systems where snapshots can be taken after token \
                 acquisition or delegation, enabling flash loan voting attacks."
                    .to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::DeFi],
                Severity::High,
            ),
        }
    }

    /// Find vulnerable snapshot patterns
    fn find_snapshot_issues(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for voting functions
            if trimmed.contains("function ")
                && (trimmed.contains("vote") || trimmed.contains("castVote"))
                && (trimmed.contains("external") || trimmed.contains("public"))
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for current block snapshot (vulnerable)
                if func_body.contains("block.number") && !func_body.contains("- 1") {
                    let issue = "Uses current block for voting power snapshot".to_string();
                    findings.push((line_num as u32 + 1, func_name.clone(), issue));
                }

                // Check for missing snapshot
                if !func_body.contains("getPastVotes")
                    && !func_body.contains("getPriorVotes")
                    && !func_body.contains("getVotesAtBlock")
                    && func_body.contains("balanceOf")
                {
                    let issue = "Uses current balance instead of historical snapshot".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }

            // Look for proposal creation without snapshot lock
            if trimmed.contains("function ")
                && (trimmed.contains("propose") || trimmed.contains("createProposal"))
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check if snapshot is set at proposal creation
                if !func_body.contains("snapshot") && !func_body.contains("startBlock") {
                    let issue = "Proposal created without locking snapshot block".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    /// Find delegation timing issues
    fn find_delegation_timing(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for delegate functions
            if trimmed.contains("function delegate") {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check if delegation takes effect immediately
                if !func_body.contains("checkpoint")
                    && !func_body.contains("_writeCheckpoint")
                    && func_body.contains("delegates[")
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

impl Detector for VotingSnapshotManipulationDetector {
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

        for (line, func_name, issue) in self.find_snapshot_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' has snapshot manipulation vulnerability. {}. \
                 Attackers can acquire tokens or delegate just before voting.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Protect against snapshot manipulation:\n\n\
                     1. Use historical snapshots (block.number - 1)\n\
                     2. Lock snapshot at proposal creation time\n\
                     3. Use ERC20Votes with checkpointing\n\
                     4. Implement minimum holding period\n\n\
                     Example:\n\
                     uint256 votes = token.getPastVotes(voter, proposal.snapshotBlock);"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_delegation_timing(source) {
            let message = format!(
                "Function '{}' in contract '{}' allows immediate delegation effect. \
                 Attackers can delegate flash-loaned tokens for instant voting power.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add delegation delay:\n\n\
                     1. Use checkpointing for delegation (ERC20Votes)\n\
                     2. Require minimum token holding time before delegation\n\
                     3. Snapshot voting power at proposal creation"
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
        let detector = VotingSnapshotManipulationDetector::new();
        assert_eq!(detector.name(), "Voting Snapshot Manipulation");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
