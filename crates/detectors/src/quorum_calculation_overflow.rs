use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for quorum calculation overflow vulnerabilities
///
/// Detects patterns where quorum calculations can overflow or be
/// manipulated via reentrancy to over-count votes.
pub struct QuorumCalculationOverflowDetector {
    base: BaseDetector,
}

impl Default for QuorumCalculationOverflowDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl QuorumCalculationOverflowDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("quorum-calculation-overflow"),
                "Quorum Calculation Overflow".to_string(),
                "Detects quorum calculations vulnerable to overflow or reentrancy \
                 attacks that can over-count votes and bypass quorum requirements."
                    .to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Logic],
                Severity::Critical,
            ),
        }
    }

    /// Find quorum overflow vulnerabilities
    fn find_quorum_overflow(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for quorum calculation functions
            if trimmed.contains("function ")
                && (trimmed.contains("quorum") || trimmed.contains("Quorum"))
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for unchecked multiplication
                if func_body.contains("unchecked")
                    && (func_body.contains("*") || func_body.contains("totalSupply"))
                {
                    let issue = "Unchecked arithmetic in quorum calculation".to_string();
                    findings.push((line_num as u32 + 1, func_name.clone(), issue));
                }

                // Check for division before multiplication (precision loss)
                if func_body.contains("/") && func_body.contains("*") {
                    // Simple heuristic: if division appears before multiplication
                    let div_pos = func_body.find('/');
                    let mul_pos = func_body.find('*');
                    if let (Some(d), Some(m)) = (div_pos, mul_pos) {
                        if d < m {
                            let issue = "Division before multiplication causes precision loss"
                                .to_string();
                            findings.push((line_num as u32 + 1, func_name.clone(), issue));
                        }
                    }
                }
            }

            // Look for vote counting with potential reentrancy
            if trimmed.contains("function ")
                && (trimmed.contains("castVote") || trimmed.contains("_countVote"))
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for state changes after external calls
                if (func_body.contains(".call") || func_body.contains("callback"))
                    && (func_body.contains("+=") || func_body.contains("forVotes"))
                {
                    let issue =
                        "Vote counting may be vulnerable to reentrancy over-counting".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    /// Find vote weight manipulation
    fn find_vote_weight_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for vote weight calculations
            if (trimmed.contains("forVotes +=") || trimmed.contains("againstVotes +="))
                && !trimmed.starts_with("//")
            {
                // Check context for reentrancy protection
                let context_start = if line_num > 20 { line_num - 20 } else { 0 };
                let context: String = lines[context_start..line_num].join("\n");

                let has_guard = context.contains("nonReentrant")
                    || context.contains("ReentrancyGuard")
                    || context.contains("hasVoted[");

                if !has_guard {
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

impl Detector for QuorumCalculationOverflowDetector {
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

        for (line, func_name, issue) in self.find_quorum_overflow(source) {
            let message = format!(
                "Function '{}' in contract '{}' has quorum calculation vulnerability. {}. \
                 Attackers may manipulate quorum to pass proposals with insufficient votes.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(190)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Fix quorum calculation:\n\n\
                     1. Use checked arithmetic (Solidity 0.8+ default)\n\
                     2. Multiply before dividing to maintain precision\n\
                     3. Use OpenZeppelin's SafeMath for older versions\n\n\
                     Example:\n\
                     // Correct: multiply first\n\
                     uint256 quorum = (totalSupply * quorumNumerator) / quorumDenominator;"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_vote_weight_issues(source) {
            let message = format!(
                "Vote counting in function '{}' of contract '{}' lacks reentrancy protection. \
                 Attackers can vote multiple times via reentrancy to exceed quorum.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(190)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Protect vote counting:\n\n\
                     1. Add ReentrancyGuard to voting functions\n\
                     2. Mark voters as voted before counting\n\
                     3. Use checks-effects-interactions pattern\n\n\
                     Example:\n\
                     require(!hasVoted[proposalId][voter], \"Already voted\");\n\
                     hasVoted[proposalId][voter] = true; // Mark before counting\n\
                     proposal.forVotes += weight;"
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
        let detector = QuorumCalculationOverflowDetector::new();
        assert_eq!(detector.name(), "Quorum Calculation Overflow");
        assert_eq!(detector.default_severity(), Severity::Critical);
    }
}
