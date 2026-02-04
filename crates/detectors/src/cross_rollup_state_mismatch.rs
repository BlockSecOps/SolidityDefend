use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for cross-rollup state mismatch vulnerabilities
///
/// Detects patterns where state inconsistencies between different rollups
/// or L1/L2 can be exploited for double-spending or arbitrage.
pub struct CrossRollupStateMismatchDetector {
    base: BaseDetector,
}

impl Default for CrossRollupStateMismatchDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossRollupStateMismatchDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("cross-rollup-state-mismatch"),
                "Cross-Rollup State Mismatch".to_string(),
                "Detects state inconsistencies across rollups that could enable \
                 double-spending, arbitrage, or manipulation attacks."
                    .to_string(),
                vec![
                    DetectorCategory::L2,
                    DetectorCategory::CrossChain,
                    DetectorCategory::Logic,
                ],
                Severity::High,
            ),
        }
    }

    /// Find state synchronization issues
    fn find_sync_issues(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect cross-chain state reads
            if trimmed.contains("function ")
                && (trimmed.contains("getRemoteState")
                    || trimmed.contains("crossChainBalance")
                    || trimmed.contains("remoteSupply"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for staleness handling
                if !func_body.contains("lastUpdate")
                    && !func_body.contains("timestamp")
                    && !func_body.contains("blockNumber")
                {
                    let issue = "Cross-chain state read without staleness check".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }

            // Detect state updates without confirmation
            if trimmed.contains("function ")
                && (trimmed.contains("syncState") || trimmed.contains("updateRemote"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                if !func_body.contains("confirmed")
                    && !func_body.contains("finalized")
                    && !func_body.contains("proof")
                {
                    let issue = "State sync without finality confirmation".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    /// Find balance consistency issues
    fn find_balance_inconsistencies(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Check for cross-chain token patterns
        let is_cross_chain = source.contains("L1")
            || source.contains("L2")
            || source.contains("crossChain")
            || source.contains("bridged");

        if !is_cross_chain {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect mint functions that could create supply mismatch
            if trimmed.contains("function ")
                && (trimmed.contains("mint") || trimmed.contains("Mint"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for cross-chain supply tracking
                if !func_body.contains("totalBridged")
                    && !func_body.contains("l1Supply")
                    && !func_body.contains("remoteMinted")
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }

            // Detect burn functions without remote verification
            if trimmed.contains("function ")
                && (trimmed.contains("burn") || trimmed.contains("Burn"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                if !func_body.contains("sendMessage") && !func_body.contains("notifyRemote") {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find reorg vulnerability patterns
    fn find_reorg_vulnerabilities(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect functions relying on recent blocks
            if trimmed.contains("function ")
                && (trimmed.contains("process") || trimmed.contains("execute"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for reorg protection
                if func_body.contains("block.number")
                    && !func_body.contains("confirmations")
                    && !func_body.contains("SAFE_BLOCK_DELAY")
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find double-spend vulnerability patterns
    fn find_double_spend_patterns(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect withdrawal functions
            if trimmed.contains("function ")
                && (trimmed.contains("withdraw") || trimmed.contains("claim"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for cross-chain locking
                if !func_body.contains("locked")
                    && !func_body.contains("pending")
                    && !func_body.contains("nullifier")
                {
                    // Check if it updates balance before cross-chain confirmation
                    if func_body.contains("balances[") && func_body.contains("=") {
                        findings.push((line_num as u32 + 1, func_name));
                    }
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

impl Detector for CrossRollupStateMismatchDetector {
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
        // Cross-rollup state mismatch only applies to contracts deployed across multiple chains.
        // Simple L1 contracts cannot have cross-rollup state issues.
        if !utils::is_l2_contract(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        for (line, func_name, issue) in self.find_sync_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' has cross-rollup state issue: {}. \
                 State inconsistencies between chains could be exploited.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(662)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Ensure state consistency:\n\n\
                     1. Track state update timestamps/block numbers\n\
                     2. Require finality confirmation before trusting remote state\n\
                     3. Implement state verification proofs\n\
                     4. Add staleness checks with maximum age\n\
                     5. Use pessimistic state assumptions during sync"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_balance_inconsistencies(source) {
            let message = format!(
                "Function '{}' in contract '{}' may create cross-chain balance inconsistency. \
                 Total supply could differ between chains enabling inflation attacks.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(662)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Maintain supply consistency:\n\n\
                     1. Track bridged amounts on both chains\n\
                     2. Mint only after confirmed burn on source\n\
                     3. Burn only after confirmed unlock on destination\n\
                     4. Implement supply reconciliation checks"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_reorg_vulnerabilities(source) {
            let message = format!(
                "Function '{}' in contract '{}' may be vulnerable to cross-chain reorgs. \
                 Actions based on unconfirmed blocks could be invalidated.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(662)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add reorg protection:\n\n\
                     1. Wait for sufficient block confirmations\n\
                     2. Use safe block delay constants\n\
                     3. Implement finality checks\n\
                     4. Handle reorg scenarios gracefully"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_double_spend_patterns(source) {
            let message = format!(
                "Function '{}' in contract '{}' may be vulnerable to cross-chain double-spend. \
                 Balances updated before cross-chain confirmation could be exploited.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(662)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Prevent double-spending:\n\n\
                     1. Lock funds during cross-chain transfers\n\
                     2. Use pending/confirmed state pattern\n\
                     3. Implement nullifiers for withdrawal claims\n\
                     4. Update balances only after confirmation"
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
        let detector = CrossRollupStateMismatchDetector::new();
        assert_eq!(detector.name(), "Cross-Rollup State Mismatch");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
