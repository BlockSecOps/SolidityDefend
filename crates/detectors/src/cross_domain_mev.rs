use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for cross-domain MEV vulnerabilities
///
/// Detects patterns where MEV can be extracted across L1/L2 boundaries
/// or between different rollups.
pub struct CrossDomainMevDetector {
    base: BaseDetector,
}

impl Default for CrossDomainMevDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossDomainMevDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("cross-domain-mev"),
                "Cross-Domain MEV".to_string(),
                "Detects MEV extraction opportunities across L1/L2 boundaries or \
                 between different rollups where timing differences enable arbitrage."
                    .to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::L2],
                Severity::High,
            ),
        }
    }

    /// Find L1-L2 message passing vulnerabilities
    fn find_l1_l2_mev(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for cross-domain messaging
            if trimmed.contains("sendMessage")
                || trimmed.contains("relayMessage")
                || trimmed.contains("bridge")
            {
                let func_name = self.find_containing_function(&lines, line_num);

                // Check context for MEV-sensitive operations
                let context_start = if line_num > 10 { line_num - 10 } else { 0 };
                let context_end = std::cmp::min(line_num + 10, lines.len());
                let context: String = lines[context_start..context_end].join("\n");

                if context.contains("swap")
                    || context.contains("price")
                    || context.contains("oracle")
                    || context.contains("liquidat")
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find sequencer-related MEV opportunities
    fn find_sequencer_mev(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for sequencer interactions
            if trimmed.contains("sequencer")
                || trimmed.contains("Sequencer")
                || trimmed.contains("batchSubmit")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    /// Find cross-rollup arbitrage patterns
    fn find_cross_rollup_arb(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for multi-chain operations
            if trimmed.contains("chainId") || trimmed.contains("destinationChain") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String =
                    lines[line_num..std::cmp::min(func_end, line_num + 30)].join("\n");

                // Check for price-sensitive cross-chain ops
                if func_body.contains("swap")
                    || func_body.contains("trade")
                    || func_body.contains("arbitrage")
                {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find finality-related MEV
    fn find_finality_mev(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for finality assumptions
            if trimmed.contains("finalized")
                || trimmed.contains("confirmed")
                || trimmed.contains("blockConfirmations")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    fn find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                if let Some(func_start) = trimmed.find("function ") {
                    let after_func = &trimmed[func_start + 9..];
                    if let Some(paren_pos) = after_func.find('(') {
                        return after_func[..paren_pos].trim().to_string();
                    }
                }
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

impl Detector for CrossDomainMevDetector {
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

        for (line, func_name) in self.find_l1_l2_mev(source) {
            let message = format!(
                "Function '{}' in contract '{}' performs L1-L2 message passing with \
                 MEV-sensitive operations. Timing differences between L1 and L2 can \
                 be exploited for cross-domain arbitrage.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Protect against cross-domain MEV:\n\n\
                     1. Use time-weighted prices that span both domains\n\
                     2. Add delays to price-sensitive cross-domain messages\n\
                     3. Implement slippage protection on both sides\n\
                     4. Consider using shared sequencing"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_sequencer_mev(source) {
            let message = format!(
                "Function '{}' in contract '{}' interacts with sequencer, creating \
                 potential MEV opportunities through transaction ordering.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Mitigate sequencer MEV:\n\n\
                     1. Use encrypted transaction pools\n\
                     2. Implement fair ordering protocols\n\
                     3. Consider decentralized sequencer solutions"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_cross_rollup_arb(source) {
            let message = format!(
                "Function '{}' in contract '{}' performs cross-rollup operations \
                 vulnerable to arbitrage between chains with different finality.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Protect cross-rollup operations:\n\n\
                     1. Wait for finality on both chains\n\
                     2. Use consistent pricing oracles\n\
                     3. Implement atomic cross-chain swaps"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_finality_mev(source) {
            let message = format!(
                "Function '{}' in contract '{}' relies on finality assumptions \
                 that may differ between L1 and L2, creating MEV opportunities.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Low)
                .with_fix_suggestion(
                    "Handle finality carefully:\n\n\
                     1. Use appropriate confirmation counts for each chain\n\
                     2. Consider soft vs hard finality\n\
                     3. Implement withdrawal delays"
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
        let detector = CrossDomainMevDetector::new();
        assert_eq!(detector.name(), "Cross-Domain MEV");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
