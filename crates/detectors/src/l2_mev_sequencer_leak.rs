use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for L2 MEV extraction by sequencers
///
/// Detects patterns where L2 sequencers can extract MEV through transaction
/// ordering, sandwich attacks, or information asymmetry.
pub struct L2MevSequencerLeakDetector {
    base: BaseDetector,
}

impl Default for L2MevSequencerLeakDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl L2MevSequencerLeakDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("l2-mev-sequencer-leak"),
                "L2 MEV Sequencer Leak".to_string(),
                "Detects patterns vulnerable to MEV extraction by L2 sequencers \
                 through ordering manipulation or information advantages."
                    .to_string(),
                vec![DetectorCategory::L2, DetectorCategory::MEV],
                Severity::High,
            ),
        }
    }

    /// Find sequencer-exploitable ordering patterns
    fn find_ordering_vulnerabilities(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect swap functions without slippage protection
            if trimmed.contains("function ")
                && (trimmed.contains("swap") || trimmed.contains("Swap"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for slippage protection
                if !func_body.contains("minAmount")
                    && !func_body.contains("amountOutMin")
                    && !func_body.contains("slippage")
                {
                    let issue = "Swap without slippage protection".to_string();
                    findings.push((line_num as u32 + 1, func_name.clone(), issue));
                }

                // Check for deadline protection
                if !func_body.contains("deadline") && !func_body.contains("expiry") {
                    let issue = "Swap without deadline protection".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }

            // Detect liquidation functions
            if trimmed.contains("function ")
                && trimmed.contains("liquidate")
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for fair liquidation mechanisms
                if !func_body.contains("auction")
                    && !func_body.contains("dutch")
                    && !func_body.contains("delay")
                {
                    let issue = "Liquidation without fair ordering mechanism".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    /// Find priority gas auction vulnerabilities
    fn find_pga_vulnerabilities(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect first-come-first-served patterns
            if (trimmed.contains("firstCaller")
                || trimmed.contains("winner")
                || (trimmed.contains("require") && trimmed.contains("!claimed")))
                && !trimmed.starts_with("//")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }

            // Detect gas price dependencies
            if trimmed.contains("tx.gasprice") && !trimmed.starts_with("//") {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    /// Find batch transaction vulnerabilities
    fn find_batch_vulnerabilities(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect batch/multicall without atomic guarantees
            if trimmed.contains("function ")
                && (trimmed.contains("multicall")
                    || trimmed.contains("batch")
                    || trimmed.contains("aggregate"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for atomicity
                if func_body.contains("for") && !func_body.contains("revert") {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find oracle update MEV opportunities
    fn find_oracle_mev(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let has_oracle = source.contains("oracle") || source.contains("Oracle");
        if !has_oracle {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect price-dependent functions
            if trimmed.contains("function ")
                && (trimmed.contains("getPrice")
                    || trimmed.contains("latestAnswer")
                    || trimmed.contains("updatePrice"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for TWAP or aggregation
                if !func_body.contains("twap")
                    && !func_body.contains("TWAP")
                    && !func_body.contains("average")
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

    /// Check if contract appears to be L2-specific
    /// Returns true if there are indicators this is an L2 contract
    fn is_l2_context(&self, source: &str) -> bool {
        let lower = source.to_lowercase();

        // L2-specific imports/interfaces
        let has_l2_imports = lower.contains("arbitrum")
            || lower.contains("optimism")
            || lower.contains("zksync")
            || lower.contains("base")
            || lower.contains("linea")
            || lower.contains("polygon zkevm")
            || lower.contains("scroll")
            || lower.contains("starknet")
            || lower.contains("mantl")
            || lower.contains("blast");

        // L2-specific interfaces
        let has_l2_interfaces = lower.contains("iarbsys")
            || lower.contains("iovmgaspriceoracle")
            || lower.contains("il2crossdomainmessenger")
            || lower.contains("iarbitrumbridge")
            || lower.contains("isequencer")
            || lower.contains("sequencer");

        // L2-specific addresses/contracts
        let has_l2_contracts = source.contains("0x000000000000000000000000000000000000006E") // Arbitrum ArbSys
            || source.contains("0x420000000000000000000000000000000000000F") // Optimism Gas Oracle
            || lower.contains("arbsys")
            || lower.contains("arbinfo");

        // L2-specific functionality
        let has_l2_functionality = lower.contains("l2 sequencer")
            || lower.contains("cross-chain")
            || lower.contains("crosschain")
            || lower.contains("bridge")
            || lower.contains("l1 message")
            || lower.contains("l2 message");

        has_l2_imports || has_l2_interfaces || has_l2_contracts || has_l2_functionality
    }
}

impl Detector for L2MevSequencerLeakDetector {
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

        // Only check contracts that appear to be L2-specific
        // L2 MEV issues are not relevant for L1-only contracts
        if !self.is_l2_context(source) {
            return Ok(findings);
        }

        for (line, func_name, issue) in self.find_ordering_vulnerabilities(source) {
            let message = format!(
                "Function '{}' in contract '{}' is vulnerable to sequencer MEV: {}. \
                 L2 sequencers can reorder transactions for profit extraction.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Mitigate sequencer MEV:\n\n\
                     1. Implement slippage protection (minAmountOut)\n\
                     2. Add transaction deadlines\n\
                     3. Use commit-reveal schemes for sensitive operations\n\
                     4. Consider private transaction pools\n\
                     5. Implement fair sequencing protocols"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_pga_vulnerabilities(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses patterns vulnerable to priority gas auctions. \
                 Sequencers can exploit ordering for first-mover advantage.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Avoid PGA-vulnerable patterns:\n\n\
                     1. Use batch auctions instead of first-come-first-served\n\
                     2. Implement commit-reveal for competitive operations\n\
                     3. Avoid gas price dependencies\n\
                     4. Consider time-weighted allocation"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_batch_vulnerabilities(source) {
            let message = format!(
                "Function '{}' in contract '{}' performs batch operations that sequencers \
                 could exploit through partial execution ordering.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Improve batch operation safety:\n\n\
                     1. Make batch operations atomic (all-or-nothing)\n\
                     2. Add revert on partial failure\n\
                     3. Implement batch ordering guarantees\n\
                     4. Consider splitting into individual transactions"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_oracle_mev(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses oracle prices without TWAP protection. \
                 Sequencers can exploit oracle update timing for MEV.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add oracle MEV protection:\n\n\
                     1. Use TWAP instead of spot prices\n\
                     2. Implement price deviation limits\n\
                     3. Add oracle update frequency checks\n\
                     4. Consider multi-source price aggregation"
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
        let detector = L2MevSequencerLeakDetector::new();
        assert_eq!(detector.name(), "L2 MEV Sequencer Leak");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
