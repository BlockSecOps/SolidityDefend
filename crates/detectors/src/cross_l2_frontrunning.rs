use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for cross-L2 frontrunning vulnerabilities
///
/// Detects race conditions between L2 finality and L1 confirmation that can
/// be exploited for cross-domain MEV extraction.
pub struct CrossL2FrontrunningDetector {
    base: BaseDetector,
}

impl Default for CrossL2FrontrunningDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossL2FrontrunningDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("cross-l2-frontrunning"),
                "Cross-L2 Frontrunning".to_string(),
                "Detects race conditions between L2 finality and L1 confirmation \
                 that enable cross-domain frontrunning attacks."
                    .to_string(),
                vec![
                    DetectorCategory::L2,
                    DetectorCategory::MEV,
                    DetectorCategory::Timestamp,
                ],
                Severity::High,
            ),
        }
    }

    /// Find cross-domain message vulnerabilities
    fn find_cross_domain_issues(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect cross-domain message handling without finality checks
            if (trimmed.contains("onMessage")
                || trimmed.contains("receiveMessage")
                || trimmed.contains("relayMessage"))
                && trimmed.contains("function ")
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for finality validation
                if !func_body.contains("finalized")
                    && !func_body.contains("confirmed")
                    && !func_body.contains("block.number")
                    && !func_body.contains("confirmations")
                {
                    let issue = "Cross-domain message without finality check".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }

            // Detect L1->L2 message dependencies that could be frontrun
            if (trimmed.contains("sendCrossDomainMessage")
                || trimmed.contains("depositTransaction")
                || trimmed.contains("createRetryableTicket"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end.min(line_num + 20)].join("\n");

                // Check for commit-reveal or deadline protection
                if !func_body.contains("deadline")
                    && !func_body.contains("commit")
                    && !func_body.contains("nonce")
                {
                    let issue = "Cross-domain call without frontrunning protection".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    /// Find L2 to L1 withdrawal vulnerabilities
    fn find_withdrawal_race_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect withdrawal initiation without delay
            if trimmed.contains("function ")
                && (trimmed.contains("initiateWithdrawal") || trimmed.contains("withdraw"))
                && (trimmed.contains("external") || trimmed.contains("public"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Look for immediate state changes that could be exploited
                if func_body.contains("balances[")
                    && !func_body.contains("pending")
                    && !func_body.contains("delay")
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find state sync race conditions
    fn find_state_sync_races(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect state sync handlers
            if trimmed.contains("function ")
                && (trimmed.contains("syncState")
                    || trimmed.contains("updateState")
                    || trimmed.contains("onStateReceive"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for atomic state transitions
                if !func_body.contains("reentrancyGuard")
                    && !func_body.contains("nonReentrant")
                    && !func_body.contains("lock")
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find oracle price sync vulnerabilities
    fn find_oracle_sync_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Check if contract uses cross-chain oracles
        let has_oracle = source.contains("oracle") || source.contains("Oracle");
        let has_cross_chain =
            source.contains("L1") || source.contains("L2") || source.contains("crossChain");

        if !has_oracle || !has_cross_chain {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect price updates from cross-chain sources
            if (trimmed.contains("updatePrice") || trimmed.contains("setPrice"))
                && trimmed.contains("function ")
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for staleness and deviation checks
                if !func_body.contains("deviation") && !func_body.contains("maxDelta") {
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

impl Detector for CrossL2FrontrunningDetector {
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

        // CRITICAL FP FIX: Only analyze L2/cross-chain contracts
        // This detector should NOT flag simple L1 contracts with regular withdraw functions.
        // Cross-L2 frontrunning only applies to contracts with actual cross-chain functionality.
        if !utils::is_l2_contract(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        for (line, func_name, issue) in self.find_cross_domain_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' has cross-L2 frontrunning vulnerability: {}. \
                 Attackers can exploit the delay between L2 state and L1 confirmation.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Prevent cross-L2 frontrunning:\n\n\
                     1. Wait for finality before processing cross-domain messages\n\
                     2. Use commit-reveal schemes for sensitive operations\n\
                     3. Implement deadline parameters for cross-chain calls\n\
                     4. Add nonce tracking to prevent replay attacks\n\
                     5. Consider time-locks for large value transfers"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_withdrawal_race_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' has withdrawal race vulnerability. \
                 State changes during withdrawal period can be exploited.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add withdrawal protection:\n\n\
                     1. Use pending/confirmed state pattern\n\
                     2. Lock funds during withdrawal period\n\
                     3. Add delay before withdrawal completion\n\
                     4. Implement challenge mechanism"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_state_sync_races(source) {
            let message = format!(
                "Function '{}' in contract '{}' handles state sync without reentrancy protection. \
                 Cross-chain state updates could be exploited via reentrancy.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add state sync protection:\n\n\
                     1. Use nonReentrant modifier\n\
                     2. Implement checks-effects-interactions pattern\n\
                     3. Add state transition validation\n\
                     4. Consider optimistic locking"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_oracle_sync_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' updates cross-chain oracle prices without \
                 deviation checks. Price manipulation attacks are possible during sync delays.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add oracle price protection:\n\n\
                     1. Implement maximum price deviation checks\n\
                     2. Use TWAP for cross-chain prices\n\
                     3. Add circuit breakers for extreme movements\n\
                     4. Consider multi-source price aggregation"
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
        let detector = CrossL2FrontrunningDetector::new();
        assert_eq!(detector.name(), "Cross-L2 Frontrunning");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
