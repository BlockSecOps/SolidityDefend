use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for oracle update MEV vulnerabilities
///
/// Detects patterns where oracle price updates can be front-run
/// to exploit the price change.
pub struct OracleUpdateMevDetector {
    base: BaseDetector,
}

impl Default for OracleUpdateMevDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl OracleUpdateMevDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("oracle-update-mev"),
                "Oracle Update MEV".to_string(),
                "Detects oracle update patterns vulnerable to front-running where \
                 searchers can profit by trading before price updates."
                    .to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::Oracle],
                Severity::High,
            ),
        }
    }

    /// Find oracle update functions
    fn find_oracle_updates(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ")
                && (trimmed.contains("updatePrice")
                    || trimmed.contains("setPrice")
                    || trimmed.contains("submitAnswer")
                    || trimmed.contains("updateAnswer"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for MEV protection
                let has_protection = func_body.contains("commit")
                    || func_body.contains("delay")
                    || func_body.contains("batch")
                    || func_body.contains("aggregate");

                if !has_protection {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find instant price usage
    fn find_instant_price_usage(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for price reads followed by value transfers
            if trimmed.contains("getPrice")
                || trimmed.contains("latestAnswer")
                || trimmed.contains("latestRoundData")
            {
                let context_end = std::cmp::min(line_num + 10, lines.len());
                let context: String = lines[line_num..context_end].join("\n");

                if context.contains("transfer")
                    || context.contains("swap")
                    || context.contains("mint")
                    || context.contains("burn")
                {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find push oracle patterns
    fn find_push_oracle(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Push oracles are more vulnerable to front-running
            if trimmed.contains("function ")
                && (trimmed.contains("push") || trimmed.contains("submit"))
                && trimmed.contains("price")
            {
                let func_name = self.extract_function_name(trimmed);
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
}

impl Detector for OracleUpdateMevDetector {
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

        for (line, func_name) in self.find_oracle_updates(source) {
            let message = format!(
                "Function '{}' in contract '{}' updates oracle prices without MEV protection. \
                 Searchers can front-run price updates to profit from the change.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Protect oracle updates from front-running:\n\n\
                     1. Use commit-reveal for price updates\n\
                     2. Aggregate multiple oracle reports\n\
                     3. Add delay between update and usage\n\
                     4. Use pull-based oracles (Chainlink)\n\
                     5. Implement price smoothing"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_instant_price_usage(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses oracle prices immediately for \
                 value transfers. This creates a window for oracle update front-running.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add delay or use TWAP:\n\n\
                     1. Use time-weighted average price (TWAP)\n\
                     2. Add freshness checks on oracle data\n\
                     3. Implement price bands for large deviations\n\
                     4. Use multiple oracle sources"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_push_oracle(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses push-based oracle updates. \
                 Push oracles are more vulnerable to front-running than pull oracles.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Consider pull-based oracles:\n\n\
                     1. Use Chainlink price feeds (pull-based)\n\
                     2. Implement median of multiple sources\n\
                     3. Add deviation thresholds\n\
                     4. Use private transaction pools for updates"
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
        let detector = OracleUpdateMevDetector::new();
        assert_eq!(detector.name(), "Oracle Update MEV");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
