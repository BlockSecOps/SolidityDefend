use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for liquidation MEV vulnerabilities
///
/// Detects patterns where liquidation mechanisms can be front-run
/// or exploited by MEV searchers.
pub struct LiquidationMevDetector {
    base: BaseDetector,
}

impl Default for LiquidationMevDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl LiquidationMevDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("liquidation-mev"),
                "Liquidation MEV".to_string(),
                "Detects liquidation patterns vulnerable to MEV extraction where \
                 searchers can front-run liquidations or manipulate prices to \
                 trigger profitable liquidations."
                    .to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::DeFi],
                Severity::Critical,
            ),
        }
    }

    /// Find liquidation functions
    fn find_liquidation_functions(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ")
                && (trimmed.contains("liquidate")
                    || trimmed.contains("Liquidate")
                    || trimmed.contains("seize"))
                && (trimmed.contains("external") || trimmed.contains("public"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for MEV protection
                let has_protection = func_body.contains("dutch")
                    || func_body.contains("Dutch")
                    || func_body.contains("gradual")
                    || func_body.contains("keeper")
                    || func_body.contains("authorized");

                if !has_protection {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find liquidation incentive patterns
    fn find_liquidation_incentives(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for high liquidation incentives
            if trimmed.contains("liquidationBonus")
                || trimmed.contains("liquidationIncentive")
                || trimmed.contains("liquidationPenalty")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    /// Find health factor calculations
    fn find_health_factor_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("healthFactor")
                || trimmed.contains("collateralRatio")
                || trimmed.contains("isLiquidatable")
            {
                let func_name = self.find_containing_function(&lines, line_num);

                // Check if it uses spot price
                let context_start = if line_num > 5 { line_num - 5 } else { 0 };
                let context_end = std::cmp::min(line_num + 5, lines.len());
                let context: String = lines[context_start..context_end].join("\n");

                if !context.contains("twap") && !context.contains("TWAP") {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find flash loan liquidation patterns
    fn find_flash_liquidation(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let has_flash = source.contains("flash") || source.contains("Flash");
        let has_liquidate = source.contains("liquidat") || source.contains("Liquidat");

        if has_flash && has_liquidate {
            for (line_num, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                if trimmed.contains("function ") && trimmed.contains("flash") {
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

impl Detector for LiquidationMevDetector {
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

        for (line, func_name) in self.find_liquidation_functions(source) {
            let message = format!(
                "Function '{}' in contract '{}' implements liquidation without MEV protection. \
                 Searchers can front-run liquidations to capture the liquidation bonus.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Implement MEV-resistant liquidation:\n\n\
                     1. Dutch auction liquidations:\n\
                     function liquidate(address user) external {\n\
                         uint256 discount = getAuctionDiscount(auctionStart);\n\
                         // Discount increases over time, reducing MEV\n\
                     }\n\n\
                     2. Keeper network with fair ordering\n\
                     3. Gradual liquidation to reduce impact\n\
                     4. Grace period before liquidation"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_liquidation_incentives(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses liquidation incentives that may \
                 be too high, creating profitable MEV opportunities.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Optimize liquidation incentives:\n\n\
                     1. Use dynamic incentives based on urgency\n\
                     2. Cap maximum liquidation bonus\n\
                     3. Consider soft liquidation mechanisms\n\
                     4. Implement partial liquidations"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_health_factor_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' calculates liquidation eligibility \
                 without TWAP prices. Spot prices can be manipulated to trigger liquidations.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Use manipulation-resistant prices:\n\n\
                     1. Use TWAP instead of spot prices\n\
                     2. Add price deviation checks\n\
                     3. Implement flash loan protection\n\
                     4. Use multiple oracle sources"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_flash_liquidation(source) {
            let message = format!(
                "Function '{}' in contract '{}' allows flash loan liquidations. \
                 Attackers can borrow, manipulate price, liquidate, and repay atomically.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Protect against flash liquidations:\n\n\
                     1. Add reentrancy guards\n\
                     2. Use TWAP prices\n\
                     3. Require collateral to be held for minimum time\n\
                     4. Add delay between price update and liquidation"
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
        let detector = LiquidationMevDetector::new();
        assert_eq!(detector.name(), "Liquidation MEV");
        assert_eq!(detector.default_severity(), Severity::Critical);
    }
}
