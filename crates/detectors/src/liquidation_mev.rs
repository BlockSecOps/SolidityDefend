use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};
use crate::utils;

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

            // Skip struct definitions, comments, and parameter declarations
            if trimmed.starts_with("//")
                || trimmed.starts_with("*")
                || trimmed.starts_with("struct ")
                || trimmed.contains("@param")
                || trimmed.contains("uint256 liquidation")
            // parameter declaration
            {
                continue;
            }

            // Look for liquidation incentive USAGE in calculations, not just mentions
            // Must be in actual calculation context (assignment or arithmetic)
            if (trimmed.contains("liquidationBonus")
                || trimmed.contains("liquidationIncentive")
                || trimmed.contains("liquidationPenalty"))
                && (trimmed.contains("=") || trimmed.contains("*") || trimmed.contains("/"))
                && !trimmed.contains("//")
            // Not a comment
            {
                let func_name = self.find_containing_function(&lines, line_num);
                // Only flag if in actual function, not struct or interface
                if func_name != "unknown" {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find health factor calculations
    fn find_health_factor_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();
        let source_lower = source.to_lowercase();

        // Skip if using Chainlink (reliable oracle) or has TWAP
        if source_lower.contains("chainlink")
            || source_lower.contains("aggregatorv3")
            || source_lower.contains("latestrounddata")
            || source_lower.contains("twap")
        {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Skip comments, struct definitions, interface declarations
            if trimmed.starts_with("//")
                || trimmed.starts_with("*")
                || trimmed.starts_with("struct ")
                || trimmed.contains("interface ")
                || trimmed.contains("@return")
            {
                continue;
            }

            // Only flag health factor CALCULATIONS, not just variable reads
            if (trimmed.contains("healthFactor")
                || trimmed.contains("collateralRatio")
                || trimmed.contains("isLiquidatable"))
                && (trimmed.contains("=") && (trimmed.contains("*") || trimmed.contains("/")))
            {
                let func_name = self.find_containing_function(&lines, line_num);

                // Only flag if in actual function
                if func_name != "unknown" {
                    // Check surrounding context for price oracle protection
                    let context_start = if line_num > 10 { line_num - 10 } else { 0 };
                    let context_end = std::cmp::min(line_num + 10, lines.len());
                    let context: String =
                        lines[context_start..context_end].join("\n").to_lowercase();

                    // Skip if context shows oracle protection
                    if !context.contains("twap")
                        && !context.contains("chainlink")
                        && !context.contains("aggregator")
                        && !context.contains("pricefeed")
                    {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find flash loan liquidation patterns
    fn find_flash_liquidation(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();
        let lower = source.to_lowercase();

        // Must have BOTH flash loan AND liquidation in same contract with actual implementation
        let has_flash_impl = lower.contains("function flashloan") && source.contains("{");
        let has_liquidate_impl = lower.contains("function liquidate") && source.contains("{");

        // Skip if it's just an interface or only has one of the two
        if !has_flash_impl || !has_liquidate_impl {
            return findings;
        }

        // Skip if has reentrancy protection
        if lower.contains("nonreentrant") || lower.contains("reentrancyguard") {
            return findings;
        }

        // Skip if uses Chainlink/TWAP (manipulation resistant)
        if lower.contains("chainlink") || lower.contains("twap") || lower.contains("aggregator") {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Only flag actual flash loan function implementations
            if trimmed.contains("function ")
                && trimmed.to_lowercase().contains("flash")
                && (trimmed.contains("external") || trimmed.contains("public"))
            {
                // Check if this function can trigger liquidation
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n").to_lowercase();

                if func_body.contains("liquidat") {
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

    /// Check if contract is an interface (no implementation)
    fn is_interface_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let contract_name = &ctx.contract.name.name;

        // Interface naming convention
        if contract_name.starts_with('I')
            && contract_name
                .chars()
                .nth(1)
                .map_or(false, |c| c.is_uppercase())
        {
            return true;
        }

        // Explicit interface keyword
        if source.contains(&format!("interface {}", contract_name)) {
            return true;
        }

        // No function implementations (all functions end with ;)
        let has_implementation =
            source.contains("function ") && source.contains("{") && !source.contains("interface ");

        !has_implementation
    }

    /// Check if contract is a configuration/helper (not actual liquidation logic)
    fn is_config_or_helper(&self, ctx: &AnalysisContext) -> bool {
        let contract_name = ctx.contract.name.name.to_lowercase();
        let source_lower = ctx.source_code.to_lowercase();

        // Config/helper naming patterns
        let is_config_named = contract_name.contains("config")
            || contract_name.contains("helper")
            || contract_name.contains("setup")
            || contract_name.contains("admin")
            || contract_name.contains("registry")
            || contract_name.contains("factory")
            || contract_name.contains("types")
            || contract_name.contains("storage")
            || contract_name.contains("events");

        // Library contracts
        let is_library = source_lower.contains(&format!("library {}", contract_name));

        // Data types / structs only
        let is_types_only =
            source_lower.contains("struct ") && !source_lower.contains("function liquidate");

        is_config_named || is_library || is_types_only
    }

    /// Check if contract is a known lending protocol with MEV protection
    fn is_known_protected_protocol(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let lower = source.to_lowercase();

        // Aave patterns - uses Chainlink oracles and has proper protections
        let is_aave =
            (lower.contains("aave") || lower.contains("atoken") || lower.contains("ipool"))
                && (lower.contains("chainlink")
                    || lower.contains("aggregator")
                    || lower.contains("getassetprice"));

        // Compound patterns - uses Chainlink and has proper protections
        let is_compound = (lower.contains("compound")
            || lower.contains("ctoken")
            || lower.contains("comptroller"))
            && (lower.contains("pricefeed") || lower.contains("getunderlyingprice"));

        // MakerDAO patterns
        let is_maker =
            lower.contains("makerdao") || lower.contains("dss") || lower.contains("vat.");

        // Check for Chainlink oracle usage (strong MEV protection)
        let uses_chainlink = lower.contains("aggregatorv3interface")
            || lower.contains("latestrounddata")
            || lower.contains("chainlinkpricefeed");

        // Check for access control on liquidation
        let has_access_control = lower.contains("onlykeeper")
            || lower.contains("onlyliquidator")
            || lower.contains("authorized")
            || (lower.contains("liquidat") && lower.contains("hasrole"));

        is_aave || is_compound || is_maker || uses_chainlink || has_access_control
    }

    /// Check if the contract actually implements liquidation logic (not just references it)
    fn has_liquidation_implementation(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let lower = source.to_lowercase();

        // Must have actual liquidation function with body
        let has_liquidate_func = lower.contains("function liquidate")
            || lower.contains("function liquidatecall")
            || lower.contains("function executeliquidation");

        // Must have implementation (function body with logic)
        let has_implementation = source.contains("function ")
            && source.matches('{').count() > source.matches("interface").count() + 1;

        // Must have collateral seizure or debt repayment logic
        let has_liquidation_logic = lower.contains("seize")
            || lower.contains("repayborrow")
            || lower.contains("transfercollateral")
            || (lower.contains("liquidat") && lower.contains("transfer"));

        has_liquidate_func && has_implementation && has_liquidation_logic
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

        // Skip test contracts
        if utils::is_test_contract(ctx) {
            return Ok(findings);
        }

        // Skip interface contracts - they have no implementation to analyze
        if self.is_interface_contract(ctx) {
            return Ok(findings);
        }

        // Skip configuration/helper contracts - they don't execute liquidations
        if self.is_config_or_helper(ctx) {
            return Ok(findings);
        }

        // Skip known lending protocols with proper MEV protection
        // (Aave, Compound, MakerDAO use Chainlink and have access controls)
        if self.is_known_protected_protocol(ctx) {
            return Ok(findings);
        }

        // Skip if contract doesn't actually implement liquidation logic
        if !self.has_liquidation_implementation(ctx) {
            return Ok(findings);
        }

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
        let detector = LiquidationMevDetector::new();
        assert_eq!(detector.name(), "Liquidation MEV");
        assert_eq!(detector.default_severity(), Severity::Critical);
    }
}
