use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for backrunning opportunity vulnerabilities
///
/// Detects state changes that create profitable opportunities for
/// backrunners who execute transactions immediately after.
///
/// Vulnerable pattern:
/// ```solidity
/// function updatePrice(uint256 newPrice) external {
///     // Price update visible, arbitrageurs can backrun
///     price = newPrice;
///     // No protection against immediate arbitrage
/// }
/// ```
pub struct BackrunningOpportunityDetector {
    base: BaseDetector,
}

impl Default for BackrunningOpportunityDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BackrunningOpportunityDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("backrunning-opportunity"),
                "Backrunning Opportunity".to_string(),
                "Detects state changes that can be exploited by backrunners who \
                 execute transactions immediately after to capture arbitrage profits."
                    .to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::DeFi],
                Severity::High,
            ),
        }
    }

    /// Find price update functions vulnerable to backrunning
    fn find_price_updates(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for price update functions
            if trimmed.contains("function ")
                && (trimmed.contains("updatePrice")
                    || trimmed.contains("setPrice")
                    || trimmed.contains("updateRate")
                    || trimmed.contains("setRate")
                    || trimmed.contains("updateOracle"))
            {
                // Phase 14 FP Reduction: Skip interface function signatures
                if !self.has_function_body(&lines, line_num) {
                    continue;
                }

                // Phase 14 FP Reduction: Skip getter/view functions
                if trimmed.contains("view") || trimmed.contains("pure") {
                    continue;
                }

                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for backrun protection
                let has_protection = func_body.contains("batch")
                    || func_body.contains("Batch")
                    || func_body.contains("commit")
                    || func_body.contains("delay")
                    || func_body.contains("smooth")
                    || func_body.contains("onlyOwner")
                    || func_body.contains("onlyAdmin")
                    || func_body.contains("onlyKeeper");

                if !has_protection {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find liquidation functions vulnerable to backrunning
    fn find_liquidation_updates(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for state changes that trigger liquidations
            if trimmed.contains("function ")
                && (trimmed.contains("liquidat")
                    || trimmed.contains("Liquidat")
                    || trimmed.contains("updateHealth")
                    || trimmed.contains("checkPosition"))
            {
                // Phase 14 FP Reduction: Skip interface function signatures
                if !self.has_function_body(&lines, line_num) {
                    continue;
                }

                // Phase 14 FP Reduction: Skip getter/view functions
                if trimmed.contains("view") || trimmed.contains("pure") {
                    continue;
                }

                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Phase 14 FP Reduction: Require actual liquidation logic
                let has_liquidation_logic = func_body.contains("seize")
                    || func_body.contains("repay")
                    || func_body.contains("transfer")
                    || func_body.contains("safeTransfer")
                    || func_body.contains("collateral")
                    || func_body.contains("debt");

                if has_liquidation_logic {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find reward distribution vulnerable to backrunning
    fn find_reward_distributions(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for reward functions
            if trimmed.contains("function ")
                && (trimmed.contains("distribute")
                    || trimmed.contains("notifyReward")
                    || trimmed.contains("addReward")
                    || trimmed.contains("depositReward"))
            {
                // Phase 14 FP Reduction: Skip interface function signatures
                if !self.has_function_body(&lines, line_num) {
                    continue;
                }

                // Phase 14 FP Reduction: Skip getter/view functions
                if trimmed.contains("view") || trimmed.contains("pure") {
                    continue;
                }

                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Reward distribution without vesting is vulnerable
                let has_vesting = func_body.contains("vesting")
                    || func_body.contains("Vesting")
                    || func_body.contains("duration")
                    || func_body.contains("stream")
                    || func_body.contains("onlyOwner")
                    || func_body.contains("onlyAdmin");

                if !has_vesting {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find pool rebalance opportunities
    fn find_rebalance_opportunities(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for rebalance functions
            if trimmed.contains("function ")
                && (trimmed.contains("rebalance")
                    || trimmed.contains("Rebalance")
                    || trimmed.contains("sync")
                    || trimmed.contains("skim"))
            {
                // Phase 14 FP Reduction: Skip interface function signatures
                if !self.has_function_body(&lines, line_num) {
                    continue;
                }

                // Phase 14 FP Reduction: Skip getter/view functions
                if trimmed.contains("view") || trimmed.contains("pure") {
                    continue;
                }

                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check if rebalance is protected
                let is_protected = func_body.contains("onlyKeeper")
                    || func_body.contains("onlyAuthorized")
                    || func_body.contains("onlyOwner")
                    || func_body.contains("onlyAdmin")
                    || func_body.contains("private");

                if !is_protected && (trimmed.contains("external") || trimmed.contains("public")) {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find arbitrage-triggering state changes
    fn find_arbitrage_triggers(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for functions that change exchange rates
            if trimmed.contains("function ") {
                // Phase 14 FP Reduction: Skip interface function signatures
                if !self.has_function_body(&lines, line_num) {
                    continue;
                }

                // Phase 14 FP Reduction: Skip getter/view functions
                if trimmed.contains("view") || trimmed.contains("pure") {
                    continue;
                }

                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for exchange rate modifications
                let changes_rate = func_body.contains("exchangeRate")
                    || func_body.contains("pricePerShare")
                    || func_body.contains("virtualPrice")
                    || func_body.contains("getRate");

                // Check for reserve modifications
                let changes_reserves = func_body.contains("reserve0")
                    || func_body.contains("reserve1")
                    || func_body.contains("_update(");

                if (changes_rate || changes_reserves)
                    && (trimmed.contains("external") || trimmed.contains("public"))
                {
                    // Check for atomic protection
                    let has_atomic_protection = func_body.contains("nonReentrant")
                        || func_body.contains("lock")
                        || func_body.contains("mutex")
                        || func_body.contains("onlyOwner")
                        || func_body.contains("onlyAdmin");

                    if !has_atomic_protection {
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

    /// Phase 14 FP Reduction: Check if contract is an interface (no implementation)
    fn is_interface_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let contract_name = &ctx.contract.name.name;

        // Interface naming convention (IPool, IAToken, etc.)
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

    /// Phase 14 FP Reduction: Check if contract is a configuration/helper contract
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
            || contract_name.contains("events")
            || contract_name.contains("errors")
            || contract_name.contains("constants");

        // Library contracts
        let is_library = source_lower.contains(&format!("library {}", contract_name));

        // Data types / structs only
        let is_types_only =
            source_lower.contains("struct ") && !source_lower.contains("function liquidate");

        is_config_named || is_library || is_types_only
    }

    /// Phase 14 FP Reduction: Check if contract is a known MEV-protected protocol
    fn is_known_protected_protocol(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let lower = source.to_lowercase();
        let contract_name = ctx.contract.name.name.to_lowercase();

        // Aave patterns - known protocol with proper MEV protections
        // Aave uses Chainlink oracles and has dutch auction liquidations
        let is_aave = lower.contains("@author aave")
            || lower.contains("aave-upgradeability")
            || lower.contains("ipool")
            || lower.contains("atoken")
            || (contract_name.contains("pool") && lower.contains("liquidationcall"))
            || (contract_name.contains("l2") && lower.contains("aave"));

        // Compound patterns - uses Chainlink and has proper protections
        let is_compound = lower.contains("compound")
            || lower.contains("ctoken")
            || lower.contains("comptroller")
            || lower.contains("@author compound");

        // MakerDAO patterns
        let is_maker =
            lower.contains("makerdao") || lower.contains("dss") || lower.contains("vat.");

        // Check for Chainlink oracle usage (strong MEV protection)
        let uses_chainlink = lower.contains("aggregatorv3interface")
            || lower.contains("latestrounddata")
            || lower.contains("chainlinkpricefeed");

        // Check for access control patterns
        let has_access_control = lower.contains("onlykeeper")
            || lower.contains("onlyliquidator")
            || lower.contains("onlyauthorized")
            || lower.contains("hasrole(");

        // Encoder/decoder helpers - not actual implementation
        let is_encoder = contract_name.contains("encoder")
            || contract_name.contains("decoder")
            || contract_name.contains("calldata");

        is_aave || is_compound || is_maker || uses_chainlink || has_access_control || is_encoder
    }

    /// Phase 14 FP Reduction: Check if function actually has implementation (not just signature)
    fn has_function_body(&self, lines: &[&str], start: usize) -> bool {
        let func_end = self.find_function_end(lines, start);
        let func_body: String = lines[start..func_end].join("\n");

        // Must have curly braces with content inside
        let open_braces = func_body.matches('{').count();
        let close_braces = func_body.matches('}').count();

        // Interface functions end with ;
        if func_body.contains(");") && open_braces <= 1 {
            return false;
        }

        // Must have actual implementation
        open_braces >= 1 && close_braces >= 1 && func_body.len() > 50
    }
}

impl Detector for BackrunningOpportunityDetector {
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

        // Phase 14 FP Reduction: Skip test contracts
        if utils::is_test_contract(ctx) {
            return Ok(findings);
        }

        // Phase 14 FP Reduction: Skip interface contracts - no implementation to analyze
        if self.is_interface_contract(ctx) {
            return Ok(findings);
        }

        // Phase 14 FP Reduction: Skip configuration/helper contracts
        if self.is_config_or_helper(ctx) {
            return Ok(findings);
        }

        // Phase 14 FP Reduction: Skip known MEV-protected protocols (Aave, Compound, MakerDAO)
        if self.is_known_protected_protocol(ctx) {
            return Ok(findings);
        }

        // Find price updates
        for (line, func_name) in self.find_price_updates(source) {
            let message = format!(
                "Function '{}' in contract '{}' updates prices without backrun protection. \
                 Arbitrageurs can monitor for price updates and immediately backrun to \
                 profit from the price change.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Implement backrun protection for price updates:\n\n\
                     1. Use batch updates with commit-reveal:\n\
                     function commitPriceUpdate(bytes32 hash) external;\n\
                     function revealPriceUpdate(uint256 price, bytes32 salt) external;\n\n\
                     2. Use time-weighted average prices (TWAP)\n\
                     3. Add smoothing to prevent instant large changes\n\
                     4. Use frequent small updates instead of rare large ones"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Find liquidation opportunities
        for (line, func_name) in self.find_liquidation_updates(source) {
            let message = format!(
                "Function '{}' in contract '{}' may trigger liquidation opportunities. \
                 Backrunners can monitor for positions becoming liquidatable and immediately \
                 execute liquidations for profit.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Protect liquidations from predatory backrunning:\n\n\
                     1. Implement dutch auction for liquidations\n\
                     2. Add grace period before liquidation is profitable\n\
                     3. Use keeper networks with fair ordering\n\
                     4. Cap liquidation incentives to reduce MEV"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Find reward distributions
        for (line, func_name) in self.find_reward_distributions(source) {
            let message = format!(
                "Function '{}' in contract '{}' distributes rewards without vesting. \
                 Backrunners can deposit just before rewards and withdraw immediately \
                 after to capture disproportionate rewards.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Add vesting to reward distributions:\n\n\
                     function notifyRewardAmount(uint256 reward) external {\n\
                         rewardRate = reward / DURATION;\n\
                         lastUpdateTime = block.timestamp;\n\
                         periodFinish = block.timestamp + DURATION;\n\
                     }\n\n\
                     // Rewards vest over DURATION, preventing instant capture"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Find rebalance opportunities
        for (line, func_name) in self.find_rebalance_opportunities(source) {
            let message = format!(
                "Function '{}' in contract '{}' exposes rebalance as public. \
                 Backrunners can profit by rebalancing after price changes.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Protect rebalance operations:\n\n\
                     1. Restrict to authorized keepers\n\
                     2. Add cooldown between rebalances\n\
                     3. Use private transaction pools\n\
                     4. Implement batch rebalancing"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Find arbitrage triggers
        for (line, func_name) in self.find_arbitrage_triggers(source) {
            let message = format!(
                "Function '{}' in contract '{}' changes exchange rates or reserves \
                 without atomic protection. This creates backrunning opportunities.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Protect rate-changing operations:\n\n\
                     1. Use reentrancy guards to prevent atomic exploitation\n\
                     2. Implement rate smoothing over multiple blocks\n\
                     3. Add flash loan protection\n\
                     4. Consider using virtual reserves"
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
        let detector = BackrunningOpportunityDetector::new();
        assert_eq!(detector.name(), "Backrunning Opportunity");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_price_update_detection() {
        let detector = BackrunningOpportunityDetector::new();

        let vulnerable = r#"
            contract Oracle {
                function updatePrice(uint256 newPrice) external {
                    price = newPrice;
                }
            }
        "#;
        let findings = detector.find_price_updates(vulnerable);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_reward_distribution() {
        let detector = BackrunningOpportunityDetector::new();

        let vulnerable = r#"
            contract Staking {
                function distributeRewards(uint256 amount) external {
                    totalRewards += amount;
                }
            }
        "#;
        let findings = detector.find_reward_distributions(vulnerable);
        assert!(!findings.is_empty());
    }
}
