use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for token launch MEV vulnerabilities
///
/// Detects patterns where token launches can be sniped by MEV bots
/// that front-run initial liquidity addition.
pub struct TokenLaunchMevDetector {
    base: BaseDetector,
}

impl Default for TokenLaunchMevDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenLaunchMevDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("token-launch-mev"),
                "Token Launch MEV".to_string(),
                "Detects token launch patterns vulnerable to sniping where MEV bots \
                 can front-run initial liquidity to buy tokens at launch price."
                    .to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::DeFi],
                Severity::Critical,
            ),
        }
    }

    /// Find initial liquidity addition vulnerabilities
    fn find_initial_liquidity(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ")
                && (trimmed.contains("addLiquidity")
                    || trimmed.contains("createPair")
                    || trimmed.contains("initializePool"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for launch protection
                let has_protection = func_body.contains("whitelist")
                    || func_body.contains("launch")
                    || func_body.contains("antiBot")
                    || func_body.contains("maxBuy");

                if !has_protection {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find trading enable patterns
    fn find_trading_enable(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ")
                && (trimmed.contains("enableTrading")
                    || trimmed.contains("openTrading")
                    || trimmed.contains("startTrading"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for snipe protection
                let has_protection = func_body.contains("delay")
                    || func_body.contains("cooldown")
                    || func_body.contains("block.number");

                if !has_protection {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find presale to DEX transition vulnerabilities
    fn find_presale_transition(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let has_presale = source.contains("presale") || source.contains("Presale");
        let has_dex =
            source.contains("uniswap") || source.contains("pancake") || source.contains("router");

        if has_presale && has_dex {
            for (line_num, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                if trimmed.contains("function ")
                    && (trimmed.contains("finalize") || trimmed.contains("launch"))
                {
                    let func_name = self.extract_function_name(trimmed);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find fair launch vulnerabilities
    fn find_fair_launch_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for transfer with launch logic
            if trimmed.contains("function ")
                && (trimmed.contains("transfer") || trimmed.contains("_transfer"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for any launch protection
                let has_launch_check = func_body.contains("launchBlock")
                    || func_body.contains("launchTime")
                    || func_body.contains("tradingEnabled");

                let has_protection = func_body.contains("maxTx")
                    || func_body.contains("maxWallet")
                    || func_body.contains("cooldown");

                if has_launch_check && !has_protection {
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

impl Detector for TokenLaunchMevDetector {
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

        for (line, func_name) in self.find_initial_liquidity(source) {
            let message = format!(
                "Function '{}' in contract '{}' adds initial liquidity without snipe protection. \
                 MEV bots can front-run to buy tokens at launch price.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Protect initial liquidity from sniping:\n\n\
                     1. Add initial buy limits:\n\
                     require(amount <= maxBuyAmount, \"Exceeds max buy\");\n\n\
                     2. Implement anti-bot measures:\n\
                     require(block.number > launchBlock + 3, \"Too early\");\n\n\
                     3. Use whitelist for early buyers\n\
                     4. Add cooldown between purchases"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_trading_enable(source) {
            let message = format!(
                "Function '{}' in contract '{}' enables trading without delay mechanism. \
                 Bots monitoring the mempool can snipe immediately.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Add delay to trading enable:\n\n\
                     function enableTrading() external onlyOwner {\n\
                         launchBlock = block.number;\n\
                         launchTime = block.timestamp;\n\
                         tradingEnabled = true;\n\
                     }\n\n\
                     // In transfer:\n\
                     if (block.number < launchBlock + 3) {\n\
                         require(amount <= maxBuyFirstBlocks);\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_presale_transition(source) {
            let message = format!(
                "Function '{}' in contract '{}' transitions from presale to DEX. \
                 This transition is a prime target for sniper bots.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Protect presale to DEX transition:\n\n\
                     1. Use deadblock protection (first N blocks restricted)\n\
                     2. Add liquidity via private transaction\n\
                     3. Implement gradual price discovery\n\
                     4. Use fair launch platforms (Unicrypt, PinkSale)"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_fair_launch_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' has launch checks without transaction limits. \
                 Snipers can buy large amounts immediately at launch.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Add fair launch protections:\n\n\
                     1. Max transaction amount during launch\n\
                     2. Max wallet holding limit\n\
                     3. Cooldown between buys per wallet\n\
                     4. Higher tax in first blocks\n\
                     5. Blacklist known sniper contracts"
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
        let detector = TokenLaunchMevDetector::new();
        assert_eq!(detector.name(), "Token Launch MEV");
        assert_eq!(detector.default_severity(), Severity::Critical);
    }
}
