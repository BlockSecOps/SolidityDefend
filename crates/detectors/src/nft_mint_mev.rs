use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for NFT mint MEV vulnerabilities
///
/// Detects patterns where NFT mints can be front-run by MEV bots
/// to snipe rare or valuable tokens.
pub struct NftMintMevDetector {
    base: BaseDetector,
}

impl Default for NftMintMevDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl NftMintMevDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("nft-mint-mev"),
                "NFT Mint MEV".to_string(),
                "Detects NFT mint patterns vulnerable to front-running where MEV bots \
                 can snipe rare tokens or front-run popular mints."
                    .to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::DeFi],
                Severity::High,
            ),
        }
    }

    /// Find public mint vulnerabilities
    fn find_public_mint(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ")
                && (trimmed.contains("mint") || trimmed.contains("Mint"))
                && (trimmed.contains("public") || trimmed.contains("external"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for bot protection
                let has_protection = func_body.contains("merkle")
                    || func_body.contains("whitelist")
                    || func_body.contains("isContract")
                    || func_body.contains("tx.origin");

                if !has_protection {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find predictable token ID vulnerabilities
    fn find_predictable_token_id(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for sequential token IDs
            if trimmed.contains("tokenId++")
                || trimmed.contains("++tokenId")
                || trimmed.contains("_tokenIdCounter")
                || trimmed.contains("totalSupply()")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    /// Find reveal mechanism vulnerabilities
    fn find_reveal_vulnerabilities(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ")
                && (trimmed.contains("reveal") || trimmed.contains("setBaseURI"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for chainlink VRF or commit-reveal
                let has_random = func_body.contains("chainlink")
                    || func_body.contains("vrf")
                    || func_body.contains("VRF")
                    || func_body.contains("commit");

                if !has_random {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find Dutch auction vulnerabilities
    fn find_dutch_auction_snipe(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let has_dutch = source.contains("dutch") || source.contains("Dutch");
        let has_auction =
            source.contains("auction") || source.contains("price") && source.contains("decrease");

        if has_dutch || has_auction {
            for (line_num, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                // Look for price calculation
                if trimmed.contains("getPrice") || trimmed.contains("currentPrice") {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find batch mint vulnerabilities
    fn find_batch_mint_snipe(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ")
                && (trimmed.contains("batchMint") || trimmed.contains("mintBatch"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for limits
                let has_limits = func_body.contains("maxPerTx") || func_body.contains("maxMint");

                if !has_limits {
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

impl Detector for NftMintMevDetector {
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

        for (line, func_name) in self.find_public_mint(source) {
            let message = format!(
                "Function '{}' in contract '{}' allows public minting without bot protection. \
                 MEV bots can front-run to mint before regular users.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Add bot protection to public mint:\n\n\
                     1. Require EOA (tx.origin == msg.sender)\n\
                     2. Use merkle proof whitelist\n\
                     3. Add per-wallet mint limits\n\
                     4. Implement cooldown between mints\n\
                     5. Use commit-reveal for mint ordering"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_predictable_token_id(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses predictable token IDs. \
                 Attackers can calculate which token ID they'll receive and target rare ones.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Randomize token ID assignment:\n\n\
                     1. Use Chainlink VRF for randomness\n\
                     2. Implement delayed reveal\n\
                     3. Assign metadata post-mint randomly\n\
                     4. Use commit-reveal for minting"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_reveal_vulnerabilities(source) {
            let message = format!(
                "Function '{}' in contract '{}' reveals NFT metadata without randomness. \
                 Attackers may predict or manipulate which tokens get rare traits.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Use verifiable randomness for reveal:\n\n\
                     1. Integrate Chainlink VRF\n\
                     2. Use block hash from future block\n\
                     3. Implement commit-reveal scheme\n\
                     4. Batch reveals to reduce manipulation"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_dutch_auction_snipe(source) {
            let message = format!(
                "Function '{}' in contract '{}' implements Dutch auction pricing. \
                 MEV bots can precisely time purchases at optimal price points.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Low)
                .with_fix_suggestion(
                    "Protect Dutch auction from sniping:\n\n\
                     1. Add randomness to price curve\n\
                     2. Implement batch settlement periods\n\
                     3. Use sealed-bid component\n\
                     4. Consider rebate mechanisms"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_batch_mint_snipe(source) {
            let message = format!(
                "Function '{}' in contract '{}' allows batch minting without limits. \
                 Bots can mint entire supply in one transaction.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Limit batch minting:\n\n\
                     require(amount <= maxPerTx, \"Exceeds max per tx\");\n\
                     require(minted[msg.sender] + amount <= maxPerWallet);\n\n\
                     Consider adding gas limits to prevent large batches."
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
        let detector = NftMintMevDetector::new();
        assert_eq!(detector.name(), "NFT Mint MEV");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
