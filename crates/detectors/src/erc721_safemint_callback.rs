use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for ERC721 safeMint callback vulnerabilities
///
/// Detects patterns where onERC721Received callbacks can be exploited
/// for reentrancy or state manipulation during NFT minting.
pub struct Erc721SafemintCallbackDetector {
    base: BaseDetector,
}

impl Default for Erc721SafemintCallbackDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Erc721SafemintCallbackDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("erc721-safemint-callback"),
                "ERC721 SafeMint Callback".to_string(),
                "Detects ERC721 safeMint patterns vulnerable to callback exploitation \
                 through onERC721Received reentrancy attacks."
                    .to_string(),
                vec![DetectorCategory::Reentrancy, DetectorCategory::DeFi],
                Severity::High,
            ),
        }
    }

    /// Find safeMint in loops without reentrancy protection
    fn find_safemint_loop(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ") && trimmed.contains("mint") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for safeMint in loop
                if func_body.contains("for (")
                    && (func_body.contains("_safeMint") || func_body.contains("safeMint"))
                {
                    // Check if no reentrancy guard
                    if !func_body.contains("nonReentrant") && !func_body.contains("_status") {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find safeMint with state updates after
    fn find_safemint_state_after(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Find safeMint followed by state changes
                if let Some(mint_pos) = func_body.find("_safeMint") {
                    let after_mint = &func_body[mint_pos..];

                    // Check for state changes after safeMint
                    let has_state_after = after_mint.contains("totalMinted")
                        || after_mint.contains("mintedBy[")
                        || after_mint.contains("claimed[")
                        || after_mint.contains(" += ")
                        || after_mint.contains(" = true");

                    if has_state_after && !func_body.contains("nonReentrant") {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find safeMint with payment handling
    fn find_safemint_payment(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ") && trimmed.contains("payable") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for safeMint with msg.value
                if (func_body.contains("_safeMint") || func_body.contains("safeMint"))
                    && func_body.contains("msg.value")
                {
                    // Check if refund happens after safeMint (vulnerable)
                    if func_body.contains("transfer(")
                        || func_body.contains(".call{value:")
                        || func_body.contains("payable(msg.sender)")
                    {
                        if !func_body.contains("nonReentrant") {
                            findings.push((line_num as u32 + 1, func_name));
                        }
                    }
                }
            }
        }

        findings
    }

    /// Find whitelist check before safeMint
    fn find_whitelist_safemint(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ") && trimmed.contains("mint") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for whitelist pattern with safeMint
                let has_whitelist = func_body.contains("whitelist[")
                    || func_body.contains("isWhitelisted")
                    || func_body.contains("merkleProof")
                    || func_body.contains("allowlist");

                if has_whitelist
                    && (func_body.contains("_safeMint") || func_body.contains("safeMint"))
                {
                    // Check if whitelist updated after safeMint
                    if let Some(mint_pos) = func_body.find("_safeMint") {
                        let after_mint = &func_body[mint_pos..];
                        if after_mint.contains("whitelist[")
                            || after_mint.contains("claimed[")
                            || after_mint.contains("minted[")
                        {
                            if !func_body.contains("nonReentrant") {
                                findings.push((line_num as u32 + 1, func_name));
                            }
                        }
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

impl Detector for Erc721SafemintCallbackDetector {
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

        for (line, func_name) in self.find_safemint_loop(source) {
            let message = format!(
                "Function '{}' in contract '{}' calls safeMint in a loop without reentrancy guard. \
                 onERC721Received callback can reenter and mint more tokens.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Protect safeMint loops from reentrancy:\n\n\
                     1. Add reentrancy guard:\n\
                     function batchMint(...) external nonReentrant { ... }\n\n\
                     2. Or use _mint instead of _safeMint for trusted receivers\n\
                     3. Update counters before minting"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_safemint_state_after(source) {
            let message = format!(
                "Function '{}' in contract '{}' updates state after safeMint. \
                 Callback can reenter before state is updated.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Update state before safeMint (checks-effects-interactions):\n\n\
                     // GOOD:\n\
                     totalMinted++;\n\
                     _safeMint(to, tokenId);\n\n\
                     // BAD:\n\
                     _safeMint(to, tokenId);\n\
                     totalMinted++;"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_safemint_payment(source) {
            let message = format!(
                "Function '{}' in contract '{}' handles payment around safeMint without reentrancy guard. \
                 Callback can manipulate payment flow.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Secure payment handling with safeMint:\n\n\
                     1. Add nonReentrant modifier\n\
                     2. Process refunds before minting\n\
                     3. Or use pull pattern for refunds"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_whitelist_safemint(source) {
            let message = format!(
                "Function '{}' in contract '{}' updates whitelist status after safeMint. \
                 Attacker can reenter and bypass mint limits.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(841)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Update whitelist before safeMint:\n\n\
                     // Mark as claimed BEFORE minting\n\
                     claimed[msg.sender] = true;\n\
                     _safeMint(msg.sender, tokenId);\n\n\
                     // Or use nonReentrant modifier"
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
        let detector = Erc721SafemintCallbackDetector::new();
        assert_eq!(detector.name(), "ERC721 SafeMint Callback");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
