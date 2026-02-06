use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for order flow auction abuse vulnerabilities
///
/// Detects patterns where order flow auctions can be manipulated
/// by searchers to extract value from users.
pub struct OrderFlowAuctionAbuseDetector {
    base: BaseDetector,
}

impl Default for OrderFlowAuctionAbuseDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl OrderFlowAuctionAbuseDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("order-flow-auction-abuse"),
                "Order Flow Auction Abuse".to_string(),
                "Detects order flow auction patterns vulnerable to manipulation \
                 where searchers can game the auction mechanism to extract value."
                    .to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::DeFi],
                Severity::High,
            ),
        }
    }

    /// Find auction bid patterns
    fn find_auction_bids(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ") && (trimmed.contains("bid") || trimmed.contains("Bid"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for bid manipulation protections
                let has_protection = func_body.contains("minBid")
                    || func_body.contains("maxBid")
                    || func_body.contains("commit");

                if !has_protection {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find auction settlement patterns
    fn find_auction_settlement(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ")
                && (trimmed.contains("settle") || trimmed.contains("finalize"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for fair settlement
                let has_fair_settlement = func_body.contains("randomness")
                    || func_body.contains("vrf")
                    || func_body.contains("commit");

                if !has_fair_settlement {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find first-price auction vulnerabilities
    fn find_first_price_auction(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for highest bid wins pattern
            if trimmed.contains("highestBid") || trimmed.contains("winningBid") {
                let context_start = if line_num > 10 { line_num - 10 } else { 0 };
                let context_end = std::cmp::min(line_num + 5, lines.len());
                let context: String = lines[context_start..context_end].join("\n");

                // First-price auction without sealed bids
                if !context.contains("sealed") && !context.contains("commit") {
                    let func_name = self.find_containing_function(&lines, line_num);
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

impl Detector for OrderFlowAuctionAbuseDetector {
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

        for (line, func_name) in self.find_auction_bids(source) {
            let message = format!(
                "Function '{}' in contract '{}' accepts bids without manipulation protection. \
                 Searchers can game the bidding process.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Add bid manipulation protections:\n\n\
                     1. Implement sealed-bid auctions with commit-reveal\n\
                     2. Add minimum bid increments\n\
                     3. Use time-weighted bidding\n\
                     4. Implement bid bonds to prevent spam"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_auction_settlement(source) {
            let message = format!(
                "Function '{}' in contract '{}' settles auctions without fairness guarantees. \
                 Settlement can be manipulated by timing attacks.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Implement fair auction settlement:\n\n\
                     1. Use VRF for winner selection in ties\n\
                     2. Add batch settlement periods\n\
                     3. Implement uniform price auctions\n\
                     4. Use MEV-aware ordering"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_first_price_auction(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses first-price auction without sealed bids. \
                 Bidders can see and outbid each other, enabling last-moment sniping.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Use sealed-bid or second-price auctions:\n\n\
                     // Sealed-bid commit-reveal\n\
                     function commitBid(bytes32 hash) external;\n\
                     function revealBid(uint256 amount, bytes32 salt) external;\n\n\
                     // Or second-price (Vickrey) auction\n\
                     winner pays second-highest bid"
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
        let detector = OrderFlowAuctionAbuseDetector::new();
        assert_eq!(detector.name(), "Order Flow Auction Abuse");
        assert_eq!(detector.default_severity(), Severity::High);
    }
}
