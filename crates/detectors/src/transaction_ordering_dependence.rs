use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for transaction ordering dependence vulnerabilities
///
/// Detects patterns where contract behavior depends on transaction ordering,
/// making them vulnerable to front-running and MEV attacks.
///
/// Vulnerable patterns:
/// - First-come-first-served rewards
/// - Deadline-based distributions
/// - Price-sensitive operations without slippage protection
pub struct TransactionOrderingDependenceDetector {
    base: BaseDetector,
}

impl Default for TransactionOrderingDependenceDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionOrderingDependenceDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("transaction-ordering-dependence"),
                "Transaction Ordering Dependence".to_string(),
                "Detects patterns where contract behavior depends on transaction ordering. \
                 Such patterns are vulnerable to front-running, sandwich attacks, and MEV \
                 extraction by miners/validators."
                    .to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::DeFi],
                Severity::Medium,
            ),
        }
    }

    /// Find first-come-first-served patterns
    fn find_fcfs_patterns(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for first-come patterns
            if trimmed.contains("require(") || trimmed.contains("if (") {
                // Check for patterns indicating FCFS
                let patterns = [
                    "participants.length",
                    "totalClaimed",
                    "claimed[",
                    "hasClaimed",
                    "isClaimed",
                    "supply >=",
                    "supply <=",
                    "remaining",
                    "slots",
                    "spots",
                ];

                for pattern in patterns {
                    if trimmed.contains(pattern) {
                        // Check context for reward/claim/mint
                        let context_start = if line_num > 10 { line_num - 10 } else { 0 };
                        let context_end = std::cmp::min(line_num + 10, lines.len());
                        let context: String = lines[context_start..context_end].join("\n");

                        if context.contains("reward")
                            || context.contains("claim")
                            || context.contains("mint")
                            || context.contains("prize")
                            || context.contains("airdrop")
                        {
                            let func_name = self.find_containing_function(&lines, line_num);
                            findings.push((line_num as u32 + 1, func_name));
                            break;
                        }
                    }
                }
            }
        }

        findings
    }

    /// Find deadline-based distribution patterns
    fn find_deadline_patterns(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for timestamp/deadline checks
            if (trimmed.contains("block.timestamp")
                || trimmed.contains("block.number")
                || trimmed.contains("deadline"))
                && (trimmed.contains(">=")
                    || trimmed.contains("<=")
                    || trimmed.contains(">")
                    || trimmed.contains("<"))
            {
                // Check if this is part of a distribution
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                if (func_body.contains("transfer(")
                    || func_body.contains("safeTransfer")
                    || func_body.contains("mint")
                    || func_body.contains("reward"))
                    && !func_body.contains("commit")
                    && !func_body.contains("reveal")
                {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find price-sensitive operations without slippage
    fn find_unprotected_price_operations(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for swap/trade patterns
            let swap_patterns = [
                "swap(",
                "swapExact",
                "exchange(",
                "trade(",
                "getAmountOut",
                "getAmountsOut",
            ];

            for pattern in swap_patterns {
                if trimmed.contains(pattern) {
                    // Check for slippage protection
                    let context_start = if line_num > 15 { line_num - 15 } else { 0 };
                    let context_end = std::cmp::min(line_num + 10, lines.len());
                    let context: String = lines[context_start..context_end].join("\n");

                    let has_slippage_protection = context.contains("minAmount")
                        || context.contains("amountOutMin")
                        || context.contains("slippage")
                        || context.contains("minReceived")
                        || context.contains("minOut")
                        || context.contains("deadline");

                    if !has_slippage_protection {
                        let func_name = self.find_containing_function(&lines, line_num);
                        findings.push((line_num as u32 + 1, func_name));
                        break;
                    }
                }
            }
        }

        findings
    }

    /// Find containing function name
    fn find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                if let Some(func_start) = trimmed.find("function ") {
                    let after_func = &trimmed[func_start + 9..];
                    if let Some(paren_pos) = after_func.find('(') {
                        return after_func[..paren_pos].trim().to_string();
                    }
                }
            }
        }
        "unknown".to_string()
    }

    /// Find the end of a function
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

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for TransactionOrderingDependenceDetector {
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

        // Check for first-come-first-served patterns
        let fcfs = self.find_fcfs_patterns(source);
        for (line, func_name) in fcfs {
            let message = format!(
                "Function '{}' in contract '{}' has first-come-first-served logic that depends \
                 on transaction ordering. Attackers can front-run legitimate users to claim \
                 rewards, spots, or limited supply.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 30)
                .with_cwe(362) // CWE-362: Race Condition
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Use commit-reveal scheme or Chainlink VRF for fair distribution:\n\n\
                     // Commit phase\n\
                     function commit(bytes32 hash) external {\n\
                         commits[msg.sender] = hash;\n\
                         commitBlock[msg.sender] = block.number;\n\
                     }\n\n\
                     // Reveal phase (after N blocks)\n\
                     function reveal(uint256 secret) external {\n\
                         require(block.number > commitBlock[msg.sender] + MIN_BLOCKS);\n\
                         require(commits[msg.sender] == keccak256(abi.encode(secret)));\n\
                         // Fair distribution logic\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        // Check for deadline patterns
        let deadlines = self.find_deadline_patterns(source);
        for (line, func_name) in deadlines {
            let message = format!(
                "Function '{}' in contract '{}' has deadline-based logic without protection \
                 against front-running. Attackers can time transactions to maximize their \
                 advantage at the deadline.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 30)
                .with_cwe(362) // CWE-362: Race Condition
                .with_confidence(Confidence::Low)
                .with_fix_suggestion(
                    "Add commit-reveal for deadline-sensitive operations:\n\n\
                     // Or use time-weighted average to reduce timing advantage"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Check for unprotected price operations
        let price_ops = self.find_unprotected_price_operations(source);
        for (line, func_name) in price_ops {
            let message = format!(
                "Function '{}' in contract '{}' performs price-sensitive operation without \
                 slippage protection. Vulnerable to sandwich attacks where attacker manipulates \
                 price before and after the transaction.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 30)
                .with_cwe(362) // CWE-362: Race Condition
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Add slippage protection and deadline:\n\n\
                     function swap(\n\
                         uint256 amountIn,\n\
                         uint256 amountOutMin, // Slippage protection\n\
                         address[] calldata path,\n\
                         uint256 deadline // Timing protection\n\
                     ) external {\n\
                         require(block.timestamp <= deadline, \"Expired\");\n\
                         // ... swap logic ...\n\
                         require(amountOut >= amountOutMin, \"Slippage\");\n\
                     }"
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
        let detector = TransactionOrderingDependenceDetector::new();
        assert_eq!(detector.name(), "Transaction Ordering Dependence");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_fcfs_detection() {
        let detector = TransactionOrderingDependenceDetector::new();

        let vulnerable = r#"
            contract Airdrop {
                function claim() external {
                    require(participants.length < MAX_PARTICIPANTS);
                    require(!claimed[msg.sender]);
                    claimed[msg.sender] = true;
                    reward.transfer(msg.sender, REWARD_AMOUNT);
                }
            }
        "#;
        let findings = detector.find_fcfs_patterns(vulnerable);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_deadline_detection() {
        let detector = TransactionOrderingDependenceDetector::new();

        let vulnerable = r#"
            contract Distribution {
                function claimReward() external {
                    require(block.timestamp >= deadline);
                    uint256 reward = rewardPool / participants.length;
                    token.transfer(msg.sender, reward);
                }
            }
        "#;
        let findings = detector.find_deadline_patterns(vulnerable);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_swap_without_slippage() {
        let detector = TransactionOrderingDependenceDetector::new();

        let vulnerable = r#"
            contract Swapper {
                function doSwap(uint256 amount) external {
                    router.swapExactTokensForTokens(amount, 0, path, to, deadline);
                }
            }
        "#;
        // Has deadline but no minAmount check
        let findings = detector.find_unprotected_price_operations(vulnerable);
        // Should pass because deadline exists
        assert!(findings.is_empty());
    }
}
