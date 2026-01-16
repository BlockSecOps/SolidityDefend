use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for conditional sandwich attack vulnerabilities
///
/// Detects swap patterns that are vulnerable to sandwich attacks with
/// conditional execution, where attackers can profit by sandwiching
/// transactions based on observable conditions.
///
/// Vulnerable pattern:
/// ```solidity
/// function swap(uint256 amountIn, uint256 minOut) external {
///     // No deadline check - can be sandwiched at any time
///     // No private mempool - transaction visible
///     uint256 amountOut = router.swapExactTokensForTokens(
///         amountIn,
///         minOut,  // Slippage allows sandwich profit
///         path,
///         msg.sender,
///         block.timestamp  // Meaningless deadline
///     );
/// }
/// ```
pub struct SandwichConditionalSwapDetector {
    base: BaseDetector,
}

impl Default for SandwichConditionalSwapDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SandwichConditionalSwapDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("sandwich-conditional-swap"),
                "Sandwich Conditional Swap".to_string(),
                "Detects swap patterns vulnerable to conditional sandwich attacks where \
                 attackers can sandwich transactions based on observable on-chain conditions \
                 like price thresholds, balance checks, or time windows."
                    .to_string(),
                vec![DetectorCategory::MEV, DetectorCategory::DeFi],
                Severity::Critical,
            ),
        }
    }

    /// Find swaps with weak slippage protection
    fn find_weak_slippage_swaps(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for swap functions
            if trimmed.contains("swap") && trimmed.contains("function ") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for weak slippage patterns
                let has_min_out = func_body.contains("minOut")
                    || func_body.contains("minAmount")
                    || func_body.contains("amountOutMin");

                let has_deadline = func_body.contains("deadline")
                    && !func_body.contains("block.timestamp");

                let uses_router = func_body.contains("swapExact")
                    || func_body.contains("swap(")
                    || func_body.contains("exchange(");

                if uses_router && (!has_min_out || !has_deadline) {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find conditional swap patterns
    fn find_conditional_swaps(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for conditions before swaps
            if trimmed.starts_with("if") || trimmed.starts_with("require") {
                let context_end = std::cmp::min(line_num + 15, lines.len());
                let context: String = lines[line_num..context_end].join("\n");

                // Condition followed by swap
                if context.contains("swap") || context.contains("exchange") {
                    // Check for observable conditions (case-insensitive)
                    let lower = trimmed.to_lowercase();
                    let has_price_condition = lower.contains("price")
                        || lower.contains("rate")
                        || lower.contains("getamountsout");

                    let has_balance_condition = lower.contains("balanceof")
                        || lower.contains("balance");

                    let has_time_condition = trimmed.contains("block.timestamp")
                        || trimmed.contains("block.number");

                    if has_price_condition || has_balance_condition || has_time_condition {
                        let func_name = self.find_containing_function(&lines, line_num);
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find swaps without private transaction protection
    fn find_public_swaps(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for public/external swap functions
            if trimmed.contains("function ")
                && (trimmed.contains("swap") || trimmed.contains("trade"))
                && (trimmed.contains("external") || trimmed.contains("public"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Check for MEV protection
                let has_flashbots = func_body.contains("flashbots")
                    || func_body.contains("Flashbots")
                    || func_body.contains("mevBlocker");

                let has_commit_reveal = func_body.contains("commit")
                    || func_body.contains("reveal")
                    || func_body.contains("commitment");

                let has_private_pool = func_body.contains("private")
                    || func_body.contains("encrypted");

                if !has_flashbots && !has_commit_reveal && !has_private_pool {
                    // Check if it actually does a swap
                    if func_body.contains("swapExact")
                        || func_body.contains(".swap(")
                        || func_body.contains("uniswap")
                        || func_body.contains("router")
                    {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find timestamp-based deadline issues
    fn find_meaningless_deadline(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for block.timestamp as deadline parameter
            if trimmed.contains("block.timestamp") {
                // Check surrounding context for swap-related calls
                let context_start = if line_num > 5 { line_num - 5 } else { 0 };
                let context_end = std::cmp::min(line_num + 3, lines.len());
                let context: String = lines[context_start..context_end].join("\n");

                // If block.timestamp is used near a swap function, it's likely a meaningless deadline
                if context.contains("swap")
                    || context.contains("Swap")
                    || context.contains("deadline")
                    || context.contains("router")
                {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }

            // Look for type(uint256).max as deadline
            if trimmed.contains("type(uint256).max") || trimmed.contains("uint256(-1)") {
                let context_start = if line_num > 5 { line_num - 5 } else { 0 };
                let context: String = lines[context_start..line_num + 1].join("\n");

                if context.contains("swap") || context.contains("deadline") {
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

impl Detector for SandwichConditionalSwapDetector {
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

        // Find weak slippage swaps
        for (line, func_name) in self.find_weak_slippage_swaps(source) {
            let message = format!(
                "Function '{}' in contract '{}' performs swaps with weak slippage protection. \
                 Missing minimum output amount or deadline allows sandwich attackers to extract \
                 maximum extractable value (MEV) from users.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Add proper slippage and deadline protection:\n\n\
                     function swap(uint256 amountIn, uint256 minOut, uint256 deadline) external {\n\
                         require(block.timestamp <= deadline, \"Expired\");\n\
                         uint256 out = router.swapExactTokensForTokens(\n\
                             amountIn,\n\
                             minOut,  // User-specified minimum\n\
                             path,\n\
                             msg.sender,\n\
                             deadline  // User-specified deadline\n\
                         );\n\
                         require(out >= minOut, \"Slippage\");\n\
                     }"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Find conditional swaps
        for (line, func_name) in self.find_conditional_swaps(source) {
            let message = format!(
                "Function '{}' in contract '{}' has observable conditions before swap execution. \
                 Attackers can monitor these conditions and sandwich transactions when conditions \
                 are about to be met.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Use commit-reveal or private transaction pools:\n\n\
                     1. Commit-reveal scheme:\n\
                     mapping(bytes32 => uint256) public commitments;\n\
                     function commitSwap(bytes32 hash) external { ... }\n\
                     function revealSwap(uint256 amount, bytes32 salt) external { ... }\n\n\
                     2. Flashbots Protect or MEV Blocker for private transactions"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Find public swaps without protection
        for (line, func_name) in self.find_public_swaps(source) {
            let message = format!(
                "Function '{}' in contract '{}' executes swaps without MEV protection. \
                 Transactions are visible in the public mempool and can be sandwiched.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Implement MEV protection strategies:\n\n\
                     1. Use Flashbots Protect for private transactions\n\
                     2. Implement commit-reveal for swap intents\n\
                     3. Use batch auctions instead of immediate execution\n\
                     4. Consider CoW Protocol or similar MEV-resistant DEXs"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Find meaningless deadlines
        for (line, func_name) in self.find_meaningless_deadline(source) {
            let message = format!(
                "Function '{}' in contract '{}' uses block.timestamp or max uint as deadline. \
                 This provides no protection against transaction delays allowing sandwich attacks.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Use a meaningful deadline:\n\n\
                     // BAD: meaningless deadline\n\
                     router.swap(..., block.timestamp);\n\
                     router.swap(..., type(uint256).max);\n\n\
                     // GOOD: user-specified deadline\n\
                     function swap(uint256 deadline) external {\n\
                         require(deadline > block.timestamp, \"Invalid deadline\");\n\
                         router.swap(..., deadline);\n\
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
        let detector = SandwichConditionalSwapDetector::new();
        assert_eq!(detector.name(), "Sandwich Conditional Swap");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_meaningless_deadline() {
        let detector = SandwichConditionalSwapDetector::new();

        let vulnerable = r#"
            contract Swapper {
                function swap(uint256 amount) external {
                    router.swapExactTokensForTokens(
                        amount,
                        0,
                        path,
                        msg.sender,
                        block.timestamp
                    );
                }
            }
        "#;
        let findings = detector.find_meaningless_deadline(vulnerable);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_conditional_swap() {
        let detector = SandwichConditionalSwapDetector::new();

        let vulnerable = r#"
            contract Trader {
                function conditionalSwap() external {
                    if (getPrice() > threshold) {
                        router.swap(amount);
                    }
                }
            }
        "#;
        let findings = detector.find_conditional_swaps(vulnerable);
        assert!(!findings.is_empty());
    }
}
