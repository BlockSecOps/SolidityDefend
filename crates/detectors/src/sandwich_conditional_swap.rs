use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};
use crate::utils;

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

    // ==================== Protection detection helpers ====================

    /// Check whether a function body has proper slippage protection.
    /// Recognises common parameter naming conventions used across DeFi
    /// protocols (Uniswap, Curve, 1inch, Balancer, etc.).
    fn has_slippage_protection(func_body: &str) -> bool {
        let lower = func_body.to_lowercase();
        // Common slippage-protection parameter / variable names
        let slippage_names = [
            "minout",
            "minamount",
            "amountoutmin",
            "minamountout",
            "minoutput",
            "minimumamount",
            "minreturn",
            "minreceived",
            "minamountreceived",
            "amountoutminimum",
            "mintokensout",
            "minreturnamount",
        ];
        if slippage_names.iter().any(|n| lower.contains(n)) {
            return true;
        }

        // Also recognise explicit require / revert patterns that compare output
        // amounts against a minimum, e.g.  `require(out >= min, ...)`
        let has_output_comparison = (func_body.contains("require(")
            || func_body.contains("revert")
            || func_body.contains("if ("))
            && (func_body.contains(">=") || func_body.contains(">"))
            && (lower.contains("slippage")
                || (lower.contains("out") && lower.contains("min"))
                || lower.contains("amountout"));

        has_output_comparison
    }

    /// Check whether a function body has a proper deadline enforcement.
    ///
    /// A *proper* deadline means the function accepts a `deadline` parameter
    /// from the caller and validates `block.timestamp` against it using a
    /// comparison (`<=`, `<`, `>`, `>=`).
    ///
    /// A *meaningless* deadline is when `block.timestamp` is used directly as
    /// the deadline argument (always passes) or `type(uint256).max` is passed.
    fn has_deadline_protection(func_body: &str) -> bool {
        let has_deadline_param = func_body.contains("deadline")
            || func_body.contains("validUntil")
            || func_body.contains("expiry")
            || func_body.contains("expirationTime");

        if !has_deadline_param {
            return false;
        }

        // If the function has a deadline param AND validates it against
        // block.timestamp with a comparison operator, it has proper protection.
        if func_body.contains("block.timestamp") {
            let has_comparison = Self::has_deadline_comparison(func_body);
            if has_comparison {
                return true;
            }
            // block.timestamp present but no comparison -- might be used as
            // the deadline value itself (bad), so fall through to false.
        }

        // deadline param exists and block.timestamp is not present at all --
        // the deadline may come from the caller and be forwarded, which is fine.
        !func_body.contains("block.timestamp")
    }

    /// Detect whether `block.timestamp` is compared against a deadline
    /// variable (proper usage), e.g.:
    ///   - `require(block.timestamp <= deadline, ...)`
    ///   - `if (block.timestamp > deadline) revert ...`
    ///
    /// Returns true when the pattern looks like a proper deadline check.
    fn has_deadline_comparison(func_body: &str) -> bool {
        for line in func_body.lines() {
            let trimmed = line.trim();
            if !trimmed.contains("block.timestamp") {
                continue;
            }
            // Look for comparison operators adjacent to block.timestamp
            // These patterns indicate a CHECK, not a USE-AS-VALUE:
            //   block.timestamp > deadline
            //   block.timestamp >= deadline
            //   block.timestamp <= deadline
            //   block.timestamp < deadline
            //   deadline >= block.timestamp
            //   deadline > block.timestamp
            let is_comparison = (trimmed.contains("block.timestamp >")
                || trimmed.contains("block.timestamp <")
                || trimmed.contains("block.timestamp >=")
                || trimmed.contains("block.timestamp <=")
                || trimmed.contains("> block.timestamp")
                || trimmed.contains("< block.timestamp")
                || trimmed.contains(">= block.timestamp")
                || trimmed.contains("<= block.timestamp"))
                && (trimmed.contains("deadline")
                    || trimmed.contains("expir")
                    || trimmed.contains("validUntil"));

            if is_comparison {
                return true;
            }
        }
        false
    }

    /// Check whether a function body has K-invariant validation,
    /// which is a core AMM pool protection mechanism.
    fn has_k_invariant_check(func_body: &str) -> bool {
        let lower = func_body.to_lowercase();
        lower.contains("invariant")
            || (func_body.contains("balance0")
                && func_body.contains("balance1")
                && (func_body.contains("*") || func_body.contains("require")))
            || lower.contains("k invariant")
            || lower.contains("constant product")
    }

    /// Check if a function signature line indicates a view or pure function.
    fn is_view_or_pure_function(lines: &[&str], func_start: usize) -> bool {
        // The function signature may span multiple lines until we see `{` or `;`
        let search_end = std::cmp::min(func_start + 8, lines.len());
        for i in func_start..search_end {
            let trimmed = lines[i].trim();
            if trimmed.contains("view") || trimmed.contains("pure") {
                return true;
            }
            // Stop scanning once we reach the function body or a semicolon
            if trimmed.contains('{') || trimmed.ends_with(';') {
                break;
            }
        }
        false
    }

    /// Get the full function body from a function declaration line.
    fn get_func_body(&self, lines: &[&str], func_start: usize) -> String {
        let func_end = self.find_function_end(lines, func_start);
        lines[func_start..func_end].join("\n")
    }

    // ==================== Sub-detectors ====================

    /// Find swaps with weak slippage protection
    fn find_weak_slippage_swaps(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for swap functions
            if trimmed.contains("swap") && trimmed.contains("function ") {
                // Skip view/pure -- they cannot execute swaps
                if Self::is_view_or_pure_function(&lines, line_num) {
                    continue;
                }

                let func_body = self.get_func_body(&lines, line_num);
                let func_name = self.extract_function_name(trimmed);

                let has_min_out = Self::has_slippage_protection(&func_body);
                let has_deadline = Self::has_deadline_protection(&func_body);
                let has_k_check = Self::has_k_invariant_check(&func_body);

                let uses_router = func_body.contains("swapExact")
                    || func_body.contains("swap(")
                    || func_body.contains("exchange(");

                // If the function has K-invariant validation it is an AMM pool
                // implementation, not a consumer -- AMM pools are protected by
                // their invariant math and should not be flagged here.
                if has_k_check {
                    continue;
                }

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
                // Find the containing function to check mutability
                let func_line = self.find_containing_function_line(&lines, line_num);
                if let Some(fl) = func_line {
                    if Self::is_view_or_pure_function(&lines, fl) {
                        continue;
                    }
                }

                let context_end = std::cmp::min(line_num + 15, lines.len());
                let context: String = lines[line_num..context_end].join("\n");

                // Condition followed by swap
                if context.contains("swap") || context.contains("exchange") {
                    // Check for observable conditions (case-insensitive)
                    let lower = trimmed.to_lowercase();
                    let has_price_condition = lower.contains("price")
                        || lower.contains("rate")
                        || lower.contains("getamountsout");

                    let has_balance_condition =
                        lower.contains("balanceof") || lower.contains("balance");

                    let has_time_condition =
                        trimmed.contains("block.timestamp") || trimmed.contains("block.number");

                    if has_price_condition || has_balance_condition || has_time_condition {
                        // --- False positive reduction ---

                        // 1) If the condition is a deadline check comparing
                        //    block.timestamp against a deadline parameter, skip.
                        if has_time_condition && Self::has_deadline_comparison(trimmed) {
                            continue;
                        }

                        // 2) If the condition is a slippage/output check, skip.
                        let is_slippage_check = lower.contains("slippage")
                            || lower.contains("minamount")
                            || lower.contains("minout")
                            || lower.contains("amountoutmin");
                        if is_slippage_check {
                            continue;
                        }

                        // 3) If the condition is part of K-invariant validation
                        //    (AMM pool internal check), skip.
                        if lower.contains("invariant")
                            || (has_balance_condition
                                && (trimmed.contains("*") || trimmed.contains("reserve")))
                        {
                            // Get the containing function body and check for
                            // K-invariant pattern
                            if let Some(fl) = func_line {
                                let fb = self.get_func_body(&lines, fl);
                                if Self::has_k_invariant_check(&fb) {
                                    continue;
                                }
                            }
                        }

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
                // Skip view/pure functions
                if Self::is_view_or_pure_function(&lines, line_num) {
                    continue;
                }

                let func_body = self.get_func_body(&lines, line_num);
                let func_name = self.extract_function_name(trimmed);

                // Skip AMM pool implementations that have K-invariant checks
                if Self::has_k_invariant_check(&func_body) {
                    continue;
                }

                // Skip functions with proper slippage + deadline (comprehensive
                // MEV protection even without private mempool)
                if Self::has_slippage_protection(&func_body)
                    && Self::has_deadline_protection(&func_body)
                {
                    continue;
                }

                // Check for MEV protection
                let has_flashbots = func_body.contains("flashbots")
                    || func_body.contains("Flashbots")
                    || func_body.contains("mevBlocker");

                let has_commit_reveal = func_body.contains("commit")
                    || func_body.contains("reveal")
                    || func_body.contains("commitment");

                let has_private_pool =
                    func_body.contains("private") || func_body.contains("encrypted");

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
                // If block.timestamp is used in a comparison against a deadline
                // variable (e.g. `block.timestamp > deadline`), this is a
                // *proper* deadline check, not a meaningless use.
                if Self::has_deadline_comparison(trimmed) {
                    continue;
                }

                // Also skip if block.timestamp is used in arithmetic that
                // creates a future deadline (e.g. `block.timestamp + 300`)
                if trimmed.contains("block.timestamp +") || trimmed.contains("block.timestamp+") {
                    continue;
                }

                // Skip TWAP / oracle timestamp tracking (e.g. Uniswap _update)
                let lower = trimmed.to_lowercase();
                if lower.contains("timedelta")
                    || lower.contains("timeelapsed")
                    || lower.contains("blocktimestamp")
                    || lower.contains("cumulative")
                {
                    continue;
                }

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
                    // Additional check: skip if the containing function already
                    // has proper deadline protection elsewhere in its body.
                    let func_line = self.find_containing_function_line(&lines, line_num);
                    if let Some(fl) = func_line {
                        let fb = self.get_func_body(&lines, fl);
                        if Self::has_deadline_protection(&fb) {
                            continue;
                        }
                    }

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

    /// Find the line number of the containing function declaration.
    fn find_containing_function_line(&self, lines: &[&str], line_num: usize) -> Option<usize> {
        for i in (0..=line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return Some(i);
            }
        }
        None
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        // Skip AMM pool implementations -- they are the infrastructure, not
        // the consumer.  Flagging an AMM pool's own swap() function for missing
        // slippage/deadline is a false positive because the pool itself is not
        // the entity that needs those protections; the *caller* does.
        if utils::is_amm_pool(ctx) {
            return Ok(findings);
        }

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
        let detector = SandwichConditionalSwapDetector::new();
        assert_eq!(detector.name(), "Sandwich Conditional Swap");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }

    // ==================== Meaningless deadline tests ====================

    #[test]
    fn test_meaningless_deadline_block_timestamp_as_deadline() {
        let detector = SandwichConditionalSwapDetector::new();

        // block.timestamp passed directly as deadline arg -- should flag
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
        assert!(
            !findings.is_empty(),
            "Should flag block.timestamp used as deadline"
        );
    }

    #[test]
    fn test_meaningless_deadline_type_max() {
        let detector = SandwichConditionalSwapDetector::new();

        // type(uint256).max as deadline -- should flag
        let vulnerable = r#"
            contract Swapper {
                function swapNoDeadline(uint256 amount) external {
                    router.swapExactTokensForTokens(
                        amount,
                        0,
                        path,
                        msg.sender,
                        type(uint256).max
                    );
                }
            }
        "#;
        let findings = detector.find_meaningless_deadline(vulnerable);
        assert!(
            !findings.is_empty(),
            "Should flag type(uint256).max as deadline"
        );
    }

    #[test]
    fn test_proper_deadline_comparison_not_flagged() {
        let detector = SandwichConditionalSwapDetector::new();

        // block.timestamp compared against a deadline param -- should NOT flag
        let safe = r#"
            contract SafeSwapper {
                function swap(
                    uint256 amount0Out,
                    uint256 amount1Out,
                    address to,
                    uint256 minAmountOut,
                    uint256 deadline
                ) external {
                    if (block.timestamp > deadline) {
                        revert DeadlineExpired();
                    }
                    _doSwap(amount0Out, amount1Out, to);
                }
            }
        "#;
        let findings = detector.find_meaningless_deadline(safe);
        assert!(
            findings.is_empty(),
            "Should NOT flag block.timestamp compared against deadline"
        );
    }

    #[test]
    fn test_block_timestamp_plus_offset_not_flagged() {
        let detector = SandwichConditionalSwapDetector::new();

        // block.timestamp + 300 creates a future deadline -- should NOT flag
        let safe = r#"
            contract Swapper {
                function swap(uint256 amount) external {
                    router.swapExactTokensForTokens(
                        amount,
                        minOut,
                        path,
                        msg.sender,
                        block.timestamp + 300
                    );
                }
            }
        "#;
        let findings = detector.find_meaningless_deadline(safe);
        assert!(
            findings.is_empty(),
            "Should NOT flag block.timestamp + offset as meaningless deadline"
        );
    }

    // ==================== Weak slippage tests ====================

    #[test]
    fn test_weak_slippage_no_protection() {
        let detector = SandwichConditionalSwapDetector::new();

        let vulnerable = r#"
            contract Swapper {
                function swap(uint256 amount) external {
                    router.swapExactTokensForTokens(
                        amount, 0, path, msg.sender, block.timestamp
                    );
                }
            }
        "#;
        let findings = detector.find_weak_slippage_swaps(vulnerable);
        assert!(
            !findings.is_empty(),
            "Should flag swap without slippage protection"
        );
    }

    #[test]
    fn test_weak_slippage_with_minamountout() {
        let detector = SandwichConditionalSwapDetector::new();

        // Has minAmountOut + proper deadline -- should NOT flag
        let safe = r#"
            contract SafeSwapper {
                function swap(
                    uint256 amount0Out,
                    uint256 amount1Out,
                    address to,
                    uint256 minAmountOut,
                    uint256 deadline
                ) external {
                    if (block.timestamp > deadline) {
                        revert DeadlineExpired();
                    }
                    uint256 totalOut = amount0Out + amount1Out;
                    if (totalOut < minAmountOut) {
                        revert SlippageExceeded();
                    }
                    token0.safeTransfer(to, amount0Out);
                }
            }
        "#;
        let findings = detector.find_weak_slippage_swaps(safe);
        assert!(
            findings.is_empty(),
            "Should NOT flag swap with minAmountOut and deadline"
        );
    }

    #[test]
    fn test_weak_slippage_with_k_invariant_skipped() {
        let detector = SandwichConditionalSwapDetector::new();

        // AMM pool with K-invariant check -- should NOT flag
        let amm_pool = r#"
            contract Pair {
                function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external {
                    require(amount0Out > 0 || amount1Out > 0, 'INSUFFICIENT_OUTPUT');
                    if (amount0Out > 0) _safeTransfer(token0, to, amount0Out);
                    if (amount1Out > 0) _safeTransfer(token1, to, amount1Out);
                    uint balance0 = IERC20(token0).balanceOf(address(this));
                    uint balance1 = IERC20(token1).balanceOf(address(this));
                    require(balance0 * balance1 >= uint(reserve0) * uint(reserve1), 'K invariant');
                }
            }
        "#;
        let findings = detector.find_weak_slippage_swaps(amm_pool);
        assert!(
            findings.is_empty(),
            "Should NOT flag AMM pool swap with K-invariant check"
        );
    }

    #[test]
    fn test_view_function_skipped() {
        let detector = SandwichConditionalSwapDetector::new();

        let safe = r#"
            contract Helper {
                function getSwapAmount(uint256 amount) external view returns (uint256) {
                    return router.getAmountsOut(amount, path)[1];
                }
            }
        "#;
        let findings = detector.find_weak_slippage_swaps(safe);
        assert!(findings.is_empty(), "Should NOT flag view functions");
    }

    // ==================== Conditional swap tests ====================

    #[test]
    fn test_conditional_swap_price_condition() {
        let detector = SandwichConditionalSwapDetector::new();

        // Observable price condition before swap -- should flag
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
        assert!(
            !findings.is_empty(),
            "Should flag observable price condition before swap"
        );
    }

    #[test]
    fn test_conditional_swap_deadline_check_not_flagged() {
        let detector = SandwichConditionalSwapDetector::new();

        // Deadline check is a protection, not an observable condition
        let safe = r#"
            contract SafeTrader {
                function swap(uint256 amount, uint256 deadline) external {
                    if (block.timestamp > deadline) {
                        revert DeadlineExpired();
                    }
                    router.swap(amount);
                }
            }
        "#;
        let findings = detector.find_conditional_swaps(safe);
        assert!(
            findings.is_empty(),
            "Should NOT flag deadline comparison as observable condition"
        );
    }

    #[test]
    fn test_conditional_swap_slippage_check_not_flagged() {
        let detector = SandwichConditionalSwapDetector::new();

        // Slippage check is a protection, not an observable condition
        let safe = r#"
            contract SafeTrader {
                function swap(uint256 amount, uint256 minAmountOut) external {
                    require(amountOut >= minAmountOut, "SlippageExceeded");
                    router.swap(amount);
                }
            }
        "#;
        let findings = detector.find_conditional_swaps(safe);
        assert!(
            findings.is_empty(),
            "Should NOT flag slippage check as observable condition"
        );
    }

    // ==================== Public swap tests ====================

    #[test]
    fn test_public_swap_with_full_protection_not_flagged() {
        let detector = SandwichConditionalSwapDetector::new();

        // Has both slippage + deadline -- should NOT flag
        let safe = r#"
            contract SafeSwap {
                function swap(uint256 amount, uint256 minAmountOut, uint256 deadline) external {
                    if (block.timestamp > deadline) revert Expired();
                    uint256 out = router.swapExactTokensForTokens(amount, minAmountOut, path, msg.sender, deadline);
                    require(out >= minAmountOut, "Slippage");
                }
            }
        "#;
        let findings = detector.find_public_swaps(safe);
        assert!(
            findings.is_empty(),
            "Should NOT flag public swap with slippage + deadline protection"
        );
    }

    #[test]
    fn test_public_swap_no_protection() {
        let detector = SandwichConditionalSwapDetector::new();

        // No protection at all -- should flag
        let vulnerable = r#"
            contract BadSwap {
                function swap(uint256 amount) external {
                    router.swapExactTokensForTokens(amount, 0, path, msg.sender, block.timestamp);
                }
            }
        "#;
        let findings = detector.find_public_swaps(vulnerable);
        assert!(
            !findings.is_empty(),
            "Should flag public swap with no MEV protection"
        );
    }

    #[test]
    fn test_public_swap_amm_pool_k_invariant_not_flagged() {
        let detector = SandwichConditionalSwapDetector::new();

        // AMM pool with K invariant -- should NOT flag
        let amm = r#"
            contract Pair {
                function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external {
                    _safeTransfer(token0, to, amount0Out);
                    uint balance0 = IERC20(token0).balanceOf(address(this));
                    uint balance1 = IERC20(token1).balanceOf(address(this));
                    require(balance0 * balance1 >= uint(reserve0) * uint(reserve1), 'K invariant');
                }
            }
        "#;
        let findings = detector.find_public_swaps(amm);
        assert!(
            findings.is_empty(),
            "Should NOT flag AMM pool swap with K-invariant"
        );
    }

    // ==================== Helper method tests ====================

    #[test]
    fn test_has_slippage_protection_various_names() {
        assert!(SandwichConditionalSwapDetector::has_slippage_protection(
            "uint256 minAmountOut"
        ));
        assert!(SandwichConditionalSwapDetector::has_slippage_protection(
            "uint256 amountOutMin"
        ));
        assert!(SandwichConditionalSwapDetector::has_slippage_protection(
            "uint256 minOut"
        ));
        assert!(SandwichConditionalSwapDetector::has_slippage_protection(
            "uint256 minReturn"
        ));
        assert!(SandwichConditionalSwapDetector::has_slippage_protection(
            "uint256 amountOutMinimum"
        ));
        assert!(!SandwichConditionalSwapDetector::has_slippage_protection(
            "uint256 amount"
        ));
    }

    #[test]
    fn test_has_deadline_protection() {
        // Proper: has deadline param + comparison
        assert!(SandwichConditionalSwapDetector::has_deadline_protection(
            "function swap(uint256 deadline) external {\n    if (block.timestamp > deadline) revert();\n}"
        ));

        // Proper: deadline without block.timestamp (forwarded to router)
        assert!(SandwichConditionalSwapDetector::has_deadline_protection(
            "function swap(uint256 deadline) external {\n    router.swap(amount, deadline);\n}"
        ));

        // Bad: no deadline param at all
        assert!(!SandwichConditionalSwapDetector::has_deadline_protection(
            "function swap(uint256 amount) external {\n    router.swap(amount, block.timestamp);\n}"
        ));
    }

    #[test]
    fn test_has_deadline_comparison() {
        assert!(SandwichConditionalSwapDetector::has_deadline_comparison(
            "if (block.timestamp > deadline) revert();"
        ));
        assert!(SandwichConditionalSwapDetector::has_deadline_comparison(
            "require(block.timestamp <= deadline, \"Expired\");"
        ));
        assert!(SandwichConditionalSwapDetector::has_deadline_comparison(
            "require(deadline >= block.timestamp, \"Expired\");"
        ));
        // No comparison -- just using block.timestamp as value
        assert!(!SandwichConditionalSwapDetector::has_deadline_comparison(
            "router.swap(amount, block.timestamp);"
        ));
    }

    #[test]
    fn test_has_k_invariant_check() {
        assert!(SandwichConditionalSwapDetector::has_k_invariant_check(
            "require(balance0 * balance1 >= reserve0 * reserve1, 'K invariant');"
        ));
        assert!(SandwichConditionalSwapDetector::has_k_invariant_check(
            "if (balance0Adjusted * balance1Adjusted < _reserve0 * _reserve1 * 1000000) { revert InvariantViolation(); }"
        ));
        assert!(!SandwichConditionalSwapDetector::has_k_invariant_check(
            "router.swapExactTokensForTokens(amount, 0, path, msg.sender, block.timestamp);"
        ));
    }

    #[test]
    fn test_is_view_or_pure_function() {
        let view_lines = vec!["    function getPrice() external view returns (uint256) {"];
        assert!(SandwichConditionalSwapDetector::is_view_or_pure_function(
            &view_lines,
            0
        ));

        let pure_lines = vec!["    function sqrt(uint256 y) internal pure returns (uint256) {"];
        assert!(SandwichConditionalSwapDetector::is_view_or_pure_function(
            &pure_lines,
            0
        ));

        let external_lines = vec!["    function swap(uint256 amount) external {"];
        assert!(!SandwichConditionalSwapDetector::is_view_or_pure_function(
            &external_lines,
            0
        ));

        // Multiline function signature
        let multiline = vec![
            "    function getSwapAmount(",
            "        uint256 amount",
            "    ) external view returns (uint256) {",
        ];
        assert!(SandwichConditionalSwapDetector::is_view_or_pure_function(
            &multiline, 0
        ));
    }
}
