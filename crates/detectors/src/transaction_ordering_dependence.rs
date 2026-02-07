use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for transaction ordering dependence vulnerabilities
///
/// Detects patterns where contract behavior depends on transaction ordering,
/// making them vulnerable to front-running and MEV attacks.
///
/// Vulnerable patterns:
/// - First-come-first-served rewards
/// - Deadline-based distributions
/// - Price-sensitive operations without slippage protection
///
/// False positive reduction:
/// - Flash loan callback/execution functions (atomic execution makes TOD irrelevant)
/// - View/pure/internal functions (cannot be front-run directly)
/// - Governance functions (vote, execute, propose) in governance contracts
/// - Price helper functions without actual DEX swap or token transfer operations
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
                    let func_sig = self.find_containing_function_signature(&lines, line_num);

                    // FP Reduction: Skip flash loan callback/execution functions
                    // Flash loans execute atomically, making TOD irrelevant
                    if self.is_flash_loan_function(&func_name, source) {
                        continue;
                    }

                    // FP Reduction: Skip view/pure/internal/private functions
                    if self.is_view_pure_or_internal_function(&func_sig) {
                        continue;
                    }

                    // FP Reduction: Skip governance functions (vote, execute, propose)
                    // Governance deadlines are intentional timelock/voting mechanisms
                    if self.is_governance_function(&func_name, source) {
                        continue;
                    }

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
                        let func_sig = self.find_containing_function_signature(&lines, line_num);

                        // FP Reduction: Skip view/pure/internal/private functions
                        // These are read-only helpers or internal utilities, not
                        // externally callable state-changing operations
                        if self.is_view_pure_or_internal_function(&func_sig) {
                            break;
                        }

                        // FP Reduction: Skip flash loan callback/execution functions
                        if self.is_flash_loan_function(&func_name, source) {
                            break;
                        }

                        // FP Reduction: For view-like patterns (getAmountOut, getAmountsOut,
                        // getPrice*, etc.), require the containing function to actually
                        // perform a DEX swap or token transfer. Pure price-reading helpers
                        // are not vulnerable to TOD.
                        let is_price_read_pattern = trimmed.contains("getAmountOut")
                            || trimmed.contains("getAmountsOut")
                            || trimmed.contains("getPrice")
                            || trimmed.contains("get_price")
                            || trimmed.contains("fetchPrice")
                            || trimmed.contains("queryPrice");

                        if is_price_read_pattern
                            && !self.has_actual_dex_interaction(&lines, line_num)
                        {
                            break;
                        }

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

    /// Find the full function signature text for the function containing a given line.
    /// Returns everything from the `function` keyword through the opening `{`.
    fn find_containing_function_signature(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..=line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                // Collect lines from function keyword up to the opening brace
                let mut sig = String::new();
                for j in i..lines.len() {
                    sig.push_str(lines[j]);
                    sig.push(' ');
                    if lines[j].contains('{') {
                        break;
                    }
                }
                return sig;
            }
        }
        String::new()
    }

    /// Check if a function is a flash loan callback or execution function.
    /// Flash loan callbacks execute atomically within a single transaction,
    /// making transaction ordering irrelevant.
    fn is_flash_loan_function(&self, func_name: &str, source: &str) -> bool {
        let name_lower = func_name.to_lowercase();

        // Flash loan callback function names (execute atomically)
        let flash_loan_callbacks = [
            "executeoperation",       // Aave flash loan callback
            "onflashloan",            // ERC-3156 flash loan callback
            "receiveflashloan",       // Balancer flash loan callback
            "flashloancallback",      // Generic flash loan callback
            "uniswapv2call",          // Uniswap V2 flash swap callback
            "uniswapv3flashcallback", // Uniswap V3 flash callback
            "pancakecall",            // PancakeSwap flash swap callback
        ];

        for callback in &flash_loan_callbacks {
            if name_lower == *callback {
                return true;
            }
        }

        // Flash loan execution/arbitrage functions
        let flash_loan_executors = [
            "executearbitrage",
            "executeflashloan",
            "initiateflashloan",
            "flasharbitrage",
            "flashswap",
            "performarbitrage",
        ];

        for executor in &flash_loan_executors {
            if name_lower == *executor {
                return true;
            }
        }

        // Check if the function body is within a flash loan context by looking
        // at whether the containing contract has flash loan interfaces/callbacks
        let source_lower = source.to_lowercase();
        let is_flash_contract = source_lower.contains("iflashloanreceiver")
            || source_lower.contains("iflashborrower")
            || source_lower.contains("ierc3156flashborrower")
            || source_lower.contains("flashloanreceiver")
            || source.contains("executeOperation")
            || source.contains("onFlashLoan")
            || source.contains("receiveFlashLoan");

        // If it is a flash loan contract and the function name contains "arbitrage",
        // "flash", or "execute" (but not generic execute in governance), skip it
        if is_flash_contract {
            if name_lower.contains("arbitrage")
                || name_lower.contains("flash")
                || (name_lower.contains("execute") && !name_lower.contains("proposal"))
            {
                return true;
            }
        }

        false
    }

    /// Check if a function signature indicates it is view, pure, internal, or private.
    /// Such functions cannot be directly front-run or are read-only helpers.
    fn is_view_pure_or_internal_function(&self, func_signature: &str) -> bool {
        let sig_lower = func_signature.to_lowercase();

        // Check for view/pure modifiers (read-only, no state changes)
        if sig_lower.contains(" view ")
            || sig_lower.contains(" view{")
            || sig_lower.contains(" pure ")
            || sig_lower.contains(" pure{")
            || sig_lower.contains(" view\n")
            || sig_lower.contains(" pure\n")
        {
            return true;
        }

        // Check for internal/private visibility (cannot be called externally)
        if sig_lower.contains(" internal ")
            || sig_lower.contains(" internal{")
            || sig_lower.contains(" private ")
            || sig_lower.contains(" private{")
            || sig_lower.contains(" internal\n")
            || sig_lower.contains(" private\n")
        {
            return true;
        }

        false
    }

    /// Check if a function is a governance operation (vote, execute, propose)
    /// in a governance contract context. Governance functions use deadlines
    /// intentionally for timelock/voting periods and are not TOD vulnerabilities.
    fn is_governance_function(&self, func_name: &str, source: &str) -> bool {
        let name_lower = func_name.to_lowercase();

        // Governance function names
        let governance_functions = [
            "vote",
            "castvote",
            "castvotewithsig",
            "castvotewithreasonandsig",
            "castvotewithparams",
            "castvotewithparamsbysig",
            "castvotebysig",
            "execute",
            "executeproposal",
            "propose",
            "queue",
            "cancel",
            "cancelproposal",
        ];

        let is_governance_func = governance_functions.iter().any(|gf| name_lower == *gf);

        if !is_governance_func {
            return false;
        }

        // Verify the contract actually has governance context
        let source_lower = source.to_lowercase();
        let has_governance_indicators = source_lower.contains("proposal")
            || source_lower.contains("governor")
            || source_lower.contains("governance")
            || source_lower.contains("voting")
            || source_lower.contains("quorum")
            || source_lower.contains("timelock")
            || source_lower.contains("votecount")
            || source_lower.contains("ballot");

        is_governance_func && has_governance_indicators
    }

    /// Check if the containing function performs an actual DEX swap or external
    /// token transfer. View/helper functions that merely read prices without
    /// performing state-changing operations are not vulnerable to TOD.
    fn has_actual_dex_interaction(&self, lines: &[&str], line_num: usize) -> bool {
        // Find the function boundaries
        let func_start = self.find_function_start(lines, line_num);
        let func_end = self.find_function_end(lines, func_start);
        let func_body: String = lines[func_start..func_end].join("\n");

        // Check for actual state-changing DEX/token operations
        let has_state_changing_ops = func_body.contains(".swap(")
            || func_body.contains("swapExact")
            || func_body.contains("swapTokens")
            || func_body.contains(".transfer(")
            || func_body.contains(".transferFrom(")
            || func_body.contains("safeTransfer(")
            || func_body.contains("safeTransferFrom(")
            || func_body.contains(".exchange(")
            || func_body.contains(".trade(")
            || func_body.contains(".deposit(")
            || func_body.contains(".withdraw(")
            || func_body.contains(".mint(")
            || func_body.contains(".burn(");

        has_state_changing_ops
    }

    /// Find the start of the function containing a given line
    fn find_function_start(&self, lines: &[&str], line_num: usize) -> usize {
        for i in (0..=line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return i;
            }
        }
        0
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

        // FP Reduction: Skip flash loan provider contracts entirely
        // Flash loan providers/receivers execute atomically, making TOD irrelevant
        if utils::is_flash_loan_provider(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip governance protocol contracts entirely
        // Governance contracts use deadlines intentionally for voting/timelock
        if utils::is_governance_protocol(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip test contracts
        if utils::is_test_contract(ctx) {
            return Ok(findings);
        }

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

    // ================================================================
    // FP Reduction Tests: Flash Loan Functions
    // ================================================================

    #[test]
    fn test_no_fp_flash_loan_arbitrage_deadline() {
        let detector = TransactionOrderingDependenceDetector::new();

        // Flash loan arbitrage function with deadline-based logic.
        // Executes atomically within a flash loan -- TOD is irrelevant.
        let source = r#"
            contract FlashLoanArbitrage is IFlashLoanReceiver {
                function executeArbitrage(address token, uint256 amount) external {
                    require(block.timestamp <= deadline);
                    pool.flashLoan(address(this), token, amount, "");
                    token.transfer(msg.sender, profit);
                }

                function executeOperation(
                    address asset,
                    uint256 amount,
                    uint256 premium,
                    address initiator,
                    bytes calldata params
                ) external returns (bool) {
                    require(block.timestamp <= deadline);
                    dex1.swap(token, amount);
                    dex2.swap(token, amountOut);
                    IERC20(asset).transfer(msg.sender, amount + premium);
                    return true;
                }
            }
        "#;
        let findings = detector.find_deadline_patterns(source);
        assert!(
            findings.is_empty(),
            "Flash loan arbitrage and callback functions should not trigger deadline TOD findings, got: {:?}",
            findings
        );
    }

    #[test]
    fn test_no_fp_flash_loan_callback_names() {
        let detector = TransactionOrderingDependenceDetector::new();

        assert!(
            detector
                .is_flash_loan_function("executeOperation", "contract X is IFlashLoanReceiver {}"),
            "executeOperation should be recognized as a flash loan function"
        );
        assert!(
            detector.is_flash_loan_function("onFlashLoan", "contract X {}"),
            "onFlashLoan should be recognized as a flash loan function"
        );
        assert!(
            detector.is_flash_loan_function("receiveFlashLoan", "contract X {}"),
            "receiveFlashLoan should be recognized as a flash loan function"
        );
        assert!(
            detector.is_flash_loan_function(
                "executeArbitrage",
                "contract X { function onFlashLoan() {} }"
            ),
            "executeArbitrage in flash loan context should be recognized"
        );
        assert!(
            !detector.is_flash_loan_function("withdraw", "contract X {}"),
            "withdraw should NOT be recognized as a flash loan function"
        );
    }

    // ================================================================
    // FP Reduction Tests: View/Pure/Internal Functions
    // ================================================================

    #[test]
    fn test_no_fp_view_function_price_read() {
        let detector = TransactionOrderingDependenceDetector::new();

        // getPriceFromDEX is a view/internal helper -- should not be flagged
        let source = r#"
            contract FlashLoanArbitrage {
                function getPriceFromDEX(address dex, address token) internal view returns (uint256) {
                    uint256 amountOut = IDex(dex).getAmountOut(1e18, token, WETH);
                    uint256 price = IDex(dex).getAmountsOut(1e18, path)[1];
                    return price;
                }
            }
        "#;
        let findings = detector.find_unprotected_price_operations(source);
        assert!(
            findings.is_empty(),
            "View/internal price helper functions should not trigger TOD findings, got: {:?}",
            findings
        );
    }

    #[test]
    fn test_no_fp_pure_function() {
        let detector = TransactionOrderingDependenceDetector::new();

        let source = r#"
            contract PriceUtils {
                function calculateSwapAmount(uint256 input) internal pure returns (uint256) {
                    return getAmountOut(input, reserveIn, reserveOut);
                }
            }
        "#;
        let findings = detector.find_unprotected_price_operations(source);
        assert!(
            findings.is_empty(),
            "Pure functions should not trigger TOD findings"
        );
    }

    #[test]
    fn test_no_fp_internal_function() {
        let detector = TransactionOrderingDependenceDetector::new();

        let source = r#"
            contract DEXHelper {
                function _getPrice(address pair) internal returns (uint256) {
                    return IPair(pair).getAmountOut(1e18, token0, token1);
                }
            }
        "#;
        let findings = detector.find_unprotected_price_operations(source);
        assert!(
            findings.is_empty(),
            "Internal functions should not trigger TOD findings"
        );
    }

    #[test]
    fn test_view_pure_internal_detection() {
        let detector = TransactionOrderingDependenceDetector::new();

        assert!(
            detector.is_view_pure_or_internal_function(
                "function getPrice() internal view returns (uint256) {"
            ),
            "Should detect internal view function"
        );
        assert!(
            detector.is_view_pure_or_internal_function("function calc() pure returns (uint256) {"),
            "Should detect pure function"
        );
        assert!(
            detector.is_view_pure_or_internal_function(
                "function _helper() private returns (uint256) {"
            ),
            "Should detect private function"
        );
        assert!(
            !detector.is_view_pure_or_internal_function(
                "function doSwap() external returns (uint256) {"
            ),
            "Should NOT flag external function"
        );
        assert!(
            !detector
                .is_view_pure_or_internal_function("function doSwap() public returns (uint256) {"),
            "Should NOT flag public function"
        );
    }

    // ================================================================
    // FP Reduction Tests: Governance Functions
    // ================================================================

    #[test]
    fn test_no_fp_governance_vote() {
        let detector = TransactionOrderingDependenceDetector::new();

        // Governance vote function with deadline checks -- intentional timelock pattern
        let source = r#"
            contract SecureFlashLoan {
                mapping(uint256 => Proposal) public proposals;

                function vote(uint256 proposalId, bool support) external {
                    Proposal storage proposal = proposals[proposalId];
                    require(block.timestamp <= proposal.deadline);
                    require(!proposal.hasVoted[msg.sender]);
                    proposal.hasVoted[msg.sender] = true;
                    if (support) {
                        proposal.forVotes += votingPower[msg.sender];
                    }
                    token.transfer(address(this), votingDeposit);
                }
            }
        "#;
        let findings = detector.find_deadline_patterns(source);
        assert!(
            findings.is_empty(),
            "Governance vote function should not trigger deadline TOD findings, got: {:?}",
            findings
        );
    }

    #[test]
    fn test_no_fp_governance_execute() {
        let detector = TransactionOrderingDependenceDetector::new();

        // Governance execute function with timelock -- intentional pattern
        let source = r#"
            contract SecureFlashLoan {
                mapping(uint256 => Proposal) public proposals;

                function execute(uint256 proposalId) external {
                    Proposal storage proposal = proposals[proposalId];
                    require(block.timestamp >= proposal.deadline + timelock);
                    require(proposal.forVotes > proposal.againstVotes);
                    proposal.executed = true;
                    (bool success,) = proposal.target.call(proposal.data);
                    token.transfer(proposal.proposer, proposal.deposit);
                }
            }
        "#;
        let findings = detector.find_deadline_patterns(source);
        assert!(
            findings.is_empty(),
            "Governance execute function should not trigger deadline TOD findings, got: {:?}",
            findings
        );
    }

    #[test]
    fn test_governance_function_detection() {
        let detector = TransactionOrderingDependenceDetector::new();

        let governance_source =
            "contract Gov { mapping(uint256 => Proposal) proposals; function propose() {} }";

        assert!(
            detector.is_governance_function("vote", governance_source),
            "vote should be recognized as governance function"
        );
        assert!(
            detector.is_governance_function("execute", governance_source),
            "execute should be recognized as governance function"
        );
        assert!(
            detector.is_governance_function("castVote", governance_source),
            "castVote should be recognized as governance function"
        );
        assert!(
            !detector.is_governance_function("vote", "contract Token { function transfer() {} }"),
            "vote in non-governance contract should NOT be recognized"
        );
        assert!(
            !detector.is_governance_function("withdraw", governance_source),
            "withdraw should NOT be recognized as governance function"
        );
    }

    // ================================================================
    // FP Reduction Tests: Price Helpers Without DEX Interaction
    // ================================================================

    #[test]
    fn test_no_fp_price_helper_no_dex_interaction() {
        let detector = TransactionOrderingDependenceDetector::new();

        // Function that reads prices but does not actually swap -- it is a helper
        let source = r#"
            contract PriceOracle {
                function getQuote(address tokenIn, address tokenOut, uint256 amountIn) external returns (uint256) {
                    uint256[] memory amounts = router.getAmountsOut(amountIn, path);
                    return amounts[amounts.length - 1];
                }
            }
        "#;
        let findings = detector.find_unprotected_price_operations(source);
        assert!(
            findings.is_empty(),
            "Price-reading helpers without actual DEX interaction should not be flagged, got: {:?}",
            findings
        );
    }

    // ================================================================
    // True Positive Tests: Ensure genuine vulnerabilities still detected
    // ================================================================

    #[test]
    fn test_tp_deadline_distribution_still_detected() {
        let detector = TransactionOrderingDependenceDetector::new();

        // Genuine deadline-based distribution vulnerability
        let source = r#"
            contract Distribution {
                function claimReward() external {
                    require(block.timestamp >= deadline);
                    uint256 reward = rewardPool / participants.length;
                    token.transfer(msg.sender, reward);
                }
            }
        "#;
        let findings = detector.find_deadline_patterns(source);
        assert!(
            !findings.is_empty(),
            "Genuine deadline-based distribution should still be detected"
        );
    }

    #[test]
    fn test_tp_unprotected_swap_still_detected() {
        let detector = TransactionOrderingDependenceDetector::new();

        // Genuine unprotected swap vulnerability (external function that swaps)
        let source = r#"
            contract VulnerableSwapper {
                function doSwap(uint256 amount) external {
                    router.swap(tokenA, tokenB, amount);
                    token.transfer(msg.sender, received);
                }
            }
        "#;
        let findings = detector.find_unprotected_price_operations(source);
        assert!(
            !findings.is_empty(),
            "Genuine unprotected swap should still be detected"
        );
    }

    #[test]
    fn test_tp_fcfs_pattern_still_detected() {
        let detector = TransactionOrderingDependenceDetector::new();

        let source = r#"
            contract Airdrop {
                function claim() external {
                    require(participants.length < MAX_PARTICIPANTS);
                    require(!claimed[msg.sender]);
                    claimed[msg.sender] = true;
                    reward.transfer(msg.sender, REWARD_AMOUNT);
                }
            }
        "#;
        let findings = detector.find_fcfs_patterns(source);
        assert!(
            !findings.is_empty(),
            "Genuine FCFS pattern should still be detected"
        );
    }
}
