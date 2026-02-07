use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for challenge period bypass vulnerabilities
///
/// Detects patterns where withdrawals or state transitions can bypass
/// the challenge period in optimistic rollups.
pub struct ChallengePeriodBypassDetector {
    base: BaseDetector,
}

impl Default for ChallengePeriodBypassDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ChallengePeriodBypassDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("challenge-period-bypass"),
                "Challenge Period Bypass".to_string(),
                "Detects vulnerabilities allowing premature withdrawals or state \
                 finalization before the challenge period expires."
                    .to_string(),
                vec![DetectorCategory::L2, DetectorCategory::Timestamp],
                Severity::Critical,
            ),
        }
    }

    /// Find premature finalization patterns
    fn find_premature_finalization(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect finalization functions
            if trimmed.contains("function ")
                && (trimmed.contains("finalize")
                    || trimmed.contains("Finalize")
                    || trimmed.contains("completeWithdrawal")
                    || trimmed.contains("proveAndFinalize"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for challenge period validation
                if !func_body.contains("challengePeriod")
                    && !func_body.contains("finalizationPeriod")
                    && !func_body.contains("CHALLENGE_PERIOD")
                    && !func_body.contains("block.timestamp")
                {
                    let issue = "Finalization without challenge period check".to_string();
                    findings.push((line_num as u32 + 1, func_name.clone(), issue));
                }

                // Check for proper time comparison
                if func_body.contains("block.timestamp")
                    && !func_body.contains(">=")
                    && !func_body.contains(">")
                {
                    let issue = "Weak timestamp comparison in finalization".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    /// Check if the contract operates in a bridge, rollup, or optimistic system context.
    /// Challenge periods are only relevant for these types of contracts, not for standard
    /// token vaults, flash loan providers, or simple fund management contracts.
    fn is_bridge_or_rollup_context(&self, contract_name: &str, source: &str) -> bool {
        let name_lower = contract_name.to_lowercase();
        let source_lower = source.to_lowercase();

        // Check contract name for bridge/rollup/optimistic indicators
        let name_indicators = [
            "bridge",
            "rollup",
            "optimistic",
            "dispute",
            "challenge",
            "relay",
            "messenger",
            "portal",
            "l1",
            "l2",
            "crosschain",
            "cross_chain",
        ];
        if name_indicators
            .iter()
            .any(|indicator| name_lower.contains(indicator))
        {
            return true;
        }

        // Check source code for bridge/rollup/optimistic context indicators
        let source_indicators = [
            "stateroot",
            "state_root",
            "fraudproof",
            "fraud_proof",
            "disputegame",
            "dispute_game",
            "challengeperiod",
            "challenge_period",
            "finalizationperiod",
            "finalization_period",
            "l1bridge",
            "l2bridge",
            "crossdomainmessenger",
            "optimismportal",
            "rollupbridge",
            "outputroot",
            "output_root",
        ];
        source_indicators
            .iter()
            .any(|indicator| source_lower.contains(indicator))
    }

    /// Check if a withdrawal function body represents a standard user withdrawal
    /// (e.g., user withdrawing their own funds based on their balance). These
    /// patterns do not require challenge periods.
    fn is_standard_user_withdrawal(&self, func_body: &str) -> bool {
        let body_lower = func_body.to_lowercase();

        // Pattern 1: msg.sender balance check (user withdrawing own funds)
        let has_sender_balance_check = func_body.contains("balances[msg.sender]")
            || func_body.contains("balanceOf[msg.sender]")
            || func_body.contains("_balances[msg.sender]")
            || func_body.contains("balance[msg.sender]")
            || func_body.contains("deposits[msg.sender]")
            || func_body.contains("userBalance[msg.sender]")
            || func_body.contains("shares[msg.sender]");

        // Pattern 2: Standard ERC-20/token withdrawal patterns
        let has_token_withdrawal_pattern = (func_body.contains("msg.sender")
            && (func_body.contains("require(") || func_body.contains("if (")))
            && (func_body.contains(".transfer(") || func_body.contains(".safeTransfer("))
            && !body_lower.contains("finalize")
            && !body_lower.contains("stateroot")
            && !body_lower.contains("outputroot");

        // Pattern 3: Flash loan context indicators
        let is_flash_loan_context = body_lower.contains("flashloan")
            || body_lower.contains("flash_loan")
            || body_lower.contains("flashfee")
            || body_lower.contains("onflashloan")
            || body_lower.contains("ierc3156")
            || body_lower.contains("callback_success");

        has_sender_balance_check || has_token_withdrawal_pattern || is_flash_loan_context
    }

    /// Check if the contract is a flash loan contract based on source-level indicators
    fn is_flash_loan_contract(&self, contract_name: &str, source: &str) -> bool {
        let name_lower = contract_name.to_lowercase();
        let source_lower = source.to_lowercase();

        // Check contract name for flash loan indicators
        let name_indicators = ["flashloan", "flash_loan", "flashmint", "flashlender"];
        if name_indicators
            .iter()
            .any(|indicator| name_lower.contains(indicator))
        {
            return true;
        }

        // Check source for flash loan interface/pattern indicators
        let source_indicators = [
            "ierc3156flashlender",
            "ierc3156flashborrower",
            "onflashloan",
            "flashloan(",
            "flashfee(",
            "maxflashloan(",
            "callback_success",
        ];
        source_indicators
            .iter()
            .any(|indicator| source_lower.contains(indicator))
    }

    /// Find instant withdrawal patterns.
    /// Only flags withdrawals that appear to be in bridge/rollup/optimistic contexts.
    /// Skips standard user fund withdrawals, flash loan contract withdrawals, and
    /// simple balance-based withdrawal patterns.
    fn find_instant_withdrawal_issues(
        &self,
        source: &str,
        contract_name: &str,
    ) -> Vec<(u32, String)> {
        // Only flag instant withdrawals in bridge/rollup/optimistic contexts.
        // Standard contracts (vaults, flash loans, token contracts) do not need
        // challenge periods for their withdraw functions.
        if !self.is_bridge_or_rollup_context(contract_name, source) {
            return Vec::new();
        }

        // Skip flash loan contracts entirely -- their withdrawals are standard operations
        if self.is_flash_loan_contract(contract_name, source) {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect withdrawal initiation and completion in same transaction
            if trimmed.contains("function ")
                && trimmed.contains("withdraw")
                && (trimmed.contains("external") || trimmed.contains("public"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Skip standard user withdrawal patterns
                if self.is_standard_user_withdrawal(&func_body) {
                    continue;
                }

                // Check for immediate transfer after withdrawal request
                if (func_body.contains("transfer(") || func_body.contains("safeTransfer"))
                    && !func_body.contains("pendingWithdrawals")
                    && !func_body.contains("withdrawalQueue")
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find challenge period manipulation vectors
    fn find_period_manipulation(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect modifiable challenge period
            if trimmed.contains("function ")
                && (trimmed.contains("setChallengePeriod")
                    || trimmed.contains("updatePeriod")
                    || trimmed.contains("setFinalizationPeriod"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for minimum period enforcement
                if !func_body.contains("MIN_") && !func_body.contains("minimum") {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }

            // Detect zero challenge period
            if (trimmed.contains("challengePeriod = 0")
                || trimmed.contains("CHALLENGE_PERIOD = 0")
                || trimmed.contains("finalizationPeriod = 0"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    /// Find dispute bypass patterns
    fn find_dispute_bypass(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect state root acceptance without dispute window
            if trimmed.contains("function ")
                && (trimmed.contains("acceptStateRoot") || trimmed.contains("confirmStateRoot"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for dispute window
                if !func_body.contains("disputed")
                    && !func_body.contains("challenged")
                    && !func_body.contains("fraud")
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }

            // Detect emergency bypass mechanisms
            if trimmed.contains("function ")
                && trimmed.contains("emergency")
                && trimmed.contains("finalize")
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
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

impl Detector for ChallengePeriodBypassDetector {
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

        for (line, func_name, issue) in self.find_premature_finalization(source) {
            let message = format!(
                "Function '{}' in contract '{}' has challenge period bypass: {}. \
                 Withdrawals may be finalized before the challenge period expires, \
                 allowing fraudulent transactions to be accepted.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(367)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Enforce challenge period:\n\n\
                     1. Require block.timestamp >= proposalTime + CHALLENGE_PERIOD\n\
                     2. Use strict timestamp comparisons (>=, not >)\n\
                     3. Store proposal timestamp at initiation\n\
                     4. Verify no pending challenges before finalization\n\
                     5. Add minimum challenge period constant (e.g., 7 days)"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_instant_withdrawal_issues(source, &contract_name) {
            let message = format!(
                "Function '{}' in contract '{}' allows instant withdrawals without \
                 queuing. This bypasses the challenge/dispute mechanism.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(367)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Implement withdrawal queue:\n\n\
                     1. Separate withdrawal request from finalization\n\
                     2. Queue withdrawals with timestamp\n\
                     3. Require challenge period before claiming\n\
                     4. Track pending withdrawals per user"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_period_manipulation(source) {
            let message = format!(
                "Function '{}' in contract '{}' allows challenge period manipulation. \
                 Setting period to zero would disable fraud proofs.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(367)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Protect challenge period configuration:\n\n\
                     1. Enforce minimum challenge period (MIN_CHALLENGE_PERIOD)\n\
                     2. Use timelock for period changes\n\
                     3. Require governance approval for changes\n\
                     4. Never allow zero challenge period"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_dispute_bypass(source) {
            let message = format!(
                "Function '{}' in contract '{}' accepts state without dispute verification. \
                 Fraudulent state roots could be finalized without challenge.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(367)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Add dispute verification:\n\n\
                     1. Check for pending disputes before acceptance\n\
                     2. Require dispute resolution before finalization\n\
                     3. Track challenged proposals separately\n\
                     4. Emergency functions should pause, not bypass"
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
    use crate::types::test_utils::*;

    #[test]
    fn test_detector_properties() {
        let detector = ChallengePeriodBypassDetector::new();
        assert_eq!(detector.name(), "Challenge Period Bypass");
        assert_eq!(detector.default_severity(), Severity::Critical);
    }

    // ========================================================================
    // Bridge/Rollup context detection tests
    // ========================================================================

    #[test]
    fn test_is_bridge_or_rollup_context_by_name() {
        let detector = ChallengePeriodBypassDetector::new();

        // Should detect bridge/rollup context from contract name
        assert!(detector.is_bridge_or_rollup_context("L1Bridge", ""));
        assert!(detector.is_bridge_or_rollup_context("OptimisticRollup", ""));
        assert!(detector.is_bridge_or_rollup_context("CrossChainRelay", ""));
        assert!(detector.is_bridge_or_rollup_context("DisputeGame", ""));
        assert!(detector.is_bridge_or_rollup_context("L2Messenger", ""));
        assert!(detector.is_bridge_or_rollup_context("OptimismPortal", ""));

        // Should NOT detect bridge/rollup context from standard contract names
        assert!(!detector.is_bridge_or_rollup_context("VulnerableFlashLoan", ""));
        assert!(!detector.is_bridge_or_rollup_context("FlashLoanArbitrage", ""));
        assert!(!detector.is_bridge_or_rollup_context("SecureFlashLoan", ""));
        assert!(!detector.is_bridge_or_rollup_context("SimpleVault", ""));
        assert!(!detector.is_bridge_or_rollup_context("TokenSwap", ""));
        assert!(!detector.is_bridge_or_rollup_context("TestContract", ""));
    }

    #[test]
    fn test_is_bridge_or_rollup_context_by_source() {
        let detector = ChallengePeriodBypassDetector::new();

        // Should detect from source code indicators
        let bridge_source = r#"
            contract Vault {
                mapping(bytes32 => bool) public stateRoots;
                uint256 public challengePeriod = 7 days;
            }
        "#;
        assert!(detector.is_bridge_or_rollup_context("Vault", bridge_source));

        let rollup_source = r#"
            contract Handler {
                IOptimismPortal public portal;
                function processMessage() external {}
            }
        "#;
        assert!(detector.is_bridge_or_rollup_context("Handler", rollup_source));

        // Should NOT detect from standard vault/flash loan source
        let vault_source = r#"
            contract Vault {
                mapping(address => uint256) public balances;
                function withdraw(uint256 amount) external {
                    require(balances[msg.sender] >= amount);
                    balances[msg.sender] -= amount;
                    payable(msg.sender).transfer(amount);
                }
            }
        "#;
        assert!(!detector.is_bridge_or_rollup_context("Vault", vault_source));
    }

    // ========================================================================
    // Flash loan contract detection tests
    // ========================================================================

    #[test]
    fn test_is_flash_loan_contract() {
        let detector = ChallengePeriodBypassDetector::new();

        // Should detect flash loan contracts by name
        assert!(detector.is_flash_loan_contract("VulnerableFlashLoan", ""));
        assert!(detector.is_flash_loan_contract("FlashLoanArbitrage", ""));
        assert!(detector.is_flash_loan_contract("SecureFlashLoan", ""));

        // Should detect flash loan contracts by source
        let flash_loan_source = r#"
            contract LoanProvider is IERC3156FlashLender {
                function flashLoan(address receiver, address token, uint256 amount, bytes calldata data) external {
                    // ...
                }
            }
        "#;
        assert!(detector.is_flash_loan_contract("LoanProvider", flash_loan_source));

        // Should NOT flag standard contracts
        assert!(!detector.is_flash_loan_contract("SimpleVault", ""));
        assert!(!detector.is_flash_loan_contract("TokenSwap", ""));
    }

    // ========================================================================
    // Standard user withdrawal detection tests
    // ========================================================================

    #[test]
    fn test_is_standard_user_withdrawal() {
        let detector = ChallengePeriodBypassDetector::new();

        // Pattern: msg.sender balance check
        let sender_balance = r#"
            function withdraw(uint256 amount) external {
                require(balances[msg.sender] >= amount);
                balances[msg.sender] -= amount;
                payable(msg.sender).transfer(amount);
            }
        "#;
        assert!(detector.is_standard_user_withdrawal(sender_balance));

        // Pattern: deposits mapping
        let deposits = r#"
            function withdraw(uint256 amount) external {
                require(deposits[msg.sender] >= amount);
                deposits[msg.sender] -= amount;
                token.safeTransfer(msg.sender, amount);
            }
        "#;
        assert!(detector.is_standard_user_withdrawal(deposits));

        // Pattern: flash loan context
        let flash_loan = r#"
            function withdraw(uint256 amount) external {
                // Part of flash loan provider
                uint256 fee = flashFee(token, amount);
                token.safeTransfer(msg.sender, amount);
            }
        "#;
        assert!(detector.is_standard_user_withdrawal(flash_loan));

        // Pattern: standard token withdrawal with require and msg.sender
        let standard_token = r#"
            function withdraw(uint256 amount) external {
                require(amount > 0, "Amount zero");
                if (msg.sender == owner) {
                    token.transfer(msg.sender, amount);
                }
            }
        "#;
        assert!(detector.is_standard_user_withdrawal(standard_token));

        // NOT standard: bridge finalization withdrawal
        let bridge_withdrawal = r#"
            function withdrawFromBridge(bytes32 outputRoot) external {
                require(stateRoots[outputRoot], "Invalid root");
                token.transfer(recipient, amount);
            }
        "#;
        assert!(!detector.is_standard_user_withdrawal(bridge_withdrawal));
    }

    // ========================================================================
    // False positive regression tests (the 5 FPs from the issue)
    // ========================================================================

    #[test]
    fn test_no_fp_flash_loan_withdraw() {
        let detector = ChallengePeriodBypassDetector::new();

        // Simulates VulnerableFlashLoan.sol:168 withdraw
        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;
            contract VulnerableFlashLoan {
                mapping(address => uint256) public balances;
                function withdraw(uint256 amount) external {
                    require(balances[msg.sender] >= amount, "Insufficient balance");
                    balances[msg.sender] -= amount;
                    payable(msg.sender).transfer(amount);
                }
            }
        "#;

        let results = detector.find_instant_withdrawal_issues(source, "VulnerableFlashLoan");
        assert!(
            results.is_empty(),
            "Should NOT flag standard withdraw in flash loan contract, got: {:?}",
            results
        );
    }

    #[test]
    fn test_no_fp_flash_loan_arbitrage_withdraw_profits() {
        let detector = ChallengePeriodBypassDetector::new();

        // Simulates FlashLoanArbitrage.sol:213 withdrawProfits
        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;
            contract FlashLoanArbitrage {
                mapping(address => uint256) public balances;
                function withdrawProfits() external {
                    uint256 amount = balances[msg.sender];
                    require(amount > 0, "No profits");
                    balances[msg.sender] = 0;
                    payable(msg.sender).transfer(amount);
                }
            }
        "#;

        let results = detector.find_instant_withdrawal_issues(source, "FlashLoanArbitrage");
        assert!(
            results.is_empty(),
            "Should NOT flag withdrawProfits in flash loan arbitrage contract, got: {:?}",
            results
        );
    }

    #[test]
    fn test_no_fp_secure_flash_loan_withdraw() {
        let detector = ChallengePeriodBypassDetector::new();

        // Simulates SecureFlashLoan.sol:249 withdraw
        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;
            contract SecureFlashLoan is IERC3156FlashLender {
                mapping(address => uint256) public deposits;
                function withdraw(uint256 amount) external {
                    require(deposits[msg.sender] >= amount);
                    deposits[msg.sender] -= amount;
                    token.safeTransfer(msg.sender, amount);
                }
            }
        "#;

        let results = detector.find_instant_withdrawal_issues(source, "SecureFlashLoan");
        assert!(
            results.is_empty(),
            "Should NOT flag withdraw in SecureFlashLoan, got: {:?}",
            results
        );
    }

    #[test]
    fn test_no_fp_access_control_withdraw() {
        let detector = ChallengePeriodBypassDetector::new();

        // Simulates access_control_issues.sol:23 withdraw
        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;
            contract AccessControlIssues {
                mapping(address => uint256) public balances;
                function withdraw(uint256 amount) external {
                    require(balances[msg.sender] >= amount, "Insufficient");
                    balances[msg.sender] -= amount;
                    payable(msg.sender).transfer(amount);
                }
            }
        "#;

        let results = detector.find_instant_withdrawal_issues(source, "AccessControlIssues");
        assert!(
            results.is_empty(),
            "Should NOT flag standard withdraw in access control contract, got: {:?}",
            results
        );
    }

    #[test]
    fn test_no_fp_reentrancy_issues_withdraw() {
        let detector = ChallengePeriodBypassDetector::new();

        // Simulates reentrancy_issues.sol:28 withdrawBasedOnBalance
        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;
            contract ReentrancyIssues {
                mapping(address => uint256) public balance;
                function withdrawBasedOnBalance() external {
                    uint256 amount = balance[msg.sender];
                    require(amount > 0, "No balance");
                    balance[msg.sender] = 0;
                    payable(msg.sender).transfer(amount);
                }
            }
        "#;

        let results = detector.find_instant_withdrawal_issues(source, "ReentrancyIssues");
        assert!(
            results.is_empty(),
            "Should NOT flag withdrawBasedOnBalance in reentrancy issues contract, got: {:?}",
            results
        );
    }

    // ========================================================================
    // True positive tests -- bridge/rollup contracts SHOULD be flagged
    // ========================================================================

    #[test]
    fn test_tp_bridge_instant_withdrawal_flagged() {
        let detector = ChallengePeriodBypassDetector::new();

        // A bridge contract with an instant withdrawal SHOULD be flagged
        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;
            contract L1Bridge {
                mapping(bytes32 => bool) public stateRoots;
                function withdrawFromL2(bytes32 proof, address recipient, uint256 amount) external {
                    require(stateRoots[proof], "Invalid proof");
                    payable(recipient).transfer(amount);
                }
            }
        "#;

        let results = detector.find_instant_withdrawal_issues(source, "L1Bridge");
        assert!(
            !results.is_empty(),
            "Should flag instant withdrawal in bridge contract"
        );
    }

    #[test]
    fn test_tp_optimistic_rollup_instant_withdrawal_flagged() {
        let detector = ChallengePeriodBypassDetector::new();

        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;
            contract OptimisticRollup {
                function withdrawFunds(address recipient, uint256 amount) external {
                    // Missing challenge period check
                    payable(recipient).transfer(amount);
                }
            }
        "#;

        let results = detector.find_instant_withdrawal_issues(source, "OptimisticRollup");
        assert!(
            !results.is_empty(),
            "Should flag instant withdrawal in optimistic rollup contract"
        );
    }

    #[test]
    fn test_tp_rollup_context_from_source_indicators() {
        let detector = ChallengePeriodBypassDetector::new();

        // Contract with rollup indicators in source but not in name
        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;
            contract WithdrawalHandler {
                mapping(bytes32 => bool) public stateRoots;
                uint256 public challengePeriod;
                function withdrawFromOutput(address recipient, uint256 amount) external {
                    payable(recipient).transfer(amount);
                }
            }
        "#;

        let results = detector.find_instant_withdrawal_issues(source, "WithdrawalHandler");
        assert!(
            !results.is_empty(),
            "Should flag instant withdrawal when source has rollup indicators"
        );
    }

    // ========================================================================
    // Integration test with detect() via create_test_context
    // ========================================================================

    #[test]
    fn test_detect_no_fp_on_standard_withdraw() {
        let detector = ChallengePeriodBypassDetector::new();

        // Standard vault contract -- should produce no instant-withdrawal findings
        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;
            contract TestContract {
                mapping(address => uint256) public balances;
                function withdraw(uint256 amount) external {
                    require(balances[msg.sender] >= amount, "Insufficient balance");
                    balances[msg.sender] -= amount;
                    payable(msg.sender).transfer(amount);
                }
            }
        "#;

        let ctx = create_test_context(source);
        let results = detector.detect(&ctx).unwrap();

        // Filter for instant withdrawal findings specifically
        let instant_withdrawal_findings: Vec<&Finding> = results
            .iter()
            .filter(|f| f.message.contains("instant withdrawals"))
            .collect();

        assert!(
            instant_withdrawal_findings.is_empty(),
            "Standard withdraw should not trigger challenge period bypass finding, got: {:?}",
            instant_withdrawal_findings
                .iter()
                .map(|f| &f.message)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_bridge_context_not_skipped_for_other_checks() {
        let detector = ChallengePeriodBypassDetector::new();

        // Verify that non-bridge contracts still get checked for finalization issues
        // (find_premature_finalization, find_period_manipulation, find_dispute_bypass
        // are NOT gated by bridge context check)
        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;
            contract TestContract {
                function finalize() external {
                    // No challenge period check, no timestamp
                    settled = true;
                }
            }
        "#;

        let ctx = create_test_context(source);
        let results = detector.detect(&ctx).unwrap();

        let finalization_findings: Vec<&Finding> = results
            .iter()
            .filter(|f| f.message.contains("challenge period bypass"))
            .collect();

        assert!(
            !finalization_findings.is_empty(),
            "Finalization without challenge period should still be flagged"
        );
    }
}
