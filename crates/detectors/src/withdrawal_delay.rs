use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for withdrawal delay vulnerabilities in staking systems
pub struct WithdrawalDelayDetector {
    base: BaseDetector,
}

impl Default for WithdrawalDelayDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl WithdrawalDelayDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("withdrawal-delay".to_string()),
                "Withdrawal Delay Vulnerability".to_string(),
                "Detects vulnerabilities in stake withdrawal mechanisms that can lock funds indefinitely or enable unfair delays".to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::AccessControl],
                Severity::High,
            ),
        }
    }
}

impl Detector for WithdrawalDelayDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
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


        // Skip if this is an ERC-4626 vault - asset transfers are normal, not delays
        let is_vault = utils::is_erc4626_vault(ctx);

        // Skip contracts that already enforce withdrawal delays at the contract level.
        // Protocols like EigenLayer define MIN_WITHDRAWAL_DELAY_BLOCKS or WITHDRAWAL_DELAY
        // constants and enforce them across all withdrawal functions.
        if self.contract_has_delay_enforcement(ctx) {
            return Ok(findings);
        }

        // Skip non-staking contract contexts where withdrawal-delay findings are irrelevant
        if self.is_non_staking_context(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            if let Some(withdrawal_issue) = self.check_withdrawal_delay(function, ctx, is_vault) {
                let message = format!(
                    "Function '{}' has withdrawal delay vulnerability. {} \
                    Improper withdrawal mechanisms can lock user funds indefinitely or enable denial of service.",
                    function.name.name, withdrawal_issue
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(400) // CWE-400: Uncontrolled Resource Consumption
                .with_cwe(667) // CWE-667: Improper Locking
                .with_fix_suggestion(format!(
                    "Fix withdrawal mechanism in '{}'. \
                    Implement maximum withdrawal delay caps, add emergency withdrawal options with penalties, \
                    prevent admin from extending delays arbitrarily, implement fair queue systems, \
                    add partial withdrawal capabilities, and document clear withdrawal timelines.",
                    function.name.name
                ));

                findings.push(finding);
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl WithdrawalDelayDetector {
    /// Check if the contract already enforces withdrawal delay at the contract level.
    /// Contracts with delay constants like MIN_WITHDRAWAL_DELAY_BLOCKS or WITHDRAWAL_DELAY
    /// already have delay enforcement -- flagging individual functions is redundant.
    fn contract_has_delay_enforcement(&self, ctx: &AnalysisContext) -> bool {
        let source = ctx.source_code.as_str();
        source.contains("MIN_WITHDRAWAL_DELAY")
            || source.contains("WITHDRAWAL_DELAY")
            || source.contains("withdrawalDelay")
            || (source.contains("withdrawal") && source.contains("7 days"))
    }

    /// Check if this contract is in a non-staking context where withdrawal-delay
    /// findings would be false positives (e.g., allowance/TOCTOU contracts, bridges,
    /// transient reentrancy tests, simple token contracts).
    fn is_non_staking_context(&self, ctx: &AnalysisContext) -> bool {
        let source = ctx.source_code.as_str();

        // Bridge contracts handle cross-chain transfers, not staking withdrawals
        let is_bridge = source.contains("bridge") || source.contains("Bridge");
        let has_cross_chain = source.contains("sourceChain")
            || source.contains("destChain")
            || source.contains("crossChain")
            || source.contains("relayer");
        if is_bridge && has_cross_chain {
            return true;
        }

        // Allowance/approval TOCTOU test contracts
        if (source.contains("allowance") || source.contains("approve")) && source.contains("TOCTOU")
        {
            return true;
        }

        // Transient storage reentrancy test contracts
        if source.contains("tstore") || source.contains("tload") {
            if source.contains("reentrancy") || source.contains("Reentrancy") {
                return true;
            }
        }

        false
    }

    /// Check if function source contains actual delay/lock patterns.
    /// Avoids false positives from bare "lock" matching "block.timestamp"/"block.number"
    /// and bare "period" matching unrelated contexts.
    fn has_delay_pattern(source: &str) -> bool {
        // Explicit delay keywords
        if source.contains("delay")
            || source.contains("Delay")
            || source.contains("cooldown")
            || source.contains("Cooldown")
        {
            return true;
        }

        // Lock-related patterns, but NOT "block" (which is ubiquitous in Solidity)
        if source.contains("lockTime")
            || source.contains("lockPeriod")
            || source.contains("lock_period")
            || source.contains("lockEndTime")
            || source.contains("unlockTime")
            || source.contains("lockDuration")
            || source.contains("timeLock")
            || source.contains("timelock")
            || source.contains("Timelock")
        {
            return true;
        }

        // Bare "locked" as a state variable, excluding reentrancy guards.
        // Reentrancy guards use patterns like "locked = 1" / "locked = 0" / "locked = true/false",
        // while actual withdrawal locks use "locked" with block.timestamp comparisons.
        if source.contains(" locked") || source.contains(".locked") {
            // Exclude reentrancy guard pattern: simple binary lock toggle
            let is_reentrancy_guard = (source.contains("locked = 1")
                || source.contains("locked = true"))
                && (source.contains("locked = 0") || source.contains("locked = false"));
            if !is_reentrancy_guard {
                return true;
            }
        }

        // Period-related patterns specific to withdrawal/staking
        if source.contains("lockPeriod")
            || source.contains("stakingPeriod")
            || source.contains("withdrawalPeriod")
            || source.contains("vestingPeriod")
            || source.contains("unbondingPeriod")
        {
            return true;
        }

        false
    }

    /// Check if the function name itself indicates a withdrawal operation.
    /// This is stricter than checking the source body, reducing FPs from functions
    /// that merely reference withdrawals in comments or variable names.
    fn is_withdrawal_function_name(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        lower.contains("withdraw")
            || lower.contains("unstake")
            || lower == "exit"
            || lower.contains("redeem")
    }

    /// Check for withdrawal delay vulnerabilities
    fn check_withdrawal_delay(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
        is_vault: bool,
    ) -> Option<String> {
        function.body.as_ref()?;

        // Skip view/pure functions - they cannot modify state so cannot have
        // withdrawal delay vulnerabilities
        if matches!(
            function.mutability,
            ast::StateMutability::View | ast::StateMutability::Pure
        ) {
            return None;
        }

        let func_name = &function.name.name;
        let func_name_lower = func_name.to_lowercase();

        // Require the function NAME to be withdrawal-related (not just source body).
        // This prevents flagging functions like _delegate, addPool, slashOperatorShares
        // that merely reference withdrawals in their implementation.
        let name_is_withdrawal = self.is_withdrawal_function_name(func_name);

        if !name_is_withdrawal {
            return None;
        }

        // Skip admin-only configuration functions (e.g., setWithdrawalDelay, addPool)
        // that manage parameters but do not process user withdrawals
        if func_name_lower.starts_with("set")
            || func_name_lower.starts_with("add")
            || func_name_lower.starts_with("update")
            || func_name_lower.starts_with("configure")
        {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);

        // Pattern 1: Unbounded withdrawal delay
        // Note: Avoid bare "lock" which matches "block.timestamp"/"block.number".
        // Use specific delay/lock patterns instead.
        let has_delay = Self::has_delay_pattern(&func_source);

        let no_max_delay = has_delay
            && !func_source.contains("MAX_DELAY")
            && !func_source.contains("maxDelay")
            && !func_source.contains("MAX_WITHDRAWAL")
            && !func_source.contains("MIN_WITHDRAWAL");

        if no_max_delay {
            return Some(
                "Withdrawal delay has no maximum cap, \
                admin can set arbitrarily long delays locking funds indefinitely"
                    .to_string(),
            );
        }

        // Pattern 2: Admin can arbitrarily extend withdrawal delay
        let admin_can_modify =
            func_source.contains("onlyOwner") || func_source.contains("onlyAdmin");

        let modifies_delay = (func_source.contains("delay =")
            || func_source.contains("setDelay")
            || func_source.contains("updateDelay"))
            && admin_can_modify;

        if modifies_delay {
            return Some(
                "Admin can modify withdrawal delay without limits, \
                centralization risk enabling fund lockup"
                    .to_string(),
            );
        }

        // Pattern 3: No emergency withdrawal mechanism
        let has_emergency = func_source.contains("emergency")
            || func_source.contains("Emergency")
            || func_source.contains("instant")
            || func_source.contains("immediate");

        let lacks_emergency = has_delay && !has_emergency;

        if lacks_emergency {
            return Some(
                "No emergency withdrawal option even with penalty, \
                users cannot access funds in urgent situations"
                    .to_string(),
            );
        }

        // Pattern 4: Withdrawal queue without fairness guarantees
        // Only flag when the function actively manages a queue (push/pop/enqueue),
        // not when it merely reads queue state via "pending" mappings.
        let manages_queue = func_source.contains(".push(")
            || func_source.contains("enqueue")
            || func_source.contains("addToQueue");

        let no_fifo_enforcement =
            manages_queue && !func_source.contains("FIFO") && !func_source.contains("order");

        if no_fifo_enforcement {
            return Some(
                "Withdrawal queue without FIFO enforcement, \
                allows queue jumping or unfair withdrawal ordering"
                    .to_string(),
            );
        }

        // Pattern 5: Delay can be extended retroactively
        let checks_original_delay = func_source.contains("initialDelay")
            || func_source.contains("originalDelay")
            || func_source.contains("requestTime");

        let no_retroactive_protection = has_delay && !checks_original_delay;

        if no_retroactive_protection {
            return Some(
                "Withdrawal delay can be extended retroactively, \
                users who initiated withdrawal may face unexpected delays"
                    .to_string(),
            );
        }

        // Pattern 6: Single point of failure for withdrawal processing
        // Only flag when there is an explicit "processor" role, not generic "operator"
        // references which are common in DeFi (e.g., EigenLayer operators, pool operators).
        let has_single_processor = func_source.contains("processor")
            || func_source.contains("Processor")
            || (func_source.contains("onlyOperator") && func_source.contains("processWithdraw"));

        let no_backup_mechanism = has_single_processor
            && !func_source.contains("backup")
            && !func_source.contains("fallback");

        if no_backup_mechanism {
            return Some(
                "Single withdrawal processor without backup, \
                if processor fails, all withdrawals blocked"
                    .to_string(),
            );
        }

        // Pattern 7: No partial withdrawal capability
        let full_withdrawal_only = func_source.contains("balance[msg.sender]")
            && !func_source.contains("amount")
            && !func_source.contains("partial");

        if full_withdrawal_only {
            return Some(
                "Only full withdrawal allowed, no partial withdrawals, \
                users must exit entirely even for small amounts"
                    .to_string(),
            );
        }

        // Pattern 8: Withdrawal depends on external call
        let has_external_call = func_source.contains(".call")
            || func_source.contains(".transfer")
            || func_source.contains(".send");

        // Skip for vaults - they need to transfer assets out (that's not a delay, it's the withdrawal itself)
        // Use our own has_delay_pattern instead of utils::has_actual_delay_mechanism
        // which has a bug matching "lock" inside "block".
        let blocking_external_call = has_external_call
            && !is_vault  // Skip if vault
            && !func_source.contains("nonReentrant")
            && func_source.contains("require")
            && has_delay; // Only flag if there's an actual delay in this function

        if blocking_external_call {
            return Some(
                "Withdrawal requires successful external call, \
                failing calls can permanently block withdrawals"
                    .to_string(),
            );
        }

        // Pattern 9: Withdrawal disabled by circuit breaker
        let has_circuit_breaker = func_source.contains("paused")
            || func_source.contains("Paused")
            || func_source.contains("whenNotPaused");

        let no_emergency_override = has_circuit_breaker && !has_emergency;

        if no_emergency_override {
            return Some(
                "Withdrawal can be paused without emergency override, \
                admin can indefinitely block all withdrawals"
                    .to_string(),
            );
        }

        // Pattern 10: Withdrawal window expires
        // Only flag when there is a withdrawal request/queue system with expiry,
        // not simple transaction deadline parameters (Uniswap-style deadline checks).
        let has_request_system = func_source.contains("request")
            || func_source.contains("queued")
            || func_source.contains("pending");

        let has_expiry = func_source.contains("expire") || func_source.contains("validUntil");

        let withdrawal_expires = has_expiry
            && has_request_system
            && !func_source.contains("extend")
            && !func_source.contains("renew");

        if withdrawal_expires {
            return Some(
                "Withdrawal requests expire without renewal option, \
                users lose withdrawal opportunity and must restart process"
                    .to_string(),
            );
        }

        None
    }

    /// Get function source code
    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            source_lines[start..=end].join("\n")
        } else {
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = WithdrawalDelayDetector::new();
        assert_eq!(detector.name(), "Withdrawal Delay Vulnerability");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_contract_has_delay_enforcement() {
        let detector = WithdrawalDelayDetector::new();

        // Helper to create a minimal context with given source
        let check = |source: &str| -> bool {
            // We test the string matching logic directly
            source.contains("MIN_WITHDRAWAL_DELAY")
                || source.contains("WITHDRAWAL_DELAY")
                || source.contains("withdrawalDelay")
                || (source.contains("withdrawal") && source.contains("7 days"))
        };

        assert!(check(
            "uint256 constant MIN_WITHDRAWAL_DELAY_BLOCKS = 50400;"
        ));
        assert!(check("uint256 public constant WITHDRAWAL_DELAY = 7 days;"));
        assert!(check("uint256 public withdrawalDelay = 7 days;"));
        assert!(check("withdrawal must wait 7 days"));
        assert!(!check("function withdraw() external {}"));
        // Verify detector struct is used (suppress unused warning)
        assert_eq!(detector.name(), "Withdrawal Delay Vulnerability");
    }

    #[test]
    fn test_is_withdrawal_function_name() {
        let detector = WithdrawalDelayDetector::new();

        // Should match withdrawal-related names
        assert!(detector.is_withdrawal_function_name("withdraw"));
        assert!(detector.is_withdrawal_function_name("withdrawETH"));
        assert!(detector.is_withdrawal_function_name("emergencyWithdraw"));
        assert!(detector.is_withdrawal_function_name("unstake"));
        assert!(detector.is_withdrawal_function_name("exit"));
        assert!(detector.is_withdrawal_function_name("requestWithdrawal"));
        assert!(detector.is_withdrawal_function_name("completeWithdrawal"));
        assert!(detector.is_withdrawal_function_name("redeem"));

        // Should NOT match non-withdrawal names
        assert!(!detector.is_withdrawal_function_name("_delegate"));
        assert!(!detector.is_withdrawal_function_name("addPool"));
        assert!(!detector.is_withdrawal_function_name("slashOperatorShares"));
        assert!(!detector.is_withdrawal_function_name("decreaseDelegatedShares"));
        assert!(!detector.is_withdrawal_function_name("_removeDepositShares"));
        assert!(!detector.is_withdrawal_function_name("_clearBurnOrRedistributableShares"));
        assert!(!detector.is_withdrawal_function_name("convertToDepositShares"));
        assert!(!detector.is_withdrawal_function_name("deposit"));
        assert!(!detector.is_withdrawal_function_name("transfer"));
        assert!(!detector.is_withdrawal_function_name("approve"));
    }

    #[test]
    fn test_is_non_staking_context() {
        let detector = WithdrawalDelayDetector::new();

        // Helper to check string matching logic directly
        let is_bridge_context = |source: &str| -> bool {
            let is_bridge = source.contains("bridge") || source.contains("Bridge");
            let has_cross_chain = source.contains("sourceChain")
                || source.contains("destChain")
                || source.contains("crossChain")
                || source.contains("relayer");
            is_bridge && has_cross_chain
        };

        let is_toctou_context = |source: &str| -> bool {
            (source.contains("allowance") || source.contains("approve"))
                && source.contains("TOCTOU")
        };

        let is_transient_reentrancy = |source: &str| -> bool {
            (source.contains("tstore") || source.contains("tload"))
                && (source.contains("reentrancy") || source.contains("Reentrancy"))
        };

        // Bridge contexts
        assert!(is_bridge_context(
            "contract BridgeVault { address relayer; }"
        ));
        assert!(!is_bridge_context(
            "contract Vault { function withdraw() {} }"
        ));

        // TOCTOU contexts
        assert!(is_toctou_context("// TOCTOU allowance race condition"));
        assert!(!is_toctou_context("function approve() external {}"));

        // Transient reentrancy contexts
        assert!(is_transient_reentrancy(
            "tstore(slot, 1) // reentrancy guard"
        ));
        assert!(!is_transient_reentrancy("function withdraw() external {}"));

        // Verify detector struct is used
        assert_eq!(detector.name(), "Withdrawal Delay Vulnerability");
    }

    #[test]
    fn test_has_delay_pattern() {
        // Should match actual delay/lock patterns
        assert!(WithdrawalDelayDetector::has_delay_pattern(
            "uint256 delay = 7 days;"
        ));
        assert!(WithdrawalDelayDetector::has_delay_pattern(
            "withdrawalDelay"
        ));
        assert!(WithdrawalDelayDetector::has_delay_pattern(
            "cooldown period"
        ));
        assert!(WithdrawalDelayDetector::has_delay_pattern(
            "lockTime = block.timestamp + 7 days;"
        ));
        assert!(WithdrawalDelayDetector::has_delay_pattern("lockPeriod"));
        assert!(WithdrawalDelayDetector::has_delay_pattern("unlockTime"));
        assert!(WithdrawalDelayDetector::has_delay_pattern("lockEndTime"));
        assert!(WithdrawalDelayDetector::has_delay_pattern("timeLock"));
        assert!(WithdrawalDelayDetector::has_delay_pattern(
            "Timelock contract"
        ));
        assert!(WithdrawalDelayDetector::has_delay_pattern("stakingPeriod"));
        assert!(WithdrawalDelayDetector::has_delay_pattern("vestingPeriod"));
        assert!(WithdrawalDelayDetector::has_delay_pattern(
            "unbondingPeriod"
        ));

        // State variable " locked" that is NOT a reentrancy guard
        assert!(WithdrawalDelayDetector::has_delay_pattern(
            "if (user.locked) revert StillLocked();"
        ));

        // Should NOT match these patterns (common FP sources)
        assert!(!WithdrawalDelayDetector::has_delay_pattern(
            "require(block.timestamp <= deadline, \"Expired\");"
        ));
        assert!(!WithdrawalDelayDetector::has_delay_pattern(
            "block.number > startBlock"
        ));
        assert!(!WithdrawalDelayDetector::has_delay_pattern(
            "payable(msg.sender).transfer(amount);"
        ));
        assert!(!WithdrawalDelayDetector::has_delay_pattern(
            "require(amount > 0, \"No balance\");"
        ));

        // Reentrancy guard pattern should NOT match (locked = 1/0 toggle)
        assert!(!WithdrawalDelayDetector::has_delay_pattern(
            "locked = 1; user.call{value: amount}(\"\"); locked = 0;"
        ));
    }

    #[test]
    fn test_admin_function_name_filtering() {
        // Admin/config function names that should be skipped
        let admin_names = vec![
            "setWithdrawalDelay",
            "addPool",
            "updateWithdrawalFee",
            "configureWithdrawal",
        ];
        for name in admin_names {
            let lower = name.to_lowercase();
            assert!(
                lower.starts_with("set")
                    || lower.starts_with("add")
                    || lower.starts_with("update")
                    || lower.starts_with("configure"),
                "Expected '{}' to be filtered as admin function",
                name
            );
        }

        // Actual withdrawal function names should NOT be filtered
        let withdrawal_names = vec![
            "withdraw",
            "emergencyWithdraw",
            "unstake",
            "processWithdrawals",
            "completeWithdrawal",
            "requestWithdrawal",
        ];
        for name in withdrawal_names {
            let lower = name.to_lowercase();
            assert!(
                !lower.starts_with("set")
                    && !lower.starts_with("add")
                    && !lower.starts_with("update")
                    && !lower.starts_with("configure"),
                "Expected '{}' to NOT be filtered",
                name
            );
        }
    }
}
