//! Restaking Withdrawal Delays Detector
//!
//! Detects missing withdrawal delay enforcement, queue manipulation, and liquidity lock
//! vulnerabilities in restaking protocols. EigenLayer requires 7-day delay; protocols that
//! bypass this or fail to maintain liquidity expose users to forced liquidations.
//!
//! Severity: HIGH
//! Category: DeFi, Restaking
//!
//! Real-World Incident:
//! - Renzo ezETH Depeg (April 2024) - $65M+ in liquidations
//!   "Lack of support for withdrawals from the protocol, resulting in liquidations for
//!    positions in derivative markets, leading to over $50 million in losses"
//!
//! Vulnerabilities Detected:
//! 1. Instant withdrawals (bypassing 7-day delay)
//! 2. No withdrawal queue system
//! 3. No liquidity reserve (100% restaked)
//! 4. Withdrawal delay not propagated to users

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::restaking::classification::*;
use crate::safe_patterns::vault_patterns;
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use ast;

pub struct RestakingWithdrawalDelaysDetector {
    base: BaseDetector,
}

impl RestakingWithdrawalDelaysDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("restaking-withdrawal-delays".to_string()),
                "Restaking Withdrawal Delays Not Enforced".to_string(),
                "Detects missing withdrawal delay enforcement, queue manipulation, and liquidity lock vulnerabilities".to_string(),
                vec![DetectorCategory::DeFi],
                Severity::High,
            ),
        }
    }

    // ========================================================================
    // FP Reduction: Context-Aware Helpers
    // ========================================================================

    /// Returns true if the function is view, pure, internal, or private.
    /// These functions cannot process actual withdrawals so flagging them is an FP.
    fn is_non_mutating_or_non_public(function: &ast::Function) -> bool {
        matches!(
            function.mutability,
            ast::StateMutability::View | ast::StateMutability::Pure
        ) || matches!(
            function.visibility,
            ast::Visibility::Internal | ast::Visibility::Private
        )
    }

    /// Returns true if the function has admin/owner-only modifiers.
    /// Admin-only withdrawal functions are configuration or emergency functions,
    /// not user-facing withdrawal paths that need delay enforcement.
    fn is_admin_only_function(function: &ast::Function, ctx: &AnalysisContext) -> bool {
        // Check modifiers on the AST for owner/admin/role guards
        let admin_modifier_names = [
            "onlyowner",
            "onlyadmin",
            "onlyrole",
            "onlygovernance",
            "onlyguardian",
            "onlymultisig",
            "onlyoperator",
            "onlymanager",
            "onlyauthorized",
        ];

        for modifier in function.modifiers.iter() {
            let mod_name_lower = modifier.name.name.to_lowercase();
            if admin_modifier_names
                .iter()
                .any(|&admin| mod_name_lower.contains(admin))
            {
                return true;
            }
        }

        // Also check function source for inline admin checks
        let func_source = get_function_source(function, ctx).to_lowercase();
        func_source.contains("require(msg.sender == owner")
            || func_source.contains("require(msg.sender == admin")
            || func_source.contains("require(msg.sender == governance")
            || func_source.contains("_checkowner()")
            || func_source.contains("_checkrole(")
    }

    /// Returns true if the contract delegates to a separate withdrawal queue contract.
    /// Contracts that use an external queue (e.g., IWithdrawalQueue, withdrawalQueue)
    /// handle delays in the queue contract, so flagging the wrapper is an FP.
    fn uses_external_withdrawal_queue(ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Interface references to external withdrawal queue
        source.contains("IWithdrawalQueue")
            || source.contains("WithdrawalQueue")
            || source_lower.contains("withdrawalqueue")
            || source_lower.contains("withdrawal_queue")
            // Delegation to external queue contract storage variable
            || source_lower.contains("withdrawqueue")
            || source_lower.contains("withdrawrouter")
            // EigenLayer-specific queue delegation
            || source.contains("IDelayedWithdrawalRouter")
            || source.contains("delayedWithdrawalRouter")
    }

    /// Returns true if the contract already has delay enforcement at the contract level.
    /// This includes delay constants, timelock patterns, and block-based delay checks.
    fn has_contract_level_delay_enforcement(ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Delay constants
        source.contains("WITHDRAWAL_DELAY")
            || source.contains("withdrawalDelay")
            || source.contains("WITHDRAWAL_PERIOD")
            || source.contains("MIN_WITHDRAWAL_DELAY")
            || source.contains("MIN_WITHDRAWAL_DELAY_BLOCKS")
            // Timelock patterns
            || source_lower.contains("timelock")
            || source_lower.contains("timelockcontroller")
            // Explicit 7-day delay references
            || (source_lower.contains("withdrawal") && source.contains("7 days"))
            // Block-based delay enforcement (EigenLayer uses block-based delays)
            || (source_lower.contains("withdrawal") && source.contains("minDelayBlocks"))
            // Unbonding period (common in staking protocols)
            || source.contains("unbondingPeriod")
            || source.contains("UNBONDING_PERIOD")
            || source.contains("cooldownPeriod")
            || source.contains("COOLDOWN_PERIOD")
    }

    /// Returns true if the contract uses EigenLayer-style withdrawal patterns.
    /// EigenLayer uses queueWithdrawals/completeQueuedWithdrawals with built-in
    /// delay enforcement, so contracts delegating to these are safe.
    fn has_eigenlayer_withdrawal_pattern(ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;

        // EigenLayer queue withdrawal pattern
        (source.contains("queueWithdrawal") || source.contains("queueWithdrawals"))
            && (source.contains("completeQueuedWithdrawal")
                || source.contains("completeQueuedWithdrawals"))
    }

    /// Returns true if the contract has timestamp-based delay checks in any function.
    /// Patterns: require(block.timestamp >= ...), block.timestamp > ... + delay
    fn has_timestamp_delay_check(ctx: &AnalysisContext) -> bool {
        let source_lower = ctx.source_code.to_lowercase();

        // Look for timestamp comparison patterns that enforce delays
        (source_lower.contains("block.timestamp >=") || source_lower.contains("block.timestamp >"))
            && (source_lower.contains("requesttime")
                || source_lower.contains("request_time")
                || source_lower.contains("withdrawaltime")
                || source_lower.contains("withdrawal_time")
                || source_lower.contains("queuedtime")
                || source_lower.contains("queued_time")
                || source_lower.contains("submittedtime")
                || source_lower.contains("+ delay")
                || source_lower.contains("+ withdrawal")
                || source_lower.contains("+ cooldown")
                || source_lower.contains("+ unbonding"))
    }

    /// Returns true if the contract is a non-staking context where withdrawal delay
    /// findings would be false positives (simple token, bridge, governance, etc.)
    fn is_non_restaking_withdrawal_context(ctx: &AnalysisContext) -> bool {
        let source_lower = ctx.source_code.to_lowercase();

        // Simple ERC-20 token contracts that happen to match restaking keywords in comments
        let is_simple_token = source_lower.contains("erc20")
            && !source_lower.contains("restaking")
            && !source_lower.contains("eigenlayer")
            && !source_lower.contains("staking");

        if is_simple_token {
            return true;
        }

        // Governance contracts with withdraw functions (not restaking)
        let is_governance = source_lower.contains("governance")
            && source_lower.contains("proposal")
            && source_lower.contains("vote");

        if is_governance {
            return true;
        }

        // Test/mock contracts
        let is_test = source_lower.contains("contract mock")
            || source_lower.contains("contract test")
            || source_lower.contains("// spdx-license-identifier") && source_lower.contains("test");

        if is_test && !source_lower.contains("restaking") && !source_lower.contains("eigenlayer") {
            return true;
        }

        false
    }

    /// Checks if a withdrawal function name indicates a "complete" or "claim" step
    /// in a two-step pattern, which inherently implies delay is enforced at request time.
    fn is_completion_step_function(func_name_lower: &str) -> bool {
        func_name_lower.contains("complete")
            || func_name_lower.contains("claim")
            || func_name_lower.contains("finalize")
            || func_name_lower.contains("execute")
            || func_name_lower.contains("process")
    }

    // ========================================================================
    // Core Detection Methods
    // ========================================================================

    /// Checks withdrawal functions for delay enforcement
    fn check_withdrawal_delay(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // FP Reduction: Skip non-mutating or non-public functions
        if Self::is_non_mutating_or_non_public(function) {
            return findings;
        }

        // FP Reduction: Skip admin-only functions
        if Self::is_admin_only_function(function, ctx) {
            return findings;
        }

        let func_name_lower = function.name.name.to_lowercase();

        // Only check withdrawal/redeem/unstake functions
        if !func_name_lower.contains("withdraw")
            && !func_name_lower.contains("redeem")
            && !func_name_lower.contains("unstake")
        {
            return findings;
        }

        // Skip request functions, check complete/execute functions
        if func_name_lower.contains("request") {
            return findings;
        }

        // FP Reduction: Skip completion-step functions (complete/claim/finalize)
        // as they are the second step in a two-step pattern where the delay
        // is already enforced by the request step or within the completion logic
        if Self::is_completion_step_function(&func_name_lower) {
            return findings;
        }

        // Check for withdrawal delay
        if !has_withdrawal_delay(function, ctx) {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    format!(
                        "No withdrawal delay in '{}' - bypasses EigenLayer 7-day delay requirement",
                        function.name.name
                    ),
                    function.name.location.start().line() as u32,
                    0,
                    20,
                    Severity::Critical,
                )
                .with_fix_suggestion(
                    "Implement 7-day withdrawal delay (EigenLayer requirement):\n\
                 \n\
                 uint256 public constant WITHDRAWAL_DELAY = 7 days;\n\
                 \n\
                 struct WithdrawalRequest {\n\
                     uint256 shares;\n\
                     uint256 assets;\n\
                     uint256 requestTime;\n\
                     bool completed;\n\
                 }\n\
                 \n\
                 mapping(address => WithdrawalRequest) public withdrawalRequests;\n\
                 \n\
                 function requestWithdrawal(uint256 shares) external {\n\
                     require(shares > 0, \"Zero shares\");\n\
                     require(balanceOf(msg.sender) >= shares, \"Insufficient balance\");\n\
                     require(withdrawalRequests[msg.sender].shares == 0, \"Pending withdrawal\");\n\
                     \n\
                     uint256 assets = convertToAssets(shares);\n\
                     \n\
                     withdrawalRequests[msg.sender] = WithdrawalRequest({\n\
                         shares: shares,\n\
                         assets: assets,\n\
                         requestTime: block.timestamp,\n\
                         completed: false\n\
                     });\n\
                     \n\
                     // Burn shares immediately to prevent double-withdrawal\n\
                     _burn(msg.sender, shares);\n\
                     \n\
                     emit WithdrawalRequested(msg.sender, shares, assets);\n\
                 }\n\
                 \n\
                 function completeWithdrawal() external {\n\
                     WithdrawalRequest storage request = withdrawalRequests[msg.sender];\n\
                     require(request.shares > 0, \"No pending withdrawal\");\n\
                     require(!request.completed, \"Already completed\");\n\
                     require(\n\
                         block.timestamp >= request.requestTime + WITHDRAWAL_DELAY,\n\
                         \"Delay period not elapsed (7 days required)\"\n\
                     );\n\
                     \n\
                     request.completed = true;\n\
                     asset.transfer(msg.sender, request.assets);\n\
                     \n\
                     emit WithdrawalCompleted(msg.sender, request.assets);\n\
                 }"
                    .to_string(),
                );

            findings.push(finding);
        }

        findings
    }

    /// Checks if contract has two-step withdrawal (request + complete)
    fn check_two_step_withdrawal(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Find user-facing withdrawal functions (skip internal/private/view/pure)
        let has_user_facing_withdrawal = ctx.get_functions().iter().any(|f| {
            let name = f.name.name.to_lowercase();
            let is_withdrawal_name =
                name.contains("withdraw") || name.contains("redeem") || name.contains("unstake");
            let is_public_mutable = !Self::is_non_mutating_or_non_public(f);
            is_withdrawal_name && is_public_mutable
        });

        if !has_user_facing_withdrawal {
            return findings;
        }

        // FP Reduction: Recognize EigenLayer-style queue patterns as valid two-step
        if Self::has_eigenlayer_withdrawal_pattern(ctx) {
            return findings;
        }

        // FP Reduction: Also check for broader two-step patterns beyond the strict
        // requestWithdrawal/completeWithdrawal naming convention
        if self.has_broad_two_step_pattern(ctx) {
            return findings;
        }

        // Check for two-step pattern (strict naming)
        if !is_two_step_withdrawal(ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                "Single-step withdrawal detected - should implement two-step (request + complete) for delay enforcement".to_string(),
                1,
                0,
                20,
                Severity::High,
            )
            .with_fix_suggestion(
                "Implement two-step withdrawal pattern:\n\
                 \n\
                 // Step 1: Request withdrawal (immediate)\n\
                 function requestWithdrawal(uint256 shares) external {\n\
                     // Burn shares, record request\n\
                     _burn(msg.sender, shares);\n\
                     withdrawalRequests[msg.sender] = WithdrawalRequest({\n\
                         shares: shares,\n\
                         assets: convertToAssets(shares),\n\
                         requestTime: block.timestamp,\n\
                         completed: false\n\
                     });\n\
                 }\n\
                 \n\
                 // Step 2: Complete withdrawal (after 7 days)\n\
                 function completeWithdrawal() external {\n\
                     WithdrawalRequest storage request = withdrawalRequests[msg.sender];\n\
                     require(\n\
                         block.timestamp >= request.requestTime + WITHDRAWAL_DELAY,\n\
                         \"Delay not elapsed\"\n\
                     );\n\
                     \n\
                     request.completed = true;\n\
                     asset.transfer(msg.sender, request.assets);\n\
                 }\n\
                 \n\
                 This ensures EigenLayer's 7-day delay is enforced.".to_string()
            );

            findings.push(finding);
        }

        findings
    }

    /// Checks for broader two-step withdrawal patterns beyond strict naming.
    /// Recognizes patterns like queue+claim, initiate+finalize, submit+execute.
    fn has_broad_two_step_pattern(&self, ctx: &AnalysisContext) -> bool {
        let functions: Vec<String> = ctx
            .get_functions()
            .iter()
            .map(|f| f.name.name.to_lowercase())
            .collect();

        // Pattern: queue + claim/complete
        let has_queue = functions
            .iter()
            .any(|n| n.contains("queue") && n.contains("withdraw"));
        let has_claim_or_complete = functions.iter().any(|n| {
            (n.contains("claim") || n.contains("complete") || n.contains("finalize"))
                && (n.contains("withdraw") || n.contains("queued"))
        });

        if has_queue && has_claim_or_complete {
            return true;
        }

        // Pattern: initiate + finalize/execute
        let has_initiate = functions.iter().any(|n| {
            (n.contains("initiate") || n.contains("submit") || n.contains("start"))
                && (n.contains("withdraw") || n.contains("unstake") || n.contains("redeem"))
        });
        let has_finalize = functions.iter().any(|n| {
            (n.contains("finalize") || n.contains("execute") || n.contains("process"))
                && (n.contains("withdraw") || n.contains("unstake") || n.contains("redeem"))
        });

        if has_initiate && has_finalize {
            return true;
        }

        // Pattern: separate request/pending tracking with any withdrawal completion
        let source_lower = ctx.source_code.to_lowercase();
        let has_pending_tracking = source_lower.contains("pendingwithdrawals")
            || source_lower.contains("pending_withdrawals")
            || source_lower.contains("withdrawalrequests")
            || source_lower.contains("withdrawal_requests");

        if has_pending_tracking && has_claim_or_complete {
            return true;
        }

        false
    }

    /// Checks deposit functions for liquidity reserve
    fn check_liquidity_reserve(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // FP Reduction: Skip non-mutating or non-public functions
        if Self::is_non_mutating_or_non_public(function) {
            return findings;
        }

        // FP Reduction: Skip admin-only functions
        if Self::is_admin_only_function(function, ctx) {
            return findings;
        }

        // FP Reduction: Skip if deposits stay in the contract (contract IS the reserve)
        // Only flag if deposits are forwarded to an external restaking protocol
        let func_source = get_function_source(function, ctx).to_lowercase();
        let forwards_to_external = func_source.contains("eigenlayer")
            || func_source.contains("strategymanager")
            || func_source.contains("delegationmanager")
            || func_source.contains("restake")
            || func_source.contains(".deposit(")  // calling external deposit
            || func_source.contains(".stake(");    // calling external stake
        if !forwards_to_external {
            return findings;
        }

        let func_name_lower = function.name.name.to_lowercase();

        // Only check deposit/stake functions
        if !func_name_lower.contains("deposit")
            && !func_name_lower.contains("stake")
            && !func_name_lower.contains("mint")
        {
            return findings;
        }

        // FP Reduction: Skip internal helper functions like _deposit, _stake
        if func_name_lower.starts_with('_') {
            return findings;
        }

        // Check for liquidity reserve
        if !has_liquidity_reserve(function, ctx) {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    format!(
                        "No liquidity reserve in '{}' - 100% restaking prevents normal withdrawals",
                        function.name.name
                    ),
                    function.name.location.start().line() as u32,
                    0,
                    20,
                    Severity::Medium,
                )
                .with_fix_suggestion(
                    "Maintain liquidity reserve for withdrawals:\n\
                 \n\
                 uint256 public constant LIQUIDITY_RESERVE_PERCENTAGE = 10;  // 10% liquid\n\
                 uint256 public totalAvailableLiquidity;\n\
                 \n\
                 function deposit(uint256 assets) external {\n\
                     asset.transferFrom(msg.sender, address(this), assets);\n\
                     \n\
                     // Keep 10% liquid for immediate withdrawals\n\
                     uint256 toLiquidity = (assets * LIQUIDITY_RESERVE_PERCENTAGE) / 100;\n\
                     uint256 toRestake = assets - toLiquidity;\n\
                     \n\
                     totalAvailableLiquidity += toLiquidity;\n\
                     \n\
                     // Restake 90% to EigenLayer\n\
                     eigenlayer.deposit(toRestake);\n\
                     \n\
                     _mint(msg.sender, assets);\n\
                 }\n\
                 \n\
                 function completeWithdrawal() external {\n\
                     WithdrawalRequest storage request = withdrawalRequests[msg.sender];\n\
                     \n\
                     require(\n\
                         totalAvailableLiquidity >= request.assets,\n\
                         \"Insufficient liquidity - please try later\"\n\
                     );\n\
                     \n\
                     totalAvailableLiquidity -= request.assets;\n\
                     asset.transfer(msg.sender, request.assets);\n\
                 }\n\
                 \n\
                 This prevents Renzo-style incidents where withdrawals are impossible."
                        .to_string(),
                );

            findings.push(finding);
        }

        findings
    }

    /// Checks for WITHDRAWAL_DELAY constant
    fn check_withdrawal_delay_constant(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Only check if contract has user-facing withdrawal functions
        let has_user_facing_withdrawal = ctx.get_functions().iter().any(|f| {
            let name = f.name.name.to_lowercase();
            name.contains("withdraw") && !Self::is_non_mutating_or_non_public(f)
        });

        if !has_user_facing_withdrawal {
            return findings;
        }

        // FP Reduction: Skip if contract already has delay enforcement at contract level
        // (broader check than just the constant name)
        if Self::has_contract_level_delay_enforcement(ctx) {
            return findings;
        }

        // FP Reduction: Skip if contract has timestamp-based delay checks
        if Self::has_timestamp_delay_check(ctx) {
            return findings;
        }

        // Check for WITHDRAWAL_DELAY constant
        if !has_withdrawal_delay_constant(ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                "No WITHDRAWAL_DELAY constant defined - should match EigenLayer's 7-day requirement".to_string(),
                1,
                0,
                20,
                Severity::Low,
            )
            .with_fix_suggestion(
                "Define withdrawal delay constant:\n\
                 \n\
                 // EigenLayer requirement: 7 days\n\
                 uint256 public constant WITHDRAWAL_DELAY = 7 days;\n\
                 \n\
                 // Or make it governance-controlled (cannot be <7 days)\n\
                 uint256 public withdrawalDelay = 7 days;\n\
                 \n\
                 function setWithdrawalDelay(uint256 newDelay) external onlyGovernance {\n\
                     require(newDelay >= 7 days, \"Cannot be less than EigenLayer minimum\");\n\
                     withdrawalDelay = newDelay;\n\
                 }".to_string()
            );

            findings.push(finding);
        }

        findings
    }

    /// Checks for instant withdrawal vulnerability
    fn check_instant_withdrawal(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // FP Reduction: Skip non-mutating or non-public functions
        if Self::is_non_mutating_or_non_public(function) {
            return findings;
        }

        // FP Reduction: Skip admin-only functions (emergency withdraw, etc.)
        if Self::is_admin_only_function(function, ctx) {
            return findings;
        }

        let func_name_lower = function.name.name.to_lowercase();

        // Only check withdraw/redeem functions
        if !func_name_lower.contains("withdraw") && !func_name_lower.contains("redeem") {
            return findings;
        }

        // FP Reduction: Skip completion-step functions
        if Self::is_completion_step_function(&func_name_lower) {
            return findings;
        }

        // FP Reduction: Skip request functions (they queue, not instant-withdraw)
        if func_name_lower.contains("request") || func_name_lower.contains("queue") {
            return findings;
        }

        // Check if single-step (burn + transfer in same function)
        if is_single_step_withdrawal(function, ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                format!(
                    "Instant withdrawal in '{}' - single-step pattern bypasses EigenLayer delay",
                    function.name.name
                ),
                function.name.location.start().line() as u32,
                0,
                20,
                Severity::Critical,
            )
            .with_fix_suggestion(
                "Replace instant withdrawal with delayed pattern:\n\
                 \n\
                 // VULNERABLE: Instant withdrawal\n\
                 function withdraw(uint256 shares) external {\n\
                     uint256 assets = convertToAssets(shares);\n\
                     _burn(msg.sender, shares);  // Burns\n\
                     asset.transfer(msg.sender, assets);  // Transfers instantly - WRONG!\n\
                 }\n\
                 \n\
                 // SECURE: Delayed withdrawal\n\
                 function requestWithdrawal(uint256 shares) external {\n\
                     _burn(msg.sender, shares);\n\
                     withdrawalRequests[msg.sender] = WithdrawalRequest({\n\
                         assets: convertToAssets(shares),\n\
                         requestTime: block.timestamp,\n\
                         completed: false\n\
                     });\n\
                 }\n\
                 \n\
                 function completeWithdrawal() external {\n\
                     WithdrawalRequest storage request = withdrawalRequests[msg.sender];\n\
                     require(\n\
                         block.timestamp >= request.requestTime + 7 days,\n\
                         \"7-day delay required\"\n\
                     );\n\
                     asset.transfer(msg.sender, request.assets);\n\
                 }".to_string()
            );

            findings.push(finding);
        }

        findings
    }
}

impl Default for RestakingWithdrawalDelaysDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for RestakingWithdrawalDelaysDetector {
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

        // FP Reduction: Skip secure/fixed example contracts
        if crate::utils::is_secure_example_file(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip attack/exploit contracts
        if crate::utils::is_attack_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Only analyze contracts with withdrawal/staking functions
        let contract_func_names: Vec<String> = ctx
            .contract
            .functions
            .iter()
            .map(|f| f.name.name.to_lowercase())
            .collect();
        let contract_name_lower = ctx.contract.name.name.to_lowercase();
        let contract_has_withdrawal_fn = contract_func_names.iter().any(|n| {
            n.contains("withdraw")
                || n.contains("unstake")
                || n.contains("redeem")
                || n.contains("stake")
                || n.contains("deposit")
                || n.contains("claim")
                || n.contains("delegate")
                || n.contains("undelegate")
        }) || contract_name_lower.contains("staking")
            || contract_name_lower.contains("vault")
            || contract_name_lower.contains("restaking")
            || contract_name_lower.contains("lrt");
        if !contract_has_withdrawal_fn {
            return Ok(findings);
        }

        // Only run on restaking/LRT contracts
        if !is_restaking_contract(ctx) && !is_lrt_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip slashing-focused contracts.
        // Contracts named Slasher or *_Slasher test slashing conditions, not
        // withdrawal delays. They may have withdraw/stake functions but the
        // primary vulnerability is in slashing logic, not delay enforcement.
        {
            let name_lower = ctx.contract.name.name.to_lowercase();
            if name_lower.contains("slasher") || name_lower == "slasher" {
                return Ok(findings);
            }
            // Skip pure token contracts (e.g., EzEthToken) — these are
            // restaking receipt tokens, not withdrawal-handling contracts.
            // The token itself doesn't handle withdrawal delays.
            if name_lower.ends_with("token") && !name_lower.contains("vault") {
                return Ok(findings);
            }
        }

        // FP Reduction: Skip non-restaking contexts that may have matched keywords
        if Self::is_non_restaking_withdrawal_context(ctx) {
            return Ok(findings);
        }

        // Phase 2 Enhancement: Safe pattern detection with dynamic confidence

        // Level 1: Strong restaking protocol protections (return early)
        if vault_patterns::has_eigenlayer_delegation_pattern(ctx) {
            // EigenLayer has battle-tested withdrawal queue with 7-day delay
            return Ok(findings);
        }

        // Level 2: Contract uses EigenLayer-style queue withdrawal pattern
        if Self::has_eigenlayer_withdrawal_pattern(ctx) {
            return Ok(findings);
        }

        // Level 3: Contract delegates to an external withdrawal queue contract
        if Self::uses_external_withdrawal_queue(ctx) {
            return Ok(findings);
        }

        // Level 4: Contract already has delay enforcement at the contract level
        if Self::has_contract_level_delay_enforcement(ctx) {
            return Ok(findings);
        }

        // Level 5: Contract has timestamp-based delay checks
        if Self::has_timestamp_delay_check(ctx) {
            return Ok(findings);
        }

        // Check each function for withdrawal vulnerabilities
        for function in ctx.get_functions() {
            findings.extend(self.check_withdrawal_delay(function, ctx));
            findings.extend(self.check_liquidity_reserve(function, ctx));
            findings.extend(self.check_instant_withdrawal(function, ctx));
        }

        // Contract-level checks — skip two-step check if per-function findings already
        // flag withdrawal issues (avoid redundant contract-level + function-level findings)
        if findings.is_empty() {
            findings.extend(self.check_two_step_withdrawal(ctx));
        }
        findings.extend(self.check_withdrawal_delay_constant(ctx));

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {

    // Test cases would go here
    // Should cover:
    // 1. No withdrawal delay
    // 2. Single-step withdrawal
    // 3. No liquidity reserve
    // 4. Instant withdrawal
    // 5. No false positives on secure implementations with delay
}
