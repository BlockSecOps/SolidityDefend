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
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::restaking::classification::*;
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

    /// Checks withdrawal functions for delay enforcement
    fn check_withdrawal_delay(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let func_name_lower = function.name.name.to_lowercase();

        // Only check withdrawal/redeem/unstake functions
        if !func_name_lower.contains("withdraw") &&
           !func_name_lower.contains("redeem") &&
           !func_name_lower.contains("unstake") {
            return findings;
        }

        // Skip request functions, check complete/execute functions
        if func_name_lower.contains("request") {
            return findings;
        }

        // Check for withdrawal delay
        if !has_withdrawal_delay(function, ctx) {
            let finding = self.base.create_finding_with_severity(
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
                 }".to_string()
            );

            findings.push(finding);
        }

        findings
    }

    /// Checks if contract has two-step withdrawal (request + complete)
    fn check_two_step_withdrawal(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Find withdrawal functions
        let has_withdrawal = ctx.get_functions().iter().any(|f| {
            let name = f.name.name.to_lowercase();
            name.contains("withdraw") || name.contains("redeem") || name.contains("unstake")
        });

        if !has_withdrawal {
            return findings;
        }

        // Check for two-step pattern
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

    /// Checks deposit functions for liquidity reserve
    fn check_liquidity_reserve(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let func_name_lower = function.name.name.to_lowercase();

        // Only check deposit/stake functions
        if !func_name_lower.contains("deposit") &&
           !func_name_lower.contains("stake") &&
           !func_name_lower.contains("mint") {
            return findings;
        }

        // Check for liquidity reserve
        if !has_liquidity_reserve(function, ctx) {
            let finding = self.base.create_finding_with_severity(
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
                 This prevents Renzo-style incidents where withdrawals are impossible.".to_string()
            );

            findings.push(finding);
        }

        findings
    }

    /// Checks for WITHDRAWAL_DELAY constant
    fn check_withdrawal_delay_constant(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Only check if contract has withdrawal functions
        let has_withdrawal = ctx.get_functions().iter().any(|f| {
            f.name.name.to_lowercase().contains("withdraw")
        });

        if !has_withdrawal {
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

        let func_name_lower = function.name.name.to_lowercase();

        // Only check withdraw/redeem functions
        if !func_name_lower.contains("withdraw") &&
           !func_name_lower.contains("redeem") {
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

        // Only run on restaking/LRT contracts
        if !is_restaking_contract(ctx) && !is_lrt_contract(ctx) {
            return Ok(findings);
        }

        // Check each function for withdrawal vulnerabilities
        for function in ctx.get_functions() {
            findings.extend(self.check_withdrawal_delay(function, ctx));
            findings.extend(self.check_liquidity_reserve(function, ctx));
            findings.extend(self.check_instant_withdrawal(function, ctx));
        }

        // Contract-level checks
        findings.extend(self.check_two_step_withdrawal(ctx));
        findings.extend(self.check_withdrawal_delay_constant(ctx));

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test cases would go here
    // Should cover:
    // 1. No withdrawal delay
    // 2. Single-step withdrawal
    // 3. No liquidity reserve
    // 4. Instant withdrawal
    // 5. No false positives on secure implementations with delay
}
