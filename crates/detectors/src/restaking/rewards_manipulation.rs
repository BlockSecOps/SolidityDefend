//! Restaking Rewards Manipulation Detector
//!
//! Detects reward calculation exploits, point system gaming, and unfair reward distribution
//! in restaking protocols. Operators control reward distribution, creating manipulation
//! opportunities.
//!
//! Severity: MEDIUM
//! Category: DeFi, Restaking
//!
//! Real-World Context:
//! - Renzo Airdrop Controversy: Farming via quick deposits/withdrawals
//! - Point systems without time-weighting vulnerable to Sybil attacks
//! - Operators can favor certain stakers in reward distribution
//!
//! Vulnerabilities Detected:
//! 1. Unfair reward distribution (not pro-rata)
//! 2. Point system without Sybil protection
//! 3. Rewards calculated using balanceOf (donation manipulation)
//! 4. No reward rate limits
//! 5. No early withdrawal penalty (farming prevention)

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::vault_patterns;
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::restaking::classification::*;
use ast;

pub struct RestakingRewardsManipulationDetector {
    base: BaseDetector,
}

impl RestakingRewardsManipulationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("restaking-rewards-manipulation".to_string()),
                "Restaking Rewards Manipulation".to_string(),
                "Detects reward calculation exploits, point system gaming, and unfair reward distribution".to_string(),
                vec![DetectorCategory::DeFi],
                Severity::Medium,
            ),
        }
    }

    /// Checks reward distribution for proportional calculation
    fn check_proportional_distribution(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let func_name_lower = function.name.name.to_lowercase();

        // Only check reward distribution functions
        if !func_name_lower.contains("distribute") &&
           !func_name_lower.contains("claim") &&
           !func_name_lower.contains("reward") {
            return findings;
        }

        // Skip if not reward-related
        if !func_name_lower.contains("reward") &&
           !func_name_lower.contains("distribute") {
            return findings;
        }

        // Check for proportional distribution
        if !has_proportional_distribution(function, ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                format!(
                    "No proportional reward distribution in '{}' - can favor certain stakers unfairly",
                    function.name.name
                ),
                function.name.location.start().line() as u32,
                0,
                20,
                Severity::High,
            )
            .with_fix_suggestion(
                "Implement pro-rata reward distribution (Synthetix StakingRewards pattern):\n\
                 \n\
                 uint256 public rewardPerTokenStored;\n\
                 mapping(address => uint256) public userRewardPerTokenPaid;\n\
                 mapping(address => uint256) public rewards;\n\
                 \n\
                 function rewardPerToken() public view returns (uint256) {\n\
                     if (totalStaked == 0) {\n\
                         return rewardPerTokenStored;\n\
                     }\n\
                     return rewardPerTokenStored +\n\
                         ((totalRewardsTracked * 1e18) / totalStaked);\n\
                 }\n\
                 \n\
                 function earned(address user) public view returns (uint256) {\n\
                     return (stakes[user] *\n\
                         (rewardPerToken() - userRewardPerTokenPaid[user])) / 1e18\n\
                         + rewards[user];\n\
                 }\n\
                 \n\
                 function claimRewards() external {\n\
                     updateReward(msg.sender);\n\
                     uint256 reward = rewards[msg.sender];\n\
                     require(reward > 0, \"No rewards\");\n\
                     rewards[msg.sender] = 0;\n\
                     rewardToken.transfer(msg.sender, reward);\n\
                 }\n\
                 \n\
                 This ensures fair, proportional rewards based on stake amount.".to_string()
            );

            findings.push(finding);
        }

        findings
    }

    /// Checks point accrual for time-weighting
    fn check_time_weighted_points(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let func_name_lower = function.name.name.to_lowercase();

        // Only check point accrual functions
        if !func_name_lower.contains("point") &&
           !func_name_lower.contains("accrue") &&
           !func_name_lower.contains("calculatepoints") {
            return findings;
        }

        // Check for time-weighting
        if !has_time_weighting(function, ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                format!(
                    "No time-weighted points in '{}' - vulnerable to farming (Renzo-style)",
                    function.name.name
                ),
                function.name.location.start().line() as u32,
                0,
                20,
                Severity::Medium,
            )
            .with_fix_suggestion(
                "Implement time-weighted points to prevent farming:\n\
                 \n\
                 struct StakeInfo {\n\
                     uint256 amount;\n\
                     uint256 depositTime;\n\
                     uint256 points;\n\
                 }\n\
                 \n\
                 mapping(address => StakeInfo) public stakes;\n\
                 \n\
                 function updatePoints(address user) internal {\n\
                     StakeInfo storage stake = stakes[user];\n\
                     if (stake.amount > 0) {\n\
                         // Time-weighted: points = amount * time staked\n\
                         uint256 timeStaked = block.timestamp - stake.depositTime;\n\
                         uint256 additionalPoints = (stake.amount * timeStaked) / 1 days;\n\
                         stake.points += additionalPoints;\n\
                         stake.depositTime = block.timestamp;  // Reset timer\n\
                     }\n\
                 }\n\
                 \n\
                 function deposit(uint256 amount) external {\n\
                     updatePoints(msg.sender);  // Accrue points first\n\
                     stakes[msg.sender].amount += amount;\n\
                     stakes[msg.sender].depositTime = block.timestamp;\n\
                 }\n\
                 \n\
                 This prevents quick deposit/withdrawal farming.".to_string()
            );

            findings.push(finding);
        }

        findings
    }

    /// Checks reward calculation for balanceOf usage
    fn check_reward_calculation(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let func_name_lower = function.name.name.to_lowercase();

        // Only check reward calculation functions
        if !func_name_lower.contains("reward") &&
           !func_name_lower.contains("earned") &&
           !func_name_lower.contains("calculatereward") {
            return findings;
        }

        // Check if uses balanceOf
        if reward_uses_balance_of(function, ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                format!(
                    "Reward calculation uses balanceOf in '{}' - donation manipulation possible",
                    function.name.name
                ),
                function.name.location.start().line() as u32,
                0,
                20,
                Severity::High,
            )
            .with_fix_suggestion(
                "Use tracked rewards instead of balanceOf:\n\
                 \n\
                 // BAD: Includes donations\n\
                 function calculateRewards(address user) public view returns (uint256) {\n\
                     uint256 totalRewards = rewardToken.balanceOf(address(this));  // VULNERABLE\n\
                     return (stakes[user] * totalRewards) / totalStaked;\n\
                 }\n\
                 \n\
                 // GOOD: Only counts legitimate rewards\n\
                 uint256 public totalRewardsTracked;\n\
                 \n\
                 function addRewards(uint256 amount) external onlyOperator {\n\
                     rewardToken.transferFrom(msg.sender, address(this), amount);\n\
                     totalRewardsTracked += amount;  // Track explicitly\n\
                 }\n\
                 \n\
                 function rewardPerToken() public view returns (uint256) {\n\
                     if (totalStaked == 0) return 0;\n\
                     return (totalRewardsTracked * 1e18) / totalStaked;  // Use tracked\n\
                 }\n\
                 \n\
                 This prevents attacker from inflating rewards via direct transfer.".to_string()
            );

            findings.push(finding);
        }

        findings
    }

    /// Checks for reward rate limits
    fn check_reward_rate_limits(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let func_name_lower = function.name.name.to_lowercase();

        // Only check reward rate setting functions
        if !func_name_lower.contains("setrewardrate") &&
           !func_name_lower.contains("setrate") &&
           !func_name_lower.contains("updaterate") {
            return findings;
        }

        if !func_name_lower.contains("reward") {
            return findings;
        }

        // Check for max rate cap
        if !has_max_rate_cap(function, ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                format!(
                    "No maximum reward rate cap in '{}' - operator can set unsustainable rates",
                    function.name.name
                ),
                function.name.location.start().line() as u32,
                0,
                20,
                Severity::Low,
            )
            .with_fix_suggestion(
                "Enforce maximum reward rate:\n\
                 \n\
                 uint256 public constant MAX_REWARD_RATE = 1e18;  // 100% APR maximum\n\
                 \n\
                 function setRewardRate(uint256 newRate) external onlyGovernance {\n\
                     require(\n\
                         newRate <= MAX_REWARD_RATE,\n\
                         \"Reward rate too high (max 100% APR)\"\n\
                     );\n\
                     \n\
                     // Optional: Check sustainability\n\
                     uint256 annualRewards = (totalStaked * newRate) / 1e18;\n\
                     require(\n\
                         annualRewards <= rewardToken.balanceOf(address(this)),\n\
                         \"Insufficient reward reserves\"\n\
                     );\n\
                     \n\
                     rewardRate = newRate;\n\
                 }".to_string()
            );

            findings.push(finding);
        }

        findings
    }

    /// Checks for early withdrawal penalty
    fn check_early_withdrawal_penalty(
        &self,
        function: &ast::Function,
        ctx: &AnalysisContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let func_name_lower = function.name.name.to_lowercase();

        // Only check withdrawal functions
        if !func_name_lower.contains("withdraw") &&
           !func_name_lower.contains("unstake") {
            return findings;
        }

        // Check for early withdrawal penalty
        if !has_early_withdrawal_penalty(function, ctx) {
            let finding = self.base.create_finding_with_severity(
                ctx,
                format!(
                    "No early withdrawal penalty in '{}' - vulnerable to farming (quick deposit/withdraw)",
                    function.name.name
                ),
                function.name.location.start().line() as u32,
                0,
                20,
                Severity::Low,
            )
            .with_fix_suggestion(
                "Implement early withdrawal penalty:\n\
                 \n\
                 uint256 public constant MIN_STAKE_DURATION = 30 days;\n\
                 \n\
                 struct StakeInfo {\n\
                     uint256 amount;\n\
                     uint256 depositTime;\n\
                 }\n\
                 \n\
                 mapping(address => StakeInfo) public stakes;\n\
                 \n\
                 function withdraw(uint256 amount) external {\n\
                     updateReward(msg.sender);\n\
                     \n\
                     StakeInfo storage stake = stakes[msg.sender];\n\
                     uint256 timeStaked = block.timestamp - stake.depositTime;\n\
                     \n\
                     // Penalty for early withdrawal (< 30 days)\n\
                     if (timeStaked < MIN_STAKE_DURATION) {\n\
                         uint256 rewardAmount = rewards[msg.sender];\n\
                         uint256 penalty = (rewardAmount * 50) / 100;  // 50% penalty\n\
                         rewards[msg.sender] -= penalty;\n\
                         \n\
                         // Redistribute penalty to long-term stakers\n\
                         totalRewardsTracked += penalty;\n\
                         \n\
                         emit EarlyWithdrawalPenalty(msg.sender, penalty);\n\
                     }\n\
                     \n\
                     stake.amount -= amount;\n\
                     totalStaked -= amount;\n\
                     asset.transfer(msg.sender, amount);\n\
                 }\n\
                 \n\
                 This prevents farming via quick deposits/withdrawals.".to_string()
            );

            findings.push(finding);
        }

        findings
    }
}

impl Default for RestakingRewardsManipulationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for RestakingRewardsManipulationDetector {
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

        // Only run on restaking contracts
        if !is_restaking_contract(ctx) && !is_lrt_contract(ctx) {
            return Ok(findings);
        }

        // Phase 2 Enhancement: Safe pattern detection with dynamic confidence

        // Level 1: Strong restaking protocol protections (return early)
        if vault_patterns::has_safe_reward_distribution(ctx) {
            // Comprehensive reward distribution patterns - proportional, time-weighted
            return Ok(findings);
        }

        if vault_patterns::has_eigenlayer_delegation_pattern(ctx) {
            // EigenLayer has battle-tested reward distribution mechanisms
            return Ok(findings);
        }

        // Check each function for rewards vulnerabilities
        for function in ctx.get_functions() {
            findings.extend(self.check_proportional_distribution(function, ctx));
            findings.extend(self.check_time_weighted_points(function, ctx));
            findings.extend(self.check_reward_calculation(function, ctx));
            findings.extend(self.check_reward_rate_limits(function, ctx));
            findings.extend(self.check_early_withdrawal_penalty(function, ctx));
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

    // Test cases would go here
    // Should cover:
    // 1. No proportional distribution
    // 2. No time-weighted points
    // 3. Rewards use balanceOf
    // 4. No reward rate limits
    // 5. No early withdrawal penalty
    // 6. No false positives on Synthetix StakingRewards pattern
}
