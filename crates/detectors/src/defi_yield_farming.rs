//! DeFi Yield Farming Exploits Detector

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::vault_patterns;
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct YieldFarmingDetector {
    base: BaseDetector,
}

impl YieldFarmingDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("defi-yield-farming-exploits".to_string()),
                "Yield Farming Exploits".to_string(),
                "Detects missing deposit/withdrawal fee validation, reward calculation errors, and share price manipulation".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    fn is_yield_vault(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code.to_lowercase();

        // Strong signals - any of these is definitive
        if source.contains("erc4626") || source.contains("vault") && source.contains("shares") {
            return true;
        }

        if source.contains("staking") && source.contains("reward") {
            return true;
        }

        // Count medium-strength indicators
        let mut indicator_count = 0;

        if source.contains("deposit") && source.contains("shares") {
            indicator_count += 1;
        }

        if source.contains("withdraw") && source.contains("shares") {
            indicator_count += 1;
        }

        if source.contains("totalassets") {
            indicator_count += 1;
        }

        if source.contains("rewardpertoken") || source.contains("rewardrate") {
            indicator_count += 1;
        }

        if source.contains("stake") && source.contains("unstake") {
            indicator_count += 1;
        }

        // Require 2+ medium-strength indicators
        indicator_count >= 2
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

    fn check_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
        skip_inflation_checks: bool,
        has_contract_min_deposit: bool,
    ) -> Vec<(String, Severity, String)> {
        let name = function.name.name.to_lowercase();
        let mut issues = Vec::new();

        // Get function body specifically, not entire source code
        let func_source = self.get_function_source(function, ctx);
        let source_lower = func_source.to_lowercase();

        // Also get contract-level source for things like state variable checks
        let contract_source_lower = ctx.source_code.to_lowercase();

        // Check deposit functions
        if name.contains("deposit") || name.contains("stake") {
            // Skip inflation-related checks if contract has protection patterns
            if !skip_inflation_checks {
                // Check for share inflation attack protection (check function body)
                let has_min_deposit = has_contract_min_deposit
                    || source_lower.contains("minimum")
                    || source_lower.contains("min_deposit")
                    || (source_lower.contains("require") && source_lower.contains("amount >"))
                    || source_lower.contains("amount >= min");

                if !has_min_deposit {
                    issues.push((
                        "No minimum deposit (share inflation attack risk)".to_string(),
                        Severity::Critical,
                        "Add minimum: require(amount >= MIN_DEPOSIT, \"Amount too small\"); // e.g., MIN_DEPOSIT = 1e6".to_string()
                    ));
                }

                // Check for first depositor protection (in function body)
                let has_first_deposit_lock = source_lower.contains("totalsupply == 0")
                    || source_lower.contains("totalsupply() == 0")
                    || source_lower.contains("initialdeposit")
                    || contract_source_lower.contains("_initialdeposit"); // contract-level check

                if !has_first_deposit_lock && source_lower.contains("shares") {
                    issues.push((
                        "No first depositor protection (inflation attack on vault initialization)".to_string(),
                        Severity::Critical,
                        "Lock initial shares: if (totalSupply() == 0) { _mint(address(0), INITIAL_SHARES); }".to_string()
                    ));
                }
            }

            // Check for share calculation (in function body)
            let has_share_calc = source_lower.contains("totalsupply")
                && (source_lower.contains("totalassets") || source_lower.contains("balance"));

            // Only flag if function explicitly deals with shares
            if source_lower.contains("shares =") && !has_share_calc {
                issues.push((
                    "Share calculation doesn't use totalSupply and totalAssets".to_string(),
                    Severity::High,
                    "Calculate shares: shares = (amount * totalSupply()) / totalAssets();"
                        .to_string(),
                ));
            }

            // Check for rounding errors (only if shares are calculated in this function)
            if source_lower.contains("shares =") {
                let has_rounding_check =
                    source_lower.contains("shares > 0") || source_lower.contains("require(shares");

                if !has_rounding_check {
                    issues.push((
                        "No zero-share validation (rounding error exploitation)".to_string(),
                        Severity::High,
                        "Validate shares: require(shares > 0, \"Shares must be non-zero\");"
                            .to_string(),
                    ));
                }
            }

            // Check for fee-on-transfer token support (only for functions using transferFrom)
            if source_lower.contains("transferfrom") {
                let has_actual_amount = source_lower.contains("balancebefore")
                    || source_lower.contains("balanceafter")
                    || source_lower.contains("balance -");

                if !has_actual_amount {
                    issues.push((
                        "Doesn't handle fee-on-transfer tokens (accounting mismatch)".to_string(),
                        Severity::Medium,
                        "Handle fees: uint256 balanceBefore = token.balanceOf(address(this)); token.transferFrom(msg.sender, address(this), amount); uint256 actualAmount = token.balanceOf(address(this)) - balanceBefore;".to_string()
                    ));
                }
            }
        }

        // Check withdraw functions
        if name.contains("withdraw") || name.contains("unstake") || name.contains("redeem") {
            // NOTE: Withdrawal fees are a design choice, not a vulnerability
            // Removed the withdrawal fee check as it created false positives

            // Check for asset calculation
            let has_asset_calc = source_lower.contains("shares")
                && (source_lower.contains("totalsupply") || source_lower.contains("totalassets"));

            if !has_asset_calc {
                issues.push((
                    "Asset calculation missing totalSupply/totalAssets".to_string(),
                    Severity::High,
                    "Calculate assets: assets = (shares * totalAssets()) / totalSupply();"
                        .to_string(),
                ));
            }

            // Check for zero-asset validation
            let has_zero_check = source_lower.contains("assets > 0")
                || (source_lower.contains("require") && source_lower.contains("!= 0"));

            if source_lower.contains("assets") && !has_zero_check {
                issues.push((
                    "No validation for zero assets on withdrawal".to_string(),
                    Severity::Medium,
                    "Validate assets: require(assets > 0, \"Assets must be non-zero\");"
                        .to_string(),
                ));
            }

            // Check for slippage protection
            let has_min_output = source_lower.contains("minassets")
                || source_lower.contains("minamount")
                || (source_lower.contains("amount") && source_lower.contains(">="));

            if !has_min_output {
                issues.push((
                    "No slippage protection on withdrawal".to_string(),
                    Severity::Medium,
                    "Add slippage: require(assets >= minAssets, \"Slippage too high\");"
                        .to_string(),
                ));
            }
        }

        // Check reward calculation functions
        if name.contains("reward") || name.contains("earn") || name.contains("claim") {
            // Check for reward per token calculation
            let has_reward_calc = source_lower.contains("rewardpertoken")
                || (source_lower.contains("reward") && source_lower.contains("totalsupply"));

            if !has_reward_calc {
                issues.push((
                    "Reward calculation doesn't account for totalSupply".to_string(),
                    Severity::High,
                    "Calculate rewards: rewardPerToken = (rewardRate * timeDelta * 1e18) / totalSupply;".to_string()
                ));
            }

            // Check for timestamp validation
            let has_time_check = source_lower.contains("lastupdatetime")
                || source_lower.contains("lastclaimtime")
                || (source_lower.contains("timestamp") && source_lower.contains("require"));

            if !has_time_check {
                issues.push((
                    "No timestamp tracking for reward accrual".to_string(),
                    Severity::High,
                    "Track time: lastUpdateTime = block.timestamp; Use for accurate reward calculation".to_string()
                ));
            }

            // Check for reward debt accounting
            let has_reward_debt =
                source_lower.contains("rewarddebt") || source_lower.contains("paidreward");

            if !has_reward_debt {
                issues.push((
                    "Missing reward debt tracking (double-claim risk)".to_string(),
                    Severity::Critical,
                    "Track debt: userRewardDebt[user] = (userBalance * rewardPerToken) / 1e18;"
                        .to_string(),
                ));
            }

            // Check for precision loss
            let has_precision = source_lower.contains("1e18") || source_lower.contains("precision");

            if !has_precision {
                issues.push((
                    "Reward calculation without precision multiplier (rounding errors)".to_string(),
                    Severity::Medium,
                    "Add precision: Use 1e18 multiplier for reward calculations to minimize rounding errors".to_string()
                ));
            }
        }

        // Check harvest/compound functions
        if name.contains("harvest") || name.contains("compound") {
            // Check for reentrancy protection
            let has_reentrancy_guard =
                source_lower.contains("nonreentrant") || source_lower.contains("locked");

            if !has_reentrancy_guard {
                issues.push((
                    "Harvest function without reentrancy protection".to_string(),
                    Severity::Critical,
                    "Add guard: Use nonReentrant modifier or ReentrancyGuard".to_string(),
                ));
            }

            // NOTE: Performance fees are a design choice, not a vulnerability
            // Removed the performance fee check as it created false positives
        }

        // Check updateReward modifier or function
        if name.contains("update") && source_lower.contains("reward") {
            // Check for zero supply handling
            let has_zero_supply = source_lower.contains("totalsupply() == 0")
                || source_lower.contains("totalsupply > 0");

            if !has_zero_supply {
                issues.push((
                    "Reward update doesn't handle zero totalSupply (division by zero)".to_string(),
                    Severity::High,
                    "Handle zero: if (totalSupply() > 0) { rewardPerToken = ...; }".to_string(),
                ));
            }
        }

        issues
    }
}

impl Default for YieldFarmingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for YieldFarmingDetector {
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

        if !self.is_yield_vault(ctx) {
            return Ok(findings);
        }

        // Check for vault inflation protection patterns
        // These reduce false positives for share inflation attacks
        let has_inflation_protection = vault_patterns::has_inflation_protection(ctx);
        let has_dead_shares = vault_patterns::has_dead_shares_pattern(ctx);
        let has_virtual_shares = vault_patterns::has_virtual_shares_pattern(ctx);
        let has_min_deposit = vault_patterns::has_minimum_deposit_pattern(ctx);

        // If vault has comprehensive inflation protection, skip inflation-related checks
        let skip_inflation_checks = has_inflation_protection || has_dead_shares || has_virtual_shares;

        for function in ctx.get_functions() {
            // Skip internal/private functions
            if function.visibility == ast::Visibility::Internal
                || function.visibility == ast::Visibility::Private
            {
                continue;
            }

            // Skip view/pure functions - they don't modify state
            if function.mutability == ast::StateMutability::View
                || function.mutability == ast::StateMutability::Pure
            {
                continue;
            }

            // Skip standard token functions that aren't yield-specific
            let func_name_lower = function.name.name.to_lowercase();
            if func_name_lower == "transfer"
                || func_name_lower == "transferfrom"
                || func_name_lower == "approve"
                || func_name_lower == "allowance"
                || func_name_lower == "balanceof"
            {
                continue;
            }

            let issues = self.check_function(function, ctx, skip_inflation_checks, has_min_deposit);
            for (message, severity, remediation) in issues {
                let finding = self
                    .base
                    .create_finding_with_severity(
                        ctx,
                        format!("{} in '{}'", message, function.name.name),
                        function.name.location.start().line() as u32,
                        0,
                        20,
                        severity,
                    )
                    .with_cwe(682) // CWE-682: Incorrect Calculation
                    .with_cwe(191) // CWE-191: Integer Underflow
                    .with_fix_suggestion(remediation);

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
