//! DeFi Yield Farming Exploits Detector

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
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
        (source.contains("deposit") || source.contains("withdraw"))
            && (source.contains("reward")
                || source.contains("yield")
                || source.contains("shares")
                || source.contains("stake"))
    }

    fn check_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Vec<(String, Severity, String)> {
        let name = function.name.name.to_lowercase();
        let mut issues = Vec::new();
        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Check deposit functions
        if name.contains("deposit") || name.contains("stake") {
            // Check for share inflation attack protection
            let has_min_deposit = source_lower.contains("minimum")
                || source_lower.contains("min_deposit")
                || (source_lower.contains("require") && source_lower.contains("amount"));

            if !has_min_deposit {
                issues.push((
                    "No minimum deposit (share inflation attack risk)".to_string(),
                    Severity::Critical,
                    "Add minimum: require(amount >= MIN_DEPOSIT, \"Amount too small\"); // e.g., MIN_DEPOSIT = 1e6".to_string()
                ));
            }

            // Check for first depositor protection
            let has_first_deposit_lock = source_lower.contains("totalsupply == 0")
                || source_lower.contains("initialdeposit");

            if !has_first_deposit_lock {
                issues.push((
                    "No first depositor protection (inflation attack on vault initialization)".to_string(),
                    Severity::Critical,
                    "Lock initial shares: if (totalSupply() == 0) { _mint(address(0), INITIAL_SHARES); }".to_string()
                ));
            }

            // Check for share calculation
            let has_share_calc = source_lower.contains("totalsupply")
                && (source_lower.contains("totalassets") || source_lower.contains("balance"));

            if source_lower.contains("shares") && !has_share_calc {
                issues.push((
                    "Share calculation doesn't use totalSupply and totalAssets".to_string(),
                    Severity::High,
                    "Calculate shares: shares = (amount * totalSupply()) / totalAssets();"
                        .to_string(),
                ));
            }

            // Check for rounding errors
            let has_rounding_check =
                source_lower.contains("shares > 0") || source_lower.contains("!= 0");

            if source_lower.contains("shares") && !has_rounding_check {
                issues.push((
                    "No zero-share validation (rounding error exploitation)".to_string(),
                    Severity::High,
                    "Validate shares: require(shares > 0, \"Shares must be non-zero\");"
                        .to_string(),
                ));
            }

            // Check for fee-on-transfer token support
            let has_actual_amount = source_lower.contains("balancebefore")
                || source_lower.contains("balanceafter")
                || (source_lower.contains("balance") && source_lower.contains("-"));

            if !has_actual_amount {
                issues.push((
                    "Doesn't handle fee-on-transfer tokens (accounting mismatch)".to_string(),
                    Severity::Medium,
                    "Handle fees: uint256 balanceBefore = token.balanceOf(address(this)); token.transferFrom(msg.sender, address(this), amount); uint256 actualAmount = token.balanceOf(address(this)) - balanceBefore;".to_string()
                ));
            }

            // Check for deposit cap
            let has_cap = source_lower.contains("maxdeposit")
                || source_lower.contains("cap")
                || source_lower.contains("limit");

            if !has_cap {
                issues.push((
                    "No deposit cap (unlimited exposure risk)".to_string(),
                    Severity::Low,
                    "Add cap: require(totalAssets() + amount <= depositCap, \"Cap exceeded\");"
                        .to_string(),
                ));
            }
        }

        // Check withdraw functions
        if name.contains("withdraw") || name.contains("unstake") || name.contains("redeem") {
            // Check for withdrawal fee validation
            let has_fee_calc = source_lower.contains("withdrawalfee")
                || source_lower.contains("exitfee")
                || (source_lower.contains("fee") && source_lower.contains("withdraw"));

            if !has_fee_calc {
                issues.push((
                    "No withdrawal fee accounting (fee bypass risk)".to_string(),
                    Severity::Medium,
                    "Calculate fee: uint256 fee = (amount * withdrawalFee) / FEE_DENOMINATOR; uint256 amountAfterFee = amount - fee;".to_string()
                ));
            }

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

            // Check for performance fee
            let has_perf_fee = source_lower.contains("performancefee")
                || (source_lower.contains("fee") && source_lower.contains("harvest"));

            if !has_perf_fee {
                issues.push((
                    "No performance fee on harvest (governance revenue loss)".to_string(),
                    Severity::Low,
                    "Add fee: uint256 fee = (harvestedAmount * performanceFee) / FEE_DENOMINATOR;"
                        .to_string(),
                ));
            }
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

        for function in ctx.get_functions() {
            let issues = self.check_function(function, ctx);
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
