//! DeFi Just-In-Time (JIT) Liquidity Attacks Detector

use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

pub struct JitLiquidityDetector {
    base: BaseDetector,
}

impl JitLiquidityDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("defi-jit-liquidity-attacks".to_string()),
                "JIT Liquidity Attacks".to_string(),
                "Detects lack of minimum liquidity lock periods and validates LP commitment to prevent sandwich attacks".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::MEV],
                Severity::High,
            ),
        }
    }

    fn is_liquidity_pool(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code.to_lowercase();
        (source.contains("addliquidity") || source.contains("removeliquidity")) &&
        (source.contains("liquidity") || source.contains("mint") || source.contains("burn"))
    }

    fn check_function(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> Vec<(String, Severity, String)> {
        let name = function.name.name.to_lowercase();
        let mut issues = Vec::new();
        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Check addLiquidity/mint functions
        if name.contains("addliquidity") || name.contains("mint") {
            // Check for timestamp/lock tracking
            let has_lock_time = source_lower.contains("locktime") ||
                source_lower.contains("deposittime") ||
                source_lower.contains("timestamp") && source_lower.contains("mapping");

            if !has_lock_time {
                issues.push((
                    "No liquidity lock time tracking (JIT attack risk)".to_string(),
                    Severity::High,
                    "Track lock time: mapping(address => uint256) public liquidityLockTime; liquidityLockTime[msg.sender] = block.timestamp;".to_string()
                ));
            }

            // Check for minimum liquidity duration
            let has_min_duration = source_lower.contains("min_lock") ||
                source_lower.contains("minimum_duration") ||
                (source_lower.contains("lock") && source_lower.contains("period"));

            if !has_min_duration {
                issues.push((
                    "No minimum lock period enforced (instant liquidity removal)".to_string(),
                    Severity::High,
                    "Enforce minimum: uint256 constant MIN_LOCK_PERIOD = 1 hours; // or appropriate duration".to_string()
                ));
            }

            // Check for LP token cooldown
            let has_cooldown = source_lower.contains("cooldown") ||
                source_lower.contains("withdrawal") && source_lower.contains("delay");

            if !has_cooldown {
                issues.push((
                    "No cooldown period between add and remove liquidity".to_string(),
                    Severity::Medium,
                    "Add cooldown: require(block.timestamp >= lastDeposit[msg.sender] + COOLDOWN_PERIOD, \"Cooldown active\");".to_string()
                ));
            }

            // Check for anti-sandwich protection
            let has_fee_on_entry = source_lower.contains("depositfee") ||
                source_lower.contains("entryfee");

            if !has_fee_on_entry {
                issues.push((
                    "No entry fee to discourage JIT liquidity provision".to_string(),
                    Severity::Low,
                    "Consider entry fee: Apply small fee on liquidity provision to make JIT attacks unprofitable".to_string()
                ));
            }
        }

        // Check removeLiquidity/burn functions
        if name.contains("removeliquidity") || name.contains("burn") {
            // Check for lock time validation
            let has_lock_check = (source_lower.contains("locktime") || source_lower.contains("deposittime")) &&
                (source_lower.contains("require") || source_lower.contains("block.timestamp"));

            if !has_lock_check {
                issues.push((
                    "No lock time validation on liquidity removal".to_string(),
                    Severity::Critical,
                    "Enforce lock: require(block.timestamp >= liquidityLockTime[msg.sender] + MIN_LOCK_PERIOD, \"Locked\");".to_string()
                ));
            }

            // Check for exit fee
            let has_exit_fee = source_lower.contains("exitfee") ||
                source_lower.contains("withdrawalfee") ||
                source_lower.contains("penalty");

            if !has_exit_fee {
                issues.push((
                    "No early exit fee (JIT attacks profitable)".to_string(),
                    Severity::Medium,
                    "Add exit fee: if (block.timestamp < lockTime + EXTENDED_PERIOD) { applyEarlyExitFee(); }".to_string()
                ));
            }

            // Check for same-block deposit/withdrawal protection
            let has_block_check = source_lower.contains("block.number") &&
                source_lower.contains("deposit") || source_lower.contains("lastblock");

            if !has_block_check {
                issues.push((
                    "No protection against same-block deposit and withdrawal".to_string(),
                    Severity::High,
                    "Block same-block: require(depositBlock[msg.sender] < block.number, \"Same block\");".to_string()
                ));
            }
        }

        // Check swap functions for JIT protection
        if name.contains("swap") {
            // Check if swap validates liquidity age
            let has_liquidity_age_check = source_lower.contains("liquidityage") ||
                (source_lower.contains("reserve") && source_lower.contains("timestamp"));

            if source_lower.contains("reserve") && !has_liquidity_age_check {
                issues.push((
                    "Swap doesn't validate liquidity age (JIT sandwich risk)".to_string(),
                    Severity::Medium,
                    "Validate age: Consider requiring minimum liquidity age or use TWAP prices".to_string()
                ));
            }

            // Check for multi-block TWAP
            let has_twap = source_lower.contains("twap") ||
                source_lower.contains("timeweighted") ||
                source_lower.contains("cumulative");

            if !has_twap {
                issues.push((
                    "No TWAP pricing (vulnerable to JIT manipulation)".to_string(),
                    Severity::High,
                    "Use TWAP: Implement time-weighted average price over multiple blocks".to_string()
                ));
            }
        }

        // Check for liquidity incentive structures
        if name.contains("stake") || name.contains("reward") {
            // Check for vesting period
            let has_vesting = source_lower.contains("vesting") ||
                source_lower.contains("cliff") ||
                (source_lower.contains("release") && source_lower.contains("time"));

            if !has_vesting {
                issues.push((
                    "No vesting period for liquidity rewards (JIT farming)".to_string(),
                    Severity::Medium,
                    "Add vesting: Implement vested rewards that unlock over time to encourage long-term LPs".to_string()
                ));
            }
        }

        // Check for concentrated liquidity (Uniswap V3 style)
        if name.contains("position") || source_lower.contains("ticklower") {
            // Check for position lock
            let has_position_lock = source_lower.contains("lock") ||
                source_lower.contains("freeze");

            if !has_position_lock {
                issues.push((
                    "Concentrated liquidity without position lock (JIT range orders)".to_string(),
                    Severity::High,
                    "Lock positions: Require minimum time before concentrated positions can be removed".to_string()
                ));
            }

            // Check for fee tier based on lock duration
            let has_dynamic_fees = source_lower.contains("feediscount") ||
                (source_lower.contains("fee") && source_lower.contains("duration"));

            if !has_dynamic_fees {
                issues.push((
                    "No fee incentive for long-term liquidity providers".to_string(),
                    Severity::Low,
                    "Dynamic fees: Reduce fees for LPs who lock liquidity for longer periods".to_string()
                ));
            }
        }

        issues
    }
}

impl Default for JitLiquidityDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for JitLiquidityDetector {
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

        if !self.is_liquidity_pool(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            let issues = self.check_function(function, ctx);
            for (message, severity, remediation) in issues {
                let finding = self.base.create_finding_with_severity(
                    ctx,
                    format!("{} in '{}'", message, function.name.name),
                    function.name.location.start().line() as u32,
                    0,
                    20,
                    severity,
                )
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
