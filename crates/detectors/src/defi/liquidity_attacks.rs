use crate::defi::{DeFiDetector, DeFiPatterns};
use crate::types::{
    AnalysisContext, Confidence, DetectorId, DetectorResult, Finding, Severity, SourceLocation,
};
use ast::Function;

/// Detector for liquidity-related attack vulnerabilities
pub struct LiquidityAttackDetector;

impl DeFiDetector for LiquidityAttackDetector {
    fn detect_defi_vulnerabilities(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        // Only analyze contracts that interact with liquidity mechanisms
        if !self.applies_to_contract(ctx) {
            return results;
        }

        results.extend(self.detect_liquidity_drain_attacks(ctx));
        results.extend(self.detect_impermanent_loss_amplification(ctx));
        results.extend(self.detect_liquidity_sniping_vulnerabilities(ctx));
        results.extend(self.detect_just_in_time_liquidity_attacks(ctx));
        results.extend(self.detect_liquidity_fragmentation_risks(ctx));
        results.extend(self.detect_vampire_attack_vulnerabilities(ctx));

        results
    }

    fn name(&self) -> &'static str {
        "liquidity-attack-detector"
    }

    fn description(&self) -> &'static str {
        "Detects vulnerabilities related to liquidity provision and management attacks"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn applies_to_contract(&self, ctx: &AnalysisContext) -> bool {
        self.manages_liquidity(ctx) || DeFiPatterns::interacts_with_amm(ctx)
    }
}

impl LiquidityAttackDetector {
    /// Detect liquidity drain attack vulnerabilities
    fn detect_liquidity_drain_attacks(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.is_liquidity_withdrawal_function(func) {
                let mut vulnerabilities = Vec::new();

                if !self.has_withdrawal_limits(ctx, func) {
                    vulnerabilities.push("No withdrawal limits");
                }

                if !self.has_slippage_protection(ctx, func) {
                    vulnerabilities.push("No slippage protection");
                }

                if !self.validates_liquidity_availability(ctx, func) {
                    vulnerabilities.push("No liquidity availability validation");
                }

                if self.allows_emergency_withdrawal(ctx, func)
                    && !self.has_emergency_controls(ctx, func)
                {
                    vulnerabilities.push("Uncontrolled emergency withdrawal");
                }

                if !vulnerabilities.is_empty() {
                    let finding = Finding::new(
                        DetectorId::new(self.name()),
                        Severity::High,
                        Confidence::High,
                        format!(
                            "Function '{}' is vulnerable to liquidity drain attacks: {}. \
                            This could allow attackers to extract disproportionate value from liquidity pools.",
                            func.name.as_str(),
                            vulnerabilities.join(", ")
                        ),
                        SourceLocation::new(
                            ctx.file_path.clone(),
                            func.location.start().line() as u32,
                            0,
                            func.name.as_str().len() as u32,
                        ),
                    ).with_cwe(682);

                    results.push(DetectorResult::new(finding)
                        .with_gas_impact("High - Large liquidity movements are gas-intensive".to_string())
                        .with_suggested_fix(
                            "Implement withdrawal limits, slippage protection, and proper liquidity validation".to_string()
                        ));
                }
            }
        }

        results
    }

    /// Detect impermanent loss amplification
    fn detect_impermanent_loss_amplification(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.manages_liquidity_positions(ctx, func)
                && self.has_impermanent_loss_amplification_risk(ctx, func)
            {
                let finding = Finding::new(
                    DetectorId::new(self.name()),
                    Severity::Medium,
                    Confidence::Medium,
                    format!(
                        "Function '{}' may amplify impermanent loss for liquidity providers \
                        through aggressive rebalancing or exposure to volatile token pairs.",
                        func.name.as_str()
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                )
                .with_cwe(682);

                results.push(DetectorResult::new(finding)
                    .with_gas_impact("Medium - Rebalancing operations require gas".to_string())
                    .with_suggested_fix(
                        "Implement impermanent loss protection mechanisms or clear risk disclosure".to_string()
                    ));
            }
        }

        results
    }

    /// Detect liquidity sniping vulnerabilities
    fn detect_liquidity_sniping_vulnerabilities(
        &self,
        ctx: &AnalysisContext,
    ) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.is_liquidity_addition_function(func)
                && !self.has_frontrunning_protection(ctx, func)
            {
                let finding = Finding::new(
                    DetectorId::new(self.name()),
                    Severity::Medium,
                    Confidence::Medium,
                    format!(
                        "Function '{}' allows liquidity addition without frontrunning protection. \
                        MEV bots can snipe profitable liquidity positions before legitimate users.",
                        func.name.as_str()
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                )
                .with_cwe(362);

                results.push(DetectorResult::new(finding)
                    .with_gas_impact("High - Frontrunning involves gas competition".to_string())
                    .with_suggested_fix(
                        "Implement commit-reveal schemes, minimum liquidity holding periods, or batch processing".to_string()
                    ));
            }
        }

        results
    }

    /// Detect just-in-time liquidity attacks
    fn detect_just_in_time_liquidity_attacks(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.is_reward_distribution_function(func)
                && self.vulnerable_to_jit_attacks(ctx, func)
            {
                let finding = Finding::new(
                    DetectorId::new(self.name()),
                    Severity::High,
                    Confidence::High,
                    format!(
                        "Function '{}' distributes rewards based on current liquidity snapshots. \
                        Attackers can add liquidity just before rewards and remove it immediately after.",
                        func.name.as_str()
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                ).with_cwe(362);

                results.push(DetectorResult::new(finding)
                    .with_gas_impact("Very High - Multiple add/remove operations in single block".to_string())
                    .with_suggested_fix(
                        "Use time-weighted liquidity calculations or minimum staking periods for rewards".to_string()
                    ));
            }
        }

        results
    }

    /// Detect liquidity fragmentation risks
    fn detect_liquidity_fragmentation_risks(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.creates_multiple_pools(ctx, func) && !self.has_liquidity_aggregation(ctx, func)
            {
                let finding = Finding::new(
                    DetectorId::new(self.name()),
                    Severity::Medium,
                    Confidence::Low,
                    format!(
                        "Function '{}' creates multiple liquidity pools for the same assets \
                        without aggregation mechanisms, leading to fragmented liquidity and worse pricing.",
                        func.name.as_str()
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                ).with_cwe(682);

                results.push(
                    DetectorResult::new(finding)
                        .with_gas_impact(
                            "Medium - Multiple pool interactions increase gas costs".to_string(),
                        )
                        .with_suggested_fix(
                            "Implement liquidity aggregation or routing to prevent fragmentation"
                                .to_string(),
                        ),
                );
            }
        }

        results
    }

    /// Detect vampire attack vulnerabilities
    fn detect_vampire_attack_vulnerabilities(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.offers_migration_incentives(ctx, func)
                && self.has_excessive_migration_rewards(ctx, func)
            {
                let finding = Finding::new(
                    DetectorId::new(self.name()),
                    Severity::Medium,
                    Confidence::Low,
                    format!(
                        "Function '{}' offers excessive incentives for liquidity migration \
                        that could be exploited to drain value from the protocol through \
                        cyclical migrations.",
                        func.name.as_str()
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                )
                .with_cwe(682);

                results.push(DetectorResult::new(finding)
                    .with_gas_impact("High - Migration operations involve complex interactions".to_string())
                    .with_suggested_fix(
                        "Implement reasonable migration incentive caps and anti-gaming mechanisms".to_string()
                    ));
            }
        }

        results
    }

    // Helper methods for liquidity attack detection

    fn manages_liquidity(&self, ctx: &AnalysisContext) -> bool {
        let liquidity_indicators = [
            "liquidity",
            "addLiquidity",
            "removeLiquidity",
            "stake",
            "unstake",
            "deposit",
            "withdraw",
            "pool",
            "reserve",
        ];
        liquidity_indicators
            .iter()
            .any(|&indicator| ctx.source_code.to_lowercase().contains(indicator))
    }

    fn is_liquidity_withdrawal_function(&self, func: &Function) -> bool {
        let withdrawal_patterns = ["removeLiquidity", "withdraw", "unstake", "exit", "redeem"];
        withdrawal_patterns
            .iter()
            .any(|&pattern| func.name.as_str().to_lowercase().contains(pattern))
    }

    fn is_liquidity_addition_function(&self, func: &Function) -> bool {
        let addition_patterns = ["addLiquidity", "deposit", "stake", "provide", "supply"];
        addition_patterns
            .iter()
            .any(|&pattern| func.name.as_str().to_lowercase().contains(pattern))
    }

    fn has_withdrawal_limits(&self, ctx: &AnalysisContext, _func: &Function) -> bool {
        let limit_patterns = [
            "maxWithdraw",
            "withdrawLimit",
            "dailyLimit",
            "cap",
            "maximum",
        ];
        limit_patterns
            .iter()
            .any(|&pattern| ctx.source_code.contains(pattern))
    }

    fn has_slippage_protection(&self, ctx: &AnalysisContext, _func: &Function) -> bool {
        let slippage_patterns = ["slippage", "minAmount", "maxSlippage", "tolerance"];
        slippage_patterns
            .iter()
            .any(|&pattern| ctx.source_code.contains(pattern))
    }

    fn validates_liquidity_availability(&self, ctx: &AnalysisContext, _func: &Function) -> bool {
        let validation_patterns = [
            "require(balance",
            "availableLiquidity",
            "checkLiquidity",
            "sufficientLiquidity",
        ];
        validation_patterns
            .iter()
            .any(|&pattern| ctx.source_code.contains(pattern))
    }

    fn allows_emergency_withdrawal(&self, _ctx: &AnalysisContext, func: &Function) -> bool {
        let emergency_patterns = ["emergency", "panic", "drain", "rescue", "recover"];
        emergency_patterns
            .iter()
            .any(|&pattern| func.name.as_str().to_lowercase().contains(pattern))
    }

    fn has_emergency_controls(&self, ctx: &AnalysisContext, _func: &Function) -> bool {
        let control_patterns = ["onlyOwner", "onlyAdmin", "multisig", "timelock", "pause"];
        control_patterns
            .iter()
            .any(|&pattern| ctx.source_code.contains(pattern))
    }

    fn manages_liquidity_positions(&self, _ctx: &AnalysisContext, func: &Function) -> bool {
        let position_patterns = ["position", "rebalance", "allocate", "distribute", "manage"];
        position_patterns
            .iter()
            .any(|&pattern| func.name.as_str().to_lowercase().contains(pattern))
    }

    fn has_impermanent_loss_amplification_risk(
        &self,
        ctx: &AnalysisContext,
        _func: &Function,
    ) -> bool {
        let risk_indicators = [
            "leverage",
            "amplify",
            "volatile",
            "aggressive",
            "high-frequency",
        ];
        risk_indicators
            .iter()
            .any(|&indicator| ctx.source_code.to_lowercase().contains(indicator))
    }

    fn has_frontrunning_protection(&self, ctx: &AnalysisContext, _func: &Function) -> bool {
        let protection_patterns = ["commitReveal", "timelock", "batch", "private", "deadline"];
        protection_patterns
            .iter()
            .any(|&pattern| ctx.source_code.contains(pattern))
    }

    fn is_reward_distribution_function(&self, func: &Function) -> bool {
        let reward_patterns = ["distribute", "reward", "claim", "harvest", "payout"];
        reward_patterns
            .iter()
            .any(|&pattern| func.name.as_str().to_lowercase().contains(pattern))
    }

    fn vulnerable_to_jit_attacks(&self, ctx: &AnalysisContext, _func: &Function) -> bool {
        let jit_vulnerability_patterns = ["snapshot", "current", "now", "block.timestamp"];
        jit_vulnerability_patterns
            .iter()
            .any(|&pattern| ctx.source_code.contains(pattern))
            && !self.has_time_weighted_rewards(ctx)
    }

    fn has_time_weighted_rewards(&self, ctx: &AnalysisContext) -> bool {
        let time_weighted_patterns = [
            "timeWeighted",
            "duration",
            "period",
            "accumulated",
            "average",
        ];
        time_weighted_patterns
            .iter()
            .any(|&pattern| ctx.source_code.contains(pattern))
    }

    fn creates_multiple_pools(&self, _ctx: &AnalysisContext, func: &Function) -> bool {
        let pool_creation_patterns = ["createPool", "newPool", "deployPool", "initializePool"];
        pool_creation_patterns
            .iter()
            .any(|&pattern| func.name.as_str().contains(pattern))
    }

    fn has_liquidity_aggregation(&self, ctx: &AnalysisContext, _func: &Function) -> bool {
        let aggregation_patterns = ["aggregate", "route", "combine", "merge", "consolidate"];
        aggregation_patterns
            .iter()
            .any(|&pattern| ctx.source_code.contains(pattern))
    }

    fn offers_migration_incentives(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        let migration_patterns = [
            "migrate",
            "transfer",
            "move",
            "switch",
            "incentive",
            "bonus",
        ];
        migration_patterns.iter().any(|&pattern| {
            func.name.as_str().to_lowercase().contains(pattern)
                || ctx.source_code.to_lowercase().contains(pattern)
        })
    }

    fn has_excessive_migration_rewards(&self, ctx: &AnalysisContext, _func: &Function) -> bool {
        // This would require more sophisticated analysis of reward calculations
        // For now, check for large bonus percentages or unlimited rewards
        let excessive_reward_patterns = ["bonus", "multiplier", "100%", "unlimited", "uncapped"];
        excessive_reward_patterns
            .iter()
            .any(|&pattern| ctx.source_code.contains(pattern))
    }
}

// TODO: Update tests to use new AST-based approach
/*
#[cfg(test)]
mod tests {

//    #[test]
//    fn test_liquidity_withdrawal_detection() {
        let detector = LiquidityAttackDetector;

        let func = Function {
            name: "removeLiquidity".to_string(),
            visibility: Some("external".to_string()),
            line_number: 10,
            parameters: Vec::new(),
            returns: Vec::new(),
        };

        assert!(detector.is_liquidity_withdrawal_function(&func));
    }

//    #[test]
//    fn test_liquidity_addition_detection() {
        let detector = LiquidityAttackDetector;

        let func = Function {
            name: "addLiquidity".to_string(),
            visibility: Some("external".to_string()),
            line_number: 10,
            parameters: Vec::new(),
            returns: Vec::new(),
        };

        assert!(detector.is_liquidity_addition_function(&func));
    }

//    #[test]
//    fn test_detector_properties() {
        let detector = LiquidityAttackDetector;
        assert_eq!(detector.name(), "liquidity-attack-detector");
        assert_eq!(detector.severity(), Severity::High);
        assert!(!detector.description().is_empty());
    }

//    #[test]
//    fn test_jit_vulnerability_detection() {
        let detector = LiquidityAttackDetector;

        let mut ctx = create_mock_context();
        ctx.source = "function distribute() { uint snapshot = block.timestamp; }".to_string();

        let func = Function {
            name: "distribute".to_string(),
            visibility: Some("external".to_string()),
            line_number: 10,
            parameters: Vec::new(),
            returns: Vec::new(),
        };

        assert!(detector.is_reward_distribution_function(&func));
        assert!(detector.vulnerable_to_jit_attacks(&ctx, &func));
    }
}*/
