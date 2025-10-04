use crate::types::{DetectorResult, AnalysisContext, Severity, Finding, DetectorId, Confidence, SourceLocation};
use ast::Function;
use crate::defi::{DeFiDetector, DeFiPatterns};

/// Detector for MEV (Maximal Extractable Value) vulnerabilities
pub struct MEVDetector;

impl DeFiDetector for MEVDetector {
    fn detect_defi_vulnerabilities(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        // Only analyze DeFi contracts that could be subject to MEV
        if !self.applies_to_contract(ctx) {
            return results;
        }

        // Check for various MEV vulnerabilities
        results.extend(self.detect_frontrunning_vulnerabilities(ctx));
        results.extend(self.detect_sandwich_attack_risks(ctx));
        results.extend(self.detect_back_running_opportunities(ctx));
        results.extend(self.detect_priority_gas_auction_risks(ctx));
        results.extend(self.detect_atomic_arbitrage_exposure(ctx));
        results.extend(self.detect_liquidation_mev_risks(ctx));

        results
    }

    fn name(&self) -> &'static str {
        "mev-detector"
    }

    fn description(&self) -> &'static str {
        "Detects MEV (Maximal Extractable Value) vulnerabilities and extraction opportunities"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn applies_to_contract(&self, ctx: &AnalysisContext) -> bool {
        // MEV applies to contracts that:
        // 1. Interact with AMMs/DEXs
        // 2. Have price-dependent logic
        // 3. Manage significant value
        // 4. Have time-dependent operations
        DeFiPatterns::interacts_with_amm(ctx) ||
        DeFiPatterns::has_oracle_dependencies(ctx) ||
        DeFiPatterns::manages_significant_value(ctx) ||
        DeFiPatterns::has_time_dependencies(ctx)
    }
}

impl MEVDetector {
    /// Detect frontrunning vulnerabilities
    fn detect_frontrunning_vulnerabilities(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            // Check for functions vulnerable to frontrunning
            if self.is_frontrunnable_function(ctx, func) {
                let vulnerability_type = self.classify_frontrunning_risk(ctx, func);

                let confidence_val = self.assess_frontrunning_confidence(ctx, func);
                let confidence = if confidence_val >= 0.9 {
                    Confidence::High
                } else if confidence_val >= 0.7 {
                    Confidence::Medium
                } else {
                    Confidence::Low
                };

                let finding = Finding::new(
                    DetectorId::new(self.name()),
                    self.assess_frontrunning_severity(&vulnerability_type),
                    confidence,
                    format!(
                        "Function '{}' is vulnerable to frontrunning attacks. {}",
                        func.name.as_str(),
                        self.get_frontrunning_description(&vulnerability_type)
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                ).with_cwe(362);

                results.push(DetectorResult::new(finding)
                    .with_gas_impact("High - Vulnerable to gas price manipulation".to_string())
                    .with_suggested_fix(self.get_frontrunning_mitigation(&vulnerability_type)));
            }
        }

        results
    }

    /// Detect sandwich attack risks
    fn detect_sandwich_attack_risks(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.is_vulnerable_to_sandwich_attacks(ctx, func) {
                let finding = Finding::new(
                    DetectorId::new(self.name()),
                    Severity::High,
                    Confidence::High,
                    format!(
                        "Function '{}' performs price-dependent operations without slippage protection. \
                        This allows MEV bots to sandwich the transaction for profit at user's expense.",
                        func.name.as_str()
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                ).with_cwe(682);

                results.push(DetectorResult::new(finding)
                    .with_gas_impact("High - Multiple transactions required for attack".to_string())
                    .with_suggested_fix(
                        "Implement slippage protection, deadline checks, or commit-reveal schemes \
                        to prevent sandwich attacks".to_string()
                    ));
            }
        }

        results
    }

    /// Detect back-running opportunities
    fn detect_back_running_opportunities(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.creates_backrunning_opportunity(ctx, func) {
                let finding = Finding::new(
                    DetectorId::new(self.name()),
                    Severity::Medium,
                    Confidence::Low,
                    format!(
                        "Function '{}' creates state changes that can be profitably back-run by MEV bots. \
                        This may indicate leaking value to extractors.",
                        func.name.as_str()
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                ).with_cwe(682);

                results.push(DetectorResult::new(finding)
                    .with_gas_impact("Medium - Depends on state change complexity".to_string())
                    .with_suggested_fix(
                        "Consider batching operations or implementing MEV-resistant mechanisms \
                        to capture value for users".to_string()
                    ));
            }
        }

        results
    }

    /// Detect priority gas auction risks
    fn detect_priority_gas_auction_risks(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.is_susceptible_to_pga(ctx, func) {
                let finding = Finding::new(
                    DetectorId::new(self.name()),
                    Severity::Medium,
                    Confidence::Medium,
                    format!(
                        "Function '{}' is susceptible to Priority Gas Auctions where users \
                        compete with increasing gas prices, potentially leading to failed transactions \
                        and wasted gas.",
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
                    .with_gas_impact("Very High - Users may waste significant gas in auctions".to_string())
                    .with_suggested_fix(
                        "Implement fair queuing mechanisms, batch processing, or other PGA-resistant designs".to_string()
                    ));
            }
        }

        results
    }

    /// Detect atomic arbitrage exposure
    fn detect_atomic_arbitrage_exposure(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.enables_atomic_arbitrage(ctx, func) {
                let finding = Finding::new(
                    DetectorId::new(self.name()),
                    Severity::Medium,
                    Confidence::Medium,
                    format!(
                        "Function '{}' enables atomic arbitrage opportunities within the same transaction. \
                        This may lead to value extraction from the protocol or its users.",
                        func.name.as_str()
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                ).with_cwe(682);

                results.push(DetectorResult::new(finding)
                    .with_gas_impact("High - Complex arbitrage transactions".to_string())
                    .with_suggested_fix(
                        "Consider implementing arbitrage resistance through time delays, \
                        minimum holding periods, or profit-sharing mechanisms".to_string()
                    ));
            }
        }

        results
    }

    /// Detect liquidation MEV risks
    fn detect_liquidation_mev_risks(&self, ctx: &AnalysisContext) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        for func in &ctx.contract.functions {
            if self.is_liquidation_function(func) && self.has_mev_extractable_liquidation(ctx, func) {
                let finding = Finding::new(
                    DetectorId::new(self.name()),
                    Severity::Medium,
                    Confidence::Medium,
                    format!(
                        "Liquidation function '{}' may provide excessive rewards to liquidators, \
                        creating MEV extraction opportunities at the expense of liquidated users.",
                        func.name.as_str()
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                ).with_cwe(682);

                results.push(DetectorResult::new(finding)
                    .with_gas_impact("Medium - Liquidation transaction complexity".to_string())
                    .with_suggested_fix(
                        "Implement fair liquidation mechanisms such as auctions, \
                        graduated penalties, or profit sharing".to_string()
                    ));
            }
        }

        results
    }

    // Helper methods for MEV pattern detection

    fn is_frontrunnable_function(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        // Functions that create frontrunning opportunities
        let frontrunnable_patterns = [
            "approve", "transfer", "swap", "trade", "buy", "sell",
            "mint", "burn", "deposit", "withdraw", "claim"
        ];

        frontrunnable_patterns.iter().any(|&pattern|
            func.name.as_str().to_lowercase().contains(pattern)
        ) && !self.has_frontrunning_protection(ctx, func)
    }

    fn classify_frontrunning_risk(&self, _ctx: &AnalysisContext, func: &Function) -> String {
        if func.name.as_str().to_lowercase().contains("approve") {
            "Approval frontrunning".to_string()
        } else if func.name.as_str().to_lowercase().contains("swap") || func.name.as_str().to_lowercase().contains("trade") {
            "Trade frontrunning".to_string()
        } else if func.name.as_str().to_lowercase().contains("mint") || func.name.as_str().to_lowercase().contains("burn") {
            "Token issuance frontrunning".to_string()
        } else {
            "General frontrunning".to_string()
        }
    }

    fn assess_frontrunning_severity(&self, vulnerability_type: &str) -> Severity {
        match vulnerability_type {
            "Approval frontrunning" => Severity::High,
            "Trade frontrunning" => Severity::High,
            "Token issuance frontrunning" => Severity::Medium,
            _ => Severity::Medium,
        }
    }

    fn assess_frontrunning_confidence(&self, ctx: &AnalysisContext, func: &Function) -> f64 {
        let mut confidence: f64 = 0.6;

        // Increase confidence if function is public/external
        if matches!(func.visibility, ast::Visibility::Public | ast::Visibility::External) {
            confidence += 0.2;
        }

        // Increase confidence if function affects valuable state
        if DeFiPatterns::manages_significant_value(ctx) {
            confidence += 0.1;
        }

        confidence.min(0.95)
    }

    fn get_frontrunning_description(&self, vulnerability_type: &str) -> String {
        match vulnerability_type {
            "Approval frontrunning" =>
                "Attackers can observe approval transactions and front-run them to exploit allowances.".to_string(),
            "Trade frontrunning" =>
                "Traders can observe pending transactions and front-run them to extract value.".to_string(),
            "Token issuance frontrunning" =>
                "MEV bots can front-run token minting/burning to profit from price changes.".to_string(),
            _ =>
                "Transactions can be front-run by MEV bots for profit extraction.".to_string(),
        }
    }

    fn get_frontrunning_mitigation(&self, vulnerability_type: &str) -> String {
        match vulnerability_type {
            "Approval frontrunning" =>
                "Use increaseAllowance/decreaseAllowance or implement atomic approve patterns".to_string(),
            "Trade frontrunning" =>
                "Implement commit-reveal schemes, time delays, or private mempools".to_string(),
            "Token issuance frontrunning" =>
                "Use batch processing or time-based restrictions on token operations".to_string(),
            _ =>
                "Implement MEV-resistant patterns such as commit-reveal or batch processing".to_string(),
        }
    }

    fn is_vulnerable_to_sandwich_attacks(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        // Functions that perform swaps without adequate slippage protection
        let swap_patterns = ["swap", "trade", "exchange"];
        let slippage_patterns = ["slippage", "minAmount", "deadline", "maxPrice"];

        let is_swap_function = swap_patterns.iter().any(|&pattern|
            func.name.as_str().to_lowercase().contains(pattern)
        );

        let has_slippage_protection = slippage_patterns.iter().any(|&pattern|
            ctx.source_code.to_lowercase().contains(pattern)
        );

        is_swap_function && !has_slippage_protection
    }

    fn creates_backrunning_opportunity(&self, _ctx: &AnalysisContext, func: &Function) -> bool {
        // Functions that create profitable state changes
        let backrunnable_patterns = [
            "updatePrice", "sync", "rebalance", "liquidate", "harvest"
        ];

        backrunnable_patterns.iter().any(|&pattern|
            func.name.as_str().to_lowercase().contains(pattern)
        )
    }

    fn is_susceptible_to_pga(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        // Functions with limited opportunity windows
        let pga_patterns = [
            "claim", "redeem", "liquidate", "arbitrage", "flashLoan"
        ];

        pga_patterns.iter().any(|&pattern|
            func.name.as_str().to_lowercase().contains(pattern)
        ) && DeFiPatterns::has_time_dependencies(ctx)
    }

    fn enables_atomic_arbitrage(&self, ctx: &AnalysisContext, func: &Function) -> bool {
        // Functions that allow complex multi-step operations
        let arbitrage_enablers = [
            "multicall", "batch", "swap", "flashLoan"
        ];

        arbitrage_enablers.iter().any(|&pattern|
            func.name.as_str().to_lowercase().contains(pattern)
        ) && DeFiPatterns::interacts_with_amm(ctx)
    }

    fn is_liquidation_function(&self, func: &Function) -> bool {
        let liquidation_patterns = ["liquidat", "seize", "repay", "foreclose"];
        liquidation_patterns.iter().any(|&pattern|
            func.name.as_str().to_lowercase().contains(pattern)
        )
    }

    fn has_mev_extractable_liquidation(&self, ctx: &AnalysisContext, _func: &Function) -> bool {
        // Check if liquidation provides excessive rewards
        let reward_indicators = ["bonus", "incentive", "reward", "discount"];
        reward_indicators.iter().any(|&indicator|
            ctx.source_code.to_lowercase().contains(indicator)
        )
    }

    fn has_frontrunning_protection(&self, ctx: &AnalysisContext, _func: &Function) -> bool {
        let protection_patterns = [
            "commitReveal", "timelock", "nonce", "deadline", "private"
        ];
        protection_patterns.iter().any(|&pattern|
            ctx.source_code.to_lowercase().contains(pattern)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::test_utils::*;
    use ast::{AstArena, Visibility, StateMutability};

    #[test]
    fn test_frontrunning_detection() {
        let detector = MEVDetector;
        let arena = AstArena::new();

        // Create mock AST function that detectors expect
        let function = create_mock_ast_function(
            &arena,
            "swapTokens",
            Visibility::Public,
            StateMutability::NonPayable,
        );

        let contract = create_mock_ast_contract(&arena, "TestContract", vec![function]);

        let ctx = AnalysisContext {
            contract: &contract,
            symbols: semantic::SymbolTable::new(),
            source_code: "".to_string(),
            file_path: "test.sol".to_string(),
        };

        assert!(detector.is_frontrunnable_function(&ctx, &ctx.contract.functions[0]));
    }

    #[test]
    fn test_mev_detector_properties() {
        let detector = MEVDetector;
        assert_eq!(detector.name(), "mev-detector");
        assert_eq!(detector.severity(), Severity::Medium);
        assert!(!detector.description().is_empty());
    }


}