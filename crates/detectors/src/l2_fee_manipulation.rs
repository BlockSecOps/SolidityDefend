use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for L2 fee manipulation vulnerabilities
pub struct L2FeeManipulationDetector {
    base: BaseDetector,
}

impl L2FeeManipulationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("l2-fee-manipulation".to_string()),
                "L2 Fee Manipulation".to_string(),
                "Detects vulnerabilities in L2 fee mechanisms including unbounded oracle-based fees, front-runnable fee updates, and lack of fee bounds that could lead to economic attacks or denial of service".to_string(),
                vec![DetectorCategory::L2, DetectorCategory::DeFi],
                Severity::Medium,
            ),
        }
    }
}

impl Detector for L2FeeManipulationDetector {
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

        // FP Reduction: Only fire on contracts with actual L2-specific patterns.
        // Generic fee functions in AMM pools, vaults, and flash loan providers
        // are not L2 fee manipulation vulnerabilities.
        let source_lower = ctx.source_code.to_lowercase();
        let has_l2_context = source_lower.contains("l1fee")
            || source_lower.contains("l2fee")
            || source_lower.contains("l1datafee")
            || source_lower.contains("l1block")
            || source_lower.contains("sequencer")
            || source_lower.contains("crossdomain")
            || source_lower.contains("l2messenger")
            || source_lower.contains("rollup")
            || source_lower.contains("optimism")
            || source_lower.contains("arbitrum")
            || source_lower.contains("zksync")
            || source_lower.contains("basefee") && source_lower.contains("l1")
            || source_lower.contains("gaspriceoracle")
            || source_lower.contains("l1gasoracle")
            || source_lower.contains("l2outputoracle");
        if !has_l2_context {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            // Skip internal/private functions
            if !self.is_external_or_public(function) {
                continue;
            }

            let func_source = self.get_function_source(function, ctx);

            // Check for fee calculation functions
            if self.is_fee_calculation_function(function.name.name, &func_source) {
                let issues = self.check_fee_bounds(&func_source);

                for issue in issues {
                    let message = format!(
                        "Function '{}' calculates fees without proper bounds. {} \
                        Unbounded fees can lead to excessive charges or economic DoS attacks.",
                        function.name.name, issue
                    );

                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            function.name.location.start().line() as u32,
                            function.name.location.start().column() as u32,
                            function.name.name.len() as u32,
                        )
                        .with_cwe(682) // CWE-682: Incorrect Calculation
                        .with_fix_suggestion(format!(
                            "Add fee bounds to '{}': \
                            (1) Define MIN_FEE and MAX_FEE constants, \
                            (2) Implement require(fee >= MIN_FEE && fee <= MAX_FEE), \
                            (3) Add overflow protection in fee calculations, \
                            (4) Consider using safe math library, \
                            (5) Implement fee caps per transaction type.",
                            function.name.name
                        ));

                    findings.push(finding);
                }
            }

            // Check for fee update functions
            if self.is_fee_update_function(function.name.name, &func_source) {
                let issues = self.check_fee_update_protection(&func_source);

                for issue in issues {
                    let message = format!(
                        "Function '{}' updates fees without proper protections. {} \
                        Vulnerable fee updates can be front-run or manipulated to extract value.",
                        function.name.name, issue
                    );

                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            function.name.location.start().line() as u32,
                            function.name.location.start().column() as u32,
                            function.name.name.len() as u32,
                        )
                        .with_cwe(362) // CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
                        .with_fix_suggestion(format!(
                            "Protect fee updates in '{}': \
                            (1) Implement time-delayed fee changes with announcement period, \
                            (2) Add governance or multi-sig control for fee updates, \
                            (3) Limit rate of fee changes (e.g., max 10% per day), \
                            (4) Emit events before fee changes take effect, \
                            (5) Consider using commit-reveal scheme for fee updates.",
                            function.name.name
                        ));

                    findings.push(finding);
                }
            }

            // Check for oracle-based fee functions
            if self.is_oracle_fee_function(function.name.name, &func_source) {
                let issues = self.check_oracle_fee_security(&func_source);

                for issue in issues {
                    let message = format!(
                        "Function '{}' uses oracle for fee calculation with inadequate safeguards. {} \
                        Oracle manipulation can lead to incorrect fees and economic attacks.",
                        function.name.name, issue
                    );

                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            function.name.location.start().line() as u32,
                            function.name.location.start().column() as u32,
                            function.name.name.len() as u32,
                        )
                        .with_cwe(20) // CWE-20: Improper Input Validation
                        .with_fix_suggestion(format!(
                            "Strengthen oracle fee security in '{}': \
                            (1) Validate oracle price is within reasonable bounds, \
                            (2) Use time-weighted average price (TWAP) to prevent manipulation, \
                            (3) Implement circuit breakers for extreme price movements, \
                            (4) Check oracle data freshness/staleness, \
                            (5) Use multiple oracle sources and median pricing.",
                            function.name.name
                        ));

                    findings.push(finding);
                }
            }

            // Check for dynamic fee functions
            if self.is_dynamic_fee_function(function.name.name, &func_source) {
                let issues = self.check_dynamic_fee_logic(&func_source);

                for issue in issues {
                    let message = format!(
                        "Function '{}' implements dynamic fees without proper constraints. {} \
                        Unconstrained dynamic fees can be exploited or cause unexpected behavior.",
                        function.name.name, issue
                    );

                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            function.name.location.start().line() as u32,
                            function.name.location.start().column() as u32,
                            function.name.name.len() as u32,
                        )
                        .with_cwe(682) // CWE-682: Incorrect Calculation
                        .with_fix_suggestion(format!(
                            "Add constraints to dynamic fees in '{}': \
                            (1) Cap maximum fee adjustment per block/time period, \
                            (2) Implement smoothing function to prevent sudden spikes, \
                            (3) Add sanity checks on input parameters, \
                            (4) Test edge cases and extreme market conditions, \
                            (5) Consider EIP-1559 style fee market design.",
                            function.name.name
                        ));

                    findings.push(finding);
                }
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl L2FeeManipulationDetector {
    fn is_external_or_public(&self, function: &ast::Function<'_>) -> bool {
        function.visibility == ast::Visibility::External
            || function.visibility == ast::Visibility::Public
    }

    fn is_fee_calculation_function(&self, name: &str, source: &str) -> bool {
        let patterns = [
            "calculateFee",
            "computeFee",
            "getFee",
            "estimateFee",
            "calculateL1Fee",
            "calculateL2Fee",
        ];

        let name_lower = name.to_lowercase();
        patterns
            .iter()
            .any(|pattern| name_lower.contains(&pattern.to_lowercase()))
            || (source.contains("fee")
                && (source.contains("calculate") || source.contains("compute")))
    }

    fn is_fee_update_function(&self, name: &str, source: &str) -> bool {
        let patterns = [
            "setFee",
            "updateFee",
            "setBaseFee",
            "updateBaseFee",
            "setGasPrice",
            "updateScalar",
        ];

        let name_lower = name.to_lowercase();
        patterns
            .iter()
            .any(|pattern| name_lower.contains(&pattern.to_lowercase()))
            || (source.contains("fee") && (source.contains(" = ") || source.contains("update")))
    }

    fn is_oracle_fee_function(&self, name: &str, source: &str) -> bool {
        let patterns = ["getL1FeeOracle", "getGasPriceOracle", "fetchL1BaseFee"];

        let name_lower = name.to_lowercase();
        patterns
            .iter()
            .any(|pattern| name_lower.contains(&pattern.to_lowercase()))
            || (source.contains("oracle") && source.contains("fee"))
    }

    fn is_dynamic_fee_function(&self, name: &str, source: &str) -> bool {
        let patterns = ["adjustFee", "updateDynamicFee", "calculateDynamicFee"];

        let name_lower = name.to_lowercase();
        patterns
            .iter()
            .any(|pattern| name_lower.contains(&pattern.to_lowercase()))
            || (source.contains("baseFee") && source.contains("gasUsed"))
    }

    fn check_fee_bounds(&self, source: &str) -> Vec<String> {
        let mut issues = Vec::new();

        // Pattern 1: No upper bound check
        if (source.contains("fee") || source.contains("Fee"))
            && !source.contains("MAX_FEE")
            && !source.contains("<=")
        {
            issues.push(
                "No maximum fee bound. Should define MAX_FEE constant and enforce: require(fee <= MAX_FEE)"
                    .to_string(),
            );
        }

        // Pattern 2: No lower bound check
        if (source.contains("fee") || source.contains("Fee"))
            && !source.contains("MIN_FEE")
            && !source.contains(">=")
        {
            issues.push(
                "No minimum fee bound. Should define MIN_FEE to prevent zero or negative fees"
                    .to_string(),
            );
        }

        // Pattern 3: Potential overflow in multiplication
        if source.contains("*") && !source.contains("checked") && !source.contains("SafeMath") {
            issues.push(
                "Potential overflow in fee calculation. Use checked arithmetic or SafeMath library"
                    .to_string(),
            );
        }

        // Pattern 4: Division without zero check
        if source.contains("/") && !source.contains("require") && !source.contains("if") {
            issues.push(
                "Division in fee calculation without zero check. Could cause revert or incorrect fees"
                    .to_string(),
            );
        }

        issues
    }

    fn check_fee_update_protection(&self, source: &str) -> Vec<String> {
        let mut issues = Vec::new();

        // Pattern 1: No access control
        if !source.contains("onlyOwner")
            && !source.contains("onlyGovernance")
            && !source.contains("require(msg.sender")
            && !source.contains("onlyAdmin")
        {
            issues.push(
                "No access control on fee updates. Anyone can modify fees leading to manipulation"
                    .to_string(),
            );
        }

        // Pattern 2: Immediate effect without delay
        if !source.contains("timestamp")
            && !source.contains("delay")
            && !source.contains("timelock")
        {
            issues.push(
                "Fee updates take immediate effect. Should implement time delay to prevent front-running"
                    .to_string(),
            );
        }

        // Pattern 3: No event emission
        if !source.contains("emit") {
            issues.push(
                "No event emission for fee updates. Users cannot track fee changes or prepare for them"
                    .to_string(),
            );
        }

        // Pattern 4: No rate limiting
        if !source.contains("lastUpdate") && !source.contains("cooldown") {
            issues.push(
                "No rate limiting on fee updates. Fees could be changed too frequently causing instability"
                    .to_string(),
            );
        }

        // Pattern 5: No bounds on new fee value
        if source.contains(" = ") && !source.contains("require") && !source.contains("<=") {
            issues.push(
                "No validation of new fee value. Should enforce reasonable bounds on fee changes"
                    .to_string(),
            );
        }

        issues
    }

    fn check_oracle_fee_security(&self, source: &str) -> Vec<String> {
        let mut issues = Vec::new();

        // Pattern 1: No price bounds validation
        if source.contains("oracle") && !source.contains("require") {
            issues.push(
                "No validation of oracle price. Should check price is within reasonable bounds"
                    .to_string(),
            );
        }

        // Pattern 2: No freshness check
        if source.contains("oracle")
            && !source.contains("timestamp")
            && !source.contains("updatedAt")
        {
            issues.push(
                "No staleness check for oracle data. Should verify price was updated recently"
                    .to_string(),
            );
        }

        // Pattern 3: Single oracle source
        if source.contains("oracle") && !source.contains("median") && !source.contains("multiple") {
            issues.push(
                "Single oracle source. Consider using multiple oracles and median price for robustness"
                    .to_string(),
            );
        }

        // Pattern 4: No circuit breaker
        if source.contains("oracle")
            && !source.contains("circuitBreaker")
            && !source.contains("paused")
        {
            issues.push(
                "No circuit breaker for extreme price movements. Should pause or limit fees on anomalous prices"
                    .to_string(),
            );
        }

        // Pattern 5: No TWAP usage
        if source.contains("oracle") && !source.contains("twap") && !source.contains("average") {
            issues.push(
                "Direct oracle price usage. Consider TWAP to prevent flash manipulation attacks"
                    .to_string(),
            );
        }

        issues
    }

    fn check_dynamic_fee_logic(&self, source: &str) -> Vec<String> {
        let mut issues = Vec::new();

        // Pattern 1: Unbounded adjustment
        if (source.contains("increase") || source.contains("decrease")) && !source.contains("MAX_")
        {
            issues.push(
                "Unbounded fee adjustment. Should cap maximum increase/decrease per adjustment"
                    .to_string(),
            );
        }

        // Pattern 2: No smoothing
        if source.contains("baseFee") && !source.contains("smooth") && !source.contains("average") {
            issues.push(
                "No smoothing in fee adjustment. Sudden changes can cause UX issues and exploits"
                    .to_string(),
            );
        }

        // Pattern 3: Missing parameter validation
        if (source.contains("gasUsed") || source.contains("gasTarget"))
            && !source.contains("require")
        {
            issues.push(
                "No validation of input parameters. Should verify gasUsed and other inputs are valid"
                    .to_string(),
            );
        }

        // Pattern 4: No minimum change threshold
        if source.contains("baseFee")
            && !source.contains("MIN_CHANGE")
            && !source.contains("threshold")
        {
            issues.push(
                "No minimum change threshold. Tiny adjustments can be gas inefficient".to_string(),
            );
        }

        issues
    }

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

impl Default for L2FeeManipulationDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = L2FeeManipulationDetector::new();
        assert_eq!(detector.name(), "L2 Fee Manipulation");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
        assert_eq!(detector.id().0, "l2-fee-manipulation");
        assert!(detector.categories().contains(&DetectorCategory::L2));
        assert!(detector.categories().contains(&DetectorCategory::DeFi));
    }

    #[test]
    fn test_is_fee_calculation_function() {
        let detector = L2FeeManipulationDetector::new();

        assert!(detector.is_fee_calculation_function("calculateFee", ""));
        assert!(detector.is_fee_calculation_function("computeFee", ""));
        assert!(detector.is_fee_calculation_function("getFee", ""));
        assert!(!detector.is_fee_calculation_function("withdraw", ""));
    }

    #[test]
    fn test_is_fee_update_function() {
        let detector = L2FeeManipulationDetector::new();

        assert!(detector.is_fee_update_function("setFee", ""));
        assert!(detector.is_fee_update_function("updateBaseFee", ""));
        assert!(detector.is_fee_update_function("setGasPrice", ""));
        assert!(!detector.is_fee_update_function("calculate", ""));
    }

    #[test]
    fn test_check_fee_bounds_missing() {
        let detector = L2FeeManipulationDetector::new();
        let source = "function calculateFee(uint256 amount) public returns (uint256) { return amount * feeRate; }";
        let issues = detector.check_fee_bounds(source);

        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| i.contains("maximum fee bound")));
    }

    #[test]
    fn test_check_fee_bounds_with_validation() {
        let detector = L2FeeManipulationDetector::new();
        let source = r#"
            function calculateFee(uint256 amount) public returns (uint256) {
                uint256 fee = amount * feeRate;
                require(fee >= MIN_FEE && fee <= MAX_FEE, "Fee out of bounds");
                return fee;
            }
        "#;
        let issues = detector.check_fee_bounds(source);

        // Should have fewer issues with bounds
        assert!(issues.len() < 2);
    }

    #[test]
    fn test_check_fee_update_protection() {
        let detector = L2FeeManipulationDetector::new();
        let source = "function setFee(uint256 newFee) public { baseFee = newFee; }";
        let issues = detector.check_fee_update_protection(source);

        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| i.contains("access control")));
        assert!(issues.iter().any(|i| i.contains("time delay")));
    }

    #[test]
    fn test_check_fee_update_with_protection() {
        let detector = L2FeeManipulationDetector::new();
        let source = r#"
            function setFee(uint256 newFee) public onlyOwner {
                require(newFee >= MIN_FEE && newFee <= MAX_FEE);
                require(block.timestamp >= lastUpdate + delay);
                baseFee = newFee;
                lastUpdate = block.timestamp;
                emit FeeUpdated(newFee);
            }
        "#;
        let issues = detector.check_fee_update_protection(source);

        // Should have minimal issues with proper protection
        assert!(issues.len() <= 1);
    }

    #[test]
    fn test_check_oracle_fee_security() {
        let detector = L2FeeManipulationDetector::new();
        let source =
            "function getL1Fee() public view returns (uint256) { return oracle.getPrice(); }";
        let issues = detector.check_oracle_fee_security(source);

        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| i.contains("validation")));
        assert!(issues.iter().any(|i| i.contains("staleness")));
    }

    #[test]
    fn test_check_oracle_fee_with_validation() {
        let detector = L2FeeManipulationDetector::new();
        let source = r#"
            function getL1Fee() public view returns (uint256) {
                (uint256 price, uint256 timestamp) = oracle.getPrice();
                require(block.timestamp - timestamp < 1 hours, "Stale price");
                require(price >= MIN_PRICE && price <= MAX_PRICE, "Price out of bounds");
                return getTWAP();
            }
        "#;
        let issues = detector.check_oracle_fee_security(source);

        // Should have fewer issues with proper validation (may still have circuit breaker and multiple oracle warnings)
        assert!(issues.len() <= 3);
    }

    #[test]
    fn test_check_dynamic_fee_logic() {
        let detector = L2FeeManipulationDetector::new();
        let source = "function adjustFee(uint256 gasUsed) public { baseFee = baseFee + gasUsed; }";
        let issues = detector.check_dynamic_fee_logic(source);

        assert!(!issues.is_empty());
        // Will detect missing smoothing, parameter validation, and minimum change threshold
        assert!(issues.iter().any(|i| i.contains("smoothing")
            || i.contains("validation")
            || i.contains("threshold")));
    }

    #[test]
    fn test_check_dynamic_fee_with_constraints() {
        let detector = L2FeeManipulationDetector::new();
        let source = r#"
            function adjustFee(uint256 gasUsed, uint256 gasTarget) public {
                require(gasUsed <= MAX_GAS && gasTarget > 0);
                uint256 adjustment = calculateAdjustment(gasUsed, gasTarget);
                adjustment = min(adjustment, MAX_ADJUSTMENT);
                baseFee = smoothAdjustment(baseFee, adjustment);
            }
        "#;
        let issues = detector.check_dynamic_fee_logic(source);

        // Should have fewer issues with constraints
        assert!(issues.len() < 2);
    }
}
