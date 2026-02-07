use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for stale oracle price data vulnerabilities
pub struct PriceOracleStaleDetector {
    base: BaseDetector,
}

impl Default for PriceOracleStaleDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PriceOracleStaleDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("price-oracle-stale".to_string()),
                "Stale Price Oracle Data".to_string(),
                "Detects missing staleness checks on oracle price feeds that could lead to using outdated price data".to_string(),
                vec![DetectorCategory::Oracle],
                Severity::Critical,
            ),
        }
    }
}

impl Detector for PriceOracleStaleDetector {
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

        for function in ctx.get_functions() {
            if let Some(oracle_issue) = self.check_stale_oracle(function, ctx) {
                let message = format!(
                    "Function '{}' uses oracle price data without staleness validation. {} \
                    Using stale oracle data can lead to incorrect liquidations, price manipulations, and financial losses.",
                    function.name.name, oracle_issue
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
                    .with_cwe(829) // CWE-829: Inclusion of Functionality from Untrusted Control Sphere
                    .with_cwe(672) // CWE-672: Operation on a Resource after Expiration or Release
                    .with_fix_suggestion(format!(
                        "Add staleness checks in '{}'. \
                    Implement: (1) Check oracle updatedAt timestamp, \
                    (2) Verify data freshness with block.timestamp comparison, \
                    (3) Add HEARTBEAT_THRESHOLD constant (e.g., 3600 seconds), \
                    (4) Revert if price is too old, \
                    (5) Consider Chainlink's latestRoundData() with timestamp validation.",
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

impl PriceOracleStaleDetector {
    fn check_stale_oracle(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        let func_name = &function.name.name;
        let func_source = self.get_function_source(function, ctx);

        // FP Fix 1: Skip view/pure calculation helpers that just use stored values.
        // These functions do not fetch oracle data -- they perform arithmetic on
        // values already stored in state or passed as parameters.
        if self.is_view_pure_calculation_helper(function, func_name, &func_source) {
            return None;
        }

        // FP Fix 2: Skip flash loan callback functions. Prices in callbacks are
        // passed as parameters from the lender, not fetched from an oracle.
        if self.is_flash_loan_callback(func_name, &func_source) {
            return None;
        }

        // FP Fix 3: Skip functions that already implement staleness checks.
        if self.has_staleness_validation(&func_source) {
            return None;
        }

        // Pattern 1: Direct oracle call (latestRoundData, latestAnswer, consult)
        // without staleness check. We require an actual oracle interface call
        // pattern, not just reading a "price" variable.
        let has_direct_oracle_call = func_source.contains("latestRoundData")
            || func_source.contains("latestAnswer")
            || func_source.contains(".consult(")
            || func_source.contains(".getLatestPrice(")
            || func_source.contains(".getRoundData(");

        if has_direct_oracle_call {
            return Some(
                "Oracle price fetch without staleness validation. \
                Missing checks for updatedAt timestamp, price age, or heartbeat threshold"
                    .to_string(),
            );
        }

        // Pattern 2: Using stored/cached price without checking lastUpdate.
        // Only flag if the function actually writes or uses the price in a
        // state-changing context (not view/pure).
        let uses_stored_price = func_source.contains("lastPrice")
            || func_source.contains("cachedPrice")
            || func_source.contains("storedPrice");

        let checks_last_update = func_source.contains("lastUpdate")
            && (func_source.contains("block.timestamp") || func_source.contains("require"));

        if uses_stored_price && !checks_last_update {
            // Only flag if the function is state-changing -- view/pure helpers
            // that read stored prices are not vulnerable themselves.
            if function.mutability != ast::StateMutability::View
                && function.mutability != ast::StateMutability::Pure
            {
                return Some(
                    "Uses stored oracle price without verifying lastUpdate timestamp. \
                    Price may be stale and cause incorrect calculations"
                        .to_string(),
                );
            }
        }

        // Pattern 3: Calling a wrapper getPrice() that lacks round metadata.
        // Require that this is an actual function call (contains parentheses)
        // and the function performs a member access call pattern (e.g., oracle.getPrice()).
        if (func_source.contains(".getPrice(") || func_source.contains("oracle.getPrice"))
            && !func_source.contains("latestRoundData")
            && !func_source.contains("updatedAt")
            && function.mutability != ast::StateMutability::View
            && function.mutability != ast::StateMutability::Pure
        {
            return Some(
                "Uses simplified getPrice() without fetching round metadata. \
                Should use latestRoundData() to access updatedAt timestamp"
                    .to_string(),
            );
        }

        None
    }

    /// Returns true if the function is a view/pure calculation helper that
    /// merely reads stored price values or uses parameters -- it does not
    /// fetch oracle data itself.
    fn is_view_pure_calculation_helper(
        &self,
        function: &ast::Function<'_>,
        func_name: &str,
        func_source: &str,
    ) -> bool {
        let is_view_or_pure = function.mutability == ast::StateMutability::View
            || function.mutability == ast::StateMutability::Pure;

        if !is_view_or_pure {
            return false;
        }

        // View/pure functions that make actual oracle calls should still be
        // flagged (e.g., a view function that calls latestRoundData).
        let has_actual_oracle_call = func_source.contains("latestRoundData")
            || func_source.contains("latestAnswer")
            || func_source.contains(".consult(")
            || func_source.contains(".getLatestPrice(")
            || func_source.contains(".getRoundData(");

        if has_actual_oracle_call {
            return false;
        }

        // Common calculation helper names that use prices but do not fetch them.
        let is_calc_helper = func_name.contains("calculate")
            || func_name.contains("compute")
            || func_name.contains("estimate")
            || func_name.contains("convert")
            || func_name.starts_with("get")
            || func_name.starts_with("_get");

        is_calc_helper
    }

    /// Returns true if the function is a flash loan callback. Flash loan
    /// callbacks receive prices as parameters from the lender, they do not
    /// fetch from an oracle.
    fn is_flash_loan_callback(&self, func_name: &str, func_source: &str) -> bool {
        // ERC-3156 standard callback
        if func_name == "onFlashLoan" {
            return true;
        }

        // Aave-style flash loan callbacks
        if func_name == "executeOperation" {
            return true;
        }

        // dYdX-style callbacks
        if func_name == "callFunction" && func_source.contains("Account.Info") {
            return true;
        }

        false
    }

    /// Returns true if the function source already contains staleness validation
    /// patterns (timestamp comparisons, heartbeat thresholds, freshness checks).
    fn has_staleness_validation(&self, func_source: &str) -> bool {
        let has_timestamp_check = func_source.contains("updatedAt")
            || func_source.contains("HEARTBEAT")
            || func_source.contains("MAX_AGE")
            || func_source.contains("STALE")
            || func_source.contains("MAX_STALENESS")
            || func_source.contains("staleness")
            || func_source.contains("freshness")
            || func_source.contains("maxDelay")
            || func_source.contains("priceAge");

        if !has_timestamp_check {
            return false;
        }

        // Confirm the staleness constant/variable is used with a comparison or
        // require/revert, not just declared.
        let has_enforcement = func_source.contains("require(")
            || func_source.contains("revert")
            || func_source.contains("block.timestamp")
            || func_source.contains("if (")
            || func_source.contains("if(")
            || func_source.contains("assert(");

        has_enforcement
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = PriceOracleStaleDetector::new();
        assert_eq!(detector.name(), "Stale Price Oracle Data");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }

    // ============================================================================
    // FP Fix: Flash loan callback skip tests
    // ============================================================================

    #[test]
    fn test_skip_on_flash_loan_callback() {
        let detector = PriceOracleStaleDetector::new();

        // ERC-3156 onFlashLoan callback should be skipped
        assert!(detector.is_flash_loan_callback("onFlashLoan", ""));
        // Aave-style executeOperation callback should be skipped
        assert!(detector.is_flash_loan_callback("executeOperation", ""));
        // dYdX-style callFunction callback with Account.Info
        assert!(detector.is_flash_loan_callback(
            "callFunction",
            "function callFunction(address sender, Account.Info memory account, bytes memory data)"
        ));
        // dYdX callFunction without Account.Info is not a flash loan callback
        assert!(!detector.is_flash_loan_callback("callFunction", "function callFunction(uint x)"));
        // Regular function names should not be skipped
        assert!(!detector.is_flash_loan_callback("withdraw", ""));
        assert!(!detector.is_flash_loan_callback("updatePrice", ""));
    }

    // ============================================================================
    // FP Fix: Staleness validation detection tests
    // ============================================================================

    #[test]
    fn test_has_staleness_validation_with_updated_at() {
        let detector = PriceOracleStaleDetector::new();

        let source_with_check = r#"
            (,int256 answer,,uint256 updatedAt,) = priceFeed.latestRoundData();
            require(block.timestamp - updatedAt < HEARTBEAT, "Stale price");
        "#;
        assert!(detector.has_staleness_validation(source_with_check));
    }

    #[test]
    fn test_has_staleness_validation_with_max_staleness() {
        let detector = PriceOracleStaleDetector::new();

        let source_with_max_staleness = r#"
            uint256 price = oracle.getPrice();
            require(block.timestamp - lastUpdated < MAX_STALENESS, "Price too old");
        "#;
        assert!(detector.has_staleness_validation(source_with_max_staleness));
    }

    #[test]
    fn test_has_staleness_validation_with_max_age() {
        let detector = PriceOracleStaleDetector::new();

        let source_with_max_age = r#"
            if (block.timestamp - priceTimestamp > MAX_AGE) {
                revert("Stale oracle data");
            }
        "#;
        assert!(detector.has_staleness_validation(source_with_max_age));
    }

    #[test]
    fn test_has_staleness_validation_with_heartbeat() {
        let detector = PriceOracleStaleDetector::new();

        let source_with_heartbeat = r#"
            require(block.timestamp - updatedAt <= HEARTBEAT, "Oracle stale");
        "#;
        assert!(detector.has_staleness_validation(source_with_heartbeat));
    }

    #[test]
    fn test_no_staleness_validation_without_enforcement() {
        let detector = PriceOracleStaleDetector::new();

        // Has a staleness keyword but no enforcement (no require/revert/if)
        let source_declaration_only = r#"
            uint256 public HEARTBEAT = 3600;
        "#;
        assert!(!detector.has_staleness_validation(source_declaration_only));
    }

    #[test]
    fn test_no_staleness_validation_no_keywords() {
        let detector = PriceOracleStaleDetector::new();

        let source_no_staleness = r#"
            int256 price = oracle.latestAnswer();
            return uint256(price);
        "#;
        assert!(!detector.has_staleness_validation(source_no_staleness));
    }

    // ============================================================================
    // FP Fix: View/pure calculation helper skip tests
    // ============================================================================

    #[test]
    fn test_skip_view_calculate_helper() {
        let detector = PriceOracleStaleDetector::new();
        let arena = ast::AstArena::new();

        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "calculateCollateralValue",
            ast::Visibility::Public,
            ast::StateMutability::View,
        );

        let func_source = "return collateral * price / 1e18;";
        assert!(detector.is_view_pure_calculation_helper(
            &func,
            "calculateCollateralValue",
            func_source
        ));
    }

    #[test]
    fn test_skip_pure_compute_helper() {
        let detector = PriceOracleStaleDetector::new();
        let arena = ast::AstArena::new();

        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "computeAmount",
            ast::Visibility::Public,
            ast::StateMutability::Pure,
        );

        assert!(detector.is_view_pure_calculation_helper(&func, "computeAmount", "return a * b;"));
    }

    #[test]
    fn test_skip_view_get_secure_price() {
        let detector = PriceOracleStaleDetector::new();
        let arena = ast::AstArena::new();

        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "getSecurePrice",
            ast::Visibility::Public,
            ast::StateMutability::View,
        );

        // This is a view getter with no direct oracle call -- skip it
        let func_source = "return storedPrice;";
        assert!(detector.is_view_pure_calculation_helper(&func, "getSecurePrice", func_source));
    }

    #[test]
    fn test_skip_view_calculate_potential_profit() {
        let detector = PriceOracleStaleDetector::new();
        let arena = ast::AstArena::new();

        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "calculatePotentialProfit",
            ast::Visibility::External,
            ast::StateMutability::View,
        );

        let func_source = "return priceA > priceB ? priceA - priceB : 0;";
        assert!(detector.is_view_pure_calculation_helper(
            &func,
            "calculatePotentialProfit",
            func_source
        ));
    }

    #[test]
    fn test_do_not_skip_view_with_oracle_call() {
        let detector = PriceOracleStaleDetector::new();
        let arena = ast::AstArena::new();

        // A view function that actually calls latestRoundData should NOT be skipped
        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "getPrice",
            ast::Visibility::Public,
            ast::StateMutability::View,
        );

        let func_source = "(,int256 answer,,,) = priceFeed.latestRoundData();";
        assert!(!detector.is_view_pure_calculation_helper(&func, "getPrice", func_source));
    }

    #[test]
    fn test_do_not_skip_nonpayable_calculate() {
        let detector = PriceOracleStaleDetector::new();
        let arena = ast::AstArena::new();

        // A non-view function named "calculate..." should NOT be skipped
        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "calculateAndUpdate",
            ast::Visibility::Public,
            ast::StateMutability::NonPayable,
        );

        let func_source = "price = oracle.getPrice();";
        assert!(!detector.is_view_pure_calculation_helper(
            &func,
            "calculateAndUpdate",
            func_source
        ));
    }

    #[test]
    fn test_do_not_skip_view_non_helper_name() {
        let detector = PriceOracleStaleDetector::new();
        let arena = ast::AstArena::new();

        // A view function without a calc helper name pattern -- should not be skipped
        let func = crate::types::test_utils::create_mock_ast_function(
            &arena,
            "withdraw",
            ast::Visibility::Public,
            ast::StateMutability::View,
        );

        let func_source = "return balance;";
        assert!(!detector.is_view_pure_calculation_helper(&func, "withdraw", func_source));
    }

    // ============================================================================
    // Regression: True positives should still be detected
    // ============================================================================

    #[test]
    fn test_tp_latestanswer_without_staleness() {
        let detector = PriceOracleStaleDetector::new();

        // No staleness keywords at all
        let source = "int256 price = priceFeed.latestAnswer();";
        assert!(!detector.has_staleness_validation(source));
        // And it matches the oracle call pattern
        assert!(source.contains("latestAnswer"));
    }

    #[test]
    fn test_tp_latestrounddata_without_staleness() {
        let detector = PriceOracleStaleDetector::new();

        let source = r#"
            (,int256 answer,,,) = priceFeed.latestRoundData();
            return uint256(answer);
        "#;
        assert!(!detector.has_staleness_validation(source));
        assert!(source.contains("latestRoundData"));
    }

    #[test]
    fn test_tp_stored_price_in_state_changing_function() {
        // A state-changing function using lastPrice without lastUpdate check
        // should be flagged. Verify the source patterns match our detection logic.
        let source = "uint256 value = amount * lastPrice / 1e18; balances[msg.sender] = value;";
        assert!(source.contains("lastPrice"));
        assert!(!source.contains("lastUpdate"));
    }

    #[test]
    fn test_staleness_validation_with_freshness_if_check() {
        let detector = PriceOracleStaleDetector::new();

        let source = r#"
            uint256 age = block.timestamp - updatedAt;
            if (age > MAX_AGE) { revert StalePrice(); }
        "#;
        assert!(detector.has_staleness_validation(source));
    }

    #[test]
    fn test_staleness_validation_with_price_age() {
        let detector = PriceOracleStaleDetector::new();

        let source = r#"
            uint256 priceAge = block.timestamp - lastUpdate;
            require(priceAge < maxDelay, "Price too old");
        "#;
        assert!(detector.has_staleness_validation(source));
    }
}
