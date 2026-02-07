use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils::{is_deployment_tooling, is_oracle_implementation, is_test_contract};

/// Detector for single oracle source dependencies
pub struct SingleSourceDetector {
    base: BaseDetector,
}

/// Detector for missing price validation
pub struct PriceValidationDetector {
    base: BaseDetector,
}

impl Default for SingleSourceDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SingleSourceDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("single-oracle-source".to_string()),
                "Single Oracle Source".to_string(),
                "Contract relies on a single oracle source for critical price data".to_string(),
                vec![DetectorCategory::Oracle],
                Severity::High,
            ),
        }
    }

    /// Check if function has slippage protection which mitigates oracle manipulation risk
    fn has_slippage_protection(&self, func_source: &str) -> bool {
        let lower = func_source.to_lowercase();
        lower.contains("minoutput")
            || lower.contains("minamount")
            || lower.contains("minreturn")
            || lower.contains("maxslippage")
            || lower.contains("amountoutmin")
            || lower.contains("amountinmax")
            || lower.contains("min_output")
            || lower.contains("min_amount")
            || lower.contains("slippage")
            || lower.contains("deadline")
            // Check for explicit bound checks on amounts
            || (lower.contains("require") && (lower.contains(">= min") || lower.contains("<= max")))
    }

    /// Phase 9 FP Reduction: Check if using Chainlink oracle pattern
    /// Chainlink is a well-established, reliable oracle infrastructure
    fn is_using_chainlink(&self, source: &str) -> bool {
        let lower = source.to_lowercase();
        lower.contains("aggregatorv3interface")
            || lower.contains("aggregatorinterface")
            || lower.contains("latestrounddata")
            || lower.contains("getlatestprice")
            || lower.contains("pricefeed")
            || lower.contains("chainlink")
            || lower.contains("datafeedstore")
    }

    /// Phase 9 FP Reduction: Check if using TWAP oracle pattern
    /// TWAP oracles are resistant to flash loan manipulation
    fn is_using_twap(&self, source: &str) -> bool {
        let lower = source.to_lowercase();
        lower.contains("twap")
            || lower.contains("timewightedaverage")
            || lower.contains("pricecumulativelast")
            || lower.contains("observe(")
            || lower.contains("consult(")
            || lower.contains("oraclecumulative")
            || lower.contains("gettwap")
    }

    /// Phase 14 FP Reduction: Check if contract actually uses oracle/price data
    /// Skip contracts that don't use oracles at all
    fn contract_uses_oracle_data(&self, source: &str) -> bool {
        let lower = source.to_lowercase();

        // Must have price-related state or function calls
        let has_price_calls = lower.contains("getprice")
            || lower.contains("latestprice")
            || lower.contains("latestrounddata")
            || lower.contains("pricefeed")
            || lower.contains("getlatestanswer")
            || lower.contains("getassetprice")
            || lower.contains("getunderlyingprice");

        // Must have oracle-related imports or interfaces
        let has_oracle_imports = lower.contains("ioracle")
            || lower.contains("ipriceoracle")
            || lower.contains("aggregatorv3interface")
            || lower.contains("aggregatorinterface")
            || lower.contains("pricefeedinterface")
            || lower.contains("chainlinkpricefeed");

        // Must have oracle state variable patterns
        let has_oracle_state = lower.contains("oracle")
            && (lower.contains("address") || lower.contains("mapping"))
            && !lower.contains("// oracle"); // Skip comments

        // Check for actual price usage patterns
        let has_price_usage = (lower.contains("price") || lower.contains("rate"))
            && (lower.contains("*") || lower.contains("/") || lower.contains("calculate"));

        has_price_calls || has_oracle_imports || (has_oracle_state && has_price_usage)
    }

    /// Check if function actually uses oracle/price data
    fn function_uses_oracle(&self, func_source: &str) -> bool {
        let lower = func_source.to_lowercase();

        // Oracle call patterns
        let has_oracle_call = lower.contains("getprice")
            || lower.contains("latestprice")
            || lower.contains("latestrounddata")
            || lower.contains("getlatestanswer")
            || lower.contains("getassetprice")
            || lower.contains("getunderlyingprice")
            || lower.contains("pricefeed.")
            || lower.contains("oracle.get")
            || lower.contains("priceoracle.");

        // Price calculation patterns
        let has_price_calc = (lower.contains("price") || lower.contains("rate"))
            && (lower.contains(" * ") || lower.contains(" / "))
            && !lower.contains("address"); // Not address-related

        has_oracle_call || has_price_calc
    }

    fn _is_oracle_call(&self, expr: &ast::Expression<'_>) -> bool {
        match expr {
            ast::Expression::FunctionCall { function, .. } => match function {
                ast::Expression::MemberAccess { member, .. } => {
                    let member_name = &member.name;
                    member_name.contains("price")
                        || member_name.contains("rate")
                        || *member_name == "latestRoundData"
                        || *member_name == "getPrice"
                        || *member_name == "decimals"
                }
                _ => false,
            },
            _ => false,
        }
    }

    fn count_oracle_sources(&self, function: &ast::Function<'_>) -> usize {
        let mut oracle_sources = std::collections::HashSet::new();

        if let Some(body) = &function.body {
            self.collect_oracle_sources(&body.statements, &mut oracle_sources);
        }

        oracle_sources.len()
    }

    fn collect_oracle_sources(
        &self,
        statements: &[ast::Statement<'_>],
        sources: &mut std::collections::HashSet<String>,
    ) {
        for stmt in statements {
            match stmt {
                ast::Statement::Expression(expr) => {
                    self.extract_oracle_source(expr, sources);
                }
                ast::Statement::Block(block) => {
                    self.collect_oracle_sources(&block.statements, sources);
                }
                _ => {}
            }
        }
    }

    fn extract_oracle_source(
        &self,
        expr: &ast::Expression<'_>,
        sources: &mut std::collections::HashSet<String>,
    ) {
        if let ast::Expression::FunctionCall { function, .. } = expr {
            if let ast::Expression::MemberAccess {
                expression, member, ..
            } = function
            {
                // Phase 14 FP Reduction: Only extract if it's an actual oracle call
                let member_name = member.name.to_lowercase();
                let is_oracle_call = member_name.contains("price")
                    || member_name.contains("rate")
                    || member_name.contains("latestrounddata")
                    || member_name.contains("getprice")
                    || member_name.contains("getlatestanswer")
                    || member_name.contains("decimals")
                    || member_name.contains("getassetprice");

                if is_oracle_call {
                    if let ast::Expression::Identifier(id) = expression {
                        sources.insert(id.name.to_string());
                    }
                }
            }
        }
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

impl Detector for SingleSourceDetector {
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

        let source = &ctx.source_code;

        // Phase 9 FP Reduction: Skip test contracts
        if is_test_contract(ctx) {
            return Ok(findings);
        }

        // Phase 9 FP Reduction: Skip contracts that ARE oracle implementations
        // Oracle contracts providing data don't need multiple oracle sources themselves
        if is_oracle_implementation(ctx) {
            return Ok(findings);
        }

        // Phase 14 FP Reduction: Skip deployment tooling
        // Deployment libraries don't use oracles for price data
        if is_deployment_tooling(ctx) {
            return Ok(findings);
        }

        // Phase 14 FP Reduction: Skip contracts that don't actually use oracle data
        // This is the main fix - only analyze contracts that have oracle-related patterns
        if !self.contract_uses_oracle_data(source) {
            return Ok(findings);
        }

        // Phase 9 FP Reduction: Skip if using Chainlink (trusted decentralized oracle)
        if self.is_using_chainlink(source) {
            return Ok(findings);
        }

        // Phase 9 FP Reduction: Skip if using TWAP (manipulation resistant)
        if self.is_using_twap(source) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            // Get function source first
            let func_source = self.get_function_source(function, ctx);

            // Phase 14 FP Reduction: Skip functions that don't actually use oracle data
            if !self.function_uses_oracle(&func_source) {
                continue;
            }

            let oracle_count = self.count_oracle_sources(function);
            if oracle_count == 1 {
                // Skip if function has slippage protection - mitigates oracle manipulation
                if self.has_slippage_protection(&func_source) {
                    continue;
                }

                let message = format!(
                    "Function '{}' relies on a single oracle source for price data, creating centralization risk",
                    function.name.name
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(693) // CWE-693: Protection Mechanism Failure
                .with_fix_suggestion(format!(
                    "Use multiple oracle sources and implement price aggregation in function '{}'",
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

impl Default for PriceValidationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PriceValidationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("missing-price-validation".to_string()),
                "Missing Price Validation".to_string(),
                "Oracle price data is used without proper validation".to_string(),
                vec![DetectorCategory::Oracle],
                Severity::Medium,
            ),
        }
    }

    fn has_price_validation(&self, function: &ast::Function<'_>) -> bool {
        if let Some(body) = &function.body {
            self.check_statements_for_validation(&body.statements)
        } else {
            false
        }
    }

    fn check_statements_for_validation(&self, statements: &[ast::Statement<'_>]) -> bool {
        for stmt in statements {
            match stmt {
                ast::Statement::Expression(ast::Expression::FunctionCall { function, .. }) => {
                    if let ast::Expression::Identifier(id) = function {
                        if id.name == "require" || id.name == "assert" {
                            return true;
                        }
                    }
                }
                ast::Statement::If { .. } => {
                    return true; // Basic check for conditional validation
                }
                ast::Statement::Block(block) => {
                    if self.check_statements_for_validation(&block.statements) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    fn uses_oracle_data(&self, function: &ast::Function<'_>) -> bool {
        if let Some(body) = &function.body {
            self.check_statements_for_oracle_usage(&body.statements)
        } else {
            false
        }
    }

    fn check_statements_for_oracle_usage(&self, statements: &[ast::Statement<'_>]) -> bool {
        for stmt in statements {
            match stmt {
                ast::Statement::Expression(expr) => {
                    if self.expression_uses_oracle(expr) {
                        return true;
                    }
                }
                ast::Statement::Block(block) => {
                    if self.check_statements_for_oracle_usage(&block.statements) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    fn expression_uses_oracle(&self, expr: &ast::Expression<'_>) -> bool {
        match expr {
            ast::Expression::FunctionCall { function, .. } => match function {
                ast::Expression::MemberAccess { member, .. } => {
                    let member_name = &member.name;
                    member_name.contains("price")
                        || member_name.contains("rate")
                        || *member_name == "latestRoundData"
                }
                _ => false,
            },
            _ => false,
        }
    }
}

impl Detector for PriceValidationDetector {
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
            if self.uses_oracle_data(function) && !self.has_price_validation(function) {
                let message = format!(
                    "Function '{}' uses oracle price data without proper validation",
                    function.name.name
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
                        "Add validation checks for oracle price data in function '{}'",
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
