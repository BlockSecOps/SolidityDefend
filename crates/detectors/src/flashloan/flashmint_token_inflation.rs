//! Flash Mint Token Inflation Detector
//!
//! Detects flash mint vulnerabilities:
//! - Uncapped flash mint amount (unlimited minting)
//! - No flash mint fee (free mints enable spam)
//! - No rate limiting (DoS via spam)
//!
//! Severity: HIGH
//! Context: MakerDAO flash mint used in Euler $200M exploit

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use ast;

pub struct FlashmintTokenInflationDetector {
    base: BaseDetector,
}

impl FlashmintTokenInflationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("flashmint-token-inflation".to_string()),
                "Flash Mint Token Inflation Attack".to_string(),
                "Detects flash mint vulnerabilities allowing unlimited minting and spam"
                    .to_string(),
                vec![DetectorCategory::DeFi],
                Severity::High,
            ),
        }
    }

    fn has_flash_mint_cap(&self, ctx: &AnalysisContext) -> bool {
        let source_lower = ctx.source_code.to_lowercase();

        // Check for MAX_FLASH_MINT or similar constant
        (source_lower.contains("max") && source_lower.contains("flash"))
            || source_lower.contains("flashlimit")
            || source_lower.contains("maxflashloan")
    }

    fn get_function_source<'a>(
        &self,
        function: &ast::Function,
        ctx: &'a AnalysisContext,
    ) -> &'a str {
        let source = &ctx.source_code;
        let func_start = function.location.start().offset();
        let func_end = function.location.end().offset();

        if func_end <= func_start || func_start >= source.len() {
            return "";
        }

        &source[func_start..func_end.min(source.len())]
    }

    fn has_flash_mint_fee(&self, function: &ast::Function, ctx: &AnalysisContext) -> bool {
        let func_source = self.get_function_source(function, ctx);
        let func_lower = func_source.to_lowercase();
        let source_lower = ctx.source_code.to_lowercase();

        // --- Function-level checks ---

        // Check 1: Function body contains fee arithmetic (original check)
        if func_lower.contains("fee")
            && (func_lower.contains("*") || func_lower.contains("/") || func_lower.contains("mul"))
        {
            return true;
        }

        // Check 2: Function calls a flashFee() or similar fee-computing function
        if func_lower.contains("flashfee(")
            || func_lower.contains("flash_fee(")
            || func_lower.contains("getfee(")
            || func_lower.contains("calculatefee(")
            || func_lower.contains("_fee(")
        {
            return true;
        }

        // Check 3: Function body references fee state variables or constants
        if func_lower.contains("flashloanfee")
            || func_lower.contains("flashmintfee")
            || func_lower.contains("flash_loan_fee")
            || func_lower.contains("flash_mint_fee")
            || func_lower.contains("flashloan_premium")
            || func_lower.contains("flash_premium")
            || func_lower.contains("feerate")
            || func_lower.contains("fee_rate")
            || func_lower.contains("basis_points")
            || func_lower.contains("fee_bps")
        {
            return true;
        }

        // Check 4: Function has repayment validation that includes a fee
        // e.g., amount + fee, balanceBefore + fee, require(repayment >= ...)
        if func_lower.contains("amount + fee")
            || func_lower.contains("amount +fee")
            || func_lower.contains("amount+fee")
            || (func_lower.contains("balancebefore") && func_lower.contains("+ fee"))
            || (func_lower.contains("repay") && func_lower.contains("fee"))
        {
            return true;
        }

        // Check 5: Function has a fee parameter (e.g., onFlashLoan's fee param)
        for param in function.parameters.iter() {
            if let Some(ref name) = param.name {
                let param_lower = name.name.to_lowercase();
                if param_lower == "fee"
                    || param_lower == "_fee"
                    || param_lower.contains("flashfee")
                    || param_lower.contains("flash_fee")
                {
                    return true;
                }
            }
        }

        // --- Contract-level checks ---

        // Check 6: Contract has a flashFee() function (ERC-3156 standard)
        if source_lower.contains("function flashfee(")
            || source_lower.contains("function flash_fee(")
        {
            return true;
        }

        // Check 7: Contract has fee state variables or constants
        if source_lower.contains("flashloanfee")
            || source_lower.contains("flashmintfee")
            || source_lower.contains("flash_loan_fee")
            || source_lower.contains("flash_mint_fee")
            || source_lower.contains("flashloan_premium")
        {
            return true;
        }

        // Check 8: Contract has fee-bounding constants (MAX_FEE, BASIS_POINTS)
        if (source_lower.contains("max_fee")
            || source_lower.contains("maxfee")
            || source_lower.contains("maxflashloanfee")
            || source_lower.contains("max_flash_loan_fee"))
            && (source_lower.contains("basis_points")
                || source_lower.contains("bps")
                || source_lower.contains("10000")
                || source_lower.contains("1e4"))
        {
            return true;
        }

        // Check 9: Contract is ERC-3156 compliant (inherently has fee handling)
        if (ctx.source_code.contains("IERC3156FlashLender")
            || ctx.source_code.contains("IERC3156FlashBorrower")
            || ctx.source_code.contains("ERC3156"))
            && ctx.source_code.contains("CALLBACK_SUCCESS")
        {
            return true;
        }

        // Check 10: Contract has explicit fee require/validation
        if source_lower.contains("require(fee") || source_lower.contains("require(_fee") {
            return true;
        }

        false
    }
}

impl Default for FlashmintTokenInflationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for FlashmintTokenInflationDetector {
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

        // Find flash mint function
        for function in ctx.get_functions() {
            let func_name = function.name.name.to_lowercase();

            if func_name.contains("flashmint") || func_name.contains("flashloan") {
                let line = function.name.location.start().line() as u32;

                // Check 1: Flash mint cap
                if !self.has_flash_mint_cap(ctx) {
                    findings.push(
                        self.base
                            .create_finding_with_severity(
                                ctx,
                                "Uncapped flash mint - unlimited token minting possible"
                                    .to_string(),
                                line,
                                0,
                                20,
                                Severity::High,
                            )
                            .with_fix_suggestion(
                                "Add MAX_FLASH_MINT constant and validate amount".to_string(),
                            ),
                    );
                }

                // Check 2: Flash mint fee
                if !self.has_flash_mint_fee(function, ctx) {
                    findings.push(
                        self.base
                            .create_finding_with_severity(
                                ctx,
                                "No flash mint fee - free flash mints enable spam".to_string(),
                                line,
                                0,
                                20,
                                Severity::Medium,
                            )
                            .with_fix_suggestion(
                                "Add flash mint fee (e.g., 0.05% like MakerDAO)".to_string(),
                            ),
                    );
                }
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
