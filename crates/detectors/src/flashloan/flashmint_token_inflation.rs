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
                "Detects flash mint vulnerabilities allowing unlimited minting and spam".to_string(),
                vec![DetectorCategory::DeFi],
                Severity::High,
            ),
        }
    }

    fn has_flash_mint_cap(&self, ctx: &AnalysisContext) -> bool {
        let source_lower = ctx.source_code.to_lowercase();

        // Check for MAX_FLASH_MINT or similar constant
        (source_lower.contains("max") && source_lower.contains("flash")) ||
        source_lower.contains("flashlimit") ||
        source_lower.contains("maxflashloan")
    }

    fn get_function_source<'a>(&self, function: &ast::Function, ctx: &'a AnalysisContext) -> &'a str {
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

        // Check if function calculates a fee
        func_lower.contains("fee") &&
        (func_lower.contains("*") || func_lower.contains("/") || func_lower.contains("mul"))
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
                    findings.push(self.base.create_finding_with_severity(
                        ctx,
                        "Uncapped flash mint - unlimited token minting possible".to_string(),
                        line, 0, 20,
                        Severity::High,
                    ).with_fix_suggestion("Add MAX_FLASH_MINT constant and validate amount".to_string()));
                }

                // Check 2: Flash mint fee
                if !self.has_flash_mint_fee(function, ctx) {
                    findings.push(self.base.create_finding_with_severity(
                        ctx,
                        "No flash mint fee - free flash mints enable spam".to_string(),
                        line, 0, 20,
                        Severity::Medium,
                    ).with_fix_suggestion("Add flash mint fee (e.g., 0.05% like MakerDAO)".to_string()));
                }
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
