//! Enhanced Input Validation Detector (OWASP 2025)
//!
//! Detects missing comprehensive bounds checking that led to $14.6M in losses.
//! Array length validation, parameter bounds, zero-value checks.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils::{is_secure_example_file, is_test_contract};

pub struct EnhancedInputValidationDetector {
    base: BaseDetector,
}

impl EnhancedInputValidationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("enhanced-input-validation".to_string()),
                "Enhanced Input Validation".to_string(),
                "Detects missing bounds checking and array validation ($14.6M impact)".to_string(),
                vec![
                    DetectorCategory::Validation,
                    DetectorCategory::BestPractices,
                ],
                Severity::High,
            ),
        }
    }
}

impl Default for EnhancedInputValidationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl EnhancedInputValidationDetector {
    /// Phase 51 FP Reduction: Skip known safe libraries
    fn is_safe_library_or_interface(&self, source: &str, lower: &str) -> bool {
        // OpenZeppelin contracts are battle-tested
        if source.contains("@openzeppelin") || source.contains("openzeppelin-contracts") {
            return true;
        }

        // Solmate
        if source.contains("@solmate") || source.contains("solmate/") {
            return true;
        }

        // Interface files don't have implementations
        if lower.contains("interface ") && !lower.contains("contract ") {
            return true;
        }

        // Abstract contracts often delegate validation to implementations
        if lower.contains("abstract contract") {
            return true;
        }

        false
    }

    /// Phase 51 FP Reduction: Check batch operations for array validation
    fn check_batch_operations(
        &self,
        ctx: &AnalysisContext<'_>,
        source: &str,
        lower: &str,
        findings: &mut Vec<Finding>,
    ) {
        // Only check functions with "batch", "multi", or "bulk" in name
        let has_batch_function = lower.contains("function batch")
            || lower.contains("function multi")
            || lower.contains("function bulk")
            || lower.contains("batchexecute")
            || lower.contains("multicall");

        if !has_batch_function {
            return;
        }

        // Check for multiple array parameters (high risk for mismatch)
        let has_multiple_arrays = (source.matches("[]").count() >= 2
            || source.matches("[] calldata").count() >= 2
            || source.matches("[] memory").count() >= 2);

        if has_multiple_arrays {
            // Check for length matching validation
            let has_length_match = lower.contains(".length ==")
                || lower.contains(".length !=")
                || lower.contains("length mismatch")
                || lower.contains("arrays must");

            if !has_length_match {
                let finding = self
                    .base
                    .create_finding_with_severity(
                        ctx,
                        "Batch function with multiple arrays lacks length matching validation"
                            .to_string(),
                        1,
                        0,
                        20,
                        Severity::High,
                    )
                    .with_fix_suggestion(
                        "✅ VALIDATE ARRAY MATCHING:\n\
                     function batchTransfer(\n\
                         address[] calldata recipients,\n\
                         uint256[] calldata amounts\n\
                     ) external {\n\
                         require(\n\
                             recipients.length == amounts.length,\n\
                             \"Length mismatch\"\n\
                         );\n\
                         require(recipients.length > 0, \"Empty arrays\");\n\
                         require(recipients.length <= MAX_BATCH, \"Too many\");\n\
                     }"
                        .to_string(),
                    );
                findings.push(finding);
            }
        }
    }

    /// Phase 51 FP Reduction: Check admin functions for address validation
    fn check_admin_address_validation(
        &self,
        ctx: &AnalysisContext<'_>,
        source: &str,
        lower: &str,
        findings: &mut Vec<Finding>,
    ) {
        // Check for admin/owner setter functions and simple address setters
        let admin_setter_patterns = [
            "function setowner",
            "function settokenaddress",
            "function settreasury",
            "function setadmin",
            "function transferownership",
            "function updateoracle",
            "function setfeerecipient",
            // Common address setter patterns
            "function settoken",
            "function setaddress",
            "function setcontract",
            "function setrecipient",
            "function setmanager",
        ];

        let has_admin_setter = admin_setter_patterns.iter().any(|p| lower.contains(p));

        // Also check for generic "function set*" followed by "(address" pattern
        let has_address_setter = lower.contains("function set") && lower.contains("(address");

        if !has_admin_setter && !has_address_setter {
            return;
        }

        // Check for zero-address validation
        let has_address_check = source.contains("address(0)")
            && (source.contains("require") || source.contains("if") || source.contains("revert"));

        if !has_address_check {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    "Admin setter function without zero-address validation".to_string(),
                    1,
                    0,
                    20,
                    Severity::Medium,
                )
                .with_fix_suggestion(
                    "✅ VALIDATE ADMIN ADDRESS:\n\
                 function setOwner(address newOwner) external onlyOwner {\n\
                     require(newOwner != address(0), \"Zero address\");\n\
                     owner = newOwner;\n\
                 }"
                    .to_string(),
                );
            findings.push(finding);
        }
    }

    /// Phase 51 FP Reduction: Check fee setter functions for bounds validation
    fn check_fee_setter_functions(
        &self,
        ctx: &AnalysisContext<'_>,
        source: &str,
        lower: &str,
        findings: &mut Vec<Finding>,
    ) {
        // Only check explicit fee/ratio setter functions
        let fee_setter_patterns = [
            "function setfee",
            "function updatefee",
            "function setratio",
            "function setbasispoints",
            "function setpercentage",
            "function setprotocolfee",
            "function setswapfee",
        ];

        let has_fee_setter = fee_setter_patterns.iter().any(|p| lower.contains(p));

        if !has_fee_setter {
            return;
        }

        // Check for upper bounds validation
        let has_upper_bound = source.contains("<=")
            || source.contains("< ")
            || lower.contains("max_fee")
            || lower.contains("maxfee")
            || lower.contains("fee_cap")
            || lower.contains("feecap");

        if !has_upper_bound {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    "Fee setter function without upper bounds validation".to_string(),
                    1,
                    0,
                    20,
                    Severity::Medium,
                )
                .with_fix_suggestion(
                    "✅ VALIDATE FEE BOUNDS:\n\
                 uint256 public constant MAX_FEE = 1000;  // 10% in basis points\n\
                 \n\
                 function setFee(uint256 newFee) external onlyOwner {\n\
                     require(newFee <= MAX_FEE, \"Fee too high\");\n\
                     fee = newFee;\n\
                 }"
                    .to_string(),
                );
            findings.push(finding);
        }
    }
}

impl Detector for EnhancedInputValidationDetector {
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

        // Phase 10: Skip test contracts and secure examples
        if is_test_contract(ctx) || is_secure_example_file(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;
        let lower = source.to_lowercase();

        // Phase 51 FP Reduction: Skip known safe libraries and interfaces
        // These are heavily audited and have proper validation
        if self.is_safe_library_or_interface(source, &lower) {
            return Ok(findings);
        }

        // Phase 51 FP Reduction: Only check for specific high-risk patterns
        // Focus on batch/multi-call operations where array validation is critical
        self.check_batch_operations(ctx, source, &lower, &mut findings);

        // Phase 51 FP Reduction: Only check admin functions for address validation
        // Regular user functions often don't need zero-address checks
        self.check_admin_address_validation(ctx, source, &lower, &mut findings);

        // Phase 51 FP Reduction: Only check functions that explicitly set fees/ratios
        self.check_fee_setter_functions(ctx, source, &lower, &mut findings);

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
