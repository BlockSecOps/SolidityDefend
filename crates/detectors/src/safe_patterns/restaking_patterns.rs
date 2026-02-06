//! Restaking Safe Patterns Module
//!
//! This module provides consolidated access to restaking pattern detection functions
//! for use in FP reduction across detectors. It re-exports functions from the
//! restaking classification module and adds convenience functions for safe pattern detection.
//!
//! Safe patterns include:
//! - EigenLayer delegation validation
//! - AVS validation and security measures
//! - Slashing accounting and protections
//! - Operator validation patterns
//! - Withdrawal queue protections

use crate::types::AnalysisContext;

// Re-export from restaking classification module
pub use crate::restaking::classification::*;

/// Check if contract has EigenLayer delegation safety measures
///
/// Returns true if the contract implements operator validation,
/// delegation caps, or allocation delays.
pub fn has_eigenlayer_delegation_safety(ctx: &AnalysisContext) -> bool {
    if !is_eigenlayer_integration(ctx) {
        return false;
    }

    // Check for delegation safety patterns at contract level
    has_max_operator_delegation(ctx) || has_delegation_tracking(ctx)
}

/// Check if contract has comprehensive AVS validation
///
/// Returns true if AVS registration requires collateral or governance approval.
pub fn has_avs_validation(ctx: &AnalysisContext) -> bool {
    // Check for governance approval pattern
    has_governance_approval(ctx)
}

/// Check if contract has proper slashing accounting
///
/// Returns true if the contract implements max slashing percentage limits.
pub fn has_slashing_accounting(ctx: &AnalysisContext) -> bool {
    has_max_slash_percentage_constant(ctx)
}

/// Check if contract has operator validation patterns
///
/// Returns true if the contract uses operator whitelisting or approval.
pub fn has_operator_validation_pattern(ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();

    source_lower.contains("approvedoperators")
        || source_lower.contains("approved_operators")
        || source_lower.contains("operatorwhitelist")
        || source_lower.contains("operator_whitelist")
        || source_lower.contains("isoperator")
        || source_lower.contains("is_operator")
}

/// Check if contract has withdrawal queue protections
///
/// Returns true if the contract implements two-step withdrawal or has withdrawal delay.
pub fn has_withdrawal_queue_protection(ctx: &AnalysisContext) -> bool {
    is_two_step_withdrawal(ctx) || has_withdrawal_delay_constant(ctx)
}

/// Check if contract has LRT share inflation protection
///
/// Returns true if the LRT implements share inflation protections.
pub fn has_lrt_inflation_protection(ctx: &AnalysisContext) -> bool {
    if !is_lrt_contract(ctx) {
        return false;
    }

    // Check for tracked assets (not using vulnerable balanceOf)
    has_tracked_assets_storage(ctx)
}

/// Check if contract has comprehensive restaking safety measures
///
/// Returns true if the contract implements multiple restaking safety patterns.
pub fn has_comprehensive_restaking_safety(ctx: &AnalysisContext) -> bool {
    if !is_restaking_contract(ctx) {
        return false;
    }

    let delegation_safety = has_eigenlayer_delegation_safety(ctx);
    let avs_safety = has_avs_validation(ctx);
    let slashing_safety = has_slashing_accounting(ctx);
    let operator_safety = has_operator_validation_pattern(ctx);
    let withdrawal_safety = has_withdrawal_queue_protection(ctx);

    // Count safety measures
    let safety_count = [
        delegation_safety,
        avs_safety,
        slashing_safety,
        operator_safety,
        withdrawal_safety,
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    // Comprehensive if 3+ patterns
    safety_count >= 3
}

/// Check if restaking function has proper operator validation
///
/// Convenience function for checking individual functions.
pub fn function_has_operator_validation(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    has_operator_validation(function, ctx)
}

/// Check if slashing function has proper evidence validation
///
/// Convenience function for checking slashing functions.
pub fn function_has_slashing_safety(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    has_evidence_parameter(function) && validates_evidence(function, ctx)
}

/// Check if withdrawal function has delay protection
///
/// Convenience function for checking withdrawal functions.
pub fn function_has_withdrawal_delay(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    has_withdrawal_delay(function, ctx)
}

// NOTE: Unit tests for restaking patterns are in tests/fp_regression_tests.rs
// The tests below require AnalysisContext which needs AST parsing.
// Pattern detection tests are covered by source-level tests in the FP regression suite.
