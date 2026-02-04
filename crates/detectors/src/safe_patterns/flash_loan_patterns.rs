//! Flash Loan Safe Patterns Module
//!
//! This module provides functions to detect safe flash loan implementations
//! that reduce false positive rates for flash loan vulnerability detectors.
//!
//! Safe patterns include:
//! - ERC-3156 compliant flash loan implementations
//! - Proper callback validation (msg.sender, initiator checks)
//! - Fee validation and bounds checking
//! - State validation after callback execution

use crate::types::AnalysisContext;

/// Detect ERC-3156 compliant flash loan implementation
///
/// ERC-3156 defines a standard interface for flash loans with proper security measures.
///
/// Patterns detected:
/// - IERC3156FlashLender interface
/// - IERC3156FlashBorrower interface
/// - flashLoan() function signature
/// - onFlashLoan() callback with CALLBACK_SUCCESS return
pub fn is_erc3156_compliant(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let source_lower = source.to_lowercase();

    // Pattern 1: ERC-3156 interfaces
    let has_erc3156_interface = source.contains("IERC3156FlashLender")
        || source.contains("IERC3156FlashBorrower")
        || source.contains("ERC3156")
        || source.contains("erc3156");

    // Pattern 2: Standard flashLoan function signature
    let has_flash_loan_sig = source_lower.contains("flashloan(")
        && (source_lower.contains("receiver") || source_lower.contains("borrower"));

    // Pattern 3: onFlashLoan callback
    let has_callback = source_lower.contains("onflashloan(");

    // Pattern 4: CALLBACK_SUCCESS constant (ERC-3156 standard return value)
    let has_callback_success = source.contains("CALLBACK_SUCCESS")
        || source.contains("keccak256(\"ERC3156FlashBorrower.onFlashLoan\")")
        || source.contains("0x439148f0bbc682ca079e46d6e2c2f0c1e3b820f1a291b069d8882abf8cf18dd9");

    // Strong indicator: Interface + callback + success constant
    if has_erc3156_interface && has_callback && has_callback_success {
        return true;
    }

    // Medium indicator: Interface + standard function signature
    if has_erc3156_interface && has_flash_loan_sig {
        return true;
    }

    // Pattern 5: FlashLoanSimpleReceiverBase (Aave V3 style)
    if source.contains("FlashLoanSimpleReceiverBase")
        || source.contains("FlashLoanReceiverBase")
        || source.contains("IFlashLoanSimpleReceiver")
    {
        return true;
    }

    false
}

/// Detect proper flash loan callback validation
///
/// Safe callbacks validate the caller and initiator to prevent unauthorized execution.
///
/// Patterns detected:
/// - msg.sender == pool/lender validation
/// - initiator == address(this) check
/// - Callback origin verification
pub fn has_flash_loan_callback_validation(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let source_lower = source.to_lowercase();

    // Pattern 1: msg.sender validation against pool/lender
    let has_sender_check = (source.contains("require(msg.sender ==")
        || source.contains("if (msg.sender !="))
        && (source_lower.contains("pool")
            || source_lower.contains("lender")
            || source_lower.contains("flashloan"));

    // Pattern 2: initiator == address(this) check
    let has_initiator_check = (source.contains("require(initiator ==")
        || source.contains("if (initiator !=")
        || source.contains("require(_initiator =="))
        && (source.contains("address(this)") || source_lower.contains("initiator"));

    // Pattern 3: onlyPool or onlyLender modifier
    let has_modifier = source_lower.contains("onlypool")
        || source_lower.contains("onlylender")
        || source_lower.contains("onlyflashloan");

    // Pattern 4: Callback with origin verification
    let has_origin_check = source_lower.contains("callback")
        && (source.contains("msg.sender") || source.contains("_initiator"));

    // Pattern 5: Aave V3 style executeOperation validation
    if source_lower.contains("executeoperation")
        && (source.contains("require(msg.sender") || source.contains("initiator"))
    {
        return true;
    }

    has_sender_check || has_initiator_check || has_modifier || has_origin_check
}

/// Detect flash loan fee validation
///
/// Safe implementations validate flash loan fees to prevent excessive charges.
///
/// Patterns detected:
/// - Fee bounds checking
/// - maxFlashLoanFee constant
/// - Fee percentage validation
pub fn has_flash_loan_fee_validation(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let source_lower = source.to_lowercase();

    // Pattern 1: Max fee constant
    if source.contains("MAX_FEE")
        || source.contains("maxFee")
        || source.contains("MAX_FLASH_LOAN_FEE")
        || source.contains("maxFlashLoanFee")
    {
        return true;
    }

    // Pattern 2: Fee validation in require
    if source.contains("require(fee") || source.contains("require(_fee") {
        return true;
    }

    // Pattern 3: Flash fee getter/validation
    if source_lower.contains("flashfee(") && source.contains("<=") {
        return true;
    }

    // Pattern 4: Fee percentage bounds
    if source_lower.contains("fee") && source.contains("BASIS_POINTS") {
        return true;
    }

    // Pattern 5: Fee cap in flashLoan function
    if source_lower.contains("flashloan")
        && (source.contains("fee <=") || source.contains("fee <"))
    {
        return true;
    }

    false
}

/// Detect state validation after flash loan callback
///
/// Safe implementations verify state integrity after callback execution.
///
/// Patterns detected:
/// - Balance validation after callback
/// - Repayment verification
/// - Invariant checks
pub fn has_state_validation_after_callback(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let source_lower = source.to_lowercase();

    // Pattern 1: Balance validation after callback
    let has_balance_check = source_lower.contains("balance")
        && (source.contains("require(")
            || source.contains("assert(")
            || source.contains("if ("));

    // Pattern 2: Repayment verification
    let has_repayment_check = source_lower.contains("repay")
        || source_lower.contains("payback")
        || (source_lower.contains("amount") && source_lower.contains("fee"));

    // Pattern 3: Invariant check pattern
    let has_invariant = source_lower.contains("invariant")
        || (source_lower.contains("before") && source_lower.contains("after"));

    // Pattern 4: Transfer + balance verification
    if (source_lower.contains("transferfrom") || source_lower.contains("safetransferfrom"))
        && has_balance_check
    {
        return true;
    }

    // Pattern 5: ERC-3156 return value check
    if source.contains("CALLBACK_SUCCESS") && source.contains("require(") {
        return true;
    }

    has_balance_check && (has_repayment_check || has_invariant)
}

/// Detect flash loan reentrancy protection
///
/// Safe implementations prevent reentrancy during flash loan execution.
///
/// Patterns detected:
/// - ReentrancyGuard usage
/// - nonReentrant modifier
/// - Custom lock patterns
pub fn has_flash_loan_reentrancy_protection(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let source_lower = source.to_lowercase();

    // Pattern 1: OpenZeppelin ReentrancyGuard
    if source.contains("ReentrancyGuard") || source.contains("nonReentrant") {
        return true;
    }

    // Pattern 2: Custom lock variable
    if source_lower.contains("locked") || source_lower.contains("_lock") {
        if source.contains("require(!") || source.contains("if (!") {
            return true;
        }
    }

    // Pattern 3: Flash loan specific lock
    if source_lower.contains("flashloanlock")
        || source_lower.contains("flashloan_lock")
        || source_lower.contains("inprogress")
    {
        return true;
    }

    // Pattern 4: EIP-1153 transient storage lock
    if source_lower.contains("tload") || source_lower.contains("tstore") {
        if source_lower.contains("lock") || source_lower.contains("reentrancy") {
            return true;
        }
    }

    false
}

/// Check if contract is a safe flash loan provider
///
/// Returns true if the contract implements safe flash loan lending patterns.
pub fn is_safe_flash_loan_provider(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let source_lower = source.to_lowercase();

    // Must have flash loan functionality
    if !source_lower.contains("flashloan") && !source_lower.contains("flash_loan") {
        return false;
    }

    // Check for multiple safety patterns
    let is_erc3156 = is_erc3156_compliant(ctx);
    let has_callback_validation = has_flash_loan_callback_validation(ctx);
    let has_state_validation = has_state_validation_after_callback(ctx);
    let has_reentrancy_protection = has_flash_loan_reentrancy_protection(ctx);

    // Safe if: ERC-3156 compliant or (callback + state validation + reentrancy)
    is_erc3156 || (has_callback_validation && has_state_validation && has_reentrancy_protection)
}

/// Check if contract is a safe flash loan borrower/receiver
///
/// Returns true if the contract safely receives and handles flash loans.
pub fn is_safe_flash_loan_borrower(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let source_lower = source.to_lowercase();

    // Must have callback functionality
    if !source_lower.contains("onflashloan")
        && !source_lower.contains("executeoperation")
        && !source_lower.contains("flashloancallback")
    {
        return false;
    }

    // Must validate callback caller
    let has_caller_validation = has_flash_loan_callback_validation(ctx);

    // Should have reentrancy protection
    let has_reentrancy = has_flash_loan_reentrancy_protection(ctx);

    // Safe if caller validation + reentrancy, or ERC-3156 compliant
    (has_caller_validation && has_reentrancy) || is_erc3156_compliant(ctx)
}

/// Detect comprehensive flash loan safety
///
/// Returns true if the contract has multiple flash loan safety measures.
pub fn has_comprehensive_flash_loan_safety(ctx: &AnalysisContext) -> bool {
    let callback_validation = has_flash_loan_callback_validation(ctx);
    let fee_validation = has_flash_loan_fee_validation(ctx);
    let state_validation = has_state_validation_after_callback(ctx);
    let reentrancy_protection = has_flash_loan_reentrancy_protection(ctx);
    let erc3156 = is_erc3156_compliant(ctx);

    // Count safety measures
    let safety_count = [
        callback_validation,
        fee_validation,
        state_validation,
        reentrancy_protection,
        erc3156,
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    // Comprehensive if 3+ patterns or ERC-3156 compliant
    safety_count >= 3 || erc3156
}

// NOTE: Unit tests for flash loan patterns are in tests/fp_regression_tests.rs
// The tests below require AnalysisContext which needs AST parsing.
// Pattern detection tests are covered by source-level tests in the FP regression suite.
