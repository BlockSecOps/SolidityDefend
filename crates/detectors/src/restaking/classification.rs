//! Shared classification and utility functions for restaking security detectors
//!
//! This module provides common pattern recognition functions used across all 6 restaking
//! detectors to avoid code duplication and ensure consistent detection logic.

use crate::types::AnalysisContext;
use ast;

// ============================================================================
// Contract Type Identification
// ============================================================================

/// Checks if contract is a restaking protocol (EigenLayer integration)
pub fn is_restaking_contract(ctx: &AnalysisContext) -> bool {
    let source_lower = crate::utils::get_contract_source(ctx).to_lowercase();

    // Check for restaking-specific keywords
    source_lower.contains("restaking") ||
    source_lower.contains("eigenlayer") ||
    source_lower.contains("delegation") && source_lower.contains("operator") ||
    source_lower.contains("slash") && source_lower.contains("operator") ||

    // Check for common restaking interfaces
    source_lower.contains("idelegationmanager") ||
    source_lower.contains("istrategymanager") ||
    source_lower.contains("ieigenpod") ||
    source_lower.contains("iavs") ||

    // Check for restaking-specific functions
    has_function_name(ctx, "delegateTo") ||
    has_function_name(ctx, "undelegate") ||
    has_function_name(ctx, "registerAsOperator")
}

/// Checks if contract is a Liquid Restaking Token (LRT)
pub fn is_lrt_contract(ctx: &AnalysisContext) -> bool {
    let source_lower = crate::utils::get_contract_source(ctx).to_lowercase();

    // LRT-specific patterns
    (source_lower.contains("liquid") && source_lower.contains("restaking")) ||
    source_lower.contains("lrt") ||

    // Common LRT names
    source_lower.contains("ezeth") ||  // Renzo
    source_lower.contains("rseth") ||  // Kelp DAO
    source_lower.contains("pufeth") || // Puffer

    // ERC-4626 vault pattern + restaking
    (is_erc4626_vault(ctx) && source_lower.contains("restaking")) ||
    (is_erc4626_vault(ctx) && source_lower.contains("eigenlayer"))
}

/// Checks if contract implements ERC-4626 vault interface
pub fn is_erc4626_vault(ctx: &AnalysisContext) -> bool {
    let source_lower = crate::utils::get_contract_source(ctx).to_lowercase();

    // ERC-4626 interface functions
    (source_lower.contains("totalassets") || source_lower.contains("total_assets"))
        && (source_lower.contains("converttoshares") || source_lower.contains("convert_to_shares"))
        && (source_lower.contains("converttoassets") || source_lower.contains("convert_to_assets"))
}

/// Checks if contract integrates with EigenLayer
pub fn is_eigenlayer_integration(ctx: &AnalysisContext) -> bool {
    let source_lower = crate::utils::get_contract_source(ctx).to_lowercase();

    source_lower.contains("eigenlayer")
        || source_lower.contains("idelegationmanager")
        || source_lower.contains("istrategymanager")
        || source_lower.contains("ieigenpod")
}

// ============================================================================
// Function Name Helpers
// ============================================================================

fn has_function_name(ctx: &AnalysisContext, name: &str) -> bool {
    ctx.get_functions().iter().any(|f| {
        f.name
            .name
            .to_lowercase()
            .contains(name.to_lowercase().as_str())
    })
}

pub fn get_function_source<'a>(function: &ast::Function, ctx: &'a AnalysisContext) -> &'a str {
    let source = &ctx.source_code;
    let func_start = function.location.start().offset();
    let func_end = function.location.end().offset();

    if func_end <= func_start || func_start >= source.len() {
        return "";
    }

    &source[func_start..func_end.min(source.len())]
}

// ============================================================================
// Delegation Detection
// ============================================================================

/// Checks if function validates operator before delegation
pub fn has_operator_validation(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    // Check for operator whitelist patterns
    (func_lower.contains("approvedoperators")
        || func_lower.contains("approved_operators")
        || func_lower.contains("operatorwhitelist")
        || func_lower.contains("operator_whitelist")
        || func_lower.contains("isoperator")
        || func_lower.contains("is_operator"))
        && func_lower.contains("require")
}

/// Checks if function enforces delegation cap
pub fn has_delegation_cap(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    (func_lower.contains("maxdelegation")
        || func_lower.contains("max_delegation")
        || func_lower.contains("delegationcap")
        || func_lower.contains("delegation_cap"))
        && (func_lower.contains("require") || func_lower.contains("<="))
}

/// Checks if allocation changes have time delay
pub fn has_allocation_delay(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    (func_lower.contains("delay")
        || func_lower.contains("timelock")
        || func_lower.contains("pending"))
        && func_lower.contains("timestamp")
        && (func_lower.contains("require") || func_lower.contains(">="))
}

/// Checks if function has operator parameter
pub fn has_operator_parameter(function: &ast::Function) -> bool {
    function.parameters.iter().any(|param| {
        if let Some(param_name) = &param.name {
            param_name.name.to_lowercase().contains("operator")
        } else {
            false
        }
    })
}

/// Checks if function increases delegation amount
pub fn increases_delegation_amount(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    (func_lower.contains("delegat") && func_lower.contains("+="))
        || (func_lower.contains("totaldelegated") && func_lower.contains("+"))
        || func_lower.contains("_delegate(")
}

/// Checks if contract has max operator delegation storage
pub fn has_max_operator_delegation(ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();

    source_lower.contains("maxoperatordelegation")
        || source_lower.contains("max_operator_delegation")
        || source_lower.contains("operatormaxdelegation")
}

/// Checks if contract has delegation tracking
pub fn has_delegation_tracking(ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();

    (source_lower.contains("delegations") || source_lower.contains("delegated"))
        && source_lower.contains("mapping")
}

/// Checks if function has time delay check
pub fn has_time_delay(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    func_lower.contains("timestamp")
        && (func_lower.contains("delay")
            || func_lower.contains(">=")
            || func_lower.contains("require"))
}

// ============================================================================
// Slashing Detection
// ============================================================================

/// Checks if slashing function has evidence parameter
pub fn has_evidence_parameter(function: &ast::Function) -> bool {
    function.parameters.iter().any(|param| {
        if let Some(param_name) = &param.name {
            let name_lower = param_name.name.to_lowercase();
            name_lower.contains("evidence") || name_lower.contains("proof")
        } else {
            false
        }
    })
}

/// Checks if slashing function validates evidence
pub fn validates_evidence(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    func_lower.contains("evidence")
        && (func_lower.contains("require")
            || func_lower.contains("length")
            || func_lower.contains("validate"))
}

/// Checks if slashing has delay/appeal period
pub fn has_slashing_delay(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    (func_source.contains("SLASHING_DELAY")
        || func_source.contains("slashingDelay")
        || func_lower.contains("slash") && func_lower.contains("delay"))
        && func_lower.contains("timestamp")
        && (func_lower.contains(">=") || func_lower.contains("require"))
}

/// Checks if slashing validates maximum percentage
pub fn has_max_slashing_validation(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    (func_lower.contains("max") && func_lower.contains("slash"))
        && (func_lower.contains("require") || func_lower.contains("<="))
}

/// Checks if slashing checks for compound slashing
pub fn checks_already_slashed(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    (func_lower.contains("totalslashed") || func_lower.contains("total_slashed"))
        && (func_lower.contains("require") || func_lower.contains("<="))
}

/// Checks if contract has MAX_SLASH_PERCENTAGE constant
pub fn has_max_slash_percentage_constant(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    source.contains("MAX_SLASH_PERCENTAGE")
        || source.contains("MAX_SLASHING_PERCENTAGE")
        || source.contains("maxSlashPercentage")
}

/// Checks if function has slashing percentage parameter
pub fn has_slashing_percentage_param(function: &ast::Function) -> bool {
    function.parameters.iter().any(|param| {
        if let Some(param_name) = &param.name {
            let name_lower = param_name.name.to_lowercase();
            (name_lower.contains("slash") && name_lower.contains("percent"))
                || name_lower.contains("slashpercentage")
                || name_lower.contains("slash_percentage")
        } else {
            false
        }
    })
}

/// Checks if function validates max slashing
pub fn validates_max_slashing(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    (func_lower.contains("max") && func_lower.contains("slash")) && func_lower.contains("require")
}

// ============================================================================
// Share Inflation Detection (LRT/Vault)
// ============================================================================

/// Checks if deposit function has initial share lock (OpenZeppelin pattern)
pub fn has_initial_share_lock(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    // Check for OpenZeppelin pattern: _mint(address(0), INITIAL_SHARE_LOCK)
    (func_lower.contains("_mint") && func_lower.contains("address(0)")) ||
    func_lower.contains("initial_share_lock") ||
    func_lower.contains("initialsharelock") ||
    func_source.contains("INITIAL_SHARE_LOCK") ||
    // Check for dead shares pattern (mint 1000 to address(0))
    (func_lower.contains("1000") && func_lower.contains("_mint") && func_lower.contains("address(0)"))
}

/// Checks if deposit function detects donations via balance before/after
pub fn has_donation_detection(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    (func_lower.contains("balancebefore") || func_lower.contains("balance_before"))
        && (func_lower.contains("balanceafter") || func_lower.contains("balance_after"))
        && func_lower.contains("require")
}

/// Checks if deposit function validates minimum shares
pub fn checks_minimum_shares(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    func_lower.contains("shares")
        && func_lower.contains(">")
        && (func_lower.contains("require") || func_lower.contains("0"))
}

/// Checks if totalAssets() uses balanceOf (vulnerable to donations)
pub fn uses_balance_of(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    func_lower.contains("balanceof") && func_lower.contains("address(this)")
}

/// Checks if contract has tracked assets storage (not using balanceOf)
pub fn has_tracked_assets_storage(ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();

    source_lower.contains("_totalassets")
        || source_lower.contains("_total_assets")
        || source_lower.contains("trackedassets")
        || source_lower.contains("tracked_assets")
        || source_lower.contains("totaltracked")
}

/// Checks if function has first deposit logic
pub fn has_first_deposit_logic(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    (func_lower.contains("totalsupply") || func_lower.contains("total_supply"))
        && func_lower.contains("== 0")
        && func_lower.contains("if")
}

// ============================================================================
// Withdrawal Detection
// ============================================================================

/// Checks if withdrawal function enforces delay
pub fn has_withdrawal_delay(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    (func_source.contains("WITHDRAWAL_DELAY")
        || func_source.contains("withdrawalDelay")
        || (func_lower.contains("withdrawal") && func_lower.contains("delay")))
        && func_lower.contains("timestamp")
        && (func_lower.contains("require") || func_lower.contains(">="))
}

/// Checks if deposit function maintains liquidity reserve
pub fn has_liquidity_reserve(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    (func_lower.contains("liquidity")
        || func_lower.contains("reserve")
        || func_lower.contains("buffer"))
        && (func_lower.contains("percentage")
            || func_lower.contains("%")
            || func_lower.contains("/100")
            || func_lower.contains("* 10"))
}

/// Checks if contract has two-step withdrawal (request + complete)
pub fn is_two_step_withdrawal(ctx: &AnalysisContext) -> bool {
    let has_request = ctx.get_functions().iter().any(|f| {
        let name = f.name.name.to_lowercase();
        (name.contains("request") && name.contains("withdraw"))
            || name == "requestwithdrawal"
            || name == "request_withdrawal"
    });

    let has_complete = ctx.get_functions().iter().any(|f| {
        let name = f.name.name.to_lowercase();
        (name.contains("complete") && name.contains("withdraw"))
            || name == "completewithdrawal"
            || name == "complete_withdrawal"
    });

    has_request && has_complete
}

/// Checks if contract has WITHDRAWAL_DELAY constant
pub fn has_withdrawal_delay_constant(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    source.contains("WITHDRAWAL_DELAY")
        || source.contains("withdrawalDelay")
        || source.contains("WITHDRAWAL_PERIOD")
}

/// Checks if withdrawal is single-step (instant)
pub fn is_single_step_withdrawal(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    // Single-step if it burns shares AND transfers in same function
    func_lower.contains("_burn") && func_lower.contains("transfer")
}

// ============================================================================
// AVS Validation Detection
// ============================================================================

/// Checks if AVS registration requires collateral
pub fn has_collateral_requirement(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    (func_lower.contains("collateral") || func_lower.contains("msg.value"))
        && func_lower.contains("require")
        && (func_lower.contains(">=") || func_lower.contains(">"))
}

/// Checks if AVS registration requires security validation
pub fn has_security_validation(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    (func_lower.contains("audit")
        || func_lower.contains("security")
        || func_lower.contains("approved"))
        && func_lower.contains("require")
}

/// Checks if contract has governance approval for AVS
pub fn has_governance_approval(ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();

    (source_lower.contains("approveavs") || source_lower.contains("approve_avs"))
        || (source_lower.contains("governance") && source_lower.contains("avs"))
}

/// Checks if AVS delegation requires operator approval
pub fn requires_operator_approval(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    (func_lower.contains("msg.sender") && func_lower.contains("operator"))
        || func_lower.contains("onlyoperator")
        || (func_lower.contains("require") && func_lower.contains("operator"))
}

/// Checks if function validates max slashing cap
pub fn has_max_slashing_cap(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    (func_lower.contains("max") && func_lower.contains("slash"))
        && (func_lower.contains("require") || func_lower.contains("<="))
}

// ============================================================================
// Rewards Detection
// ============================================================================

/// Checks if reward distribution is proportional (pro-rata)
pub fn has_proportional_distribution(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    // Check for pro-rata calculation patterns
    (func_lower.contains("stakes") || func_lower.contains("balance"))
        && func_lower.contains("/")
        && (func_lower.contains("totalstaked")
            || func_lower.contains("total_staked")
            || func_lower.contains("totalsupply")
            || func_lower.contains("total_supply"))
}

/// Checks if points calculation is time-weighted
pub fn has_time_weighting(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    (func_lower.contains("timestamp") || func_lower.contains("time"))
        && (func_lower.contains("deposit") || func_lower.contains("stake"))
        && (func_lower.contains("block.timestamp") || func_lower.contains("block .timestamp"))
}

/// Checks if withdrawal has early penalty
pub fn has_early_withdrawal_penalty(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    func_lower.contains("penalty")
        || (func_lower.contains("timestamp")
            && func_lower.contains("<")
            && (func_lower.contains("reward") || func_lower.contains("slash")))
}

/// Checks if reward calculation uses balanceOf (vulnerable to donations)
pub fn reward_uses_balance_of(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    (func_lower.contains("reward") || func_lower.contains("earned"))
        && func_lower.contains("balanceof")
        && func_lower.contains("address(this)")
}

/// Checks if reward rate has maximum cap
pub fn has_max_rate_cap(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    (func_lower.contains("max") && func_lower.contains("rate"))
        && (func_lower.contains("require") || func_lower.contains("<="))
}
