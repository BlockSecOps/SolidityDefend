// ERC-7683 Contract Classification Utilities
//
// Provides utilities to identify and classify ERC-7683 intent contracts:
// - Origin settlers (IOriginSettler)
// - Destination settlers (IDestinationSettler)
// - Hybrid contracts (both)

use crate::types::AnalysisContext;
use ast;

/// Identifies if a contract implements ERC-7683 intent functionality
pub fn is_intent_contract(ctx: &AnalysisContext) -> bool {
    is_origin_settler(ctx)
        || is_destination_settler(ctx)
        || has_intent_structs(ctx)
        || has_intent_interfaces(ctx)
}

/// Identifies Origin Settler contracts (IOriginSettler)
pub fn is_origin_settler(ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();

    // Check for IOriginSettler interface
    if source_lower.contains("ioriginsettler") {
        return true;
    }

    // Check for characteristic functions
    let has_open_for = ctx.get_functions().iter().any(|f| {
        let name_lower = f.name.name.to_lowercase();
        name_lower == "openfor" || name_lower == "open_for"
    });

    let has_open = ctx.get_functions().iter().any(|f| {
        let name_lower = f.name.name.to_lowercase();
        name_lower == "open" && !f.parameters.is_empty()
    });

    let has_resolve_for = ctx.get_functions().iter().any(|f| {
        let name_lower = f.name.name.to_lowercase();
        name_lower == "resolvefor" || name_lower == "resolve_for"
    });

    // Origin settler typically has openFor or open + resolveFor
    (has_open_for || has_open) && has_resolve_for
}

/// Identifies Destination Settler contracts (IDestinationSettler)
pub fn is_destination_settler(ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();

    // Check for IDestinationSettler interface
    if source_lower.contains("idestinationsettler") {
        return true;
    }

    // Check for fill function characteristic of destination settlers
    let has_fill = ctx.get_functions().iter().any(|f| {
        let name_lower = f.name.name.to_lowercase();
        name_lower == "fill" && f.parameters.len() >= 2
    });

    // Check for cross-chain context
    let has_cross_chain_context = source_lower.contains("orderid")
        || source_lower.contains("origindata")
        || source_lower.contains("fillerdata");

    has_fill && has_cross_chain_context
}

/// Checks for ERC-7683 order structs
pub fn has_intent_structs(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Check for standard ERC-7683 struct names
    source.contains("GaslessCrossChainOrder")
        || source.contains("OnchainCrossChainOrder")
        || source.contains("ResolvedCrossChainOrder")
        || source.contains("CrossChainOrder")
}

/// Checks for ERC-7683 interface imports or definitions
pub fn has_intent_interfaces(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    source.contains("IOriginSettler")
        || source.contains("IDestinationSettler")
        || source.contains("ISettler")
}

/// Finds functions that handle gasless cross-chain orders
pub fn is_gasless_order_function(function: &ast::Function) -> bool {
    let name_lower = function.name.name.to_lowercase();

    // openFor is the canonical gasless function
    if name_lower == "openfor" || name_lower == "open_for" {
        return true;
    }

    // Check if function takes signature parameter (indicates gasless)
    function.parameters.iter().any(|param| {
        if let Some(param_name) = &param.name {
            let param_name_lower = param_name.name.to_lowercase();
            param_name_lower.contains("signature") || param_name_lower == "sig"
        } else {
            false
        }
    })
}

/// Finds fill/execution functions in destination settlers
pub fn is_fill_function(function: &ast::Function) -> bool {
    let name_lower = function.name.name.to_lowercase();

    name_lower == "fill" || name_lower == "fillorder" || name_lower == "fill_order"
}

/// Finds settlement functions (open, openFor, fill, resolve)
pub fn is_settlement_function(function: &ast::Function) -> bool {
    let name_lower = function.name.name.to_lowercase();

    name_lower == "open"
        || name_lower == "openfor"
        || name_lower == "open_for"
        || name_lower == "fill"
        || name_lower == "fillorder"
        || name_lower == "resolve"
        || name_lower == "resolvefor"
        || name_lower == "resolve_for"
}

/// Checks if contract uses Permit2 for gasless approvals
pub fn uses_permit2(ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();

    source_lower.contains("permit2")
        || source_lower.contains("ipermit2")
        || source_lower.contains("permitwitnesstransferfrom")
        || source_lower.contains("permittransferfrom")
}

/// Checks for EIP-712 domain separator (should include chainId)
pub fn has_eip712_domain_separator(ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();

    (source_lower.contains("domain_separator") || source_lower.contains("domainseparator"))
        && source_lower.contains("eip712")
}

/// Checks if domain separator includes chainId
pub fn domain_separator_includes_chain_id(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Look for domain separator construction with chainId
    if let Some(domain_pos) = source.to_lowercase().find("domain") {
        let after_domain = &source[domain_pos..];

        // Check next 500 chars for chainId
        let search_window = &after_domain[..after_domain.len().min(500)];
        let search_lower = search_window.to_lowercase();

        search_lower.contains("chainid") || search_lower.contains("chain.id")
    } else {
        false
    }
}

/// Checks for chainId validation in function
pub fn has_chain_id_validation(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let func_start = function.location.start().offset();
    let func_end = function.location.end().offset();

    if func_end <= func_start || func_start >= source.len() {
        return false;
    }

    let func_source = &source[func_start..func_end.min(source.len())];
    let func_lower = func_source.to_lowercase();

    // Check for explicit chainId validation
    let has_chain_check = (func_lower.contains("chainid") || func_lower.contains("chain.id"))
        && (func_lower.contains("==")
            || func_lower.contains("require")
            || func_lower.contains("if"));

    // Check for block.chainid comparison
    let has_block_chainid = func_lower.contains("block.chainid");

    has_chain_check && has_block_chainid
}

/// Checks for nonce validation in function
pub fn has_nonce_validation(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let func_start = function.location.start().offset();
    let func_end = function.location.end().offset();

    if func_end <= func_start || func_start >= source.len() {
        return false;
    }

    let func_source = &source[func_start..func_end.min(source.len())];
    let func_lower = func_source.to_lowercase();

    // Check for nonce validation patterns
    let has_nonce_check = func_lower.contains("nonce")
        && (func_lower.contains("require")
            || func_lower.contains("if")
            || func_lower.contains("revert"));

    // Check for used nonce tracking
    let has_used_tracking = func_lower.contains("usednonces")
        || func_lower.contains("used_nonces")
        || func_lower.contains("filledno nces")
        || func_lower.contains("nonce") && func_lower.contains("used");

    has_nonce_check || has_used_tracking
}

/// Checks if nonce is incremented or marked as used
pub fn has_nonce_update(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let func_start = function.location.start().offset();
    let func_end = function.location.end().offset();

    if func_end <= func_start || func_start >= source.len() {
        return false;
    }

    let func_source = &source[func_start..func_end.min(source.len())];
    let func_lower = func_source.to_lowercase();

    // Check for nonce increment (++)
    let has_increment = func_lower.contains("nonce++")
        || func_lower.contains("nonce + 1")
        || func_lower.contains("nonce+=");

    // Check for marking nonce as used (= true)
    let has_marking = func_lower.contains("= true") && func_lower.contains("nonce");

    // Check for Permit2 (handles nonce internally)
    let uses_permit2 =
        func_lower.contains("permit2") || func_lower.contains("permitwitnesstransferfrom");

    has_increment || has_marking || uses_permit2
}

/// Checks for deadline validation (fillDeadline or openDeadline)
pub fn has_deadline_validation(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let func_start = function.location.start().offset();
    let func_end = function.location.end().offset();

    if func_end <= func_start || func_start >= source.len() {
        return false;
    }

    let func_source = &source[func_start..func_end.min(source.len())];
    let func_lower = func_source.to_lowercase();

    // Check for deadline validation
    let has_deadline = func_lower.contains("deadline") || func_lower.contains("expir");
    let has_timestamp_check = func_lower.contains("timestamp")
        && (func_lower.contains("<=")
            || func_lower.contains("<")
            || func_lower.contains("require"));

    has_deadline && has_timestamp_check
}

/// Checks for solver/filler authentication
pub fn has_solver_authentication(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let func_start = function.location.start().offset();
    let func_end = function.location.end().offset();

    if func_end <= func_start || func_start >= source.len() {
        return false;
    }

    let func_source = &source[func_start..func_end.min(source.len())];
    let func_lower = func_source.to_lowercase();

    // Check for solver/filler whitelist
    let has_whitelist = func_lower.contains("approvedsolver")
        || func_lower.contains("approved_solver")
        || func_lower.contains("whitelistedsolver")
        || func_lower.contains("approvedfiller")
        || func_lower.contains("authorized");

    // Check for msg.sender validation
    let has_sender_check = func_lower.contains("msg.sender")
        && (func_lower.contains("require") || func_lower.contains("if"));

    has_whitelist && has_sender_check
}

/// Checks for reentrancy protection
pub fn has_reentrancy_protection(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let func_start = function.location.start().offset();
    let func_end = function.location.end().offset();

    if func_end <= func_start || func_start >= source.len() {
        return false;
    }

    // Check function modifiers
    for modifier in &function.modifiers {
        let modifier_name = modifier.name.name.to_lowercase();
        if modifier_name.contains("nonreentrant")
            || modifier_name.contains("non_reentrant")
            || modifier_name.contains("reentrancyguard")
        {
            return true;
        }
    }

    // Check for reentrancy guard pattern in function body
    let func_source = &source[func_start..func_end.min(source.len())];
    let func_lower = func_source.to_lowercase();

    func_lower.contains("reentrancyguard")
        || func_lower.contains("reentrancy_guard")
        || func_lower.contains("_locked")
        || func_lower.contains("_status")
}

/// Checks for output amount validation (minReceived)
pub fn has_output_validation(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let func_start = function.location.start().offset();
    let func_end = function.location.end().offset();

    if func_end <= func_start || func_start >= source.len() {
        return false;
    }

    let func_source = &source[func_start..func_end.min(source.len())];
    let func_lower = func_source.to_lowercase();

    // Check for minReceived validation
    let has_min_received = func_lower.contains("minreceived")
        || func_lower.contains("min_received")
        || func_lower.contains("minoutput");

    // Check for amount comparison
    let has_comparison = (func_lower.contains(">=") || func_lower.contains(">"))
        && (func_lower.contains("amount") || func_lower.contains("received"));

    has_min_received && has_comparison
}

/// Checks for maxSpent validation
pub fn has_max_spent_validation(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let func_start = function.location.start().offset();
    let func_end = function.location.end().offset();

    if func_end <= func_start || func_start >= source.len() {
        return false;
    }

    let func_source = &source[func_start..func_end.min(source.len())];
    let func_lower = func_source.to_lowercase();

    // Check for maxSpent validation
    let has_max_spent = func_lower.contains("maxspent")
        || func_lower.contains("max_spent")
        || func_lower.contains("maxinput");

    // Check for amount comparison
    let has_comparison = (func_lower.contains("<=") || func_lower.contains("<"))
        && (func_lower.contains("amount") || func_lower.contains("spent"));

    has_max_spent && has_comparison
}

/// Checks for double-fill prevention
pub fn has_double_fill_prevention(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let func_start = function.location.start().offset();
    let func_end = function.location.end().offset();

    if func_end <= func_start || func_start >= source.len() {
        return false;
    }

    let func_source = &source[func_start..func_end.min(source.len())];
    let func_lower = func_source.to_lowercase();

    // Check for filled order tracking
    let has_filled_tracking = func_lower.contains("filledorder")
        || func_lower.contains("filled_order")
        || func_lower.contains("usedorder")
        || func_lower.contains("executedorder");

    // Check for validation
    let has_validation = func_lower.contains("require") || func_lower.contains("if");

    has_filled_tracking && has_validation
}

/// Checks for MEV protection mechanisms (commit-reveal)
pub fn has_mev_protection(ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();

    // Check for commit-reveal scheme
    let has_commitment = source_lower.contains("commitment") || source_lower.contains("commit");

    let has_reveal = source_lower.contains("reveal");

    // Check for private mempool usage
    let has_private_mempool =
        source_lower.contains("flashbots") || source_lower.contains("privatemem pool");

    (has_commitment && has_reveal) || has_private_mempool
}

#[cfg(test)]
mod tests {

    // Tests would go here
    // For now, the functions are designed to be testable with mock AnalysisContext
}
