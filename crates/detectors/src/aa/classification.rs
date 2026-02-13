//! Account Abstraction Classification Utilities
//!
//! Shared pattern recognition functions for ERC-4337 security detectors.
//! Uses string-based analysis on function source code for reliable detection.

use crate::types::AnalysisContext;
use ast;

// ============================================================================
// Helper Functions
// ============================================================================

fn get_function_source<'a>(function: &ast::Function, ctx: &'a AnalysisContext) -> &'a str {
    let source = &ctx.source_code;
    let func_start = function.location.start().offset();
    let func_end = function.location.end().offset();

    if func_end <= func_start || func_start >= source.len() {
        return "";
    }

    &source[func_start..func_end.min(source.len())]
}

// ============================================================================
// Contract Type Classification
// ============================================================================

/// Checks if contract is an ERC-4337 Account (implements IAccount)
pub fn is_aa_account(ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();

    // Explicit IAccount interface — strong signal
    if source_lower.contains("iaccount") {
        return true;
    }

    // validateUserOp alone is not enough (EntryPoints also have it).
    // Require wallet-like structure: state (owner/nonce) or EntryPoint storage.
    let has_validate = ctx
        .get_functions()
        .iter()
        .any(|f| f.name.name == "validateUserOp");
    let has_wallet_structure = source_lower.contains("owner")
        || source_lower.contains("nonce")
        || source_lower.contains("entrypoint")
            && (source_lower.contains("trusted") || source_lower.contains("immutable"));

    has_validate && has_wallet_structure
}

/// Checks if contract is an ERC-4337 Paymaster (implements IPaymaster)
pub fn is_paymaster_contract(ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();

    // Check for IPaymaster interface
    source_lower.contains("ipaymaster") ||
    // Check for validatePaymasterUserOp function
    ctx.get_functions().iter().any(|f| f.name.name == "validatePaymasterUserOp")
}

/// Checks if contract uses signature aggregation
pub fn uses_signature_aggregation(ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();

    source_lower.contains("iaggregator")
        || ctx.get_functions().iter().any(|f| {
            let name = f.name.name.to_lowercase();
            name.contains("aggregate") && name.contains("signature")
        })
}

// ============================================================================
// Paymaster Detection Patterns
// ============================================================================

/// Checks if function has replay protection (usedHashes tracking)
pub fn has_replay_protection(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    // Check for hash tracking storage variable
    let has_hash_tracking = source_lower.contains("usedhash")
        || source_lower.contains("executed")
        || source_lower.contains("processed")
        || source_lower.contains("usedop");

    // Check function uses hash tracking
    has_hash_tracking
        && func_lower.contains("require")
        && (func_lower.contains("usedhash") || func_lower.contains("executed"))
}

/// Checks if paymaster has spending limits
pub fn has_spending_limits(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    // Check for spending tracking storage
    let has_spent_tracking = source_lower.contains("spent")
        || source_lower.contains("allocated")
        || source_lower.contains("accountspent");

    // Check for maximum limit constant
    let has_max_constant = source_lower.contains("max")
        && (source_lower.contains("account")
            || source_lower.contains("per")
            || source_lower.contains("limit"));

    // Check function validates spending
    has_spent_tracking && has_max_constant && func_lower.contains("require")
}

/// Checks if paymaster validates target addresses
pub fn has_target_validation(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    // Check for allowedTargets mapping
    let has_whitelist = source_lower.contains("allowedtarget")
        || source_lower.contains("whitelist")
        || source_lower.contains("approvedtarget");

    // Check function references the whitelist
    has_whitelist
        && func_lower.contains("require")
        && (func_lower.contains("allowedtarget") || func_lower.contains("whitelist"))
}

/// Checks if paymaster enforces gas limits
pub fn has_gas_limits(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    // Check for MAX_GAS constant
    let has_gas_constant = source_lower.contains("max") && source_lower.contains("gas");

    // Check function validates gas
    has_gas_constant
        && func_lower.contains("require")
        && (func_lower.contains("gaslimit") || func_lower.contains("callgaslimit"))
}

/// Checks if signature validation includes chain ID
pub fn validates_chain_id(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    func_lower.contains("chainid")
        && (func_lower.contains("block.chainid") || func_lower.contains("chain"))
}

// ============================================================================
// Nonce Management Detection Patterns
// ============================================================================

/// Checks if function uses EntryPoint's getNonce (not manual tracking)
pub fn uses_entrypoint_nonce(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    func_lower.contains("getnonce")
        && (func_lower.contains("entrypoint") || func_lower.contains("entry"))
}

/// Checks if contract uses fixed nonce key (always 0)
pub fn uses_fixed_nonce_key(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    // Check for getNonce(..., 0) pattern
    func_lower.contains("getnonce") && (func_lower.contains(", 0)") || func_lower.contains(",0)"))
}

/// Checks if contract has session key nonce isolation
pub fn has_session_key_nonce_isolation(ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();

    source_lower.contains("sessionnoncekey")
        || (source_lower.contains("session")
            && source_lower.contains("nonce")
            && source_lower.contains("key")
            && source_lower.contains("mapping"))
}

// ============================================================================
// Session Key Detection Patterns
// ============================================================================

/// Checks if contract has session keys
pub fn has_session_keys(ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();
    source_lower.contains("sessionkey")
}

/// Checks if session keys have restrictions (not unlimited access)
pub fn has_session_key_restrictions(ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();

    // Check for SessionKeyData struct with restriction fields
    source_lower.contains("sessionkey")
        && (source_lower.contains("validuntil")
            || source_lower.contains("allowedtarget")
            || source_lower.contains("spendinglimit"))
}

/// Checks if session keys have expiration time
pub fn has_session_expiration(ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();

    source_lower.contains("sessionkey")
        && (source_lower.contains("validuntil")
            || source_lower.contains("expires")
            || source_lower.contains("deadline"))
}

/// Checks if session keys have target restrictions
pub fn has_target_restrictions(ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();

    source_lower.contains("sessionkey")
        && (source_lower.contains("allowedtarget") || source_lower.contains("whitelist"))
}

/// Checks if session keys have function selector restrictions
pub fn has_selector_restrictions(ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();

    source_lower.contains("sessionkey")
        && (source_lower.contains("allowedselector") || source_lower.contains("selector"))
}

/// Checks if session keys have period-based spending limits
pub fn has_period_based_limits(ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();

    source_lower.contains("sessionkey")
        && source_lower.contains("period")
        && (source_lower.contains("duration") || source_lower.contains("periodstart"))
}

/// Checks if session keys have emergency pause mechanism
pub fn has_emergency_pause(ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();

    // Check struct has paused field and pause function exists
    source_lower.contains("sessionkey")
        && source_lower.contains("pause")
        && ctx.get_functions().iter().any(|f| {
            let name = f.name.name.to_lowercase();
            name.contains("pause") && name.contains("session")
        })
}

// ============================================================================
// Social Recovery Detection Patterns
// ============================================================================

/// Checks if contract has social recovery mechanism
pub fn has_social_recovery(ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();

    source_lower.contains("recovery") || source_lower.contains("guardian")
}

/// Checks if recovery mechanism has time delay
pub fn has_recovery_delay(ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();

    // Check for RECOVERY_DELAY constant
    let has_delay_constant = source_lower.contains("recovery") && source_lower.contains("delay");

    // Check executeRecovery validates timestamp
    let validates_timestamp = ctx.get_functions().iter().any(|f| {
        if f.name.name.to_lowercase().contains("executerecovery") {
            let func_source = get_function_source(f, ctx);
            let func_lower = func_source.to_lowercase();
            func_lower.contains("timestamp") && func_lower.contains("require")
        } else {
            false
        }
    });

    has_delay_constant && validates_timestamp
}

/// Checks if recovery has sufficient guardian threshold
pub fn has_sufficient_threshold(ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();

    // Check for threshold > 1 (not 1-of-N)
    // Look for patterns like "THRESHOLD = 2", "THRESHOLD = 3", etc.
    source_lower.contains("threshold")
        && !(source_lower.contains("threshold = 1") || source_lower.contains("threshold=1"))
}

/// Checks if contract has recovery cancellation function
pub fn has_recovery_cancellation(ctx: &AnalysisContext) -> bool {
    ctx.get_functions()
        .iter()
        .any(|f| f.name.name.to_lowercase().contains("cancelrecovery"))
}

// ============================================================================
// Gas Griefing Detection Patterns
// ============================================================================

/// Checks if function has unbounded loops
pub fn has_unbounded_loops(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    // Check for loops with storage-based bounds (e.g., guardians.length)
    // Common patterns: for (uint i = 0; i < array.length; i++)
    func_lower.contains("for") && func_lower.contains(".length") && !func_lower.contains("require") // No max length validation
}

/// Checks if function has storage writes (banned in validation)
pub fn has_storage_writes(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    // Check for assignment patterns (but not in local vars)
    // Look for storage writes like: mapping[key] = value or stateVar = value
    (func_lower.contains("[") && func_lower.contains("] ="))
        || (func_lower.matches("=").count() > func_lower.matches("==").count()
            && !func_lower.contains("memory")
            && !func_lower.contains("calldata"))
}

// ============================================================================
// Signature Aggregation Detection Patterns
// ============================================================================

/// Checks if function validates aggregator address
pub fn validates_aggregator(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    // Check for trusted aggregators whitelist
    let has_whitelist = source_lower.contains("aggregator")
        && (source_lower.contains("trusted")
            || source_lower.contains("allowed")
            || source_lower.contains("whitelist"));

    // Check function validates against whitelist
    has_whitelist && func_lower.contains("require") && func_lower.contains("aggregator")
}

/// Checks if function validates signature count against threshold
pub fn checks_signature_count(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let source_lower = ctx.source_code.to_lowercase();
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    // Check for threshold constant
    let has_threshold = source_lower.contains("threshold");

    // Check function compares against threshold
    has_threshold
        && func_lower.contains("require")
        && (func_lower.contains(">=") || func_lower.contains("threshold"))
}

/// Checks if function validates signer uniqueness
pub fn checks_signer_uniqueness(function: &ast::Function, ctx: &AnalysisContext) -> bool {
    let func_source = get_function_source(function, ctx);
    let func_lower = func_source.to_lowercase();

    // Look for duplicate detection logic
    // Common patterns: nested for loops or seen mapping
    (func_lower.matches("for").count() >= 2) || // Nested loops
    (func_lower.contains("seen") && func_lower.contains("mapping"))
}
