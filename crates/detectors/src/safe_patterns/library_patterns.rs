/// Library pattern recognition for false positive reduction
///
/// This module detects usage of well-known, audited libraries that
/// provide built-in security protections. When a contract uses these
/// libraries correctly, many vulnerability patterns are already mitigated.

use crate::types::AnalysisContext;

// ============================================================================
// OpenZeppelin Library Detection
// ============================================================================

/// Detect OpenZeppelin library imports
pub fn uses_openzeppelin(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    source.contains("@openzeppelin")
        || source.contains("openzeppelin-contracts")
        || source.contains("OpenZeppelin")
}

/// Detect OpenZeppelin SafeERC20 usage
/// SafeERC20 handles return value checking for ERC20 tokens
pub fn uses_safe_erc20(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    source.contains("SafeERC20")
        || source.contains("safeTransfer")
        || source.contains("safeTransferFrom")
        || source.contains("safeApprove")
        || source.contains("safeIncreaseAllowance")
        || source.contains("safeDecreaseAllowance")
}

/// Detect OpenZeppelin SafeMath usage (for Solidity < 0.8)
pub fn uses_safe_math(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    source.contains("SafeMath")
        || source.contains("using SafeMath")
        || (source.contains(".add(") && source.contains(".sub(") && source.contains(".mul("))
}

/// Detect OpenZeppelin Address library usage
pub fn uses_address_library(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    source.contains("Address.")
        || source.contains("using Address")
        || source.contains("sendValue")
        || source.contains("functionCall")
        || source.contains("functionCallWithValue")
        || source.contains("functionDelegateCall")
}

/// Detect OpenZeppelin Strings library usage
pub fn uses_strings_library(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    source.contains("Strings.")
        || source.contains("using Strings")
        || source.contains(".toString()")
        || source.contains(".toHexString(")
}

/// Detect OpenZeppelin ECDSA library usage
/// ECDSA provides signature verification with malleability protection
pub fn uses_ecdsa_library(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    source.contains("ECDSA")
        || source.contains("ECDSA.recover")
        || source.contains("ECDSA.tryRecover")
        || source.contains("ECDSA.toEthSignedMessageHash")
}

/// Detect OpenZeppelin MerkleProof library usage
pub fn uses_merkle_proof(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    source.contains("MerkleProof")
        || source.contains("MerkleProof.verify")
        || source.contains("MerkleProof.verifyCalldata")
        || source.contains("MerkleProof.processProof")
}

/// Detect OpenZeppelin EIP712 domain separator usage
pub fn uses_eip712(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    source.contains("EIP712")
        || source.contains("_DOMAIN_SEPARATOR")
        || source.contains("DOMAIN_SEPARATOR")
        || source.contains("_hashTypedDataV4")
        || source.contains("_domainSeparatorV4")
}

// ============================================================================
// Solmate Library Detection
// ============================================================================

/// Detect Solmate library usage
pub fn uses_solmate(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    source.contains("solmate")
        || source.contains("transmissions11/solmate")
        || source.contains("rari-capital/solmate")
}

/// Detect Solmate SafeTransferLib usage
pub fn uses_solmate_safe_transfer(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    (uses_solmate(ctx) || source.contains("SafeTransferLib"))
        && (source.contains("safeTransfer")
            || source.contains("safeTransferFrom")
            || source.contains("safeTransferETH"))
}

/// Detect Solmate FixedPointMathLib usage
pub fn uses_solmate_fixed_point_math(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    source.contains("FixedPointMathLib")
        || source.contains("mulWadDown")
        || source.contains("mulWadUp")
        || source.contains("divWadDown")
        || source.contains("divWadUp")
        || source.contains("mulDivDown")
        || source.contains("mulDivUp")
}

// ============================================================================
// PRBMath Library Detection
// ============================================================================

/// Detect PRBMath library usage
pub fn uses_prb_math(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    source.contains("PRBMath")
        || source.contains("PRBMathSD59x18")
        || source.contains("PRBMathUD60x18")
        || source.contains("prb-math")
}

// ============================================================================
// DSMath Library Detection (Dappsys)
// ============================================================================

/// Detect DSMath library usage
pub fn uses_ds_math(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    source.contains("DSMath")
        || source.contains("DSAuth")
        || source.contains("wmul")
        || source.contains("wdiv")
        || source.contains("rpow")
}

// ============================================================================
// Solidity Built-in Protection Detection
// ============================================================================

/// Detect Solidity version >= 0.8.0 (has built-in overflow protection)
pub fn uses_solidity_08_or_later(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Check pragma statements
    source.contains("pragma solidity ^0.8")
        || source.contains("pragma solidity >=0.8")
        || source.contains("pragma solidity 0.8")
        || source.contains("pragma solidity ^0.9")
        || source.contains("pragma solidity >=0.9")
        || source.contains("pragma solidity 0.9")
        || source.contains("pragma solidity ^1.")
        || source.contains("pragma solidity >=1.")
        || source.contains("pragma solidity 1.")
}

/// Detect Solidity version < 0.8.0 (needs SafeMath)
pub fn uses_pre_solidity_08(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    source.contains("pragma solidity ^0.4")
        || source.contains("pragma solidity ^0.5")
        || source.contains("pragma solidity ^0.6")
        || source.contains("pragma solidity ^0.7")
        || source.contains("pragma solidity 0.4")
        || source.contains("pragma solidity 0.5")
        || source.contains("pragma solidity 0.6")
        || source.contains("pragma solidity 0.7")
        || source.contains("pragma solidity >=0.4")
        || source.contains("pragma solidity >=0.5")
        || source.contains("pragma solidity >=0.6")
        || source.contains("pragma solidity >=0.7")
}

// ============================================================================
// Known Safe Protocol Detection
// ============================================================================

/// Detect Aave protocol contracts
pub fn is_aave_protocol(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let lower = source.to_lowercase();

    lower.contains("@aave")
        || lower.contains("aave-protocol")
        || lower.contains("@author aave")
        || source.contains("ILendingPool")
        || source.contains("IAToken")
        || source.contains("IVariableDebtToken")
        || source.contains("IStableDebtToken")
        || source.contains("ADDRESSES_PROVIDER")
}

/// Detect Compound protocol contracts
pub fn is_compound_protocol(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let lower = source.to_lowercase();

    lower.contains("@compound")
        || lower.contains("compound-protocol")
        || lower.contains("@author compound")
        || source.contains("CToken")
        || source.contains("Comptroller")
        || source.contains("CErc20")
        || source.contains("CEther")
}

/// Detect Uniswap protocol contracts
pub fn is_uniswap_protocol(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let lower = source.to_lowercase();

    lower.contains("@uniswap")
        || lower.contains("uniswap-v2")
        || lower.contains("uniswap-v3")
        || lower.contains("uniswap-v4")
        || source.contains("IUniswapV2")
        || source.contains("IUniswapV3")
        || source.contains("ISwapRouter")
        || source.contains("IPoolManager")
}

/// Detect Chainlink contracts
pub fn is_chainlink_protocol(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let lower = source.to_lowercase();

    lower.contains("@chainlink")
        || lower.contains("chainlink-contracts")
        || source.contains("AggregatorV3Interface")
        || source.contains("VRFConsumerBase")
        || source.contains("ChainlinkClient")
        || source.contains("COORDINATOR")
}

/// Detect Safe (Gnosis Safe) wallet contracts
pub fn is_safe_wallet(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let lower = source.to_lowercase();
    let file_path_lower = ctx.file_path.to_lowercase();

    file_path_lower.contains("safe-smart-account")
        || file_path_lower.contains("safe-contracts")
        || file_path_lower.contains("/safe/")
        || lower.contains("gnosis safe")
        || lower.contains("@author stefan george")
        || lower.contains("@author richard meissner")
        || source.contains("GnosisSafe")
        || source.contains("execFromModule")
        || source.contains("OwnerManager")
        || source.contains("GuardManager")
        || source.contains("ModuleManager")
}

/// Check if contract is from a known audited protocol
pub fn is_known_audited_protocol(ctx: &AnalysisContext) -> bool {
    is_aave_protocol(ctx)
        || is_compound_protocol(ctx)
        || is_uniswap_protocol(ctx)
        || is_chainlink_protocol(ctx)
        || is_safe_wallet(ctx)
        || uses_openzeppelin(ctx)
}

// ============================================================================
// Contract Type Detection
// ============================================================================

/// Detect if contract is a library
pub fn is_library_contract(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let contract_name = &ctx.contract.name.name;

    source.contains(&format!("library {}", contract_name))
}

/// Detect if contract is an interface
pub fn is_interface_contract(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let contract_name = &ctx.contract.name.name;

    // Interface naming convention (IPool, IAToken, etc.)
    if contract_name.starts_with('I')
        && contract_name.chars().nth(1).map_or(false, |c| c.is_uppercase())
    {
        return true;
    }

    // Explicit interface keyword
    source.contains(&format!("interface {}", contract_name))
}

/// Detect if contract is abstract
pub fn is_abstract_contract(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;
    let contract_name = &ctx.contract.name.name;

    source.contains(&format!("abstract contract {}", contract_name))
}

// Note: is_test_contract is defined in contract_classification.rs

/// Detect if this is a deployment/script contract
pub fn is_deployment_script(ctx: &AnalysisContext) -> bool {
    let file_path_lower = ctx.file_path.to_lowercase();
    let contract_name_lower = ctx.contract.name.name.to_lowercase();

    file_path_lower.contains("/script/")
        || file_path_lower.contains("/scripts/")
        || file_path_lower.contains("/deploy/")
        || file_path_lower.contains("_deploy")
        || file_path_lower.ends_with(".s.sol")
        || contract_name_lower.contains("deploy")
        || contract_name_lower.contains("script")
}

// ============================================================================
// Inline Protection Detection
// ============================================================================

/// Detect inline require/revert checks for msg.sender
pub fn has_inline_sender_check(function_source: &str) -> bool {
    let lower = function_source.to_lowercase();

    lower.contains("require(msg.sender")
        || lower.contains("if (msg.sender")
        || lower.contains("if(msg.sender")
        || lower.contains("msg.sender ==")
        || lower.contains("msg.sender !=")
        || lower.contains("== msg.sender")
        || lower.contains("!= msg.sender")
}

/// Detect inline require/revert checks for zero address
pub fn has_inline_zero_check(function_source: &str) -> bool {
    function_source.contains("address(0)")
        && (function_source.contains("require(")
            || function_source.contains("if (")
            || function_source.contains("if(")
            || function_source.contains("revert"))
}

/// Detect inline require/revert checks for amount/balance
pub fn has_inline_balance_check(function_source: &str) -> bool {
    let lower = function_source.to_lowercase();

    (lower.contains("balance") || lower.contains("amount"))
        && (lower.contains("require(") || lower.contains("if (") || lower.contains("if("))
        && (lower.contains(" >= ") || lower.contains(" > ") || lower.contains(" <= ") || lower.contains(" < "))
}

/// Detect try/catch usage for external calls
pub fn has_try_catch(function_source: &str) -> bool {
    function_source.contains("try ") && function_source.contains("catch")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::test_utils::create_test_context;

    #[test]
    fn test_openzeppelin_detection() {
        let source = r#"
            import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
            contract Token is ERC20 {}
        "#;
        let ctx = create_test_context(source);
        assert!(uses_openzeppelin(&ctx));
    }

    #[test]
    fn test_safe_erc20_detection() {
        let source = r#"
            import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
            contract Vault {
                using SafeERC20 for IERC20;
                function deposit() {
                    token.safeTransferFrom(msg.sender, address(this), amount);
                }
            }
        "#;
        let ctx = create_test_context(source);
        assert!(uses_safe_erc20(&ctx));
    }

    #[test]
    fn test_solidity_08_detection() {
        let source_08 = "pragma solidity ^0.8.0; contract Test {}";
        let ctx_08 = create_test_context(source_08);
        assert!(uses_solidity_08_or_later(&ctx_08));
        assert!(!uses_pre_solidity_08(&ctx_08));

        let source_07 = "pragma solidity ^0.7.0; contract Test {}";
        let ctx_07 = create_test_context(source_07);
        assert!(!uses_solidity_08_or_later(&ctx_07));
        assert!(uses_pre_solidity_08(&ctx_07));
    }

    #[test]
    fn test_known_protocol_detection() {
        let aave_source = r#"
            // @author Aave
            import "@aave/protocol/LendingPool.sol";
            contract AaveIntegration {}
        "#;
        let ctx = create_test_context(aave_source);
        assert!(is_aave_protocol(&ctx));
        assert!(is_known_audited_protocol(&ctx));
    }

    #[test]
    fn test_inline_sender_check() {
        let with_check = r#"
            function withdraw() {
                require(msg.sender == owner, "Not owner");
                // ...
            }
        "#;
        assert!(has_inline_sender_check(with_check));

        let without_check = r#"
            function withdraw() {
                balance = 0;
            }
        "#;
        assert!(!has_inline_sender_check(without_check));
    }

    #[test]
    fn test_try_catch_detection() {
        let with_try_catch = r#"
            try target.call() returns (uint256 result) {
                // success
            } catch {
                // failure
            }
        "#;
        assert!(has_try_catch(with_try_catch));

        let without_try_catch = "target.call();";
        assert!(!has_try_catch(without_try_catch));
    }
}
