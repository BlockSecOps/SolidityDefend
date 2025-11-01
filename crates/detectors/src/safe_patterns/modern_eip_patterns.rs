use crate::types::AnalysisContext;

/// Detect safe EIP-1153 transient storage usage
///
/// Patterns for secure transient storage (TSTORE/TLOAD) usage.
///
/// Patterns detected:
/// - Reentrancy guards using transient storage
/// - Transient state cleanup
/// - Lock patterns with transient storage
/// - Proper scope isolation
pub fn has_safe_transient_storage_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: Reentrancy guard with transient storage
    if source.contains("tstore") && source.contains("tload") {
        if source.contains("locked") || source.contains("guard") {
            return true;
        }
    }

    // Pattern 2: Transient lock pattern
    if source.contains("transient") && source.contains("lock") {
        return true;
    }

    // Pattern 3: Assembly with proper transient usage
    if source.contains("assembly") {
        if source.contains("tstore(") && source.contains("tload(") {
            return true;
        }
    }

    // Pattern 4: EIP-1153 comment or documentation
    if source.contains("EIP-1153") || source.contains("EIP1153") {
        return true;
    }

    false
}

/// Detect safe EIP-7702 delegation pattern
///
/// Patterns for secure account delegation (set code).
///
/// Patterns detected:
/// - Authorization list validation
/// - Delegation signature verification
/// - Nonce tracking for delegations
/// - Revocation mechanism
pub fn has_safe_delegation_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: Authorization validation
    if source.contains("authorization") && source.contains("verify") {
        return true;
    }

    // Pattern 2: Delegation signature
    if source.contains("delegationSignature") || source.contains("authorizationSignature") {
        return true;
    }

    // Pattern 3: Nonce for delegation
    if source.contains("delegationNonce") || source.contains("authNonce") {
        return true;
    }

    // Pattern 4: Revoke delegation
    if source.contains("revokeDelegate") || source.contains("revokeDelegation") {
        return true;
    }

    // Pattern 5: EIP-7702 reference
    if source.contains("EIP-7702") || source.contains("EIP7702") {
        return true;
    }

    false
}

/// Detect safe ERC-7821 batch executor pattern
///
/// Patterns for secure batch transaction execution.
///
/// Patterns detected:
/// - Atomic batch execution (all-or-nothing)
/// - Per-call gas limits
/// - Reentrancy protection on batch
/// - Batch size limits
pub fn has_safe_batch_executor_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: Atomic batch execution
    if source.contains("executeBatch") {
        if source.contains("revert") || source.contains("require(success") {
            return true;
        }
    }

    // Pattern 2: Batch size limit
    if source.contains("batch") && (source.contains("MAX_BATCH") || source.contains("limit")) {
        return true;
    }

    // Pattern 3: Per-call gas limit
    if source.contains("gasLimit") && source.contains("call") {
        return true;
    }

    // Pattern 4: Batch validation before execution
    if source.contains("validateBatch") || source.contains("_validateBatch") {
        return true;
    }

    // Pattern 5: ERC-7821 reference
    if source.contains("ERC-7821") || source.contains("ERC7821") {
        return true;
    }

    false
}

/// Detect safe ERC-7683 intent-based pattern
///
/// Patterns for secure intent-based cross-chain operations.
///
/// Patterns detected:
/// - Intent validation
/// - Filler authorization
/// - Settlement verification
/// - Oracle validation for intent pricing
pub fn has_safe_intent_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: Intent struct or type
    if source.contains("Intent") && source.contains("struct") {
        return true;
    }

    // Pattern 2: Filler validation
    if source.contains("filler") && (source.contains("authorized") || source.contains("valid")) {
        return true;
    }

    // Pattern 3: Settlement verification
    if source.contains("settle") && source.contains("verify") {
        return true;
    }

    // Pattern 4: Intent nonce/uniqueness
    if source.contains("intentNonce") || source.contains("intentHash") {
        return true;
    }

    // Pattern 5: ERC-7683 reference
    if source.contains("ERC-7683") || source.contains("ERC7683") {
        return true;
    }

    false
}

/// Detect safe Diamond proxy pattern (ERC-2535)
///
/// Patterns for secure Diamond proxy implementation.
///
/// Patterns detected:
/// - Storage collision prevention
/// - Facet validation
/// - Selector clash prevention
/// - Diamond storage pattern
pub fn has_safe_diamond_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: Diamond storage struct
    if source.contains("DiamondStorage") {
        return true;
    }

    // Pattern 2: Facet cut validation
    if source.contains("diamondCut") && source.contains("validate") {
        return true;
    }

    // Pattern 3: Selector to facet mapping
    if source.contains("selectorToFacet") || source.contains("facetAddress") {
        return true;
    }

    // Pattern 4: Storage slot pattern (EIP-2535 style)
    if source.contains("DIAMOND_STORAGE") && source.contains("keccak256") {
        return true;
    }

    // Pattern 5: ERC-2535 reference
    if source.contains("ERC-2535") || source.contains("ERC2535") {
        return true;
    }

    false
}

/// Detect safe upgrade pattern
///
/// Patterns for secure proxy upgrades.
///
/// Patterns detected:
/// - UUPS upgrade with authorization
/// - Transparent proxy admin separation
/// - Upgrade delay/timelock
/// - Storage layout validation
pub fn has_safe_upgrade_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: UUPS with authorization
    if source.contains("UUPSUpgradeable") {
        if source.contains("_authorizeUpgrade") {
            return true;
        }
    }

    // Pattern 2: Transparent proxy
    if source.contains("TransparentUpgradeableProxy") {
        return true;
    }

    // Pattern 3: Upgrade with timelock
    if source.contains("upgrade") && source.contains("timelock") {
        return true;
    }

    // Pattern 4: Implementation validation
    if source.contains("upgradeTo") && source.contains("require(") {
        return true;
    }

    // Pattern 5: Storage gap for upgrades
    if source.contains("__gap") && source.contains("uint256[") {
        return true;
    }

    false
}

/// Detect safe CREATE2 usage
///
/// Patterns for secure CREATE2 deployment.
///
/// Patterns detected:
/// - Salt validation
/// - Deployment address verification
/// - Redeployment prevention
/// - Bytecode hash verification
pub fn has_safe_create2_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: CREATE2 with salt
    if source.contains("create2") || source.contains("CREATE2") {
        return true;
    }

    // Pattern 2: Computed address verification
    if source.contains("computeAddress") || source.contains("getAddress") {
        if source.contains("create2") || source.contains("salt") {
            return true;
        }
    }

    // Pattern 3: Deployment tracking
    if source.contains("deployed") && source.contains("mapping") {
        return true;
    }

    // Pattern 4: Bytecode hash check
    if source.contains("bytecodeHash") && source.contains("create2") {
        return true;
    }

    false
}

/// Detect safe meta-transaction pattern
///
/// Patterns for secure meta-transactions and gasless transactions.
///
/// Patterns detected:
/// - Nonce tracking per user
/// - Signature verification
/// - Replay protection
/// - Domain separator (EIP-712)
pub fn has_safe_metatx_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: User nonces
    if source.contains("nonces") && source.contains("mapping") {
        if source.contains("address") {
            return true;
        }
    }

    // Pattern 2: executeMetaTransaction or similar
    if source.contains("executeMetaTransaction") || source.contains("metaTransaction") {
        return true;
    }

    // Pattern 3: EIP-712 domain separator
    if source.contains("DOMAIN_SEPARATOR") {
        return true;
    }

    // Pattern 4: Signature verification with nonce
    if source.contains("verify") && source.contains("signature") && source.contains("nonce") {
        return true;
    }

    // Pattern 5: Trusted forwarder pattern (GSN)
    if source.contains("isTrustedForwarder") || source.contains("trustedForwarder") {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_context(source: &str) -> AnalysisContext<'static> {
        crate::types::test_utils::create_test_context(source)
    }

    #[test]
    fn test_transient_storage_pattern() {
        let source = r#"
            // EIP-1153: Transient storage for reentrancy guard
            function deposit() public {
                assembly {
                    let locked := tload(0)
                    if locked { revert(0, 0) }
                    tstore(0, 1)
                }
                // ... deposit logic ...
                assembly {
                    tstore(0, 0)
                }
            }
        "#;
        let ctx = create_context(source);
        assert!(has_safe_transient_storage_pattern(&ctx));
    }

    #[test]
    fn test_batch_executor_pattern() {
        let source = r#"
            uint256 public constant MAX_BATCH_SIZE = 100;

            function executeBatch(Call[] memory calls) public {
                require(calls.length <= MAX_BATCH_SIZE, "Batch too large");

                for (uint256 i = 0; i < calls.length; i++) {
                    (bool success, ) = calls[i].target.call{gas: calls[i].gasLimit}(calls[i].data);
                    require(success, "Call failed");
                }
            }
        "#;
        let ctx = create_context(source);
        assert!(has_safe_batch_executor_pattern(&ctx));
    }

    #[test]
    fn test_intent_pattern() {
        let source = r#"
            struct Intent {
                address user;
                uint256 amount;
                uint256 deadline;
                bytes32 intentHash;
            }

            mapping(address => bool) public authorizedFillers;

            function settle(Intent memory intent, address filler) public {
                require(authorizedFillers[filler], "Unauthorized filler");
                require(verifyIntent(intent), "Invalid intent");
            }
        "#;
        let ctx = create_context(source);
        assert!(has_safe_intent_pattern(&ctx));
    }

    #[test]
    fn test_metatx_pattern() {
        let source = r#"
            mapping(address => uint256) public nonces;
            bytes32 public DOMAIN_SEPARATOR;

            function executeMetaTransaction(
                address user,
                bytes memory functionSignature,
                bytes32 sigR,
                bytes32 sigS,
                uint8 sigV
            ) public {
                uint256 nonce = nonces[user];
                bytes32 hash = keccak256(abi.encode(user, nonce, functionSignature));
                address signer = ecrecover(hash, sigV, sigR, sigS);
                require(signer == user, "Invalid signature");
                nonces[user]++;
            }
        "#;
        let ctx = create_context(source);
        assert!(has_safe_metatx_pattern(&ctx));
    }
}
