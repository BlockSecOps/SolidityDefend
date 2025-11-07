use crate::types::AnalysisContext;

/// Detect LayerZero endpoint pattern
///
/// Proper LayerZero cross-chain messaging patterns.
///
/// Patterns detected:
/// - ILayerZeroEndpoint interface
/// - lzReceive function with proper validation
/// - Trusted remote validation
/// - Nonce tracking for replay protection
pub fn has_layerzero_endpoint_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: ILayerZeroEndpoint interface
    if source.contains("ILayerZeroEndpoint") {
        return true;
    }

    // Pattern 2: lzReceive function
    if source.contains("function lzReceive(") {
        return true;
    }

    // Pattern 3: Trusted remote validation
    if source.contains("trustedRemote") || source.contains("isTrustedRemote") {
        return true;
    }

    // Pattern 4: LayerZero send function
    if source.contains("lzEndpoint.send(") {
        return true;
    }

    // Pattern 5: Path validation (srcChainId + srcAddress)
    if source.contains("_srcChainId") && source.contains("_srcAddress") {
        return true;
    }

    false
}

/// Detect Wormhole relayer pattern
///
/// Wormhole cross-chain messaging patterns.
///
/// Patterns detected:
/// - IWormholeRelayer interface
/// - receiveWormholeMessages function
/// - VAA (Verifiable Action Approval) validation
/// - Delivery hash verification
pub fn has_wormhole_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: Wormhole interfaces
    if source.contains("IWormholeRelayer") || source.contains("IWormhole") {
        return true;
    }

    // Pattern 2: receiveWormholeMessages function
    if source.contains("receiveWormholeMessages") {
        return true;
    }

    // Pattern 3: VAA parsing/validation
    if source.contains("parseAndVerifyVM") || source.contains("VAA") {
        return true;
    }

    // Pattern 4: Delivery hash
    if source.contains("deliveryHash") {
        return true;
    }

    // Pattern 5: Wormhole send
    if source.contains("wormholeRelayer.send") {
        return true;
    }

    false
}

/// Detect Chainlink CCIP pattern
///
/// Chainlink Cross-Chain Interoperability Protocol patterns.
///
/// Patterns detected:
/// - IRouterClient interface
/// - ccipReceive function
/// - Message validation with source chain
/// - Fee payment handling
pub fn has_chainlink_ccip_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: CCIP interfaces
    if source.contains("IRouterClient") || source.contains("IAny2EVMMessageReceiver") {
        return true;
    }

    // Pattern 2: ccipReceive function
    if source.contains("function ccipReceive(") || source.contains("_ccipReceive(") {
        return true;
    }

    // Pattern 3: Client.Any2EVMMessage type
    if source.contains("Any2EVMMessage") {
        return true;
    }

    // Pattern 4: Source chain validation
    if source.contains("sourceChainSelector") {
        return true;
    }

    // Pattern 5: CCIP send with fee
    if source.contains("ccipSend") || source.contains("getFee") {
        return true;
    }

    false
}

/// Detect chain ID validation pattern
///
/// Proper chain ID validation for cross-chain operations.
///
/// Patterns detected:
/// - block.chainid validation
/// - Supported chain mapping
/// - Chain ID in message signature
/// - Domain separator with chain ID
pub fn has_chain_id_validation(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: block.chainid check
    if source.contains("block.chainid") && (source.contains("require(") || source.contains("if ("))
    {
        return true;
    }

    // Pattern 2: Supported chains mapping
    if source.contains("supportedChains") || source.contains("allowedChains") {
        return true;
    }

    // Pattern 3: Chain ID in domain separator (EIP-712)
    if source.contains("DOMAIN_SEPARATOR") && source.contains("chainId") {
        return true;
    }

    // Pattern 4: Chain validation function
    if source.contains("isChainSupported") || source.contains("validateChain") {
        return true;
    }

    false
}

/// Detect nonce-based replay protection
///
/// Nonce tracking to prevent message replay attacks.
///
/// Patterns detected:
/// - Nonce mapping per user/chain
/// - Nonce increment on message processing
/// - Expected nonce validation
/// - Sequence number tracking
pub fn has_nonce_replay_protection(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: Nonce mapping
    if source.contains("mapping") && source.contains("nonce") {
        return true;
    }

    // Pattern 2: Nonce increment
    if source.contains("nonce++") || source.contains("nonce + 1") || source.contains("nonce += 1") {
        return true;
    }

    // Pattern 3: Expected nonce check
    if source.contains("require(nonce ==") || source.contains("if (nonce ==") {
        return true;
    }

    // Pattern 4: Sequence number
    if (source.contains("sequenceNumber") || source.contains("sequence"))
        && (source.contains("++") || source.contains("+ 1"))
    {
        return true;
    }

    // Pattern 5: Message hash tracking (prevents duplicate processing)
    if source.contains("processedMessages") && source.contains("mapping") {
        return true;
    }

    false
}

/// Detect message signature verification
///
/// Cryptographic verification of cross-chain messages.
///
/// Patterns detected:
/// - ECDSA signature recovery
/// - Multi-signature verification
/// - Merkle proof validation
/// - Authorized signer validation
pub fn has_message_verification(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: ECDSA recovery
    if source.contains("ecrecover") || source.contains("ECDSA.recover") {
        return true;
    }

    // Pattern 2: Merkle proof validation
    if source.contains("MerkleProof.verify") || source.contains("verifyProof") {
        return true;
    }

    // Pattern 3: Signature verification
    if source.contains("verifySignature") || source.contains("_verifySignature") {
        return true;
    }

    // Pattern 4: Authorized signer check
    if source.contains("authorizedSigners") || source.contains("isSigner") {
        return true;
    }

    // Pattern 5: Multi-sig threshold
    if source.contains("threshold") && source.contains("signatures") {
        return true;
    }

    false
}

/// Detect safe token bridge pattern
///
/// Secure token bridging with proper locking/burning.
///
/// Patterns detected:
/// - Lock on source, mint on destination
/// - Burn on source, unlock on destination
/// - Token vault with withdrawal validation
/// - Bridge balance tracking
pub fn has_safe_bridge_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: Lock and mint pattern
    if source.contains("lock(") && source.contains("mint(") {
        return true;
    }

    // Pattern 2: Burn and unlock pattern
    if source.contains("burn(") && source.contains("unlock(") {
        return true;
    }

    // Pattern 3: Token vault
    if source.contains("vault")
        && source.contains("withdraw")
        && (source.contains("require(") || source.contains("if ("))
    {
        return true;
    }

    // Pattern 4: Locked balance tracking
    if source.contains("lockedBalance") || source.contains("totalLocked") {
        return true;
    }

    // Pattern 5: Bridge reserve validation
    if source.contains("bridgeReserve") || source.contains("reserves") {
        return true;
    }

    false
}

/// Detect cross-chain message ordering
///
/// Proper message ordering and sequencing.
///
/// Patterns detected:
/// - Sequence number enforcement
/// - Ordered message queue
/// - Gap detection and handling
/// - Out-of-order rejection
pub fn has_message_ordering(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: Expected sequence check
    if source.contains("expectedSequence") || source.contains("nextSequence") {
        return true;
    }

    // Pattern 2: Sequence validation
    if source.contains("require(sequence ==") || source.contains("if (sequence ==") {
        return true;
    }

    // Pattern 3: Message queue
    if source.contains("messageQueue") || source.contains("pendingMessages") {
        return true;
    }

    // Pattern 4: Gap handling
    if source.contains("processMessage") && source.contains("sequence") {
        return true;
    }

    false
}

/// Detect source chain validation
///
/// Validation of message source chain for security.
///
/// Patterns detected:
/// - Allowed source chains whitelist
/// - Source chain ID validation
/// - Trusted source check
/// - Chain-specific configuration
pub fn has_source_validation(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: Allowed sources
    if source.contains("allowedSources") || source.contains("trustedSources") {
        return true;
    }

    // Pattern 2: Source chain validation
    if source.contains("sourceChain") && (source.contains("require(") || source.contains("if (")) {
        return true;
    }

    // Pattern 3: Trusted remote (LayerZero style)
    if source.contains("trustedRemote") {
        return true;
    }

    // Pattern 4: isValidSource function
    if source.contains("isValidSource") || source.contains("validateSource") {
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
    fn test_layerzero_pattern() {
        let source = r#"
            import "@layerzerolabs/contracts/interfaces/ILayerZeroEndpoint.sol";

            ILayerZeroEndpoint public lzEndpoint;
            mapping(uint16 => bytes) public trustedRemote;

            function lzReceive(
                uint16 _srcChainId,
                bytes memory _srcAddress,
                uint64 _nonce,
                bytes memory _payload
            ) public {
                require(msg.sender == address(lzEndpoint));
                require(_srcAddress.length == trustedRemote[_srcChainId].length);
            }
        "#;
        let ctx = create_context(source);
        assert!(has_layerzero_endpoint_pattern(&ctx));
        assert!(has_nonce_replay_protection(&ctx));
    }

    #[test]
    fn test_chain_id_validation() {
        let source = r#"
            mapping(uint256 => bool) public supportedChains;

            function processMessage(uint256 chainId) public {
                require(supportedChains[chainId], "Chain not supported");
                require(block.chainid == chainId, "Wrong chain");
            }
        "#;
        let ctx = create_context(source);
        assert!(has_chain_id_validation(&ctx));
    }

    #[test]
    fn test_message_verification() {
        let source = r#"
            mapping(address => bool) public authorizedSigners;

            function verifyMessage(bytes32 hash, bytes memory signature) public view returns (bool) {
                address signer = ECDSA.recover(hash, signature);
                return authorizedSigners[signer];
            }
        "#;
        let ctx = create_context(source);
        assert!(has_message_verification(&ctx));
    }

    #[test]
    fn test_safe_bridge_pattern() {
        let source = r#"
            mapping(address => uint256) public lockedBalance;

            function lock(address token, uint256 amount) public {
                lockedBalance[token] += amount;
                IERC20(token).transferFrom(msg.sender, address(this), amount);
            }

            function unlock(address token, uint256 amount, bytes memory proof) public {
                require(verifyProof(proof), "Invalid proof");
                lockedBalance[token] -= amount;
                IERC20(token).transfer(msg.sender, amount);
            }
        "#;
        let ctx = create_context(source);
        assert!(has_safe_bridge_pattern(&ctx));
    }
}
