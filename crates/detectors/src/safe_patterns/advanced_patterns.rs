use crate::types::AnalysisContext;

/// Detect safe ZK proof validation patterns
///
/// Patterns for secure zero-knowledge proof verification.
///
/// Patterns detected:
/// - Proof uniqueness tracking
/// - Public input validation
/// - Verifier key validation
/// - Proof binding to transaction/user
pub fn has_safe_zk_proof_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: Proof uniqueness (prevents replay)
    if source.contains("proofHash") && source.contains("mapping") {
        return true;
    }

    // Pattern 2: verifyProof function with validation
    if source.contains("verifyProof") && source.contains("require(") {
        return true;
    }

    // Pattern 3: Public input bounds checking
    if source.contains("publicInputs") && source.contains("< FIELD_MODULUS") {
        return true;
    }

    // Pattern 4: Commitment binding
    if source.contains("commitment") && source.contains("hash") {
        return true;
    }

    // Pattern 5: zkSNARK/zkSTARK libraries
    if source.contains("Verifier") || source.contains("Pairing") {
        return true;
    }

    false
}

/// Detect safe recursive proof validation
///
/// Patterns for secure recursive ZK proof composition.
///
/// Patterns detected:
/// - Depth limit enforcement
/// - Batch verification
/// - Aggregation validation
/// - Inner proof verification
pub fn has_safe_recursive_proof_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: Recursion depth limit
    if (source.contains("recursionDepth") || source.contains("MAX_DEPTH"))
        && (source.contains("require(") || source.contains("if ("))
    {
        return true;
    }

    // Pattern 2: Batch verification
    if source.contains("batchVerify") || source.contains("verifyBatch") {
        return true;
    }

    // Pattern 3: Aggregated proof
    if source.contains("aggregatedProof") || source.contains("proofAggregation") {
        return true;
    }

    // Pattern 4: Inner proof validation
    if source.contains("innerProof") && source.contains("verify") {
        return true;
    }

    false
}

/// Detect safe data availability patterns
///
/// Patterns for Celestia/Avail data availability validation.
///
/// Patterns detected:
/// - DA commitment verification
/// - Merkle proof validation
/// - Namespace proof checking
/// - Data root validation
pub fn has_safe_da_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: Data availability commitment
    if source.contains("dataCommitment") || source.contains("daCommitment") {
        return true;
    }

    // Pattern 2: Merkle proof for DA
    if source.contains("merkleProof") && source.contains("dataRoot") {
        return true;
    }

    // Pattern 3: Namespace validation (Celestia)
    if source.contains("namespace") && source.contains("verify") {
        return true;
    }

    // Pattern 4: Data root verification
    if source.contains("dataRoot") && source.contains("require(") {
        return true;
    }

    // Pattern 5: Blobstream or similar
    if source.contains("blobstream") || source.contains("IDataAvailability") {
        return true;
    }

    false
}

/// Detect safe cross-rollup atomicity pattern
///
/// Patterns for atomic operations across multiple rollups.
///
/// Patterns detected:
/// - Two-phase commit
/// - Rollback mechanism
/// - State sync validation
/// - Cross-rollup lock
pub fn has_safe_cross_rollup_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: Two-phase commit
    if source.contains("prepare")
        && source.contains("commit")
        && (source.contains("rollback") || source.contains("abort"))
    {
        return true;
    }

    // Pattern 2: Cross-rollup lock
    if source.contains("crossRollupLock") || source.contains("atomicLock") {
        return true;
    }

    // Pattern 3: State synchronization
    if source.contains("syncState") && source.contains("rollup") {
        return true;
    }

    // Pattern 4: Atomic batch across rollups
    if source.contains("atomicBatch") || source.contains("crossRollupBatch") {
        return true;
    }

    false
}

/// Detect safe fraud proof patterns
///
/// Patterns for Optimistic rollup fraud proof validation.
///
/// Patterns detected:
/// - Challenge period enforcement
/// - Dispute resolution timing
/// - Bond requirement
/// - State transition validation
pub fn has_safe_fraud_proof_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: Challenge period
    if source.contains("challengePeriod") || source.contains("CHALLENGE_PERIOD") {
        return true;
    }

    // Pattern 2: Challenge with bond
    if source.contains("challenge") && source.contains("bond") {
        return true;
    }

    // Pattern 3: Dispute resolution
    if source.contains("resolveDispute") || source.contains("finalizeChallenge") {
        return true;
    }

    // Pattern 4: State root validation
    if source.contains("stateRoot") && source.contains("verify") {
        return true;
    }

    // Pattern 5: Withdrawal delay for fraud proofs
    if source.contains("withdrawalDelay") && source.contains("proof") {
        return true;
    }

    false
}

/// Detect safe AI oracle patterns
///
/// Patterns for secure AI/LLM oracle integration.
///
/// Patterns detected:
/// - Multi-oracle consensus
/// - Input sanitization
/// - Output validation
/// - Rate limiting
pub fn has_safe_ai_oracle_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: Multiple oracles
    if source.contains("oracles") && source.contains("consensus") {
        return true;
    }

    // Pattern 2: Oracle threshold/quorum
    if source.contains("threshold") && source.contains("oracle") {
        return true;
    }

    // Pattern 3: Input validation for AI
    if (source.contains("validateInput") || source.contains("sanitize"))
        && (source.contains("oracle") || source.contains("ai") || source.contains("llm"))
    {
        return true;
    }

    // Pattern 4: Output bounds checking
    if source.contains("oracleOutput") && source.contains("bounds") {
        return true;
    }

    // Pattern 5: Staleness check for AI responses
    if source.contains("lastUpdate") && source.contains("oracle") {
        return true;
    }

    false
}

/// Detect safe AI agent patterns
///
/// Patterns for secure autonomous AI agent contracts.
///
/// Patterns detected:
/// - Action whitelist
/// - Spending limits
/// - Emergency shutdown
/// - Multi-signature for critical actions
pub fn has_safe_ai_agent_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: Action whitelist
    if source.contains("allowedActions") || source.contains("approvedFunctions") {
        return true;
    }

    // Pattern 2: Spending/transaction limits
    if source.contains("limit") && (source.contains("agent") || source.contains("autonomous")) {
        return true;
    }

    // Pattern 3: Emergency pause for agents
    if source.contains("emergencyStop") || source.contains("pauseAgent") {
        return true;
    }

    // Pattern 4: Multi-sig for high-value actions
    if source.contains("threshold") && source.contains("agent") {
        return true;
    }

    // Pattern 5: Rate limiting
    if source.contains("rateLimit") || source.contains("cooldown") {
        return true;
    }

    false
}

/// Detect safe prompt injection prevention
///
/// Patterns to prevent prompt injection in AI-integrated contracts.
///
/// Patterns detected:
/// - Input escaping/encoding
/// - Prompt template validation
/// - Output format enforcement
/// - Delimiter validation
pub fn has_prompt_injection_prevention(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: Input sanitization
    if (source.contains("sanitize") || source.contains("escape"))
        && (source.contains("input") || source.contains("prompt"))
    {
        return true;
    }

    // Pattern 2: Template validation
    if source.contains("validateTemplate") || source.contains("checkTemplate") {
        return true;
    }

    // Pattern 3: Input length limits
    if (source.contains("MAX_INPUT_LENGTH") || source.contains("inputLength"))
        && (source.contains("require(") || source.contains("if ("))
    {
        return true;
    }

    // Pattern 4: Delimiter checking
    if source.contains("delimiter") && source.contains("validate") {
        return true;
    }

    false
}

/// Detect safe sovereign rollup patterns
///
/// Patterns for secure sovereign rollup validation.
///
/// Patterns detected:
/// - State transition validation
/// - Block validation
/// - Fork choice rules
/// - Consensus participation
pub fn has_safe_sovereign_rollup_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: State transition function validation
    if source.contains("validateStateTransition") || source.contains("verifyStateTransition") {
        return true;
    }

    // Pattern 2: Block validation
    if source.contains("validateBlock") && source.contains("stateRoot") {
        return true;
    }

    // Pattern 3: Fork choice
    if source.contains("forkChoice") || source.contains("canonicalChain") {
        return true;
    }

    // Pattern 4: Consensus rules
    if source.contains("consensus") && source.contains("validate") {
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
    fn test_zk_proof_pattern() {
        let source = r#"
            mapping(bytes32 => bool) public usedProofs;

            function verifyProof(
                uint256[] memory publicInputs,
                uint256[] memory proof
            ) public returns (bool) {
                bytes32 proofHash = keccak256(abi.encode(proof));
                require(!usedProofs[proofHash], "Proof already used");

                // Validate public inputs are in field
                for (uint i = 0; i < publicInputs.length; i++) {
                    require(publicInputs[i] < FIELD_MODULUS, "Invalid input");
                }

                usedProofs[proofHash] = true;
                return Verifier.verify(proof, publicInputs);
            }
        "#;
        let ctx = create_context(source);
        assert!(has_safe_zk_proof_pattern(&ctx));
    }

    #[test]
    fn test_da_pattern() {
        let source = r#"
            // Celestia data availability validation
            bytes32 public dataRoot;

            function verifyDataAvailability(
                bytes32 namespace,
                bytes memory data,
                bytes32[] memory merkleProof
            ) public view returns (bool) {
                bytes32 leaf = keccak256(abi.encode(namespace, data));
                return MerkleProof.verify(merkleProof, dataRoot, leaf);
            }
        "#;
        let ctx = create_context(source);
        assert!(has_safe_da_pattern(&ctx));
    }

    #[test]
    fn test_ai_oracle_pattern() {
        let source = r#"
            address[] public oracles;
            uint256 public threshold = 2;

            function getConsensus() public view returns (uint256) {
                uint256[] memory responses = new uint256[](oracles.length);
                for (uint i = 0; i < oracles.length; i++) {
                    responses[i] = IOracle(oracles[i]).getResponse();
                }
                return calculateConsensus(responses, threshold);
            }

            function validateInput(string memory input) internal pure {
                require(bytes(input).length < MAX_INPUT_LENGTH, "Input too long");
                // Sanitize input
            }
        "#;
        let ctx = create_context(source);
        assert!(has_safe_ai_oracle_pattern(&ctx));
    }

    #[test]
    fn test_fraud_proof_pattern() {
        let source = r#"
            uint256 public constant CHALLENGE_PERIOD = 7 days;
            mapping(bytes32 => uint256) public withdrawalTimestamp;

            function challenge(bytes32 stateRoot, bytes memory proof) public payable {
                require(msg.value >= CHALLENGE_BOND, "Insufficient bond");
                // Challenge logic
            }

            function finalizeWithdrawal(bytes32 withdrawalId) public {
                require(
                    block.timestamp >= withdrawalTimestamp[withdrawalId] + CHALLENGE_PERIOD,
                    "Challenge period not over"
                );
                // Finalize
            }
        "#;
        let ctx = create_context(source);
        assert!(has_safe_fraud_proof_pattern(&ctx));
    }
}
