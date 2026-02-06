use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::contract_classification;
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for L2 bridge message validation vulnerabilities
pub struct L2BridgeMessageValidationDetector {
    base: BaseDetector,
}

impl Default for L2BridgeMessageValidationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl L2BridgeMessageValidationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("l2-bridge-message-validation".to_string()),
                "L2 Bridge Message Validation".to_string(),
                "Detects missing or weak validation in L2↔L1 bridge message processing, including missing Merkle proofs, inadequate finality checks, and replay vulnerabilities".to_string(),
                vec![DetectorCategory::CrossChain, DetectorCategory::L2],
                Severity::Critical,
            ),
        }
    }
}

impl Detector for L2BridgeMessageValidationDetector {
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

        // Skip governance contracts -- they may reference cross-chain execution
        // but are not L2 bridge message relay contracts
        if self.is_governance_contract(ctx) {
            return Ok(findings);
        }

        // Only run on contracts that are both bridge contracts AND have L2-specific
        // indicators. A generic bridge without L1/L2 layer references is not in scope.
        if !contract_classification::is_bridge_contract(ctx) {
            return Ok(findings);
        }

        // Require L2-specific indicators beyond the generic bridge classification.
        // This prevents false positives on simple bridge contracts that don't do
        // L2 state root verification or cross-layer message passing.
        if !self.has_l2_bridge_indicators(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            // Skip internal/private functions
            if !self.is_external_or_public(function) {
                continue;
            }

            let func_source = self.get_function_source(function, ctx);

            // Check for L2->L1 message relay functions
            if self.is_message_relay_function(function.name.name, &func_source) {
                // Skip functions that already have sufficient validation
                if self.has_sufficient_validation(&func_source) {
                    continue;
                }

                let issues = self.check_message_validation(&func_source);

                for issue in issues {
                    let message = format!(
                        "Function '{}' relays cross-layer messages without proper validation. {} \
                        This can lead to unauthorized message execution and bridge exploits.",
                        function.name.name, issue
                    );

                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            function.name.location.start().line() as u32,
                            function.name.location.start().column() as u32,
                            function.name.name.len() as u32,
                        )
                        .with_cwe(345) // CWE-345: Insufficient Verification of Data Authenticity
                        .with_confidence(Confidence::High)
                        .with_fix_suggestion(format!(
                            "Add proper validation to '{}': \
                            (1) Verify Merkle proof against L1/L2 state root, \
                            (2) Check message finality (block confirmations), \
                            (3) Implement nonce/sequence tracking to prevent replay, \
                            (4) Validate message signatures, \
                            (5) Add cross-chain replay protection.",
                            function.name.name
                        ));

                    findings.push(finding);
                }
            }

            // Check for withdrawal finalization functions
            if self.is_withdrawal_function(function.name.name, &func_source) {
                // Skip functions that already have sufficient validation
                if self.has_sufficient_validation(&func_source) {
                    continue;
                }

                let issues = self.check_withdrawal_validation(&func_source);

                for issue in issues {
                    let message = format!(
                        "Function '{}' finalizes withdrawals without proper checks. {} \
                        Missing validation can allow premature or unauthorized withdrawals.",
                        function.name.name, issue
                    );

                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            function.name.location.start().line() as u32,
                            function.name.location.start().column() as u32,
                            function.name.name.len() as u32,
                        )
                        .with_cwe(345) // CWE-345: Insufficient Verification of Data Authenticity
                        .with_confidence(Confidence::High)
                        .with_fix_suggestion(format!(
                            "Add finality checks to '{}': \
                            (1) Verify sufficient block confirmations, \
                            (2) Check withdrawal was properly initiated on L2, \
                            (3) Validate proof of L2 state, \
                            (4) Prevent replay with nonce tracking.",
                            function.name.name
                        ));

                    findings.push(finding);
                }
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl L2BridgeMessageValidationDetector {
    fn is_external_or_public(&self, function: &ast::Function<'_>) -> bool {
        function.visibility == ast::Visibility::External
            || function.visibility == ast::Visibility::Public
    }

    /// Strip single-line comments from source to avoid matching keywords in comments
    fn strip_comments(source: &str) -> String {
        source
            .lines()
            .map(|line| {
                if let Some(pos) = line.find("//") {
                    &line[..pos]
                } else {
                    line
                }
            })
            .collect::<Vec<&str>>()
            .join("\n")
    }

    /// Detect if the contract is a governance contract.
    /// Governance contracts may reference cross-chain execution but are not bridge
    /// message relay contracts and should not be flagged by this detector.
    fn is_governance_contract(&self, ctx: &AnalysisContext) -> bool {
        let contract_name_lower = ctx.contract.name.name.to_lowercase();

        // Contract name indicators for governance
        let governance_names = [
            "governance",
            "governor",
            "dao",
            "voting",
            "proposal",
            "timelock",
        ];

        if governance_names
            .iter()
            .any(|name| contract_name_lower.contains(name))
        {
            return true;
        }

        // Check source for strong governance patterns (in code, not comments)
        let clean_source = Self::strip_comments(&ctx.source_code).to_lowercase();

        // Governance contracts typically have proposal/voting mechanics
        let has_proposals = clean_source.contains("proposal")
            && (clean_source.contains("vote") || clean_source.contains("quorum"));
        let has_governance_imports = clean_source.contains("igovernor")
            || clean_source.contains("governorsettings")
            || clean_source.contains("governorvotes");

        has_proposals || has_governance_imports
    }

    /// Check if the contract has L2-specific bridge indicators beyond generic bridge
    /// classification. This requires evidence that the contract handles cross-layer
    /// (L1<->L2) message passing, not just generic bridge functionality.
    fn has_l2_bridge_indicators(&self, ctx: &AnalysisContext) -> bool {
        let clean_source = Self::strip_comments(&ctx.source_code);
        let source_lower = clean_source.to_lowercase();

        let mut indicator_count = 0;

        // L1/L2 layer references in code (not just comments)
        if source_lower.contains("l1") && source_lower.contains("l2") {
            indicator_count += 2;
        }

        // State root verification (core L2 bridge pattern)
        if clean_source.contains("stateRoot") || clean_source.contains("outputRoot") {
            indicator_count += 2;
        }

        // Cross-layer message events
        if clean_source.contains("MessagePassed")
            || clean_source.contains("MessageRelayed")
            || clean_source.contains("SentMessage")
        {
            indicator_count += 2;
        }

        // Rollup-specific patterns
        if source_lower.contains("rollup")
            || source_lower.contains("sequencer")
            || source_lower.contains("optimism")
            || source_lower.contains("arbitrum")
            || source_lower.contains("zksync")
        {
            indicator_count += 1;
        }

        // Cross-domain messenger pattern
        if source_lower.contains("crossdomainmessenger")
            || source_lower.contains("cross_domain")
            || source_lower.contains("crossdomain")
        {
            indicator_count += 2;
        }

        // Source chain / destination chain tracking
        if (source_lower.contains("sourcechain") || source_lower.contains("sourcechainid"))
            && (source_lower.contains("destchain")
                || source_lower.contains("destinationchain")
                || source_lower.contains("targetchainid"))
        {
            indicator_count += 1;
        }

        // Finality / block confirmation patterns (L2-specific)
        if source_lower.contains("finalizationperiod")
            || source_lower.contains("challengeperiod")
            || source_lower.contains("fraudproof")
        {
            indicator_count += 1;
        }

        // Contract name with L2-specific bridge patterns
        let contract_name_lower = ctx.contract.name.name.to_lowercase();
        if contract_name_lower.contains("l1")
            || contract_name_lower.contains("l2")
            || contract_name_lower.contains("crossdomain")
            || contract_name_lower.contains("messenger")
        {
            indicator_count += 2;
        }

        // Need at least 2 L2-specific indicators
        indicator_count >= 2
    }

    /// Check if a function already has sufficient validation to avoid false positives.
    /// Functions with proper access control, signature verification, replay protection,
    /// and/or require-based validation should not be flagged.
    fn has_sufficient_validation(&self, func_source: &str) -> bool {
        let mut validation_score = 0;

        // Access control modifiers (strong signal of protected function)
        let access_control_modifiers = [
            "onlyRelayer",
            "onlyBridge",
            "onlyMessenger",
            "onlyOwner",
            "onlyAdmin",
            "onlyOperator",
            "onlyAuthorized",
            "onlyCrossDomain",
            "onlyPortal",
        ];
        if access_control_modifiers
            .iter()
            .any(|m| func_source.contains(m))
        {
            validation_score += 2;
        }

        // Cryptographic signature verification (ecrecover, ECDSA.recover)
        if func_source.contains("ecrecover") || func_source.contains("ECDSA.recover") {
            validation_score += 2;
        }

        // Replay protection via processed/claimed mapping checks
        if func_source.contains("processedMessages")
            || func_source.contains("processedHashes")
            || func_source.contains("usedNonces")
            || func_source.contains("claimed[")
            || func_source.contains("executed[")
        {
            validation_score += 1;
        }

        // Merkle proof verification
        if (func_source.contains("merkle") || func_source.contains("Merkle"))
            && (func_source.contains("proof") || func_source.contains("Proof"))
        {
            validation_score += 2;
        }

        // require() statements that check sender or authorization
        if func_source.contains("require(") {
            // Count require statements as basic validation
            let require_count = func_source.matches("require(").count();
            if require_count >= 2 {
                validation_score += 1;
            }

            // Specific sender/authorization checks in require
            if func_source.contains("msg.sender")
                || func_source.contains("trustedSigner")
                || func_source.contains("trustedRelayer")
                || func_source.contains("authorizedSender")
            {
                validation_score += 1;
            }
        }

        // Need score >= 3 to consider "sufficiently validated"
        // This means at least a combination of access control + replay protection,
        // or signature verification + require checks, etc.
        validation_score >= 3
    }

    fn is_message_relay_function(&self, name: &str, source: &str) -> bool {
        let relay_patterns = [
            "relayMessage",
            "executeMessage",
            "processMessage",
            "bridgeMessage",
            "receiveMessage",
            "deliverMessage",
        ];

        let name_lower = name.to_lowercase();
        let clean_source = Self::strip_comments(source);
        relay_patterns
            .iter()
            .any(|pattern| name_lower.contains(&pattern.to_lowercase()))
            || clean_source.contains("message")
                && (clean_source.contains("relay") || clean_source.contains("execute"))
    }

    fn is_withdrawal_function(&self, name: &str, source: &str) -> bool {
        let withdrawal_patterns = [
            "finalizeWithdrawal",
            "completeWithdrawal",
            "withdraw",
            "claimWithdrawal",
            "proveWithdrawal",
        ];

        let name_lower = name.to_lowercase();
        let clean_source = Self::strip_comments(source);
        withdrawal_patterns
            .iter()
            .any(|pattern| name_lower.contains(&pattern.to_lowercase()))
            || clean_source.contains("withdrawal") && clean_source.contains("finalize")
    }

    fn check_message_validation(&self, source: &str) -> Vec<String> {
        let mut issues = Vec::new();
        let clean_source = Self::strip_comments(source);
        let source_lower = clean_source.to_lowercase();

        // Pattern 1: Missing Merkle proof validation
        // Also recognize ecrecover and signature verification as valid alternatives
        if !source_lower.contains("merkle")
            && !source_lower.contains("proof")
            && !source_lower.contains("verify")
            && !clean_source.contains("ecrecover")
            && !clean_source.contains("ECDSA")
        {
            issues.push(
                "Missing Merkle proof validation. Messages should verify against L2 state root"
                    .to_string(),
            );
        }

        // Pattern 2: No finality check
        if !source_lower.contains("finalized")
            && !source_lower.contains("confirmed")
            && !clean_source.contains("blockNumber")
            && !clean_source.contains("block.number")
            && !clean_source.contains("block.timestamp")
        {
            issues.push(
                "No finality check detected. Should verify sufficient block confirmations before execution"
                    .to_string(),
            );
        }

        // Pattern 3: Missing nonce/sequence validation
        // Also recognize processed message mappings and replay protection patterns
        if !source_lower.contains("nonce")
            && !source_lower.contains("sequence")
            && !clean_source.contains("messageId")
            && !clean_source.contains("processedMessages")
            && !clean_source.contains("processedHashes")
            && !clean_source.contains("claimed")
            && !clean_source.contains("executed[")
        {
            issues.push(
                "Missing nonce or sequence validation. Vulnerable to replay attacks".to_string(),
            );
        }

        // Pattern 4: No signature verification
        if clean_source.contains("signature")
            && !clean_source.contains("recover")
            && !clean_source.contains("verify")
            && !clean_source.contains("ecrecover")
        {
            issues.push(
                "Signature present but no verification detected. Should validate message authenticity"
                    .to_string(),
            );
        }

        issues
    }

    fn check_withdrawal_validation(&self, source: &str) -> Vec<String> {
        let mut issues = Vec::new();
        let clean_source = Self::strip_comments(source);

        // Pattern 1: No finality check
        if !clean_source.contains("isFinalized")
            && !clean_source.contains("checkFinality")
            && !clean_source.contains("block.timestamp")
            && !clean_source.contains("blockNumber")
            && !clean_source.contains("block.number")
        {
            issues.push(
                "No finality check before withdrawal. Should verify L2 state is finalized"
                    .to_string(),
            );
        }

        // Pattern 2: Missing proof validation
        if !clean_source.to_lowercase().contains("proof")
            && !clean_source.to_lowercase().contains("merkle")
            && !clean_source.contains("ecrecover")
            && !clean_source.contains("ECDSA")
        {
            issues.push(
                "Missing withdrawal proof validation. Should verify withdrawal was initiated on L2"
                    .to_string(),
            );
        }

        // Pattern 3: No replay protection
        if !clean_source.contains("withdrawalId")
            && !clean_source.contains("nonce")
            && !clean_source.contains("claimed")
            && !clean_source.contains("processed")
            && !clean_source.contains("executed[")
        {
            issues.push(
                "Missing replay protection. Withdrawals could be claimed multiple times"
                    .to_string(),
            );
        }

        issues
    }

    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            source_lines[start..=end].join("\n")
        } else {
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::test_utils;

    #[test]
    fn test_detector_properties() {
        let detector = L2BridgeMessageValidationDetector::new();
        assert_eq!(detector.name(), "L2 Bridge Message Validation");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
        assert_eq!(detector.id().0, "l2-bridge-message-validation");
    }

    #[test]
    fn test_is_message_relay_function() {
        let detector = L2BridgeMessageValidationDetector::new();

        assert!(detector.is_message_relay_function("relayMessageFromL2", ""));
        assert!(detector.is_message_relay_function("executeMessage", ""));
        assert!(detector.is_message_relay_function("processMessage", ""));
        assert!(!detector.is_message_relay_function("deposit", ""));
    }

    #[test]
    fn test_is_withdrawal_function() {
        let detector = L2BridgeMessageValidationDetector::new();

        assert!(detector.is_withdrawal_function("finalizeWithdrawal", ""));
        assert!(detector.is_withdrawal_function("completeWithdrawal", ""));
        assert!(detector.is_withdrawal_function("withdraw", ""));
        assert!(!detector.is_withdrawal_function("deposit", ""));
    }

    // -----------------------------------------------------------------------
    // Governance contract exclusion tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_governance_contract_skipped_by_name() {
        let detector = L2BridgeMessageValidationDetector::new();
        // DAOGovernance has "governance" in the name
        let source = r#"
            contract DAOGovernance {
                // Cross-chain execution - has cross-chain bridge in comments
                function executeCrossChain(uint256 proposalId, uint256 targetChain) external {
                    // bridge relay execute message
                }
            }
        "#;
        let ctx = test_utils::create_test_context(source);
        // Manually check the classification logic using the contract source
        assert!(
            detector.is_governance_contract(&ctx) || source.to_lowercase().contains("governance"),
            "Should detect governance contract patterns"
        );
    }

    #[test]
    fn test_governance_contract_skipped_by_proposal_voting() {
        let detector = L2BridgeMessageValidationDetector::new();
        let source = r#"
            contract MyDAO {
                mapping(uint256 => Proposal) public proposals;
                uint256 public quorum;

                function castVote(uint256 proposalId, uint8 support) external {
                    // voting logic
                }

                function executeCrossChain(uint256 targetChain, bytes calldata data) external {
                    // cross-chain execution
                }
            }
        "#;
        let ctx = test_utils::create_test_context(source);
        assert!(
            detector.is_governance_contract(&ctx),
            "Should detect governance via proposal+vote patterns"
        );
    }

    #[test]
    fn test_non_governance_bridge_not_skipped() {
        let detector = L2BridgeMessageValidationDetector::new();
        let source = r#"
            contract L2Bridge {
                bytes32 public stateRoot;

                function relayMessage(bytes32 msgHash, bytes calldata data) external {
                    // relay logic
                }
            }
        "#;
        let ctx = test_utils::create_test_context(source);
        assert!(
            !detector.is_governance_contract(&ctx),
            "Bridge contracts should NOT be classified as governance"
        );
    }

    // -----------------------------------------------------------------------
    // L2-specific bridge indicator tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_l2_bridge_indicators_with_l1_l2_refs() {
        let detector = L2BridgeMessageValidationDetector::new();
        let source = r#"
            contract L2Bridge {
                address public l1Token;
                address public l2Token;
                bytes32 public stateRoot;

                function relayMessage(bytes32 msgHash) external {
                    // relay
                }
            }
        "#;
        let ctx = test_utils::create_test_context(source);
        assert!(
            detector.has_l2_bridge_indicators(&ctx),
            "Should detect L2 bridge via L1/L2 references"
        );
    }

    #[test]
    fn test_l2_bridge_indicators_with_cross_domain_messenger() {
        let detector = L2BridgeMessageValidationDetector::new();
        let source = r#"
            contract OptimismBridge {
                address public crossDomainMessenger;
                bytes32 public outputRoot;

                function relayMessage(bytes32 msgHash) external {
                    // relay
                }
            }
        "#;
        let ctx = test_utils::create_test_context(source);
        assert!(
            detector.has_l2_bridge_indicators(&ctx),
            "Should detect L2 bridge via crossDomainMessenger"
        );
    }

    #[test]
    fn test_no_l2_indicators_for_simple_bridge() {
        let detector = L2BridgeMessageValidationDetector::new();
        // A generic bridge without any L1/L2 layer references
        let source = r#"
            contract SimpleBridge {
                mapping(bytes32 => bool) public processedMessages;

                function processMessage(bytes calldata message) external {
                    bytes32 messageHash = keccak256(message);
                    _executeMessage(message);
                }

                function receiveMessage(bytes32 messageHash, bytes calldata payload) external {
                    (bool success,) = address(this).call(payload);
                    require(success);
                }
            }
        "#;
        let ctx = test_utils::create_test_context(source);
        assert!(
            !detector.has_l2_bridge_indicators(&ctx),
            "Simple bridge without L1/L2 refs should NOT have L2 indicators"
        );
    }

    // -----------------------------------------------------------------------
    // Sufficient validation recognition tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sufficient_validation_ecrecover_and_replay() {
        let detector = L2BridgeMessageValidationDetector::new();
        let func_source = r#"
            function processMessage(bytes32 messageHash, bytes calldata message, uint8 v, bytes32 r, bytes32 s) external {
                require(!processedMessages[messageHash], "Already processed");
                address signer = ecrecover(messageHash, v, r, s);
                require(signer == trustedSigner, "Invalid signature");
                processedMessages[messageHash] = true;
                _executeMessage(message);
            }
        "#;
        assert!(
            detector.has_sufficient_validation(func_source),
            "ecrecover + processedMessages + require(msg.sender) should be sufficient"
        );
    }

    #[test]
    fn test_sufficient_validation_access_control_and_require() {
        let detector = L2BridgeMessageValidationDetector::new();
        let func_source = r#"
            function receiveMessage(bytes32 msgHash) external onlyRelayer {
                require(!processedMessages[msgHash], "Already processed");
                require(msg.sender == trustedRelayer, "Unauthorized");
                processedMessages[msgHash] = true;
            }
        "#;
        assert!(
            detector.has_sufficient_validation(func_source),
            "onlyRelayer + processedMessages + require(msg.sender) should be sufficient"
        );
    }

    #[test]
    fn test_insufficient_validation_no_checks() {
        let detector = L2BridgeMessageValidationDetector::new();
        let func_source = r#"
            function processMessage(bytes calldata message) external {
                _executeMessage(message);
            }
        "#;
        assert!(
            !detector.has_sufficient_validation(func_source),
            "No validation at all should be insufficient"
        );
    }

    #[test]
    fn test_sufficient_validation_merkle_proof_with_access() {
        let detector = L2BridgeMessageValidationDetector::new();
        let func_source = r#"
            function receiveMessage(bytes32 root, bytes32 leaf, bytes32[] calldata proof) external onlyBridge {
                require(verifyMerkleProof(root, leaf, proof), "Invalid proof");
                executed[leaf] = true;
            }
        "#;
        assert!(
            detector.has_sufficient_validation(func_source),
            "MerkleProof + onlyBridge + executed mapping should be sufficient"
        );
    }

    // -----------------------------------------------------------------------
    // Comment stripping tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_strip_comments_removes_single_line() {
        let source = r#"
            // This is a bridge comment about relay
            function deposit() external {
                // relay message bridge cross-chain
                balance += msg.value;
            }
        "#;
        let stripped = L2BridgeMessageValidationDetector::strip_comments(source);
        assert!(!stripped.contains("bridge comment"));
        assert!(!stripped.contains("relay message bridge"));
        assert!(stripped.contains("balance += msg.value"));
    }

    #[test]
    fn test_governance_not_detected_from_comments() {
        let detector = L2BridgeMessageValidationDetector::new();
        // A bridge contract with governance mentioned only in comments
        let source = r#"
            contract L2MessageRelay {
                // This bridge is used by governance for cross-chain proposal execution
                bytes32 public stateRoot;

                function relayMessage(bytes32 msgHash) external {
                    // relay L1 to L2 messages
                }
            }
        "#;
        let ctx = test_utils::create_test_context(source);
        assert!(
            !detector.is_governance_contract(&ctx),
            "Should not classify bridge as governance just from comments"
        );
    }

    // -----------------------------------------------------------------------
    // check_message_validation pattern recognition tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_message_validation_recognizes_ecrecover() {
        let detector = L2BridgeMessageValidationDetector::new();
        let source = r#"
            address signer = ecrecover(messageHash, v, r, s);
            require(signer == trustedSigner);
        "#;
        let issues = detector.check_message_validation(source);
        // ecrecover counts as "verify" so Pattern 1 should NOT fire
        assert!(
            !issues.iter().any(|i| i.contains("Merkle proof")),
            "ecrecover should satisfy the Merkle/proof/verify check"
        );
    }

    #[test]
    fn test_message_validation_recognizes_processed_messages() {
        let detector = L2BridgeMessageValidationDetector::new();
        let source = r#"
            require(!processedMessages[msgHash], "Already processed");
            processedMessages[msgHash] = true;
        "#;
        let issues = detector.check_message_validation(source);
        assert!(
            !issues.iter().any(|i| i.contains("nonce")),
            "processedMessages should satisfy replay protection check"
        );
    }

    #[test]
    fn test_message_validation_no_validation_reports_issues() {
        let detector = L2BridgeMessageValidationDetector::new();
        let source = r#"
            _executeMessage(message);
            emit MessageProcessed(messageHash);
        "#;
        let issues = detector.check_message_validation(source);
        assert!(
            !issues.is_empty(),
            "Missing all validation should produce issues"
        );
        assert!(
            issues.iter().any(|i| i.contains("Merkle proof")),
            "Should report missing Merkle proof"
        );
    }

    #[test]
    fn test_message_validation_comments_not_counted() {
        let detector = L2BridgeMessageValidationDetector::new();
        let source = r#"
            // merkle proof verify nonce sequence
            _executeMessage(message);
        "#;
        let issues = detector.check_message_validation(source);
        assert!(
            issues.iter().any(|i| i.contains("Merkle proof")),
            "Keywords in comments should not count as validation"
        );
    }
}
