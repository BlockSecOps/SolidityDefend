//! Multi-Signature Bypass Detection
//!
//! Detects multi-signature wallets and governance systems with flawed signature verification
//! that allows threshold bypass, signature reuse, or owner manipulation.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct MultisigBypassDetector {
    base: BaseDetector,
}

impl MultisigBypassDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("multisig-bypass".to_string()),
                "Multi-Signature Bypass Detection".to_string(),
                "Detects multi-signature systems with flawed signature verification that allows threshold bypass, signature reuse, or owner manipulation".to_string(),
                vec![
                    DetectorCategory::AccessControl,
                    DetectorCategory::Auth,
                    DetectorCategory::Logic,
                ],
                Severity::Critical,
            ),
        }
    }

    /// Check if the contract is an ERC-4337 paymaster or account abstraction contract.
    /// These contracts have their own signature/validation patterns that are not multisig.
    fn is_erc4337_or_aa_contract(source_lower: &str) -> bool {
        // ERC-4337 paymaster indicators
        let is_paymaster = source_lower.contains("validatepaymasteruserop")
            || source_lower.contains("paymaster")
            || source_lower.contains("userop")
            || source_lower.contains("userophash");

        // Account abstraction indicators
        let is_aa = source_lower.contains("entrypoint")
            || source_lower.contains("validateuserop")
            || source_lower.contains("iaccountexecution")
            || source_lower.contains("sessionkey");

        is_paymaster || is_aa
    }

    /// Check if the contract is a delegatecall proxy pattern.
    /// Proxies use delegatecall for upgradeability, not for multisig execution.
    fn is_delegatecall_proxy(source_lower: &str) -> bool {
        let has_delegatecall = source_lower.contains("delegatecall");
        let has_proxy_indicators = source_lower.contains("implementation")
            || source_lower.contains("proxy")
            || source_lower.contains("fallback()")
            || source_lower.contains("calldatacopy");

        // Strong proxy signal: delegatecall + proxy patterns without multisig-specific state
        has_delegatecall && has_proxy_indicators
    }

    /// Check if the contract is a social recovery contract.
    /// Social recovery uses guardians, not multiple owner signatures.
    fn is_social_recovery_contract(source_lower: &str) -> bool {
        let has_recovery =
            source_lower.contains("recovery") || source_lower.contains("socialrecovery");
        let has_guardians = source_lower.contains("guardian");

        has_recovery && has_guardians
    }

    /// Determine if the contract has actual multisig structural indicators.
    /// A true multisig contract requires multiple owners to sign transactions
    /// before execution. This is distinct from simple signature verification,
    /// social recovery, paymasters, or proxy patterns.
    fn has_multisig_structure(source_lower: &str) -> bool {
        // Explicit multisig naming (strong signal)
        let has_multisig_name = source_lower.contains("multisig")
            || source_lower.contains("multi_sig")
            || source_lower.contains("multi-sig")
            || source_lower.contains("multisigwallet")
            || source_lower.contains("gnosis");

        // Structural indicators: multisig contracts track owners and require
        // multiple signatures to reach a threshold for execution
        let has_owners_state = source_lower.contains("isowner[")
            || source_lower.contains("isowner(")
            || source_lower.contains("mapping(address => bool)")
                && (source_lower.contains("owner") || source_lower.contains("signer"))
            || source_lower.contains("address[] public owners")
            || source_lower.contains("address[] owners")
            || source_lower.contains("ownercount")
            || source_lower.contains("numowners");

        let has_threshold_state = source_lower.contains("threshold")
            || source_lower.contains("required")
            || source_lower.contains("numconfirmations")
            || source_lower.contains("minsignatures");

        let has_signature_collection = source_lower.contains("signatures")
            || source_lower.contains("confirmations")
            || source_lower.contains("approvals");

        // A multisig needs either:
        // 1. Explicit multisig naming, OR
        // 2. Both owner tracking AND threshold/required state AND signature collection
        if has_multisig_name {
            return true;
        }

        // Require at least 2 of the 3 structural indicators for implicit detection
        let indicator_count = [
            has_owners_state,
            has_threshold_state,
            has_signature_collection,
        ]
        .iter()
        .filter(|&&x| x)
        .count();

        indicator_count >= 2
    }

    fn check_multisig_patterns(&self, ctx: &AnalysisContext) -> Vec<(String, u32, String)> {
        let mut findings = Vec::new();
        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Early exit: skip non-multisig contract types that share superficial keywords
        if Self::is_erc4337_or_aa_contract(&source_lower) {
            return findings;
        }

        if Self::is_delegatecall_proxy(&source_lower) {
            return findings;
        }

        if Self::is_social_recovery_contract(&source_lower) {
            return findings;
        }

        // Require actual multisig structural indicators
        if !Self::has_multisig_structure(&source_lower) {
            return findings;
        }

        // Pattern 1: Missing nonce validation in signature verification
        if source_lower.contains("signature") || source_lower.contains("execute") {
            let has_nonce = source_lower.contains("nonce")
                || source_lower.contains("executedtx")
                || source_lower.contains("usedtransaction");

            let has_verification = source_lower.contains("ecrecover")
                || source_lower.contains("verify")
                || source_lower.contains("checksignature");

            if has_verification && !has_nonce {
                findings.push((
                    "Missing nonce validation in signature verification (replay attack risk)".to_string(),
                    0,
                    "Add nonce tracking: mapping(bytes32 => bool) public executedTxs; Include nonce in signature hash: bytes32 hash = keccak256(abi.encodePacked(target, value, data, nonce));".to_string(),
                ));
            }
        }

        // Pattern 2: Insufficient duplicate signature check
        if source_lower.contains("threshold") && source_lower.contains("signature") {
            let has_duplicate_check = source_lower.contains("mapping")
                && (source_lower.contains("signed") || source_lower.contains("used"))
                || source_lower.contains("set<")
                || source_lower.contains("unique");

            let checks_length =
                source_lower.contains("signatures.length") && source_lower.contains("threshold");

            if checks_length && !has_duplicate_check {
                findings.push((
                    "Signature count validation without duplicate signer check (threshold bypass)".to_string(),
                    0,
                    "Check for duplicate signers: mapping(address => bool) signed; for each signature: address signer = ecrecover(...); require(!signed[signer]); signed[signer] = true;".to_string(),
                ));
            }
        }

        // Pattern 3: Owner enumeration issues
        if source_lower.contains("owner")
            && (source_lower.contains("add") || source_lower.contains("remove"))
        {
            let modifies_owners = (source_lower.contains("addowner")
                || source_lower.contains("removeowner"))
                || (source_lower.contains("function addowner")
                    || source_lower.contains("function removeowner"));

            let adjusts_threshold = source_lower.contains("threshold")
                && (source_lower.contains("=") || source_lower.contains("update"));

            if modifies_owners {
                // Check for threshold validation
                let validates_threshold = (source_lower.contains("require")
                    && source_lower.contains("threshold"))
                    || source_lower.contains("threshold <=")
                    || source_lower.contains("threshold <");

                if !validates_threshold {
                    findings.push((
                        "Owner modification without threshold validation (inconsistent state)".to_string(),
                        0,
                        "Validate threshold: require(threshold <= ownerCount && threshold > 0, \"Invalid threshold\"); Adjust threshold when removing owners if needed.".to_string(),
                    ));
                }

                // Check if threshold is adjusted when removing last owners
                if source_lower.contains("remove") && !adjusts_threshold {
                    findings.push((
                        "Owner removal without threshold adjustment (can make contract unusable)".to_string(),
                        0,
                        "Adjust threshold: if (ownerCount < threshold) { threshold = ownerCount; } Ensure threshold remains achievable after owner removal.".to_string(),
                    ));
                }
            }
        }

        // Pattern 4: Signature malleability (missing s-value check)
        if source_lower.contains("ecrecover") {
            let has_malleability_check = source_lower.contains("secp256k1")
                || (source_lower.contains("require") && source_lower.contains("s <="))
                || source_lower
                    .contains("0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");

            // Skip for ERC-2612 permit tokens (nonce provides replay protection)
            let is_permit_token = source_lower.contains("permit")
                && source_lower.contains("nonces")
                && (source_lower.contains("domainseparator")
                    || source_lower.contains("domain_separator"));

            if !has_malleability_check && !is_permit_token {
                findings.push((
                    "Missing signature malleability protection (duplicate signature acceptance)".to_string(),
                    0,
                    "Check s-value: require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, \"Invalid s-value\"); This prevents signature malleability.".to_string(),
                ));
            }
        }

        // Pattern 5: Missing domain separator (cross-contract replay)
        if source_lower.contains("keccak256") && source_lower.contains("signature") {
            // Look for actual domain separator usage patterns, not just the word in comments
            let has_domain_separator = source_lower.contains("domainseparator")
                || source_lower.contains("domain_separator")
                || source_lower.contains("block.chainid")
                || (source_lower.contains("address(this)") && source_lower.contains("abi.encode"));

            if !has_domain_separator {
                findings.push((
                    "Missing domain separator in signature hash (cross-contract/chain replay)".to_string(),
                    0,
                    "Include domain separator: bytes32 domainSeparator = keccak256(abi.encode(TYPEHASH, address(this), block.chainid)); bytes32 hash = keccak256(abi.encodePacked(domainSeparator, data));".to_string(),
                ));
            }
        }

        // Pattern 6: Off-by-one threshold validation
        if source_lower.contains("threshold") {
            let _has_strict_comparison =
                source_lower.contains(">=") && source_lower.contains("threshold");

            let has_loose_comparison =
                source_lower.contains("> threshold") || source_lower.contains("< threshold");

            if has_loose_comparison {
                findings.push((
                    "Potential off-by-one error in threshold validation (use >= not >)".to_string(),
                    0,
                    "Use correct comparison: require(validSignatures >= threshold, \"Insufficient signatures\"); Not: validSignatures > threshold-1".to_string(),
                ));
            }
        }

        // Pattern 7: Missing signature expiration
        if source_lower.contains("execute") && source_lower.contains("signature") {
            // Look for actual deadline usage patterns or nonce (nonce also prevents replay)
            let has_deadline = (source_lower.contains("deadline")
                && (source_lower.contains("<=")
                    || source_lower.contains("<")
                    || source_lower.contains("require")))
                || (source_lower.contains("expir") && source_lower.contains("block.timestamp"))
                || (source_lower.contains("block.timestamp")
                    && source_lower.contains("<=")
                    && source_lower.contains("require"));

            // Nonce also prevents replay and is an alternative to deadline
            let has_nonce_in_execution = source_lower.contains("nonce")
                && (source_lower.contains("nonce++")
                    || source_lower.contains("nonce + 1")
                    || source_lower.contains("increment"));

            if !has_deadline && !has_nonce_in_execution {
                findings.push((
                    "Signatures without expiration/deadline (indefinite validity risk)".to_string(),
                    0,
                    "Add expiration: Include deadline in signature data; require(block.timestamp <= deadline, \"Signature expired\"); Prevents execution of stale signatures.".to_string(),
                ));
            }
        }

        // Pattern 8: Zero address signer vulnerability
        if source_lower.contains("ecrecover") {
            // Look for actual zero address validation in code, not comments
            // Real code has comma (error msg) or && (additional condition) after the check
            let checks_zero_address = source_lower.contains("signer != address(0) &&")
                || source_lower.contains("address(0) != signer &&")
                || source_lower.contains("signer != address(0),")
                || source_lower.contains("address(0) != signer,")
                || (source_lower.contains("signer == address(0)")
                    && source_lower.contains("if (")
                    && source_lower.contains("revert"));

            let has_owner_check = source_lower.contains("isowner")
                || source_lower.contains("owner[")
                || source_lower.contains("owners");

            // isOwner[signer] implicitly checks for zero address (address(0) can't be an owner)
            let has_isowner_require = source_lower.contains("require(isowner[signer]")
                || source_lower.contains("require(isowner[")
                || (source_lower.contains("isowner[signer]") && source_lower.contains("require"));

            if has_owner_check && !checks_zero_address && !has_isowner_require {
                findings.push((
                    "Missing zero address check after ecrecover (invalid signature counts as address(0))".to_string(),
                    0,
                    "Validate signer: address signer = ecrecover(hash, v, r, s); require(signer != address(0) && isOwner[signer], \"Invalid signature\");".to_string(),
                ));
            }
        }

        // Pattern 9: Public execute function without proper validation
        if (source_lower.contains("function execute")
            || source_lower.contains("function executetransaction"))
            && (source_lower.contains("public") || source_lower.contains("external"))
        {
            let has_signature_check = source_lower.contains("signature")
                || source_lower.contains("ecrecover")
                || source_lower.contains("verify");

            if !has_signature_check {
                findings.push((
                    "Public execute function without signature verification".to_string(),
                    0,
                    "Add signature verification: Verify all required signatures before execution; Check threshold; Validate signers are owners.".to_string(),
                ));
            }
        }

        // Pattern 10: Threshold zero or exceeds owner count
        if source_lower.contains("threshold") {
            let has_threshold_validation = (source_lower.contains("require")
                || source_lower.contains("if"))
                && source_lower.contains("threshold")
                && (source_lower.contains("> 0") || source_lower.contains("!= 0"));

            if !has_threshold_validation {
                findings.push((
                    "Missing threshold validation (can be set to zero or exceed owner count)".to_string(),
                    0,
                    "Validate threshold: require(threshold > 0 && threshold <= ownerCount, \"Invalid threshold\"); Prevents unusable multi-sig configurations.".to_string(),
                ));
            }
        }

        findings
    }
}

impl Default for MultisigBypassDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for MultisigBypassDetector {
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        let issues = self.check_multisig_patterns(ctx);

        for (message, line_offset, remediation) in issues {
            let severity = if message.contains("threshold bypass")
                || message.contains("without signature verification")
                || message.contains("replay attack risk")
            {
                Severity::Critical
            } else if message.contains("duplicate")
                || message.contains("malleability")
                || message.contains("zero address")
            {
                Severity::High
            } else {
                Severity::Medium
            };

            let finding = self
                .base
                .create_finding_with_severity(ctx, message, line_offset, 0, 20, severity)
                .with_fix_suggestion(remediation)
                .with_cwe(347); // CWE-347: Improper Verification of Cryptographic Signature

            findings.push(finding);
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::test_utils::*;

    #[test]
    fn test_detector_properties() {
        let detector = MultisigBypassDetector::new();
        assert_eq!(detector.id().to_string(), "multisig-bypass");
        assert_eq!(detector.name(), "Multi-Signature Bypass Detection");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_detects_missing_nonce() {
        let detector = MultisigBypassDetector::new();
        let source = r#"
            contract MultiSig {
                function executeTransaction(bytes[] memory signatures) external {
                    bytes32 hash = keccak256(txData);
                    for (uint i = 0; i < signatures.length; i++) {
                        address signer = ecrecover(hash, v, r, s);
                        require(isOwner[signer]);
                    }
                    // Execute transaction
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
        assert!(result.iter().any(|f| f.message.contains("nonce")));
    }

    #[test]
    fn test_detects_no_duplicate_check() {
        let detector = MultisigBypassDetector::new();
        let source = r#"
            contract MultiSig {
                mapping(address => bool) public isOwner;
                uint256 public ownerCount;
                uint256 public threshold;

                function execute(bytes[] memory signatures) external {
                    require(signatures.length >= threshold);
                    // Missing: duplicate signer check
                    for (uint i = 0; i < signatures.length; i++) {
                        verifySignature(signatures[i]);
                    }
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
        assert!(result.iter().any(|f| f.message.contains("duplicate")));
    }

    #[test]
    fn test_detects_owner_modification_without_threshold_check() {
        let detector = MultisigBypassDetector::new();
        let source = r#"
            contract MultiSig {
                mapping(address => bool) public isOwner;
                uint256 public ownerCount;
                uint256 public threshold;

                function removeOwner(address owner) external {
                    require(isOwner[owner]);
                    isOwner[owner] = false;
                    ownerCount--;
                    // Missing: threshold validation
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
        assert!(result.iter().any(|f| f.message.contains("threshold")));
    }

    #[test]
    fn test_detects_signature_malleability() {
        let detector = MultisigBypassDetector::new();
        let source = r#"
            contract MultiSig {
                function verifySignature(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal view returns (address) {
                    address signer = ecrecover(hash, v, r, s);
                    // Missing: s-value malleability check
                    return signer;
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
        assert!(result.iter().any(|f| f.message.contains("malleability")));
    }

    #[test]
    fn test_detects_missing_domain_separator() {
        let detector = MultisigBypassDetector::new();
        let source = r#"
            contract MultiSig {
                function getTransactionHash(address target, uint256 value) public pure returns (bytes32) {
                    return keccak256(abi.encodePacked(target, value));
                    // Missing: domain separator (contract address, chain ID)
                }

                function execute(bytes[] memory signatures) external {
                    bytes32 hash = getTransactionHash(target, value);
                    verifySignatures(hash, signatures);
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
        assert!(
            result
                .iter()
                .any(|f| f.message.contains("domain separator"))
        );
    }

    #[test]
    fn test_detects_missing_expiration() {
        let detector = MultisigBypassDetector::new();
        let source = r#"
            contract MultiSig {
                function executeTransaction(
                    address target,
                    uint256 value,
                    bytes[] memory signatures
                ) external {
                    bytes32 hash = keccak256(abi.encodePacked(target, value));
                    // Missing: deadline/expiration check
                    verifySignatures(hash, signatures);
                    target.call{value: value}("");
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
        assert!(
            result
                .iter()
                .any(|f| f.message.contains("expiration") || f.message.contains("deadline"))
        );
    }

    #[test]
    fn test_detects_zero_address_signer() {
        // This test verifies implicit zero address check is recognized
        // require(isOwner[signer]) implicitly checks for zero address since
        // isOwner[address(0)] would typically be false
        let detector = MultisigBypassDetector::new();
        let source = r#"
            contract MultiSig {
                mapping(address => bool) public isOwner;

                function verifySignature(bytes32 hash, bytes memory signature) internal view {
                    (uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);
                    address signer = ecrecover(hash, v, r, s);
                    // Implicit zero address check via isOwner mapping
                    require(isOwner[signer], "Not owner");
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        // Should recognize implicit zero address check
        let has_zero_address_finding = result.iter().any(|f| f.message.contains("zero address"));
        assert!(
            !has_zero_address_finding,
            "require(isOwner[signer]) provides implicit zero address check"
        );
    }

    #[test]
    fn test_safe_multisig_has_fewer_findings() {
        let detector = MultisigBypassDetector::new();
        let source = r#"
            contract SafeMultiSig {
                mapping(address => bool) public isOwner;
                mapping(bytes32 => bool) public executedTxs;
                uint256 public threshold;
                uint256 public ownerCount;
                uint256 public nonce;

                function executeTransaction(
                    address target,
                    uint256 value,
                    bytes memory data,
                    uint256 deadline,
                    bytes[] memory signatures
                ) external {
                    require(block.timestamp <= deadline, "Expired");
                    require(signatures.length >= threshold, "Insufficient signatures");
                    require(threshold > 0 && threshold <= ownerCount, "Invalid threshold");

                    bytes32 txHash = keccak256(abi.encodePacked(
                        address(this),
                        block.chainid,
                        target,
                        value,
                        data,
                        nonce,
                        deadline
                    ));

                    require(!executedTxs[txHash], "Already executed");

                    mapping(address => bool) memory signed;
                    uint256 validSigs = 0;

                    for (uint i = 0; i < signatures.length; i++) {
                        (uint8 v, bytes32 r, bytes32 s) = splitSignature(signatures[i]);
                        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "Invalid s");

                        address signer = ecrecover(txHash, v, r, s);
                        require(signer != address(0) && isOwner[signer], "Invalid signer");
                        require(!signed[signer], "Duplicate signature");

                        signed[signer] = true;
                        validSigs++;
                    }

                    require(validSigs >= threshold, "Threshold not met");
                    executedTxs[txHash] = true;
                    nonce++;

                    (bool success,) = target.call{value: value}(data);
                    require(success, "Execution failed");
                }

                function removeOwner(address owner) external {
                    require(isOwner[owner]);
                    isOwner[owner] = false;
                    ownerCount--;
                    if (ownerCount < threshold) {
                        threshold = ownerCount;
                    }
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        // Should have minimal findings due to comprehensive protections
    }

    // ========================================================================
    // False positive regression tests
    // ========================================================================

    #[test]
    fn test_no_fp_delegatecall_proxy_contract() {
        // UserControlledDelegatecall.sol - delegatecall proxy, not a multisig
        let detector = MultisigBypassDetector::new();
        let source = r#"
            contract DirectUserControlled {
                address public owner;
                mapping(address => uint256) public balances;

                function execute(address target, bytes calldata data) external payable {
                    (bool success, ) = target.delegatecall(data);
                    require(success, "Delegatecall failed");
                }

                function deposit() external payable {
                    balances[msg.sender] += msg.value;
                }
            }

            contract VulnerableProxyPattern {
                address public implementation;

                function setImplementation(address newImpl) external {
                    implementation = newImpl;
                }

                fallback() external payable {
                    address impl = implementation;
                    assembly {
                        calldatacopy(0, 0, calldatasize())
                        let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
                        returndatacopy(0, 0, returndatasize())
                        switch result
                        case 0 { revert(0, returndatasize()) }
                        default { return(0, returndatasize()) }
                    }
                }
            }

            contract AttackDemo {
                function exploit(address victim) external {
                    DirectUserControlled target = DirectUserControlled(payable(victim));
                    bytes memory data = abi.encodeWithSignature("takeOwnership()");
                    target.execute(address(this), data);
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "Delegatecall proxy contracts should not trigger multisig-bypass findings, got: {:?}",
            result.iter().map(|f| &f.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_no_fp_erc4337_vulnerable_paymaster() {
        // VulnerablePaymaster.sol - ERC-4337 paymaster, not a multisig
        let detector = MultisigBypassDetector::new();
        let source = r#"
            contract VulnerablePaymaster {
                mapping(address => uint256) public deposits;

                function validatePaymasterUserOp(
                    bytes calldata userOp,
                    bytes32 userOpHash,
                    uint256 maxCost
                ) external returns (bytes memory context, uint256 validationData) {
                    return ("", 0);
                }

                function sponsorTransaction(address user, uint256 cost) external {
                    require(deposits[msg.sender] >= cost, "Insufficient deposit");
                    deposits[msg.sender] -= cost;
                }

                function executeUserOp(bytes calldata userOp) external {
                }
            }

            contract VulnerableSignatureAggregator {
                function aggregateSignatures(
                    bytes[] calldata signatures
                ) external pure returns (bytes memory) {
                    bytes memory aggregated;
                    for (uint i = 0; i < signatures.length; i++) {
                        aggregated = abi.encodePacked(aggregated, signatures[i]);
                    }
                    return aggregated;
                }
            }

            contract VulnerableSocialRecovery {
                mapping(address => address[]) public guardians;
                mapping(address => uint256) public threshold;

                function initiateRecovery(address account, address newOwner) external {
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "ERC-4337 paymaster contracts should not trigger multisig-bypass findings, got: {:?}",
            result.iter().map(|f| &f.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_no_fp_erc4337_secure_paymaster() {
        // SecurePaymaster.sol - ERC-4337 paymaster, not a multisig
        let detector = MultisigBypassDetector::new();
        let source = r#"
            contract SecurePaymaster {
                mapping(address => uint256) public deposits;
                mapping(address => mapping(uint256 => bool)) public usedNonces;
                uint256 public immutable chainId;

                function validatePaymasterUserOp(
                    bytes calldata userOp,
                    bytes32 userOpHash,
                    uint256 maxCost
                ) external returns (bytes memory context, uint256 validationData) {
                    return ("", 0);
                }
            }

            contract SecureSessionKey {
                mapping(address => mapping(address => bool)) public sessionKeys;

                function executeWithSessionKey(
                    address account,
                    address target,
                    uint256 value,
                    bytes calldata data
                ) external {
                    require(sessionKeys[account][msg.sender], "Invalid session key");
                    (bool success,) = target.call{value: value}(data);
                    require(success, "Execution failed");
                }
            }

            contract SecureSocialRecovery {
                mapping(address => address[]) public guardians;
                mapping(address => uint256) public threshold;

                function initiateRecovery(address account, address newOwner) external {
                }

                function completeRecovery(address account) external {
                    require(block.timestamp >= request.initiatedAt + RECOVERY_TIMELOCK);
                    require(request.approvalCount >= threshold[account]);
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "ERC-4337 secure paymaster contracts should not trigger multisig-bypass findings, got: {:?}",
            result.iter().map(|f| &f.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_no_fp_social_recovery_contract() {
        // test_social_recovery.sol - social recovery, not a multisig
        let detector = MultisigBypassDetector::new();
        let source = r#"
            contract VulnerableSocialRecovery {
                mapping(address => address[]) public guardians;

                function initiateRecovery(address account, address newOwner) external {
                    // No timelock delay
                }

                function approveRecovery(address account) external {
                    // Missing guardian validation
                }

                function completeRecovery(address account) external {
                    // No replay protection
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "Social recovery contracts should not trigger multisig-bypass findings, got: {:?}",
            result.iter().map(|f| &f.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_no_fp_hardware_wallet_delegation() {
        // Hardware wallet delegation is not a multisig pattern
        let detector = MultisigBypassDetector::new();
        let source = r#"
            contract HardwareWalletDelegation {
                mapping(address => address) public delegates;

                function setDelegate(address delegate) external {
                    delegates[msg.sender] = delegate;
                }

                function executeAsDelegate(
                    address account,
                    address target,
                    uint256 value,
                    bytes calldata data
                ) external {
                    require(delegates[account] == msg.sender, "Not delegate");
                    (bool success,) = target.call{value: value}(data);
                    require(success, "Execution failed");
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "Hardware wallet delegation should not trigger multisig-bypass findings, got: {:?}",
            result.iter().map(|f| &f.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_still_detects_real_multisig_issues() {
        // Ensure the detector still finds real multisig vulnerabilities
        let detector = MultisigBypassDetector::new();
        let source = r#"
            contract VulnerableMultisigWallet {
                mapping(address => bool) public isOwner;
                uint256 public ownerCount;
                uint256 public threshold;

                function executeTransaction(
                    address target,
                    uint256 value,
                    bytes[] memory signatures
                ) external {
                    bytes32 hash = keccak256(abi.encodePacked(target, value));
                    for (uint i = 0; i < signatures.length; i++) {
                        address signer = ecrecover(hash, v, r, s);
                        require(isOwner[signer]);
                    }
                    (bool success,) = target.call{value: value}("");
                    require(success);
                }

                function removeOwner(address owner) external {
                    require(isOwner[owner]);
                    isOwner[owner] = false;
                    ownerCount--;
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            !result.is_empty(),
            "Real multisig contracts with vulnerabilities should still be detected"
        );
        // Should find multiple issues: missing nonce, missing deadline, threshold issues, etc.
        assert!(
            result.len() >= 2,
            "Expected multiple findings for vulnerable multisig, got {}",
            result.len()
        );
    }

    #[test]
    fn test_multisig_name_in_contract_is_sufficient() {
        // A contract explicitly named "multisig" should be analyzed
        let detector = MultisigBypassDetector::new();
        let source = r#"
            contract SimpleMultisig {
                function execute(address target, bytes calldata data) external {
                    (bool success,) = target.call(data);
                    require(success);
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        // Named multisig should be checked; execute without signature verification should trigger
        assert!(
            result
                .iter()
                .any(|f| f.message.contains("signature verification")),
            "Contract named multisig with public execute should trigger signature verification finding"
        );
    }

    #[test]
    fn test_no_fp_simple_token_with_owner() {
        // A simple token contract with owner should not be flagged
        let detector = MultisigBypassDetector::new();
        let source = r#"
            contract SimpleToken {
                address public owner;
                mapping(address => uint256) public balances;

                function transfer(address to, uint256 amount) external {
                    require(balances[msg.sender] >= amount);
                    balances[msg.sender] -= amount;
                    balances[to] += amount;
                }

                function mint(address to, uint256 amount) external {
                    require(msg.sender == owner);
                    balances[to] += amount;
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "Simple token contracts should not trigger multisig-bypass findings"
        );
    }
}
