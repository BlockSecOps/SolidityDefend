use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for missing cross-chain replay protection
///
/// Detects signature verification that doesn't include chain ID in contracts
/// that have cross-chain context (bridges, relayers, multichain deployments).
///
/// This detector requires cross-chain context to fire, avoiding false positives
/// on single-chain contracts like multisigs, games, and nonce-protected wallets.
///
/// Vulnerable pattern:
/// ```solidity
/// contract Bridge {
///     function relayMessage(bytes calldata data, bytes calldata sig) external {
///         bytes32 hash = keccak256(data); // Missing chain ID!
///         address signer = ECDSA.recover(hash, sig);
///         // Same sig works on mainnet, Arbitrum, Optimism...
///     }
/// }
/// ```
pub struct CrossChainReplayProtectionDetector {
    base: BaseDetector,
}

impl Default for CrossChainReplayProtectionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossChainReplayProtectionDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("cross-chain-replay-protection"),
                "Missing Cross-Chain Replay Protection".to_string(),
                "Detects signature verification without chain ID inclusion in cross-chain \
                 contracts. Signatures without chain ID can be replayed across different \
                 EVM chains (mainnet, Arbitrum, Optimism, etc.), allowing unauthorized actions."
                    .to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    /// Check if contract uses signature verification
    fn uses_signatures(&self, source: &str) -> bool {
        source.contains("ecrecover")
            || source.contains("ECDSA.recover")
            || source.contains("SignatureChecker")
            || source.contains("isValidSignature")
            || source.contains("_hashTypedDataV4")
    }

    /// Check if the contract has cross-chain context, indicating that
    /// cross-chain replay is a relevant concern. Without cross-chain context,
    /// signature replay is a same-chain issue handled by nonces, not chain IDs.
    fn has_cross_chain_context(&self, source: &str) -> bool {
        let lower = source.to_lowercase();

        // Contract/interface name indicators
        let name_indicators = [
            "bridge",
            "relay",
            "crosschain",
            "cross_chain",
            "cross-chain",
            "multichain",
            "multi_chain",
            "omnichain",
            "interchain",
            "layerzero",
            "wormhole",
            "ccip",
            "hyperlane",
            "axelar",
        ];
        for indicator in &name_indicators {
            if lower.contains(indicator) {
                return true;
            }
        }

        // Cross-chain messaging patterns
        let messaging_patterns = [
            "lzreceive",
            "lzendpoint",
            "ccipsend",
            "ccipreceive",
            "any2evmmessage",
            "receivewormholemessages",
            "trustedremote",
            "sourcechainid",
            "sourcechainselector",
            "destinationchain",
            "targetchainid",
            "targetchain",
            "fromchain",
            "tochain",
            "sendmessage",
            "receivemessage",
        ];
        for pattern in &messaging_patterns {
            if lower.contains(pattern) {
                return true;
            }
        }

        // Chain-specific state variables and parameters
        let chain_state_patterns = [
            "supportedchains",
            "allowedchains",
            "chainidmapping",
            "isvalidchain",
            "ischainsupported",
        ];
        for pattern in &chain_state_patterns {
            if lower.contains(pattern) {
                return true;
            }
        }

        // L2-specific patterns
        if lower.contains("l1") && lower.contains("l2") {
            return true;
        }

        // Multiple chain references (e.g., "arbitrum", "optimism", "polygon" in comments)
        let chain_names = [
            "arbitrum",
            "optimism",
            "polygon",
            "avalanche",
            "bsc",
            "fantom",
            "base chain",
            "zksync",
            "linea",
            "scroll",
        ];
        let chain_mentions = chain_names.iter().filter(|c| lower.contains(**c)).count();
        if chain_mentions >= 2 {
            return true;
        }

        false
    }

    /// Check if the contract has contract-wide chain ID protection
    /// (e.g., DOMAIN_SEPARATOR defined in constructor with chainId).
    /// This looks at the entire file, not just a local window.
    fn has_contract_wide_chain_protection(&self, source: &str) -> bool {
        // EIP-712 domain separator with chain ID anywhere in the contract
        if source.contains("DOMAIN_SEPARATOR") && source.contains("chainid") {
            return true;
        }
        if source.contains("DOMAIN_SEPARATOR") && source.contains("chainId") {
            return true;
        }

        // EIP-712 typed data hashing (OpenZeppelin pattern)
        if source.contains("_hashTypedDataV4") || source.contains("_domainSeparatorV4") {
            return true;
        }

        // Explicit EIP-712 domain type with chainId
        if source.contains("EIP712Domain") && source.contains("chainId") {
            return true;
        }

        // EIP712 inheritance from OpenZeppelin
        if source.contains("is EIP712") || source.contains("is ERC20Permit") {
            return true;
        }

        false
    }

    /// Check if a function is a view/pure helper or internal/private utility.
    /// These are not entry points and should not be flagged individually.
    fn is_non_entry_function(&self, lines: &[&str], line_num: usize) -> bool {
        // Walk backwards to find the function declaration
        for i in (0..=line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                let lower = trimmed.to_lowercase();
                // Skip view/pure functions
                if lower.contains(" view") || lower.contains(" pure") {
                    return true;
                }
                // Skip internal/private functions (helper utilities)
                if lower.contains(" internal") || lower.contains(" private") {
                    return true;
                }
                // Found the function declaration, stop looking
                return false;
            }
            // If we hit a contract declaration, stop
            if trimmed.contains("contract ") || trimmed.contains("library ") {
                return false;
            }
        }
        false
    }

    /// Check if the contract has nonce-based replay protection, which
    /// significantly reduces cross-chain replay risk for single-chain contracts.
    /// Currently used by tests; may be integrated into detect() for confidence
    /// adjustment in a future iteration.
    #[allow(dead_code)]
    fn has_nonce_replay_protection(&self, source: &str) -> bool {
        let has_nonce_mapping = source.contains("mapping") && source.contains("nonce");
        let has_nonce_increment = source.contains("nonce++")
            || source.contains("nonces[") && (source.contains("++") || source.contains("+= 1"));
        let has_nonce_check = source.contains("nonce ==") || source.contains("nonces[");

        // Need at least a nonce mapping/tracking AND either increment or check
        has_nonce_mapping && (has_nonce_increment || has_nonce_check)
    }

    /// Find signature verification without chain ID
    fn find_sig_without_chain_id(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Skip comments
            if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*") {
                continue;
            }

            // Look for signature recovery
            if trimmed.contains("ecrecover") || trimmed.contains("ECDSA.recover") {
                // Skip view/pure/internal/private functions
                if self.is_non_entry_function(&lines, line_num) {
                    continue;
                }

                // Check surrounding context for chain ID protection
                let context_start = if line_num > 30 { line_num - 30 } else { 0 };
                let context_end = std::cmp::min(line_num + 10, lines.len());
                let context: String = lines[context_start..context_end].join("\n");

                let has_chain_protection =
                    // Check for chain.id
                    context.contains("block.chainid")
                    || context.contains("chainId")
                    || context.contains("chain_id")
                    // Check for EIP-712 domain separator
                    || context.contains("DOMAIN_SEPARATOR")
                    || context.contains("domainSeparator")
                    || context.contains("_domainSeparatorV4")
                    || context.contains("_hashTypedDataV4")
                    // Check for typed data
                    || context.contains("EIP712")
                    || context.contains("eip712")
                    // Check for manual chain ID in hash
                    || (context.contains("keccak256") && context.contains("chainid"));

                if !has_chain_protection {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find hash construction without chain ID
    fn find_hash_without_chain_id(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Skip comments
            if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*") {
                continue;
            }

            // Look for hash construction that appears to be for signing
            if trimmed.contains("keccak256(abi.encode")
                || trimmed.contains("keccak256(abi.encodePacked")
            {
                // Skip view/pure/internal/private functions
                if self.is_non_entry_function(&lines, line_num) {
                    continue;
                }

                // Check if this hash is used for signature
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                if func_body.contains("ecrecover")
                    || func_body.contains("ECDSA.recover")
                    || func_body.contains("isValidSignature")
                {
                    // Check for chain ID in hash
                    let hash_line = trimmed;
                    let has_chain_id = hash_line.contains("chainid")
                        || hash_line.contains("block.chainid")
                        || hash_line.contains("chainId");

                    // Also check if using domain separator
                    let uses_domain = func_body.contains("DOMAIN_SEPARATOR")
                        || func_body.contains("domainSeparator");

                    if !has_chain_id && !uses_domain {
                        let func_name = self.find_containing_function(&lines, line_num);
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Check for permit without proper domain
    fn find_permit_without_domain(&self, source: &str) -> Option<u32> {
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for permit function
            if trimmed.contains("function permit") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for proper EIP-2612 implementation
                let has_domain = func_body.contains("DOMAIN_SEPARATOR")
                    || func_body.contains("_domainSeparatorV4")
                    || func_body.contains("domainSeparator");

                if !has_domain {
                    return Some(line_num as u32 + 1);
                }
            }
        }

        None
    }

    /// Find containing function name
    fn find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                if let Some(func_start) = trimmed.find("function ") {
                    let after_func = &trimmed[func_start + 9..];
                    if let Some(paren_pos) = after_func.find('(') {
                        return after_func[..paren_pos].trim().to_string();
                    }
                }
            }
        }
        "unknown".to_string()
    }

    /// Find the end of a function
    fn find_function_end(&self, lines: &[&str], start: usize) -> usize {
        let mut depth = 0;
        let mut started = false;

        for (i, line) in lines.iter().enumerate().skip(start) {
            for c in line.chars() {
                match c {
                    '{' => {
                        depth += 1;
                        started = true;
                    }
                    '}' => {
                        depth -= 1;
                        if started && depth == 0 {
                            return i + 1;
                        }
                    }
                    _ => {}
                }
            }
        }
        lines.len()
    }

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for CrossChainReplayProtectionDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
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

        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        // Only check contracts using signatures
        if !self.uses_signatures(source) {
            return Ok(findings);
        }

        // Skip contracts that already have contract-wide chain ID protection
        // (e.g., DOMAIN_SEPARATOR with chainId in constructor, EIP-712 inheritance)
        if self.has_contract_wide_chain_protection(source) {
            return Ok(findings);
        }

        // Require cross-chain context to avoid flagging single-chain contracts.
        // Contracts without cross-chain indicators (bridges, relayers, multichain
        // messaging) are not vulnerable to cross-chain replay in practice -- their
        // replay risk is same-chain and is mitigated by nonces.
        if !self.has_cross_chain_context(source) {
            return Ok(findings);
        }

        // If the contract has robust nonce-based replay protection and no
        // explicit cross-chain messaging, the cross-chain replay risk is
        // significantly reduced. Downgrade to informational only if we still
        // want to report -- for now, skip entirely since the cross-chain
        // context check above already gates relevance.

        // Check for signature recovery without chain ID
        let sig_issues = self.find_sig_without_chain_id(source);
        for (line, func_name) in &sig_issues {
            let message = format!(
                "Function '{}' in contract '{}' verifies signatures without chain ID protection. \
                 Signatures can be replayed across different EVM chains (mainnet, Arbitrum, \
                 Optimism, Polygon, etc.) allowing unauthorized cross-chain actions.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, *line, 1, 30)
                .with_cwe(294) // CWE-294: Authentication Bypass by Capture-replay
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Use EIP-712 typed data with chain ID in domain separator:\n\n\
                     bytes32 public DOMAIN_SEPARATOR;\n\n\
                     constructor() {\n\
                         DOMAIN_SEPARATOR = keccak256(abi.encode(\n\
                             keccak256(\"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)\"),\n\
                             keccak256(bytes(name)),\n\
                             keccak256(bytes(version)),\n\
                             block.chainid,\n\
                             address(this)\n\
                         ));\n\
                     }\n\n\
                     function verify(bytes32 structHash, bytes calldata signature) internal view {\n\
                         bytes32 digest = keccak256(abi.encodePacked(\n\
                             \"\\x19\\x01\",\n\
                             DOMAIN_SEPARATOR,\n\
                             structHash\n\
                         ));\n\
                         address signer = ECDSA.recover(digest, signature);\n\
                         // verify signer\n\
                     }"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Check for hash construction without chain ID
        let hash_issues = self.find_hash_without_chain_id(source);
        for (line, func_name) in hash_issues {
            // Skip if already reported
            if sig_issues.iter().any(|(l, _)| *l == line) {
                continue;
            }

            let message = format!(
                "Function '{}' in contract '{}' constructs hash for signing without chain ID. \
                 The resulting signature can be replayed on other chains.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 30)
                .with_cwe(294) // CWE-294: Authentication Bypass by Capture-replay
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Include chain ID in the signed data:\n\n\
                     bytes32 hash = keccak256(abi.encode(\n\
                         block.chainid,  // Chain ID\n\
                         address(this),  // Contract address\n\
                         nonce,          // Nonce for replay protection\n\
                         data\n\
                     ));"
                    .to_string(),
                );

            findings.push(finding);
        }

        // Check for permit without domain (only in cross-chain context)
        if let Some(line) = self.find_permit_without_domain(source) {
            let message = format!(
                "Contract '{}' implements permit() without proper EIP-2612 domain separator. \
                 Permit signatures may be replayable across chains.",
                contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 30)
                .with_cwe(294) // CWE-294: Authentication Bypass by Capture-replay
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Use OpenZeppelin's ERC20Permit which includes proper domain separator."
                        .to_string(),
                );

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

    #[test]
    fn test_detector_properties() {
        let detector = CrossChainReplayProtectionDetector::new();
        assert_eq!(detector.name(), "Missing Cross-Chain Replay Protection");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_uses_signatures() {
        let detector = CrossChainReplayProtectionDetector::new();

        assert!(detector.uses_signatures("address signer = ecrecover(hash, v, r, s);"));
        assert!(detector.uses_signatures("address signer = ECDSA.recover(hash, sig);"));
        assert!(!detector.uses_signatures("contract Simple {}"));
    }

    #[test]
    fn test_missing_chain_id() {
        let detector = CrossChainReplayProtectionDetector::new();

        let vulnerable = r#"
            contract Vulnerable {
                function execute(bytes calldata data, bytes calldata sig) external {
                    bytes32 hash = keccak256(data);
                    address signer = ECDSA.recover(hash, sig);
                    require(signer == owner);
                }
            }
        "#;
        let findings = detector.find_sig_without_chain_id(vulnerable);
        assert!(!findings.is_empty());

        let safe = r#"
            contract Safe {
                bytes32 public DOMAIN_SEPARATOR;

                function execute(bytes calldata data, bytes calldata sig) external {
                    bytes32 structHash = keccak256(data);
                    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
                    address signer = ECDSA.recover(digest, sig);
                    require(signer == owner);
                }
            }
        "#;
        let findings = detector.find_sig_without_chain_id(safe);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_eip712_detection() {
        let detector = CrossChainReplayProtectionDetector::new();

        let safe = r#"
            contract Safe {
                function execute(bytes calldata sig) external {
                    bytes32 digest = _hashTypedDataV4(structHash);
                    address signer = ECDSA.recover(digest, sig);
                }
            }
        "#;
        let findings = detector.find_sig_without_chain_id(safe);
        assert!(findings.is_empty());
    }

    // --- New tests for false positive reduction ---

    #[test]
    fn test_cross_chain_context_detection() {
        let detector = CrossChainReplayProtectionDetector::new();

        // Should detect cross-chain context
        assert!(detector.has_cross_chain_context("contract BridgeRelay {"));
        assert!(detector.has_cross_chain_context("// Cross-chain messaging bridge"));
        assert!(detector.has_cross_chain_context("function lzReceive(uint16 srcChainId"));
        assert!(detector.has_cross_chain_context("ILayerZeroEndpoint public lzEndpoint;"));
        assert!(detector.has_cross_chain_context("function ccipReceive("));
        assert!(detector.has_cross_chain_context("mapping(uint256 => bool) supportedChains;"));
        assert!(detector.has_cross_chain_context("// Works on Arbitrum and Optimism"));

        // Should NOT detect cross-chain context for single-chain contracts
        assert!(!detector.has_cross_chain_context("contract SimpleMultiSig {"));
        assert!(!detector.has_cross_chain_context(
            "contract SecureNonceIncrement { mapping(address => uint256) public nonces; }"
        ));
        assert!(!detector.has_cross_chain_context("contract ERC20Token { function transfer"));
        assert!(!detector.has_cross_chain_context("contract Vault { function deposit"));
        assert!(!detector.has_cross_chain_context("contract Game { function playGame"));
    }

    #[test]
    fn test_contract_wide_chain_protection() {
        let detector = CrossChainReplayProtectionDetector::new();

        // DOMAIN_SEPARATOR with chainId in constructor
        let protected = r#"
            contract Protected {
                bytes32 public DOMAIN_SEPARATOR;
                constructor() {
                    DOMAIN_SEPARATOR = keccak256(abi.encode(
                        DOMAIN_TYPEHASH,
                        keccak256(bytes("Test")),
                        block.chainid,
                        address(this)
                    ));
                }
                function execute(uint8 v, bytes32 r, bytes32 s) external {
                    address signer = ecrecover(hash, v, r, s);
                }
            }
        "#;
        assert!(detector.has_contract_wide_chain_protection(protected));

        // EIP712 inheritance
        assert!(detector.has_contract_wide_chain_protection("contract MyToken is EIP712, ERC20 {"));
        assert!(detector.has_contract_wide_chain_protection("contract MyToken is ERC20Permit {"));

        // No chain protection
        assert!(
            !detector.has_contract_wide_chain_protection(
                "contract SimpleWallet { function execute() {} }"
            )
        );
    }

    #[test]
    fn test_nonce_replay_protection_detection() {
        let detector = CrossChainReplayProtectionDetector::new();

        let with_nonces = r#"
            mapping(address => uint256) public nonces;
            function execute(uint8 v, bytes32 r, bytes32 s) external {
                uint256 nonce = nonces[msg.sender]++;
            }
        "#;
        assert!(detector.has_nonce_replay_protection(with_nonces));

        let without_nonces = r#"
            function execute(uint8 v, bytes32 r, bytes32 s) external {
                address signer = ecrecover(hash, v, r, s);
            }
        "#;
        assert!(!detector.has_nonce_replay_protection(without_nonces));
    }

    #[test]
    fn test_skip_view_pure_internal_functions() {
        let detector = CrossChainReplayProtectionDetector::new();

        let source = r#"
            contract Bridge {
                function _recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
                    return ecrecover(hash, v, r, s);
                }
                function verifyMessage(bytes32 hash, bytes memory sig) public view returns (bool) {
                    address signer = ecrecover(hash, v, r, s);
                    return signer == owner;
                }
            }
        "#;
        // find_sig_without_chain_id should skip internal/pure/view functions
        let findings = detector.find_sig_without_chain_id(source);
        assert!(
            findings.is_empty(),
            "Should skip view/pure/internal functions, got {:?}",
            findings
        );
    }

    #[test]
    fn test_single_chain_multisig_not_flagged() {
        let detector = CrossChainReplayProtectionDetector::new();

        // A simple multisig wallet without cross-chain context should not be flagged
        let multisig = r#"
            contract MultiSigWallet {
                address[] public owners;
                uint256 public requiredSignatures;

                function executeWithMultiSig(
                    address to, uint256 amount, bytes32 txHash,
                    uint8[] memory v, bytes32[] memory r, bytes32[] memory s
                ) external {
                    address signer = ecrecover(txHash, v[0], r[0], s[0]);
                    require(signer != address(0));
                }
            }
        "#;
        assert!(!detector.has_cross_chain_context(multisig));
    }

    #[test]
    fn test_bridge_contract_flagged() {
        let detector = CrossChainReplayProtectionDetector::new();

        // A bridge contract with signature verification but no chain ID should be flagged
        let bridge = r#"
            contract TokenBridge {
                function relayTransfer(
                    address to, uint256 amount,
                    uint8 v, bytes32 r, bytes32 s
                ) external {
                    bytes32 hash = keccak256(abi.encode(to, amount));
                    address signer = ecrecover(hash, v, r, s);
                    require(signer == relayer);
                }
            }
        "#;
        assert!(detector.has_cross_chain_context(bridge));
        assert!(!detector.has_contract_wide_chain_protection(bridge));
        let findings = detector.find_sig_without_chain_id(bridge);
        assert!(
            !findings.is_empty(),
            "Bridge without chain ID should be flagged"
        );
    }

    #[test]
    fn test_permit_without_domain_needs_cross_chain_context() {
        let detector = CrossChainReplayProtectionDetector::new();

        // Permit without domain separator in a non-cross-chain contract
        // should NOT be flagged (no cross-chain context)
        let token = r#"
            contract SimpleToken {
                function permit(address owner, address spender, uint256 value,
                    uint8 v, bytes32 r, bytes32 s) external {
                    bytes32 hash = keccak256(abi.encode(owner, spender, value));
                    address signer = ecrecover(hash, v, r, s);
                }
            }
        "#;
        assert!(!detector.has_cross_chain_context(token));
    }

    #[test]
    fn test_secure_eip712_contract_not_flagged() {
        let detector = CrossChainReplayProtectionDetector::new();

        // A contract with EIP-712 domain separator including chainId
        // should NOT be flagged even if it has cross-chain context
        let contract = r#"
            contract SecureBridge {
                bytes32 public DOMAIN_SEPARATOR;
                constructor() {
                    DOMAIN_SEPARATOR = keccak256(abi.encode(
                        DOMAIN_TYPEHASH,
                        keccak256(bytes("SecureBridge")),
                        keccak256(bytes("1")),
                        block.chainid,
                        address(this)
                    ));
                }
                function relay(bytes memory data, uint8 v, bytes32 r, bytes32 s) external {
                    bytes32 hash = keccak256(data);
                    address signer = ecrecover(hash, v, r, s);
                }
            }
        "#;
        assert!(detector.has_cross_chain_context(contract));
        assert!(detector.has_contract_wide_chain_protection(contract));
    }
}
