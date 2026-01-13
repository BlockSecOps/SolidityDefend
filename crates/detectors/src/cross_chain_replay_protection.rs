use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for missing cross-chain replay protection
///
/// Detects signature verification that doesn't include chain ID, allowing
/// signatures to be replayed across different chains (mainnet, L2s, testnets).
///
/// Vulnerable pattern:
/// ```solidity
/// function executeWithSig(bytes calldata data, bytes calldata sig) external {
///     bytes32 hash = keccak256(data); // Missing chain ID!
///     address signer = ECDSA.recover(hash, sig);
///     // Same sig works on mainnet, Arbitrum, Optimism...
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
                "Detects signature verification without chain ID inclusion. Signatures \
                 without chain ID can be replayed across different EVM chains (mainnet, \
                 Arbitrum, Optimism, etc.), allowing unauthorized actions."
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

    /// Find signature verification without chain ID
    fn find_sig_without_chain_id(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for signature recovery
            if trimmed.contains("ecrecover") || trimmed.contains("ECDSA.recover") {
                // Check surrounding context for chain ID
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

            // Look for hash construction that appears to be for signing
            if trimmed.contains("keccak256(abi.encode")
                || trimmed.contains("keccak256(abi.encodePacked")
            {
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
        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        // Only check contracts using signatures
        if !self.uses_signatures(source) {
            return Ok(findings);
        }

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

        // Check for permit without domain
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
}
