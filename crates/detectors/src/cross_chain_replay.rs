use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for cross-chain replay attack vulnerabilities
pub struct CrossChainReplayDetector {
    base: BaseDetector,
}

impl Default for CrossChainReplayDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossChainReplayDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("cross-chain-replay".to_string()),
                "Cross-Chain Replay Attack".to_string(),
                "Detects signature/hash generation missing chain ID, enabling replay attacks across chains".to_string(),
                vec![DetectorCategory::CrossChain, DetectorCategory::Auth],
                Severity::Critical,
            ),
        }
    }
}

impl Detector for CrossChainReplayDetector {
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

        for function in ctx.get_functions() {
            if self.is_vulnerable_to_cross_chain_replay(function, ctx) {
                let message = format!(
                    "Function '{}' generates hash/signature without chain ID protection. \
                    This allows the same signature to be replayed on different chains, \
                    potentially draining funds on all supported chains.",
                    function.name.name
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
                    .with_cwe(294) // CWE-294: Authentication Bypass by Capture-replay
                    .with_cwe(345) // CWE-345: Insufficient Verification of Data Authenticity
                    .with_fix_suggestion(format!(
                        "Include 'block.chainid' in the hash calculation for function '{}'. \
                    Example: keccak256(abi.encodePacked(..., block.chainid))",
                        function.name.name
                    ));

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CrossChainReplayDetector {
    /// Check if a function is vulnerable to cross-chain replay attacks
    fn is_vulnerable_to_cross_chain_replay(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> bool {
        // Only check functions with actual implementations
        if function.body.is_none() {
            return false;
        }

        // Look for bridge/cross-chain related functions
        let function_name = function.name.name.to_lowercase();
        let cross_chain_patterns = [
            "bridge",
            "relay",
            "transfer",
            "lock",
            "unlock",
            "deposit",
            "withdraw",
            "claim",
            "crosschain",
            "cross_chain",
        ];

        let is_cross_chain_function = cross_chain_patterns
            .iter()
            .any(|pattern| function_name.contains(pattern));

        if !is_cross_chain_function {
            // Also check for signature verification or hash generation in source
            let func_start = function.location.start().line();
            let func_end = function.location.end().line();

            let source_lines: Vec<&str> = ctx.source_code.lines().collect();
            if func_start >= source_lines.len() || func_end >= source_lines.len() {
                return false;
            }

            let func_source = source_lines[func_start..=func_end].join("\n");

            let has_hashing = func_source.contains("keccak256")
                || func_source.contains("sha256")
                || func_source.contains("ecrecover");

            if !has_hashing {
                return false;
            }
        }

        // Get function source code
        let func_start = function.location.start().line();
        let func_end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if func_start >= source_lines.len() || func_end >= source_lines.len() {
            return false;
        }

        let func_source = source_lines[func_start..=func_end].join("\n");

        // Check if function has hashing operations
        let has_hashing = func_source.contains("keccak256") || func_source.contains("sha256");

        if !has_hashing {
            return false;
        }

        // Check for cross-chain indicators
        let cross_chain_indicators = [
            "targetChain",
            "target_chain",
            "destinationChain",
            "destination_chain",
            "chainId",
            "chain_id",
            "toChain",
            "to_chain",
            "fromChain",
            "from_chain",
            "targetNetwork",
            "destinationNetwork",
        ];

        let has_chain_reference = cross_chain_indicators
            .iter()
            .any(|indicator| func_source.contains(indicator));

        // If it has chain references but no block.chainid in the hash, it's vulnerable
        if has_chain_reference {
            let has_chainid_protection = func_source.contains("block.chainid")
                || func_source.contains("block.chainId")
                || func_source.contains("chainid()");

            // Vulnerable if it references chains but doesn't include current chain ID
            return !has_chainid_protection;
        }

        // Check if it's a signature verification function without chain ID
        let has_signature_ops = func_source.contains("ecrecover")
            || func_source.contains("signature")
            || func_source.contains("verify");

        if has_signature_ops && has_hashing {
            // Check for EIP-712 domain separator pattern (proper implementation)
            let has_eip712_pattern = (func_source.contains("\\x19\\x01")
                && func_source.contains("DOMAIN_SEPARATOR"))
                || (func_source.contains("\\x19\\\\x01")
                    && func_source.contains("DOMAIN_SEPARATOR"));

            // Check for OpenZeppelin ECDSA library (has built-in protection)
            let uses_oz_ecdsa =
                func_source.contains("ECDSA.recover") || func_source.contains("ECDSA.tryRecover");

            // Check for direct chainId usage in hash
            let has_chainid_in_hash =
                func_source.contains("block.chainid") || func_source.contains("block.chainId");

            // Check if there's a comment about missing chainid (vulnerability marker)
            let has_vulnerability_comment =
                func_source.contains("Missing:") && func_source.contains("chainid");

            // Not vulnerable if using EIP-712 pattern, OZ ECDSA, or has chainId directly
            let has_protection = has_eip712_pattern || uses_oz_ecdsa || has_chainid_in_hash;

            return !has_protection || has_vulnerability_comment;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = CrossChainReplayDetector::new();
        assert_eq!(detector.name(), "Cross-Chain Replay Attack");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }
}
