use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for cross-chain replay attack vulnerabilities.
///
/// This detector requires cross-chain context at the contract level before
/// flagging any functions. Single-chain contracts (multisigs, vaults, AMMs,
/// basic tokens, staking) are not at risk of cross-chain replay and are
/// skipped to avoid false positives.
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

    /// Check if the contract has cross-chain context, indicating that
    /// cross-chain replay is a relevant concern. Without cross-chain context,
    /// signature replay is a same-chain issue handled by nonces, not chain IDs.
    fn has_cross_chain_context(source: &str) -> bool {
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
        ];
        for pattern in &messaging_patterns {
            if lower.contains(pattern) {
                return true;
            }
        }

        // Chain-specific state variables
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

        // L1/L2 patterns (both must appear)
        if lower.contains("l1") && lower.contains("l2") {
            return true;
        }

        // Multiple chain name references in comments/code
        let chain_names = [
            "arbitrum",
            "optimism",
            "polygon",
            "avalanche",
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
    /// (e.g., DOMAIN_SEPARATOR defined with chainId, EIP-712 inheritance).
    fn has_contract_wide_chain_protection(source: &str) -> bool {
        // EIP-712 domain separator with chain ID anywhere in the contract
        if source.contains("DOMAIN_SEPARATOR")
            && (source.contains("chainid") || source.contains("chainId"))
        {
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
        let source = &ctx.source_code;

        // Gate 1: Require cross-chain context at the contract level.
        // Single-chain contracts (multisigs, vaults, AMMs, tokens, staking)
        // are not vulnerable to cross-chain replay.
        if !Self::has_cross_chain_context(source) {
            return Ok(findings);
        }

        // Gate 2: Skip contracts that already have contract-wide chain ID
        // protection (EIP-712 domain separator with chainId, OZ EIP712
        // inheritance, etc.).
        if Self::has_contract_wide_chain_protection(source) {
            return Ok(findings);
        }

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
    /// Check if a function is vulnerable to cross-chain replay attacks.
    ///
    /// At this point, contract-level gates have already confirmed cross-chain
    /// context and the absence of contract-wide chain ID protection.
    fn is_vulnerable_to_cross_chain_replay(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> bool {
        // Only check functions with actual implementations
        if function.body.is_none() {
            return false;
        }

        // Skip view/pure functions -- they cannot change state and are not
        // entry points for replay attacks.
        if function.mutability == ast::StateMutability::View
            || function.mutability == ast::StateMutability::Pure
        {
            return false;
        }

        // Skip internal/private functions -- they are not externally callable
        // entry points.
        if function.visibility == ast::Visibility::Internal
            || function.visibility == ast::Visibility::Private
        {
            return false;
        }

        // Get function source code
        let func_start = function.location.start().line();
        let func_end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if func_start >= source_lines.len() || func_end >= source_lines.len() {
            return false;
        }

        let func_source = source_lines[func_start..=func_end].join("\n");

        // Require hashing operations in the function body
        let has_hashing = func_source.contains("keccak256") || func_source.contains("sha256");
        if !has_hashing {
            return false;
        }

        // Check for function-level chain ID protection
        let has_chainid_protection = func_source.contains("block.chainid")
            || func_source.contains("block.chainId")
            || func_source.contains("chainid()");

        if has_chainid_protection {
            return false;
        }

        // Check for EIP-712 domain separator usage within the function
        let has_domain_separator = func_source.contains("DOMAIN_SEPARATOR")
            || func_source.contains("domainSeparator")
            || func_source.contains("_domainSeparatorV4")
            || func_source.contains("_hashTypedDataV4")
            || func_source.contains("EIP712");

        if has_domain_separator {
            return false;
        }

        // Check for OpenZeppelin ECDSA library (includes protections)
        if func_source.contains("ECDSA.recover") || func_source.contains("ECDSA.tryRecover") {
            return false;
        }

        // Now check whether this function actually does signature
        // verification or produces hashes for signing. We need either
        // cross-chain indicators OR signature recovery in the function.
        let has_cross_chain_indicators = [
            "targetChain",
            "target_chain",
            "destinationChain",
            "destination_chain",
            "toChain",
            "to_chain",
            "fromChain",
            "from_chain",
            "targetNetwork",
            "destinationNetwork",
        ]
        .iter()
        .any(|indicator| func_source.contains(indicator));

        if has_cross_chain_indicators {
            // Has cross-chain parameters in the function but no chain ID
            // protection -- vulnerable.
            return true;
        }

        // Check for signature recovery without chain ID
        let has_ecrecover =
            func_source.contains("ecrecover") || func_source.contains("SignatureChecker");

        if has_ecrecover {
            // Has signature verification in a cross-chain contract without
            // chain ID protection -- vulnerable.
            return true;
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

    // --- Contract-level context gating tests ---

    #[test]
    fn test_cross_chain_context_detection() {
        // Should detect cross-chain context
        assert!(CrossChainReplayDetector::has_cross_chain_context(
            "contract BridgeRelay {"
        ));
        assert!(CrossChainReplayDetector::has_cross_chain_context(
            "// Cross-chain messaging bridge"
        ));
        assert!(CrossChainReplayDetector::has_cross_chain_context(
            "function lzReceive(uint16 srcChainId"
        ));
        assert!(CrossChainReplayDetector::has_cross_chain_context(
            "ILayerZeroEndpoint public lzEndpoint;"
        ));
        assert!(CrossChainReplayDetector::has_cross_chain_context(
            "function ccipReceive("
        ));
        assert!(CrossChainReplayDetector::has_cross_chain_context(
            "mapping(uint256 => bool) supportedChains;"
        ));
        assert!(CrossChainReplayDetector::has_cross_chain_context(
            "// Works on Arbitrum and Optimism"
        ));

        // Should NOT detect cross-chain context for single-chain contracts
        assert!(!CrossChainReplayDetector::has_cross_chain_context(
            "contract SimpleMultiSig {"
        ));
        assert!(!CrossChainReplayDetector::has_cross_chain_context(
            "contract ERC20Token { function transfer"
        ));
        assert!(!CrossChainReplayDetector::has_cross_chain_context(
            "contract Vault { function deposit"
        ));
        assert!(!CrossChainReplayDetector::has_cross_chain_context(
            "contract Game { function playGame"
        ));
        assert!(!CrossChainReplayDetector::has_cross_chain_context(
            "contract StakingPool { function stake"
        ));
    }

    #[test]
    fn test_contract_wide_chain_protection() {
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
            }
        "#;
        assert!(CrossChainReplayDetector::has_contract_wide_chain_protection(protected));

        // EIP712 inheritance
        assert!(
            CrossChainReplayDetector::has_contract_wide_chain_protection(
                "contract MyToken is EIP712, ERC20 {"
            )
        );
        assert!(
            CrossChainReplayDetector::has_contract_wide_chain_protection(
                "contract MyToken is ERC20Permit {"
            )
        );
        assert!(
            CrossChainReplayDetector::has_contract_wide_chain_protection(
                "bytes32 digest = _hashTypedDataV4(structHash);"
            )
        );

        // No chain protection
        assert!(
            !CrossChainReplayDetector::has_contract_wide_chain_protection(
                "contract SimpleWallet { function execute() {} }"
            )
        );
    }

    #[test]
    fn test_single_chain_multisig_not_flagged() {
        // A multisig wallet without cross-chain context should not trigger
        let source = "contract MultiSigWallet { address[] public owners; }";
        assert!(!CrossChainReplayDetector::has_cross_chain_context(source));
    }

    #[test]
    fn test_single_chain_vault_not_flagged() {
        let source = "contract ERC4626Vault { function deposit(uint256 assets) external {} }";
        assert!(!CrossChainReplayDetector::has_cross_chain_context(source));
    }

    #[test]
    fn test_amm_not_flagged() {
        let source = "contract UniswapV2Pair { function swap(uint amount0Out) external {} }";
        assert!(!CrossChainReplayDetector::has_cross_chain_context(source));
    }

    #[test]
    fn test_bridge_with_domain_separator_not_flagged() {
        // A bridge that already has EIP-712 protection should be skipped
        let source = r#"
            contract SecureBridge {
                bytes32 public DOMAIN_SEPARATOR;
                constructor() {
                    DOMAIN_SEPARATOR = keccak256(abi.encode(
                        DOMAIN_TYPEHASH, keccak256(bytes("Bridge")),
                        block.chainid, address(this)
                    ));
                }
            }
        "#;
        assert!(CrossChainReplayDetector::has_cross_chain_context(source));
        assert!(CrossChainReplayDetector::has_contract_wide_chain_protection(source));
    }

    #[test]
    fn test_create2_factory_not_flagged() {
        // CREATE2 factories use keccak256 for address computation, not signatures
        let source = "contract MetamorphicFactory { function deploy(bytes32 salt) external {} }";
        assert!(!CrossChainReplayDetector::has_cross_chain_context(source));
    }
}
