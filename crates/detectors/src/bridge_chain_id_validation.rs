//! Chain-ID Validation Detector for Bridge Contracts

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::contract_classification;
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct ChainIdValidationDetector {
    base: BaseDetector,
}

impl ChainIdValidationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("missing-chainid-validation".to_string()),
                "Missing Chain-ID Validation".to_string(),
                "Detects missing chain-ID validation in bridge message processing".to_string(),
                vec![DetectorCategory::CrossChain],
                Severity::High,
            ),
        }
    }

    /// Determine whether this contract is primarily a bridge contract.
    ///
    /// Uses the shared contract classification as a baseline (requires >= 2
    /// bridge indicators), then excludes contracts whose primary purpose is
    /// clearly not bridging (governance, DAO, token, vault, etc.).
    fn is_bridge_contract(&self, ctx: &AnalysisContext) -> bool {
        // First gate: must pass shared bridge classification (>= 2 indicators)
        if !contract_classification::is_bridge_contract(ctx) {
            return false;
        }

        // Exclude contracts whose primary purpose is clearly NOT bridging.
        // A governance / DAO / token / vault contract that happens to mention
        // "bridge" or "cross-chain" should not be treated as a bridge.
        let contract_name_lower = ctx.contract.name.name.to_lowercase();
        let non_bridge_names = [
            "governance",
            "governor",
            "dao",
            "voting",
            "token",
            "vault",
            "staking",
            "lending",
            "pool",
            "factory",
            "registry",
            "paymaster",
        ];
        if non_bridge_names
            .iter()
            .any(|kw| contract_name_lower.contains(kw))
        {
            return false;
        }

        // Require the contract name itself to contain a bridge-related keyword,
        // OR require strong structural indicators from the source (bridge-specific
        // function patterns). This prevents contracts that only mention "bridge"
        // in comments from being classified as bridges.
        let has_bridge_name = contract_name_lower.contains("bridge")
            || contract_name_lower.contains("relay")
            || contract_name_lower.contains("messenger")
            || contract_name_lower.contains("crosschain");

        if has_bridge_name {
            return true;
        }

        // If the contract name is generic, require bridge-specific function patterns
        let source_lower = ctx.source_code.to_lowercase();
        source_lower.contains("function relaymessage")
            || source_lower.contains("function finalize")
            || source_lower.contains("function bridgetokens")
            || source_lower.contains("function sendmessage")
            || source_lower.contains("mapping(bytes32 => bool) public processedmessages")
            || (source_lower.contains("stateroot") && source_lower.contains("merkle"))
    }

    /// Check whether a function has an access-control modifier that indicates
    /// a trusted caller pattern (e.g. onlyOwner, onlyGuardian, onlyRelayer).
    /// Trusted callers do not need chain ID validation since the access
    /// control itself provides the security guarantee.
    fn has_access_control_modifier(&self, function: &ast::Function<'_>) -> bool {
        function.modifiers.iter().any(|m| {
            let name_lower = m.name.name.to_lowercase();
            name_lower.contains("only")
                || name_lower.contains("authorized")
                || name_lower.contains("admin")
                || name_lower.contains("owner")
                || name_lower.contains("relayer")
                || name_lower.contains("role")
                || name_lower.contains("trusted")
                || name_lower.contains("guardian")
                || name_lower.contains("operator")
        })
    }

    /// Check whether the contract already uses block.chainid in an EIP-712
    /// domain separator or similar construct. This demonstrates chain-ID
    /// awareness at the contract level, so individual functions that do not
    /// explicitly re-check chain ID are less likely to be vulnerable.
    fn has_eip712_chain_id(&self, ctx: &AnalysisContext) -> bool {
        let source_lower = ctx.source_code.to_lowercase();
        // EIP-712 domain separator typically includes block.chainid in
        // keccak256(abi.encode(..., block.chainid, ...))
        source_lower.contains("eip712domain") && source_lower.contains("block.chainid")
    }

    fn check_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<(Severity, String)> {
        let name = function.name.name.to_lowercase();

        if !name.contains("process") && !name.contains("execute") && !name.contains("receive") {
            return None;
        }

        // Skip bare receive()/fallback() functions -- these are ETH receivers,
        // not cross-chain message receivers
        if function.parameters.is_empty() && (name == "receive" || name == "fallback") {
            return None;
        }

        // Only check external/public functions (skip internal/private helpers)
        let is_external = matches!(
            function.visibility,
            ast::Visibility::External | ast::Visibility::Public
        );

        if !is_external {
            return None;
        }

        // Skip functions with access-control modifiers -- trusted callers
        // do not need chain ID validation
        if self.has_access_control_modifier(function) {
            return None;
        }

        // Skip if the contract already uses EIP-712 domain separator with
        // block.chainid -- demonstrates chain-ID awareness
        if self.has_eip712_chain_id(ctx) {
            return None;
        }

        // Extract only the function body source code to avoid matching comments
        let func_source = self.get_function_source(function, ctx).to_lowercase();

        // Skip functions with inline access control (require(msg.sender == ...))
        if self.has_inline_access_control(&func_source) {
            return None;
        }

        // Look for actual validation using block.chainid (more specific than just "chainid")
        let validates_chain = (func_source.contains("block.chainid")
            || func_source.contains("block.chain.id"))
            && (func_source.contains("==") || func_source.contains("require"));

        // Check if chainid is used in hash (parameters like sourceChainId or targetChainId)
        let in_hash = func_source.contains("keccak")
            && (func_source.contains("chainid") || func_source.contains("chain_id"));

        if !validates_chain && !in_hash {
            Some((
                Severity::High,
                "Add chain-ID validation: require(message.destinationChainId == block.chainid); \
                 OR include chain-ID in message hash"
                    .to_string(),
            ))
        } else if !validates_chain && in_hash {
            Some((
                Severity::Medium,
                "Add runtime validation: require(message.destinationChainId == block.chainid);"
                    .to_string(),
            ))
        } else {
            None
        }
    }

    /// Check whether the function body contains inline access control checks
    /// such as require(msg.sender == ...) or require(authorizedRelayers[msg.sender]).
    fn has_inline_access_control(&self, func_source: &str) -> bool {
        let src = func_source.to_lowercase();
        (src.contains("require") && src.contains("msg.sender"))
            || (src.contains("authorized") && src.contains("[msg.sender]"))
            || (src.contains("relayer") && src.contains("[msg.sender]"))
            || (src.contains("trusted") && src.contains("[msg.sender]"))
    }

    /// Get function source code with comments stripped to avoid false positives
    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start >= source_lines.len() || end >= source_lines.len() {
            return String::new();
        }

        // Strip single-line comments to avoid matching keywords in comments
        source_lines[start..=end]
            .iter()
            .map(|line| {
                // Remove everything after // to strip single-line comments
                if let Some(comment_pos) = line.find("//") {
                    &line[..comment_pos]
                } else {
                    line
                }
            })
            .collect::<Vec<&str>>()
            .join("\n")
    }
}

impl Default for ChainIdValidationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for ChainIdValidationDetector {
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

        if !self.is_bridge_contract(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            if let Some((severity, remediation)) = self.check_function(function, ctx) {
                let finding = self
                    .base
                    .create_finding_with_severity(
                        ctx,
                        format!("Missing chain-ID validation in '{}'", function.name.name),
                        function.name.location.start().line() as u32,
                        0,
                        20,
                        severity,
                    )
                    .with_cwe(20) // CWE-20: Improper Input Validation
                    .with_cwe(346) // CWE-346: Origin Validation Error
                    .with_fix_suggestion(remediation);

                findings.push(finding);
            }
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
        let detector = ChainIdValidationDetector::new();
        assert_eq!(detector.name(), "Missing Chain-ID Validation");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
        assert!(
            detector
                .categories()
                .contains(&DetectorCategory::CrossChain)
        );
    }
}
