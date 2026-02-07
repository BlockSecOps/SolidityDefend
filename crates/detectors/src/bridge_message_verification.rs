//! Bridge Message Verification Detector

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::contract_classification;
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct MessageVerificationDetector {
    base: BaseDetector,
}

impl MessageVerificationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("bridge-message-verification".to_string()),
                "Bridge Message Verification".to_string(),
                "Detects missing message verification in bridge contracts".to_string(),
                vec![DetectorCategory::CrossChain],
                Severity::Critical,
            ),
        }
    }

    /// Determine whether this contract is primarily a bridge contract and
    /// should be subject to bridge-message-verification checks.
    ///
    /// Uses the shared contract classification as a baseline, then applies
    /// additional heuristics to exclude contracts that merely *interact* with
    /// bridges (e.g. governance contracts with a cross-chain execution helper)
    /// but are not bridges themselves.
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
        ];
        if non_bridge_names
            .iter()
            .any(|kw| contract_name_lower.contains(kw))
        {
            return false;
        }

        // Require the contract name itself to contain a bridge-related keyword,
        // OR require strong structural indicators (3+) from the shared
        // classifier. This prevents contracts that only mention "bridge" in
        // comments from being classified as bridges.
        let has_bridge_name = contract_name_lower.contains("bridge")
            || contract_name_lower.contains("relay")
            || contract_name_lower.contains("messenger")
            || contract_name_lower.contains("crosschain");

        if has_bridge_name {
            return true;
        }

        // If the contract name is generic, require stronger evidence:
        // must have at least one bridge-specific function pattern in
        // the source to count as a bridge.
        let source_lower = ctx.source_code.to_lowercase();
        let has_bridge_functions = source_lower.contains("function relaymessage")
            || source_lower.contains("function finalize")
            || source_lower.contains("function bridgetokens")
            || source_lower.contains("function sendmessage")
            || source_lower.contains("mapping(bytes32 => bool) public processedmessages")
            || (source_lower.contains("stateroot") && source_lower.contains("merkle"));

        has_bridge_functions
    }

    /// Check whether a function has an access-control modifier that indicates
    /// a trusted relayer / admin pattern (e.g. onlyAuthorized, onlyOwner,
    /// onlyRelayer, onlyRole). When present, the bridge relies on
    /// authentication of the caller rather than cryptographic message proofs,
    /// which is a valid verification strategy.
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

    /// Check whether the function body contains inline access control checks
    /// such as require(msg.sender == ...) or require(authorizedRelayers[msg.sender]).
    fn has_inline_access_control(&self, func_source: &str) -> bool {
        let src = func_source.to_lowercase();
        // require(msg.sender == someAddress) pattern
        (src.contains("require") && src.contains("msg.sender"))
            // Direct mapping lookup of msg.sender for authorization
            || (src.contains("authorized") && src.contains("[msg.sender]"))
            || (src.contains("relayer") && src.contains("[msg.sender]"))
            || (src.contains("trusted") && src.contains("[msg.sender]"))
    }

    /// Check whether the function signature includes parameters that suggest
    /// it is designed to perform cryptographic verification (signature bytes,
    /// proof arrays, v/r/s components). Functions without such parameters are
    /// "bare executors" that lack any verification by design -- these are
    /// better caught by more specific detectors (bridge-merkle-bypass,
    /// l2-bridge-message-validation, missing-chainid-validation).
    fn has_verification_related_params(&self, function: &ast::Function<'_>) -> bool {
        function.parameters.iter().any(|param| {
            if let Some(ref name) = param.name {
                let name_lower = name.name.to_lowercase();
                name_lower.contains("signature")
                    || name_lower.contains("sig")
                    || name_lower.contains("proof")
                    || name_lower == "v"
                    || name_lower == "r"
                    || name_lower == "s"
            } else {
                false
            }
        })
    }

    /// Check whether the function has message hash verification (hash
    /// comparison via require(hash == ...)) combined with replay protection,
    /// which together form a valid verification scheme even without ecrecover
    /// or merkle proofs.
    fn has_hash_verification_with_replay(&self, func_source: &str) -> bool {
        let src = func_source.to_lowercase();
        let has_hash_check = src.contains("require(hash ==")
            || src.contains("require(messagehash ==")
            || src.contains("== messagehash")
            || src.contains("== hash");
        let has_replay = src.contains("processedmessages[")
            || src.contains("executedmessages[")
            || src.contains("usedmessages[")
            || src.contains("processednonces[")
            || src.contains("usednonces[")
            || src.contains("processed[")
            || src.contains("used[")
            || src.contains("nonces[");
        has_hash_check && has_replay
    }

    fn check_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Vec<(String, Severity, String)> {
        let mut issues = Vec::new();
        let name = function.name.name.to_lowercase();

        if !name.contains("process")
            && !name.contains("execute")
            && !name.contains("receive")
            && !name.contains("relay")
        {
            return issues;
        }

        // Only check external/public functions
        let is_external = matches!(
            function.visibility,
            ast::Visibility::External | ast::Visibility::Public
        );

        if !is_external {
            return issues;
        }

        // Skip functions with access-control modifiers — trusted relayer pattern
        // is a valid verification strategy for bridge message handling
        if self.has_access_control_modifier(function) {
            return issues;
        }

        // Get function source with comments stripped
        let func_source = self.get_function_source(function, ctx);
        let func_source_lower = func_source.to_lowercase();

        // Skip functions with inline access control (require(msg.sender == ...))
        if self.has_inline_access_control(&func_source) {
            return issues;
        }

        let has_sig = func_source_lower.contains("ecrecover")
            || (func_source_lower.contains("verify") && func_source_lower.contains("sig"));
        let has_merkle = func_source_lower.contains("merkle")
            && (func_source_lower.contains("verify") || func_source_lower.contains("proof"));

        // Check for hash verification combined with replay protection -- this is
        // a valid verification pattern (e.g. comparing keccak256 of message
        // parameters against a provided hash, then marking it processed)
        if self.has_hash_verification_with_replay(&func_source) {
            return issues;
        }

        // If the function has NO verification-related parameters (no signature,
        // proof, v/r/s) AND no verification logic in the body, this is a "bare
        // executor" function. More specific detectors (bridge-merkle-bypass,
        // l2-bridge-message-validation, missing-chainid-validation) provide
        // better, more actionable findings for these cases.
        if !has_sig && !has_merkle && !self.has_verification_related_params(function) {
            return issues;
        }

        // Check for replay protection more specifically - look for mapping/array access patterns
        // Need to be more specific than just "executed" + "[" because that matches:
        // - Event names like "emit MessageExecuted(...)"
        // - Array parameters like "bytes32[] calldata proof"
        // We want actual state variable access like "processedMessages[hash]"
        let has_replay =
            // Specific mapping names
            func_source_lower.contains("processedmessages[") ||
            func_source_lower.contains("executedmessages[") ||
            func_source_lower.contains("usedmessages[") ||
            func_source_lower.contains("processednonces[") ||
            func_source_lower.contains("usednonces[") ||
            // Generic pattern: "processed" or "used" followed by "[" within reasonable distance
            // But not "emit SomethingExecuted" - check for actual state variable patterns
            (func_source_lower.contains("processed[") ||
             func_source_lower.contains("used[") ||
             func_source_lower.contains("nonces["));

        if !has_sig && !has_merkle {
            issues.push((
                format!("Missing message verification in '{}'", function.name.name),
                Severity::Critical,
                "Add verification: require(verifyMerkleProof(root, proof, leaf) OR ecrecover(hash, v, r, s) == signer);".to_string()
            ));
        }

        if (has_sig || has_merkle) && !has_replay {
            issues.push((
                format!("Missing replay protection in '{}'", function.name.name),
                Severity::Critical,
                "Add: require(!processedMessages[msgHash]); processedMessages[msgHash] = true;"
                    .to_string(),
            ));
        }

        issues
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

impl Default for MessageVerificationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for MessageVerificationDetector {
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

        if !self.is_bridge_contract(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            for (title, severity, remediation) in self.check_function(function, ctx) {
                let finding = self
                    .base
                    .create_finding_with_severity(
                        ctx,
                        title,
                        function.name.location.start().line() as u32,
                        0,
                        20,
                        severity,
                    )
                    .with_cwe(347) // CWE-347: Improper Verification of Cryptographic Signature
                    .with_cwe(294) // CWE-294: Authentication Bypass by Capture-replay
                    .with_fix_suggestion(remediation);
                findings.push(finding);
            }
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
        let detector = MessageVerificationDetector::new();
        assert_eq!(detector.name(), "Bridge Message Verification");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
        assert!(
            detector
                .categories()
                .contains(&DetectorCategory::CrossChain)
        );
    }
}
