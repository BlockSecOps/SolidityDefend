use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};
use crate::utils::{is_test_contract, is_bridge_contract, is_standard_token, is_zk_contract};

/// Detector for bridge merkle proof bypass vulnerabilities
///
/// Detects patterns where merkle proof validation in cross-chain bridges
/// is missing, weak, or bypassable.
pub struct BridgeMerkleBypassDetector {
    base: BaseDetector,
}

impl Default for BridgeMerkleBypassDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BridgeMerkleBypassDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("bridge-merkle-bypass"),
                "Bridge Merkle Bypass".to_string(),
                "Detects missing or weak merkle proof validation in cross-chain bridges \
                 that could allow unauthorized withdrawals or message forgery."
                    .to_string(),
                vec![
                    DetectorCategory::L2,
                    DetectorCategory::CrossChain,
                    DetectorCategory::AccessControl,
                ],
                Severity::Critical,
            ),
        }
    }

    /// Find missing merkle proof validation
    fn find_missing_proof_validation(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect withdrawal/claim functions in bridges
            if trimmed.contains("function ")
                && (trimmed.contains("withdraw")
                    || trimmed.contains("claim")
                    || trimmed.contains("finalize")
                    || trimmed.contains("relay"))
                && (trimmed.contains("external") || trimmed.contains("public"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_lower = func_body.to_lowercase();

                // Check for valid authentication: merkle proofs OR signatures
                let has_merkle = func_lower.contains("merkle")
                    || func_lower.contains("proof")
                    || func_lower.contains("verify");

                let has_signature = func_lower.contains("ecrecover")
                    || func_lower.contains("ecdsa.recover")
                    || func_lower.contains("signaturechecker")
                    || func_lower.contains("isvalidsignature")
                    || func_lower.contains("_verifysignature")
                    || func_lower.contains("signature");

                // Only flag if neither merkle nor signature authentication is present
                if !has_merkle && !has_signature {
                    let issue = "Bridge function without merkle proof or signature verification".to_string();
                    findings.push((line_num as u32 + 1, func_name.clone(), issue));
                }

                // Check for root validation (still important for merkle-based bridges)
                // But skip if using signature-based authentication
                if has_merkle && !has_signature {
                    if !func_lower.contains("root") {
                        let issue = "Bridge function without root validation".to_string();
                        findings.push((line_num as u32 + 1, func_name, issue));
                    }
                }
            }

            // Detect message relay without proof
            if trimmed.contains("function ")
                && (trimmed.contains("receiveMessage") || trimmed.contains("executeMessage"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_lower = func_body.to_lowercase();

                // Accept proof, signature, or verified sender as valid authentication
                let has_auth = func_lower.contains("proof")
                    || func_lower.contains("signature")
                    || func_lower.contains("ecrecover")
                    || func_lower.contains("ecdsa")
                    || func_lower.contains("onlymessenger")
                    || func_lower.contains("onlybridge")
                    || func_lower.contains("require(msg.sender");

                if !has_auth {
                    let issue = "Message relay without cryptographic proof or sender validation".to_string();
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    /// Find weak proof verification patterns
    fn find_weak_verification(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect proof verification functions
            if trimmed.contains("function ")
                && (trimmed.contains("verifyProof")
                    || trimmed.contains("verify")
                    || trimmed.contains("checkProof"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for empty leaf handling
                if func_body.contains("bytes32(0)") && !func_body.contains("revert") {
                    findings.push((line_num as u32 + 1, func_name.clone()));
                }

                // Check for proof length validation
                if !func_body.contains(".length") && func_body.contains("proof") {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find root update vulnerabilities
    fn find_root_update_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect root update functions
            if trimmed.contains("function ")
                && (trimmed.contains("setRoot")
                    || trimmed.contains("updateRoot")
                    || trimmed.contains("submitRoot"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for proper access control
                if !func_body.contains("onlyOwner")
                    && !func_body.contains("onlyRelayer")
                    && !func_body.contains("onlyBridge")
                    && !func_body.contains("require")
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find replay attack vulnerabilities
    fn find_replay_vulnerabilities(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Check if this is a bridge contract
        let is_bridge = source.contains("Bridge")
            || source.contains("bridge")
            || source.contains("CrossChain");

        if !is_bridge {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect claim/execute functions
            if trimmed.contains("function ")
                && (trimmed.contains("execute") || trimmed.contains("claim"))
                && (trimmed.contains("external") || trimmed.contains("public"))
                && !trimmed.starts_with("//")
            {
                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check for nonce/processed tracking
                if !func_body.contains("processed")
                    && !func_body.contains("claimed")
                    && !func_body.contains("nonce")
                    && !func_body.contains("used")
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    fn extract_function_name(&self, line: &str) -> String {
        if let Some(func_start) = line.find("function ") {
            let after_func = &line[func_start + 9..];
            if let Some(paren_pos) = after_func.find('(') {
                return after_func[..paren_pos].trim().to_string();
            }
        }
        "unknown".to_string()
    }

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

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for BridgeMerkleBypassDetector {
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

        // Phase 9 FP Reduction: Skip test contracts entirely
        if is_test_contract(ctx) {
            return Ok(findings);
        }

        // Phase 9 FP Reduction: Skip standard token contracts
        // ERC20/ERC721/ERC1155/ERC4626 are tokens, not bridges
        if is_standard_token(ctx) {
            return Ok(findings);
        }

        // Phase 14 FP Reduction: Skip ZK proof verification contracts
        // ZK verifiers have verify/proof functions but are NOT bridges
        // They should be analyzed by ZK-specific detectors instead
        if is_zk_contract(ctx) {
            return Ok(findings);
        }

        // Phase 9 FP Reduction: Strict bridge context gate
        // Only fire if contract is actually a bridge/cross-chain contract
        if !is_bridge_contract(ctx) {
            return Ok(findings);
        }

        for (line, func_name, issue) in self.find_missing_proof_validation(source) {
            let message = format!(
                "Function '{}' in contract '{}' has merkle bypass vulnerability: {}. \
                 Attackers may be able to forge withdrawal proofs or relay unauthorized messages.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(345)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Add proper merkle proof validation:\n\n\
                     1. Require merkle proof parameter for all withdrawals\n\
                     2. Verify proof against confirmed state root\n\
                     3. Use battle-tested merkle proof libraries\n\
                     4. Validate leaf hash includes all message data\n\
                     5. Check proof length matches tree depth"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_weak_verification(source) {
            let message = format!(
                "Function '{}' in contract '{}' has weak merkle proof verification. \
                 Empty proofs or invalid lengths may be accepted.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(345)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Strengthen proof verification:\n\n\
                     1. Reject proofs with bytes32(0) elements\n\
                     2. Validate proof length against expected tree depth\n\
                     3. Reject empty proofs explicitly\n\
                     4. Add bounds checking on proof indices"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_root_update_issues(source) {
            let message = format!(
                "Function '{}' in contract '{}' updates merkle root without proper access control. \
                 Unauthorized root updates could enable theft of bridge funds.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(345)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Protect root updates:\n\n\
                     1. Restrict root updates to authorized relayers/validators\n\
                     2. Implement multi-sig or threshold signatures\n\
                     3. Add time delay for root updates\n\
                     4. Verify root against L1/source chain state"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_replay_vulnerabilities(source) {
            let message = format!(
                "Function '{}' in contract '{}' may be vulnerable to replay attacks. \
                 Withdrawals or messages could be executed multiple times.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(294)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Prevent replay attacks:\n\n\
                     1. Track processed message hashes/nonces\n\
                     2. Mark claims as processed before execution\n\
                     3. Use unique identifiers per message\n\
                     4. Include chain ID in message hash"
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
        let detector = BridgeMerkleBypassDetector::new();
        assert_eq!(detector.name(), "Bridge Merkle Bypass");
        assert_eq!(detector.default_severity(), Severity::Critical);
    }
}
