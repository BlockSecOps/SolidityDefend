use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for EIP-3074 replay attack vulnerabilities
///
/// EIP-3074 AUTH signatures can be replayed if proper protections are missing:
/// 1. Cross-chain replay: Same signature valid on multiple chains
/// 2. Nonce replay: Same signature reused multiple times
/// 3. Cross-invoker replay: Signature valid for multiple invokers
///
/// Vulnerable pattern:
/// ```solidity
/// function execute(bytes calldata sig, address to) external {
///     // VULNERABLE: No nonce, no chainId, no deadline
///     bytes32 commit = keccak256(abi.encode(to));
///     // AUTH can be replayed indefinitely
/// }
/// ```
pub struct Eip3074ReplayAttackDetector {
    base: BaseDetector,
}

impl Default for Eip3074ReplayAttackDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Eip3074ReplayAttackDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("eip3074-replay-attack"),
                "EIP-3074 Replay Attack".to_string(),
                "Detects missing replay protection in EIP-3074 invokers. \
                 Without proper nonce tracking, chain ID binding, and deadline \
                 enforcement, AUTH signatures can be replayed."
                    .to_string(),
                vec![DetectorCategory::Auth, DetectorCategory::AccessControl],
                Severity::High,
            ),
        }
    }

    /// Check for replay protection mechanisms
    fn check_replay_protection(&self, source: &str) -> Vec<(u32, String, Vec<String>)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Check if this is an EIP-3074 related contract
        // Must be specific to avoid matching "authorization", "authenticate", etc.
        let is_3074_contract = self.is_eip3074_contract(source);

        if !is_3074_contract {
            return findings;
        }

        // Track what protections exist
        let has_nonce = source.contains("nonce") || source.contains("_nonce") || source.contains("usedNonces");
        let has_chain_id = source.contains("chainId") || source.contains("block.chainid") || source.contains("chainid()");
        let has_deadline = source.contains("deadline") || source.contains("expiry") || source.contains("validUntil") || source.contains("block.timestamp");
        let has_nonce_increment = source.contains("nonce++") || source.contains("nonce +=") || source.contains("++nonce") || source.contains("nonces[");

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }

            // Find AUTH usage or invoke functions
            if trimmed.contains("auth(") || trimmed.contains("AUTH") ||
               (trimmed.contains("function") && (trimmed.contains("execute") || trimmed.contains("invoke"))) {

                let mut missing = Vec::new();

                if !has_nonce {
                    missing.push("nonce tracking".to_string());
                }
                if !has_chain_id {
                    missing.push("chain ID binding".to_string());
                }
                if !has_deadline {
                    missing.push("deadline/expiry".to_string());
                }
                if has_nonce && !has_nonce_increment {
                    missing.push("nonce increment after use".to_string());
                }

                if !missing.is_empty() {
                    findings.push((line_num as u32 + 1, trimmed.to_string(), missing));
                }
            }
        }

        findings
    }

    /// Find specific replay vulnerabilities
    fn find_replay_vulnerabilities(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Check for nonce that's never incremented
            if trimmed.contains("nonce") && trimmed.contains("=") && !trimmed.contains("++") && !trimmed.contains("+= 1") {
                // Look ahead for increment
                let context_end = (line_num + 20).min(lines.len());
                let context: String = lines[line_num..context_end].join("\n");
                if !context.contains("nonce++") && !context.contains("++nonce") && !context.contains("nonce += 1") && !context.contains("nonce = nonce + 1") {
                    // Check if it's just reading the nonce
                    if !trimmed.contains("mapping") && !trimmed.contains("uint256 nonce") {
                        findings.push((line_num as u32 + 1, "nonce read without increment".to_string()));
                    }
                }
            }

            // Check for deadline without enforcement
            if trimmed.contains("deadline") && !source.contains("require") && !source.contains("revert") {
                if !source.contains("deadline >") && !source.contains("deadline >=") && !source.contains("> deadline") && !source.contains(">= deadline") {
                    findings.push((line_num as u32 + 1, "deadline without enforcement".to_string()));
                }
            }
        }

        findings
    }

    /// Check if this is specifically an EIP-3074 related contract
    /// Must be precise to avoid false positives on "authorization", "authenticate", etc.
    fn is_eip3074_contract(&self, source: &str) -> bool {
        // Check for AUTH opcode in assembly (the key EIP-3074 indicator)
        // Pattern: assembly { ... auth( ... }
        if source.contains("assembly") {
            // Look for auth( or AUTH in assembly blocks
            let lower = source.to_lowercase();
            let mut in_assembly = false;
            for line in lower.lines() {
                let trimmed = line.trim();
                if trimmed.contains("assembly") && trimmed.contains("{") {
                    in_assembly = true;
                }
                if in_assembly {
                    // Check for auth opcode call (not "authorize" or "authorized")
                    if trimmed.contains("auth(") || trimmed.contains("authcall(") {
                        return true;
                    }
                    if trimmed.contains("}") && !trimmed.contains("{") {
                        in_assembly = false;
                    }
                }
            }
        }

        // Check for specific EIP-3074 invoker patterns
        // Must have "Invoker" as a word boundary (contract name or interface)
        let has_invoker_contract = source.contains("contract") &&
            (source.contains("Invoker ") || source.contains("Invoker{") || source.contains("is Invoker"));

        let has_invoker_interface = source.contains("interface") &&
            (source.contains("IInvoker") || source.contains("Invoker ") || source.contains("Invoker{"));

        // Check for EIP-3074 specific commit pattern with AUTH
        let has_3074_commit = source.contains("commit") &&
            source.contains("keccak256") &&
            (source.contains("AUTH") || source.contains("invoker"));

        has_invoker_contract || has_invoker_interface || has_3074_commit
    }

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for Eip3074ReplayAttackDetector {
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

        // Only analyze EIP-3074 related contracts
        if !self.is_eip3074_contract(source) {
            return Ok(findings);
        }

        // Check for missing replay protections
        let protection_issues = self.check_replay_protection(source);
        for (line, code_context, missing) in protection_issues {
            let message = format!(
                "EIP-3074 replay vulnerability in contract '{}': Missing {}. \
                 Without these protections, AUTH signatures can be replayed, \
                 allowing attackers to execute authorized actions multiple times \
                 or on different chains.",
                contract_name,
                missing.join(", ")
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, code_context.len() as u32)
                .with_cwe(294) // CWE-294: Authentication Bypass by Capture-replay
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Implement complete replay protection:\n\n\
                     1. Nonce tracking:\n\
                        mapping(address => uint256) public nonces;\n\
                        require(nonce == nonces[signer]++, \"Invalid nonce\");\n\n\
                     2. Chain ID binding:\n\
                        require(block.chainid == expectedChainId, \"Wrong chain\");\n\n\
                     3. Deadline enforcement:\n\
                        require(block.timestamp <= deadline, \"Expired\");\n\n\
                     4. Include all in commit hash:\n\
                        commit = keccak256(abi.encode(..., nonce, chainId, deadline));"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Check for specific replay vulnerabilities (only in EIP-3074 contracts)
        let replay_vulns = self.find_replay_vulnerabilities(source);
        for (line, issue) in replay_vulns {
            let message = format!(
                "Potential replay vulnerability in contract '{}': {}. \
                 This could allow signature reuse attacks.",
                contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(294) // CWE-294: Authentication Bypass by Capture-replay
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Ensure nonces are incremented after each use and deadlines are enforced."
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
        let detector = Eip3074ReplayAttackDetector::new();
        assert_eq!(detector.name(), "EIP-3074 Replay Attack");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_replay_protection_check() {
        let detector = Eip3074ReplayAttackDetector::new();

        // Missing all protections
        let vulnerable = r#"
            contract VulnerableInvoker {
                function execute(bytes calldata sig, address to) external {
                    assembly { auth(to, 0) }
                }
            }
        "#;
        let issues = detector.check_replay_protection(vulnerable);
        assert!(!issues.is_empty());

        // Has protections
        let safe = r#"
            contract SafeInvoker {
                mapping(address => uint256) public nonces;
                function execute(bytes calldata sig, address to, uint256 nonce, uint256 deadline) external {
                    require(block.timestamp <= deadline);
                    require(nonce == nonces[msg.sender]++);
                    require(block.chainid == 1);
                    assembly { auth(to, commit) }
                }
            }
        "#;
        let issues = detector.check_replay_protection(safe);
        // Should have fewer or no issues
        assert!(issues.len() < 3);
    }
}
