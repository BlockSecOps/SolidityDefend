use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for EIP-3074 commit validation vulnerabilities
///
/// In EIP-3074, the 'commit' is a 32-byte value that binds the AUTH signature
/// to specific call parameters. Improper commit validation can allow:
/// 1. Signature reuse for different transactions
/// 2. Parameter manipulation after signing
/// 3. Unauthorized actions within authorized scope
///
/// Vulnerable pattern:
/// ```solidity
/// function execute(bytes calldata sig, address to, uint256 value) external {
///     // WRONG: commit doesn't include all parameters
///     bytes32 commit = keccak256(abi.encode(to));
///     // Missing: value, data, nonce, deadline
/// }
/// ```
pub struct Eip3074CommitValidationDetector {
    base: BaseDetector,
}

impl Default for Eip3074CommitValidationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Eip3074CommitValidationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("eip3074-commit-validation"),
                "EIP-3074 Commit Validation".to_string(),
                "Detects improper commit hash validation in EIP-3074 invokers. \
                 The commit must include all transaction parameters to prevent \
                 signature reuse and parameter manipulation attacks."
                    .to_string(),
                vec![DetectorCategory::Auth, DetectorCategory::AccessControl],
                Severity::High,
            ),
        }
    }

    /// Check if contract uses EIP-3074 commit patterns
    fn find_commit_issues(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }

            // Check for commit hash creation
            if trimmed.contains("commit") && trimmed.contains("keccak256") {
                // Analyze what's included in the commit
                let context_start = if line_num > 5 { line_num - 5 } else { 0 };
                let context_end = (line_num + 10).min(lines.len());
                let context: String = lines[context_start..context_end].join("\n");

                let mut missing = Vec::new();

                // Check for required commit components
                if !context.contains("nonce") && !context.contains("_nonce") {
                    missing.push("nonce");
                }
                if !context.contains("deadline")
                    && !context.contains("expiry")
                    && !context.contains("validUntil")
                {
                    missing.push("deadline/expiry");
                }
                if !context.contains("chainId") && !context.contains("block.chainid") {
                    missing.push("chainId");
                }
                if !context.contains("address(this)") && !context.contains("invoker") {
                    missing.push("invoker address");
                }

                if !missing.is_empty() {
                    findings.push((
                        line_num as u32 + 1,
                        "incomplete commit hash".to_string(),
                        missing.join(", "),
                    ));
                }
            }

            // Check for AUTH without commit validation
            if (trimmed.contains("auth(") || trimmed.contains("AUTH")) && !source.contains("commit")
            {
                findings.push((
                    line_num as u32 + 1,
                    "AUTH without commit".to_string(),
                    "no commit validation found".to_string(),
                ));
            }
        }

        findings
    }

    /// Check for weak commit patterns
    fn find_weak_commit_patterns(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Check for commit = 0 or empty commit
            if trimmed.contains("commit")
                && (trimmed.contains("= 0") || trimmed.contains("= bytes32(0)"))
            {
                findings.push((line_num as u32 + 1, "zero commit value".to_string()));
            }

            // Check for commit without encoding call data
            if trimmed.contains("commit") && trimmed.contains("keccak256") {
                if !trimmed.contains("data")
                    && !trimmed.contains("calldata")
                    && !trimmed.contains("payload")
                {
                    // Look ahead for data inclusion
                    let context_end = (line_num + 5).min(lines.len());
                    let context: String = lines[line_num..context_end].join("\n");
                    if !context.contains("data") && !context.contains("calldata") {
                        findings
                            .push((line_num as u32 + 1, "commit missing call data".to_string()));
                    }
                }
            }
        }

        findings
    }

    /// Check if this is specifically an EIP-3074 related contract
    /// Must be precise to avoid false positives on "authorization", "authenticate", etc.
    fn is_eip3074_contract(&self, source: &str) -> bool {
        // Check for AUTH opcode in assembly (the key EIP-3074 indicator)
        if source.contains("assembly") {
            let lower = source.to_lowercase();
            let mut in_assembly = false;
            for line in lower.lines() {
                let trimmed = line.trim();
                if trimmed.contains("assembly") && trimmed.contains("{") {
                    in_assembly = true;
                }
                if in_assembly {
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
        let has_invoker_contract = source.contains("contract")
            && (source.contains("Invoker ")
                || source.contains("Invoker{")
                || source.contains("is Invoker"));

        let has_invoker_interface = source.contains("interface")
            && (source.contains("IInvoker")
                || source.contains("Invoker ")
                || source.contains("Invoker{"));

        // Check for EIP-3074 specific commit pattern with AUTH
        let has_3074_commit = source.contains("commit")
            && source.contains("keccak256")
            && (source.contains("AUTH") || source.contains("invoker"));

        has_invoker_contract || has_invoker_interface || has_3074_commit
    }

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for Eip3074CommitValidationDetector {
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

        // Only check contracts that use EIP-3074 patterns
        // Must be specific to avoid matching "authorization", "authenticate", etc.
        if !self.is_eip3074_contract(source) {
            return Ok(findings);
        }

        // Check for commit validation issues
        let commit_issues = self.find_commit_issues(source);
        for (line, issue_type, details) in commit_issues {
            let message = format!(
                "EIP-3074 {} in contract '{}': {}. The commit hash must include all \
                 transaction parameters (to, value, data, nonce, deadline, chainId, invoker) \
                 to prevent signature reuse and parameter manipulation.",
                issue_type, contract_name, details
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(345) // CWE-345: Insufficient Verification of Data Authenticity
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Include all parameters in the commit hash:\n\n\
                     bytes32 commit = keccak256(abi.encode(\n\
                         to,           // target address\n\
                         value,        // ETH value\n\
                         data,         // call data\n\
                         nonce,        // replay protection\n\
                         deadline,     // expiration time\n\
                         block.chainid,// chain binding\n\
                         address(this) // invoker binding\n\
                     ));"
                    .to_string(),
                );

            findings.push(finding);
        }

        // Check for weak commit patterns
        let weak_patterns = self.find_weak_commit_patterns(source);
        for (line, issue) in weak_patterns {
            let message = format!(
                "Weak EIP-3074 commit pattern in contract '{}': {}. This can allow \
                 attackers to reuse signatures or manipulate transaction parameters.",
                contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(345) // CWE-345: Insufficient Verification of Data Authenticity
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Ensure commit hash includes transaction-specific data and is non-zero."
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
        let detector = Eip3074CommitValidationDetector::new();
        assert_eq!(detector.name(), "EIP-3074 Commit Validation");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_weak_commit_patterns() {
        let detector = Eip3074CommitValidationDetector::new();

        let weak = "bytes32 commit = bytes32(0);";
        let patterns = detector.find_weak_commit_patterns(weak);
        assert!(!patterns.is_empty());
    }
}
