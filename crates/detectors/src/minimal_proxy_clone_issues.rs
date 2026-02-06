use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for EIP-1167 minimal proxy (clone) issues
///
/// Minimal proxies (clones) are cheap to deploy but have specific patterns
/// that can lead to vulnerabilities:
/// 1. Clones not initialized after creation
/// 2. Predictable CREATE2 addresses allowing front-running
/// 3. Implementation not properly secured
pub struct MinimalProxyCloneIssuesDetector {
    base: BaseDetector,
}

impl Default for MinimalProxyCloneIssuesDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MinimalProxyCloneIssuesDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("minimal-proxy-clone-issues"),
                "Minimal Proxy Clone Issues".to_string(),
                "Detects potential vulnerabilities in EIP-1167 minimal proxy (clone) usage \
                 including uninitialized clones and predictable addresses"
                    .to_string(),
                vec![DetectorCategory::Upgradeable, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    /// Check if contract uses clone functionality
    fn uses_clones(&self, source: &str) -> bool {
        source.contains("Clones.clone")
            || source.contains("Clones.cloneDeterministic")
            || source.contains("createClone")
            || source.contains("LibClone")
            || source.contains("create(0,") // Low-level clone pattern
    }

    /// Find clone-related issues
    fn find_clone_issues(&self, source: &str) -> Vec<(u32, String, Confidence)> {
        let mut issues = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            // Check for clone without immediate initialization
            if line.contains("Clones.clone(") {
                // Look at next few lines for initialization
                let next_lines: String = lines
                    .iter()
                    .skip(i)
                    .take(5)
                    .cloned()
                    .collect::<Vec<&str>>()
                    .join("\n");

                if !next_lines.contains(".initialize(")
                    && !next_lines.contains("init(")
                    && !next_lines.contains("__init(")
                {
                    issues.push((
                        (i + 1) as u32,
                        "Clone created without immediate initialization - attacker may front-run initialization".to_string(),
                        Confidence::Medium,
                    ));
                }
            }

            // Check for deterministic clone with predictable salt
            if line.contains("cloneDeterministic(") {
                // Check if salt is derived from predictable values
                if line.contains("block.timestamp")
                    || line.contains("block.number")
                    || line.contains("msg.sender")
                {
                    issues.push((
                        (i + 1) as u32,
                        "Deterministic clone with predictable salt - address can be computed and front-run".to_string(),
                        Confidence::Medium,
                    ));
                }
            }

            // Check for clone factory without access control
            if (line.contains("function create") || line.contains("function deploy"))
                && source.contains("Clones.")
            {
                // Check if function is public/external without access control
                if (line.contains("public") || line.contains("external"))
                    && !line.contains("onlyOwner")
                    && !line.contains("onlyAdmin")
                {
                    // Look for access control in function body
                    let func_end = self.find_function_end(&lines, i);
                    let func_body: String = lines[i..=func_end].join("\n");

                    if !func_body.contains("require(msg.sender") && !func_body.contains("hasRole(")
                    {
                        issues.push((
                            (i + 1) as u32,
                            "Clone factory function without access control - anyone can create clones".to_string(),
                            Confidence::Low,
                        ));
                    }
                }
            }
        }

        issues
    }

    /// Find end of function
    fn find_function_end(&self, lines: &[&str], start: usize) -> usize {
        let mut depth = 0;
        let mut started = false;

        for (i, line) in lines.iter().enumerate().skip(start) {
            for c in line.chars() {
                if c == '{' {
                    depth += 1;
                    started = true;
                } else if c == '}' {
                    depth -= 1;
                    if started && depth == 0 {
                        return i;
                    }
                }
            }
        }
        lines.len() - 1
    }

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for MinimalProxyCloneIssuesDetector {
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

        if !self.uses_clones(source) {
            return Ok(findings);
        }

        let issues = self.find_clone_issues(source);

        for (line, issue_desc, confidence) in issues {
            let message = format!("Clone factory '{}': {}", contract_name, issue_desc);

            let finding = self
                .base
                .create_finding(ctx, message, line, 0, 20)
                .with_cwe(672) // CWE-672: Operation on Resource After Expiration or Release
                .with_cwe(362) // CWE-362: Race Condition
                .with_confidence(confidence)
                .with_fix_suggestion(
                    "For clone security:\n\n\
                     1. Initialize clones atomically in the same transaction:\n\
                        address clone = Clones.clone(impl);\n\
                        IImpl(clone).initialize(...);\n\n\
                     2. Use unpredictable salts for deterministic clones:\n\
                        bytes32 salt = keccak256(abi.encodePacked(msg.sender, userNonce++, block.prevrandao));\n\n\
                     3. Consider access control on factory functions."
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
        let detector = MinimalProxyCloneIssuesDetector::new();
        assert_eq!(detector.name(), "Minimal Proxy Clone Issues");
        assert_eq!(detector.default_severity(), Severity::High);
    }

    #[test]
    fn test_uses_clones() {
        let detector = MinimalProxyCloneIssuesDetector::new();
        assert!(detector.uses_clones("address clone = Clones.clone(implementation);"));
        assert!(detector.uses_clones("Clones.cloneDeterministic(impl, salt)"));
        assert!(!detector.uses_clones("contract SimpleToken {}"));
    }
}
