use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for EIP-3074 upgradeable invoker vulnerabilities
///
/// EIP-3074 explicitly forbids upgradeable invoker contracts because:
/// 1. Users sign AUTH messages trusting a specific invoker address
/// 2. If the invoker is upgradeable, the code can change after signing
/// 3. This breaks the security model where users trust specific code
///
/// Vulnerable pattern:
/// ```solidity
/// // FORBIDDEN: Upgradeable invoker
/// contract UpgradeableInvoker is UUPSUpgradeable {
///     function authCall(bytes calldata signature) external {
///         // Uses AUTH opcode with upgradeable code - DANGEROUS
///     }
/// }
/// ```
pub struct Eip3074UpgradeableInvokerDetector {
    base: BaseDetector,
}

impl Default for Eip3074UpgradeableInvokerDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Eip3074UpgradeableInvokerDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("eip3074-upgradeable-invoker"),
                "EIP-3074 Upgradeable Invoker".to_string(),
                "Detects upgradeable contracts that use EIP-3074 AUTH/AUTHCALL opcodes. \
                 EIP-3074 explicitly forbids upgradeable invokers because users sign AUTH \
                 messages trusting specific code. Upgradeable invokers break this trust model."
                    .to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Upgradeable],
                Severity::Critical,
            ),
        }
    }

    /// Check if contract is upgradeable
    fn is_upgradeable(&self, source: &str) -> bool {
        // Check for common upgradeable patterns
        source.contains("UUPSUpgradeable")
            || source.contains("TransparentUpgradeableProxy")
            || source.contains("BeaconProxy")
            || source.contains("Initializable")
            || source.contains("upgradeTo")
            || source.contains("upgradeToAndCall")
            || source.contains("_authorizeUpgrade")
            || source.contains("implementation()")
            || (source.contains("delegatecall") && source.contains("implementation"))
    }

    /// Check if contract uses EIP-3074 patterns
    fn uses_eip3074(&self, source: &str) -> bool {
        // Check for AUTH/AUTHCALL opcode usage (assembly)
        source.contains("auth(")
            || source.contains("authcall(")
            || source.contains("AUTH")
            || source.contains("AUTHCALL")
            // Check for invoker patterns
            || source.contains("invoker")
            || source.contains("Invoker")
            // Check for commit patterns (EIP-3074 specific)
            || (source.contains("commit") && source.contains("signature"))
    }

    /// Find AUTH/AUTHCALL usage locations
    fn find_auth_usage(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }

            // Check for AUTH opcode in assembly
            if trimmed.contains("auth(") || trimmed.contains("AUTH") {
                findings.push((line_num as u32 + 1, "AUTH opcode".to_string()));
            }

            // Check for AUTHCALL opcode in assembly
            if trimmed.contains("authcall(") || trimmed.contains("AUTHCALL") {
                findings.push((line_num as u32 + 1, "AUTHCALL opcode".to_string()));
            }

            // Check for invoker function patterns
            if trimmed.contains("function") && trimmed.contains("invoke") {
                if source.contains("assembly") {
                    findings.push((line_num as u32 + 1, "invoker function".to_string()));
                }
            }
        }

        findings
    }

    /// Find upgradeable pattern locations
    fn find_upgrade_patterns(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("UUPSUpgradeable") {
                findings.push((line_num as u32 + 1, "UUPS pattern".to_string()));
            } else if trimmed.contains("TransparentUpgradeableProxy") {
                findings.push((line_num as u32 + 1, "Transparent proxy".to_string()));
            } else if trimmed.contains("BeaconProxy") {
                findings.push((line_num as u32 + 1, "Beacon proxy".to_string()));
            } else if trimmed.contains("function upgradeTo") {
                findings.push((line_num as u32 + 1, "upgradeTo function".to_string()));
            } else if trimmed.contains("_authorizeUpgrade") {
                findings.push((line_num as u32 + 1, "_authorizeUpgrade".to_string()));
            }
        }

        findings
    }

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for Eip3074UpgradeableInvokerDetector {
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

        // Check if contract is both upgradeable AND uses EIP-3074
        let is_upgradeable = self.is_upgradeable(source);
        let uses_3074 = self.uses_eip3074(source);

        if is_upgradeable && uses_3074 {
            let auth_usages = self.find_auth_usage(source);
            let upgrade_patterns = self.find_upgrade_patterns(source);

            // Report the AUTH/AUTHCALL usage as the primary issue
            for (line, opcode) in auth_usages.iter().take(2) {
                let upgrade_type = upgrade_patterns
                    .first()
                    .map(|(_, t)| t.as_str())
                    .unwrap_or("upgradeable pattern");

                let message = format!(
                    "Contract '{}' uses {} in an upgradeable context ({}). EIP-3074 explicitly \
                     forbids upgradeable invokers. Users sign AUTH messages trusting the invoker's \
                     current code. If the contract is upgraded, previously signed AUTH messages \
                     could be exploited by the new malicious code.",
                    contract_name, opcode, upgrade_type
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, *line, 1, 50)
                    .with_cwe(284) // CWE-284: Improper Access Control
                    .with_confidence(Confidence::High)
                    .with_fix_suggestion(
                        "EIP-3074 invokers MUST NOT be upgradeable. Options:\n\n\
                         1. Deploy invoker as immutable contract (no proxy)\n\
                         2. If upgrade needed, deploy new invoker and have users re-sign\n\
                         3. Use CREATE2 for deterministic addresses without upgradeability\n\
                         4. Consider EIP-7702 which has different security model"
                            .to_string(),
                    );

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
        let detector = Eip3074UpgradeableInvokerDetector::new();
        assert_eq!(detector.name(), "EIP-3074 Upgradeable Invoker");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_upgradeable_detection() {
        let detector = Eip3074UpgradeableInvokerDetector::new();

        assert!(detector.is_upgradeable("contract Foo is UUPSUpgradeable {}"));
        assert!(detector.is_upgradeable("function upgradeTo(address newImpl) external"));
        assert!(detector.is_upgradeable("function _authorizeUpgrade(address) internal"));
        assert!(!detector.is_upgradeable("contract SimpleContract {}"));
    }

    #[test]
    fn test_eip3074_detection() {
        let detector = Eip3074UpgradeableInvokerDetector::new();

        assert!(detector.uses_eip3074("assembly { auth(invoker, commit) }"));
        assert!(detector.uses_eip3074("assembly { authcall(gas, to, value) }"));
        assert!(detector.uses_eip3074("contract MyInvoker {}"));
        assert!(!detector.uses_eip3074("contract SimpleContract {}"));
    }
}
