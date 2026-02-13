use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for hardcoded or untrusted EntryPoint contracts in ERC-4337 wallets
pub struct Erc4337EntrypointTrustDetector {
    base: BaseDetector,
}

impl Default for Erc4337EntrypointTrustDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Erc4337EntrypointTrustDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("erc4337-entrypoint-trust".to_string()),
                "ERC-4337 Untrusted EntryPoint".to_string(),
                "Detects hardcoded or untrusted EntryPoint contracts in ERC-4337 account abstraction wallets that could allow full account takeover".to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Validation],
                Severity::Critical,
            ),
        }
    }
}

impl Detector for Erc4337EntrypointTrustDetector {
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

        let contract_source = crate::utils::get_contract_source(ctx);

        // Check for ERC-4337 account abstraction patterns
        if !self.is_erc4337_wallet(contract_source) {
            return Ok(findings);
        }

        // Pattern 1: Hardcoded EntryPoint address
        if let Some(hardcoded_issues) = self.check_hardcoded_entrypoint(contract_source) {
            for (line, issue) in hardcoded_issues {
                let message = format!(
                    "ERC-4337 wallet uses hardcoded EntryPoint. {} \
                    Hardcoded EntryPoint creates single point of failure - if EntryPoint is compromised or deprecated, wallet becomes unusable or vulnerable.",
                    issue
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 0, 40)
                    .with_cwe(798) // CWE-798: Use of Hard-coded Credentials
                    .with_cwe(670) // CWE-670: Always-Incorrect Control Flow Implementation
                    .with_fix_suggestion(
                        "Implement upgradeable EntryPoint pattern: \
                    (1) Use storage variable for EntryPoint address, \
                    (2) Add secure upgrade mechanism with time-lock, \
                    (3) Emit events on EntryPoint changes, \
                    (4) Implement EntryPoint validation checks, \
                    (5) Consider multi-sig approval for EntryPoint updates."
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        // Pattern 2: Missing EntryPoint validation
        if let Some(validation_issues) = self.check_entrypoint_validation(contract_source) {
            for (line, issue) in validation_issues {
                let message = format!(
                    "ERC-4337 wallet missing EntryPoint validation. {} \
                    Missing validation allows malicious contracts to impersonate EntryPoint and execute arbitrary operations.",
                    issue
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 0, 40)
                    .with_cwe(20) // CWE-20: Improper Input Validation
                    .with_cwe(345) // CWE-345: Insufficient Verification of Data Authenticity
                    .with_fix_suggestion(
                        "Add EntryPoint validation: \
                    (1) Verify msg.sender is trusted EntryPoint in validateUserOp, \
                    (2) Implement onlyEntryPoint modifier, \
                    (3) Store and validate EntryPoint address, \
                    (4) Revert on unauthorized callers, \
                    (5) Use OpenZeppelin's BaseAccount pattern."
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        // Pattern 3: Mutable EntryPoint without access control
        if let Some(mutability_issues) = self.check_entrypoint_mutability(contract_source) {
            for (line, issue) in mutability_issues {
                let message = format!(
                    "ERC-4337 EntryPoint can be changed without proper access control. {} \
                    Unrestricted EntryPoint modification allows attackers to replace trusted EntryPoint with malicious contract.",
                    issue
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 0, 40)
                    .with_cwe(284) // CWE-284: Improper Access Control
                    .with_cwe(862) // CWE-862: Missing Authorization
                    .with_fix_suggestion(
                        "Protect EntryPoint updates: \
                    (1) Add onlyOwner or multi-sig requirement, \
                    (2) Implement time-lock for changes, \
                    (3) Emit EntryPointChanged event, \
                    (4) Validate new EntryPoint implements IEntryPoint, \
                    (5) Consider making EntryPoint immutable if appropriate."
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        // Pattern 4: Missing IEntryPoint interface validation
        if !contract_source.contains("IEntryPoint") && contract_source.contains("EntryPoint") {
            let message = "ERC-4337 wallet references EntryPoint without importing IEntryPoint interface. \
                Missing interface validation can lead to incorrect EntryPoint interaction and security vulnerabilities.".to_string();

            let finding = self
                .base
                .create_finding(ctx, message, 1, 0, 40)
                .with_cwe(1104) // CWE-1104: Use of Unmaintained Third Party Components
                .with_fix_suggestion(
                    "Import and validate IEntryPoint: \
                (1) Import IEntryPoint from @account-abstraction/contracts, \
                (2) Cast EntryPoint to IEntryPoint interface, \
                (3) Validate interface support using ERC165, \
                (4) Ensure compliance with ERC-4337 specification."
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

impl Erc4337EntrypointTrustDetector {
    fn is_erc4337_wallet(&self, source: &str) -> bool {
        // Explicit AA wallet interfaces — strong signal
        let explicit_wallet = source.contains("IAccount")
            || source.contains("BaseAccount");
        if explicit_wallet {
            return true;
        }

        // validateUserOp alone is not enough (EntryPoints also have it).
        // Require a wallet-like structure: state (owner/nonce) or EntryPoint storage.
        let has_validate = source.contains("validateUserOp");
        let has_wallet_structure = source.contains("owner")
            || source.contains("nonce")
            || source.contains("trustedEntryPoint")
            || source.contains("ENTRY_POINT");

        has_validate && has_wallet_structure
    }

    fn check_hardcoded_entrypoint(&self, source: &str) -> Option<Vec<(u32, String)>> {
        let lines: Vec<&str> = source.lines().collect();
        let mut issues = Vec::new();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Pattern: address constant/immutable ENTRYPOINT = 0x...
            if trimmed.contains("EntryPoint") || trimmed.contains("entryPoint") {
                if (trimmed.contains("constant") || trimmed.contains("immutable"))
                    && trimmed.contains("= 0x")
                {
                    issues.push((
                        (idx + 1) as u32,
                        "EntryPoint address is hardcoded as constant/immutable".to_string(),
                    ));
                }

                // Pattern: EntryPoint = IEntryPoint(0x5FF...)
                if trimmed.contains("= IEntryPoint(0x") || trimmed.contains("= EntryPoint(0x") {
                    issues.push((
                        (idx + 1) as u32,
                        "EntryPoint initialized with hardcoded address".to_string(),
                    ));
                }
            }
        }

        if issues.is_empty() {
            None
        } else {
            Some(issues)
        }
    }

    fn check_entrypoint_validation(&self, source: &str) -> Option<Vec<(u32, String)>> {
        let lines: Vec<&str> = source.lines().collect();
        let mut issues = Vec::new();
        let mut in_validate_userop = false;
        let mut validate_start_line = 0;
        let mut has_entrypoint_check = false;

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function validateUserOp") {
                in_validate_userop = true;
                validate_start_line = idx;
                has_entrypoint_check = false;
            }

            if in_validate_userop {
                // Check for EntryPoint validation
                if trimmed.contains("msg.sender")
                    && (trimmed.contains("entryPoint") || trimmed.contains("EntryPoint"))
                    && (trimmed.contains("require") || trimmed.contains("if"))
                {
                    has_entrypoint_check = true;
                }

                // Recognize onlyEntryPoint modifier as valid EntryPoint check
                if trimmed.contains("onlyEntryPoint") {
                    has_entrypoint_check = true;
                }

                // End of function
                if trimmed == "}" {
                    if !has_entrypoint_check {
                        issues.push((
                            (validate_start_line + 1) as u32,
                            "validateUserOp function missing EntryPoint sender validation"
                                .to_string(),
                        ));
                    }
                    in_validate_userop = false;
                }
            }
        }

        if issues.is_empty() {
            None
        } else {
            Some(issues)
        }
    }

    fn check_entrypoint_mutability(&self, source: &str) -> Option<Vec<(u32, String)>> {
        let lines: Vec<&str> = source.lines().collect();
        let mut issues = Vec::new();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Pattern: function that sets EntryPoint
            if trimmed.contains("function")
                && (trimmed.contains("setEntryPoint")
                    || trimmed.contains("updateEntryPoint")
                    || trimmed.contains("changeEntryPoint"))
            {
                // Check for access control in next few lines
                let mut has_access_control = false;
                let check_lines = 5.min(lines.len() - idx - 1);

                for i in 0..check_lines {
                    let next_line = lines[idx + i].trim();
                    if next_line.contains("onlyOwner")
                        || next_line.contains("require(msg.sender")
                        || next_line.contains("require(owner")
                        || next_line.contains("onlyAdmin")
                    {
                        has_access_control = true;
                        break;
                    }
                }

                if !has_access_control {
                    issues.push((
                        (idx + 1) as u32,
                        "EntryPoint setter function lacks access control (onlyOwner/require)"
                            .to_string(),
                    ));
                }
            }

            // Pattern: direct EntryPoint assignment
            if (trimmed.contains("entryPoint =") || trimmed.contains("EntryPoint ="))
                && !trimmed.contains("//")
            {
                // Check if it's in a protected context (wider window to capture function modifiers)
                let context = lines[idx.saturating_sub(10)..=idx].join(" ");
                if !context.contains("onlyOwner")
                    && !context.contains("onlyAdmin")
                    && !context.contains("require(msg.sender")
                    && !context.contains("constructor")
                {
                    issues.push((
                        (idx + 1) as u32,
                        "EntryPoint assignment without access control check".to_string(),
                    ));
                }
            }
        }

        if issues.is_empty() {
            None
        } else {
            Some(issues)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = Erc4337EntrypointTrustDetector::new();
        assert_eq!(detector.name(), "ERC-4337 Untrusted EntryPoint");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }
}
