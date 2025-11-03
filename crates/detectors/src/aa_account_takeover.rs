use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::{access_control_patterns, modern_eip_patterns};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for vulnerabilities allowing EntryPoint replacement attacks
pub struct AaAccountTakeoverDetector {
    base: BaseDetector,
}

impl AaAccountTakeoverDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("aa-account-takeover".to_string()),
                "Account Abstraction Takeover Vulnerability".to_string(),
                "Detects vulnerabilities allowing EntryPoint replacement attacks and full account takeover in ERC-4337 wallets".to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Logic],
                Severity::Critical,
            ),
        }
    }
}

impl Detector for AaAccountTakeoverDetector {
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
        let contract_source = ctx.source_code.as_str();

        // Check for ERC-4337 patterns
        if !self.is_erc4337_contract(contract_source) {
            return Ok(findings);
        }

        // Phase 2 Enhancement: Safe pattern detection with dynamic confidence

        // Level 1: Strong AA/access control protections (return early)
        if modern_eip_patterns::has_safe_metatx_pattern(ctx) {
            // Safe meta-tx pattern includes comprehensive signature validation + replay protection
            // This prevents signature bypass and ensures proper authentication
            if access_control_patterns::has_two_step_ownership(ctx) {
                if access_control_patterns::has_timelock_pattern(ctx) {
                    // Comprehensive protection: EIP-712 sigs + two-step ownership + timelock
                    // Prevents all account takeover vectors
                    return Ok(findings);
                }
            }
        }

        // Level 2: Standard access control protections
        let has_timelock = access_control_patterns::has_timelock_pattern(ctx);
        let has_multisig = access_control_patterns::has_multisig_pattern(ctx);
        let has_two_step_ownership = access_control_patterns::has_two_step_ownership(ctx);
        let _has_role_hierarchy = access_control_patterns::has_role_hierarchy_pattern(ctx);

        // Early return if strong governance protections are present
        if has_timelock && has_multisig {
            // Timelock + multisig provides strong protection against unauthorized changes
            return Ok(findings);
        }

        if has_two_step_ownership && (has_timelock || has_multisig) {
            // Two-step ownership with additional protection is sufficient
            return Ok(findings);
        }

        // Pattern 1: Unprotected EntryPoint replacement
        if let Some(replacement_issues) = self.check_entrypoint_replacement(contract_source) {
            for (line, issue) in replacement_issues {
                let message = format!(
                    "EntryPoint can be replaced allowing account takeover. {} \
                    Attackers can replace the trusted EntryPoint with malicious contract to execute arbitrary operations and drain account.",
                    issue
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 0, 40)
                    .with_cwe(284) // CWE-284: Improper Access Control
                    .with_cwe(639) // CWE-639: Authorization Bypass Through User-Controlled Key
                    .with_fix_suggestion(
                        "Prevent EntryPoint replacement: \
                    (1) Make EntryPoint immutable if possible, \
                    (2) Add strict access control (multi-sig required), \
                    (3) Implement time-lock for EntryPoint updates, \
                    (4) Require user signature for changes, \
                    (5) Emit EntryPointChanged event for monitoring."
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        // Pattern 2: Module system vulnerabilities
        if let Some(module_issues) = self.check_module_vulnerabilities(contract_source) {
            for (line, issue) in module_issues {
                let message = format!(
                    "Module system allows unauthorized privilege escalation. {} \
                    Malicious modules can be added to gain full account control and execute unauthorized operations.",
                    issue
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 0, 40)
                    .with_cwe(269) // CWE-269: Improper Privilege Management
                    .with_cwe(862) // CWE-862: Missing Authorization
                    .with_fix_suggestion(
                        "Secure module system: \
                    (1) Validate module addresses before adding, \
                    (2) Implement module whitelist/registry, \
                    (3) Require user signature for module changes, \
                    (4) Add time-lock for module additions, \
                    (5) Emit ModuleAdded/ModuleRemoved events."
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        // Pattern 3: Signature validation bypass
        if let Some(sig_issues) = self.check_signature_bypass(contract_source) {
            for (line, issue) in sig_issues {
                let message = format!(
                    "Signature validation can be bypassed in validateUserOp. {} \
                    Bypass allows attackers to execute operations without valid signatures, leading to unauthorized access.",
                    issue
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 0, 40)
                    .with_cwe(345) // CWE-345: Insufficient Verification of Data Authenticity
                    .with_cwe(290) // CWE-290: Authentication Bypass by Spoofing
                    .with_fix_suggestion(
                        "Enforce signature validation: \
                    (1) Always validate signature in validateUserOp, \
                    (2) Use proper signature recovery (ecrecover or ECDSA), \
                    (3) Validate signer matches account owner, \
                    (4) Include nonce in signed message, \
                    (5) Follow ERC-4337 signature requirements."
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        // Pattern 4: Fallback function takeover
        if let Some(fallback_issues) = self.check_fallback_vulnerabilities(contract_source) {
            for (line, issue) in fallback_issues {
                let message = format!(
                    "Fallback/receive function allows unauthorized execution. {} \
                    Unrestricted fallback functions can be exploited to bypass normal execution flow and access control.",
                    issue
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 0, 40)
                    .with_cwe(749) // CWE-749: Exposed Dangerous Method or Function
                    .with_cwe(670) // CWE-670: Always-Incorrect Control Flow Implementation
                    .with_fix_suggestion(
                        "Secure fallback functions: \
                    (1) Add onlyEntryPoint modifier to fallback, \
                    (2) Validate msg.sender in fallback/receive, \
                    (3) Limit fallback functionality, \
                    (4) Log fallback calls for monitoring, \
                    (5) Consider removing fallback if not needed."
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        // Pattern 5: Upgradeable implementation vulnerabilities
        if let Some(upgrade_issues) = self.check_upgrade_vulnerabilities(contract_source) {
            for (line, issue) in upgrade_issues {
                let message = format!(
                    "Upgradeable account vulnerable to implementation takeover. {} \
                    Unprotected upgrades allow attackers to replace logic contract with malicious implementation.",
                    issue
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 0, 40)
                    .with_cwe(913) // CWE-913: Improper Control of Dynamically-Managed Code Resources
                    .with_cwe(494) // CWE-494: Download of Code Without Integrity Check
                    .with_fix_suggestion(
                        "Protect upgrade mechanism: \
                    (1) Require multi-sig for upgrades, \
                    (2) Implement time-lock delay, \
                    (3) Validate new implementation interface, \
                    (4) Add upgrade proposal/voting system, \
                    (5) Emit ImplementationUpgraded event."
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

impl AaAccountTakeoverDetector {
    fn is_erc4337_contract(&self, source: &str) -> bool {
        source.contains("validateUserOp")
            || source.contains("IAccount")
            || source.contains("BaseAccount")
            || source.contains("EntryPoint")
    }

    fn check_entrypoint_replacement(&self, source: &str) -> Option<Vec<(u32, String)>> {
        let lines: Vec<&str> = source.lines().collect();
        let mut issues = Vec::new();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for EntryPoint setter functions
            if trimmed.contains("function")
                && (trimmed.contains("setEntryPoint")
                    || trimmed.contains("updateEntryPoint")
                    || trimmed.contains("replaceEntryPoint")
                    || trimmed.contains("changeEntryPoint"))
            {
                let func_body = self.get_function_body(&lines, idx);

                // Check for proper access control
                let has_owner_check = func_body.contains("onlyOwner")
                    || func_body.contains("require(msg.sender == owner")
                    || func_body.contains("_checkOwner");

                let has_timelock = func_body.contains("timelock")
                    || func_body.contains("delay")
                    || func_body.contains("block.timestamp");

                let has_multisig = func_body.contains("multisig")
                    || func_body.contains("threshold")
                    || func_body.contains("signatures");

                if !has_owner_check {
                    issues.push((
                        (idx + 1) as u32,
                        "EntryPoint replacement missing owner check".to_string(),
                    ));
                } else if !has_timelock && !has_multisig {
                    issues.push((
                        (idx + 1) as u32,
                        "EntryPoint replacement lacks time-lock or multi-sig protection"
                            .to_string(),
                    ));
                }
            }

            // Check for direct EntryPoint assignment
            if trimmed.contains("entryPoint =") && !trimmed.contains("//") {
                let context = self.get_surrounding_context(&lines, idx, 5);

                if !context.contains("constructor")
                    && !context.contains("initialize")
                    && !context.contains("onlyOwner")
                {
                    issues.push((
                        (idx + 1) as u32,
                        "EntryPoint assignment without proper authorization".to_string(),
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

    fn check_module_vulnerabilities(&self, source: &str) -> Option<Vec<(u32, String)>> {
        let lines: Vec<&str> = source.lines().collect();
        let mut issues = Vec::new();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for module addition functions
            if trimmed.contains("function")
                && (trimmed.contains("addModule")
                    || trimmed.contains("enableModule")
                    || trimmed.contains("installModule"))
            {
                let func_body = self.get_function_body(&lines, idx);

                // Check for validation
                let has_validation = func_body.contains("require(") || func_body.contains("revert");

                let has_whitelist = func_body.contains("approved")
                    || func_body.contains("whitelist")
                    || func_body.contains("registry");

                let has_signature =
                    func_body.contains("signature") || func_body.contains("ecrecover");

                if !has_validation {
                    issues.push((
                        (idx + 1) as u32,
                        "Module addition without validation checks".to_string(),
                    ));
                } else if !has_whitelist && !has_signature {
                    issues.push((
                        (idx + 1) as u32,
                        "Module addition lacks whitelist or signature verification".to_string(),
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

    fn check_signature_bypass(&self, source: &str) -> Option<Vec<(u32, String)>> {
        let lines: Vec<&str> = source.lines().collect();
        let mut issues = Vec::new();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function validateUserOp") {
                let func_body = self.get_function_body(&lines, idx);

                // Check for signature validation
                let has_sig_check = func_body.contains("ecrecover")
                    || func_body.contains("ECDSA.recover")
                    || func_body.contains("SignatureChecker");

                // Check for early returns that bypass validation
                let has_early_return = func_body.contains("if (") && func_body.contains("return 0");

                // Check for owner validation
                let validates_owner = func_body.contains("owner") || func_body.contains("signer");

                if !has_sig_check {
                    issues.push((
                        (idx + 1) as u32,
                        "validateUserOp missing signature verification".to_string(),
                    ));
                } else if has_early_return && !validates_owner {
                    issues.push((
                        (idx + 1) as u32,
                        "validateUserOp has early return that may bypass signature check"
                            .to_string(),
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

    fn check_fallback_vulnerabilities(&self, source: &str) -> Option<Vec<(u32, String)>> {
        let lines: Vec<&str> = source.lines().collect();
        let mut issues = Vec::new();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("fallback()") || trimmed.contains("receive()") {
                let func_body = self.get_function_body(&lines, idx);

                // Check for access control
                let has_entrypoint_check = func_body.contains("msg.sender == entryPoint")
                    || func_body.contains("onlyEntryPoint");

                let has_validation = func_body.contains("require(") || func_body.contains("revert");

                if !has_entrypoint_check && !has_validation {
                    issues.push((
                        (idx + 1) as u32,
                        "Fallback/receive function lacks access control".to_string(),
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

    fn check_upgrade_vulnerabilities(&self, source: &str) -> Option<Vec<(u32, String)>> {
        let lines: Vec<&str> = source.lines().collect();
        let mut issues = Vec::new();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function")
                && (trimmed.contains("upgradeTo")
                    || trimmed.contains("upgradeToAndCall")
                    || trimmed.contains("setImplementation"))
            {
                let func_body = self.get_function_body(&lines, idx);

                // Check for protections
                let has_owner =
                    func_body.contains("onlyOwner") || func_body.contains("require(owner");

                let has_timelock = func_body.contains("timelock") || func_body.contains("delay");

                let validates_impl =
                    func_body.contains("require(") && func_body.contains("!= address(0)");

                if !has_owner {
                    issues.push((
                        (idx + 1) as u32,
                        "Upgrade function missing owner check".to_string(),
                    ));
                } else if !has_timelock {
                    issues.push((
                        (idx + 1) as u32,
                        "Upgrade function lacks time-lock protection".to_string(),
                    ));
                } else if !validates_impl {
                    issues.push((
                        (idx + 1) as u32,
                        "Upgrade function doesn't validate new implementation".to_string(),
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

    fn get_function_body(&self, lines: &[&str], start_idx: usize) -> String {
        let mut body = Vec::new();
        let mut brace_count = 0;
        let mut started = false;

        for line in lines.iter().skip(start_idx) {
            if line.contains("{") {
                started = true;
                brace_count += line.matches('{').count() as i32;
            }
            if started {
                body.push(*line);
                brace_count -= line.matches('}').count() as i32;
                if brace_count <= 0 {
                    break;
                }
            }
        }

        body.join("\n")
    }

    fn get_surrounding_context(&self, lines: &[&str], idx: usize, range: usize) -> String {
        let start = idx.saturating_sub(range);
        let end = (idx + range).min(lines.len());
        lines[start..end].join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = AaAccountTakeoverDetector::new();
        assert_eq!(
            detector.name(),
            "Account Abstraction Takeover Vulnerability"
        );
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }
}
