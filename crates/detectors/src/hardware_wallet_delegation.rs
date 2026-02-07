use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for unsafe EIP-7702 delegation patterns in hardware wallets
pub struct HardwareWalletDelegationDetector {
    base: BaseDetector,
}

impl Default for HardwareWalletDelegationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareWalletDelegationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("hardware-wallet-delegation".to_string()),
                "Hardware Wallet Delegation Vulnerability".to_string(),
                "Detects unsafe EIP-7702 delegation patterns that can brick hardware wallets or compromise security when delegating EOA control".to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Validation],
                Severity::High,
            ),
        }
    }
}

impl Detector for HardwareWalletDelegationDetector {
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

        let contract_source = ctx.source_code.as_str();

        // Check for EIP-7702 or delegation patterns
        if !self.is_delegation_contract(contract_source) {
            return Ok(findings);
        }

        // Pattern 1: Hardcoded relayer dependency
        if let Some(relayer_issues) = self.check_hardcoded_relayer(contract_source) {
            for (line, issue) in relayer_issues {
                let message = format!(
                    "EIP-7702 delegation hardcodes relayer dependency. {} \
                    Hardcoded relayers create single point of failure - if relayer goes offline, hardware wallet account becomes permanently bricked.",
                    issue
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 0, 40)
                    .with_cwe(1188) // CWE-1188: Initialization of a Resource with an Insecure Default
                    .with_cwe(665) // CWE-665: Improper Initialization
                    .with_fix_suggestion(
                        "Avoid hardcoded relayer dependencies: \
                    (1) Support multiple relayer backends, \
                    (2) Allow relayer switching via user signature, \
                    (3) Implement fallback to direct transaction submission, \
                    (4) Never require single trusted relayer, \
                    (5) Follow EIP-7702 decentralization principles."
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        // Pattern 2: Unsafe delegation without recovery
        if let Some(recovery_issues) = self.check_delegation_recovery(contract_source) {
            for (line, issue) in recovery_issues {
                let message = format!(
                    "Delegation contract missing recovery mechanism. {} \
                    Without recovery, hardware wallet users lose access if delegation target is compromised or becomes incompatible.",
                    issue
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 0, 40)
                    .with_cwe(672) // CWE-672: Operation on a Resource after Expiration or Release
                    .with_cwe(404) // CWE-404: Improper Resource Shutdown or Release
                    .with_fix_suggestion(
                        "Implement delegation recovery: \
                    (1) Add removeDelegation function, \
                    (2) Allow switching delegation targets, \
                    (3) Implement emergency mode fallback, \
                    (4) Support direct EOA transactions, \
                    (5) Require hardware wallet signature for changes."
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        // Pattern 3: Missing asset protection
        if let Some(asset_issues) = self.check_asset_protection(contract_source) {
            for (line, issue) in asset_issues {
                let message = format!(
                    "Delegation gives full control over all EOA assets. {} \
                    Unrestricted delegation allows malicious code to drain all ETH and tokens from hardware wallet.",
                    issue
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 0, 40)
                    .with_cwe(269) // CWE-269: Improper Privilege Management
                    .with_cwe(250) // CWE-250: Execution with Unnecessary Privileges
                    .with_fix_suggestion(
                        "Limit delegation scope: \
                    (1) Implement per-asset spending limits, \
                    (2) Add transaction value restrictions, \
                    (3) Whitelist approved operations only, \
                    (4) Require two-step approval for large transfers, \
                    (5) Use time-locked withdrawal mechanisms."
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        // Pattern 4: Unsafe code update mechanism
        if let Some(update_issues) = self.check_code_update_safety(contract_source) {
            for (line, issue) in update_issues {
                let message = format!(
                    "Delegation code can be updated without hardware wallet approval. {} \
                    Automatic updates bypass hardware wallet security, allowing silent replacement with malicious code.",
                    issue
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 0, 40)
                    .with_cwe(494) // CWE-494: Download of Code Without Integrity Check
                    .with_cwe(345) // CWE-345: Insufficient Verification of Data Authenticity
                    .with_fix_suggestion(
                        "Secure code update mechanism: \
                    (1) Require hardware wallet signature for updates, \
                    (2) Display delegation changes on device, \
                    (3) Implement update time-lock period, \
                    (4) Validate new code before activation, \
                    (5) Provide update preview on hardware wallet screen."
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        // Pattern 5: Missing signature validation
        if let Some(sig_issues) = self.check_signature_validation(contract_source) {
            for (line, issue) in sig_issues {
                let message = format!(
                    "Delegation operations lack hardware wallet signature validation. {} \
                    Missing signature checks allow unauthorized changes to delegation configuration.",
                    issue
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 0, 40)
                    .with_cwe(306) // CWE-306: Missing Authentication for Critical Function
                    .with_cwe(862) // CWE-862: Missing Authorization
                    .with_fix_suggestion(
                        "Enforce hardware wallet signatures: \
                    (1) Require ECDSA signature from hardware wallet, \
                    (2) Validate signer matches EOA owner, \
                    (3) Include nonce to prevent replay, \
                    (4) Display operation details on hardware device, \
                    (5) Follow EIP-191 or EIP-712 signing standards."
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        // Pattern 6: Trusted delegate without validation
        if !contract_source.contains("supportsInterface")
            && contract_source.contains("delegatecall")
        {
            let message = "Delegation target not validated for interface compatibility. \
                Missing interface validation can cause hardware wallet to delegate to incompatible code, bricking the account.".to_string();

            let finding = self
                .base
                .create_finding(ctx, message, 1, 0, 40)
                .with_cwe(20) // CWE-20: Improper Input Validation
                .with_cwe(704) // CWE-704: Incorrect Type Conversion or Cast
                .with_fix_suggestion(
                    "Validate delegation target: \
                (1) Check supportsInterface for EIP-165, \
                (2) Verify required functions exist, \
                (3) Test delegation in simulation first, \
                (4) Implement delegation preview/confirmation, \
                (5) Maintain whitelist of verified delegation targets."
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

impl HardwareWalletDelegationDetector {
    fn is_delegation_contract(&self, source: &str) -> bool {
        // Phase 53 FP Reduction: Skip standard proxy contracts
        // Proxy contracts use delegatecall but are NOT EIP-7702 delegation contracts
        let is_proxy_contract = source.contains("abstract contract Proxy")
            || source.contains("contract Proxy ")
            || source.contains("TransparentUpgradeableProxy")
            || source.contains("UUPSUpgradeable")
            || source.contains("BeaconProxy")
            || source.contains("ERC1967")
            || source.contains("function _implementation(")
            || (source.contains("function _delegate(") && source.contains("fallback()"));

        if is_proxy_contract {
            return false;
        }

        // Only flag as delegation contract if it has EIP-7702 specific patterns
        // Not just any delegatecall usage
        source.contains("EIP-7702")
            || source.contains("EIP7702")
            || source.contains("setCode(")
            || (source.contains("delegation")
                && (source.contains("setDelegation")
                    || source.contains("removeDelegation")
                    || source.contains("enableDelegation")))
    }

    fn check_hardcoded_relayer(&self, source: &str) -> Option<Vec<(u32, String)>> {
        let lines: Vec<&str> = source.lines().collect();
        let mut issues = Vec::new();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Check for hardcoded relayer addresses
            if (trimmed.contains("relayer") || trimmed.contains("RELAYER"))
                && (trimmed.contains("constant") || trimmed.contains("immutable"))
                && trimmed.contains("= 0x")
            {
                issues.push((
                    (idx + 1) as u32,
                    "Hardcoded relayer address creates single point of failure".to_string(),
                ));
            }

            // Check for require(msg.sender == relayer) without alternatives
            if trimmed.contains("require(msg.sender == ")
                && (trimmed.contains("relayer") || trimmed.contains("RELAYER"))
            {
                // Check if there's any fallback mechanism nearby
                let context = self.get_surrounding_context(&lines, idx, 5);
                if !context.contains("||") && !context.contains("else") {
                    issues.push((
                        (idx + 1) as u32,
                        "Single relayer requirement without fallback mechanism".to_string(),
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

    fn check_delegation_recovery(&self, source: &str) -> Option<Vec<(u32, String)>> {
        let has_delegation = source.contains("delegatecall") || source.contains("setDelegation");

        if !has_delegation {
            return None;
        }

        // Check for recovery mechanisms
        let has_remove = source.contains("removeDelegation")
            || source.contains("clearDelegation")
            || source.contains("revokeDelegation");

        let has_switch = source.contains("switchDelegation") || source.contains("updateDelegation");

        let has_emergency = source.contains("emergency") || source.contains("recover");

        if !has_remove && !has_switch && !has_emergency {
            return Some(vec![(
                1,
                "No recovery mechanism found - users cannot undo delegation".to_string(),
            )]);
        }

        None
    }

    fn check_asset_protection(&self, source: &str) -> Option<Vec<(u32, String)>> {
        let lines: Vec<&str> = source.lines().collect();
        let mut issues = Vec::new();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Check for unrestricted value transfers
            if trimmed.contains("delegatecall") {
                let func_context = self.get_function_context(&lines, idx);

                // Check for value limits
                let has_limit = func_context.contains("maxAmount")
                    || func_context.contains("limit")
                    || func_context.contains("cap")
                    || func_context.contains("require(amount <")
                    || func_context.contains("require(value <");

                if !has_limit
                    && (func_context.contains(".value(") || func_context.contains(".transfer("))
                {
                    issues.push((
                        (idx + 1) as u32,
                        "Delegation allows unrestricted asset transfers without limits".to_string(),
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

    fn check_code_update_safety(&self, source: &str) -> Option<Vec<(u32, String)>> {
        let lines: Vec<&str> = source.lines().collect();
        let mut issues = Vec::new();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function")
                && (trimmed.contains("updateDelegation")
                    || trimmed.contains("setDelegation")
                    || trimmed.contains("changeDelegation"))
            {
                let func_body = self.get_function_body(&lines, idx);

                // Check for hardware wallet signature verification
                let has_hw_sig = func_body.contains("signature")
                    && (func_body.contains("ecrecover") || func_body.contains("ECDSA.recover"));

                // Check for timelock
                let has_timelock = func_body.contains("timelock")
                    || func_body.contains("delay")
                    || func_body.contains("block.timestamp");

                if !has_hw_sig {
                    issues.push((
                        (idx + 1) as u32,
                        "Delegation update lacks hardware wallet signature verification"
                            .to_string(),
                    ));
                } else if !has_timelock {
                    issues.push((
                        (idx + 1) as u32,
                        "Delegation update lacks time-lock protection".to_string(),
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

    fn check_signature_validation(&self, source: &str) -> Option<Vec<(u32, String)>> {
        let lines: Vec<&str> = source.lines().collect();
        let mut issues = Vec::new();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for critical delegation functions
            if trimmed.contains("function")
                && (trimmed.contains("setDelegation")
                    || trimmed.contains("enableDelegation")
                    || trimmed.contains("delegate"))
                && trimmed.contains("external")
            {
                let func_body = self.get_function_body(&lines, idx);

                // Check for signature validation
                let has_sig_check = func_body.contains("ecrecover")
                    || func_body.contains("ECDSA.recover")
                    || func_body.contains("SignatureChecker");

                if !has_sig_check {
                    issues.push((
                        (idx + 1) as u32,
                        "Critical delegation function missing signature validation".to_string(),
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

    fn get_surrounding_context(&self, lines: &[&str], idx: usize, range: usize) -> String {
        let start = idx.saturating_sub(range);
        let end = (idx + range).min(lines.len());
        lines[start..end].join(" ")
    }

    fn get_function_context(&self, lines: &[&str], idx: usize) -> String {
        // Get the function containing this line
        let mut func_start = idx;
        for i in (0..idx).rev() {
            if lines[i].trim().contains("function ") {
                func_start = i;
                break;
            }
        }
        self.get_function_body(lines, func_start)
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = HardwareWalletDelegationDetector::new();
        assert_eq!(detector.name(), "Hardware Wallet Delegation Vulnerability");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
