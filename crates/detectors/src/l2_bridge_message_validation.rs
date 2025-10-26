use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::contract_classification;
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for L2 bridge message validation vulnerabilities
pub struct L2BridgeMessageValidationDetector {
    base: BaseDetector,
}

impl L2BridgeMessageValidationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("l2-bridge-message-validation".to_string()),
                "L2 Bridge Message Validation".to_string(),
                "Detects missing or weak validation in L2↔L1 bridge message processing, including missing Merkle proofs, inadequate finality checks, and replay vulnerabilities".to_string(),
                vec![DetectorCategory::CrossChain, DetectorCategory::L2],
                Severity::Critical,
            ),
        }
    }
}

impl Detector for L2BridgeMessageValidationDetector {
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

        // NEW: Only run this detector on bridge contracts
        if !contract_classification::is_bridge_contract(ctx) {
            return Ok(findings); // Not a bridge - skip analysis
        }

        for function in ctx.get_functions() {
            // Skip internal/private functions
            if !self.is_external_or_public(function) {
                continue;
            }

            let func_source = self.get_function_source(function, ctx);

            // Check for L2→L1 message relay functions
            if self.is_message_relay_function(&function.name.name, &func_source) {
                let issues = self.check_message_validation(&func_source);

                for issue in issues {
                    let message = format!(
                        "Function '{}' relays cross-layer messages without proper validation. {} \
                        This can lead to unauthorized message execution and bridge exploits.",
                        function.name.name, issue
                    );

                    // NEW: High confidence since this IS a bridge contract
                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            function.name.location.start().line() as u32,
                            function.name.location.start().column() as u32,
                            function.name.name.len() as u32,
                        )
                        .with_cwe(345) // CWE-345: Insufficient Verification of Data Authenticity
                        .with_confidence(Confidence::High) // NEW: Set confidence
                        .with_fix_suggestion(format!(
                            "Add proper validation to '{}': \
                            (1) Verify Merkle proof against L1/L2 state root, \
                            (2) Check message finality (block confirmations), \
                            (3) Implement nonce/sequence tracking to prevent replay, \
                            (4) Validate message signatures, \
                            (5) Add cross-chain replay protection.",
                            function.name.name
                        ));

                    findings.push(finding);
                }
            }

            // Check for withdrawal finalization functions
            if self.is_withdrawal_function(&function.name.name, &func_source) {
                let issues = self.check_withdrawal_validation(&func_source);

                for issue in issues {
                    let message = format!(
                        "Function '{}' finalizes withdrawals without proper checks. {} \
                        Missing validation can allow premature or unauthorized withdrawals.",
                        function.name.name, issue
                    );

                    // NEW: High confidence since this IS a bridge contract
                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            function.name.location.start().line() as u32,
                            function.name.location.start().column() as u32,
                            function.name.name.len() as u32,
                        )
                        .with_cwe(345) // CWE-345: Insufficient Verification of Data Authenticity
                        .with_confidence(Confidence::High) // NEW: Set confidence
                        .with_fix_suggestion(format!(
                            "Add finality checks to '{}': \
                            (1) Verify sufficient block confirmations, \
                            (2) Check withdrawal was properly initiated on L2, \
                            (3) Validate proof of L2 state, \
                            (4) Prevent replay with nonce tracking.",
                            function.name.name
                        ));

                    findings.push(finding);
                }
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl L2BridgeMessageValidationDetector {
    fn is_external_or_public(&self, function: &ast::Function<'_>) -> bool {
        function.visibility == ast::Visibility::External
            || function.visibility == ast::Visibility::Public
    }

    fn is_message_relay_function(&self, name: &str, source: &str) -> bool {
        let relay_patterns = [
            "relayMessage",
            "executeMessage",
            "processMessage",
            "bridgeMessage",
            "receiveMessage",
            "deliverMessage",
        ];

        let name_lower = name.to_lowercase();
        relay_patterns
            .iter()
            .any(|pattern| name_lower.contains(&pattern.to_lowercase()))
            || source.contains("message")
                && (source.contains("relay") || source.contains("execute"))
    }

    fn is_withdrawal_function(&self, name: &str, source: &str) -> bool {
        let withdrawal_patterns = [
            "finalizeWithdrawal",
            "completeWithdrawal",
            "withdraw",
            "claimWithdrawal",
            "proveWithdrawal",
        ];

        let name_lower = name.to_lowercase();
        withdrawal_patterns
            .iter()
            .any(|pattern| name_lower.contains(&pattern.to_lowercase()))
            || source.contains("withdrawal") && source.contains("finalize")
    }

    fn check_message_validation(&self, source: &str) -> Vec<String> {
        let mut issues = Vec::new();

        // Pattern 1: Missing Merkle proof validation
        if !source.contains("merkle")
            && !source.contains("proof")
            && !source.contains("verify")
        {
            issues.push(
                "Missing Merkle proof validation. Messages should verify against L2 state root"
                    .to_string(),
            );
        }

        // Pattern 2: No finality check
        if !source.contains("finalized")
            && !source.contains("confirmed")
            && !source.contains("blockNumber")
        {
            issues.push(
                "No finality check detected. Should verify sufficient block confirmations before execution"
                    .to_string(),
            );
        }

        // Pattern 3: Missing nonce/sequence validation
        if !source.contains("nonce") && !source.contains("sequence") && !source.contains("messageId") {
            issues.push(
                "Missing nonce or sequence validation. Vulnerable to replay attacks"
                    .to_string(),
            );
        }

        // Pattern 4: No signature verification
        if source.contains("signature") && !source.contains("recover") && !source.contains("verify") {
            issues.push(
                "Signature present but no verification detected. Should validate message authenticity"
                    .to_string(),
            );
        }

        issues
    }

    fn check_withdrawal_validation(&self, source: &str) -> Vec<String> {
        let mut issues = Vec::new();

        // Pattern 1: No finality check
        if !source.contains("isFinalized")
            && !source.contains("checkFinality")
            && !source.contains("block.timestamp")
            && !source.contains("blockNumber")
        {
            issues.push(
                "No finality check before withdrawal. Should verify L2 state is finalized"
                    .to_string(),
            );
        }

        // Pattern 2: Missing proof validation
        if !source.contains("proof") && !source.contains("merkle") {
            issues.push(
                "Missing withdrawal proof validation. Should verify withdrawal was initiated on L2"
                    .to_string(),
            );
        }

        // Pattern 3: No replay protection
        if !source.contains("withdrawalId")
            && !source.contains("nonce")
            && !source.contains("claimed")
            && !source.contains("processed")
        {
            issues.push(
                "Missing replay protection. Withdrawals could be claimed multiple times"
                    .to_string(),
            );
        }

        issues
    }

    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            source_lines[start..=end].join("\n")
        } else {
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = L2BridgeMessageValidationDetector::new();
        assert_eq!(detector.name(), "L2 Bridge Message Validation");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
        assert_eq!(detector.id().0, "l2-bridge-message-validation");
    }

    #[test]
    fn test_is_message_relay_function() {
        let detector = L2BridgeMessageValidationDetector::new();

        assert!(detector.is_message_relay_function("relayMessageFromL2", ""));
        assert!(detector.is_message_relay_function("executeMessage", ""));
        assert!(detector.is_message_relay_function("processMessage", ""));
        assert!(!detector.is_message_relay_function("deposit", ""));
    }

    #[test]
    fn test_is_withdrawal_function() {
        let detector = L2BridgeMessageValidationDetector::new();

        assert!(detector.is_withdrawal_function("finalizeWithdrawal", ""));
        assert!(detector.is_withdrawal_function("completeWithdrawal", ""));
        assert!(detector.is_withdrawal_function("withdraw", ""));
        assert!(!detector.is_withdrawal_function("deposit", ""));
    }
}
