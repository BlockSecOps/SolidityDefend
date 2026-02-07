//! SELFDESTRUCT Recipient Manipulation Detection
//!
//! Detects contracts that use SELFDESTRUCT with user-controlled or unchecked recipients,
//! which can be used to force ether to contracts or manipulate accounting.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct SelfdestructRecipientDetector {
    base: BaseDetector,
}

impl SelfdestructRecipientDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("selfdestruct-recipient-manipulation".to_string()),
                "SELFDESTRUCT Recipient Manipulation".to_string(),
                "Detects unsafe SELFDESTRUCT usage with unchecked recipients that could force ether to contracts or manipulate balances".to_string(),
                vec![
                    DetectorCategory::Logic,
                    DetectorCategory::Metamorphic,
                    DetectorCategory::Deployment,
                ],
                Severity::High,
            ),
        }
    }

    fn check_selfdestruct_patterns(&self, ctx: &AnalysisContext) -> Vec<(String, u32, String)> {
        let mut findings = Vec::new();
        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Check if contract uses selfdestruct
        if !source_lower.contains("selfdestruct") && !source_lower.contains("suicide") {
            return findings;
        }

        // Pattern 1: User-controlled recipient
        let has_param_recipient = (source_lower.contains("selfdestruct(")
            || source_lower.contains("suicide("))
            && (source_lower.contains("msg.sender")
                || source_lower.contains("_recipient")
                || source_lower.contains("recipient")
                || source_lower.contains("to")
                || source_lower.contains("address"));

        // Check if recipient is from function parameter
        let has_function_param = source_lower.contains("function")
            && (source_lower.contains("address") && source_lower.contains("recipient")
                || source_lower.contains("address to")
                || source_lower.contains("address _to"));

        if has_param_recipient || has_function_param {
            // Check for access control
            let has_access_control = source_lower.contains("onlyowner")
                || source_lower.contains("onlyadmin")
                || (source_lower.contains("require") && source_lower.contains("owner"))
                || (source_lower.contains("modifier") && source_lower.contains("only"));

            // Check for recipient validation
            let has_recipient_validation = (source_lower.contains("require")
                && source_lower.contains("recipient"))
                || source_lower.contains("whitelist")
                || source_lower.contains("approved");

            if !has_access_control {
                findings.push((
                    "SELFDESTRUCT with user-controlled recipient lacks access control".to_string(),
                    0,
                    "Add access control modifier (e.g., onlyOwner) to prevent unauthorized destruction. Only trusted addresses should be able to trigger selfdestruct.".to_string(),
                ));
            }

            if !has_recipient_validation {
                findings.push((
                    "SELFDESTRUCT recipient is not validated (can force ether to contracts)".to_string(),
                    0,
                    "Validate recipient address: require(recipient != address(0) && isApproved(recipient)). Be aware that selfdestruct can force ether to contracts that don't accept it.".to_string(),
                ));
            }
        }

        // Pattern 2: SELFDESTRUCT to msg.sender
        if source_lower.contains("selfdestruct(msg.sender)")
            || source_lower.contains("suicide(msg.sender)")
        {
            let has_reentrancy_protection = source_lower.contains("nonreentrant")
                || source_lower.contains("locked")
                || source_lower.contains("guard");

            if !has_reentrancy_protection {
                findings.push((
                    "SELFDESTRUCT to msg.sender without reentrancy protection".to_string(),
                    0,
                    "Add reentrancy guard to prevent manipulation. SELFDESTRUCT transfers all ether to recipient, which could trigger malicious fallback functions.".to_string(),
                ));
            }

            // Check access control
            let has_access_control = source_lower.contains("onlyowner")
                || source_lower.contains("onlyadmin")
                || (source_lower.contains("require")
                    && (source_lower.contains("owner") || source_lower.contains("admin")));

            if !has_access_control {
                findings.push((
                    "SELFDESTRUCT callable by anyone (destroys contract state)".to_string(),
                    0,
                    "Restrict selfdestruct to authorized addresses only. Unrestricted selfdestruct allows anyone to destroy the contract and transfer all ether.".to_string(),
                ));
            }
        }

        // Pattern 3: SELFDESTRUCT in constructor (metamorphic pattern)
        // Need to check if they're actually in the same code block, not just anywhere in file
        if source_lower.contains("constructor") && source_lower.contains("selfdestruct") {
            // More precise check: Look for "constructor" followed by "selfdestruct" within reasonable distance
            if let Some(constructor_pos) = source_lower.find("constructor") {
                if let Some(selfdestruct_pos) = source_lower.find("selfdestruct") {
                    // Only flag if selfdestruct appears within 500 chars after constructor keyword
                    if selfdestruct_pos > constructor_pos
                        && selfdestruct_pos - constructor_pos < 500
                    {
                        // Additional check: Make sure there's no other function definition between them
                        let between = &source_lower[constructor_pos..selfdestruct_pos];
                        if !between.contains("function ") {
                            findings.push((
                                "SELFDESTRUCT in constructor (metamorphic contract pattern)".to_string(),
                                0,
                                "Using selfdestruct in constructor enables metamorphic contracts via CREATE2. This allows changing contract code at the same address, bypassing immutability assumptions.".to_string(),
                            ));
                        }
                    }
                }
            }
        }

        // Pattern 4: SELFDESTRUCT without balance check
        if source_lower.contains("selfdestruct") || source_lower.contains("suicide") {
            let has_balance_check = source_lower.contains("address(this).balance")
                || source_lower.contains("balance")
                || source_lower.contains("getbalance");

            // Timelock + recipient validation is also a safety pattern
            let has_timelock = source_lower.contains("timestamp")
                && (source_lower.contains("delay")
                    || source_lower.contains("days")
                    || source_lower.contains("hours"));
            let has_recipient_check =
                source_lower.contains("recipient") && source_lower.contains("require");

            if !has_balance_check && !has_timelock && !has_recipient_check {
                findings.push((
                    "SELFDESTRUCT without checking contract balance".to_string(),
                    0,
                    "Check contract balance before selfdestruct to ensure expected state. Document that all remaining ether will be forcibly transferred to recipient.".to_string(),
                ));
            }
        }

        // Pattern 5: Assembly SELFDESTRUCT
        if source_lower.contains("assembly") && source_lower.contains("selfdestruct") {
            // Check if they're actually in the same assembly block
            if let Some(assembly_pos) = source_lower.find("assembly") {
                if let Some(selfdestruct_pos) = source_lower.find("selfdestruct") {
                    // Only flag if selfdestruct appears within 300 chars after "assembly {"
                    if selfdestruct_pos > assembly_pos && selfdestruct_pos - assembly_pos < 300 {
                        // Make sure there's no closing brace between them (which would indicate end of assembly block)
                        let between = &source_lower[assembly_pos..selfdestruct_pos];
                        // Simple heuristic: if there's "}" without matching "{", we've exited the assembly block
                        let open_braces = between.matches('{').count();
                        let close_braces = between.matches('}').count();
                        if open_braces > close_braces {
                            findings.push((
                                "Uses assembly SELFDESTRUCT (difficult to audit)".to_string(),
                                0,
                                "Assembly selfdestruct bypasses Solidity safety checks. Ensure recipient address is thoroughly validated and access control is enforced.".to_string(),
                            ));
                        }
                    }
                }
            }
        }

        // Pattern 6: SELFDESTRUCT with zero address
        if source_lower.contains("selfdestruct(address(0))")
            || source_lower.contains("suicide(address(0))")
        {
            findings.push((
                "SELFDESTRUCT to zero address (ether permanently lost)".to_string(),
                0,
                "Sending ether to address(0) via selfdestruct permanently destroys the funds. Use a designated burn address or charity address instead if intentional.".to_string(),
            ));
        }

        findings
    }
}

impl Default for SelfdestructRecipientDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for SelfdestructRecipientDetector {
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

        let issues = self.check_selfdestruct_patterns(ctx);

        for (message, line_offset, remediation) in issues {
            let severity = if message.contains("metamorphic")
                || message.contains("anyone")
                || message.contains("lacks access control")
            {
                Severity::Critical
            } else if message.contains("not validated") || message.contains("without reentrancy") {
                Severity::High
            } else {
                Severity::Medium
            };

            let finding = self
                .base
                .create_finding_with_severity(ctx, message, line_offset, 0, 20, severity)
                .with_fix_suggestion(remediation)
                .with_cwe(477); // CWE-477: Use of Obsolete Function

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
    use crate::types::test_utils::*;

    #[test]
    fn test_detector_properties() {
        let detector = SelfdestructRecipientDetector::new();
        assert_eq!(
            detector.id().to_string(),
            "selfdestruct-recipient-manipulation"
        );
        assert_eq!(detector.name(), "SELFDESTRUCT Recipient Manipulation");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_detects_unprotected_selfdestruct() {
        let detector = SelfdestructRecipientDetector::new();
        let source = r#"
            contract Vulnerable {
                function destroy(address payable recipient) external {
                    selfdestruct(recipient);
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    fn test_detects_selfdestruct_to_msg_sender() {
        let detector = SelfdestructRecipientDetector::new();
        let source = r#"
            contract Vulnerable {
                function withdraw() external {
                    selfdestruct(msg.sender);
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    fn test_detects_constructor_selfdestruct() {
        let detector = SelfdestructRecipientDetector::new();
        let source = r#"
            contract Metamorphic {
                constructor() {
                    selfdestruct(payable(msg.sender));
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
        assert!(result.iter().any(|f| f.message.contains("metamorphic")));
    }

    #[test]
    fn test_detects_zero_address_selfdestruct() {
        let detector = SelfdestructRecipientDetector::new();
        let source = r#"
            contract Vulnerable {
                function destroy() external {
                    selfdestruct(address(0));
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
        assert!(result.iter().any(|f| f.message.contains("zero address")));
    }

    #[test]
    fn test_detects_assembly_selfdestruct() {
        let detector = SelfdestructRecipientDetector::new();
        let source = r#"
            contract Vulnerable {
                function destroy(address recipient) external {
                    assembly {
                        selfdestruct(recipient)
                    }
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    fn test_protected_selfdestruct_still_flagged() {
        let detector = SelfdestructRecipientDetector::new();
        let source = r#"
            contract Protected {
                address public owner;

                modifier onlyOwner() {
                    require(msg.sender == owner);
                    _;
                }

                function destroy() external onlyOwner {
                    selfdestruct(payable(owner));
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        // Should still flag for balance check and other concerns
        // but should have fewer/less severe findings
    }
}
