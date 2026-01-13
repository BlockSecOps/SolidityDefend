use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for EIP-1967 storage slot compliance
///
/// EIP-1967 defines standard storage slots for proxy contracts:
/// - Implementation: bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
///   = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
/// - Admin: bytes32(uint256(keccak256('eip1967.proxy.admin')) - 1)
///   = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103
/// - Beacon: bytes32(uint256(keccak256('eip1967.proxy.beacon')) - 1)
///   = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50
///
/// Using non-standard slots causes compatibility issues with block explorers,
/// wallets, and other tooling.
pub struct Eip1967SlotComplianceDetector {
    base: BaseDetector,
}

impl Default for Eip1967SlotComplianceDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Eip1967SlotComplianceDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("eip1967-slot-compliance"),
                "EIP-1967 Storage Slot Compliance".to_string(),
                "Detects proxy contracts using non-standard storage slots for implementation, \
                 admin, or beacon addresses instead of EIP-1967 compliant slots"
                    .to_string(),
                vec![DetectorCategory::Upgradeable, DetectorCategory::BestPractices],
                Severity::Medium,
            ),
        }
    }

    /// Standard EIP-1967 slot values
    fn get_standard_slots(&self) -> Vec<(&'static str, &'static str, &'static str)> {
        vec![
            (
                "implementation",
                "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
                "eip1967.proxy.implementation",
            ),
            (
                "admin",
                "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
                "eip1967.proxy.admin",
            ),
            (
                "beacon",
                "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
                "eip1967.proxy.beacon",
            ),
        ]
    }

    /// Check if contract is a proxy
    fn is_proxy_contract(&self, source: &str) -> bool {
        source.contains("Proxy")
            || source.contains("delegatecall")
            || source.contains("_implementation")
            || source.contains("IMPLEMENTATION_SLOT")
            || source.contains("_fallback()")
    }

    /// Find storage slot definitions
    fn find_slot_definitions(&self, source: &str) -> Vec<(u32, String, String, String)> {
        let mut slots = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            // Look for constant/immutable bytes32 slot definitions
            if (line.contains("bytes32") || line.contains("uint256"))
                && (line.contains("constant") || line.contains("immutable"))
                && (line.to_lowercase().contains("slot")
                    || line.to_lowercase().contains("position")
                    || line.to_lowercase().contains("_implementation")
                    || line.to_lowercase().contains("_admin")
                    || line.to_lowercase().contains("_beacon"))
            {
                if let Some((name, slot_type, value)) = self.extract_slot_info(line) {
                    slots.push(((i + 1) as u32, name, slot_type, value));
                }
            }

            // Also check for inline keccak256 slot definitions
            if line.contains("keccak256") && line.contains("slot") {
                if let Some(slot_name) = self.extract_keccak_slot_name(line) {
                    slots.push((
                        (i + 1) as u32,
                        slot_name.clone(),
                        "keccak256".to_string(),
                        slot_name,
                    ));
                }
            }
        }

        slots
    }

    /// Extract slot information from line
    fn extract_slot_info(&self, line: &str) -> Option<(String, String, String)> {
        let trimmed = line.trim();

        // Extract variable name
        let mut name = String::new();
        if let Some(eq_pos) = trimmed.find('=') {
            let before_eq = &trimmed[..eq_pos];
            let words: Vec<&str> = before_eq.split_whitespace().collect();
            if let Some(last) = words.last() {
                name = last.to_string();
            }
        }

        // Determine slot type (implementation, admin, beacon)
        let slot_type = if trimmed.to_lowercase().contains("implementation") {
            "implementation"
        } else if trimmed.to_lowercase().contains("admin") {
            "admin"
        } else if trimmed.to_lowercase().contains("beacon") {
            "beacon"
        } else {
            "unknown"
        };

        // Extract value
        let mut value = String::new();
        if let Some(eq_pos) = trimmed.find('=') {
            value = trimmed[eq_pos + 1..]
                .trim()
                .trim_end_matches(';')
                .to_string();
        }

        if !name.is_empty() && !value.is_empty() {
            Some((name, slot_type.to_string(), value))
        } else {
            None
        }
    }

    /// Extract slot name from keccak256 pattern
    fn extract_keccak_slot_name(&self, line: &str) -> Option<String> {
        // Look for patterns like keccak256("my.slot.name")
        if let Some(start) = line.find("keccak256(") {
            let after_keccak = &line[start + 10..];
            if let Some(quote_start) = after_keccak.find('"') {
                let after_quote = &after_keccak[quote_start + 1..];
                if let Some(quote_end) = after_quote.find('"') {
                    return Some(after_quote[..quote_end].to_string());
                }
            }
            if let Some(quote_start) = after_keccak.find('\'') {
                let after_quote = &after_keccak[quote_start + 1..];
                if let Some(quote_end) = after_quote.find('\'') {
                    return Some(after_quote[..quote_end].to_string());
                }
            }
        }
        None
    }

    /// Check if slot value matches EIP-1967 standard
    fn check_slot_compliance(&self, slot_type: &str, value: &str) -> Option<String> {
        let standard_slots = self.get_standard_slots();

        for (std_type, std_value, std_name) in &standard_slots {
            if slot_type == *std_type {
                // Check if value matches standard
                let value_lower = value.to_lowercase();
                if value_lower.contains(&std_value.to_lowercase()) {
                    return None; // Compliant
                }

                // Check if it's using the standard keccak pattern
                if value_lower.contains(&std_name.to_lowercase()) {
                    return None; // Compliant (using named pattern)
                }

                // Non-compliant - return expected value
                return Some(format!(
                    "Expected EIP-1967 slot for {}: {} (keccak256(\"{}\") - 1)",
                    std_type, std_value, std_name
                ));
            }
        }

        None // Unknown slot type, don't flag
    }

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for Eip1967SlotComplianceDetector {
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

        // Only check proxy contracts
        if !self.is_proxy_contract(source) {
            return Ok(findings);
        }

        // Find slot definitions
        let slots = self.find_slot_definitions(source);

        for (line, name, slot_type, value) in slots {
            // Check compliance
            if let Some(expected) = self.check_slot_compliance(&slot_type, &value) {
                let message = format!(
                    "Proxy contract '{}' uses non-standard storage slot '{}' for {} address. \
                     {}. Non-EIP-1967 slots cause compatibility issues with block explorers, \
                     wallets (like MetaMask), and security tools.",
                    contract_name, name, slot_type, expected
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 0, name.len() as u32)
                    .with_cwe(573) // CWE-573: Improper Following of Specification by Caller
                    .with_cwe(710) // CWE-710: Improper Adherence to Coding Standards
                    .with_confidence(Confidence::Medium)
                    .with_fix_suggestion(format!(
                        "Use EIP-1967 standard storage slots for proxy contracts:\n\n\
                         // Implementation slot\n\
                         bytes32 internal constant _IMPLEMENTATION_SLOT = \n\
                             0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;\n\n\
                         // Admin slot\n\
                         bytes32 internal constant _ADMIN_SLOT = \n\
                             0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;\n\n\
                         // Beacon slot\n\
                         bytes32 internal constant _BEACON_SLOT = \n\
                             0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;\n\n\
                         See EIP-1967: https://eips.ethereum.org/EIPS/eip-1967"
                    ));

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
        let detector = Eip1967SlotComplianceDetector::new();
        assert_eq!(detector.name(), "EIP-1967 Storage Slot Compliance");
        assert_eq!(detector.default_severity(), Severity::Medium);
    }

    #[test]
    fn test_is_proxy_contract() {
        let detector = Eip1967SlotComplianceDetector::new();
        assert!(detector.is_proxy_contract("contract MyProxy is Proxy { function _implementation() }"));
        assert!(detector.is_proxy_contract("function _fallback() internal { delegatecall(impl) }"));
        assert!(!detector.is_proxy_contract("contract SimpleToken { }"));
    }

    #[test]
    fn test_slot_compliance() {
        let detector = Eip1967SlotComplianceDetector::new();

        // Standard slot should pass
        let result = detector.check_slot_compliance(
            "implementation",
            "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
        );
        assert!(result.is_none());

        // Non-standard slot should fail
        let result = detector.check_slot_compliance(
            "implementation",
            "keccak256(\"my.custom.implementation.slot\")",
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_extract_keccak_slot_name() {
        let detector = Eip1967SlotComplianceDetector::new();

        let name =
            detector.extract_keccak_slot_name("bytes32 slot = keccak256(\"eip1967.proxy.implementation\");");
        assert_eq!(name, Some("eip1967.proxy.implementation".to_string()));
    }
}
