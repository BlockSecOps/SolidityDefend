use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for proxy storage collision vulnerabilities
///
/// This detector identifies storage layout conflicts between proxy and implementation
/// contracts that can lead to state corruption and unexpected behavior.
///
/// **Vulnerability:** CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes)
/// **Severity:** High
///
/// ## Description
///
/// Storage collisions occur when:
/// 1. Proxy contract uses non-standard storage slots
/// 2. Implementation contract's storage overlaps with proxy's storage
/// 3. Upgrades change storage layout incompatibly
/// 4. EIP-1967 slots are not used properly
///
pub struct ProxyStorageCollisionDetector {
    base: BaseDetector,
}

impl Default for ProxyStorageCollisionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyStorageCollisionDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("proxy-storage-collision".to_string()),
                "Proxy Storage Collision".to_string(),
                "Detects storage layout conflicts between proxy and implementation contracts that can corrupt state"
                    .to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::AccessControl],
                Severity::High,
            ),
        }
    }
}

impl Detector for ProxyStorageCollisionDetector {
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

        // Check for storage collision risks in the contract
        if let Some(risk_description) = self.has_storage_collision_risk(ctx) {
            let message = format!(
                "Contract '{}' has potential proxy storage collision vulnerability. {} \
                Storage collisions can corrupt critical state variables and lead to fund loss.",
                ctx.contract.name.name, risk_description
            );

            let finding = self
                .base
                .create_finding(
                    ctx,
                    message,
                    ctx.contract.name.location.start().line() as u32,
                    ctx.contract.name.location.start().column() as u32,
                    ctx.contract.name.name.len() as u32,
                )
                .with_cwe(1321) // CWE-1321: Improperly Controlled Modification of Object Prototype Attributes
                .with_cwe(119) // CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
                .with_fix_suggestion(
                    "Use EIP-1967 standard storage slots for proxy-specific variables. \
                    Reserve storage slots using 'bytes32 private constant SLOT = keccak256(...)'. \
                    Avoid declaring storage variables at the beginning of proxy contracts. \
                    Use upgradeable patterns like OpenZeppelin's transparent proxy."
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

impl ProxyStorageCollisionDetector {
    /// Check if contract has storage collision risks
    fn has_storage_collision_risk(&self, ctx: &AnalysisContext) -> Option<String> {
        // Get contract source for analysis
        let contract_source = &ctx.source_code;

        // Check if this looks like a proxy contract
        let is_proxy = self.is_proxy_contract(ctx, contract_source);

        if !is_proxy {
            return None;
        }

        // FP Reduction: If proxy uses proper EIP-1967 storage patterns, it's safe
        // OpenZeppelin proxies and other audited implementations use these correctly
        if self.uses_eip1967_storage(contract_source) {
            return None;
        }

        // Check for non-EIP-1967 storage in proxy
        if self.has_non_standard_storage(ctx, contract_source) {
            return Some(
                "Proxy contract declares storage variables without using EIP-1967 slots, \
                risking collision with implementation contract storage."
                    .to_string(),
            );
        }

        // Check for direct storage slot usage without proper offsetting
        if self.has_unsafe_storage_slots(contract_source) {
            return Some(
                "Contract uses assembly storage operations (sstore/sload) without proper \
                slot collision prevention. This can overwrite critical proxy state."
                    .to_string(),
            );
        }

        // Check for missing storage gap in upgradeable contracts
        if self.missing_storage_gap(ctx, contract_source) {
            return Some(
                "Upgradeable contract is missing storage gap reservation. \
                Future upgrades may cause storage layout collisions."
                    .to_string(),
            );
        }

        None
    }

    /// Check if this is a proxy contract
    /// Requires strong signals to avoid FPs - not just any delegatecall usage
    fn is_proxy_contract(&self, ctx: &AnalysisContext, source: &str) -> bool {
        // Check contract name for proxy patterns
        let name_lower = ctx.contract.name.name.to_lowercase();
        let has_proxy_name = name_lower.contains("proxy")
            || name_lower.contains("upgradeable")
            || name_lower == "erc1967proxy"
            || name_lower == "transparentupgradeableproxy";

        // Strong proxy signals (EIP-1967 or explicit proxy patterns)
        let has_proxy_patterns = source.contains("IMPLEMENTATION_SLOT")
            || source.contains("_IMPLEMENTATION_SLOT")
            || source.contains("_ADMIN_SLOT")
            || source.contains("eip1967")
            || source.contains("EIP1967")
            || source.contains("_fallback")
            || source.contains("_delegate")
            || (source.contains("implementation()") && source.contains("delegatecall"));

        // Must have both delegatecall AND proxy-specific patterns
        // Just having delegatecall doesn't make something a proxy
        let has_delegatecall = source.contains("delegatecall");

        // A contract is a proxy if:
        // 1. It has proxy in name AND delegatecall, OR
        // 2. It has explicit proxy storage slots/patterns
        (has_proxy_name && has_delegatecall) || has_proxy_patterns
    }

    /// Check if proxy uses proper EIP-1967 storage patterns
    /// OpenZeppelin and other audited proxies use these patterns correctly
    fn uses_eip1967_storage(&self, source: &str) -> bool {
        let lower = source.to_lowercase();

        // Check for EIP-1967 storage slot constants
        // These are the standard slots defined in EIP-1967
        let has_implementation_slot = source
            .contains("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
            || source.contains("IMPLEMENTATION_SLOT")
            || source.contains("_IMPLEMENTATION_SLOT");

        let has_admin_slot = source
            .contains("0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103")
            || source.contains("ADMIN_SLOT")
            || source.contains("_ADMIN_SLOT");

        let has_beacon_slot = source
            .contains("0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50")
            || source.contains("BEACON_SLOT")
            || source.contains("_BEACON_SLOT");

        // Check for OpenZeppelin proxy patterns
        let is_oz_proxy = source.contains("@openzeppelin")
            || source.contains("openzeppelin-contracts")
            || lower.contains("erc1967upgrade")
            || lower.contains("erc1967utils")
            || lower.contains("storageSlot.getAddressSlot");

        // Check for proper keccak256 slot calculation
        let has_proper_slot_calc = source.contains("keccak256(\"eip1967.")
            || source.contains("keccak256('eip1967.")
            || source.contains("bytes32(uint256(keccak256");

        has_implementation_slot
            || has_admin_slot
            || has_beacon_slot
            || is_oz_proxy
            || has_proper_slot_calc
    }

    /// Check if proxy has non-standard storage variables
    fn has_non_standard_storage(&self, ctx: &AnalysisContext, source: &str) -> bool {
        // If contract has state variables declared normally (not in slots)
        if !ctx.contract.state_variables.is_empty() {
            // Check if any are not constants or using proper slots
            for var in &ctx.contract.state_variables {
                let var_name = var.name.name.to_lowercase();

                // Allow constants and properly slotted variables
                if var_name.contains("slot")
                    || var_name.contains("constant")
                    || source.contains(&format!("constant {} =", var.name.name))
                {
                    continue;
                }

                // Non-constant, non-slotted variable in proxy = risk
                return true;
            }
        }

        false
    }

    /// Check for unsafe storage slot usage
    fn has_unsafe_storage_slots(&self, source: &str) -> bool {
        // Direct sstore/sload without EIP-1967 pattern
        if source.contains("sstore") || source.contains("sload") {
            // Check if using proper EIP-1967 slots
            let has_eip1967 = source.contains("eip1967")
                || source.contains("keccak256(")
                || source.contains("bytes32 private constant");

            if !has_eip1967 {
                return true;
            }
        }

        false
    }

    /// Check if upgradeable contract is missing storage gap
    fn missing_storage_gap(&self, ctx: &AnalysisContext, source: &str) -> bool {
        // Check if this is upgradeable
        let is_upgradeable = source.contains("upgrade")
            || source.contains("Upgradeable")
            || ctx.contract.name.name.contains("Upgradeable");

        if !is_upgradeable {
            return false;
        }

        // Check for storage gap pattern
        let has_gap = source.contains("__gap")
            || source.contains("reserved")
            || source.contains("uint256[50]")
            || source.contains("uint256[49]");

        !has_gap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = ProxyStorageCollisionDetector::new();
        assert_eq!(detector.name(), "Proxy Storage Collision");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
        assert_eq!(detector.id().0, "proxy-storage-collision");
    }
}
