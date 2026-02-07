use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for missing storage gaps in upgradeable contracts
///
/// When using inheritance in upgradeable contracts, base contracts should reserve
/// storage slots for future use. Without storage gaps, adding new state variables
/// to base contracts in upgrades can corrupt the storage layout.
///
/// Vulnerable pattern:
/// ```solidity
/// contract UpgradeableBase is Initializable {
///     uint256 public value;
///     // Missing: uint256[49] private __gap;
/// }
///
/// contract UpgradeableChild is UpgradeableBase {
///     uint256 public childValue; // This slot could be corrupted if Base adds storage
/// }
/// ```
pub struct MissingStorageGapDetector {
    base: BaseDetector,
}

impl Default for MissingStorageGapDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MissingStorageGapDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("missing-storage-gap"),
                "Missing Storage Gap".to_string(),
                "Detects upgradeable base contracts missing storage gap arrays (__gap) \
                 which could lead to storage collision on upgrade"
                    .to_string(),
                vec![DetectorCategory::Upgradeable, DetectorCategory::Logic],
                Severity::Medium,
            ),
        }
    }

    /// Check if contract is an upgradeable base contract
    fn is_upgradeable_base_contract(&self, source: &str) -> bool {
        // Must have upgradeable patterns
        let has_upgradeable = source.contains("Initializable")
            || source.contains("Upgradeable")
            || source.contains("initializer");

        // Should be a base contract (likely inherited from)
        let is_base = source.contains("abstract contract")
            || source.contains("contract ") && source.contains(" is ");

        has_upgradeable && is_base
    }

    /// Check if contract has storage gap
    fn has_storage_gap(&self, source: &str) -> bool {
        // Standard gap patterns
        source.contains("__gap")
            || source.contains("_gap")
            || source.contains("__reserved")
            || source.contains("uint256[")
                && (source.contains("private") || source.contains("internal"))
                && (source.contains("50]") || source.contains("49]") || source.contains("48]"))
    }

    /// Check if contract has state variables
    fn has_state_variables(&self, source: &str) -> Vec<(u32, String)> {
        let mut state_vars = Vec::new();
        let lines: Vec<&str> = source.lines().collect();
        let mut in_contract = false;
        let mut brace_depth = 0;
        let mut in_function = false;

        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Track contract body
            if trimmed.contains("contract ") || trimmed.contains("abstract contract ") {
                in_contract = true;
            }

            for c in line.chars() {
                if c == '{' {
                    brace_depth += 1;
                } else if c == '}' {
                    brace_depth -= 1;
                }
            }

            // Track function scope
            if trimmed.contains("function ") {
                in_function = true;
            }
            if in_function && brace_depth <= 1 && trimmed.contains('}') {
                in_function = false;
            }

            // Only check contract-level declarations (not in functions)
            if in_contract && brace_depth == 1 && !in_function {
                // Check for state variable declarations
                if self.is_state_variable_declaration(trimmed) {
                    if let Some(var_name) = self.extract_variable_name(trimmed) {
                        state_vars.push(((i + 1) as u32, var_name));
                    }
                }
            }
        }

        state_vars
    }

    /// Check if line is a state variable declaration
    fn is_state_variable_declaration(&self, line: &str) -> bool {
        let storage_types = [
            "uint256", "uint128", "uint64", "uint32", "uint16", "uint8", "uint", "int256",
            "int128", "int64", "int32", "int16", "int8", "int", "address", "bool", "bytes32",
            "bytes", "string", "mapping",
        ];

        for type_name in &storage_types {
            if line.starts_with(type_name)
                || line.starts_with(&format!("{} ", type_name))
                || line.contains(&format!(" {} ", type_name))
            {
                // Must have visibility or be a declaration
                if (line.contains("public")
                    || line.contains("private")
                    || line.contains("internal"))
                    && !line.contains("function")
                    && !line.contains("//")
                {
                    return true;
                }
            }
        }

        // Check for struct/array state variables
        if line.contains("[] ") && !line.contains("function") {
            return true;
        }

        false
    }

    /// Extract variable name from declaration
    fn extract_variable_name(&self, line: &str) -> Option<String> {
        // Split by common delimiters and find the variable name
        let parts: Vec<&str> = line.split(|c| c == ';' || c == '=').collect();
        if let Some(decl) = parts.first() {
            let words: Vec<&str> = decl.split_whitespace().collect();
            // Variable name is usually the last word before ; or =
            for word in words.iter().rev() {
                if !word.is_empty()
                    && !["public", "private", "internal", "constant", "immutable"]
                        .contains(&word.to_lowercase().as_str())
                {
                    return Some(word.to_string());
                }
            }
        }
        None
    }

    /// Find the contract declaration line
    fn find_contract_line(&self, source: &str) -> u32 {
        for (i, line) in source.lines().enumerate() {
            if line.contains("contract ") || line.contains("abstract contract ") {
                return (i + 1) as u32;
            }
        }
        1
    }

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for MissingStorageGapDetector {
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

        // Phase 53 FP Reduction: Skip proxy contracts
        // Proxy contracts use EIP-1967 storage slots, not regular state variables
        // They don't need storage gaps because they don't store state in regular slots
        let is_proxy_contract = source.contains("abstract contract Proxy")
            || source.contains("contract TransparentUpgradeableProxy")
            || source.contains("contract ERC1967Proxy")
            || source.contains("contract BeaconProxy")
            || source.contains("library ERC1967Utils")
            || source.contains("function _delegate(address")
            || source.contains("IMPLEMENTATION_SLOT")
            || source
                .contains("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc");

        if is_proxy_contract {
            return Ok(findings);
        }

        // Only check upgradeable base contracts
        if !self.is_upgradeable_base_contract(source) {
            return Ok(findings);
        }

        // Check if contract has state variables
        let state_vars = self.has_state_variables(source);
        if state_vars.is_empty() {
            return Ok(findings);
        }

        // Check if contract has storage gap
        if self.has_storage_gap(source) {
            return Ok(findings);
        }

        let contract_line = self.find_contract_line(source);
        let message = format!(
            "Upgradeable contract '{}' has {} state variable(s) but no storage gap. \
             Adding new state variables in future upgrades may corrupt storage layout \
             of derived contracts.",
            contract_name,
            state_vars.len()
        );

        let finding = self
            .base
            .create_finding(ctx, message, contract_line, 0, 20)
            .with_cwe(119) // CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
            .with_cwe(787) // CWE-787: Out-of-bounds Write
            .with_confidence(Confidence::Medium)
            .with_fix_suggestion(
                "Add a storage gap at the end of the contract to reserve slots for future use:\n\n\
                 contract UpgradeableBase is Initializable {\n\
                     uint256 public value;\n\
                     \n\
                     // Reserve 50 slots for future storage variables\n\
                     // Reduce this number when adding new state variables\n\
                     uint256[50] private __gap;\n\
                 }\n\n\
                 When adding new state variables, reduce the gap size accordingly:\n\
                 uint256 public newValue; // Added in upgrade\n\
                 uint256[49] private __gap; // Reduced from 50 to 49"
                    .to_string(),
            );

        findings.push(finding);

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
        let detector = MissingStorageGapDetector::new();
        assert_eq!(detector.name(), "Missing Storage Gap");
        assert_eq!(detector.default_severity(), Severity::Medium);
    }

    #[test]
    fn test_has_storage_gap() {
        let detector = MissingStorageGapDetector::new();

        let with_gap = "uint256[50] private __gap;";
        assert!(detector.has_storage_gap(with_gap));

        let without_gap = "uint256 public value;";
        assert!(!detector.has_storage_gap(without_gap));
    }

    #[test]
    fn test_is_upgradeable_base() {
        let detector = MissingStorageGapDetector::new();

        let upgradeable =
            "abstract contract UpgradeableBase is Initializable { function initialize() {} }";
        assert!(detector.is_upgradeable_base_contract(upgradeable));

        let not_upgradeable = "contract SimpleToken { }";
        assert!(!detector.is_upgradeable_base_contract(not_upgradeable));
    }
}
