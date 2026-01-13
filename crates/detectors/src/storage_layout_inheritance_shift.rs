use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for storage layout shifts due to inheritance changes
///
/// Detects patterns where storage slots may shift due to inheritance chain modifications.
/// This vulnerability led to the $6M Audius exploit in 2022.
///
/// Vulnerable patterns:
/// 1. Adding state variables to proxy contract that shift implementation slots:
/// ```solidity
/// contract ProxyV1 {
///     address impl; // slot 0
/// }
/// contract ProxyV2 {
///     address admin; // NEW - shifts impl to slot 1
///     address impl;  // Now slot 1, was slot 0
/// }
/// ```
///
/// 2. Multiple inheritance without proper storage gap consideration:
/// ```solidity
/// contract A { uint256 a; }
/// contract B { uint256 b; }
/// contract C is A, B { } // Inheritance order matters!
/// ```
pub struct StorageLayoutInheritanceShiftDetector {
    base: BaseDetector,
}

impl Default for StorageLayoutInheritanceShiftDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageLayoutInheritanceShiftDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("storage-layout-inheritance-shift"),
                "Storage Layout Inheritance Shift".to_string(),
                "Detects patterns that may cause storage layout shifts due to inheritance chain \
                 modifications. Adding state variables to proxy contracts or changing inheritance \
                 order can shift storage slots and corrupt state. This led to the $6M Audius exploit."
                    .to_string(),
                vec![DetectorCategory::Upgradeable, DetectorCategory::Logic],
                Severity::Critical,
            ),
        }
    }

    /// Check if contract appears to be a proxy contract
    fn is_proxy_contract(&self, source: &str) -> bool {
        source.contains("Proxy")
            || source.contains("delegatecall")
            || source.contains("implementation")
            || source.contains("_implementation")
            || source.contains("ERC1967")
    }

    /// Check if contract has state variables before critical proxy variables
    fn has_state_before_proxy_vars(&self, source: &str) -> Option<(u32, String)> {
        let lines: Vec<&str> = source.lines().collect();
        let mut found_state_var = false;
        let mut state_var_line = 0u32;
        let mut state_var_name = String::new();

        let proxy_patterns = [
            "address implementation",
            "address _implementation",
            "address impl",
            "address private _impl",
            "address internal _impl",
            "bytes32 private constant _IMPLEMENTATION_SLOT",
        ];

        let state_var_patterns = [
            "address admin",
            "address owner",
            "address _admin",
            "address _owner",
            "bool paused",
            "bool _paused",
            "uint256",
            "mapping(",
            "address[] ",
        ];

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Skip comments and pragmas
            if trimmed.starts_with("//")
                || trimmed.starts_with("/*")
                || trimmed.starts_with("pragma")
                || trimmed.starts_with("import")
            {
                continue;
            }

            // Check if this is a state variable
            for pattern in &state_var_patterns {
                if trimmed.contains(pattern)
                    && !trimmed.contains("function")
                    && !trimmed.contains("event")
                    && !trimmed.starts_with("*")
                {
                    if !found_state_var {
                        found_state_var = true;
                        state_var_line = line_num as u32 + 1;
                        // Extract variable name
                        if let Some(name) = self.extract_var_name(trimmed) {
                            state_var_name = name;
                        }
                    }
                }
            }

            // Check if we hit a proxy variable after state variables
            for proxy_pattern in &proxy_patterns {
                if trimmed.contains(proxy_pattern) && found_state_var {
                    return Some((state_var_line, state_var_name.clone()));
                }
            }
        }

        None
    }

    /// Extract variable name from declaration
    fn extract_var_name(&self, line: &str) -> Option<String> {
        // Handle patterns like "address admin;" or "uint256 public value;"
        let parts: Vec<&str> = line.split_whitespace().collect();
        for (i, part) in parts.iter().enumerate() {
            if *part == "public"
                || *part == "private"
                || *part == "internal"
                || part.ends_with(';')
            {
                let name = part.trim_end_matches(';').trim_end_matches('=');
                if !name.is_empty()
                    && name != "public"
                    && name != "private"
                    && name != "internal"
                {
                    return Some(name.to_string());
                }
                // Check previous part
                if i > 0 {
                    let prev = parts[i - 1];
                    if prev != "public" && prev != "private" && prev != "internal" {
                        return Some(prev.to_string());
                    }
                }
            }
        }
        None
    }

    /// Check for multiple inheritance with state variables
    fn has_risky_multiple_inheritance(&self, source: &str) -> Option<(u32, String)> {
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for contract inheritance with multiple parents
            if trimmed.starts_with("contract ") && trimmed.contains(" is ") {
                let is_pos = trimmed.find(" is ").unwrap();
                let inheritance = &trimmed[is_pos + 4..];

                // Count inherited contracts
                let parents: Vec<&str> = inheritance
                    .split(',')
                    .map(|s| s.trim().trim_end_matches('{').trim())
                    .filter(|s| !s.is_empty())
                    .collect();

                // Flag if more than 3 parents (high risk of slot collision)
                if parents.len() > 3 {
                    // Check if any parent likely has state variables
                    let risky_parents: Vec<&str> = parents
                        .iter()
                        .filter(|p| {
                            !p.contains("Interface")
                                && !p.contains("ERC165")
                                && !p.contains("Context")
                                && !p.starts_with('I')
                        })
                        .copied()
                        .collect();

                    if risky_parents.len() > 2 {
                        return Some((line_num as u32 + 1, risky_parents.join(", ")));
                    }
                }
            }
        }

        None
    }

    /// Check if contract has storage gap issues
    fn has_storage_gap_in_middle(&self, source: &str) -> Option<u32> {
        let lines: Vec<&str> = source.lines().collect();
        let mut found_gap = false;
        let mut gap_line = 0u32;

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Check for __gap array
            if trimmed.contains("__gap") || trimmed.contains("__GAP") {
                found_gap = true;
                gap_line = line_num as u32 + 1;
            }

            // If we found gap and then find more state variables, that's a problem
            if found_gap {
                let state_patterns = ["uint256", "address", "bool", "mapping(", "bytes32"];
                for pattern in state_patterns {
                    if trimmed.contains(pattern)
                        && !trimmed.contains("__gap")
                        && !trimmed.contains("function")
                        && !trimmed.contains("event")
                        && !trimmed.contains("constant")
                        && !trimmed.starts_with("//")
                    {
                        return Some(gap_line);
                    }
                }
            }
        }

        None
    }

    /// Check for upgradeable pattern
    fn is_upgradeable(&self, source: &str) -> bool {
        source.contains("Upgradeable")
            || source.contains("Initializable")
            || source.contains("UUPSUpgradeable")
            || source.contains("TransparentUpgradeable")
    }

    /// Get contract name from source
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for StorageLayoutInheritanceShiftDetector {
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

        // Check for proxy contracts with state variables before proxy vars
        if self.is_proxy_contract(source) {
            if let Some((line, var_name)) = self.has_state_before_proxy_vars(source) {
                let message = format!(
                    "Proxy contract '{}' has state variable '{}' declared before critical proxy \
                     variables. This can shift storage slots and corrupt the implementation pointer \
                     or other proxy state. This pattern caused the $6M Audius exploit.",
                    contract_name, var_name
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 1, 30)
                    .with_cwe(119) // CWE-119: Buffer Errors (storage layout issues)
                    .with_confidence(Confidence::High)
                    .with_fix_suggestion(
                        "Move state variables to implementation contract or use EIP-1967 \
                         storage slots that don't conflict with regular storage:\n\n\
                         // Use pseudo-random slot from EIP-1967\n\
                         bytes32 internal constant _IMPLEMENTATION_SLOT = \
                         0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;\n\n\
                         Or declare proxy variables FIRST before any other state."
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        // Check for risky multiple inheritance in upgradeable contracts
        if self.is_upgradeable(source) {
            if let Some((line, parents)) = self.has_risky_multiple_inheritance(source) {
                let message = format!(
                    "Contract '{}' inherits from multiple contracts with potential state variables: {}. \
                     Multiple inheritance with state-bearing contracts can cause storage slot collisions \
                     when contracts are upgraded or inheritance order changes.",
                    contract_name, parents
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 1, 50)
                    .with_cwe(119) // CWE-119: Buffer Errors
                    .with_confidence(Confidence::Medium)
                    .with_fix_suggestion(
                        "Ensure all inherited contracts use __gap arrays and maintain \
                         consistent inheritance order. Consider using diamond pattern for \
                         complex inheritance or flatten the inheritance hierarchy:\n\n\
                         // In each base contract:\n\
                         uint256[50] private __gap;\n\n\
                         // Maintain exact same inheritance order in all versions:\n\
                         contract MyContractV1 is A, B, C {}\n\
                         contract MyContractV2 is A, B, C {} // Same order!"
                            .to_string(),
                    );

                findings.push(finding);
            }

            // Check for storage gap placement issues
            if let Some(line) = self.has_storage_gap_in_middle(source) {
                let message = format!(
                    "Contract '{}' has __gap array with state variables declared after it. \
                     Storage gaps should always be at the END of state variable declarations \
                     to reserve space for future additions.",
                    contract_name
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 1, 20)
                    .with_cwe(119) // CWE-119: Buffer Errors
                    .with_confidence(Confidence::High)
                    .with_fix_suggestion(
                        "Move __gap array to the END of all state variable declarations:\n\n\
                         contract MyContract {\n\
                             uint256 public value1;\n\
                             address public owner;\n\
                             // ... all other state variables ...\n\n\
                             // Gap MUST be last\n\
                             uint256[48] private __gap;\n\
                         }"
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
        let detector = StorageLayoutInheritanceShiftDetector::new();
        assert_eq!(detector.name(), "Storage Layout Inheritance Shift");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_is_proxy_contract() {
        let detector = StorageLayoutInheritanceShiftDetector::new();

        assert!(detector.is_proxy_contract("contract MyProxy {}"));
        assert!(detector.is_proxy_contract("assembly { delegatecall(gas(), impl, 0, 0, 0, 0) }"));
        assert!(detector.is_proxy_contract("address _implementation;"));
        assert!(!detector.is_proxy_contract("contract SimpleToken {}"));
    }

    #[test]
    fn test_state_before_proxy_vars() {
        let detector = StorageLayoutInheritanceShiftDetector::new();

        let vulnerable = r#"
            contract VulnerableProxy {
                address admin;  // Added state variable
                address implementation;  // Shifted!
            }
        "#;
        assert!(detector.has_state_before_proxy_vars(vulnerable).is_some());

        let safe = r#"
            contract SafeProxy {
                address implementation;  // First
                address admin;  // After proxy vars
            }
        "#;
        assert!(detector.has_state_before_proxy_vars(safe).is_none());
    }

    #[test]
    fn test_multiple_inheritance() {
        let detector = StorageLayoutInheritanceShiftDetector::new();

        let risky = r#"
            contract RiskyContract is Ownable, Pausable, ERC20, AccessControl, ReentrancyGuard {
                // Too many stateful parents
            }
        "#;
        assert!(detector.has_risky_multiple_inheritance(risky).is_some());

        let safe = r#"
            contract SafeContract is Ownable, IERC20 {
                // Few parents, one is interface
            }
        "#;
        assert!(detector.has_risky_multiple_inheritance(safe).is_none());
    }

    #[test]
    fn test_gap_placement() {
        let detector = StorageLayoutInheritanceShiftDetector::new();

        let bad_gap = r#"
            contract BadGap {
                uint256 value1;
                uint256[50] private __gap;
                uint256 value2;  // After gap - bad!
            }
        "#;
        assert!(detector.has_storage_gap_in_middle(bad_gap).is_some());

        let good_gap = r#"
            contract GoodGap {
                uint256 value1;
                uint256 value2;
                uint256[50] private __gap;  // At the end - good!
            }
        "#;
        assert!(detector.has_storage_gap_in_middle(good_gap).is_none());
    }

    #[test]
    fn test_is_upgradeable() {
        let detector = StorageLayoutInheritanceShiftDetector::new();

        assert!(detector.is_upgradeable("contract X is Upgradeable {}"));
        assert!(detector.is_upgradeable("contract X is Initializable {}"));
        assert!(detector.is_upgradeable("contract X is UUPSUpgradeable {}"));
        assert!(!detector.is_upgradeable("contract SimpleToken {}"));
    }
}
