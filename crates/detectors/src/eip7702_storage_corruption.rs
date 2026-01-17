use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for EIP-7702 storage corruption vulnerabilities
///
/// Detects potential storage collisions between delegated contract code
/// and the EOA's expected storage layout when using EIP-7702.
///
/// Vulnerable pattern:
/// ```solidity
/// // Contract assumes certain storage layout
/// contract DelegatedLogic {
///     address public owner;     // slot 0 - may collide with EOA state
///     uint256 public balance;   // slot 1
///
///     function initialize() external {
///         owner = msg.sender;   // Overwrites EOA's storage!
///     }
/// }
/// ```
pub struct Eip7702StorageCorruptionDetector {
    base: BaseDetector,
}

impl Default for Eip7702StorageCorruptionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Eip7702StorageCorruptionDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("eip7702-storage-corruption"),
                "EIP-7702 Storage Corruption".to_string(),
                "Detects potential storage corruption when contract code is delegated \
                 to an EOA via EIP-7702. Storage slot collisions between delegated \
                 code and EOA state can corrupt critical data."
                    .to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::Upgradeable],
                Severity::Critical,
            ),
        }
    }

    /// Check if contract could be used as delegation target
    /// Requires multiple strong signals to avoid FPs
    fn is_potential_delegation_target(&self, source: &str) -> bool {
        // Count strong signals for EIP-7702 delegation
        let mut signals = 0;

        // Strong signals - EIP-7702 specific patterns
        if source.contains("AUTH") && !source.contains("AUTHORIZATION") {
            signals += 2;
        }
        if source.contains("AUTHCALL") {
            signals += 2;
        }
        if source.contains("setCode") || source.contains("SET_CODE") {
            signals += 2;
        }
        if source.contains("EIP7702") || source.contains("eip7702") || source.contains("EIP-7702") {
            signals += 3;
        }

        // Medium signals - delegation patterns (only if combined with others)
        if source.contains("delegateCode") || source.contains("executeAs") {
            signals += 1;
        }

        // Weak signals - only count if we already have other signals
        // These are common in many contracts, so alone they don't indicate EIP-7702
        if signals > 0 {
            if source.contains("Delegate") && source.contains("Target") {
                signals += 1;
            }
            // "implementation" alone is too common (used in all proxy patterns)
            // Only count if it appears with "delegate" in close proximity
            let lower = source.to_lowercase();
            if lower.contains("delegate") && lower.contains("implementation") {
                signals += 1;
            }
        }

        // Phase 6: Require at least 3 signals for detection (raised from 2)
        signals >= 3
    }

    /// Check if contract is a standard ERC token (not a delegation target)
    fn is_standard_token(&self, source: &str) -> bool {
        // ERC-20/721/1155 tokens are typically not EIP-7702 delegation targets
        let is_erc20 = source.contains("IERC20")
            || (source.contains("transfer(")
                && source.contains("balanceOf")
                && source.contains("totalSupply"));

        let is_erc721 =
            source.contains("IERC721") || source.contains("ERC721") || source.contains("ownerOf");

        let is_erc1155 = source.contains("IERC1155")
            || source.contains("ERC1155")
            || source.contains("balanceOfBatch");

        is_erc20 || is_erc721 || is_erc1155
    }

    /// Check if contract uses OpenZeppelin upgradeable patterns (already safe)
    fn is_oz_upgradeable(&self, source: &str) -> bool {
        source.contains("@openzeppelin/contracts-upgradeable")
            || source.contains("Initializable")
            || source.contains("UUPSUpgradeable")
            || source.contains("TransparentUpgradeableProxy")
    }

    /// Check if contract only has immutable/constant state (safe for delegation)
    fn has_only_safe_storage(&self, source: &str) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        let mut has_mutable_state = false;

        for line in lines {
            let trimmed = line.trim();
            // Skip comments
            if trimmed.starts_with("//") || trimmed.starts_with("/*") {
                continue;
            }
            // Check for state variable declarations (not in functions)
            let storage_types = ["address", "uint", "int", "bool", "bytes", "string", "mapping"];
            for stype in &storage_types {
                if trimmed.starts_with(stype) || trimmed.contains(&format!(" {}", stype)) {
                    // Only safe if immutable or constant
                    if !trimmed.contains("immutable") && !trimmed.contains("constant") {
                        has_mutable_state = true;
                        break;
                    }
                }
            }
        }

        !has_mutable_state
    }

    /// Find state variables that could cause storage collision
    fn find_storage_variables(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();
        let mut in_contract = false;
        let mut in_interface = false;
        let mut brace_depth = 0;

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Track contract/interface scope
            if trimmed.starts_with("interface ") || trimmed.contains(" interface ") {
                in_interface = true;
                in_contract = false;
            } else if trimmed.contains("contract ") || trimmed.contains("abstract contract ") {
                in_contract = true;
                in_interface = false;
            }

            for c in trimmed.chars() {
                match c {
                    '{' => brace_depth += 1,
                    '}' => {
                        brace_depth -= 1;
                        if brace_depth == 0 {
                            in_contract = false;
                            in_interface = false;
                        }
                    }
                    _ => {}
                }
            }

            // Look for state variable declarations at contract level (depth 1)
            // Skip interfaces - they can't have state variables
            if in_contract && !in_interface && brace_depth == 1 {
                // Skip function declarations and other non-state lines
                if trimmed.starts_with("function ")
                    || trimmed.starts_with("event ")
                    || trimmed.starts_with("error ")
                    || trimmed.starts_with("modifier ")
                    || trimmed.starts_with("constructor")
                    || trimmed.starts_with("//")
                    || trimmed.starts_with("/*")
                    || trimmed.is_empty()
                {
                    continue;
                }

                // Detect state variables
                let storage_types = [
                    "address", "uint", "int", "bool", "bytes", "string", "mapping", "struct",
                ];

                for stype in &storage_types {
                    if trimmed.starts_with(stype) || trimmed.contains(&format!(" {}", stype)) {
                        // Extract variable name
                        let var_name = self.extract_variable_name(trimmed);
                        if !var_name.is_empty() && !var_name.contains("constant") {
                            findings.push((
                                line_num as u32 + 1,
                                var_name,
                                stype.to_string(),
                            ));
                        }
                        break;
                    }
                }
            }
        }

        findings
    }

    /// Find storage writes in functions
    fn find_storage_writes(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for direct storage assignments
            if trimmed.contains(" = ") && !trimmed.contains("==") && !trimmed.contains("!=") {
                // Skip local variable declarations
                if !trimmed.contains("memory ")
                    && !trimmed.contains("calldata ")
                    && !trimmed.starts_with("uint")
                    && !trimmed.starts_with("int")
                    && !trimmed.starts_with("address ")
                    && !trimmed.starts_with("bool ")
                    && !trimmed.starts_with("bytes ")
                {
                    let func_name = self.find_containing_function(&lines, line_num);
                    if func_name != "unknown" {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }

            // Look for assembly storage operations
            if trimmed.contains("sstore") {
                let func_name = self.find_containing_function(&lines, line_num);
                findings.push((line_num as u32 + 1, func_name));
            }
        }

        findings
    }

    /// Check for EIP-1967 storage slot usage
    fn uses_eip1967_slots(&self, source: &str) -> bool {
        source.contains("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
            || source.contains("IMPLEMENTATION_SLOT")
            || source.contains("eip1967")
            || source.contains("EIP1967")
    }

    /// Check for storage gap pattern
    fn has_storage_gap(&self, source: &str) -> bool {
        source.contains("__gap") || source.contains("_gap") || source.contains("uint256[")
    }

    /// Extract variable name from declaration
    fn extract_variable_name(&self, line: &str) -> String {
        // Handle various declaration patterns
        // Variable name is typically the identifier before semicolon or equals sign
        let trimmed = line.trim().trim_end_matches(';');
        let parts: Vec<&str> = trimmed.split_whitespace().collect();

        // Skip modifiers to find the actual variable name
        // Variable name is usually the last identifier before ; or =
        let mut candidate = String::new();

        for part in parts.iter().rev() {
            let cleaned = part
                .trim_end_matches(';')
                .trim_end_matches('=')
                .trim_end_matches(')');

            // Skip visibility and type modifiers
            if *part == "public"
                || *part == "private"
                || *part == "internal"
                || *part == "external"
                || *part == "constant"
                || *part == "immutable"
                || part.contains("(")
                || part.contains(")")
                || part.contains("=>")
                || part.contains("[")
                || part.contains("]")
                || cleaned.is_empty()
            {
                continue;
            }

            // Valid variable name: starts with letter or underscore, alphanumeric
            if cleaned.chars().next().map(|c| c.is_alphabetic() || c == '_').unwrap_or(false)
                && cleaned.chars().all(|c| c.is_alphanumeric() || c == '_')
            {
                candidate = cleaned.to_string();
                break;
            }
        }

        candidate
    }

    /// Find containing function name
    fn find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                if let Some(func_start) = trimmed.find("function ") {
                    let after_func = &trimmed[func_start + 9..];
                    if let Some(paren_pos) = after_func.find('(') {
                        return after_func[..paren_pos].trim().to_string();
                    }
                }
            }
        }
        "unknown".to_string()
    }

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for Eip7702StorageCorruptionDetector {
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

        // Phase 6: Skip standard ERC tokens (not delegation targets)
        if self.is_standard_token(source) {
            return Ok(findings);
        }

        // Phase 6: Skip OpenZeppelin upgradeable contracts (already designed for safe storage)
        if self.is_oz_upgradeable(source) {
            return Ok(findings);
        }

        // Phase 6: Skip contracts with only immutable/constant storage (safe)
        if self.has_only_safe_storage(source) {
            return Ok(findings);
        }

        // Check if this could be a delegation target
        let is_delegation_target = self.is_potential_delegation_target(source);
        let uses_safe_slots = self.uses_eip1967_slots(source);
        let has_gap = self.has_storage_gap(source);

        // Find state variables
        let state_vars = self.find_storage_variables(source);

        // If contract has state variables and could be delegation target
        if !state_vars.is_empty() && is_delegation_target && !uses_safe_slots {
            // Report first few state variables as potential collision risks
            for (line, var_name, var_type) in state_vars.iter().take(3) {
                let message = format!(
                    "State variable '{}' ({}) in contract '{}' uses standard storage slots. \
                     If this contract is used as an EIP-7702 delegation target, the storage \
                     could collide with the EOA's existing state, causing data corruption.",
                    var_name, var_type, contract_name
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, *line, 1, 50)
                    .with_cwe(119) // CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
                    .with_confidence(if is_delegation_target {
                        Confidence::High
                    } else {
                        Confidence::Medium
                    })
                    .with_fix_suggestion(
                        "For EIP-7702 safe storage:\n\n\
                         1. Use EIP-1967 storage slots for critical state:\n\
                         bytes32 constant SLOT = keccak256(\"namespace.variable\") - 1;\n\n\
                         2. Use namespaced storage pattern:\n\
                         struct Storage { address owner; uint256 balance; }\n\
                         bytes32 constant STORAGE_SLOT = keccak256(\"MyContract.storage\");\n\n\
                         3. Avoid using slot 0 and consecutive slots\n\
                         4. Document storage layout for delegation safety"
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        // Check for storage writes without safe patterns
        if !uses_safe_slots && !has_gap {
            let writes = self.find_storage_writes(source);
            for (line, func_name) in writes.iter().take(2) {
                let message = format!(
                    "Function '{}' in contract '{}' writes to storage without using EIP-1967 \
                     safe storage patterns. In EIP-7702 delegation context, this could \
                     corrupt the delegating account's state.",
                    func_name, contract_name
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, *line, 1, 50)
                    .with_cwe(119) // CWE-119: Buffer Errors
                    .with_confidence(Confidence::Medium)
                    .with_fix_suggestion(
                        "Use assembly with specific storage slots:\n\n\
                         bytes32 constant MY_SLOT = keccak256(\"myapp.myvar\");\n\n\
                         function _store(uint256 value) internal {\n\
                             assembly {\n\
                                 sstore(MY_SLOT, value)\n\
                             }\n\
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
        let detector = Eip7702StorageCorruptionDetector::new();
        assert_eq!(detector.name(), "EIP-7702 Storage Corruption");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_storage_variables() {
        let detector = Eip7702StorageCorruptionDetector::new();

        let code = r#"
            contract DelegateLogic {
                address public owner;
                uint256 public balance;
                mapping(address => uint256) public balances;
            }
        "#;
        let findings = detector.find_storage_variables(code);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_eip1967_detection() {
        let detector = Eip7702StorageCorruptionDetector::new();

        let safe = r#"
            contract SafeDelegate {
                bytes32 constant IMPLEMENTATION_SLOT =
                    0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
            }
        "#;
        assert!(detector.uses_eip1967_slots(safe));
    }

    #[test]
    fn test_storage_gap() {
        let detector = Eip7702StorageCorruptionDetector::new();

        let with_gap = "uint256[50] private __gap;";
        assert!(detector.has_storage_gap(with_gap));
    }
}
