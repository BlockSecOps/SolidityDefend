use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for EIP-1153 composability risk vulnerabilities
///
/// Detects potential issues when transient storage is used across
/// multiple contracts in composed transactions.
///
/// Vulnerable pattern:
/// ```solidity
/// contract ContractA {
///     // Uses transient slot 0
///     function setA() external {
///         assembly { tstore(0, 100) }
///     }
/// }
///
/// contract ContractB {
///     // Also uses transient slot 0 - collision!
///     function setB() external {
///         assembly { tstore(0, 200) }
///     }
/// }
///
/// // In same transaction: A.setA() then B.setB() corrupts A's state
/// ```
pub struct Eip1153ComposabilityRiskDetector {
    base: BaseDetector,
}

impl Default for Eip1153ComposabilityRiskDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Eip1153ComposabilityRiskDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("eip1153-composability-risk"),
                "EIP-1153 Composability Risk".to_string(),
                "Detects transient storage patterns that may cause issues when contracts \
                 are composed in the same transaction. Using hardcoded or common slots \
                 can lead to cross-contract transient storage collisions."
                    .to_string(),
                vec![DetectorCategory::Logic],
                Severity::Medium,
            ),
        }
    }

    /// Find hardcoded transient storage slots
    fn find_hardcoded_slots(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for tstore/tload with literal numbers
            if trimmed.contains("tstore(") || trimmed.contains("tload(") {
                // Check for hardcoded slot values (0, 1, 2, etc.)
                if let Some(slot_info) = self.extract_slot_value(trimmed) {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name, slot_info));
                }
            }
        }

        findings
    }

    /// Extract slot value from tstore/tload call
    fn extract_slot_value(&self, line: &str) -> Option<String> {
        // Look for tstore(X, or tload(X
        let patterns = ["tstore(", "tload("];

        for pattern in patterns {
            if let Some(pos) = line.find(pattern) {
                let after = &line[pos + pattern.len()..];

                // Extract the first argument
                if let Some(end) = after.find(|c| c == ',' || c == ')') {
                    let slot = after[..end].trim();

                    // Check if it's a small number (likely collision-prone)
                    if slot.parse::<u64>().is_ok() {
                        let num: u64 = slot.parse().unwrap();
                        if num < 100 {
                            return Some(format!("slot {}", num));
                        }
                    }

                    // Check for hex literals that might collide
                    if slot.starts_with("0x") && slot.len() < 10 {
                        return Some(format!("slot {}", slot));
                    }
                }
            }
        }
        None
    }

    /// Find transient storage without namespace
    fn find_missing_namespace(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Check if contract uses proper namespacing
        let has_namespace = source.contains("keccak256(")
            && (source.contains("tstore(") || source.contains("tload("));

        // Also check for dedicated slot constants with proper derivation
        let has_slot_constant = source.contains("TRANSIENT_SLOT")
            || source.contains("_SLOT")
            || source.contains("bytes32 constant");

        if !has_namespace && !has_slot_constant {
            for (line_num, line) in lines.iter().enumerate() {
                if line.contains("tstore(") || line.contains("tload(") {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find external contract calls that might share transient state
    fn find_external_transient_interaction(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Find functions with both transient operations and external calls
            if trimmed.contains("function ") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                let has_transient = func_body.contains("tstore(") || func_body.contains("tload(");

                // External calls to other contracts
                let has_external = func_body.contains(".call(")
                    || func_body.contains(".delegatecall(")
                    || func_body.contains("interface ")
                    || self.has_interface_call(&func_body);

                if has_transient && has_external {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Check if function body has interface calls (ContractName(address).function())
    fn has_interface_call(&self, body: &str) -> bool {
        // Pattern: SomeContract(address).someFunction(
        let patterns = [
            "IERC20(", "IERC721(", "IERC1155(", "IUniswap", "IPancake", "IPool(", "IRouter(",
        ];

        patterns.iter().any(|p| body.contains(p))
    }

    /// Find delegatecall with transient storage (shared context)
    fn find_delegatecall_transient(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Check if contract uses delegatecall
        if !source.contains("delegatecall") {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Both delegatecall and transient storage in same function
                if func_body.contains("delegatecall")
                    && (func_body.contains("tstore(") || func_body.contains("tload("))
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Extract function name
    fn extract_function_name(&self, line: &str) -> String {
        if let Some(func_start) = line.find("function ") {
            let after_func = &line[func_start + 9..];
            if let Some(paren_pos) = after_func.find('(') {
                return after_func[..paren_pos].trim().to_string();
            }
        }
        "unknown".to_string()
    }

    /// Find containing function name
    fn find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return self.extract_function_name(trimmed);
            }
        }
        "unknown".to_string()
    }

    /// Find end of function
    fn find_function_end(&self, lines: &[&str], start: usize) -> usize {
        let mut depth = 0;
        let mut started = false;

        for (i, line) in lines.iter().enumerate().skip(start) {
            for c in line.chars() {
                match c {
                    '{' => {
                        depth += 1;
                        started = true;
                    }
                    '}' => {
                        depth -= 1;
                        if started && depth == 0 {
                            return i + 1;
                        }
                    }
                    _ => {}
                }
            }
        }
        lines.len()
    }

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for Eip1153ComposabilityRiskDetector {
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

        // Find hardcoded slots
        let hardcoded = self.find_hardcoded_slots(source);
        for (line, func_name, slot_info) in &hardcoded {
            let message = format!(
                "Function '{}' in contract '{}' uses hardcoded transient storage {}. \
                 When composed with other contracts in the same transaction, this could \
                 cause slot collisions if other contracts use the same slot.",
                func_name, contract_name, slot_info
            );

            let finding = self
                .base
                .create_finding(ctx, message, *line, 1, 50)
                .with_cwe(664) // CWE-664: Improper Control of a Resource Through its Lifetime
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Use namespaced storage slots to avoid collisions:\n\n\
                     // BAD: hardcoded slot\n\
                     assembly { tstore(0, value) }\n\n\
                     // GOOD: namespaced slot\n\
                     bytes32 constant SLOT = keccak256(\"MyContract.myVariable\");\n\
                     assembly { tstore(SLOT, value) }\n\n\
                     Or use contract address in slot derivation:\n\
                     bytes32 slot = keccak256(abi.encode(address(this), \"myVar\"));"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Find missing namespace
        let no_namespace = self.find_missing_namespace(source);
        for (line, func_name) in no_namespace {
            if hardcoded.iter().any(|(l, _, _)| *l == line) {
                continue;
            }

            let message = format!(
                "Function '{}' in contract '{}' uses transient storage without apparent \
                 namespacing. Consider using keccak256-derived slots to prevent collisions.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(664)
                .with_confidence(Confidence::Low)
                .with_fix_suggestion(
                    "Derive unique transient storage slots:\n\n\
                     bytes32 constant MY_SLOT = bytes32(uint256(\n\
                         keccak256(\"com.myprotocol.ContractName.variableName\")\n\
                     ) - 1);"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Find external interactions with transient storage
        let externals = self.find_external_transient_interaction(source);
        for (line, func_name) in externals {
            let message = format!(
                "Function '{}' in contract '{}' uses transient storage and makes external \
                 calls. The external contract could interfere with transient state if \
                 it uses the same slots.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(664)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "When composing with external contracts:\n\n\
                     1. Use unique, namespaced storage slots\n\
                     2. Complete all transient operations before external calls\n\
                     3. Consider using reentrancy guards\n\
                     4. Document transient storage usage for integrators"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Find delegatecall with transient
        let delegatecalls = self.find_delegatecall_transient(source);
        for (line, func_name) in delegatecalls {
            let message = format!(
                "Function '{}' in contract '{}' uses both delegatecall and transient storage. \
                 Delegatecall executes in the caller's context, sharing transient storage \
                 space and potentially causing collisions.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(664)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Delegatecall shares transient storage context:\n\n\
                     1. Ensure delegated code uses unique slot namespaces\n\
                     2. Coordinate transient storage usage between proxy and impl\n\
                     3. Document which slots are used by each contract\n\
                     4. Consider using regular call instead if isolation needed"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = Eip1153ComposabilityRiskDetector::new();
        assert_eq!(detector.name(), "EIP-1153 Composability Risk");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_hardcoded_slots() {
        let detector = Eip1153ComposabilityRiskDetector::new();

        let vulnerable = r#"
            contract BadSlots {
                function setFlag() external {
                    assembly { tstore(0, 1) }
                }
            }
        "#;
        let findings = detector.find_hardcoded_slots(vulnerable);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_namespaced_safe() {
        let detector = Eip1153ComposabilityRiskDetector::new();

        let safe = r#"
            contract SafeSlots {
                bytes32 constant SLOT = keccak256("myContract.flag");

                function setFlag() external {
                    assembly { tstore(SLOT, 1) }
                }
            }
        "#;
        let findings = detector.find_missing_namespace(safe);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_delegatecall_transient() {
        let detector = Eip1153ComposabilityRiskDetector::new();

        let vulnerable = r#"
            contract Proxy {
                function execute(address impl, bytes calldata data) external {
                    assembly { tstore(0, 1) }
                    (bool success,) = impl.delegatecall(data);
                    assembly { let flag := tload(0) }
                }
            }
        "#;
        let findings = detector.find_delegatecall_transient(vulnerable);
        assert!(!findings.is_empty());
    }
}
