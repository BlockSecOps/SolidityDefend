use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for EIP-1153 reentrancy guard bypass vulnerabilities
///
/// Detects potential bypasses of reentrancy guards that use transient storage
/// (TSTORE/TLOAD) when the guard implementation is flawed.
///
/// Vulnerable pattern:
/// ```solidity
/// contract BadGuard {
///     // Flawed: doesn't reset lock properly
///     function withdraw() external {
///         assembly {
///             let locked := tload(0)
///             if locked { revert(0, 0) }
///             tstore(0, 1)
///         }
///         payable(msg.sender).transfer(balance);
///         // Missing: tstore(0, 0) to clear lock
///         // Lock persists only until end of tx anyway!
///     }
/// }
/// ```
pub struct Eip1153GuardBypassDetector {
    base: BaseDetector,
}

impl Default for Eip1153GuardBypassDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Eip1153GuardBypassDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("eip1153-guard-bypass"),
                "EIP-1153 Guard Bypass".to_string(),
                "Detects potential bypasses of reentrancy guards implemented with \
                 transient storage. Flawed implementations may not properly check \
                 or reset the lock, allowing reentrancy attacks."
                    .to_string(),
                vec![DetectorCategory::Reentrancy, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    /// Find guard patterns that don't reset lock
    fn find_unreset_guard(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");
                let func_name = self.extract_function_name(trimmed);

                // Has guard pattern (tload check + tstore set)
                let has_check = func_body.contains("tload(")
                    && (func_body.contains("if ")
                        || func_body.contains("revert")
                        || func_body.contains("require"));

                let set_count = func_body.matches("tstore(").count();
                let has_external = func_body.contains(".call(")
                    || func_body.contains(".transfer(")
                    || func_body.contains(".send(")
                    || func_body.contains("safeTransfer");

                // Guard pattern but only one tstore (sets but doesn't reset)
                if has_check && set_count == 1 && has_external {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find guards with wrong check order
    fn find_wrong_check_order(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ") {
                let func_end = self.find_function_end(&lines, line_num);
                let func_lines = &lines[line_num..func_end];

                let mut tload_line: Option<usize> = None;
                let mut tstore_line: Option<usize> = None;
                let mut external_call_line: Option<usize> = None;

                for (i, func_line) in func_lines.iter().enumerate() {
                    if func_line.contains("tload(") {
                        tload_line = Some(i);
                    }
                    if func_line.contains("tstore(") && tstore_line.is_none() {
                        tstore_line = Some(i);
                    }
                    if func_line.contains(".call(")
                        || func_line.contains(".transfer(")
                        || func_line.contains("safeTransfer")
                    {
                        external_call_line = Some(i);
                    }
                }

                // Wrong order: external call before guard is fully set
                if let (Some(tstore), Some(ext_call)) = (tstore_line, external_call_line) {
                    if ext_call < tstore {
                        let func_name = self.extract_function_name(trimmed);
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }

                // Wrong order: tstore before tload check
                if let (Some(tload), Some(tstore)) = (tload_line, tstore_line) {
                    if tstore < tload {
                        let func_name = self.extract_function_name(trimmed);
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find guards using same slot for different purposes
    fn find_slot_confusion(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Count unique slots used
        let mut slots_used: Vec<String> = Vec::new();

        for line in &lines {
            if let Some(slot) = self.extract_slot(line) {
                if !slots_used.contains(&slot) {
                    slots_used.push(slot);
                }
            }
        }

        // If only one slot but multiple tstore operations with different values
        if slots_used.len() == 1 {
            let mut store_count = 0;
            let mut different_values = false;
            let mut last_value = String::new();

            for (line_num, line) in lines.iter().enumerate() {
                if line.contains("tstore(") {
                    store_count += 1;

                    // Extract value being stored
                    if let Some(value) = self.extract_tstore_value(line) {
                        if !last_value.is_empty() && value != last_value {
                            different_values = true;
                        }
                        last_value = value;
                    }

                    if store_count > 2 && different_values {
                        let func_name = self.find_containing_function(&lines, line_num);
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find modifiers using transient guards incorrectly
    fn find_modifier_guard_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Find modifier definitions
            if trimmed.starts_with("modifier ") {
                let mod_end = self.find_function_end(&lines, line_num);
                let mod_body: String = lines[line_num..mod_end].join("\n");

                // Check for transient guard pattern
                let has_tload = mod_body.contains("tload(");
                let has_tstore = mod_body.contains("tstore(");
                let has_placeholder = mod_body.contains("_;");

                if has_tload && has_tstore && has_placeholder {
                    // Check if tstore reset happens AFTER placeholder
                    let placeholder_pos = mod_body.find("_;");
                    let last_tstore_pos = mod_body.rfind("tstore(");

                    if let (Some(ph), Some(ts)) = (placeholder_pos, last_tstore_pos) {
                        // Reset should be after placeholder
                        if ts < ph {
                            let mod_name = self.extract_modifier_name(trimmed);
                            findings.push((line_num as u32 + 1, mod_name));
                        }
                    }
                }
            }
        }

        findings
    }

    /// Extract slot from tstore/tload
    fn extract_slot(&self, line: &str) -> Option<String> {
        let patterns = ["tstore(", "tload("];

        for pattern in patterns {
            if let Some(pos) = line.find(pattern) {
                let after = &line[pos + pattern.len()..];
                if let Some(end) = after.find(|c| c == ',' || c == ')') {
                    return Some(after[..end].trim().to_string());
                }
            }
        }
        None
    }

    /// Extract value from tstore
    fn extract_tstore_value(&self, line: &str) -> Option<String> {
        if let Some(pos) = line.find("tstore(") {
            let after = &line[pos + 7..];
            if let Some(comma) = after.find(',') {
                let value_part = &after[comma + 1..];
                if let Some(end) = value_part.find(')') {
                    return Some(value_part[..end].trim().to_string());
                }
            }
        }
        None
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

    /// Extract modifier name
    fn extract_modifier_name(&self, line: &str) -> String {
        if let Some(mod_start) = line.find("modifier ") {
            let after_mod = &line[mod_start + 9..];
            if let Some(end) = after_mod.find(|c: char| c == '(' || c == '{' || c.is_whitespace()) {
                return after_mod[..end].trim().to_string();
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

    /// Find end of function/modifier
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

impl Detector for Eip1153GuardBypassDetector {
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

        // Find guards that don't reset
        let unreset = self.find_unreset_guard(source);
        for (line, func_name) in &unreset {
            let message = format!(
                "Function '{}' in contract '{}' implements a transient reentrancy guard \
                 that sets the lock but may not reset it. While transient storage clears \
                 at transaction end, the function should reset the lock for proper behavior \
                 within the same transaction.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, *line, 1, 50)
                .with_cwe(667) // CWE-667: Improper Locking
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Properly reset transient reentrancy guard:\n\n\
                     modifier nonReentrant() {\n\
                         assembly {\n\
                             if tload(LOCK_SLOT) { revert(0, 0) }\n\
                             tstore(LOCK_SLOT, 1)  // Set lock\n\
                         }\n\
                         _;\n\
                         assembly {\n\
                             tstore(LOCK_SLOT, 0)  // Reset lock!\n\
                         }\n\
                     }\n\n\
                     Or use OpenZeppelin's ReentrancyGuardTransient."
                        .to_string(),
                );

            findings.push(finding);
        }

        // Find wrong check order
        let wrong_order = self.find_wrong_check_order(source);
        for (line, func_name) in wrong_order {
            if unreset.iter().any(|(l, _)| *l == line) {
                continue;
            }

            let message = format!(
                "Function '{}' in contract '{}' has transient guard operations in wrong order. \
                 The lock check should happen before setting, and external calls should happen \
                 after the lock is set.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(667) // CWE-667: Improper Locking
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Correct order for transient reentrancy guard:\n\n\
                     1. Check if locked (tload)\n\
                     2. If not locked, set lock (tstore)\n\
                     3. Perform operations including external calls\n\
                     4. Reset lock (tstore)"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Find modifier guard issues
        let mod_issues = self.find_modifier_guard_issues(source);
        for (line, mod_name) in mod_issues {
            let message = format!(
                "Modifier '{}' in contract '{}' implements transient reentrancy guard \
                 with potential issues. The lock reset should happen after the function \
                 body placeholder (_).",
                mod_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(667) // CWE-667: Improper Locking
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Modifier should reset lock after function body:\n\n\
                     modifier nonReentrant() {\n\
                         assembly { if tload(SLOT) { revert(0,0) } tstore(SLOT, 1) }\n\
                         _;  // Function body executes here\n\
                         assembly { tstore(SLOT, 0) }  // Reset AFTER _;\n\
                     }"
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
        let detector = Eip1153GuardBypassDetector::new();
        assert_eq!(detector.name(), "EIP-1153 Guard Bypass");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_unreset_guard() {
        let detector = Eip1153GuardBypassDetector::new();

        let vulnerable = r#"
            contract BadGuard {
                function withdraw() external {
                    assembly {
                        let locked := tload(0)
                        if locked { revert(0, 0) }
                        tstore(0, 1)
                    }
                    payable(msg.sender).transfer(address(this).balance);
                }
            }
        "#;
        let findings = detector.find_unreset_guard(vulnerable);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_proper_guard() {
        let detector = Eip1153GuardBypassDetector::new();

        let safe = r#"
            contract GoodGuard {
                function withdraw() external {
                    assembly {
                        let locked := tload(0)
                        if locked { revert(0, 0) }
                        tstore(0, 1)
                    }
                    payable(msg.sender).transfer(address(this).balance);
                    assembly { tstore(0, 0) }
                }
            }
        "#;
        let findings = detector.find_unreset_guard(safe);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_modifier_guard() {
        let detector = Eip1153GuardBypassDetector::new();

        let vulnerable = r#"
            contract BadModifier {
                modifier nonReentrant() {
                    assembly {
                        if tload(0) { revert(0, 0) }
                        tstore(0, 1)
                        tstore(0, 0)
                    }
                    _;
                }
            }
        "#;
        let findings = detector.find_modifier_guard_issues(vulnerable);
        assert!(!findings.is_empty());
    }
}
