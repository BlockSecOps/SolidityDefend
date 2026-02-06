use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for EIP-1153 cross-transaction assumption vulnerabilities
///
/// Detects code that incorrectly assumes transient storage persists
/// across transactions when it actually clears after each transaction.
///
/// Vulnerable pattern:
/// ```solidity
/// contract BadAssumption {
///     // Developer thinks this persists like regular storage
///     function setFlag() external {
///         assembly { tstore(0, 1) }  // Clears after tx!
///     }
///
///     function checkFlag() external view {
///         assembly {
///             let flag := tload(0)  // Always 0 in new tx
///             if iszero(flag) { revert(0, 0) }
///         }
///     }
/// }
/// ```
pub struct Eip1153CrossTxAssumptionDetector {
    base: BaseDetector,
}

impl Default for Eip1153CrossTxAssumptionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Eip1153CrossTxAssumptionDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("eip1153-cross-tx-assumption"),
                "EIP-1153 Cross-Transaction Assumption".to_string(),
                "Detects code that may incorrectly assume transient storage (TSTORE/TLOAD) \
                 persists across transactions. Transient storage clears at the end of each \
                 transaction, and assuming persistence can lead to critical bugs."
                    .to_string(),
                vec![DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    /// Find tstore in one function and tload in another (potential cross-tx assumption)
    fn find_separate_store_load(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // First pass: find all tstore locations and their functions
        let mut tstore_funcs: Vec<(String, u32)> = Vec::new();
        for (line_num, line) in lines.iter().enumerate() {
            if line.contains("tstore(") {
                let func_name = self.find_containing_function(&lines, line_num);
                tstore_funcs.push((func_name, line_num as u32 + 1));
            }
        }

        // Second pass: find tload in different functions
        for (line_num, line) in lines.iter().enumerate() {
            if line.contains("tload(") {
                let func_name = self.find_containing_function(&lines, line_num);

                // Check if there's a tstore in a DIFFERENT function
                for (store_func, store_line) in &tstore_funcs {
                    if store_func != &func_name && store_func != "unknown" && func_name != "unknown"
                    {
                        findings.push((line_num as u32 + 1, func_name.clone(), store_func.clone()));
                        // Also report the tstore location
                        findings.push((*store_line, store_func.clone(), func_name.clone()));
                    }
                }
            }
        }

        // Deduplicate
        findings.sort_by_key(|(l, _, _)| *l);
        findings.dedup_by_key(|(l, _, _)| *l);
        findings
    }

    /// Find view/pure functions using tload (likely expecting persisted state)
    fn find_view_tload(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for view/pure functions
            if trimmed.contains("function ")
                && (trimmed.contains(" view") || trimmed.contains(" pure"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Using tload in view function suggests expecting persistence
                if func_body.contains("tload(") {
                    let func_name = self.extract_function_name(trimmed);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find transient storage for state that should persist
    fn find_persistent_state_patterns(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Keywords suggesting persistent state
        let persistent_keywords = [
            "owner",
            "admin",
            "balance",
            "total",
            "count",
            "nonce",
            "allowance",
            "approved",
            "paused",
            "initialized",
        ];

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim().to_lowercase();

            if trimmed.contains("tstore(") || trimmed.contains("tload(") {
                // Check context for persistent state keywords
                let context_start = if line_num > 5 { line_num - 5 } else { 0 };
                let context_end = std::cmp::min(line_num + 5, lines.len());
                let context: String = lines[context_start..context_end].join("\n").to_lowercase();

                for keyword in &persistent_keywords {
                    if context.contains(keyword) {
                        let func_name = self.find_containing_function(&lines, line_num);
                        findings.push((line_num as u32 + 1, func_name));
                        break;
                    }
                }
            }
        }

        findings
    }

    /// Find initialization patterns in transient storage
    fn find_transient_init(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Look for functions that initialize transient state
            if trimmed.contains("function ") {
                let lower = trimmed.to_lowercase();
                if lower.contains("init")
                    || lower.contains("setup")
                    || lower.contains("configure")
                    || lower.contains("set")
                {
                    let func_end = self.find_function_end(&lines, line_num);
                    let func_body: String = lines[line_num..func_end].join("\n");

                    // Using tstore for initialization is suspicious
                    if func_body.contains("tstore(") && !func_body.contains("sstore") {
                        let func_name = self.extract_function_name(trimmed);
                        findings.push((line_num as u32 + 1, func_name));
                    }
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

impl Detector for Eip1153CrossTxAssumptionDetector {
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

        // Phase 52 FP Reduction: Skip transient storage utility contracts
        // Contracts like Exttload/Extsload are DESIGNED to expose transient storage reads.
        // These are EIP-1153 helper contracts for gas-efficient state access within transactions.
        if utils::is_transient_storage_utility(ctx) {
            return Ok(findings);
        }

        // Phase 52 FP Reduction: Skip interface-only contracts
        if utils::is_interface_only(ctx) {
            return Ok(findings);
        }

        // Find separate store/load (cross-function patterns)
        let separate = self.find_separate_store_load(source);
        let mut reported_lines: Vec<u32> = Vec::new();

        for (line, func_name, other_func) in &separate {
            if reported_lines.contains(line) {
                continue;
            }
            reported_lines.push(*line);

            let message = format!(
                "Function '{}' in contract '{}' uses transient storage that is written in \
                 function '{}'. Transient storage clears after each transaction - if these \
                 functions are called in separate transactions, the data will be lost.",
                func_name, contract_name, other_func
            );

            let finding = self
                .base
                .create_finding(ctx, message, *line, 1, 50)
                .with_cwe(362) // CWE-362: Race Condition
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "If data needs to persist across transactions, use regular storage:\n\n\
                     // BAD: transient (clears after tx)\n\
                     assembly { tstore(slot, value) }\n\n\
                     // GOOD: persistent storage\n\
                     storage[slot] = value;  // or use SSTORE\n\n\
                     Only use transient storage for within-transaction state."
                        .to_string(),
                );

            findings.push(finding);
        }

        // Find view functions with tload
        let view_tloads = self.find_view_tload(source);
        for (line, func_name) in view_tloads {
            if reported_lines.contains(&line) {
                continue;
            }

            let message = format!(
                "View function '{}' in contract '{}' reads from transient storage. \
                 This will always return zero when called externally in a new transaction \
                 since transient storage clears between transactions.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362) // CWE-362: Race Condition
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "View functions reading transient storage will return stale/zero values:\n\n\
                     // This always returns 0 in a new transaction\n\
                     function getFlag() external view returns (uint256) {\n\
                         assembly { flag := tload(0) }  // Always 0!\n\
                     }\n\n\
                     Use regular storage for data that needs to be readable across txs."
                        .to_string(),
                );

            findings.push(finding);
        }

        // Find persistent state patterns
        let persistent = self.find_persistent_state_patterns(source);
        for (line, func_name) in persistent {
            if reported_lines.contains(&line) {
                continue;
            }

            let message = format!(
                "Function '{}' in contract '{}' uses transient storage for what appears \
                 to be persistent state (owner, balance, nonce, etc.). This data will be \
                 lost after each transaction.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362) // CWE-362: Race Condition
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "State like owner, balances, nonces must use persistent storage:\n\n\
                     // BAD: transient storage for owner\n\
                     assembly { tstore(OWNER_SLOT, newOwner) }\n\n\
                     // GOOD: persistent storage\n\
                     owner = newOwner;  // Standard storage variable"
                        .to_string(),
                );

            findings.push(finding);
        }

        // Find initialization in transient storage
        let inits = self.find_transient_init(source);
        for (line, func_name) in inits {
            if reported_lines.contains(&line) {
                continue;
            }

            let message = format!(
                "Function '{}' in contract '{}' initializes state using only transient \
                 storage. Initialization data will be lost after the transaction completes.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(362) // CWE-362: Race Condition
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Initialization must use persistent storage:\n\n\
                     function initialize() external {\n\
                         owner = msg.sender;  // Persists\n\
                         // NOT: assembly { tstore(0, caller()) }  // Lost after tx!\n\
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
        let detector = Eip1153CrossTxAssumptionDetector::new();
        assert_eq!(detector.name(), "EIP-1153 Cross-Transaction Assumption");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_separate_store_load() {
        let detector = Eip1153CrossTxAssumptionDetector::new();

        let vulnerable = r#"
            contract BadStorage {
                function setFlag() external {
                    assembly { tstore(0, 1) }
                }

                function checkFlag() external {
                    assembly {
                        let flag := tload(0)
                        if iszero(flag) { revert(0, 0) }
                    }
                }
            }
        "#;
        let findings = detector.find_separate_store_load(vulnerable);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_view_tload() {
        let detector = Eip1153CrossTxAssumptionDetector::new();

        let vulnerable = r#"
            contract BadView {
                function getState() external view returns (uint256 result) {
                    assembly { result := tload(0) }
                }
            }
        "#;
        let findings = detector.find_view_tload(vulnerable);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_persistent_patterns() {
        let detector = Eip1153CrossTxAssumptionDetector::new();

        let vulnerable = r#"
            contract BadOwner {
                function setOwner(address newOwner) external {
                    assembly { tstore(0, newOwner) }
                }
            }
        "#;
        let findings = detector.find_persistent_state_patterns(vulnerable);
        assert!(!findings.is_empty());
    }
}
