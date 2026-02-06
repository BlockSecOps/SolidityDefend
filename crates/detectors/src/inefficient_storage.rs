use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for inefficient storage patterns and layout issues
pub struct InefficientStorageDetector {
    base: BaseDetector,
}

impl Default for InefficientStorageDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl InefficientStorageDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("inefficient-storage".to_string()),
                "Inefficient Storage Usage".to_string(),
                // Phase 6 FP Reduction: Reclassified from Low to Info.
                // This is a gas optimization suggestion, not a security vulnerability.
                "Detects inefficient storage patterns including unpacked structs, redundant storage variables, and suboptimal storage layout that waste gas".to_string(),
                vec![DetectorCategory::BestPractices],
                Severity::Info,
            ),
        }
    }
}

impl Detector for InefficientStorageDetector {
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
        let contract_source = ctx.source_code.as_str();

        // Check for inefficient storage patterns at contract level
        if let Some(storage_issues) = self.check_storage_layout(contract_source) {
            for (line_num, issue_desc) in storage_issues {
                let message = format!(
                    "Inefficient storage pattern detected. {} \
                    Inefficient storage layout increases gas costs for all state-modifying operations.",
                    issue_desc
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line_num, 0, 30)
                    .with_cwe(400) // CWE-400: Uncontrolled Resource Consumption
                    .with_fix_suggestion(
                        "Optimize storage layout. \
                    Consider: (1) Pack variables <32 bytes together in structs, \
                    (2) Order struct fields by size (largest to smallest), \
                    (3) Use uint256 instead of smaller types for standalone variables, \
                    (4) Combine boolean flags into a single uint256 bitmap, \
                    (5) Use constants/immutables for unchanging values."
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

impl InefficientStorageDetector {
    fn check_storage_layout(&self, contract_source: &str) -> Option<Vec<(u32, String)>> {
        let lines: Vec<&str> = contract_source.lines().collect();
        let mut issues = Vec::new();

        // Track boolean storage variables for Pattern 2
        let mut bool_storage_vars: Vec<(u32, &str)> = Vec::new();

        // Pattern 1: Unpacked structs (mixed sizes without optimization)
        let mut in_struct = false;
        let mut struct_start_line = 0;
        let mut struct_has_uint256 = false;
        let mut struct_has_small_types = false;
        let mut struct_small_count = 0;

        for (line_idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("struct ") {
                in_struct = true;
                struct_start_line = line_idx;
                struct_has_uint256 = false;
                struct_has_small_types = false;
                struct_small_count = 0;
            }

            if in_struct {
                if trimmed.contains("uint256") || trimmed.contains("address") {
                    struct_has_uint256 = true;
                }
                if trimmed.contains("uint8")
                    || trimmed.contains("uint16")
                    || trimmed.contains("uint32")
                    || trimmed.contains("uint64")
                    || trimmed.contains("uint128")
                    || trimmed.contains("bool")
                {
                    struct_has_small_types = true;
                    struct_small_count += 1;
                }

                if trimmed == "}" {
                    in_struct = false;
                    // Only flag if there are enough small types to make packing worthwhile (3+)
                    if struct_has_uint256 && struct_has_small_types && struct_small_count >= 3 {
                        issues.push((
                            (struct_start_line + 1) as u32,
                            "Struct contains mixed uint256 and smaller types. Pack smaller types together for gas savings".to_string()
                        ));
                    }
                }
            }

            // Track boolean storage variables (only at contract level)
            if !in_struct
                && trimmed.contains("bool ")
                && (trimmed.contains("public")
                    || trimmed.contains("private")
                    || trimmed.contains("internal"))
                && !trimmed.contains("mapping")
                && !trimmed.contains("constant")
            {
                bool_storage_vars.push(((line_idx + 1) as u32, trimmed));
            }

            // Pattern 3: Small uint types as standalone storage variables
            // Only flag if it's clearly inefficient (not semantically meaningful)
            if !in_struct
                && (trimmed.contains("uint8 ")
                    || trimmed.contains("uint16 "))
                && (trimmed.contains("public")
                    || trimmed.contains("private")
                    || trimmed.contains("internal"))
                && !trimmed.contains("decimals") // uint8 for decimals is standard
                && !trimmed.contains("version")  // uint8 for version is acceptable
                && !trimmed.contains("nonce")    // small nonces are intentional
                && !trimmed.contains("status")   // status codes are often uint8
                && !trimmed.contains("state")    // state enums are often uint8
                && !trimmed.contains("index")    // indices can be intentionally small
                && !trimmed.contains("count")    // counts can be intentionally bounded
                && !trimmed.contains("id")       // IDs can be intentionally small
                && !trimmed.contains("type")
            // type codes are often uint8
            {
                issues.push((
                    (line_idx + 1) as u32,
                    "Small uint type as standalone storage variable. Use uint256 or pack with other variables".to_string()
                ));
            }

            // Pattern 4: Constant-like variables stored in storage
            // Only flag if it looks like a hardcoded constant that never changes
            if trimmed.contains(" = ")
                && (trimmed.contains("public") || trimmed.contains("private"))
                && !trimmed.contains("constant")
                && !trimmed.contains("immutable")
                && !trimmed.contains("mapping")
                && !trimmed.contains("address")  // addresses aren't constants
                && !trimmed.contains("bool")
            // bools set to false/true are state
            {
                // Check for common constant patterns (large round numbers)
                let is_constant_like = (trimmed.contains("= 1000")
                    || trimmed.contains("= 10000")
                    || trimmed.contains("= 100000")
                    || trimmed.contains("= 1e"))
                    && !trimmed.contains("block.");

                // Exclude governance/configurable parameters that are intentionally
                // stored in storage because they can be updated via admin functions.
                let is_governance_param = trimmed.contains("threshold")
                    || trimmed.contains("Threshold")
                    || trimmed.contains("quorum")
                    || trimmed.contains("delay")
                    || trimmed.contains("Delay")
                    || trimmed.contains("period")
                    || trimmed.contains("Period")
                    || trimmed.contains("limit")
                    || trimmed.contains("Limit")
                    || trimmed.contains("fee")
                    || trimmed.contains("Fee")
                    || trimmed.contains("rate")
                    || trimmed.contains("Rate")
                    || trimmed.contains("min")
                    || trimmed.contains("max")
                    || trimmed.contains("Max")
                    || trimmed.contains("Min");

                if is_constant_like && !is_governance_param {
                    issues.push((
                        (line_idx + 1) as u32,
                        "Variable initialized with constant value but not marked as constant/immutable. Use constant or immutable".to_string()
                    ));
                }
            }
        }

        // Pattern 2: Only flag booleans if there are 3+ that could be packed
        if bool_storage_vars.len() >= 3 {
            issues.push((
                bool_storage_vars[0].0,
                format!(
                    "{} boolean storage variables found. Consider packing into uint256 bitmap for gas savings",
                    bool_storage_vars.len()
                )
            ));
        }

        // Pattern 5: Redundant storage reads
        for function in self.extract_functions(contract_source) {
            if self.has_redundant_storage_reads(&function.source) {
                issues.push((
                    function.line as u32,
                    format!(
                        "Function '{}' reads same storage variable multiple times. Cache in memory",
                        function.name
                    ),
                ));
            }
        }

        if issues.is_empty() {
            None
        } else {
            Some(issues)
        }
    }

    fn extract_functions(&self, source: &str) -> Vec<FunctionInfo> {
        let mut functions = Vec::new();
        let lines: Vec<&str> = source.lines().collect();
        let mut current_function: Option<(String, usize, Vec<String>)> = None;

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("function ") {
                if let Some(name) = self.extract_function_name(trimmed) {
                    current_function = Some((name, idx + 1, Vec::new()));
                }
            }

            if let Some((_, _, ref mut func_lines)) = current_function {
                func_lines.push(line.to_string());

                if trimmed == "}"
                    && func_lines.iter().filter(|l| l.contains('{')).count()
                        == func_lines.iter().filter(|l| l.contains('}')).count()
                {
                    let (name, line, source_lines) = current_function.take().unwrap();
                    functions.push(FunctionInfo {
                        name,
                        line,
                        source: source_lines.join("\n"),
                    });
                }
            }
        }

        functions
    }

    fn extract_function_name(&self, line: &str) -> Option<String> {
        if let Some(start) = line.find("function ") {
            let after_keyword = &line[start + 9..];
            if let Some(end) = after_keyword.find('(') {
                return Some(after_keyword[..end].trim().to_string());
            }
        }
        None
    }

    fn has_redundant_storage_reads(&self, function_source: &str) -> bool {
        // Skip view/pure functions -- gas optimization is less critical for read-only functions
        let first_lines: String = function_source
            .lines()
            .take(3)
            .collect::<Vec<_>>()
            .join(" ");
        if first_lines.contains(" view ") || first_lines.contains(" pure ") {
            return false;
        }

        // Skip flash loan functions that use before/after balance comparison patterns
        // These are security-critical patterns, not redundant reads
        let source_lower = function_source.to_lowercase();
        if (source_lower.contains("before") && source_lower.contains("after"))
            || source_lower.contains("flashloan")
            || source_lower.contains("flash_loan")
            || source_lower.contains("flashmint")
        {
            return false;
        }

        // Skip functions with external calls between storage reads --
        // re-reading after an external call may be intentional to detect manipulation
        if function_source.contains(".call{")
            || function_source.contains(".call(")
            || function_source.contains(".transfer(")
            || function_source.contains("onFlashLoan")
        {
            return false;
        }

        let state_vars = ["owner", "totalSupply", "paused", "balance"];

        // Remove comments to avoid false positives
        let source_no_comments: String = function_source
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                !trimmed.starts_with("//")
                    && !trimmed.starts_with("*")
                    && !trimmed.starts_with("/*")
            })
            .collect::<Vec<_>>()
            .join("\n");

        for var in &state_vars {
            // Use word-boundary matching to avoid substring false positives.
            // For example, "balance" should not match "balanceBefore", "balanceOf",
            // "balanceAfter", or ".balance" (address property).
            let exact_count = self.count_exact_storage_reads(&source_no_comments, var);

            // Require 4+ exact usages to flag (high threshold to avoid FPs)
            if exact_count > 3
                && !source_no_comments.contains(&format!("uint256 {} =", var))
                && !source_no_comments.contains(&format!("{} memory", var))
            {
                return true;
            }
        }

        false
    }

    /// Count exact word-boundary matches for a storage variable name.
    /// Avoids matching substrings like "balanceBefore" when searching for "balance".
    fn count_exact_storage_reads(&self, source: &str, var_name: &str) -> usize {
        let mut count = 0;
        let var_bytes = var_name.as_bytes();
        let src_bytes = source.as_bytes();
        let var_len = var_bytes.len();

        if src_bytes.len() < var_len {
            return 0;
        }

        for i in 0..=(src_bytes.len() - var_len) {
            if &src_bytes[i..i + var_len] == var_bytes {
                // Check character before the match (word boundary)
                let before_ok = if i == 0 {
                    true
                } else {
                    let c = src_bytes[i - 1] as char;
                    !c.is_alphanumeric() && c != '_'
                };

                // Check character after the match (word boundary)
                let after_ok = if i + var_len >= src_bytes.len() {
                    true
                } else {
                    let c = src_bytes[i + var_len] as char;
                    !c.is_alphanumeric() && c != '_'
                };

                if before_ok && after_ok {
                    count += 1;
                }
            }
        }

        count
    }
}

struct FunctionInfo {
    name: String,
    line: usize,
    source: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = InefficientStorageDetector::new();
        assert_eq!(detector.name(), "Inefficient Storage Usage");
        // Phase 6: Reclassified from Low to Info (gas optimization, not security)
        assert_eq!(detector.default_severity(), Severity::Info);
        assert!(detector.is_enabled());
    }

    // --- Word-boundary matching tests ---

    #[test]
    fn test_count_exact_storage_reads_word_boundary() {
        let detector = InefficientStorageDetector::new();

        // "balance" should NOT match "balanceBefore", "balanceOf", "balanceAfter"
        let source = "uint256 balanceBefore = balanceOf[msg.sender];\nuint256 balanceAfter = balanceOf[msg.sender];";
        assert_eq!(detector.count_exact_storage_reads(source, "balance"), 0);

        // "balance" SHOULD match standalone "balance" usage
        let source2 = "balance += 1;\nbalance -= 2;\nbalance = 0;\nbalance;";
        assert_eq!(detector.count_exact_storage_reads(source2, "balance"), 4);

        // "owner" should NOT match "onlyOwner" or "Ownable"
        let source3 = "modifier onlyOwner() { require(msg.sender == Ownable.owner()); }";
        // "owner" appears once as a standalone word in "Ownable.owner()" -- the .owner() part
        // Actually let's trace: "onlyOwner" -- o-n-l-y-O-w-n-e-r, the "owner" at position 4 has 'y' before it
        // so before_ok is false. "Ownable" doesn't contain "owner". ".owner()" has "owner" at position after "."
        // The "." is not alphanumeric and not '_', so before_ok = true. After is "(", so after_ok = true.
        assert_eq!(detector.count_exact_storage_reads(source3, "owner"), 1);

        // "totalSupply" should NOT match "totalSupplySnapshot" etc.
        let source4 = "uint256 supply = totalSupplySnapshot;\ntotalSupply += 1;";
        assert_eq!(
            detector.count_exact_storage_reads(source4, "totalSupply"),
            1
        );
    }

    // --- Pattern 5: Redundant storage reads FP reduction ---

    #[test]
    fn test_no_fp_on_view_functions() {
        let detector = InefficientStorageDetector::new();
        // View functions should not trigger redundant storage reads
        let source = r#"
    function getVotingPower(address account) public view returns (uint256) {
        return owner + owner + owner + owner + owner;
    }
"#;
        assert!(!detector.has_redundant_storage_reads(source));
    }

    #[test]
    fn test_no_fp_on_pure_functions() {
        let detector = InefficientStorageDetector::new();
        let source = r#"
    function calculate(uint256 x) public pure returns (uint256) {
        return owner + owner + owner + owner + owner;
    }
"#;
        assert!(!detector.has_redundant_storage_reads(source));
    }

    #[test]
    fn test_no_fp_on_flash_loan_before_after_pattern() {
        let detector = InefficientStorageDetector::new();
        // Flash loan balance before/after is a security pattern
        let source = r#"
    function flashLoan(address receiver, uint256 amount) external {
        uint256 balanceBefore = address(this).balance;
        payable(receiver).transfer(amount);
        IFlashBorrower(receiver).onFlashLoan(msg.sender, address(this), amount, 0, "");
        uint256 balanceAfter = address(this).balance;
        require(balanceAfter >= balanceBefore, "Flash loan not repaid");
    }
"#;
        assert!(!detector.has_redundant_storage_reads(source));
    }

    #[test]
    fn test_no_fp_on_functions_with_external_calls() {
        let detector = InefficientStorageDetector::new();
        // Re-reading after external call is intentional for security
        let source = r#"
    function doSomething() external {
        uint256 before = totalSupply;
        target.call{value: 1}("");
        require(totalSupply == before, "Reentrancy detected");
        totalSupply += 1;
        totalSupply += 2;
    }
"#;
        assert!(!detector.has_redundant_storage_reads(source));
    }

    #[test]
    fn test_no_fp_on_substring_matches() {
        let detector = InefficientStorageDetector::new();
        // "balance" substring in balanceOf, balanceBefore, balanceAfter should not count
        let source = r#"
    function withdraw(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount);
        balanceOf[msg.sender] -= amount;
        uint256 balanceBefore = address(this).balance;
        uint256 balanceAfter = address(this).balance;
    }
"#;
        assert!(!detector.has_redundant_storage_reads(source));
    }

    #[test]
    fn test_tp_on_genuine_redundant_reads() {
        let detector = InefficientStorageDetector::new();
        // Genuine redundant reads of the same storage variable should still be caught
        let source = r#"
    function inefficient() external {
        uint256 a = totalSupply;
        uint256 b = totalSupply;
        uint256 c = totalSupply;
        uint256 d = totalSupply;
    }
"#;
        assert!(detector.has_redundant_storage_reads(source));
    }

    // --- Pattern 4: Governance parameter FP reduction ---

    #[test]
    fn test_no_fp_on_governance_parameters() {
        let detector = InefficientStorageDetector::new();
        let source = r#"
contract Governance {
    uint256 public proposalThreshold = 100000e18;
    uint256 public quorum = 10000;
    uint256 public votingDelay = 10000;
    uint256 public minDeposit = 1000;
}
"#;
        let issues = detector.check_storage_layout(source);
        // Should not flag any of these as "constant-like"
        if let Some(ref found_issues) = issues {
            for (_, desc) in found_issues {
                assert!(
                    !desc.contains("constant/immutable"),
                    "Should not flag governance parameter as constant: {}",
                    desc
                );
            }
        }
    }

    #[test]
    fn test_tp_on_actual_constants() {
        let detector = InefficientStorageDetector::new();
        let source = r#"
contract Example {
    uint256 public multiplier = 10000;
}
"#;
        let issues = detector.check_storage_layout(source);
        let has_constant_warning = issues
            .as_ref()
            .map(|v| {
                v.iter()
                    .any(|(_, desc)| desc.contains("constant/immutable"))
            })
            .unwrap_or(false);
        assert!(
            has_constant_warning,
            "Should flag non-governance constant-like variable"
        );
    }
}
