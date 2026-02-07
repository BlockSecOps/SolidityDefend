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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

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

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl InefficientStorageDetector {
    /// Check if a line contains a Solidity visibility keyword (`public`,
    /// `private`, or `internal`) as a standalone word. This avoids false
    /// positives where the keyword appears inside an identifier, e.g.
    /// `publicInputs` should NOT match `public`.
    fn has_visibility_keyword(line: &str) -> bool {
        for keyword in &["public", "private", "internal"] {
            let kw_bytes = keyword.as_bytes();
            let line_bytes = line.as_bytes();
            let kw_len = kw_bytes.len();
            if line_bytes.len() < kw_len {
                continue;
            }
            for i in 0..=(line_bytes.len() - kw_len) {
                if &line_bytes[i..i + kw_len] == kw_bytes {
                    let before_ok = if i == 0 {
                        true
                    } else {
                        let c = line_bytes[i - 1] as char;
                        !c.is_alphanumeric() && c != '_'
                    };
                    let after_ok = if i + kw_len >= line_bytes.len() {
                        true
                    } else {
                        let c = line_bytes[i + kw_len] as char;
                        !c.is_alphanumeric() && c != '_'
                    };
                    if before_ok && after_ok {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if the contract source represents an interface or library,
    /// which have no storage layout and should be skipped entirely.
    fn is_interface_or_library(source: &str) -> bool {
        for line in source.lines() {
            let trimmed = line.trim();
            // Match top-level interface/library declarations
            if (trimmed.starts_with("interface ") || trimmed.starts_with("library "))
                && (trimmed.contains('{') || trimmed.ends_with('{'))
            {
                return true;
            }
        }
        false
    }

    /// Check if the contract uses direct storage slot manipulation (EIP-1967,
    /// Diamond storage, or similar patterns). These contracts intentionally
    /// manage their own storage layout and should not be flagged.
    fn uses_direct_storage_slots(source: &str) -> bool {
        let lower = source.to_lowercase();
        // EIP-1967 proxy storage slot patterns
        lower.contains("bytes32(uint256(keccak256(")
            || lower.contains("eip1967")
            || lower.contains("erc1967")
            // Diamond storage pattern
            || lower.contains("diamondstorage")
            || lower.contains("diamond_storage")
            || lower.contains("diamond.storage")
            // AppStorage pattern (Diamond/EIP-2535)
            || lower.contains("appstorage")
            // assembly sstore/sload direct slot usage
            || (lower.contains("sstore(") && lower.contains("sload("))
    }

    /// Count standalone state variables in the contract source (excludes
    /// constants, immutables, mappings, dynamic arrays, and struct members).
    fn count_state_variables(source: &str) -> usize {
        let mut count = 0;
        let mut in_struct = false;
        let mut in_function = false;
        let mut brace_depth: i32 = 0;

        for line in source.lines() {
            let trimmed = line.trim();

            if trimmed.starts_with("struct ") {
                in_struct = true;
            }
            if trimmed.starts_with("function ")
                || trimmed.starts_with("constructor(")
                || trimmed.starts_with("modifier ")
            {
                in_function = true;
            }

            for ch in trimmed.chars() {
                if ch == '{' {
                    brace_depth += 1;
                } else if ch == '}' {
                    brace_depth -= 1;
                    if brace_depth <= 1 {
                        in_struct = false;
                        in_function = false;
                    }
                }
            }

            // Only count lines that look like state variable declarations
            // at the contract level (brace_depth == 1, not inside struct/function)
            if !in_struct
                && !in_function
                && brace_depth == 1
                && (trimmed.contains("public")
                    || trimmed.contains("private")
                    || trimmed.contains("internal"))
                && !trimmed.starts_with("//")
                && !trimmed.starts_with("*")
                && !trimmed.starts_with("/*")
                && !trimmed.starts_with("function ")
                && !trimmed.starts_with("event ")
                && !trimmed.starts_with("error ")
                && !trimmed.starts_with("modifier ")
                && !trimmed.starts_with("constructor")
                && trimmed.contains(';')
            {
                count += 1;
            }
        }
        count
    }

    fn check_storage_layout(&self, contract_source: &str) -> Option<Vec<(u32, String)>> {
        // FP Reduction: Skip interfaces and libraries -- they have no storage layout
        if Self::is_interface_or_library(contract_source) {
            return None;
        }

        // FP Reduction: Skip contracts using direct storage slot manipulation
        // (EIP-1967 proxies, Diamond storage) -- they manage layout explicitly
        if Self::uses_direct_storage_slots(contract_source) {
            return None;
        }

        let lines: Vec<&str> = contract_source.lines().collect();
        let mut issues = Vec::new();

        // FP Reduction: Count state variables early. Contracts with very few
        // state variables (0-2) have no meaningful packing opportunity, so
        // skip Patterns 1-3 (struct packing, boolean bitmap, small uint).
        let state_var_count = Self::count_state_variables(contract_source);
        let has_enough_vars_for_packing = state_var_count >= 3;

        // Track boolean storage variables for Pattern 2, per-contract.
        // FP Reduction: Booleans in different contracts cannot be packed together,
        // so we reset tracking when a new contract/interface/library is found.
        let mut bool_storage_vars: Vec<(u32, &str)> = Vec::new();

        // Pattern 1: Unpacked structs (mixed sizes without optimization)
        let mut in_struct = false;
        let mut struct_start_line = 0;
        let mut struct_has_uint256 = false;
        let mut struct_has_small_types = false;
        let mut struct_small_count = 0;

        for (line_idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // FP Reduction: When encountering a new contract/interface/library
            // boundary, flush the current boolean tracking. Booleans in
            // different contracts are separate storage layouts.
            if (trimmed.starts_with("contract ")
                || trimmed.starts_with("interface ")
                || trimmed.starts_with("library "))
                && (trimmed.contains('{') || trimmed.ends_with('{'))
            {
                // Emit finding for the previous contract's booleans if 3+
                if bool_storage_vars.len() >= 3 && has_enough_vars_for_packing {
                    issues.push((
                        bool_storage_vars[0].0,
                        format!(
                            "{} boolean storage variables found. Consider packing into uint256 bitmap for gas savings",
                            bool_storage_vars.len()
                        )
                    ));
                }
                bool_storage_vars.clear();
            }

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
            // FP Reduction: Also skip immutable booleans (not in storage slots)
            // FP Reduction: Use word-boundary visibility check to avoid matching
            // identifiers like "publicInputs" as visibility "public"
            if !in_struct
                && trimmed.contains("bool ")
                && Self::has_visibility_keyword(trimmed)
                && !trimmed.contains("mapping")
                && !trimmed.contains("constant")
                && !trimmed.contains("immutable")
            {
                bool_storage_vars.push(((line_idx + 1) as u32, trimmed));
            }

            // Pattern 3: Small uint types as standalone storage variables
            // Only flag if it's clearly inefficient (not semantically meaningful)
            // FP Reduction: Also skip immutable variables (not in storage slots),
            // skip mappings/arrays (occupy full slots regardless of type),
            // and skip if there aren't enough state vars for packing to matter
            if !in_struct
                && has_enough_vars_for_packing
                && (trimmed.contains("uint8 ")
                    || trimmed.contains("uint16 "))
                && Self::has_visibility_keyword(trimmed)
                && !trimmed.contains("immutable")
                && !trimmed.contains("constant")
                && !trimmed.contains("mapping")  // mappings use full slots
                && !trimmed.contains("[]")       // arrays use full slots
                && !trimmed.contains("decimals") // uint8 for decimals is standard
                && !trimmed.contains("version")  // uint8 for version is acceptable
                && !trimmed.contains("nonce")    // small nonces are intentional
                && !trimmed.contains("status")   // status codes are often uint8
                && !trimmed.contains("state")    // state enums are often uint8
                && !trimmed.contains("index")    // indices can be intentionally small
                && !trimmed.contains("count")    // counts can be intentionally bounded
                && !trimmed.contains("id")       // IDs can be intentionally small
                && !trimmed.contains("type")     // type codes are often uint8
                && !trimmed.contains("support")  // e.g. uint8 support in governance
                && !trimmed.contains("level")    // level indicators
                && !trimmed.contains("flag")
            // flag values
            {
                issues.push((
                    (line_idx + 1) as u32,
                    "Small uint type as standalone storage variable. Use uint256 or pack with other variables".to_string()
                ));
            }

            // Pattern 4: Constant-like variables stored in storage
            // Only flag if it looks like a hardcoded constant that never changes
            if trimmed.contains(" = ")
                && Self::has_visibility_keyword(trimmed)
                && !trimmed.contains("constant")
                && !trimmed.contains("immutable")
                && !trimmed.contains("mapping")
                && !trimmed.contains("address")  // addresses aren't constants
                && !trimmed.contains("bool")     // bools set to false/true are state
                && !trimmed.contains("string")
            // string literals are not numeric constants
            {
                // Check for common constant patterns (large round numbers)
                let is_constant_like = (trimmed.contains("= 1000")
                    || trimmed.contains("= 10000")
                    || trimmed.contains("= 100000")
                    || trimmed.contains("= 1e"))
                    && !trimmed.contains("block.");

                // FP Reduction: Exclude variables with multiplication/exponentiation
                // expressions (e.g., "1000000 * 10**18") -- these are often initial
                // supply values that change at runtime via mint/burn.
                let has_arithmetic = trimmed.contains("* 10**")
                    || trimmed.contains("* 1e")
                    || trimmed.contains("**18")
                    || trimmed.contains("**6");

                // FP Reduction: Exclude variables whose names indicate they change
                // at runtime (supply, balance, pool, price, reward, etc.)
                let is_runtime_variable = {
                    let lower = trimmed.to_lowercase();
                    lower.contains("supply")
                        || lower.contains("balance")
                        || lower.contains("pool")
                        || lower.contains("price")
                        || lower.contains("reward")
                        || lower.contains("total")
                        || lower.contains("reserve")
                        || lower.contains("amount")
                        || lower.contains("stake")
                        || lower.contains("deposit")
                        || lower.contains("liquidity")
                        || lower.contains("rebase")
                        || lower.contains("multiplier")
                        || lower.contains("factor")
                };

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
                    || trimmed.contains("Min")
                    || trimmed.contains("boost")
                    || trimmed.contains("Boost")
                    || trimmed.contains("window")
                    || trimmed.contains("Window");

                if is_constant_like
                    && !is_governance_param
                    && !has_arithmetic
                    && !is_runtime_variable
                {
                    issues.push((
                        (line_idx + 1) as u32,
                        "Variable initialized with constant value but not marked as constant/immutable. Use constant or immutable".to_string()
                    ));
                }
            }
        }

        // Pattern 2: Only flag booleans if there are 3+ that could be packed
        // FP Reduction: Also require enough state variables overall for packing
        // to be a meaningful optimization
        if bool_storage_vars.len() >= 3 && has_enough_vars_for_packing {
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

    /// Extract parameter names from a function signature.
    /// For example, `function permit(address owner, address spender, uint256 value)`
    /// would return `["owner", "spender", "value"]`.
    fn extract_function_params(function_source: &str) -> Vec<String> {
        let mut params = Vec::new();

        // Collect lines until we find the opening brace to get the full signature
        let mut sig = String::new();
        for line in function_source.lines() {
            sig.push_str(line.trim());
            sig.push(' ');
            if line.contains('{') {
                break;
            }
        }

        // Extract the parameter list between the first '(' and its matching ')'
        if let Some(start) = sig.find('(') {
            let after_paren = &sig[start + 1..];
            let mut depth = 1;
            let mut end_idx = after_paren.len();
            for (i, ch) in after_paren.char_indices() {
                if ch == '(' {
                    depth += 1;
                } else if ch == ')' {
                    depth -= 1;
                    if depth == 0 {
                        end_idx = i;
                        break;
                    }
                }
            }
            let param_str = &after_paren[..end_idx];
            // Split by commas and extract parameter names
            for param in param_str.split(',') {
                let tokens: Vec<&str> = param.trim().split_whitespace().collect();
                // Parameter format: <type> [storage|memory|calldata] <name>
                // The name is the last token (if there are at least 2 tokens)
                if tokens.len() >= 2 {
                    let name = tokens.last().unwrap().trim();
                    // Skip empty or non-identifier names
                    if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                        params.push(name.to_string());
                    }
                }
            }
        }
        params
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

        // FP Reduction: Skip ERC-2612 permit functions and similar standard
        // EIP functions. These use parameter names like "owner" that collide
        // with common state variable names. The repeated usage is of the
        // function parameter, not a redundant storage read.
        let func_name_lower = source_lower.lines().next().unwrap_or("").trim().to_string();
        if func_name_lower.contains("permit")
            || func_name_lower.contains("approve")
            || func_name_lower.contains("_approve")
        {
            return false;
        }

        // FP Reduction: Extract function parameter names so we can exclude
        // them from the state variable read check. For example, in
        // `function foo(address owner, ...)`, "owner" is a parameter, not
        // a storage read.
        let param_names = Self::extract_function_params(function_source);

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
            // FP Reduction: If the state variable name matches a function
            // parameter, skip it -- the references are to the parameter,
            // not to storage.
            if param_names.iter().any(|p| p == var) {
                continue;
            }

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
    uint256 public precision = 10000;
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
