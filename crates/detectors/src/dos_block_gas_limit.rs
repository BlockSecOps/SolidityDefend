use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for DoS via block gas limit
///
/// Detects patterns where operations can exceed the block gas limit,
/// making transactions impossible to execute.
pub struct DosBlockGasLimitDetector {
    base: BaseDetector,
}

impl Default for DosBlockGasLimitDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DosBlockGasLimitDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("dos-block-gas-limit"),
                "DoS Block Gas Limit".to_string(),
                "Detects operations that can exceed block gas limit, making functions \
                 impossible to execute as the data grows."
                    .to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::BestPractices],
                Severity::High,
            ),
        }
    }

    /// Find unbounded loops over storage
    fn find_unbounded_loops(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect for loops with .length
            if trimmed.contains("for") && trimmed.contains(".length") {
                let func_name = self.find_containing_function(&lines, line_num);

                // Skip constructor loops - they run once, not a DoS risk
                if self.is_inside_constructor(&lines, line_num) {
                    continue;
                }

                // Skip view/pure functions - they don't run as transactions
                // They're read-only calls that don't consume block gas limit
                if self.is_inside_view_or_pure(&lines, line_num) {
                    continue;
                }

                let loop_end = self.find_block_end(&lines, line_num);
                let loop_body: String = lines[line_num..loop_end].join("\n");
                let func_body = self.get_function_body(&lines, line_num);

                // Check if there's pagination or bounds limiting
                let has_bounds = self.has_loop_bounds(&func_body, &loop_body);

                if !has_bounds {
                    // Estimate gas cost - only flag if gas-intensive operations
                    let gas_intensive = loop_body.contains("SSTORE")
                        || loop_body.contains("storage")
                        || loop_body.contains(".transfer(")
                        || loop_body.contains(".call{")
                        || loop_body.contains("delete ")
                        || loop_body.contains("emit ")  // Events cost gas
                        || loop_body.contains("= "); // Storage writes

                    if gas_intensive {
                        let issue = "Unbounded loop with gas-intensive operations (storage writes, transfers, or events)".to_string();
                        findings.push((line_num as u32 + 1, func_name, issue));
                    }
                    // Don't flag simple read loops - they're usually fine
                }
            }
        }

        findings
    }

    /// Check if loop has bounds (pagination, require, or fixed limit)
    fn has_loop_bounds(&self, func_body: &str, loop_body: &str) -> bool {
        // Pagination parameters
        let has_pagination = func_body.contains("start")
            || func_body.contains("offset")
            || func_body.contains("limit")
            || func_body.contains("count")
            || func_body.contains("batch")
            || func_body.contains("pageSize");

        // Explicit max limit constants
        let has_max_limit = func_body.contains("MAX_")
            || func_body.contains("_MAX")
            || func_body.contains("maxItems")
            || func_body.contains("maxLength")
            || func_body.contains("maxSize");

        // Require statement limiting array size
        let has_require_limit = func_body.contains("require")
            && (func_body.contains(".length")
                && (func_body.contains("<=") || func_body.contains("<")));

        // Loop has early exit conditions
        let has_early_exit = loop_body.contains("break") || loop_body.contains("return");

        // Fixed iteration count (not .length)
        let has_fixed_count = loop_body.contains("< 10")
            || loop_body.contains("< 20")
            || loop_body.contains("< 50")
            || loop_body.contains("< 100")
            || loop_body.contains("<= 10")
            || loop_body.contains("<= 20")
            || loop_body.contains("<= 50")
            || loop_body.contains("<= 100");

        // Fixed-size array allocation: check if the loop iterates over an array
        // that was created with a small fixed literal size, e.g.:
        //   bytes32[] memory roles = new bytes32[](5);
        //   for (uint256 i = 0; i < roles.length; i++) { ... }
        let has_fixed_alloc = self.loop_iterates_fixed_size_array(func_body, loop_body);

        has_pagination
            || has_max_limit
            || has_require_limit
            || has_early_exit
            || has_fixed_count
            || has_fixed_alloc
    }

    /// Check if the loop iterates over an array that was created with a small
    /// fixed-size literal allocation in the same function.
    /// Matches pattern: `Type[] memory varName = new Type[](N);`
    /// where the loop condition uses `varName.length`.
    fn loop_iterates_fixed_size_array(&self, func_body: &str, loop_body: &str) -> bool {
        // Extract the array name from the loop condition: `varName.length`
        // The loop_body first line typically contains `for (... i < something.length ...)`
        let first_line = loop_body.lines().next().unwrap_or("");
        let length_var = self.extract_length_variable(first_line);
        let length_var = match length_var {
            Some(v) => v,
            None => return false,
        };

        // Now look in the function body for: varName = new Type[](N)
        for line in func_body.lines() {
            let trimmed = line.trim();
            // Check if this line allocates the array we're iterating over
            if !trimmed.contains(&length_var) || !trimmed.contains("new ") {
                continue;
            }
            if let Some(bracket_pos) = trimmed.find("](") {
                let after_bracket = &trimmed[bracket_pos + 2..];
                if let Some(close_paren) = after_bracket.find(')') {
                    let size_str = after_bracket[..close_paren].trim();
                    if let Ok(size) = size_str.parse::<u64>() {
                        if size <= 256 {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Extract the variable name from a `.length` access in a for-loop condition.
    /// For `for (uint256 i = 0; i < roles.length; i++)` returns `Some("roles")`.
    fn extract_length_variable(&self, loop_line: &str) -> Option<String> {
        if let Some(len_pos) = loop_line.find(".length") {
            // Walk backwards from `.length` to find the variable name
            let before = &loop_line[..len_pos];
            let var_name: String = before
                .chars()
                .rev()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect::<String>()
                .chars()
                .rev()
                .collect();
            if !var_name.is_empty() {
                return Some(var_name);
            }
        }
        None
    }

    /// Check if line is inside a view or pure function.
    /// Handles multi-line function signatures where view/pure may be on a
    /// different line than the `function` keyword.
    fn is_inside_view_or_pure(&self, lines: &[&str], line_num: usize) -> bool {
        // Walk backwards to find the enclosing function declaration
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") || trimmed.starts_with("function ") {
                // Collect the full function signature (from function keyword to opening brace)
                let sig = self.get_function_signature(lines, i);
                return sig.contains(" view")
                    || sig.contains(" pure")
                    || sig.contains("\tview")
                    || sig.contains("\tpure");
            }
            // Stop at contract/constructor boundary
            if trimmed.starts_with("contract ")
                || trimmed.starts_with("constructor")
                || trimmed.contains("constructor(")
            {
                return false;
            }
        }
        false
    }

    /// Collect the full function signature text from the `function` keyword
    /// line up to and including the opening `{`. This handles multi-line
    /// signatures where modifiers like `view`, `pure`, `internal`, `external`,
    /// `onlyOwner`, etc. span multiple lines.
    fn get_function_signature(&self, lines: &[&str], func_line: usize) -> String {
        let mut sig = String::new();
        for i in func_line..lines.len() {
            sig.push_str(lines[i]);
            sig.push(' ');
            if lines[i].contains('{') {
                break;
            }
        }
        sig
    }

    /// Get full function body for analysis
    fn get_function_body(&self, lines: &[&str], line_num: usize) -> String {
        let func_start = self.find_function_start_line(lines, line_num);
        let func_end = self.find_block_end(lines, func_start);
        lines[func_start..func_end].join("\n")
    }

    /// Find the start line of the containing function
    fn find_function_start_line(&self, lines: &[&str], line_num: usize) -> usize {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return i;
            }
        }
        0
    }

    /// Find functions without gas bounds
    fn find_functions_without_bounds(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect functions that process dynamic data
            if trimmed.contains("function ") && trimmed.contains("[]") {
                // Skip view/pure functions - they don't consume block gas limit
                // Use multi-line-aware signature check
                let sig = self.get_function_signature(&lines, line_num);
                if sig.contains(" view")
                    || sig.contains(" pure")
                    || sig.contains("\tview")
                    || sig.contains("\tpure")
                {
                    continue;
                }

                let func_name = self.extract_function_name(trimmed);
                let func_end = self.find_block_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                // Check if it iterates over the input array without bounds
                let has_loop = func_body.contains("for") && func_body.contains(".length");
                let has_bounds = self.has_loop_bounds(&func_body, &func_body);

                if has_loop && !has_bounds {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Find nested loops
    fn find_nested_loops(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect outer loop
            if trimmed.starts_with("for") || trimmed.starts_with("while") {
                // Skip view/pure functions - they don't consume block gas limit
                if self.is_inside_view_or_pure(&lines, line_num) {
                    continue;
                }

                // Skip constructor - runs once
                if self.is_inside_constructor(&lines, line_num) {
                    continue;
                }

                let loop_end = self.find_block_end(&lines, line_num);
                let loop_body: String = lines[line_num + 1..loop_end].join("\n");

                // Check for nested loop
                if loop_body.contains("for") || loop_body.contains("while") {
                    // Check if both loops have bounds
                    let func_body = self.get_function_body(&lines, line_num);
                    if !self.has_loop_bounds(&func_body, &loop_body) {
                        let func_name = self.find_containing_function(&lines, line_num);
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find large data copy operations
    fn find_large_data_operations(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Skip view/pure functions for storage copy warnings
            // (they're read-only but we still warn about returning large arrays)
            let in_view_or_pure = self.is_inside_view_or_pure(&lines, line_num);

            // Detect storage to memory copy of arrays (only in state-changing functions)
            if !in_view_or_pure
                && trimmed.contains("memory")
                && trimmed.contains("=")
                && (trimmed.contains("[]")
                    || trimmed.contains(".copy")
                    || trimmed.contains("abi.decode"))
            {
                // Check if it's copying from storage (not creating new)
                // Also skip function return value destructuring like:
                //   (IStrategy[] memory s, uint256[] memory v) = someFunction(...);
                // and skip lines that are clearly function call returns
                if !trimmed.contains("new ")
                    && !trimmed.contains("function ")
                    && !self.is_function_call_return(trimmed)
                {
                    let func_name = self.find_containing_function(&lines, line_num);
                    // Only flag if the array could be unbounded
                    let func_body = self.get_function_body(&lines, line_num);
                    if !self.has_loop_bounds(&func_body, &func_body) {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }

            // Detect return of large storage arrays
            // This is a warning for view functions too (gas-expensive to call)
            // Skip single mapping lookups like return balances[addr] or allowances[a][b]
            // Only flag when returning an actual array variable (not a mapping access)
            // Use "return " (with space) to avoid matching "returns" in function signatures
            if trimmed.contains("return ") && trimmed.contains("[") {
                // Check if this is a mapping access (has a variable/key inside brackets)
                // Mapping: return _balances[account]; or return _allowances[owner][spender];
                // Array: return users; (where users is an array type)
                if !self.is_mapping_access_return(trimmed) {
                    // Only flag if the function returns an unbounded array type
                    let func_name = self.find_containing_function(&lines, line_num);
                    let func_body = self.get_function_body(&lines, line_num);
                    // Check if array is bounded
                    if !self.has_loop_bounds(&func_body, &func_body) {
                        findings.push((line_num as u32 + 1, func_name));
                    }
                }
            }
        }

        findings
    }

    /// Find unbounded string/bytes operations
    fn find_unbounded_bytes_operations(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Skip view/pure functions - they don't consume block gas limit
            if self.is_inside_view_or_pure(&lines, line_num) {
                continue;
            }

            // Detect string/bytes concatenation in loops
            let is_concat = trimmed.contains("string.concat") || trimmed.contains("bytes.concat");

            // For abi.encodePacked, only flag if it's NOT inside a keccak256 call.
            // keccak256(abi.encodePacked(...)) is a standard hash pattern (e.g., Merkle
            // proof verification) that produces fixed-size output -- O(n) not O(n^2).
            let is_unbounded_encode =
                trimmed.contains("abi.encodePacked") && !trimmed.contains("keccak256");

            if is_concat || is_unbounded_encode {
                // Check if we're in a loop
                let in_loop = self.is_inside_loop(&lines, line_num);
                if in_loop {
                    let func_name = self.find_containing_function(&lines, line_num);
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    /// Check if we're inside a constructor (loops in constructors run once, not DoS risk)
    fn is_inside_constructor(&self, lines: &[&str], line_num: usize) -> bool {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.starts_with("constructor") || trimmed.contains("constructor(") {
                return true;
            }
            // Stop if we hit a function or contract boundary
            if trimmed.contains("function ") || trimmed.starts_with("contract ") {
                return false;
            }
        }
        false
    }

    /// Check if a line is a function call return value destructuring.
    /// Examples:
    ///   (IStrategy[] memory strategies, uint256[] memory shares) = getDepositedShares(staker);
    ///   uint256[] memory slashingFactors = _getSlashingFactors(staker, operator, strategies);
    /// These are not storage-to-memory copies -- they receive return values from functions.
    fn is_function_call_return(&self, line: &str) -> bool {
        let trimmed = line.trim();
        // Tuple destructuring from function call: starts with ( and has ) = funcName(
        if trimmed.starts_with('(') && trimmed.contains(") =") {
            // Check if the right side of = contains a function call
            if let Some(eq_pos) = trimmed.find(") =") {
                let rhs = &trimmed[eq_pos + 3..];
                // Function call on the right side
                if rhs.contains('(') {
                    return true;
                }
            }
        }
        // Single variable from function call: Type[] memory var = funcName(...)
        if trimmed.contains("memory") && trimmed.contains("= ") {
            if let Some(eq_pos) = trimmed.find("= ") {
                let rhs = trimmed[eq_pos + 2..].trim();
                // Starts with an identifier followed by ( -- it's a function call
                if rhs.contains('(') && !rhs.starts_with('[') && !rhs.starts_with('"') {
                    // Make sure there's an identifier before the parenthesis
                    if let Some(paren_pos) = rhs.find('(') {
                        let before_paren = rhs[..paren_pos].trim();
                        if !before_paren.is_empty()
                            && before_paren
                                .chars()
                                .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
                        {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if this return statement is a mapping access (not array return)
    fn is_mapping_access_return(&self, line: &str) -> bool {
        // Mapping access pattern: return something[key]; or return something[key1][key2];
        // These have a variable/identifier inside the brackets

        // Check for patterns that indicate mapping access:
        // 1. Has content inside brackets (not empty [])
        // 2. Doesn't end with [] which would indicate array type

        if let Some(bracket_start) = line.find('[') {
            if let Some(bracket_end) = line.rfind(']') {
                // Check if there's content between brackets (mapping key)
                if bracket_end > bracket_start + 1 {
                    // Has something inside brackets - likely a mapping access
                    return true;
                }
            }
        }
        false
    }

    fn is_inside_loop(&self, lines: &[&str], line_num: usize) -> bool {
        let mut depth = 0;

        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();

            for c in trimmed.chars().rev() {
                match c {
                    '}' => depth += 1,
                    '{' => depth -= 1,
                    _ => {}
                }
            }

            if depth < 0 {
                // We're inside a block, check if it's a loop
                if trimmed.contains("for") || trimmed.contains("while") {
                    return true;
                }
                depth = 0; // Reset for outer blocks
            }

            if trimmed.contains("function ") {
                break;
            }
        }
        false
    }

    fn find_containing_function(&self, lines: &[&str], line_num: usize) -> String {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return self.extract_function_name(trimmed);
            }
        }
        "unknown".to_string()
    }

    fn extract_function_name(&self, line: &str) -> String {
        if let Some(func_start) = line.find("function ") {
            let after_func = &line[func_start + 9..];
            if let Some(paren_pos) = after_func.find('(') {
                return after_func[..paren_pos].trim().to_string();
            }
        }
        "unknown".to_string()
    }

    fn find_block_end(&self, lines: &[&str], start: usize) -> usize {
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

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for DosBlockGasLimitDetector {
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

        for (line, func_name, issue) in self.find_unbounded_loops(source) {
            let message = format!(
                "Function '{}' in contract '{}' has gas limit risk: {}. \
                 As data grows, function may exceed block gas limit.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Implement pagination for large operations:\n\n\
                     function processItems(uint256 start, uint256 count) external {\n\
                         uint256 end = start + count;\n\
                         if (end > items.length) end = items.length;\n\
                         \n\
                         for (uint256 i = start; i < end; i++) {\n\
                             // process items[i]\n\
                         }\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_functions_without_bounds(source) {
            let message = format!(
                "Function '{}' in contract '{}' accepts unbounded array input. \
                 Large inputs can cause out-of-gas failures.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Limit input array size:\n\n\
                     uint256 constant MAX_BATCH_SIZE = 100;\n\n\
                     function processBatch(address[] calldata items) external {\n\
                         require(\n\
                             items.length <= MAX_BATCH_SIZE,\n\
                             \"Batch too large\"\n\
                         );\n\
                         // ...\n\
                     }"
                    .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_nested_loops(source) {
            let message = format!(
                "Function '{}' in contract '{}' contains nested loops. \
                 O(n*m) operations can easily exceed gas limits.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Avoid nested loops or add strict bounds:\n\n\
                     1. Use mappings instead of nested array iteration\n\
                     2. Pre-compute results off-chain\n\
                     3. Split into multiple transactions\n\
                     4. Add strict size limits on both dimensions"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_large_data_operations(source) {
            let message = format!(
                "Function '{}' in contract '{}' copies large data from storage. \
                 This can be extremely gas-expensive for large arrays.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::Low)
                .with_fix_suggestion(
                    "Avoid copying entire arrays from storage:\n\n\
                     1. Return paginated results\n\
                     2. Use events for historical data\n\
                     3. Store array length separately\n\
                     4. Use off-chain indexing"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_unbounded_bytes_operations(source) {
            let message = format!(
                "Function '{}' in contract '{}' concatenates strings/bytes in a loop. \
                 This creates O(n^2) gas complexity.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Avoid string concatenation in loops:\n\n\
                     1. Pre-allocate fixed-size buffer\n\
                     2. Build result off-chain\n\
                     3. Use events to emit data pieces\n\
                     4. Return array instead of single string"
                        .to_string(),
                );

            findings.push(finding);
        }

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
        let detector = DosBlockGasLimitDetector::new();
        assert_eq!(detector.name(), "DoS Block Gas Limit");
        assert_eq!(detector.default_severity(), Severity::High);
    }

    // --- Multi-line view/pure signature tests ---

    #[test]
    fn test_multiline_view_function_skipped() {
        let detector = DosBlockGasLimitDetector::new();
        let source = r#"
contract Test {
    function getOperatorShares(
        address operator,
        IStrategy[] memory strategies
    ) public view returns (uint256[] memory) {
        uint256[] memory shares = new uint256[](strategies.length);
        for (uint256 i = 0; i < strategies.length; ++i) {
            shares[i] = operatorShares[operator][strategies[i]];
        }
        return shares;
    }
}
"#;
        let findings = detector.find_unbounded_loops(source);
        assert!(
            findings.is_empty(),
            "Multi-line view function should not produce findings, got: {:?}",
            findings
        );
    }

    #[test]
    fn test_multiline_pure_function_skipped() {
        let detector = DosBlockGasLimitDetector::new();
        let source = r#"
contract Test {
    function _verify(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) internal pure returns (bool) {
        uint256 gasUsed = 0;
        for (uint256 i = 0; i < publicInputs.length; i++) {
            gasUsed += publicInputs[i];
        }
        return proof[0] != 0;
    }
}
"#;
        let findings = detector.find_unbounded_loops(source);
        assert!(
            findings.is_empty(),
            "Multi-line pure function should not produce findings, got: {:?}",
            findings
        );
    }

    #[test]
    fn test_single_line_view_function_skipped() {
        let detector = DosBlockGasLimitDetector::new();
        let source = r#"
contract Test {
    function getAll() external view returns (uint256[] memory) {
        uint256[] memory result = new uint256[](items.length);
        for (uint256 i = 0; i < items.length; i++) {
            result[i] = items[i];
        }
        return result;
    }
}
"#;
        let findings = detector.find_unbounded_loops(source);
        assert!(
            findings.is_empty(),
            "Single-line view function should not produce findings"
        );
    }

    #[test]
    fn test_state_changing_unbounded_loop_flagged() {
        let detector = DosBlockGasLimitDetector::new();
        let source = r#"
contract Test {
    function distribute() external {
        for (uint256 i = 0; i < recipients.length; i++) {
            recipients[i].transfer(amounts[i]);
        }
    }
}
"#;
        let findings = detector.find_unbounded_loops(source);
        assert!(
            !findings.is_empty(),
            "Unbounded loop in state-changing function should be flagged"
        );
    }

    // --- abi.encodePacked in keccak256 (Merkle proof pattern) ---

    #[test]
    fn test_keccak256_encode_packed_in_loop_skipped() {
        let detector = DosBlockGasLimitDetector::new();
        let source = r#"
contract Bridge {
    function verifyMerkleProof(
        bytes32 root,
        bytes32 leaf,
        bytes32[] calldata proof
    ) internal pure returns (bool) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computedHash = keccak256(abi.encodePacked(computedHash, proof[i]));
        }
        return computedHash == root;
    }
}
"#;
        let findings = detector.find_unbounded_bytes_operations(source);
        assert!(
            findings.is_empty(),
            "keccak256(abi.encodePacked(...)) in loop should not be flagged, got: {:?}",
            findings
        );
    }

    #[test]
    fn test_bare_encode_packed_in_loop_flagged() {
        let detector = DosBlockGasLimitDetector::new();
        let source = r#"
contract Test {
    function aggregate(bytes[] calldata data) external returns (bytes memory) {
        bytes memory result;
        for (uint256 i = 0; i < data.length; i++) {
            result = abi.encodePacked(result, data[i]);
        }
        return result;
    }
}
"#;
        let findings = detector.find_unbounded_bytes_operations(source);
        assert!(
            !findings.is_empty(),
            "Bare abi.encodePacked concatenation in loop should be flagged"
        );
    }

    // --- Fixed-size array allocation ---

    #[test]
    fn test_fixed_size_array_alloc_recognized_as_bounded() {
        let detector = DosBlockGasLimitDetector::new();
        let func_body = r#"
        bytes32[] memory roles = new bytes32[](5);
        roles[0] = keccak256("ADMIN_ROLE");
        for (uint256 i = 0; i < roles.length; i++) {
            doSomething(roles[i]);
        }
"#;
        let loop_body = r#"        for (uint256 i = 0; i < roles.length; i++) {
            doSomething(roles[i]);
        }"#;
        assert!(
            detector.has_loop_bounds(func_body, loop_body),
            "new bytes32[](5) iterated by roles.length should be recognized as bounded"
        );
    }

    #[test]
    fn test_large_fixed_alloc_not_bounded() {
        let detector = DosBlockGasLimitDetector::new();
        let func_body = r#"
        uint256[] memory data = new uint256[](1000);
        for (uint256 i = 0; i < data.length; i++) {
            data[i] = compute(i);
        }
"#;
        let loop_body = r#"        for (uint256 i = 0; i < data.length; i++) {
            data[i] = compute(i);
        }"#;
        // 1000 > 256, so this should NOT be treated as bounded by fixed alloc alone
        assert!(
            !detector.loop_iterates_fixed_size_array(func_body, loop_body),
            "new uint256[](1000) should NOT be recognized as small fixed-size alloc"
        );
    }

    #[test]
    fn test_unrelated_fixed_alloc_does_not_suppress_unbounded_loop() {
        let detector = DosBlockGasLimitDetector::new();
        // The function creates a fixed-size array (new IStrategy[](1)) inside the loop,
        // but the loop itself iterates over strategies.length which is unbounded.
        let func_body = r#"
        (IStrategy[] memory strategies, uint256[] memory shares) = getDepositedShares(staker);
        for (uint256 i = 0; i < strategies.length; i++) {
            IStrategy[] memory single = new IStrategy[](1);
            single[0] = strategies[i];
        }
"#;
        let loop_body = r#"        for (uint256 i = 0; i < strategies.length; i++) {
            IStrategy[] memory single = new IStrategy[](1);
            single[0] = strategies[i];
        }"#;
        assert!(
            !detector.loop_iterates_fixed_size_array(func_body, loop_body),
            "Fixed alloc of unrelated array should not suppress unbounded loop finding"
        );
    }

    // --- Function call return destructuring ---

    #[test]
    fn test_function_call_return_not_flagged_as_storage_copy() {
        let detector = DosBlockGasLimitDetector::new();
        // Tuple destructuring from function call
        assert!(
            detector.is_function_call_return(
                "(IStrategy[] memory strategies, uint256[] memory shares) = getDepositedShares(staker);"
            ),
            "Tuple destructuring from function call should be recognized"
        );
        // Single value from function call
        assert!(
            detector.is_function_call_return(
                "uint256[] memory slashingFactors = _getSlashingFactors(staker, operator, strategies);"
            ),
            "Single return value from function call should be recognized"
        );
    }

    #[test]
    fn test_storage_copy_still_detected() {
        let detector = DosBlockGasLimitDetector::new();
        // Direct storage array access is NOT a function call
        assert!(
            !detector.is_function_call_return("uint256[] memory data = storageArray;"),
            "Direct storage copy should not be recognized as function call return"
        );
    }

    // --- Multi-line view/pure for find_functions_without_bounds ---

    #[test]
    fn test_multiline_view_function_with_array_param_skipped() {
        let detector = DosBlockGasLimitDetector::new();
        let source = r#"
contract Test {
    function getWithdrawableShares(
        address staker,
        IStrategy[] memory strategies
    ) public view returns (uint256[] memory, uint256[] memory) {
        uint256[] memory result = new uint256[](strategies.length);
        for (uint256 i = 0; i < strategies.length; ++i) {
            result[i] = shares[staker][strategies[i]];
        }
        return (result, result);
    }
}
"#;
        let findings = detector.find_functions_without_bounds(source);
        assert!(
            findings.is_empty(),
            "Multi-line view function with array param should not produce findings, got: {:?}",
            findings
        );
    }

    // --- View/pure functions skipped in bytes operations ---

    #[test]
    fn test_bytes_operations_in_pure_function_skipped() {
        let detector = DosBlockGasLimitDetector::new();
        let source = r#"
contract Test {
    function buildData(bytes[] calldata chunks) external pure returns (bytes memory) {
        bytes memory result;
        for (uint256 i = 0; i < chunks.length; i++) {
            result = bytes.concat(result, chunks[i]);
        }
        return result;
    }
}
"#;
        let findings = detector.find_unbounded_bytes_operations(source);
        assert!(
            findings.is_empty(),
            "Bytes concat in pure function should not be flagged"
        );
    }

    // --- get_function_signature tests ---

    #[test]
    fn test_get_function_signature_multiline() {
        let detector = DosBlockGasLimitDetector::new();
        let source = r#"contract Test {
    function foo(
        uint256 a,
        uint256 b
    ) external view returns (uint256) {
        return a + b;
    }
}"#;
        let lines: Vec<&str> = source.lines().collect();
        let sig = detector.get_function_signature(&lines, 1);
        assert!(
            sig.contains("view"),
            "Signature should contain 'view': {}",
            sig
        );
        assert!(
            sig.contains("function foo"),
            "Signature should contain 'function foo': {}",
            sig
        );
    }

    #[test]
    fn test_get_function_signature_single_line() {
        let detector = DosBlockGasLimitDetector::new();
        let source = r#"contract Test {
    function foo() external pure returns (uint256) {
        return 42;
    }
}"#;
        let lines: Vec<&str> = source.lines().collect();
        let sig = detector.get_function_signature(&lines, 1);
        assert!(
            sig.contains("pure"),
            "Signature should contain 'pure': {}",
            sig
        );
    }

    // --- Nested loops in view functions skipped ---

    #[test]
    fn test_nested_loops_in_view_function_skipped() {
        let detector = DosBlockGasLimitDetector::new();
        let source = r#"
contract Test {
    function getMatrix(
        uint256[][] memory data
    ) external view returns (uint256) {
        uint256 sum = 0;
        for (uint256 i = 0; i < data.length; i++) {
            for (uint256 j = 0; j < data[i].length; j++) {
                sum += data[i][j];
            }
        }
        return sum;
    }
}
"#;
        let findings = detector.find_nested_loops(source);
        assert!(
            findings.is_empty(),
            "Nested loops in view function should not be flagged, got: {:?}",
            findings
        );
    }
}
