use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for DoS via push pattern on dynamic arrays
///
/// Detects patterns where users can push to arrays without bounds,
/// making iteration over those arrays potentially exceed gas limits.
pub struct DosPushPatternDetector {
    base: BaseDetector,
}

impl Default for DosPushPatternDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DosPushPatternDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("dos-push-pattern"),
                "DoS Push Pattern".to_string(),
                "Detects unbounded array growth via push operations that could lead to \
                 denial of service when iterating over the array."
                    .to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::BestPractices],
                Severity::High,
            ),
        }
    }

    /// Check if a function signature/header indicates admin-only access control.
    /// Looks at the function declaration line(s) and the function body for
    /// common access-control patterns that restrict callers to privileged roles.
    fn is_admin_only_function(&self, lines: &[&str], func_start: usize, func_end: usize) -> bool {
        let func_header_and_body: String =
            lines[func_start..std::cmp::min(func_end, lines.len())].join("\n");
        let lower = func_header_and_body.to_lowercase();

        // Modifier-based access control
        let admin_modifiers = [
            "onlyowner",
            "onlyadmin",
            "onlyrole",
            "onlygovernor",
            "onlygovernance",
            "onlyauthorized",
            "onlyoperator",
            "onlymanager",
            "onlyguardian",
            "onlyminter",
            "onlycontroller",
        ];
        for modifier in &admin_modifiers {
            if lower.contains(modifier) {
                return true;
            }
        }

        // Inline require-based access control
        let owner_checks = [
            "require(msg.sender == owner",
            "require(msg.sender == _owner",
            "require(msg.sender == admin",
            "require(msg.sender == governance",
            "require(msg.sender == guardian",
            "if (msg.sender != owner",
            "if (msg.sender != _owner",
            "if (msg.sender != admin",
        ];
        for check in &owner_checks {
            if lower.contains(check) {
                return true;
            }
        }

        // OpenZeppelin Ownable2Step / AccessControl patterns
        if lower.contains("_checkowner()") || lower.contains("_checkrole(") {
            return true;
        }

        false
    }

    /// Check if a push is inside a constructor (one-time bounded operation).
    fn is_inside_constructor(&self, lines: &[&str], line_num: usize) -> bool {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("constructor(") || trimmed.starts_with("constructor(") {
                // Verify we haven't exited the constructor body
                let ctor_end = self.find_function_end(lines, i);
                return line_num < ctor_end;
            }
            // If we hit a function keyword first, we're not in a constructor
            if trimmed.contains("function ") {
                return false;
            }
        }
        false
    }

    /// Check if an array has a bounded-size check in the function body.
    /// Recognizes patterns like:
    ///   require(arr.length < MAX, ...)
    ///   require(arr.length <= MAX, ...)
    ///   if (arr.length >= MAX) revert ...
    ///   assert(arr.length < ...)
    fn has_bounds_check(&self, func_body: &str, array_name: &str) -> bool {
        let length_ref = format!("{}.length", array_name);

        // Original simple check: require + .length in same function
        if func_body.contains(&length_ref) && func_body.contains("require") {
            return true;
        }

        // Check for revert / assert with length
        if func_body.contains(&length_ref)
            && (func_body.contains("revert") || func_body.contains("assert"))
        {
            return true;
        }

        // Check for MAX_ / max_ / _MAX / _LIMIT constants near length references
        let lower = func_body.to_lowercase();
        if lower.contains(&length_ref.to_lowercase()) {
            if lower.contains("max_") || lower.contains("_max") || lower.contains("_limit") {
                return true;
            }
        }

        false
    }

    /// Check if an array has removal mechanisms (pop, delete, or swap-and-pop)
    /// that prevent unbounded growth in practice.
    fn has_removal_mechanism(&self, source: &str, array_name: &str) -> bool {
        let pop_pattern = format!("{}.pop(", array_name);
        let delete_pattern = format!("delete {}[", array_name);
        // Also check for a "remove" function that references this array
        let remove_pattern = format!("{} =", array_name);

        source.contains(&pop_pattern)
            || source.contains(&delete_pattern)
            || (source.contains("function remove") && source.contains(&remove_pattern))
    }

    /// Find unbounded push patterns
    fn find_push_patterns(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect .push( patterns
            if trimmed.contains(".push(") {
                let func_name = self.find_containing_function(&lines, line_num);

                // Extract array name
                if let Some(array_name) = self.extract_array_name(trimmed) {
                    // Skip push inside constructors (one-time, bounded)
                    if self.is_inside_constructor(&lines, line_num) {
                        continue;
                    }

                    let func_start = self.find_function_start(&lines, line_num);
                    let func_end = self.find_function_end(&lines, func_start);
                    let func_body: String = lines[func_start..func_end].join("\n");

                    // Skip admin-only functions (owner/admin controls array growth)
                    if self.is_admin_only_function(&lines, func_start, func_end) {
                        continue;
                    }

                    // Skip if function is internal or private (not externally callable)
                    let func_header: String =
                        lines[func_start..std::cmp::min(func_start + 5, lines.len())].join(" ");
                    if func_header.contains("internal") || func_header.contains("private") {
                        continue;
                    }

                    // Check for length limit / bounds check
                    if self.has_bounds_check(&func_body, &array_name) {
                        continue;
                    }

                    // Skip if array has removal mechanisms elsewhere in the contract
                    if self.has_removal_mechanism(source, &array_name) {
                        continue;
                    }

                    let issue = format!("Unbounded push to array '{}'", array_name);
                    findings.push((line_num as u32 + 1, func_name, issue));
                }
            }
        }

        findings
    }

    /// Find iteration over unbounded arrays
    fn find_unbounded_iteration(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect for loops iterating over arrays
            if trimmed.contains("for") && trimmed.contains(".length") {
                let func_name = self.find_containing_function(&lines, line_num);

                // Check if the array can be user-controlled
                if let Some(array_name) = self.extract_loop_array(trimmed) {
                    // Skip if iterating function is view/pure (no state change DoS)
                    let func_start = self.find_function_start(&lines, line_num);
                    let func_end = self.find_function_end(&lines, func_start);
                    let func_header: String =
                        lines[func_start..std::cmp::min(func_start + 5, lines.len())].join(" ");
                    if func_header.contains(" view") || func_header.contains(" pure") {
                        continue;
                    }

                    // Skip if the iterating function is admin-only
                    if self.is_admin_only_function(&lines, func_start, func_end) {
                        continue;
                    }

                    // Look for push to this array in external/public functions
                    // but only if the push is from a non-admin function
                    if self.is_array_pushable_by_unprivileged(source, &array_name) {
                        let issue = format!("Iteration over unbounded array '{}'", array_name);
                        findings.push((line_num as u32 + 1, func_name, issue));
                    }
                }
            }
        }

        findings
    }

    /// Check if a for-loop iterates over a caller-controlled parameter array
    /// (calldata or memory array passed as a function argument). The caller
    /// controls the length, so they only DoS themselves.
    fn is_loop_over_caller_controlled_param(
        &self,
        loop_line: &str,
        lines: &[&str],
        line_num: usize,
    ) -> bool {
        // Extract the variable name from the loop condition (e.g., "calls.length")
        let array_name = if let Some(name) = self.extract_loop_array(loop_line) {
            name
        } else {
            return false;
        };

        // Find the function header to check if this array is a calldata/memory parameter
        let func_start = self.find_function_start(lines, line_num);
        // Gather up to 8 lines to handle multi-line function signatures
        let header_end = std::cmp::min(func_start + 8, lines.len());
        let func_header: String = lines[func_start..header_end].join(" ");

        // Check if the array name appears as a calldata or memory parameter
        // Pattern: "SomeType[] calldata arrayName" or "SomeType[] memory arrayName"
        let calldata_pattern = format!("calldata {}", array_name);
        let memory_pattern = format!("memory {}", array_name);
        let calldata_pattern2 = format!("calldata _{}", array_name);
        let memory_pattern2 = format!("memory _{}", array_name);

        func_header.contains(&calldata_pattern)
            || func_header.contains(&memory_pattern)
            || func_header.contains(&calldata_pattern2)
            || func_header.contains(&memory_pattern2)
    }

    /// Find gas-intensive operations in loops
    fn find_gas_intensive_loops(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") {
                continue;
            }

            // Detect for loops
            if trimmed.starts_with("for") || trimmed.starts_with("while") {
                let func_name = self.find_containing_function(&lines, line_num);

                // Skip loops iterating over caller-controlled parameter arrays
                if self.is_loop_over_caller_controlled_param(trimmed, &lines, line_num) {
                    continue;
                }

                // Skip if containing function is view/pure
                let func_start = self.find_function_start(&lines, line_num);
                let func_header: String =
                    lines[func_start..std::cmp::min(func_start + 5, lines.len())].join(" ");
                if func_header.contains(" view") || func_header.contains(" pure") {
                    continue;
                }

                let loop_end = self.find_loop_end(&lines, line_num);
                let loop_body: String = lines[line_num..loop_end].join("\n");

                // Check for gas-intensive operations
                if loop_body.contains("transfer(")
                    || loop_body.contains(".call{")
                    || loop_body.contains("SSTORE")
                    || (loop_body.contains("delete ") && loop_body.contains("["))
                {
                    findings.push((line_num as u32 + 1, func_name));
                }
            }
        }

        findings
    }

    fn extract_array_name(&self, line: &str) -> Option<String> {
        if let Some(push_pos) = line.find(".push(") {
            let before_push = &line[..push_pos];
            // Find the array name (last identifier before .push)
            let parts: Vec<&str> = before_push
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .collect();
            if let Some(name) = parts.last() {
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
        None
    }

    fn extract_loop_array(&self, line: &str) -> Option<String> {
        if let Some(length_pos) = line.find(".length") {
            let before_length = &line[..length_pos];
            let parts: Vec<&str> = before_length
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .collect();
            if let Some(name) = parts.last() {
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
        None
    }

    /// Check if an array can be pushed to by unprivileged (non-admin) external callers.
    /// Returns false if the only push operations are in admin-only or constructor contexts.
    fn is_array_pushable_by_unprivileged(&self, source: &str, array_name: &str) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        let push_target = format!("{}.push(", array_name);

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Check constructors
            if trimmed.contains("constructor(") || trimmed.starts_with("constructor(") {
                let ctor_end = self.find_function_end(&lines, line_num);
                let ctor_body: String = lines[line_num..ctor_end].join("\n");
                if ctor_body.contains(&push_target) {
                    // Constructor pushes are bounded, skip
                    continue;
                }
            }

            if trimmed.contains("function ")
                && (trimmed.contains("external") || trimmed.contains("public"))
            {
                let func_end = self.find_function_end(&lines, line_num);
                let func_body: String = lines[line_num..func_end].join("\n");

                if func_body.contains(&push_target) {
                    // Check if this function is admin-only
                    if self.is_admin_only_function(&lines, line_num, func_end) {
                        continue;
                    }
                    // Check if the array has a bounds check in this function
                    if self.has_bounds_check(&func_body, array_name) {
                        continue;
                    }
                    return true;
                }
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

    fn find_function_start(&self, lines: &[&str], line_num: usize) -> usize {
        for i in (0..line_num).rev() {
            let trimmed = lines[i].trim();
            if trimmed.contains("function ") {
                return i;
            }
        }
        0
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

    fn find_loop_end(&self, lines: &[&str], start: usize) -> usize {
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

impl Detector for DosPushPatternDetector {
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

        for (line, func_name, issue) in self.find_push_patterns(source) {
            let message = format!(
                "Function '{}' in contract '{}' has DoS vulnerability: {}. \
                 Users can grow array indefinitely, making iteration exceed gas limits.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Prevent unbounded array growth:\n\n\
                     1. Add maximum length check:\n\
                     require(array.length < MAX_SIZE, \"Array full\");\n\n\
                     2. Use mapping instead of array for iteration\n\
                     3. Implement pagination for large datasets\n\
                     4. Use pull pattern instead of push"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name, issue) in self.find_unbounded_iteration(source) {
            let message = format!(
                "Function '{}' in contract '{}' iterates over unbounded array: {}. \
                 Attackers can grow array to cause out-of-gas failures.",
                func_name, contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Avoid unbounded iteration:\n\n\
                     1. Limit array size on push operations\n\
                     2. Use pagination for processing:\n\
                     function process(uint start, uint count) external {\n\
                         for (uint i = start; i < start + count && i < arr.length; i++) {\n\
                             // process arr[i]\n\
                         }\n\
                     }\n\
                     3. Consider pull-over-push pattern"
                        .to_string(),
                );

            findings.push(finding);
        }

        for (line, func_name) in self.find_gas_intensive_loops(source) {
            let message = format!(
                "Function '{}' in contract '{}' performs gas-intensive operations in a loop. \
                 This can exceed block gas limit with large arrays.",
                func_name, contract_name
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(400)
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "Move gas-intensive operations outside loops:\n\n\
                     1. Use pull pattern for transfers\n\
                     2. Batch operations with limits\n\
                     3. Use events for off-chain processing\n\
                     4. Consider withdrawal patterns"
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
    use crate::types::test_utils::create_test_context;

    #[test]
    fn test_detector_properties() {
        let detector = DosPushPatternDetector::new();
        assert_eq!(detector.name(), "DoS Push Pattern");
        assert_eq!(detector.default_severity(), Severity::High);
    }

    #[test]
    fn test_detects_unbounded_push_in_public_function() {
        let detector = DosPushPatternDetector::new();
        let source = r#"
            contract Vulnerable {
                address[] public users;

                function register() external {
                    users.push(msg.sender);
                }
            }
        "#;
        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect unbounded push in public function"
        );
    }

    #[test]
    fn test_skips_admin_only_push_onlyowner() {
        let detector = DosPushPatternDetector::new();
        let source = r#"
            contract AdminControlled {
                address[] public operators;

                function addOperator(address op) external onlyOwner {
                    operators.push(op);
                }
            }
        "#;
        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "Should NOT flag admin-only push (onlyOwner): got {} findings",
            result.len()
        );
    }

    #[test]
    fn test_skips_admin_only_push_require_owner() {
        let detector = DosPushPatternDetector::new();
        let source = r#"
            contract AdminControlled {
                address public owner;
                address[] public whitelist;

                function addToWhitelist(address addr) external {
                    require(msg.sender == owner, "Not owner");
                    whitelist.push(addr);
                }
            }
        "#;
        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "Should NOT flag push guarded by require(msg.sender == owner): got {} findings",
            result.len()
        );
    }

    #[test]
    fn test_skips_constructor_push() {
        let detector = DosPushPatternDetector::new();
        let source = r#"
            contract InitOnce {
                address[] public validators;

                constructor(address[] memory _validators) {
                    for (uint i = 0; i < _validators.length; i++) {
                        validators.push(_validators[i]);
                    }
                }
            }
        "#;
        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "Should NOT flag push inside constructor: got {} findings",
            result.len()
        );
    }

    #[test]
    fn test_skips_bounded_push_with_max_check() {
        let detector = DosPushPatternDetector::new();
        let source = r#"
            contract Bounded {
                uint256 constant MAX_ITEMS = 100;
                address[] public items;

                function addItem(address item) external {
                    require(items.length < MAX_ITEMS, "Too many items");
                    items.push(item);
                }
            }
        "#;
        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "Should NOT flag push with bounds check: got {} findings",
            result.len()
        );
    }

    #[test]
    fn test_skips_internal_function_push() {
        let detector = DosPushPatternDetector::new();
        let source = r#"
            contract InternalPush {
                address[] private data;

                function _addInternal(address item) internal {
                    data.push(item);
                }
            }
        "#;
        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "Should NOT flag push in internal function: got {} findings",
            result.len()
        );
    }

    #[test]
    fn test_skips_array_with_removal_mechanism() {
        let detector = DosPushPatternDetector::new();
        let source = r#"
            contract WithRemoval {
                address[] public members;

                function addMember(address member) external {
                    members.push(member);
                }

                function removeMember(uint idx) external {
                    members[idx] = members[members.length - 1];
                    members.pop();
                }
            }
        "#;
        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "Should NOT flag push when array has pop/removal: got {} findings",
            result.len()
        );
    }

    #[test]
    fn test_skips_view_function_iteration() {
        let detector = DosPushPatternDetector::new();
        let source = r#"
            contract ViewIteration {
                uint256[] public data;

                function sumAll() external view returns (uint256 total) {
                    for (uint i = 0; i < data.length; i++) {
                        total += data[i];
                    }
                }
            }
        "#;
        // The iteration finder checks is_array_pushable_by_unprivileged,
        // and there is no push function at all, so it won't flag.
        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "Should NOT flag view function iteration: got {} findings",
            result.len()
        );
    }

    #[test]
    fn test_skips_calldata_param_loop() {
        let detector = DosPushPatternDetector::new();
        let source = r#"
            contract BatchExecutor {
                struct Call {
                    address target;
                    uint256 value;
                    bytes data;
                }

                function execute(Call[] calldata calls) external payable {
                    for (uint256 i = 0; i < calls.length; i++) {
                        (bool success, ) = calls[i].target.call{value: calls[i].value}(calls[i].data);
                    }
                }
            }
        "#;
        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "Should NOT flag gas-intensive loop over calldata param: got {} findings",
            result.len()
        );
    }

    #[test]
    fn test_detects_iteration_over_externally_pushable_array() {
        let detector = DosPushPatternDetector::new();
        let source = r#"
            contract VulnerableQueue {
                address[] public queue;

                function enqueue() external {
                    queue.push(msg.sender);
                }

                function processAll() external {
                    for (uint i = 0; i < queue.length; i++) {
                        (bool ok, ) = queue[i].call{value: 1 ether}("");
                    }
                }
            }
        "#;
        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.len() >= 2,
            "Should detect both unbounded push AND iteration: got {} findings",
            result.len()
        );
    }

    #[test]
    fn test_skips_iteration_when_push_is_admin_only() {
        let detector = DosPushPatternDetector::new();
        let source = r#"
            contract AdminArray {
                address[] public operators;

                function addOperator(address op) external onlyOwner {
                    operators.push(op);
                }

                function rebalance() external {
                    for (uint i = 0; i < operators.length; i++) {
                        (bool ok, ) = operators[i].call{value: 1 ether}("");
                    }
                }
            }
        "#;
        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        // The push is admin-only, so unbounded-iteration should not fire
        // The gas-intensive loop will still fire though (rebalance is not view)
        // but the push finding and iteration-over-unbounded finding should be suppressed
        let push_findings: Vec<_> = result
            .iter()
            .filter(|f| f.message.contains("Unbounded push"))
            .collect();
        let iter_findings: Vec<_> = result
            .iter()
            .filter(|f| f.message.contains("iterates over unbounded"))
            .collect();
        assert!(
            push_findings.is_empty(),
            "Should NOT flag admin-only push: got {} push findings",
            push_findings.len()
        );
        assert!(
            iter_findings.is_empty(),
            "Should NOT flag iteration when push is admin-only: got {} iter findings",
            iter_findings.len()
        );
    }

    #[test]
    fn test_skips_memory_param_loop() {
        let detector = DosPushPatternDetector::new();
        let source = r#"
            contract BatchProcessor {
                function distribute(address[] memory recipients) external {
                    for (uint256 i = 0; i < recipients.length; i++) {
                        (bool ok, ) = recipients[i].call{value: 1 ether}("");
                    }
                }
            }
        "#;
        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "Should NOT flag gas-intensive loop over memory param: got {} findings",
            result.len()
        );
    }

    #[test]
    fn test_skips_onlyadmin_modifier() {
        let detector = DosPushPatternDetector::new();
        let source = r#"
            contract AdminGated {
                address[] public pools;

                function addPool(address pool) external onlyAdmin {
                    pools.push(pool);
                }
            }
        "#;
        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "Should NOT flag push guarded by onlyAdmin: got {} findings",
            result.len()
        );
    }
}
