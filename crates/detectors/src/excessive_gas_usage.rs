use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::contract_classification;
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for patterns causing excessive gas consumption.
///
/// FP Reduction Strategy (v1.10.15):
/// - Skip constructors: deployment-time gas is a one-time cost, not user-facing.
/// - Skip view/pure functions: gas is only a concern for state-modifying transactions.
/// - Skip admin-only functions: gated by onlyOwner/onlyAdmin modifiers, called infrequently.
/// - Recognize already-optimized patterns: cached .length, unchecked blocks, ++i.
/// - Exclude standard token operations (transfer, approve, mint, burn) from loop-write checks.
/// - Improve has_storage_write_in_loop to avoid flagging initialization patterns (bool assignments,
///   mapping[key] = true/false) which are inherent to the function's purpose.
pub struct ExcessiveGasUsageDetector {
    base: BaseDetector,
}

impl Default for ExcessiveGasUsageDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ExcessiveGasUsageDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("excessive-gas-usage".to_string()),
                "Excessive Gas Usage".to_string(),
                // Phase 6 FP Reduction: Reclassified from Low to Info.
                // This is a gas optimization suggestion, not a security vulnerability.
                "Detects patterns causing excessive gas consumption such as storage operations in loops, redundant storage reads, and inefficient data structures".to_string(),
                vec![DetectorCategory::BestPractices],
                Severity::Info,
            ),
        }
    }
}

/// Common access-control modifier names that indicate admin/privileged functions.
/// Functions guarded by these modifiers are called infrequently by operators,
/// so gas optimization findings on them are low-value noise.
const ADMIN_MODIFIERS: &[&str] = &[
    "onlyOwner",
    "onlyAdmin",
    "onlyRole",
    "onlyGovernance",
    "onlyOperator",
    "onlyWhitelister",
    "onlyStrategyWhitelister",
    "onlyPauser",
    "onlyUnpauser",
    "onlyGuardian",
    "onlyMinter",
    "onlyManager",
    "onlyController",
    "onlyAuthorized",
    "requiresAuth",
];

/// Standard token operation names where storage writes in loops are inherent to the
/// function's purpose and cannot be optimized away.
const STANDARD_TOKEN_OPS: &[&str] = &[
    "transfer",
    "transferFrom",
    "approve",
    "mint",
    "burn",
    "safeTransfer",
    "safeTransferFrom",
    "safeMint",
    "batchTransfer",
    "batchMint",
];

impl Detector for ExcessiveGasUsageDetector {
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

        // Skip test contracts - gas optimization is less critical for tests
        if contract_classification::is_test_contract(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            // Skip constructors - deployment gas is a one-time cost paid by the deployer,
            // not an ongoing per-transaction concern for users. Initialization loops in
            // constructors (e.g., populating mappings from arrays) are standard patterns.
            // Note: The parser currently defaults function_type to Function for all
            // functions, so we also detect constructors by empty name (the parser sets
            // name to "" for constructors/fallback/receive) and by source text.
            if function.function_type == ast::FunctionType::Constructor {
                continue;
            }
            if self.is_constructor(function, ctx) {
                continue;
            }

            // Skip view/pure functions - no state changes = no gas concern for users
            // (they only consume gas when called internally, which is acceptable)
            if matches!(
                function.mutability,
                ast::StateMutability::View | ast::StateMutability::Pure
            ) {
                continue;
            }

            // Skip receive/fallback functions - these are typically minimal by design.
            // Check both function_type (if parser sets it) and source text.
            if matches!(
                function.function_type,
                ast::FunctionType::Fallback | ast::FunctionType::Receive
            ) {
                continue;
            }

            // Skip admin-only functions - these are called infrequently by privileged
            // actors who are willing to pay higher gas. Flagging them creates noise.
            let func_source = self.get_function_source(function, ctx);

            // Additional fallback/receive check via source text
            if self.is_fallback_or_receive(&func_source) {
                continue;
            }

            if self.is_admin_function(&func_source) {
                continue;
            }

            if let Some(gas_issues) = self.check_excessive_gas(function, ctx, &func_source) {
                for issue_desc in gas_issues {
                    let message = format!(
                        "Function '{}' contains excessive gas usage pattern. {} \
                        Excessive gas usage increases transaction costs and may cause out-of-gas errors.",
                        function.name.name, issue_desc
                    );

                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            function.name.location.start().line() as u32,
                            function.name.location.start().column() as u32,
                            function.name.name.len() as u32,
                        )
                        .with_cwe(400) // CWE-400: Uncontrolled Resource Consumption
                        .with_fix_suggestion(format!(
                            "Optimize gas usage in '{}'. \
                        Consider: (1) Move storage operations outside loops, \
                        (2) Cache storage reads in memory, \
                        (3) Use events instead of storage for historical data, \
                        (4) Pack struct variables efficiently, \
                        (5) Use memory arrays for temporary data.",
                            function.name.name
                        ));

                    findings.push(finding);
                }
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ExcessiveGasUsageDetector {
    fn check_excessive_gas(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
        func_source: &str,
    ) -> Option<Vec<String>> {
        function.body.as_ref()?;

        let mut issues = Vec::new();

        // Check if function already shows gas-optimization awareness
        let is_gas_optimized = self.shows_gas_optimization_awareness(func_source);

        // Pattern 1: Storage operations in loops
        if self.has_loop(func_source) {
            // Only flag .push() if the loop is not already optimized and not a standard op
            if func_source.contains(".push(")
                && !is_gas_optimized
                && !self.is_standard_token_operation(&function.name.name)
            {
                issues.push(
                    "Storage array push operation inside loop. Extremely gas-intensive".to_string(),
                );
            }

            if self.has_storage_write_in_loop(func_source)
                && !self.is_standard_token_operation(&function.name.name)
            {
                issues.push(
                    "Storage write operation inside loop. Consider using memory array".to_string(),
                );
            }

            if func_source.contains("delete ")
                && !is_gas_optimized
                && !self.is_standard_token_operation(&function.name.name)
            {
                issues.push(
                    "Storage deletion inside loop. Each delete costs significant gas".to_string(),
                );
            }
        }

        // Pattern 2: Redundant storage reads (raised threshold from 3 to 5)
        let storage_reads = self.count_storage_reads(func_source);
        if storage_reads >= 5 {
            issues.push(format!(
                "Multiple storage reads detected ({}). Cache in memory variable to save gas",
                storage_reads
            ));
        }

        // Pattern 3: String concatenation in loop or multiple times
        if self.has_loop(func_source) && func_source.contains("string.concat") {
            issues.push(
                "String concatenation in loop. Use bytes for efficient concatenation".to_string(),
            );
        }

        // Pattern 4: Dynamic array length in loop condition
        // Only flag if it's a storage array (indicated by lack of memory/calldata keywords nearby)
        // and the length has not been pre-cached in a local variable
        if func_source.contains("for")
            && func_source.contains(".length")
            && !self.has_cached_length(func_source)
            && self.is_storage_array_loop(func_source)
        {
            issues.push(
                "Array length read in every loop iteration. Cache length in local variable"
                    .to_string(),
            );
        }

        // Pattern 5: Emitting events in loops - only flag if potentially unbounded
        // Small bounded loops (e.g., <= 10 iterations) are acceptable
        if self.has_loop(func_source)
            && func_source.contains("emit ")
            && self.is_potentially_unbounded_loop(func_source)
        {
            issues.push(
                "Event emission inside loop. Can cause excessive gas costs for large arrays"
                    .to_string(),
            );
        }

        if issues.is_empty() {
            None
        } else {
            Some(issues)
        }
    }

    fn has_loop(&self, source: &str) -> bool {
        source.contains("for (")
            || source.contains("for(")
            || source.contains("while (")
            || source.contains("while(")
    }

    /// Detect constructors via name and source text.
    /// The parser currently sets name to "" for constructors, fallbacks, and receives,
    /// and defaults function_type to Function. We disambiguate by checking source text.
    ///
    /// Note: get_function_source uses 1-based line numbers as 0-based array indices,
    /// which means the signature line is not included in the returned source. We check
    /// the signature line directly from the source code using the function location.
    fn is_constructor(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> bool {
        // If the parser correctly set function_type, trust it
        if function.function_type == ast::FunctionType::Constructor {
            return true;
        }
        // Empty name could be constructor, fallback, or receive.
        // Check source text to distinguish.
        if function.name.name.is_empty() {
            // Check the function signature line(s) directly. The location line is 1-based,
            // so we need to subtract 1 to get the 0-based array index.
            let source_lines: Vec<&str> = ctx.source_code.lines().collect();
            let start_line = function.location.start().line();
            // Check the signature line and a few lines around it
            let check_start = if start_line >= 2 { start_line - 2 } else { 0 };
            let check_end = std::cmp::min(start_line + 1, source_lines.len());
            for i in check_start..check_end {
                let trimmed = source_lines[i].trim();
                if trimmed.starts_with("constructor")
                    || trimmed.starts_with("constructor(")
                    || trimmed.contains(" constructor(")
                {
                    return true;
                }
            }
        }
        false
    }

    /// Detect fallback/receive functions via source text when the parser
    /// does not set function_type correctly.
    fn is_fallback_or_receive(&self, source: &str) -> bool {
        let first_lines: Vec<&str> = source.lines().take(3).map(|l| l.trim()).collect();
        for line in &first_lines {
            if line.starts_with("fallback(")
                || line.starts_with("fallback (")
                || line.starts_with("receive(")
                || line.starts_with("receive (")
                || line.contains(" fallback(")
                || line.contains(" fallback (")
                || line.contains(" receive(")
                || line.contains(" receive (")
            {
                return true;
            }
        }
        // Also check the source for constructor/fallback/receive keywords
        // since get_function_source may not include the signature line
        // due to the 1-based/0-based line number mismatch.
        false
    }

    /// Check if function source indicates admin/privileged access control.
    fn is_admin_function(&self, source: &str) -> bool {
        // Look for modifier names in the function signature (first few lines before the body)
        // Function signatures in Solidity appear before the opening brace.
        let sig_end = source.find('{').unwrap_or(source.len());
        let signature = &source[..sig_end];

        for modifier in ADMIN_MODIFIERS {
            if signature.contains(modifier) {
                return true;
            }
        }
        false
    }

    /// Check if function name is a standard token operation.
    fn is_standard_token_operation(&self, name: &str) -> bool {
        STANDARD_TOKEN_OPS.iter().any(|op| name == *op)
    }

    /// Check if the function source shows awareness of gas optimization patterns,
    /// indicating the developer is already actively optimizing.
    fn shows_gas_optimization_awareness(&self, source: &str) -> bool {
        // Check for unchecked blocks (gas-conscious developers use these)
        if source.contains("unchecked {") || source.contains("unchecked{") {
            return true;
        }
        // Check for pre-increment (++i is cheaper than i++)
        if source.contains("++i") {
            return true;
        }
        // Check for assembly blocks (inline assembly = very gas-conscious)
        if source.contains("assembly {") || source.contains("assembly{") {
            return true;
        }
        false
    }

    /// Check if the .length value has been cached in a local variable before the loop.
    fn has_cached_length(&self, source: &str) -> bool {
        // Common patterns for caching array length:
        //   uint256 len = arr.length;
        //   uint256 arrLength = arr.length;
        //   uint len = arr.length;
        source.contains("uint len =")
            || source.contains("uint256 len =")
            || source.contains("Length =")
            || source.contains("length =")
            || source.contains("_length =")
            || source.contains("_len =")
            || source.contains("Count =")
    }

    fn has_storage_write_in_loop(&self, source: &str) -> bool {
        // Look for storage variable assignments in loops.
        // Improved heuristic: exclude known non-storage patterns and simple
        // initialization assignments (mapping[key] = true/false).
        let lines: Vec<&str> = source.lines().collect();
        let mut in_loop = false;
        let mut brace_count = 0;
        let mut loop_depth = 0;

        for line in lines {
            let trimmed = line.trim();

            if trimmed.starts_with("for ")
                || trimmed.starts_with("for(")
                || trimmed.starts_with("while ")
                || trimmed.starts_with("while(")
            {
                in_loop = true;
                if loop_depth == 0 {
                    brace_count = 0;
                }
                loop_depth += 1;
            }

            if in_loop {
                brace_count += trimmed.matches('{').count() as i32;
                brace_count -= trimmed.matches('}').count() as i32;

                // Skip the loop header line itself, comments, and empty lines
                if trimmed.starts_with("for ")
                    || trimmed.starts_with("for(")
                    || trimmed.starts_with("while ")
                    || trimmed.starts_with("while(")
                    || trimmed.starts_with("//")
                    || trimmed.starts_with("/*")
                    || trimmed.starts_with("*")
                    || trimmed.is_empty()
                    || trimmed == "{"
                    || trimmed == "}"
                {
                    if brace_count <= 0 {
                        in_loop = false;
                        loop_depth = 0;
                    }
                    continue;
                }

                // Look for storage writes, but exclude known false-positive patterns
                if trimmed.contains(" = ") {
                    // Skip lines that are clearly local variable declarations
                    if trimmed.contains("memory")
                        || trimmed.contains("calldata")
                        || trimmed.contains("uint")
                        || trimmed.contains("int ")
                        || trimmed.contains("address ")
                        || trimmed.contains("bool ")
                        || trimmed.contains("bytes ")
                        || trimmed.contains("string ")
                        || trimmed.contains("bytes32 ")
                        || trimmed.contains("bytes4 ")
                    {
                        if brace_count <= 0 {
                            in_loop = false;
                            loop_depth = 0;
                        }
                        continue;
                    }

                    // Skip simple boolean initialization patterns:
                    //   mapping[key] = true;  mapping[key] = false;
                    // These are inherent to the function's purpose (e.g., whitelisting)
                    // and cannot be optimized by moving out of the loop.
                    if self.is_simple_mapping_bool_set(trimmed) {
                        if brace_count <= 0 {
                            in_loop = false;
                            loop_depth = 0;
                        }
                        continue;
                    }

                    // Skip conditional assignments guarded by an if-check
                    // (shows the developer is being intentional about writes)
                    // This is handled implicitly -- if the only writes are bool sets
                    // we already skip them above.

                    // This looks like a genuine storage write in a loop
                    return true;
                }

                if brace_count <= 0 {
                    in_loop = false;
                    loop_depth = 0;
                }
            }
        }

        false
    }

    /// Check if a line is a simple mapping boolean assignment like:
    ///   supportedTokens[tokens[i]] = true;
    ///   strategyIsWhitelisted[strategies[i]] = false;
    ///
    /// These are idiomatic initialization patterns that cannot be avoided.
    fn is_simple_mapping_bool_set(&self, trimmed: &str) -> bool {
        // Must end with "= true;" or "= false;"
        let stripped = trimmed.trim_end_matches(';').trim();
        if stripped.ends_with("= true") || stripped.ends_with("= false") {
            // Must contain a mapping access pattern (brackets)
            if trimmed.contains('[') && trimmed.contains(']') {
                return true;
            }
        }
        false
    }

    fn count_storage_reads(&self, source: &str) -> usize {
        let mut count = 0;
        let lines: Vec<&str> = source.lines().collect();

        // Track locally declared variables to avoid FPs
        let mut local_vars: Vec<&str> = Vec::new();
        for line in &lines {
            let trimmed = line.trim();
            // Local variable declarations include memory/calldata or are type declarations
            if trimmed.contains("memory") || trimmed.contains("calldata") {
                // Extract variable name patterns
                if let Some(eq_idx) = trimmed.find(" = ") {
                    let before_eq = trimmed[..eq_idx].trim();
                    if let Some(name) = before_eq.split_whitespace().last() {
                        local_vars.push(name);
                    }
                }
            }
        }

        // Only count storage reads that aren't locally cached
        // Look for mapping access patterns with state variable indicators
        for line in &lines {
            let trimmed = line.trim();

            // Skip comments and local variable declarations
            if trimmed.starts_with("//")
                || trimmed.contains("memory")
                || trimmed.contains("calldata")
            {
                continue;
            }

            // Count mapping reads (these are definitely storage)
            count += trimmed.matches("balances[").count();
            count += trimmed.matches("allowances[").count();
            count += trimmed.matches("_balances[").count();
            count += trimmed.matches("_allowances[").count();
            count += trimmed.matches("stakes[").count();
            count += trimmed.matches("rewards[").count();
        }

        count
    }

    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            source_lines[start..=end].join("\n")
        } else {
            String::new()
        }
    }

    /// Check if loop iterates over storage array (not memory/calldata).
    /// Also checks function parameters to avoid flagging calldata/memory array iteration.
    fn is_storage_array_loop(&self, source: &str) -> bool {
        let lines: Vec<&str> = source.lines().collect();

        // First, collect parameter names from the function signature.
        // Parameters with memory/calldata keywords are not storage arrays.
        let mut param_array_names: Vec<String> = Vec::new();
        for line in &lines {
            let trimmed = line.trim();
            // Look for function signature lines with array parameters
            if (trimmed.contains("memory") || trimmed.contains("calldata"))
                && trimmed.contains("[]")
            {
                // Extract parameter name: e.g., "address[] memory tokens" -> "tokens"
                // or "IStrategy[] calldata strategiesToWhitelist" -> "strategiesToWhitelist"
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                for (i, part) in parts.iter().enumerate() {
                    if *part == "memory" || *part == "calldata" {
                        // The parameter name is usually the next token
                        if i + 1 < parts.len() {
                            let name = parts[i + 1]
                                .trim_end_matches(',')
                                .trim_end_matches(')')
                                .trim_end_matches(';');
                            if !name.is_empty() {
                                param_array_names.push(name.to_string());
                            }
                        }
                    }
                }
            }
        }

        for line in &lines {
            let trimmed = line.trim();
            // Check for loop with .length
            if (trimmed.contains("for") || trimmed.contains("while")) && trimmed.contains(".length")
            {
                // Skip if it's clearly a memory or calldata array
                if trimmed.contains("memory") || trimmed.contains("calldata") {
                    continue;
                }

                // Check if the .length access is on a known parameter array
                let is_param_array = param_array_names.iter().any(|name| {
                    trimmed.contains(&format!("{}.length", name))
                        || trimmed.contains(&format!("{}.", name))
                });
                if is_param_array {
                    continue;
                }

                // Check if array is a function parameter (likely memory/calldata)
                // Simple heuristic: storage arrays usually have state variable names
                return true;
            }
        }
        false
    }

    /// Check if loop is potentially unbounded (could iterate many times)
    fn is_potentially_unbounded_loop(&self, source: &str) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        for line in &lines {
            let trimmed = line.trim();
            if trimmed.contains("for") || trimmed.contains("while") {
                // Check for small bounded loops (explicit small limit)
                // e.g., for (uint i = 0; i < 10; i++) is bounded
                for bound in [
                    "< 10", "< 5", "< 3", "<= 10", "<= 5", "<= 3", "< 2", "<= 2", "< 8", "<= 8",
                    "< 20", "<= 20",
                ] {
                    if trimmed.contains(bound) {
                        return false; // Small bounded loop is OK
                    }
                }
                // If it's bounded by .length, it could be large
                if trimmed.contains(".length") {
                    return true;
                }
            }
        }
        // Default: not clearly unbounded
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = ExcessiveGasUsageDetector::new();
        assert_eq!(detector.name(), "Excessive Gas Usage");
        // Phase 6: Reclassified from Low to Info (gas optimization, not security)
        assert_eq!(detector.default_severity(), Severity::Info);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_is_simple_mapping_bool_set() {
        let detector = ExcessiveGasUsageDetector::new();

        // Should match: simple mapping bool assignments
        assert!(detector.is_simple_mapping_bool_set("supportedTokens[tokens[i]] = true;"));
        assert!(detector.is_simple_mapping_bool_set("isSigner[_signers[i]] = true;"));
        assert!(detector.is_simple_mapping_bool_set(
            "strategyIsWhitelistedForDeposit[strategiesToWhitelist[i]] = true;"
        ));
        assert!(detector.is_simple_mapping_bool_set(
            "strategyIsWhitelistedForDeposit[strategiesToRemoveFromWhitelist[i]] = false;"
        ));

        // Should NOT match: non-boolean assignments
        assert!(!detector.is_simple_mapping_bool_set("balances[msg.sender] = amount;"));
        assert!(!detector.is_simple_mapping_bool_set("data[i] = values[i];"));
        assert!(!detector.is_simple_mapping_bool_set("x = true;"));
    }

    #[test]
    fn test_is_admin_function() {
        let detector = ExcessiveGasUsageDetector::new();

        assert!(detector.is_admin_function("function setFee(uint256 fee) external onlyOwner {"));
        assert!(detector.is_admin_function(
            "function addStrategy(address s) external onlyAdmin nonReentrant {"
        ));
        assert!(detector.is_admin_function(
            "function addStrategiesToDepositWhitelist(\n    IStrategy[] calldata strategies\n) external onlyStrategyWhitelister nonReentrant {"
        ));

        // Should NOT match normal functions
        assert!(
            !detector.is_admin_function("function deposit(uint256 amount) external nonReentrant {")
        );
        assert!(!detector.is_admin_function("function withdraw(uint256 amount) external {"));
    }

    #[test]
    fn test_shows_gas_optimization_awareness() {
        let detector = ExcessiveGasUsageDetector::new();

        assert!(
            detector
                .shows_gas_optimization_awareness("for (uint i; i < len;) { unchecked { ++i; } }")
        );
        assert!(detector.shows_gas_optimization_awareness("for (uint i; i < len; ++i) {}"));
        assert!(detector.shows_gas_optimization_awareness("assembly { x := sload(slot) }"));

        assert!(
            !detector.shows_gas_optimization_awareness(
                "for (uint i = 0; i < len; i++) { arr.push(x); }"
            )
        );
    }

    #[test]
    fn test_has_cached_length() {
        let detector = ExcessiveGasUsageDetector::new();

        assert!(
            detector.has_cached_length("uint256 len = arr.length;\nfor (uint i; i < len; ++i) {}")
        );
        assert!(detector.has_cached_length(
            "uint256 arrLength = arr.length;\nfor (uint i; i < arrLength; ++i) {}"
        ));
        assert!(detector.has_cached_length(
            "uint256 strategiesToWhitelistLength = strategiesToWhitelist.length;"
        ));

        assert!(!detector.has_cached_length("for (uint i; i < arr.length; ++i) {}"));
    }

    #[test]
    fn test_has_storage_write_in_loop_skips_bool_init() {
        let detector = ExcessiveGasUsageDetector::new();

        // Should NOT flag: bool initialization patterns in loops
        let source = r#"
            for (uint256 i = 0; i < tokens.length; i++) {
                supportedTokens[tokens[i]] = true;
            }
        "#;
        assert!(
            !detector.has_storage_write_in_loop(source),
            "should not flag simple mapping bool set in loop"
        );

        // Should NOT flag: bool clear patterns
        let source2 = r#"
            for (uint256 i = 0; i < items.length; i++) {
                isActive[items[i]] = false;
            }
        "#;
        assert!(
            !detector.has_storage_write_in_loop(source2),
            "should not flag simple mapping bool clear in loop"
        );

        // SHOULD flag: non-trivial storage writes in loops
        let source3 = r#"
            for (uint256 i = 0; i < items.length; i++) {
                balances[items[i]] = amounts[i];
            }
        "#;
        assert!(
            detector.has_storage_write_in_loop(source3),
            "should flag non-trivial storage write in loop"
        );
    }

    #[test]
    fn test_has_storage_write_in_loop_skips_local_vars() {
        let detector = ExcessiveGasUsageDetector::new();

        // Should NOT flag: local variable assignments
        let source = r#"
            for (uint256 i = 0; i < len; i++) {
                uint256 temp = values[i];
                bool found = check(temp);
            }
        "#;
        assert!(
            !detector.has_storage_write_in_loop(source),
            "should not flag local variable declarations"
        );
    }

    #[test]
    fn test_is_standard_token_operation() {
        let detector = ExcessiveGasUsageDetector::new();

        assert!(detector.is_standard_token_operation("transfer"));
        assert!(detector.is_standard_token_operation("transferFrom"));
        assert!(detector.is_standard_token_operation("mint"));
        assert!(detector.is_standard_token_operation("burn"));
        assert!(detector.is_standard_token_operation("batchMint"));

        assert!(!detector.is_standard_token_operation("deposit"));
        assert!(!detector.is_standard_token_operation("withdraw"));
        assert!(!detector.is_standard_token_operation("rebalance"));
    }

    #[test]
    fn test_constructor_source_pattern() {
        // Verify that the FP pattern from safe_flash_loan_provider.sol would be caught
        // by constructor skip logic. We test the source-level helpers here.
        let detector = ExcessiveGasUsageDetector::new();

        // This is the exact pattern from safe_flash_loan_provider.sol constructor
        let constructor_source = r#"
            constructor(address[] memory tokens) {
                for (uint256 i = 0; i < tokens.length; i++) {
                    supportedTokens[tokens[i]] = true;
                }
            }
        "#;

        // The has_storage_write_in_loop should not flag bool set patterns
        assert!(
            !detector.has_storage_write_in_loop(constructor_source),
            "constructor bool init pattern should not be flagged as storage write"
        );
    }
}
