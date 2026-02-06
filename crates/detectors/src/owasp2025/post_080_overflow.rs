//! Post-0.8.0 Overflow Detector (OWASP 2025)
//!
//! Detects unchecked block overflows and assembly arithmetic.
//! Even with Solidity 0.8.0+ overflow protection, unchecked blocks bypass it.
//! $223M Cetus DEX hack (May 2025) was caused by assembly overflow.
//!
//! Phase 6 FP Reduction: Rewritten with proper pattern matching to avoid
//! flagging safe loop counter optimizations.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct Post080OverflowDetector {
    base: BaseDetector,
}

impl Post080OverflowDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("post-080-overflow".to_string()),
                "Post-0.8.0 Overflow Detection".to_string(),
                "Detects unchecked blocks and assembly arithmetic ($223M Cetus impact)".to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::BestPractices],
                Severity::Medium,
            ),
        }
    }

    /// Find unchecked blocks with dangerous arithmetic operations
    /// Returns (line_number, block_content, is_dangerous)
    fn find_unchecked_blocks(&self, source: &str) -> Vec<(u32, String, bool)> {
        let mut results = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let mut i = 0;
        while i < lines.len() {
            let trimmed = lines[i].trim();

            // Look for "unchecked {" or "unchecked{"
            if trimmed.contains("unchecked")
                && (trimmed.contains("{")
                    || (i + 1 < lines.len() && lines[i + 1].trim().starts_with("{")))
            {
                let start_line = i;
                let mut block_content = String::new();
                let mut brace_count = 0;
                let mut block_started = false;

                // Extract the block content
                for j in i..lines.len() {
                    let line = lines[j];
                    block_content.push_str(line);
                    block_content.push('\n');

                    for c in line.chars() {
                        if c == '{' {
                            brace_count += 1;
                            block_started = true;
                        } else if c == '}' {
                            brace_count -= 1;
                            if block_started && brace_count == 0 {
                                // Check if the block contains dangerous operations
                                let is_dangerous =
                                    self.is_dangerous_unchecked_block(&block_content);
                                results.push((
                                    start_line as u32 + 1,
                                    block_content.clone(),
                                    is_dangerous,
                                ));
                                i = j;
                                break;
                            }
                        }
                    }

                    if block_started && brace_count == 0 {
                        break;
                    }
                }
            }
            i += 1;
        }

        results
    }

    /// Determine if an unchecked block contains dangerous arithmetic
    /// Safe patterns (loop counters): ++i, i++, --i, i--, i += 1, i -= 1
    /// Dangerous patterns: +=, -=, *=, /= on non-counter vars, or a + b, a * b expressions
    fn is_dangerous_unchecked_block(&self, block: &str) -> bool {
        let block_lower = block.to_lowercase();

        // Skip blocks that are clearly just loop counter optimizations
        // These are the most common safe unchecked usage
        let safe_loop_patterns = [
            "++i",
            "i++",
            "++j",
            "j++",
            "++k",
            "k++",
            "--i",
            "i--",
            "--j",
            "j--",
            "--k",
            "k--",
            "i += 1",
            "j += 1",
            "k += 1",
            "i -= 1",
            "j -= 1",
            "k -= 1",
            "++index",
            "index++",
            "++counter",
            "counter++",
            "++n",
            "n++",
            "++len",
            "len++",
            "++offset",
            "offset++",
        ];

        // Remove comments from the block for analysis
        let block_no_comments = self.remove_comments(block);
        let block_trimmed = block_no_comments.trim();

        // Phase 16 FP Reduction: Skip fixed-point arithmetic patterns
        // Pattern: multiply then divide = bounded result (common in DeFi)
        if self.is_fixed_point_arithmetic(&block_no_comments) {
            return false;
        }

        // Phase 51 FP Reduction: Skip OpenZeppelin-style bounded arithmetic
        // OZ uses unchecked blocks for gas optimization with provably safe math
        if self.is_oz_bounded_arithmetic(&block_no_comments) {
            return false;
        }

        // Phase 51 FP Reduction: Skip subtraction where we know a >= b
        // Common pattern: unchecked { a - b } after require(a >= b)
        if self.is_safe_subtraction_pattern(&block_no_comments) {
            return false;
        }

        // Check if the block ONLY contains safe loop counter operations
        // A block like "unchecked { ++i; }" is safe
        let mut has_only_safe_patterns = false;
        for pattern in &safe_loop_patterns {
            if block_lower.contains(pattern) {
                has_only_safe_patterns = true;
                break;
            }
        }

        // If it has safe patterns, check if it ALSO has dangerous operations
        // Dangerous operations: arithmetic on variables that aren't loop counters
        let dangerous_patterns = [
            // Compound assignment with potential overflow
            "+= ", "-= ", "*= ", "/= ", // Binary operations (but not in comments)
            " + ", " - ", " * ", " / ",
        ];

        let mut has_dangerous = false;
        for pattern in &dangerous_patterns {
            if block_no_comments.contains(pattern) {
                // Check if this is a loop counter pattern
                let is_loop_counter = safe_loop_patterns
                    .iter()
                    .any(|safe| block_lower.contains(safe));

                // If the only arithmetic is loop counter, it's safe
                // Otherwise, flag it
                if !is_loop_counter || self.has_non_counter_arithmetic(&block_no_comments) {
                    has_dangerous = true;
                    break;
                }
            }
        }

        // Also flag multiplication which is the highest risk (Cetus-style)
        // But skip if it's fixed-point arithmetic (already checked above)
        if block_no_comments.contains(" * ") || block_no_comments.contains("*=") {
            // Multiplication is almost always dangerous in unchecked
            // unless it's a very specific pattern
            has_dangerous = true;
        }

        has_dangerous
    }

    /// Phase 51 FP Reduction: Check for OpenZeppelin-style bounded arithmetic
    /// OZ Math library patterns that are provably safe:
    /// - mulDiv with denominator checks
    /// - Shift operations (<<, >>)
    /// - Bitwise operations
    /// - Return statements with bounded values
    fn is_oz_bounded_arithmetic(&self, block_content: &str) -> bool {
        // Shift operations are safe (can't overflow in predictable ways)
        if block_content.contains("<<") || block_content.contains(">>") {
            return true;
        }

        // Bitwise operations are safe
        if block_content.contains(" & ")
            || block_content.contains(" | ")
            || block_content.contains(" ^ ")
        {
            return true;
        }

        // OZ-style return with type conversion (bounded by type)
        // e.g., return uint128(value)
        if block_content.contains("return uint")
            && (block_content.contains("uint8(")
                || block_content.contains("uint16(")
                || block_content.contains("uint32(")
                || block_content.contains("uint64(")
                || block_content.contains("uint128(")
                || block_content.contains("uint160("))
        {
            return true;
        }

        // OZ-style inverse/negation (bounded operation)
        if block_content.contains("~")
            || (block_content.contains("type(uint") && block_content.contains("max"))
        {
            return true;
        }

        false
    }

    /// Phase 51 FP Reduction: Check for safe subtraction patterns
    /// Pattern: subtraction where the minuend is guaranteed >= subtrahend
    fn is_safe_subtraction_pattern(&self, block_content: &str) -> bool {
        let has_subtraction = block_content.contains(" - ") || block_content.contains("-=");

        if !has_subtraction {
            return false;
        }

        // Common safe subtraction patterns
        let safe_patterns = [
            // Length-based: arr.length - 1 (length is always >= 1 when accessed)
            ".length - 1",
            ".length-1",
            // Balance after transfer check
            "balance -",
            // Timestamp/block calculations
            "block.timestamp -",
            "block.number -",
            // Supply calculations
            "totalSupply -",
            "supply -",
        ];

        for pattern in &safe_patterns {
            if block_content.contains(pattern) {
                return true;
            }
        }

        // Also safe if the subtraction result is immediately returned or assigned
        // and the block is small (likely a single operation)
        let line_count = block_content.lines().count();
        if line_count <= 3 && (block_content.contains("return ") || block_content.contains(" = ")) {
            // Small block with assignment/return is likely bounded by caller
            return true;
        }

        false
    }

    /// Phase 16 FP Reduction: Check for fixed-point arithmetic patterns
    /// Pattern: multiply then divide = bounded result (common in Safe, Solmate, DeFi)
    /// Examples:
    ///   - (a * b) / WAD
    ///   - a.mulDivDown(b, c)
    ///   - (x * PRECISION) / y
    fn is_fixed_point_arithmetic(&self, block_content: &str) -> bool {
        let has_mul = block_content.contains("*") || block_content.contains("mul");
        let has_div = block_content.contains("/") || block_content.contains("div");

        // Pattern 1: multiply then divide (bounded)
        if has_mul && has_div {
            return true;
        }

        // Pattern 2: Common fixed-point library function names
        let fixed_point_patterns = [
            "mulDiv",
            "muldiv",
            "mulWad",
            "mulwad",
            "divWad",
            "divwad",
            "mulDown",
            "mulUp",
            "divDown",
            "divUp",
            "fmul",
            "fdiv",
            "rmul",
            "rdiv",
            "wmul",
            "wdiv",
            "FullMath",
            "fullMath",
            "PRBMath",
            "FixedPoint",
        ];

        for pattern in &fixed_point_patterns {
            if block_content.contains(pattern) {
                return true;
            }
        }

        // Pattern 3: WAD/RAY/PRECISION constants (common in DeFi)
        let precision_constants = [
            "WAD",
            "RAY",
            "PRECISION",
            "SCALE",
            "UNIT",
            "1e18",
            "1e27",
            "10**18",
            "10**27",
        ];

        for constant in &precision_constants {
            if block_content.contains(constant) && (has_mul || has_div) {
                return true;
            }
        }

        false
    }

    /// Phase 16 FP Reduction: Check if source is a known safe math library
    /// These libraries intentionally use unchecked blocks for gas optimization
    /// and are audited/well-tested
    fn is_math_library(&self, source: &str) -> bool {
        // Check for well-known math library imports/packages
        let math_library_indicators = [
            // Solmate library
            "@solmate/",
            "solmate/",
            "library FixedPointMath",
            // OpenZeppelin SafeMath and Math utilities
            "library SafeMath",
            "@openzeppelin/contracts/utils/math",
            "@openzeppelin/contracts/utils/math/Math.sol",
            "@openzeppelin/contracts/utils/math/SignedMath.sol",
            // PRBMath
            "PRBMath",
            "library SD59x18",
            "library UD60x18",
            // Other common math libraries
            "library FullMath",
            "library Math",
            "library SignedMath",
            "library FixedPoint",
            "library ABDKMath",
            // Gnosis Safe math
            "GnosisSafe",
            "@safe-global/",
            // Uniswap math libraries
            "library UnsafeMath",
            "library LowGasSafeMath",
            "library BitMath",
            "library TickMath",
            "library SqrtPriceMath",
            "library FixedPoint96",
            "library FullMath",
            "library LiquidityMath",
            // Aave math
            "library WadRayMath",
            "library PercentageMath",
            "library MathUtils",
            // EigenLayer
            "library Endian",
        ];

        for indicator in &math_library_indicators {
            if source.contains(indicator) {
                return true;
            }
        }

        // Check for library declaration with math-related name
        if source.contains("library ") {
            let source_lower = source.to_lowercase();
            if source_lower.contains("library math")
                || source_lower.contains("library fixedpoint")
                || source_lower.contains("library safecalc")
                || source_lower.contains("library signedmath")
                || source_lower.contains("library wadray")
                || source_lower.contains("library percentage")
                || source_lower.contains("library tick")
                || source_lower.contains("library sqrt")
                || source_lower.contains("library liquidity")
                || source_lower.contains("library bit")
            {
                return true;
            }
        }

        // Phase 51: Check if this is an OpenZeppelin utility file (heavily audited)
        if source.contains("@openzeppelin") && source.contains("library ") {
            return true;
        }

        false
    }

    /// Phase 16 FP Reduction: Check if this is a Safe wallet project
    /// Safe wallet contracts are heavily audited and use unchecked/assembly intentionally
    fn is_safe_wallet_project(&self, ctx: &AnalysisContext) -> bool {
        // Check file path
        let file_path_lower = ctx.file_path.to_lowercase();
        if file_path_lower.contains("safe-smart-account")
            || file_path_lower.contains("safe-contracts")
            || file_path_lower.contains("gnosis-safe")
        {
            return true;
        }

        // Check for Safe-specific contract patterns in source
        let source = &ctx.source_code;
        if source.contains("ISafe")
            || source.contains("GnosisSafe")
            || source.contains("Safe.sol")
            || source.contains("@safe-global/")
            || (source.contains("contract Safe") && source.contains("execTransaction"))
        {
            return true;
        }

        false
    }

    /// Phase 16 FP Reduction: Check if assembly block is marked as memory-safe
    /// Blocks with @solidity memory-safe-assembly annotation are safe
    fn is_memory_safe_assembly(&self, source: &str, assembly_line: usize) -> bool {
        let lines: Vec<&str> = source.lines().collect();

        // Check 2 lines before assembly for memory-safe annotation
        let start = assembly_line.saturating_sub(3);
        for i in start..assembly_line {
            if let Some(line) = lines.get(i) {
                if line.contains("memory-safe-assembly") || line.contains("memory-safe") {
                    return true;
                }
            }
        }
        false
    }

    /// Phase 16 FP Reduction: Check if there's preceding validation before unchecked block
    /// If the line before unchecked has a require/if check, the arithmetic is likely safe
    fn has_preceding_validation(&self, source: &str, unchecked_line: usize) -> bool {
        let lines: Vec<&str> = source.lines().collect();

        // Check 3 lines before the unchecked block
        let start = unchecked_line.saturating_sub(4);
        for i in start..unchecked_line {
            if let Some(line) = lines.get(i) {
                let trimmed = line.trim();
                // Skip empty lines and comments
                if trimmed.is_empty() || trimmed.starts_with("//") {
                    continue;
                }

                // Check for validation patterns
                if trimmed.contains("require(")
                    || trimmed.contains("if (")
                    || trimmed.contains("if(")
                    || trimmed.contains("assert(")
                    || (trimmed.contains(">=")
                        || trimmed.contains("<=")
                        || trimmed.contains(">")
                        || trimmed.contains("<"))
                {
                    return true;
                }
            }
        }
        false
    }

    /// Check if block has arithmetic on non-loop-counter variables
    fn has_non_counter_arithmetic(&self, block: &str) -> bool {
        // Look for patterns like:
        // balance += amount
        // total = a + b
        // value *= multiplier
        let lines: Vec<&str> = block.lines().collect();

        for line in lines {
            let trimmed = line.trim();

            // Skip pure loop counter lines
            if trimmed.starts_with("++") || trimmed.starts_with("--") {
                continue;
            }
            if trimmed.ends_with("++;") || trimmed.ends_with("--;") {
                continue;
            }

            // Check for compound assignments that aren't loop counters
            if (trimmed.contains("+=")
                || trimmed.contains("-=")
                || trimmed.contains("*=")
                || trimmed.contains("/="))
            {
                // If it's not "i += 1" style, it's dangerous
                if !trimmed.contains("+= 1") && !trimmed.contains("-= 1") {
                    return true;
                }
            }

            // Check for binary arithmetic operations
            if trimmed.contains(" + ")
                || trimmed.contains(" - ")
                || trimmed.contains(" * ")
                || trimmed.contains(" / ")
            {
                // This is likely arithmetic on values
                return true;
            }
        }

        false
    }

    /// Find assembly blocks with arithmetic operations that lack overflow checks
    fn find_unsafe_assembly_arithmetic(&self, source: &str) -> Vec<(u32, String, String)> {
        let mut results = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let mut i = 0;
        while i < lines.len() {
            let trimmed = lines[i].trim();

            // Look for "assembly {" or "assembly{"
            if trimmed.contains("assembly")
                && (trimmed.contains("{")
                    || (i + 1 < lines.len() && lines[i + 1].trim().starts_with("{")))
            {
                // Phase 16 FP Reduction: Skip memory-safe assembly blocks
                if self.is_memory_safe_assembly(source, i) {
                    i += 1;
                    continue;
                }

                let start_line = i;
                let mut block_content = String::new();
                let mut brace_count = 0;
                let mut block_started = false;

                // Extract the assembly block
                for j in i..lines.len() {
                    let line = lines[j];
                    block_content.push_str(line);
                    block_content.push('\n');

                    for c in line.chars() {
                        if c == '{' {
                            brace_count += 1;
                            block_started = true;
                        } else if c == '}' {
                            brace_count -= 1;
                            if block_started && brace_count == 0 {
                                // Analyze the assembly block
                                let unsafe_ops = self.find_unsafe_assembly_ops(&block_content);
                                for (op, has_check) in unsafe_ops {
                                    if !has_check {
                                        results.push((
                                            start_line as u32 + 1,
                                            op,
                                            block_content.clone(),
                                        ));
                                    }
                                }
                                i = j;
                                break;
                            }
                        }
                    }

                    if block_started && brace_count == 0 {
                        break;
                    }
                }
            }
            i += 1;
        }

        results
    }

    /// Find unsafe arithmetic operations in assembly and check for overflow guards
    fn find_unsafe_assembly_ops(&self, block: &str) -> Vec<(String, bool)> {
        let mut ops = Vec::new();

        // Check for arithmetic operations
        let arithmetic_ops = ["add(", "sub(", "mul(", "div("];

        for op in &arithmetic_ops {
            if block.contains(op) {
                // Check if there's a corresponding overflow check
                let has_check = self.has_assembly_overflow_check(block, op);
                ops.push((op.to_string(), has_check));
            }
        }

        ops
    }

    /// Check if assembly block has overflow protection for an operation
    fn has_assembly_overflow_check(&self, block: &str, op: &str) -> bool {
        let block_lower = block.to_lowercase();

        match op {
            "add(" => {
                // Check for: if lt(result, a) { revert } or if gt(a, result) { revert }
                block_lower.contains("if lt(") ||
                block_lower.contains("if gt(") ||
                // Check for SafeMath-style: result := add(a, b) followed by check
                (block_lower.contains("add(") && block_lower.contains("revert"))
            }
            "sub(" => {
                // Check for: if gt(b, a) { revert } or comparison before sub
                block_lower.contains("if gt(")
                    || block_lower.contains("if lt(")
                    || (block_lower.contains("sub(") && block_lower.contains("revert"))
            }
            "mul(" => {
                // Check for: if div(result, a) != b { revert }
                // or if and(gt(a, 0), gt(b, div(MAX, a))) { revert }
                (block_lower.contains("mul(") && block_lower.contains("div(") && block_lower.contains("revert")) ||
                block_lower.contains("if iszero(") ||
                // Check for mulmod usage (safe pattern)
                block_lower.contains("mulmod(")
            }
            "div(" => {
                // Check for: if iszero(b) { revert }
                block_lower.contains("if iszero(")
                    || (block_lower.contains("div(") && block_lower.contains("revert"))
            }
            _ => false,
        }
    }

    /// Remove comments from code for analysis
    fn remove_comments(&self, code: &str) -> String {
        let mut result = String::new();
        let mut in_block_comment = false;
        let chars: Vec<char> = code.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            if !in_block_comment {
                if i + 1 < chars.len() && chars[i] == '/' && chars[i + 1] == '/' {
                    // Skip to end of line
                    while i < chars.len() && chars[i] != '\n' {
                        i += 1;
                    }
                } else if i + 1 < chars.len() && chars[i] == '/' && chars[i + 1] == '*' {
                    in_block_comment = true;
                    i += 2;
                } else {
                    result.push(chars[i]);
                    i += 1;
                }
            } else {
                if i + 1 < chars.len() && chars[i] == '*' && chars[i + 1] == '/' {
                    in_block_comment = false;
                    i += 2;
                } else {
                    i += 1;
                }
            }
        }

        result
    }
}

impl Default for Post080OverflowDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for Post080OverflowDetector {
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
        let source = &ctx.source_code;

        // Phase 16 FP Reduction: Skip known safe math library files
        if self.is_math_library(source) {
            return Ok(findings);
        }

        // Phase 16 FP Reduction: Skip known audited wallet projects
        if self.is_safe_wallet_project(ctx) {
            return Ok(findings);
        }

        // Phase 6: Properly analyze unchecked blocks instead of simple contains()
        let unchecked_blocks = self.find_unchecked_blocks(source);
        for (line, block, is_dangerous) in unchecked_blocks {
            // Phase 16 FP Reduction: Skip if there's preceding validation
            if is_dangerous && self.has_preceding_validation(source, line as usize) {
                continue;
            }

            if is_dangerous {
                let finding = self
                    .base
                    .create_finding_with_severity(
                        ctx,
                        "Unchecked block with dangerous arithmetic - overflow/underflow risk (OWASP 2025)"
                            .to_string(),
                        line,
                        0,
                        20,
                        Severity::Medium,
                    )
                    .with_fix_suggestion(
                        "⚠️ UNCHECKED BLOCKS BYPASS SOLIDITY 0.8.0+ PROTECTION!\n\
                     \n\
                     Solidity 0.8.0+ has automatic overflow/underflow checks,\n\
                     but 'unchecked' blocks disable this protection.\n\
                     \n\
                     ❌ DANGEROUS if user input involved:\n\
                     unchecked {\n\
                         balance += amount;  // Can overflow!\n\
                         total = a * b;      // Can overflow!\n\
                     }\n\
                     \n\
                     ✅ SAFE usage (loop counters only):\n\
                     for (uint256 i = 0; i < items.length;) {\n\
                         // Process items[i]\n\
                         unchecked { ++i; }  // Safe: loop counter\n\
                     }\n\
                     \n\
                     ✅ SAFE usage (guaranteed no overflow):\n\
                     unchecked {\n\
                         // Safe: subtraction after comparison\n\
                         if (a >= b) {\n\
                             result = a - b;  // No underflow possible\n\
                         }\n\
                     }\n\
                     \n\
                     ❌ NEVER use unchecked for:\n\
                     - User-supplied values\n\
                     - Token amounts or financial calculations\n\
                     - Multiplication of arbitrary values"
                            .to_string(),
                    );
                findings.push(finding);
            }
        }

        // Phase 6: Properly analyze assembly blocks for unsafe arithmetic
        let unsafe_assembly = self.find_unsafe_assembly_arithmetic(source);
        for (line, op, _block) in unsafe_assembly {
            let severity = if op == "mul(" {
                Severity::High // Multiplication overflow is highest risk (Cetus)
            } else {
                Severity::Medium
            };

            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    format!(
                        "Assembly {} without overflow protection - risk of silent overflow ($223M Cetus DEX)",
                        op.trim_end_matches('(')
                    ),
                    line,
                    0,
                    20,
                    severity,
                )
                .with_fix_suggestion(
                    "🚨 CRITICAL: Assembly has NO overflow protection!\n\
                     \n\
                     Real incident: Cetus DEX - $223M loss (May 2025)\n\
                     Cause: Assembly arithmetic overflow\n\
                     \n\
                     ❌ VULNERABLE:\n\
                     assembly {\n\
                         let result := add(a, b)  // NO OVERFLOW CHECK!\n\
                         let product := mul(x, y) // NO OVERFLOW CHECK!\n\
                     }\n\
                     \n\
                     ✅ SOLUTION - Add manual checks:\n\
                     assembly {\n\
                         let result := add(a, b)\n\
                         if lt(result, a) { revert(0, 0) }  // Overflow check\n\
                         \n\
                         let product := mul(x, y)\n\
                         if iszero(eq(div(product, x), y)) { revert(0, 0) }  // Mul check\n\
                     }\n\
                     \n\
                     ✅ BETTER - Use Solidity:\n\
                     uint256 result = a + b;  // Automatic overflow check"
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
        let detector = Post080OverflowDetector::new();
        assert_eq!(detector.name(), "Post-0.8.0 Overflow Detection");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_safe_loop_counter_not_flagged() {
        let detector = Post080OverflowDetector::new();

        // This is a safe pattern - should NOT be flagged
        let safe_code = r#"
            for (uint256 i = 0; i < arr.length;) {
                process(arr[i]);
                unchecked { ++i; }
            }
        "#;

        let blocks = detector.find_unchecked_blocks(safe_code);
        for (_, _, is_dangerous) in &blocks {
            assert!(!is_dangerous, "Safe loop counter should not be flagged");
        }
    }

    #[test]
    fn test_dangerous_arithmetic_flagged() {
        let detector = Post080OverflowDetector::new();

        // This is dangerous - SHOULD be flagged
        let dangerous_code = r#"
            function vulnerable(uint256 a, uint256 b) external {
                unchecked {
                    balance += amount;
                }
            }
        "#;

        let blocks = detector.find_unchecked_blocks(dangerous_code);
        let has_dangerous = blocks.iter().any(|(_, _, is_dangerous)| *is_dangerous);
        assert!(has_dangerous, "Dangerous arithmetic should be flagged");
    }

    #[test]
    fn test_multiplication_flagged() {
        let detector = Post080OverflowDetector::new();

        // Multiplication is high risk
        let mul_code = r#"
            unchecked {
                result = a * b;
            }
        "#;

        let blocks = detector.find_unchecked_blocks(mul_code);
        let has_dangerous = blocks.iter().any(|(_, _, is_dangerous)| *is_dangerous);
        assert!(
            has_dangerous,
            "Multiplication in unchecked should be flagged"
        );
    }

    #[test]
    fn test_assembly_without_check_flagged() {
        let detector = Post080OverflowDetector::new();

        // Unsafe assembly
        let unsafe_asm = r#"
            assembly {
                let result := add(a, b)
                mstore(0x00, result)
            }
        "#;

        let unsafe_ops = detector.find_unsafe_assembly_arithmetic(unsafe_asm);
        assert!(
            !unsafe_ops.is_empty(),
            "Unprotected assembly add should be flagged"
        );
    }

    #[test]
    fn test_assembly_with_check_not_flagged() {
        let detector = Post080OverflowDetector::new();

        // Safe assembly with overflow check
        let safe_asm = r#"
            assembly {
                let result := add(a, b)
                if lt(result, a) { revert(0, 0) }
                mstore(0x00, result)
            }
        "#;

        let unsafe_ops = detector.find_unsafe_assembly_arithmetic(safe_asm);
        assert!(
            unsafe_ops.is_empty(),
            "Protected assembly should not be flagged"
        );
    }

    #[test]
    fn test_fixed_point_arithmetic_not_flagged() {
        let detector = Post080OverflowDetector::new();

        // Phase 16: Fixed-point arithmetic is safe (multiply then divide)
        let fixed_point_code = r#"
            unchecked {
                result = (a * b) / WAD;
            }
        "#;

        let blocks = detector.find_unchecked_blocks(fixed_point_code);
        let has_dangerous = blocks.iter().any(|(_, _, is_dangerous)| *is_dangerous);
        assert!(
            !has_dangerous,
            "Fixed-point arithmetic (mul/div) should not be flagged"
        );
    }

    #[test]
    fn test_math_library_detection() {
        let detector = Post080OverflowDetector::new();

        // Solmate library should be detected as math library
        let solmate_source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;
            import {FixedPointMathLib} from "solmate/src/utils/FixedPointMathLib.sol";
            library FixedPointMath { ... }
        "#;
        assert!(
            detector.is_math_library(solmate_source),
            "Solmate library should be detected"
        );

        // Regular contract should not be detected as math library
        let regular_source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;
            contract MyContract { }
        "#;
        assert!(
            !detector.is_math_library(regular_source),
            "Regular contract should not be detected as math library"
        );
    }

    #[test]
    fn test_preceding_validation_check() {
        let detector = Post080OverflowDetector::new();

        let code_with_validation = r#"
            function test() {
                require(a >= b, "underflow");
                unchecked {
                    result = a - b;
                }
            }
        "#;

        // Line 4 is where unchecked starts (1-indexed)
        assert!(
            detector.has_preceding_validation(code_with_validation, 4),
            "Preceding require should be detected"
        );
    }
}
