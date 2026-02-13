use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

// ---------------------------------------------------------------------------
// 1. MissingNatspecDetector
// ---------------------------------------------------------------------------

/// Detector for public/external functions missing NatSpec documentation.
///
/// NatSpec (`///` or `/** */`) comments are the Solidity-standard way to
/// document function behaviour, parameters, and return values. Public API
/// surfaces without documentation are harder to audit and integrate with.
pub struct MissingNatspecDetector {
    base: BaseDetector,
}

impl Default for MissingNatspecDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MissingNatspecDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("missing-natspec"),
                "Missing NatSpec Documentation".to_string(),
                "Detects public and external functions that lack NatSpec documentation \
                 (/// or /** */ comments). Well-documented functions improve auditability \
                 and developer experience."
                    .to_string(),
                vec![DetectorCategory::Lint],
                Severity::Info,
            ),
        }
    }

    /// Check whether any of the lines immediately preceding `func_line_idx`
    /// (skipping blank lines) contain NatSpec markers (`///` or `/**`).
    fn has_natspec_before(lines: &[&str], func_line_idx: usize) -> bool {
        if func_line_idx == 0 {
            return false;
        }
        // Walk backwards from the line before the function declaration.
        let mut i = func_line_idx - 1;
        loop {
            let trimmed = lines[i].trim();
            // Skip blank lines
            if trimmed.is_empty() {
                if i == 0 {
                    return false;
                }
                i -= 1;
                continue;
            }
            // NatSpec single-line comment
            if trimmed.starts_with("///") {
                return true;
            }
            // NatSpec multi-line block end or single-line block
            if trimmed.contains("/**") || trimmed.contains("*/") || trimmed.starts_with("*") {
                return true;
            }
            // Any other non-blank, non-NatSpec line means no documentation
            return false;
        }
    }

    /// Return true if this is a constructor, fallback, or receive function
    /// declaration (which are excluded from the check).
    fn is_special_function(line: &str) -> bool {
        let trimmed = line.trim();
        trimmed.contains("constructor(")
            || trimmed.contains("constructor (")
            || trimmed.starts_with("fallback(")
            || trimmed.starts_with("fallback (")
            || trimmed.starts_with("receive(")
            || trimmed.starts_with("receive (")
            || trimmed.contains("function fallback(")
            || trimmed.contains("function receive(")
    }

    /// Return true if the function declaration is public or external.
    fn is_public_or_external(lines: &[&str], func_line_idx: usize) -> bool {
        // The visibility may be on the same line or on a subsequent line before
        // the opening brace. Collect up to 5 lines from the declaration start.
        let mut sig = String::new();
        for j in func_line_idx..lines.len().min(func_line_idx + 6) {
            sig.push(' ');
            sig.push_str(lines[j].trim());
            if lines[j].contains('{') || lines[j].contains(';') {
                break;
            }
        }
        sig.contains("public") || sig.contains("external")
    }

    /// Extract the function name from a declaration line.
    fn extract_function_name(line: &str) -> String {
        if let Some(start) = line.find("function ") {
            let after = &line[start + 9..];
            if let Some(paren) = after.find('(') {
                return after[..paren].trim().to_string();
            }
        }
        "unknown".to_string()
    }
}

impl Detector for MissingNatspecDetector {
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

    fn is_lint(&self) -> bool {
        true
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = ctx.source_code.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if !trimmed.contains("function ") {
                continue;
            }
            // Skip special functions
            if Self::is_special_function(trimmed) {
                continue;
            }
            // Only care about public/external
            if !Self::is_public_or_external(&lines, idx) {
                continue;
            }
            // Check for NatSpec
            if !Self::has_natspec_before(&lines, idx) {
                let func_name = Self::extract_function_name(trimmed);
                let line_number = (idx + 1) as u32;
                let message = format!(
                    "Public/external function '{}' is missing NatSpec documentation. \
                     Add /// or /** */ comments describing purpose, parameters, and return values.",
                    func_name,
                );
                let finding = self
                    .base
                    .create_finding(ctx, message, line_number, 1, trimmed.len() as u32)
                    .with_confidence(Confidence::High)
                    .with_fix_suggestion(
                        "Add NatSpec comments above the function:\n\n\
                         /// @notice Brief description of what the function does\n\
                         /// @param paramName Description of the parameter\n\
                         /// @return Description of the return value"
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

// ---------------------------------------------------------------------------
// 2. UnusedImportDetector
// ---------------------------------------------------------------------------

/// Detector for imported but unused symbols.
///
/// Unused imports add noise to the source file and can confuse auditors into
/// thinking a dependency is actually used. Removing them keeps the code clean.
pub struct UnusedImportDetector {
    base: BaseDetector,
}

impl Default for UnusedImportDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl UnusedImportDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("unused-import"),
                "Unused Import".to_string(),
                "Detects import statements where the imported name does not appear \
                 to be used elsewhere in the source file."
                    .to_string(),
                vec![DetectorCategory::Lint],
                Severity::Info,
            ),
        }
    }

    /// Extract the primary imported name from an import line.
    ///
    /// Handles:
    ///   import "./Foo.sol";                     -> Foo
    ///   import {Bar} from "./Bar.sol";          -> Bar
    ///   import {Baz as Qux} from "./Baz.sol";   -> Qux
    ///   import * as Lib from "./Lib.sol";       -> Lib
    fn extract_imported_names(line: &str) -> Vec<String> {
        let trimmed = line.trim();
        let mut names = Vec::new();

        // Pattern: import {A, B as C} from "...";
        if let (Some(open), Some(close)) = (trimmed.find('{'), trimmed.find('}')) {
            let inner = &trimmed[open + 1..close];
            for part in inner.split(',') {
                let part = part.trim();
                if let Some(as_pos) = part.find(" as ") {
                    let alias = part[as_pos + 4..].trim();
                    if !alias.is_empty() {
                        names.push(alias.to_string());
                    }
                } else if !part.is_empty() {
                    names.push(part.to_string());
                }
            }
            return names;
        }

        // Pattern: import * as Lib from "...";
        if trimmed.contains("* as ") {
            if let Some(as_pos) = trimmed.find("* as ") {
                let after = &trimmed[as_pos + 5..];
                let name: String = after
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() {
                    names.push(name);
                }
                return names;
            }
        }

        // Pattern: import "path/Foo.sol"; -> extract Foo from filename
        if let Some(start) = trimmed.find('"').or_else(|| trimmed.find('\'')) {
            let after_quote = &trimmed[start + 1..];
            if let Some(end) = after_quote.find('"').or_else(|| after_quote.find('\'')) {
                let path = &after_quote[..end];
                // Extract filename without extension
                if let Some(slash) = path.rfind('/') {
                    let filename = &path[slash + 1..];
                    if let Some(dot) = filename.rfind('.') {
                        let name = &filename[..dot];
                        if !name.is_empty() {
                            names.push(name.to_string());
                        }
                    }
                }
            }
        }

        names
    }
}

impl Detector for UnusedImportDetector {
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

    fn is_lint(&self) -> bool {
        true
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = ctx.source_code.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if !trimmed.starts_with("import ") {
                continue;
            }

            let imported_names = Self::extract_imported_names(trimmed);
            // The rest of the source after this import line
            let rest_of_source: String = lines[idx + 1..].join("\n");

            for name in &imported_names {
                // Check if the name appears anywhere after the import
                if !rest_of_source.contains(name.as_str()) {
                    let line_number = (idx + 1) as u32;
                    let message = format!(
                        "Imported name '{}' does not appear to be used in this file. \
                         Consider removing the unused import to reduce clutter.",
                        name,
                    );
                    let finding = self
                        .base
                        .create_finding(ctx, message, line_number, 1, trimmed.len() as u32)
                        .with_confidence(Confidence::High)
                        .with_fix_suggestion(format!(
                            "Remove the unused import of '{}', or use it in the contract code.",
                            name,
                        ));
                    findings.push(finding);
                }
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ---------------------------------------------------------------------------
// 3. MagicNumberDetector
// ---------------------------------------------------------------------------

/// Detector for hardcoded numeric literals ("magic numbers") in function bodies.
///
/// Magic numbers reduce readability and make maintenance harder. Named
/// constants (`uint256 constant FEE_BPS = 300;`) are preferred.
pub struct MagicNumberDetector {
    base: BaseDetector,
}

impl Default for MagicNumberDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MagicNumberDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("magic-number"),
                "Magic Number".to_string(),
                "Detects hardcoded numeric literals in function bodies that should be \
                 replaced with named constants for better readability and maintainability."
                    .to_string(),
                vec![DetectorCategory::Lint],
                Severity::Low,
            ),
        }
    }

    /// Common numeric values that should NOT be flagged.
    const ALLOWED_VALUES: &'static [&'static str] = &[
        "0",
        "1",
        "2",
        "10",
        "18",
        "100",
        "1000",
        "256",
        "255",
        "1e18",
        "1e6",
        "1e8",
        "1e9",
        "1e27",
        "0x0",
        "0x00",
        "0xff",
        "0xFF",
        "32",
        "64",
        "128",
        "160",
        "224",
        "type(uint256).max",
        "type(uint128).max",
    ];

    /// Return true if the line is inside a constant/immutable declaration,
    /// an event definition, or a state variable initializer at contract level
    /// (i.e. outside function bodies).
    fn is_declaration_context(lines: &[&str], line_idx: usize) -> bool {
        let trimmed = lines[line_idx].trim();
        // Constant or immutable declaration
        if trimmed.contains("constant ") || trimmed.contains("immutable ") {
            return true;
        }
        // Enum value
        if trimmed.starts_with("enum ") {
            return true;
        }
        // Event declaration
        if trimmed.starts_with("event ") {
            return true;
        }
        false
    }

    /// Return true if the line is inside a comment.
    fn is_comment(line: &str) -> bool {
        let trimmed = line.trim();
        trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*")
    }

    /// Return true if `line_idx` falls inside a function body (between
    /// `function ...{` and the matching `}`).
    fn is_inside_function_body(lines: &[&str], line_idx: usize) -> bool {
        // Walk backwards to see if we are between a function declaration and
        // its closing brace.
        let mut depth: i32 = 0;
        for i in (0..=line_idx).rev() {
            for c in lines[i].chars().rev() {
                match c {
                    '}' => depth += 1,
                    '{' => {
                        depth -= 1;
                        if depth < 0 {
                            // We reached an unmatched '{'. Check if this
                            // opening brace belongs to a function.
                            let mut sig = String::new();
                            for j in (0..=i).rev() {
                                sig = format!("{} {}", lines[j].trim(), sig);
                                if lines[j].trim().starts_with("function ")
                                    || lines[j].trim().contains(" function ")
                                {
                                    return true;
                                }
                                // Stop if we hit another block opener
                                if lines[j].trim().starts_with("contract ")
                                    || lines[j].trim().starts_with("library ")
                                    || lines[j].trim().starts_with("interface ")
                                {
                                    return false;
                                }
                                if sig.contains("function ") {
                                    return true;
                                }
                            }
                            return false;
                        }
                    }
                    _ => {}
                }
            }
        }
        false
    }

    /// Extract numeric literal tokens from a line of Solidity code.
    fn extract_numeric_literals(line: &str) -> Vec<(usize, String)> {
        let mut results = Vec::new();
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            // Skip string literals
            if chars[i] == '"' || chars[i] == '\'' {
                let quote = chars[i];
                i += 1;
                while i < chars.len() && chars[i] != quote {
                    if chars[i] == '\\' {
                        i += 1; // skip escaped char
                    }
                    i += 1;
                }
                i += 1;
                continue;
            }

            // Match numeric literal (decimal or hex)
            if chars[i].is_ascii_digit()
                || (chars[i] == '0'
                    && i + 1 < chars.len()
                    && (chars[i + 1] == 'x' || chars[i + 1] == 'X'))
            {
                // Make sure it's not part of an identifier (e.g., var1)
                if i > 0 && (chars[i - 1].is_alphanumeric() || chars[i - 1] == '_') {
                    i += 1;
                    continue;
                }
                let start = i;
                // Hex literal
                if chars[i] == '0'
                    && i + 1 < chars.len()
                    && (chars[i + 1] == 'x' || chars[i + 1] == 'X')
                {
                    i += 2;
                    while i < chars.len() && (chars[i].is_ascii_hexdigit() || chars[i] == '_') {
                        i += 1;
                    }
                } else {
                    // Decimal literal (possibly with underscores or scientific notation)
                    while i < chars.len()
                        && (chars[i].is_ascii_digit()
                            || chars[i] == '_'
                            || chars[i] == 'e'
                            || chars[i] == 'E')
                    {
                        i += 1;
                    }
                }
                let token: String = chars[start..i].iter().collect();
                // Clean underscores for comparison
                let clean: String = token.replace('_', "");
                if !clean.is_empty() {
                    results.push((start, clean));
                }
                continue;
            }

            i += 1;
        }

        results
    }
}

impl Detector for MagicNumberDetector {
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

    fn is_lint(&self) -> bool {
        true
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = ctx.source_code.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            if Self::is_comment(line) {
                continue;
            }
            if Self::is_declaration_context(&lines, idx) {
                continue;
            }
            if !Self::is_inside_function_body(&lines, idx) {
                continue;
            }

            let literals = Self::extract_numeric_literals(line);
            for (col, value) in &literals {
                // Skip allowed values
                if Self::ALLOWED_VALUES.contains(&value.as_str()) {
                    continue;
                }
                // Skip very small numbers (single digit values 3-9)
                if value.len() == 1 {
                    continue;
                }

                let line_number = (idx + 1) as u32;
                let message = format!(
                    "Magic number '{}' used in code. Replace with a named constant for \
                     better readability and maintainability.",
                    value,
                );
                let finding = self
                    .base
                    .create_finding(
                        ctx,
                        message,
                        line_number,
                        (*col + 1) as u32,
                        value.len() as u32,
                    )
                    .with_confidence(Confidence::High)
                    .with_fix_suggestion(format!(
                        "Define a named constant at the contract level:\n\n\
                         uint256 private constant DESCRIPTIVE_NAME = {};\n\n\
                         Then use DESCRIPTIVE_NAME instead of the literal value.",
                        value,
                    ));
                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ---------------------------------------------------------------------------
// 4. FunctionTooLongDetector
// ---------------------------------------------------------------------------

/// Detector for functions that exceed a reasonable line count.
///
/// Long functions are harder to audit, test, and maintain. Breaking them
/// into smaller, well-named helpers improves code quality.
pub struct FunctionTooLongDetector {
    base: BaseDetector,
    /// Maximum number of lines a function body may span before being flagged.
    max_lines: usize,
}

impl Default for FunctionTooLongDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl FunctionTooLongDetector {
    /// Default threshold: flag functions longer than 50 lines.
    const DEFAULT_MAX_LINES: usize = 50;

    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("function-too-long"),
                "Function Too Long".to_string(),
                "Detects functions whose body exceeds 50 lines. Long functions are \
                 harder to review and maintain; consider refactoring into smaller helpers."
                    .to_string(),
                vec![DetectorCategory::Lint],
                Severity::Info,
            ),
            max_lines: Self::DEFAULT_MAX_LINES,
        }
    }

    /// Count lines in a function body by tracking braces from the function
    /// declaration line.
    fn count_function_lines(lines: &[&str], func_start: usize) -> usize {
        let mut depth: i32 = 0;
        let mut body_started = false;
        let mut body_start_line = func_start;

        for i in func_start..lines.len() {
            for c in lines[i].chars() {
                match c {
                    '{' => {
                        if !body_started {
                            body_started = true;
                            body_start_line = i;
                        }
                        depth += 1;
                    }
                    '}' => {
                        depth -= 1;
                        if body_started && depth == 0 {
                            // i is the closing brace line
                            return i.saturating_sub(body_start_line);
                        }
                    }
                    _ => {}
                }
            }
        }
        0
    }

    /// Extract function name from a declaration line.
    fn extract_function_name(line: &str) -> String {
        if let Some(start) = line.find("function ") {
            let after = &line[start + 9..];
            if let Some(paren) = after.find('(') {
                return after[..paren].trim().to_string();
            }
        }
        "unknown".to_string()
    }
}

impl Detector for FunctionTooLongDetector {
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

    fn is_lint(&self) -> bool {
        true
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = ctx.source_code.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if !trimmed.contains("function ") {
                continue;
            }
            // Skip lines that are just comments mentioning "function"
            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }

            let body_lines = Self::count_function_lines(&lines, idx);
            if body_lines > self.max_lines {
                let func_name = Self::extract_function_name(trimmed);
                let line_number = (idx + 1) as u32;
                let message = format!(
                    "Function '{}' is {} lines long (threshold: {}). \
                     Consider refactoring into smaller, well-named helper functions.",
                    func_name, body_lines, self.max_lines,
                );
                let finding = self
                    .base
                    .create_finding(ctx, message, line_number, 1, trimmed.len() as u32)
                    .with_confidence(Confidence::High)
                    .with_fix_suggestion(
                        "Break the function into smaller helpers:\n\n\
                         1. Identify logically distinct blocks of code\n\
                         2. Extract each block into a private/internal function\n\
                         3. Give each helper a descriptive name\n\
                         4. Keep the parent function as a high-level orchestrator"
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

// ---------------------------------------------------------------------------
// 5. ExcessiveInheritanceDetector
// ---------------------------------------------------------------------------

/// Detector for contracts that inherit from more than 5 base contracts.
///
/// Excessive inheritance makes the linearisation order (C3) harder to reason
/// about, increases deployment gas, and complicates auditing.
pub struct ExcessiveInheritanceDetector {
    base: BaseDetector,
    /// Maximum number of base contracts before a warning is emitted.
    max_bases: usize,
}

impl Default for ExcessiveInheritanceDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ExcessiveInheritanceDetector {
    /// Default threshold: flag contracts inheriting more than 5 bases.
    const DEFAULT_MAX_BASES: usize = 5;

    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("excessive-inheritance"),
                "Excessive Inheritance".to_string(),
                "Detects contracts that inherit from more than 5 base contracts. \
                 Deep inheritance hierarchies complicate C3 linearisation, increase \
                 deployment gas, and make auditing harder."
                    .to_string(),
                vec![DetectorCategory::Lint],
                Severity::Info,
            ),
            max_bases: Self::DEFAULT_MAX_BASES,
        }
    }
}

impl Detector for ExcessiveInheritanceDetector {
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

    fn is_lint(&self) -> bool {
        true
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let inheritance_count = ctx.contract.inheritance.len();
        if inheritance_count > self.max_bases {
            let contract_name = ctx.contract.name.name;
            let line = ctx.contract.name.location.start().line() as u32;
            let col = ctx.contract.name.location.start().column() as u32;

            let bases: Vec<&str> = ctx
                .contract
                .inheritance
                .iter()
                .map(|i| i.base.name)
                .collect();

            let message = format!(
                "Contract '{}' inherits from {} base contracts ({}), which exceeds \
                 the recommended maximum of {}. This complicates C3 linearisation \
                 and makes the contract harder to audit.",
                contract_name,
                inheritance_count,
                bases.join(", "),
                self.max_bases,
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, col, contract_name.len() as u32)
                .with_confidence(Confidence::High)
                .with_fix_suggestion(
                    "Reduce the number of base contracts:\n\n\
                     1. Merge closely related bases into a single contract\n\
                     2. Use composition (has-a) instead of inheritance (is-a)\n\
                     3. Consolidate interface implementations\n\
                     4. Consider using libraries for shared utility code"
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- MissingNatspecDetector -----------------------------------------------

    #[test]
    fn test_missing_natspec_properties() {
        let detector = MissingNatspecDetector::new();
        assert_eq!(detector.id().0, "missing-natspec");
        assert_eq!(detector.name(), "Missing NatSpec Documentation");
        assert_eq!(detector.default_severity(), Severity::Info);
        assert!(detector.is_lint());
        assert!(detector.is_enabled());
        assert_eq!(detector.categories(), vec![DetectorCategory::Lint]);
    }

    #[test]
    fn test_missing_natspec_has_natspec() {
        let lines = vec!["/// @notice Does something", "function foo() public {"];
        assert!(MissingNatspecDetector::has_natspec_before(&lines, 1));
    }

    #[test]
    fn test_missing_natspec_no_natspec() {
        let lines = vec!["uint256 x = 1;", "function foo() public {"];
        assert!(!MissingNatspecDetector::has_natspec_before(&lines, 1));
    }

    #[test]
    fn test_missing_natspec_multiline_natspec() {
        let lines = vec![
            "/**",
            " * @notice Does something",
            " */",
            "function foo() external {",
        ];
        assert!(MissingNatspecDetector::has_natspec_before(&lines, 3));
    }

    // -- UnusedImportDetector ------------------------------------------------

    #[test]
    fn test_unused_import_properties() {
        let detector = UnusedImportDetector::new();
        assert_eq!(detector.id().0, "unused-import");
        assert_eq!(detector.name(), "Unused Import");
        assert_eq!(detector.default_severity(), Severity::Info);
        assert!(detector.is_lint());
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_extract_named_import() {
        let names = UnusedImportDetector::extract_imported_names(
            "import {Ownable} from \"@openzeppelin/contracts/access/Ownable.sol\";",
        );
        assert_eq!(names, vec!["Ownable"]);
    }

    #[test]
    fn test_extract_aliased_import() {
        let names =
            UnusedImportDetector::extract_imported_names("import {Foo as Bar} from \"./Foo.sol\";");
        assert_eq!(names, vec!["Bar"]);
    }

    #[test]
    fn test_extract_wildcard_import() {
        let names =
            UnusedImportDetector::extract_imported_names("import * as Utils from \"./Utils.sol\";");
        assert_eq!(names, vec!["Utils"]);
    }

    #[test]
    fn test_extract_path_import() {
        let names = UnusedImportDetector::extract_imported_names("import \"./MyToken.sol\";");
        assert_eq!(names, vec!["MyToken"]);
    }

    // -- MagicNumberDetector -------------------------------------------------

    #[test]
    fn test_magic_number_properties() {
        let detector = MagicNumberDetector::new();
        assert_eq!(detector.id().0, "magic-number");
        assert_eq!(detector.name(), "Magic Number");
        assert_eq!(detector.default_severity(), Severity::Low);
        assert!(detector.is_lint());
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_extract_numeric_literals() {
        let literals = MagicNumberDetector::extract_numeric_literals("uint256 x = 42 + 100;");
        let values: Vec<&str> = literals.iter().map(|(_, v)| v.as_str()).collect();
        assert!(values.contains(&"42"));
        assert!(values.contains(&"100"));
    }

    #[test]
    fn test_extract_hex_literal() {
        let literals = MagicNumberDetector::extract_numeric_literals("bytes32 x = 0xdeadbeef;");
        let values: Vec<&str> = literals.iter().map(|(_, v)| v.as_str()).collect();
        assert!(values.contains(&"0xdeadbeef"));
    }

    // -- FunctionTooLongDetector ---------------------------------------------

    #[test]
    fn test_function_too_long_properties() {
        let detector = FunctionTooLongDetector::new();
        assert_eq!(detector.id().0, "function-too-long");
        assert_eq!(detector.name(), "Function Too Long");
        assert_eq!(detector.default_severity(), Severity::Info);
        assert!(detector.is_lint());
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_count_function_lines_short() {
        let source = "function foo() public {\n    x = 1;\n    y = 2;\n}";
        let lines: Vec<&str> = source.lines().collect();
        let count = FunctionTooLongDetector::count_function_lines(&lines, 0);
        assert_eq!(count, 3); // Lines 1-3 (opening brace to closing brace)
    }

    #[test]
    fn test_count_function_lines_empty() {
        let source = "function foo() public {}";
        let lines: Vec<&str> = source.lines().collect();
        let count = FunctionTooLongDetector::count_function_lines(&lines, 0);
        assert_eq!(count, 0); // opening and closing on same line
    }

    // -- ExcessiveInheritanceDetector ----------------------------------------

    #[test]
    fn test_excessive_inheritance_properties() {
        let detector = ExcessiveInheritanceDetector::new();
        assert_eq!(detector.id().0, "excessive-inheritance");
        assert_eq!(detector.name(), "Excessive Inheritance");
        assert_eq!(detector.default_severity(), Severity::Info);
        assert!(detector.is_lint());
        assert!(detector.is_enabled());
    }
}
