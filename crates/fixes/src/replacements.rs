use anyhow::{Result, Context};
use regex::Regex;
use std::collections::HashMap;
use crate::{TextReplacement, FixSuggestion};

/// Advanced text replacement engine for applying code fixes
pub struct ReplacementEngine {
    /// Cache for compiled regex patterns
    regex_cache: HashMap<String, Regex>,
}

impl ReplacementEngine {
    /// Create a new replacement engine
    pub fn new() -> Self {
        Self {
            regex_cache: HashMap::new(),
        }
    }

    /// Apply a set of text replacements to source code
    pub fn apply_replacements(&mut self, source: &str, replacements: &[TextReplacement]) -> Result<String> {
        if replacements.is_empty() {
            return Ok(source.to_string());
        }

        // Sort replacements by position (reverse order to avoid offset issues)
        let mut sorted_replacements = replacements.to_vec();
        sorted_replacements.sort_by(|a, b| {
            let a_pos = (a.start_line, a.start_column);
            let b_pos = (b.start_line, b.start_column);
            b_pos.cmp(&a_pos) // Reverse order
        });

        let mut lines: Vec<String> = source.lines().map(|line| line.to_string()).collect();

        for replacement in sorted_replacements {
            self.apply_single_replacement(&mut lines, &replacement)
                .with_context(|| format!("Failed to apply replacement at {}:{}", replacement.start_line, replacement.start_column))?;
        }

        Ok(lines.join("\n"))
    }

    /// Apply a complete fix suggestion to source code
    pub fn apply_fix(&mut self, source: &str, fix: &FixSuggestion) -> Result<String> {
        self.apply_replacements(source, &fix.replacements)
    }

    /// Apply multiple fixes, resolving conflicts automatically
    pub fn apply_multiple_fixes(&mut self, source: &str, fixes: &[FixSuggestion]) -> Result<String> {
        // Collect all replacements
        let mut all_replacements = Vec::new();
        for fix in fixes {
            all_replacements.extend(fix.replacements.clone());
        }

        // Remove overlapping replacements (keep the first one encountered)
        let non_conflicting = self.resolve_replacement_conflicts(all_replacements)?;

        self.apply_replacements(source, &non_conflicting)
    }

    /// Generate replacement for adding a line at a specific position
    pub fn add_line_after(&self, line_number: u32, content: &str) -> TextReplacement {
        TextReplacement {
            start_line: line_number,
            start_column: u32::MAX, // End of line
            end_line: line_number,
            end_column: u32::MAX,
            replacement_text: format!("\n{}", content),
        }
    }

    /// Generate replacement for adding a line before a specific position
    pub fn add_line_before(&self, line_number: u32, content: &str) -> TextReplacement {
        TextReplacement {
            start_line: line_number,
            start_column: 1,
            end_line: line_number,
            end_column: 1,
            replacement_text: format!("{}\n", content),
        }
    }

    /// Generate replacement for replacing an entire line
    pub fn replace_line(&self, line_number: u32, new_content: &str) -> TextReplacement {
        TextReplacement {
            start_line: line_number,
            start_column: 1,
            end_line: line_number,
            end_column: u32::MAX,
            replacement_text: new_content.to_string(),
        }
    }

    /// Generate replacement for wrapping code with additional statements
    pub fn wrap_with_statements(
        &self,
        start_line: u32,
        start_column: u32,
        end_line: u32,
        end_column: u32,
        prefix: &str,
        suffix: &str,
    ) -> TextReplacement {
        TextReplacement {
            start_line,
            start_column,
            end_line,
            end_column,
            replacement_text: format!("{}{}{}", prefix, "ORIGINAL_CODE", suffix),
        }
    }

    /// Generate replacement for adding require statement
    pub fn add_require_statement(&self, line_number: u32, condition: &str, message: &str) -> TextReplacement {
        let require_stmt = format!("        require({}, \"{}\");", condition, message);
        self.add_line_before(line_number, &require_stmt)
    }

    /// Generate replacement for adding modifier to function
    pub fn add_modifier_to_function(&self, function_line: u32, modifier_name: &str) -> Result<TextReplacement> {
        // This would need more sophisticated parsing to find the right place to insert the modifier
        // For now, provide a simple implementation
        Ok(TextReplacement {
            start_line: function_line,
            start_column: 1,
            end_line: function_line,
            end_column: 1,
            replacement_text: format!("    {} ", modifier_name), // Add modifier before function signature
        })
    }

    /// Generate replacement for adding import statement
    pub fn add_import_statement(&self, import_statement: &str) -> TextReplacement {
        TextReplacement {
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: 1,
            replacement_text: format!("{}\n", import_statement),
        }
    }

    /// Generate replacement for updating pragma version
    pub fn update_pragma_version(&self, new_version: &str) -> Result<TextReplacement> {
        // Find and replace pragma solidity version
        Ok(TextReplacement {
            start_line: 1, // Typically on first few lines
            start_column: 1,
            end_line: 1,
            end_column: u32::MAX,
            replacement_text: format!("pragma solidity {};", new_version),
        })
    }

    /// Find and replace using regex patterns
    pub fn regex_replace(&mut self, source: &str, pattern: &str, replacement: &str) -> Result<String> {
        let regex = self.get_or_compile_regex(pattern)?;
        Ok(regex.replace_all(source, replacement).to_string())
    }

    /// Find all matches of a pattern and generate replacements
    pub fn find_and_replace_all(&mut self, source: &str, pattern: &str, replacement: &str) -> Result<Vec<TextReplacement>> {
        let regex = self.get_or_compile_regex(pattern)?;
        let mut replacements = Vec::new();

        let lines: Vec<&str> = source.lines().collect();

        for (line_idx, line) in lines.iter().enumerate() {
            for mat in regex.find_iter(line) {
                let replacement = TextReplacement {
                    start_line: (line_idx + 1) as u32,
                    start_column: (mat.start() + 1) as u32,
                    end_line: (line_idx + 1) as u32,
                    end_column: (mat.end() + 1) as u32,
                    replacement_text: replacement.to_string(),
                };
                replacements.push(replacement);
            }
        }

        Ok(replacements)
    }

    /// Generate replacements for reordering expressions (e.g., division before multiplication)
    pub fn reorder_expression(&self, line: u32, _old_expression: &str, new_expression: &str) -> TextReplacement {
        TextReplacement {
            start_line: line,
            start_column: 1,
            end_line: line,
            end_column: u32::MAX,
            replacement_text: new_expression.to_string(),
        }
    }

    /// Apply a single replacement to the lines
    fn apply_single_replacement(&self, lines: &mut Vec<String>, replacement: &TextReplacement) -> Result<()> {
        let start_line_idx = (replacement.start_line as usize).saturating_sub(1);
        let end_line_idx = (replacement.end_line as usize).saturating_sub(1);

        if start_line_idx >= lines.len() {
            return Ok(());
        }

        if start_line_idx == end_line_idx {
            // Single line replacement
            self.apply_single_line_replacement(lines, start_line_idx, replacement)?;
        } else {
            // Multi-line replacement
            self.apply_multi_line_replacement(lines, start_line_idx, end_line_idx, replacement)?;
        }

        Ok(())
    }

    /// Apply replacement within a single line
    fn apply_single_line_replacement(
        &self,
        lines: &mut Vec<String>,
        line_idx: usize,
        replacement: &TextReplacement,
    ) -> Result<()> {
        if line_idx >= lines.len() {
            return Ok(());
        }

        let line = &lines[line_idx];
        let start_col = if replacement.start_column == u32::MAX {
            line.len()
        } else {
            (replacement.start_column as usize).saturating_sub(1).min(line.len())
        };

        let end_col = if replacement.end_column == u32::MAX {
            line.len()
        } else {
            (replacement.end_column as usize).saturating_sub(1).min(line.len())
        };

        if start_col <= end_col && end_col <= line.len() {
            let new_line = format!(
                "{}{}{}",
                &line[..start_col],
                replacement.replacement_text,
                &line[end_col..]
            );
            lines[line_idx] = new_line;
        }

        Ok(())
    }

    /// Apply replacement across multiple lines
    fn apply_multi_line_replacement(
        &self,
        lines: &mut Vec<String>,
        start_line_idx: usize,
        end_line_idx: usize,
        replacement: &TextReplacement,
    ) -> Result<()> {
        if start_line_idx >= lines.len() || end_line_idx >= lines.len() {
            return Ok(());
        }

        let start_line = &lines[start_line_idx];
        let end_line = &lines[end_line_idx];

        let start_col = if replacement.start_column == u32::MAX {
            start_line.len()
        } else {
            (replacement.start_column as usize).saturating_sub(1).min(start_line.len())
        };

        let end_col = if replacement.end_column == u32::MAX {
            end_line.len()
        } else {
            (replacement.end_column as usize).saturating_sub(1).min(end_line.len())
        };

        // Create the new content
        let new_content = format!(
            "{}{}{}",
            &start_line[..start_col],
            replacement.replacement_text,
            &end_line[end_col..]
        );

        // Split the new content into lines
        let new_lines: Vec<String> = new_content.lines().map(|s| s.to_string()).collect();

        // Replace the range with new lines
        lines.splice(start_line_idx..=end_line_idx, new_lines);

        Ok(())
    }

    /// Resolve conflicts between overlapping replacements
    fn resolve_replacement_conflicts(&self, replacements: Vec<TextReplacement>) -> Result<Vec<TextReplacement>> {
        let mut sorted_replacements = replacements;
        // Sort by position (reverse order for easier conflict detection)
        sorted_replacements.sort_by(|a, b| {
            let a_pos = (a.start_line, a.start_column);
            let b_pos = (b.start_line, b.start_column);
            b_pos.cmp(&a_pos)
        });

        let mut non_conflicting = Vec::new();
        let mut used_ranges = Vec::new();

        for replacement in sorted_replacements {
            let range = (replacement.start_line, replacement.start_column, replacement.end_line, replacement.end_column);

            // Check for conflicts with already selected replacements
            let mut conflicts = false;
            for used_range in &used_ranges {
                if self.ranges_overlap(&range, used_range) {
                    conflicts = true;
                    break;
                }
            }

            if !conflicts {
                used_ranges.push(range);
                non_conflicting.push(replacement);
            }
        }

        // Restore original order
        non_conflicting.sort_by(|a, b| {
            let a_pos = (a.start_line, a.start_column);
            let b_pos = (b.start_line, b.start_column);
            a_pos.cmp(&b_pos)
        });

        Ok(non_conflicting)
    }

    /// Check if two ranges overlap
    fn ranges_overlap(&self, range1: &(u32, u32, u32, u32), range2: &(u32, u32, u32, u32)) -> bool {
        let (start1_line, start1_col, end1_line, end1_col) = *range1;
        let (start2_line, start2_col, end2_line, end2_col) = *range2;

        // Convert to absolute positions for easier comparison
        let start1 = (start1_line, start1_col);
        let end1 = (end1_line, end1_col);
        let start2 = (start2_line, start2_col);
        let end2 = (end2_line, end2_col);

        // Check if ranges overlap
        !(end1 <= start2 || end2 <= start1)
    }

    /// Get or compile a regex pattern
    fn get_or_compile_regex(&mut self, pattern: &str) -> Result<&Regex> {
        if !self.regex_cache.contains_key(pattern) {
            let regex = Regex::new(pattern)
                .with_context(|| format!("Invalid regex pattern: {}", pattern))?;
            self.regex_cache.insert(pattern.to_string(), regex);
        }

        Ok(self.regex_cache.get(pattern).unwrap())
    }
}

impl Default for ReplacementEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility functions for common replacement patterns
pub mod patterns {
    use super::*;

    /// Generate replacement for adding access control check
    pub fn add_access_control_check(line_number: u32, owner_variable: &str) -> TextReplacement {
        let require_stmt = format!("        require(msg.sender == {}, \"Not authorized\");", owner_variable);
        TextReplacement {
            start_line: line_number,
            start_column: 1,
            end_line: line_number,
            end_column: 1,
            replacement_text: format!("{}\n", require_stmt),
        }
    }

    /// Generate replacement for adding zero address check
    pub fn add_zero_address_check(line_number: u32, address_variable: &str) -> TextReplacement {
        let require_stmt = format!("        require({} != address(0), \"Zero address not allowed\");", address_variable);
        TextReplacement {
            start_line: line_number,
            start_column: 1,
            end_line: line_number,
            end_column: 1,
            replacement_text: format!("{}\n", require_stmt),
        }
    }

    /// Generate replacement for adding reentrancy guard
    pub fn add_reentrancy_guard(function_start_line: u32, function_end_line: u32) -> Vec<TextReplacement> {
        vec![
            // Add at the beginning of function
            TextReplacement {
                start_line: function_start_line + 1,
                start_column: 1,
                end_line: function_start_line + 1,
                end_column: 1,
                replacement_text: "        require(!locked, \"Reentrancy guard\");\n        locked = true;\n".to_string(),
            },
            // Add at the end of function
            TextReplacement {
                start_line: function_end_line,
                start_column: 1,
                end_line: function_end_line,
                end_column: 1,
                replacement_text: "        locked = false;\n".to_string(),
            },
        ]
    }

    /// Generate replacement for reordering division and multiplication
    pub fn reorder_division_multiplication(
        line_number: u32,
        start_col: u32,
        end_col: u32,
        original_expr: &str,
    ) -> Result<TextReplacement> {
        // Simple pattern matching for a / b * c -> a * c / b
        let regex = Regex::new(r"(\w+)\s*/\s*(\w+)\s*\*\s*(\w+)")
            .context("Failed to compile division reorder regex")?;

        if let Some(captures) = regex.captures(original_expr) {
            let a = &captures[1];
            let b = &captures[2];
            let c = &captures[3];
            let reordered = format!("{} * {} / {}", a, c, b);

            Ok(TextReplacement {
                start_line: line_number,
                start_column: start_col,
                end_line: line_number,
                end_column: end_col,
                replacement_text: reordered,
            })
        } else {
            Ok(TextReplacement {
                start_line: line_number,
                start_column: start_col,
                end_line: line_number,
                end_column: end_col,
                replacement_text: format!("/* TODO: Reorder to avoid precision loss */ {}", original_expr),
            })
        }
    }

    /// Generate replacement for adding SafeMath usage
    pub fn add_safemath_usage(line_number: u32, operation: &str, left: &str, right: &str) -> TextReplacement {
        let safe_operation = match operation {
            "+" => format!("{}.add({})", left, right),
            "-" => format!("{}.sub({})", left, right),
            "*" => format!("{}.mul({})", left, right),
            "/" => format!("{}.div({})", left, right),
            _ => format!("/* TODO: SafeMath for {} {} {} */", left, operation, right),
        };

        TextReplacement {
            start_line: line_number,
            start_column: 1,
            end_line: line_number,
            end_column: u32::MAX,
            replacement_text: safe_operation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_line_replacement() {
        let mut engine = ReplacementEngine::new();
        let source = "line 1\nline 2\nline 3";

        let replacement = TextReplacement {
            start_line: 2,
            start_column: 1,
            end_line: 2,
            end_column: 6,
            replacement_text: "NEW".to_string(),
        };

        let result = engine.apply_replacements(source, &[replacement]).unwrap();
        assert_eq!(result, "line 1\nNEW2\nline 3");
    }

    #[test]
    fn test_multiple_replacements() {
        let mut engine = ReplacementEngine::new();
        let source = "line 1\nline 2\nline 3";

        let replacements = vec![
            TextReplacement {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 4,
                replacement_text: "NEW1".to_string(),
            },
            TextReplacement {
                start_line: 3,
                start_column: 1,
                end_line: 3,
                end_column: 4,
                replacement_text: "NEW3".to_string(),
            },
        ];

        let result = engine.apply_replacements(source, &replacements).unwrap();
        assert_eq!(result, "NEW1e 1\nline 2\nNEW3e 3");
    }

    #[test]
    fn test_add_line_helpers() {
        let engine = ReplacementEngine::new();

        let add_after = engine.add_line_after(2, "    new line content");
        assert_eq!(add_after.start_line, 2);
        assert_eq!(add_after.replacement_text, "\n    new line content");

        let add_before = engine.add_line_before(2, "    new line content");
        assert_eq!(add_before.start_line, 2);
        assert_eq!(add_before.replacement_text, "    new line content\n");
    }
}
