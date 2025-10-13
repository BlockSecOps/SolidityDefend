pub mod access_control;
pub mod replacements;

pub use replacements::ReplacementEngine;

use anyhow::Result;
use detectors::types::{AnalysisContext, Finding};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// A text replacement operation for fixing code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextReplacement {
    /// Starting line number (1-based)
    pub start_line: u32,
    /// Starting column number (1-based)
    pub start_column: u32,
    /// Ending line number (1-based)
    pub end_line: u32,
    /// Ending column number (1-based)
    pub end_column: u32,
    /// The text to replace the selected range with
    pub replacement_text: String,
}

/// A complete fix suggestion for a vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixSuggestion {
    /// Unique identifier for this fix
    pub id: String,
    /// Human-readable description of what this fix does
    pub description: String,
    /// Detailed explanation of why this fix works
    pub explanation: String,
    /// Confidence level from 0.0 to 1.0
    pub confidence: f32,
    /// List of text replacements to apply
    pub replacements: Vec<TextReplacement>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Engine for generating and applying automatic fixes
pub struct FixEngine {
    /// Registered fix generators by detector ID
    generators: HashMap<String, Arc<dyn FixGenerator>>,
}

/// Trait for generating fixes for specific types of vulnerabilities
pub trait FixGenerator: Send + Sync {
    /// Generate one or more fix suggestions for a finding
    fn generate_fixes(
        &self,
        finding: &Finding,
        ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<FixSuggestion>>;

    /// Get the detector IDs this generator can handle
    fn supported_detectors(&self) -> Vec<String>;

    /// Get the priority of this generator (higher = preferred)
    fn priority(&self) -> i32 {
        0
    }
}

impl FixEngine {
    /// Create a new fix engine
    pub fn new() -> Result<Self> {
        let mut engine = Self {
            generators: HashMap::new(),
        };

        // Register built-in generators
        engine.register_built_in_generators()?;

        Ok(engine)
    }

    /// Register a fix generator
    pub fn register_generator<G: FixGenerator + 'static>(&mut self, generator: G) {
        let detector_ids = generator.supported_detectors();
        let arc_generator = Arc::new(generator);

        for detector_id in detector_ids {
            self.generators.insert(detector_id, arc_generator.clone());
        }
    }

    /// Generate fix suggestions for a finding
    pub fn generate_fixes(
        &self,
        finding: &Finding,
        ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<FixSuggestion>> {
        let detector_id = finding.detector_id.0.as_str();

        if let Some(generator) = self.generators.get(detector_id) {
            let mut fixes = generator.generate_fixes(finding, ctx)?;

            // Sort by confidence (highest first)
            fixes.sort_by(|a, b| {
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

            Ok(fixes)
        } else {
            // No specific generator found, try to generate generic fix
            self.generate_generic_fix(finding, ctx)
        }
    }

    /// Generate combined fixes for multiple findings, handling conflicts
    pub fn generate_combined_fixes(
        &self,
        findings: &[Finding],
        ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<FixSuggestion>> {
        let mut all_fixes = Vec::new();

        // Generate fixes for each finding
        for finding in findings {
            let fixes = self.generate_fixes(finding, ctx)?;
            all_fixes.extend(fixes);
        }

        // Resolve conflicts and merge compatible fixes
        self.resolve_conflicts(all_fixes)
    }

    /// Apply a fix suggestion to source code
    pub fn apply_fix(&self, source: &str, fix: &FixSuggestion) -> Result<String> {
        self.apply_replacements(source, &fix.replacements)
    }

    /// Apply multiple fixes to source code
    pub fn apply_multiple_fixes(&self, source: &str, fixes: &[FixSuggestion]) -> Result<String> {
        let current_source = source.to_string();

        // Sort replacements by position (reverse order to avoid offset issues)
        let mut all_replacements = Vec::new();
        for fix in fixes {
            all_replacements.extend(fix.replacements.clone());
        }

        // Sort by position (end first to avoid shifting issues)
        all_replacements.sort_by(|a, b| {
            let a_pos = (a.start_line, a.start_column);
            let b_pos = (b.start_line, b.start_column);
            b_pos.cmp(&a_pos)
        });

        self.apply_replacements(&current_source, &all_replacements)
    }

    /// Register built-in fix generators
    fn register_built_in_generators(&mut self) -> Result<()> {
        // Register generators for common vulnerability types
        self.register_generator(ReentrancyFixGenerator::new());
        self.register_generator(AccessControlFixGenerator::new());
        self.register_generator(ZeroAddressFixGenerator::new());
        self.register_generator(IntegerOverflowFixGenerator::new());
        self.register_generator(DivisionOrderFixGenerator::new());

        Ok(())
    }

    /// Generate a generic fix suggestion when no specific generator is available
    fn generate_generic_fix(
        &self,
        finding: &Finding,
        _ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<FixSuggestion>> {
        let fix = FixSuggestion {
            id: format!("generic-fix-{}", finding.detector_id.0.as_str()),
            description: format!(
                "Review and fix {} vulnerability",
                finding.detector_id.0.as_str()
            ),
            explanation: format!(
                "This {} vulnerability requires manual review. {}",
                finding.detector_id.0.as_str(),
                finding.fix_suggestion.as_deref().unwrap_or(
                    "Consider the security implications and implement appropriate safeguards."
                )
            ),
            confidence: 0.3,          // Low confidence for generic fixes
            replacements: Vec::new(), // No automatic replacements for generic fixes
            metadata: HashMap::from([
                ("type".to_string(), "manual-review".to_string()),
                (
                    "detector".to_string(),
                    finding.detector_id.0.as_str().to_string(),
                ),
            ]),
        };

        Ok(vec![fix])
    }

    /// Apply text replacements to source code
    fn apply_replacements(&self, source: &str, replacements: &[TextReplacement]) -> Result<String> {
        let lines: Vec<&str> = source.lines().collect();
        let mut result_lines: Vec<String> = lines.iter().map(|s| s.to_string()).collect();

        // Apply replacements in reverse order to avoid offset issues
        for replacement in replacements {
            let start_line_idx = (replacement.start_line as usize).saturating_sub(1);
            let end_line_idx = (replacement.end_line as usize).saturating_sub(1);

            if start_line_idx >= result_lines.len() || end_line_idx >= result_lines.len() {
                continue; // Skip invalid replacements
            }

            if start_line_idx == end_line_idx {
                // Single line replacement
                let line = &result_lines[start_line_idx];
                let start_col = (replacement.start_column as usize).saturating_sub(1);
                let end_col = (replacement.end_column as usize).saturating_sub(1);

                if start_col <= line.len() && end_col <= line.len() && start_col <= end_col {
                    let new_line = format!(
                        "{}{}{}",
                        &line[..start_col],
                        replacement.replacement_text,
                        &line[end_col..]
                    );
                    result_lines[start_line_idx] = new_line;
                }
            } else {
                // Multi-line replacement
                let start_line = &result_lines[start_line_idx];
                let end_line = &result_lines[end_line_idx];
                let start_col = (replacement.start_column as usize).saturating_sub(1);
                let end_col = (replacement.end_column as usize).saturating_sub(1);

                if start_col <= start_line.len() && end_col <= end_line.len() {
                    let new_line = format!(
                        "{}{}{}",
                        &start_line[..start_col],
                        replacement.replacement_text,
                        &end_line[end_col..]
                    );

                    // Replace the range with a single line
                    result_lines.splice(start_line_idx..=end_line_idx, vec![new_line]);
                }
            }
        }

        Ok(result_lines.join("\n"))
    }

    /// Resolve conflicts between multiple fixes
    fn resolve_conflicts(&self, fixes: Vec<FixSuggestion>) -> Result<Vec<FixSuggestion>> {
        // For now, implement a simple conflict resolution that removes overlapping fixes
        // In a more sophisticated implementation, this would attempt to merge compatible fixes

        let mut resolved_fixes = Vec::new();
        let mut used_ranges = Vec::new();

        // Sort fixes by confidence (highest first)
        let mut sorted_fixes = fixes;
        sorted_fixes.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        for fix in sorted_fixes {
            let mut conflicts = false;

            // Check if this fix conflicts with any already selected fix
            for replacement in &fix.replacements {
                let range = (
                    replacement.start_line,
                    replacement.start_column,
                    replacement.end_line,
                    replacement.end_column,
                );

                for used_range in &used_ranges {
                    if ranges_overlap(&range, used_range) {
                        conflicts = true;
                        break;
                    }
                }

                if conflicts {
                    break;
                }
            }

            if !conflicts {
                // Add this fix's ranges to the used ranges
                for replacement in &fix.replacements {
                    used_ranges.push((
                        replacement.start_line,
                        replacement.start_column,
                        replacement.end_line,
                        replacement.end_column,
                    ));
                }
                resolved_fixes.push(fix);
            }
        }

        Ok(resolved_fixes)
    }
}

/// Check if two text ranges overlap
fn ranges_overlap(range1: &(u32, u32, u32, u32), range2: &(u32, u32, u32, u32)) -> bool {
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

// Built-in fix generators for common vulnerability types

/// Fix generator for reentrancy vulnerabilities
struct ReentrancyFixGenerator;

impl ReentrancyFixGenerator {
    fn new() -> Self {
        Self
    }
}

impl FixGenerator for ReentrancyFixGenerator {
    fn generate_fixes(
        &self,
        _finding: &Finding,
        _ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<FixSuggestion>> {
        let fix = FixSuggestion {
            id: "reentrancy-checks-effects-interactions".to_string(),
            description: "Apply checks-effects-interactions pattern".to_string(),
            explanation: "Move all state changes before external calls to prevent reentrancy attacks. This ensures that if the external call is reentered, the state is already updated.".to_string(),
            confidence: 0.8,
            replacements: vec![], // Would be populated based on specific code analysis
            metadata: HashMap::from([
                ("pattern".to_string(), "checks-effects-interactions".to_string()),
                ("risk".to_string(), "high".to_string()),
            ]),
        };

        Ok(vec![fix])
    }

    fn supported_detectors(&self) -> Vec<String> {
        vec!["reentrancy".to_string()]
    }

    fn priority(&self) -> i32 {
        100
    }
}

/// Fix generator for access control vulnerabilities
struct AccessControlFixGenerator;

impl AccessControlFixGenerator {
    fn new() -> Self {
        Self
    }
}

impl FixGenerator for AccessControlFixGenerator {
    fn generate_fixes(
        &self,
        _finding: &Finding,
        _ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<FixSuggestion>> {
        let fix = FixSuggestion {
            id: "access-control-onlyowner".to_string(),
            description: "Add onlyOwner access control modifier".to_string(),
            explanation: "Add a modifier to restrict function access to authorized users only. This prevents unauthorized users from calling sensitive functions.".to_string(),
            confidence: 0.9,
            replacements: vec![], // Would be populated based on specific code analysis
            metadata: HashMap::from([
                ("modifier".to_string(), "onlyOwner".to_string()),
                ("type".to_string(), "access-control".to_string()),
            ]),
        };

        Ok(vec![fix])
    }

    fn supported_detectors(&self) -> Vec<String> {
        vec!["missing-access-control".to_string()]
    }

    fn priority(&self) -> i32 {
        90
    }
}

/// Fix generator for zero address vulnerabilities
struct ZeroAddressFixGenerator;

impl ZeroAddressFixGenerator {
    fn new() -> Self {
        Self
    }
}

impl FixGenerator for ZeroAddressFixGenerator {
    fn generate_fixes(
        &self,
        _finding: &Finding,
        _ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<FixSuggestion>> {
        let fix = FixSuggestion {
            id: "zero-address-check".to_string(),
            description: "Add zero address validation".to_string(),
            explanation: "Add a require statement to check that the address parameter is not address(0). This prevents accidental loss of funds or broken contract state.".to_string(),
            confidence: 0.95,
            replacements: vec![], // Would be populated based on specific code analysis
            metadata: HashMap::from([
                ("check".to_string(), "require(addr != address(0))".to_string()),
                ("type".to_string(), "validation".to_string()),
            ]),
        };

        Ok(vec![fix])
    }

    fn supported_detectors(&self) -> Vec<String> {
        vec!["missing-zero-address-check".to_string()]
    }

    fn priority(&self) -> i32 {
        95
    }
}

/// Fix generator for integer overflow vulnerabilities
struct IntegerOverflowFixGenerator;

impl IntegerOverflowFixGenerator {
    fn new() -> Self {
        Self
    }
}

impl FixGenerator for IntegerOverflowFixGenerator {
    fn generate_fixes(
        &self,
        _finding: &Finding,
        _ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<FixSuggestion>> {
        let solidity_08_fix = FixSuggestion {
            id: "overflow-solidity-08".to_string(),
            description: "Upgrade to Solidity ^0.8.0".to_string(),
            explanation: "Solidity 0.8.0 and later versions include built-in overflow protection. This is the recommended solution for new contracts.".to_string(),
            confidence: 0.9,
            replacements: vec![], // Would be populated with pragma update
            metadata: HashMap::from([
                ("solution".to_string(), "pragma-upgrade".to_string()),
                ("version".to_string(), "^0.8.0".to_string()),
            ]),
        };

        let safemath_fix = FixSuggestion {
            id: "overflow-safemath".to_string(),
            description: "Use SafeMath library".to_string(),
            explanation: "Import and use OpenZeppelin's SafeMath library for arithmetic operations. This provides runtime overflow protection for older Solidity versions.".to_string(),
            confidence: 0.7,
            replacements: vec![], // Would be populated with SafeMath usage
            metadata: HashMap::from([
                ("solution".to_string(), "safemath".to_string()),
                ("library".to_string(), "OpenZeppelin".to_string()),
            ]),
        };

        Ok(vec![solidity_08_fix, safemath_fix])
    }

    fn supported_detectors(&self) -> Vec<String> {
        vec![
            "integer-overflow".to_string(),
            "integer-underflow".to_string(),
        ]
    }

    fn priority(&self) -> i32 {
        85
    }
}

/// Fix generator for division before multiplication vulnerabilities
struct DivisionOrderFixGenerator;

impl DivisionOrderFixGenerator {
    fn new() -> Self {
        Self
    }
}

impl FixGenerator for DivisionOrderFixGenerator {
    fn generate_fixes(
        &self,
        _finding: &Finding,
        _ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<FixSuggestion>> {
        let fix = FixSuggestion {
            id: "division-order-reorder".to_string(),
            description: "Reorder operations: multiplication before division".to_string(),
            explanation: "Perform multiplication before division to minimize precision loss. This ensures that intermediate results are as large as possible before division truncates them.".to_string(),
            confidence: 0.85,
            replacements: vec![], // Would be populated based on specific expression analysis
            metadata: HashMap::from([
                ("pattern".to_string(), "multiply-before-divide".to_string()),
                ("issue".to_string(), "precision-loss".to_string()),
            ]),
        };

        Ok(vec![fix])
    }

    fn supported_detectors(&self) -> Vec<String> {
        vec!["division-before-multiplication".to_string()]
    }

    fn priority(&self) -> i32 {
        80
    }
}
