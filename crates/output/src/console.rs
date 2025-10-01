use anyhow::Result;
use console::{style, Term, Color};
use crossterm::tty::IsTty;
use std::collections::HashMap;
use std::io;
use detectors::types::{Finding, AnalysisContext, Severity};

/// Console output formatter with color support
#[derive(Debug)]
pub struct ConsoleFormatter {
    config: ConsoleConfig,
    term: Term,
}

/// Configuration for console output
#[derive(Debug, Clone)]
pub struct ConsoleConfig {
    pub color_mode: ColorMode,
    pub output_level: OutputLevel,
    pub show_code_snippets: bool,
    pub show_fix_suggestions: bool,
}

/// Color mode configuration
#[derive(Debug, Clone, PartialEq)]
pub enum ColorMode {
    /// Always use colors
    Always,
    /// Never use colors
    Never,
    /// Auto-detect TTY support
    Auto,
}

/// Output verbosity level
#[derive(Debug, Clone, PartialEq)]
pub enum OutputLevel {
    /// Only show errors (high/critical severity)
    Errors,
    /// Show errors and warnings (medium+ severity)
    Warnings,
    /// Show all findings
    All,
}

impl Default for ConsoleConfig {
    fn default() -> Self {
        Self {
            color_mode: ColorMode::Auto,
            output_level: OutputLevel::All,
            show_code_snippets: false,
            show_fix_suggestions: false,
        }
    }
}

impl ConsoleFormatter {
    /// Create a new console formatter
    pub fn new(config: ConsoleConfig) -> Result<Self> {
        let term = Term::stdout();

        Ok(Self {
            config,
            term,
        })
    }

    /// Format findings without context (simplified)
    pub fn format_simple(&self, findings: &[Finding]) -> Result<String> {
        let filtered_findings = self.filter_findings_by_level(findings);

        if filtered_findings.is_empty() {
            return Ok(self.format_no_issues_message());
        }

        let mut output = Vec::new();
        output.push(self.format_header(&filtered_findings));

        for finding in &filtered_findings {
            output.push(self.format_finding_simple(finding)?);
            output.push(String::new());
        }

        output.push(self.format_summary(&filtered_findings));
        Ok(output.join("\n"))
    }

    /// Format findings for console output
    pub fn format_findings(&self, findings: &[Finding], ctx: &AnalysisContext<'_>) -> Result<String> {
        let filtered_findings = self.filter_findings_by_level(findings);

        if filtered_findings.is_empty() {
            return Ok(self.format_no_issues_message());
        }

        let mut output = Vec::new();

        // Add header
        output.push(self.format_header(&filtered_findings));

        // Format each finding
        for finding in &filtered_findings {
            output.push(self.format_finding(finding, ctx)?);
            output.push(String::new()); // Empty line between findings
        }

        Ok(output.join("\n"))
    }

    /// Format findings with fix suggestions
    pub fn format_findings_with_fixes(&self, findings: &[Finding], ctx: &AnalysisContext<'_>) -> Result<String> {
        let mut config_with_fixes = self.config.clone();
        config_with_fixes.show_fix_suggestions = true;

        let temp_formatter = ConsoleFormatter {
            config: config_with_fixes,
            term: self.term.clone(),
        };

        temp_formatter.format_findings(findings, ctx)
    }

    /// Format findings with summary statistics
    pub fn format_with_summary(&self, findings: &[Finding], ctx: &AnalysisContext<'_>) -> Result<String> {
        let mut output = self.format_findings(findings, ctx)?;

        if !findings.is_empty() {
            output.push('\n');
            output.push_str(&self.format_summary(findings));
        }

        Ok(output)
    }

    /// Format a single finding without context (simplified)
    fn format_finding_simple(&self, finding: &Finding) -> Result<String> {
        let mut output = Vec::new();

        let severity_icon = self.get_severity_icon(&finding.severity);
        let severity_color = self.get_severity_color(&finding.severity);

        let header = if self.should_use_colors() {
            format!(
                "{} {} {} {}:{}",
                style(severity_icon).fg(severity_color),
                style(&finding.detector_id.0.as_str()).bold(),
                style(&finding.message).fg(severity_color),
                style(finding.primary_location.line).dim(),
                style(finding.primary_location.column).dim()
            )
        } else {
            format!(
                "{} {} {} {}:{}",
                severity_icon,
                finding.detector_id.0.as_str(),
                finding.message,
                finding.primary_location.line,
                finding.primary_location.column
            )
        };
        output.push(header);

        if let Some(description) = finding.metadata.get("description") {
            let desc_line = if self.should_use_colors() {
                format!("   {}", style(description).dim())
            } else {
                format!("   {}", description)
            };
            output.push(desc_line);
        }

        Ok(output.join("\n"))
    }

    /// Format a single finding
    fn format_finding(&self, finding: &Finding, ctx: &AnalysisContext<'_>) -> Result<String> {
        let mut output = Vec::new();

        // Finding header with severity and location
        let severity_icon = self.get_severity_icon(&finding.severity);
        let severity_color = self.get_severity_color(&finding.severity);

        let header = if self.should_use_colors() {
            format!(
                "{} {} {} {}:{}:{}",
                style(severity_icon).fg(severity_color),
                style(&finding.detector_id.0.as_str()).bold(),
                style(&finding.message).fg(severity_color),
                style(&ctx.file_path).dim(),
                style(finding.primary_location.line).dim(),
                style(finding.primary_location.column).dim()
            )
        } else {
            format!(
                "{} {} {} {}:{}:{}",
                severity_icon,
                finding.detector_id.0.as_str(),
                finding.message,
                ctx.file_path,
                finding.primary_location.line,
                finding.primary_location.column
            )
        };

        output.push(header);

        // Code snippet if enabled
        if self.config.show_code_snippets {
            if let Some(snippet) = self.extract_code_snippet(ctx, finding.primary_location.line, finding.primary_location.column, finding.primary_location.length)? {
                output.push(self.format_code_snippet(&snippet, finding.primary_location.line)?);
            }
        }

        // Fix suggestion if available and enabled
        if self.config.show_fix_suggestions {
            if let Some(fix_suggestion) = &finding.fix_suggestion {
                output.push(self.format_fix_suggestion(fix_suggestion));
            }
        }

        // CWE information if available
        if let Some(&cwe) = finding.cwe_ids.first() {
            let cwe_info = if self.should_use_colors() {
                format!("   {} {}",
                    style("CWE:").dim(),
                    style(format!("CWE-{}", cwe)).dim()
                )
            } else {
                format!("   CWE: CWE-{}", cwe)
            };
            output.push(cwe_info);
        }

        Ok(output.join("\n"))
    }

    /// Format header message
    fn format_header(&self, findings: &[Finding]) -> String {
        let count = findings.len();
        let file_count = 1; // For now, single file analysis

        let header = if count == 1 {
            format!("Found {} issue in {} file:", count, file_count)
        } else {
            format!("Found {} issues in {} file:", count, file_count)
        };

        if self.should_use_colors() {
            style(header).bold().to_string()
        } else {
            header
        }
    }

    /// Format summary statistics
    fn format_summary(&self, findings: &[Finding]) -> String {
        let mut counts = HashMap::new();

        for finding in findings {
            *counts.entry(&finding.severity).or_insert(0) += 1;
        }

        let mut summary_parts = Vec::new();

        // Count by severity
        if let Some(&critical_count) = counts.get(&Severity::Critical) {
            if critical_count > 0 {
                let text = if self.should_use_colors() {
                    style(format!("{} critical", critical_count)).fg(Color::Red).bold().to_string()
                } else {
                    format!("{} critical", critical_count)
                };
                summary_parts.push(text);
            }
        }

        if let Some(&high_count) = counts.get(&Severity::High) {
            if high_count > 0 {
                let text = if self.should_use_colors() {
                    style(format!("{} high", high_count)).fg(Color::Red).to_string()
                } else {
                    format!("{} high", high_count)
                };
                summary_parts.push(text);
            }
        }

        if let Some(&medium_count) = counts.get(&Severity::Medium) {
            if medium_count > 0 {
                let text = if self.should_use_colors() {
                    style(format!("{} medium", medium_count)).fg(Color::Yellow).to_string()
                } else {
                    format!("{} medium", medium_count)
                };
                summary_parts.push(text);
            }
        }

        if let Some(&low_count) = counts.get(&Severity::Low) {
            if low_count > 0 {
                let text = if self.should_use_colors() {
                    style(format!("{} low", low_count)).fg(Color::Cyan).to_string()
                } else {
                    format!("{} low", low_count)
                };
                summary_parts.push(text);
            }
        }

        let summary_line = if summary_parts.is_empty() {
            "No issues found".to_string()
        } else {
            format!("Summary: {}", summary_parts.join(", "))
        };

        if self.should_use_colors() {
            format!("\n{}", style(summary_line).bold())
        } else {
            format!("\n{}", summary_line)
        }
    }

    /// Format no issues message
    fn format_no_issues_message(&self) -> String {
        let message = "No security issues found! ✓";

        if self.should_use_colors() {
            style(message).fg(Color::Green).bold().to_string()
        } else {
            message.to_string()
        }
    }

    /// Format code snippet with line numbers
    fn format_code_snippet(&self, snippet: &CodeSnippet, highlight_line: u32) -> Result<String> {
        let mut output = Vec::new();

        if self.should_use_colors() {
            output.push(style("   ╭─────").dim().to_string());
        } else {
            output.push("   ┌─────".to_string());
        }

        for (line_num, line_content) in &snippet.lines {
            let line_num_str = format!("{:4}", line_num);
            let separator = if *line_num == highlight_line { "►" } else { "│" };

            let formatted_line = if self.should_use_colors() {
                if *line_num == highlight_line {
                    format!("{} {} {} {}",
                        style("   ").dim(),
                        style(&line_num_str).dim(),
                        style(separator).fg(Color::Red).bold(),
                        style(line_content).bold()
                    )
                } else {
                    format!("{} {} {} {}",
                        style("   ").dim(),
                        style(&line_num_str).dim(),
                        style(separator).dim(),
                        line_content
                    )
                }
            } else {
                format!("   {} {} {}", line_num_str, separator, line_content)
            };

            output.push(formatted_line);
        }

        if self.should_use_colors() {
            output.push(style("   ╰─────").dim().to_string());
        } else {
            output.push("   └─────".to_string());
        }

        Ok(output.join("\n"))
    }

    /// Format fix suggestion
    fn format_fix_suggestion(&self, fix_suggestion: &str) -> String {
        let icon = "💡";
        let prefix = "Fix:";

        if self.should_use_colors() {
            format!("   {} {} {}",
                icon,
                style(prefix).fg(Color::Blue).bold(),
                style(fix_suggestion).dim()
            )
        } else {
            format!("   {} {} {}", icon, prefix, fix_suggestion)
        }
    }

    /// Extract code snippet around the finding
    fn extract_code_snippet(&self, ctx: &AnalysisContext<'_>, line: u32, _column: u32, _length: u32) -> Result<Option<CodeSnippet>> {
        let lines: Vec<&str> = ctx.source.lines().collect();
        let total_lines = lines.len() as u32;

        if line == 0 || line > total_lines {
            return Ok(None);
        }

        let context_lines = 2;
        let start_line = line.saturating_sub(context_lines).max(1);
        let end_line = (line + context_lines).min(total_lines);

        let mut snippet_lines = Vec::new();

        for line_num in start_line..=end_line {
            let line_idx = (line_num - 1) as usize;
            if line_idx < lines.len() {
                snippet_lines.push((line_num, lines[line_idx].to_string()));
            }
        }

        Ok(Some(CodeSnippet {
            lines: snippet_lines,
            highlight_line: line,
        }))
    }

    /// Filter findings based on output level
    fn filter_findings_by_level(&self, findings: &[Finding]) -> Vec<Finding> {
        findings.iter().filter(|finding| {
            match self.config.output_level {
                OutputLevel::Errors => matches!(finding.severity, Severity::Critical | Severity::High),
                OutputLevel::Warnings => !matches!(finding.severity, Severity::Low | Severity::Info),
                OutputLevel::All => true,
            }
        }).cloned().collect()
    }

    /// Get severity icon
    fn get_severity_icon(&self, severity: &Severity) -> &'static str {
        match severity {
            Severity::Critical => "●",
            Severity::High => "●",
            Severity::Medium => "●",
            Severity::Low => "●",
            Severity::Info => "●",
        }
    }

    /// Get severity color
    fn get_severity_color(&self, severity: &Severity) -> Color {
        match severity {
            Severity::Critical => Color::Red,
            Severity::High => Color::Red,
            Severity::Medium => Color::Yellow,
            Severity::Low => Color::Cyan,
            Severity::Info => Color::Blue,
        }
    }

    /// Check if colors should be used
    fn should_use_colors(&self) -> bool {
        match self.config.color_mode {
            ColorMode::Always => true,
            ColorMode::Never => false,
            ColorMode::Auto => {
                // Check if stdout is a TTY and supports colors
                io::stdout().is_tty() && self.term.features().colors_supported()
            }
        }
    }
}

/// Code snippet with line numbers
#[derive(Debug)]
struct CodeSnippet {
    lines: Vec<(u32, String)>,
    highlight_line: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use detectors::types::DetectorId;

    fn create_test_finding() -> Finding {
        Finding {
            detector_id: DetectorId::new("test-detector"),
            message: "Test vulnerability".to_string(),
            severity: Severity::High,
            line: 10,
            column: 5,
            length: 15,
            cwe: Some(476),
            fix_suggestion: Some("Fix this issue".to_string()),
        }
    }

    fn create_test_context() -> AnalysisContext<'static> {
        let source = "line 1\nline 2\nvulnerable line 10\nline 4\nline 5";
        AnalysisContext {
            source_code: source.to_string(),
            file_path: "test.sol".to_string(),
            // ... other fields would be properly initialized in real usage
        }
    }

    #[test]
    fn test_no_colors_output() {
        let config = ConsoleConfig {
            color_mode: ColorMode::Never,
            output_level: OutputLevel::All,
            show_code_snippets: false,
            show_fix_suggestions: false,
        };

        let formatter = ConsoleFormatter::new(config).unwrap();
        let finding = create_test_finding();
        let ctx = create_test_context();

        let output = formatter.format_findings(&[finding], &ctx).unwrap();

        // Should not contain ANSI color codes
        assert!(!output.contains("\x1b["));
        assert!(output.contains("test-detector"));
        assert!(output.contains("Test vulnerability"));
    }

    #[test]
    fn test_severity_filtering() {
        let config = ConsoleConfig {
            color_mode: ColorMode::Never,
            output_level: OutputLevel::Errors,
            show_code_snippets: false,
            show_fix_suggestions: false,
        };

        let formatter = ConsoleFormatter::new(config).unwrap();

        let high_finding = Finding {
            severity: Severity::High,
            ..create_test_finding()
        };

        let low_finding = Finding {
            severity: Severity::Low,
            ..create_test_finding()
        };

        let ctx = create_test_context();
        let findings = vec![high_finding, low_finding];

        let output = formatter.format_findings(&findings, &ctx).unwrap();

        // Should only contain high severity finding
        assert!(output.contains("Test vulnerability"));
        // Should contain only one finding (the high severity one)
        assert_eq!(output.matches("test-detector").count(), 1);
    }

    #[test]
    fn test_code_snippet_extraction() {
        let config = ConsoleConfig {
            color_mode: ColorMode::Never,
            output_level: OutputLevel::All,
            show_code_snippets: true,
            show_fix_suggestions: false,
        };

        let formatter = ConsoleFormatter::new(config).unwrap();
        let finding = create_test_finding();
        let ctx = create_test_context();

        let output = formatter.format_findings(&[finding], &ctx).unwrap();

        assert!(output.contains("vulnerable line 10"));
        assert!(output.contains("10 ►")); // Highlight marker
    }

    #[test]
    fn test_fix_suggestion_display() {
        let config = ConsoleConfig {
            color_mode: ColorMode::Never,
            output_level: OutputLevel::All,
            show_code_snippets: false,
            show_fix_suggestions: true,
        };

        let formatter = ConsoleFormatter::new(config).unwrap();
        let finding = create_test_finding();
        let ctx = create_test_context();

        let output = formatter.format_findings(&[finding], &ctx).unwrap();

        assert!(output.contains("Fix: Fix this issue"));
        assert!(output.contains("💡"));
    }
}
