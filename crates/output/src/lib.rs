pub mod console;
pub mod json;

pub use console::{ConsoleFormatter, ConsoleConfig};
pub use json::{JsonFormatter, JsonOutputBuilder, JsonError};

use detectors::types::{Finding, AnalysisContext};

/// Unified output formatter that supports multiple formats
#[derive(Debug)]
pub enum OutputFormatter {
    Console(ConsoleFormatter),
    Json(JsonFormatter),
}

impl OutputFormatter {
    /// Create a console formatter
    pub fn console() -> Self {
        Self::Console(ConsoleFormatter::new(ConsoleConfig::default()).unwrap())
    }

    /// Create a JSON formatter
    pub fn json() -> Self {
        Self::Json(JsonFormatter::new())
    }

    /// Format findings using the selected formatter
    pub fn format(&self, findings: &[Finding]) -> Result<String, anyhow::Error> {
        match self {
            Self::Console(formatter) => formatter.format_simple(findings),
            Self::Json(formatter) => formatter.format(findings).map_err(|e| anyhow::anyhow!("{:?}", e)),
        }
    }

    /// Format findings with full context information
    pub fn format_with_context(&self, findings: &[Finding], ctx: &AnalysisContext<'_>) -> Result<String, anyhow::Error> {
        match self {
            Self::Console(formatter) => formatter.format_findings(findings, ctx),
            Self::Json(formatter) => formatter.format(findings).map_err(|e| anyhow::anyhow!("{:?}", e)),
        }
    }
}

/// Builder for creating output formatters with custom configurations
pub struct OutputFormatterBuilder {
    format_type: OutputFormat,
    pretty_print: bool,
    include_metadata: bool,
    include_statistics: bool,
    color_output: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    Console,
    Json,
}

impl OutputFormatterBuilder {
    pub fn new(format_type: OutputFormat) -> Self {
        Self {
            format_type,
            pretty_print: true,
            include_metadata: true,
            include_statistics: true,
            color_output: true,
        }
    }

    pub fn with_pretty_print(mut self, pretty: bool) -> Self {
        self.pretty_print = pretty;
        self
    }

    pub fn with_metadata(mut self, include: bool) -> Self {
        self.include_metadata = include;
        self
    }

    pub fn with_statistics(mut self, include: bool) -> Self {
        self.include_statistics = include;
        self
    }

    pub fn with_color_output(mut self, color: bool) -> Self {
        self.color_output = color;
        self
    }

    pub fn build(self) -> OutputFormatter {
        match self.format_type {
            OutputFormat::Console => {
                let config = ConsoleConfig {
                    color_mode: if self.color_output { console::ColorMode::Always } else { console::ColorMode::Never },
                    output_level: console::OutputLevel::All,
                    show_code_snippets: true,
                    show_fix_suggestions: true,
                };
                OutputFormatter::Console(ConsoleFormatter::new(config).unwrap())
            }
            OutputFormat::Json => {
                let formatter = JsonOutputBuilder::new()
                    .with_metadata(self.include_metadata)
                    .with_statistics(self.include_statistics)
                    .with_pretty_print(self.pretty_print)
                    .build();
                OutputFormatter::Json(formatter)
            }
        }
    }
}

/// Output manager for handling different output formats and destinations
pub struct OutputManager {
    _formatter: OutputFormatter,
}

impl OutputManager {
    pub fn new() -> Self {
        Self {
            _formatter: OutputFormatter::console(),
        }
    }

    pub fn with_formatter(formatter: OutputFormatter) -> Self {
        Self { _formatter: formatter }
    }

    /// Write findings to stdout with the configured format
    pub fn write_to_stdout(&self, findings: &[Finding], format: OutputFormat) -> anyhow::Result<()> {
        let formatter = match format {
            OutputFormat::Console => OutputFormatter::console(),
            OutputFormat::Json => OutputFormatter::json(),
        };

        let output = formatter.format(findings)?;
        println!("{}", output);
        Ok(())
    }

    /// Write findings to a file with the configured format
    pub fn write_to_file(&self, findings: &[Finding], format: OutputFormat, path: &std::path::Path) -> anyhow::Result<()> {
        let formatter = match format {
            OutputFormat::Console => OutputFormatter::console(),
            OutputFormat::Json => OutputFormatter::json(),
        };

        let output = formatter.format(findings)?;
        std::fs::write(path, output)?;
        Ok(())
    }
}

impl Default for OutputManager {
    fn default() -> Self {
        Self::new()
    }
}
