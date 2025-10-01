pub mod console;
pub mod json;
pub mod sarif;

pub use console::{ConsoleFormatter, ConsoleFormatterConfig};
pub use json::{JsonFormatter, JsonOutputBuilder, JsonError};
pub use sarif::{SarifFormatter, SarifFormatterConfig};

use detectors::types::Finding;

/// Unified output formatter that supports multiple formats
#[derive(Debug)]
pub enum OutputFormatter {
    Console(ConsoleFormatter),
    Json(JsonFormatter),
    Sarif(SarifFormatter),
}

impl OutputFormatter {
    /// Create a console formatter
    pub fn console() -> Self {
        Self::Console(ConsoleFormatter::new())
    }

    /// Create a JSON formatter
    pub fn json() -> Self {
        Self::Json(JsonFormatter::new())
    }

    /// Create a SARIF formatter
    pub fn sarif() -> Self {
        Self::Sarif(SarifFormatter::new())
    }

    /// Format findings using the selected formatter
    pub fn format(&self, findings: &[Finding]) -> Result<String, Box<dyn std::error::Error>> {
        match self {
            Self::Console(formatter) => formatter.format(findings).map_err(|e| Box::new(e) as Box<dyn std::error::Error>),
            Self::Json(formatter) => formatter.format(findings).map_err(|e| Box::new(e) as Box<dyn std::error::Error>),
            Self::Sarif(formatter) => formatter.format(findings).map_err(|e| Box::new(e) as Box<dyn std::error::Error>),
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
    Sarif,
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
                let config = ConsoleFormatterConfig {
                    use_colors: self.color_output,
                    show_fix_suggestions: true,
                    show_code_snippets: true,
                    compact_mode: false,
                };
                OutputFormatter::Console(ConsoleFormatter::with_config(config))
            }
            OutputFormat::Json => {
                let formatter = JsonOutputBuilder::new()
                    .with_metadata(self.include_metadata)
                    .with_statistics(self.include_statistics)
                    .with_pretty_print(self.pretty_print)
                    .build();
                OutputFormatter::Json(formatter)
            }
            OutputFormat::Sarif => {
                let config = SarifFormatterConfig {
                    include_fixes: true,
                    include_code_flows: true,
                    include_taxonomies: true,
                    tool_version: env!("CARGO_PKG_VERSION").to_string(),
                };
                OutputFormatter::Sarif(SarifFormatter::with_config(config))
            }
        }
    }
}
