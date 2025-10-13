pub mod arena;
pub mod error;
pub mod recovery;

use ast::{AstArena, SourceFile};
use std::fs;
use std::path::Path;

pub use arena::ArenaParser;
pub use error::{ParseError, ParseErrors, ParseResult};

/// High-level parser for Solidity source code with arena allocation and error recovery
#[derive(Debug)]
pub struct Parser {
    /// Configuration options for parsing
    enable_recovery: bool,
    max_errors: usize,
}

impl Parser {
    /// Default file ID used by solang-parser for single file parsing
    const DEFAULT_FILE_ID: usize = 0;
    /// Create a new parser with default settings
    pub fn new() -> Self {
        Self {
            enable_recovery: true,
            max_errors: 100,
        }
    }

    /// Create a parser with recovery disabled
    pub fn without_recovery() -> Self {
        Self {
            enable_recovery: false,
            max_errors: 1,
        }
    }

    /// Set maximum number of errors before stopping
    pub fn with_max_errors(mut self, max_errors: usize) -> Self {
        self.max_errors = max_errors;
        self
    }

    /// Enable or disable error recovery
    pub fn with_recovery(mut self, enable_recovery: bool) -> Self {
        self.enable_recovery = enable_recovery;
        self
    }

    /// Parse Solidity source code from a string
    pub fn parse<'arena>(
        &self,
        arena: &'arena AstArena,
        source: &str,
        file_path: &str,
    ) -> Result<SourceFile<'arena>, ParseErrors> {
        let arena_parser = ArenaParser::new(arena);
        arena_parser.parse(source, file_path)
    }

    /// Parse Solidity source code from a file
    pub fn parse_file<'arena>(
        &self,
        arena: &'arena AstArena,
        file_path: impl AsRef<Path>,
    ) -> Result<SourceFile<'arena>, ParseErrors> {
        let path = file_path.as_ref();
        let path_str = path.to_string_lossy();

        // Read file content
        let source = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(err) => {
                let parse_error = match err.kind() {
                    std::io::ErrorKind::NotFound => ParseError::FileNotFound {
                        file: path.to_path_buf(),
                    },
                    std::io::ErrorKind::InvalidData => ParseError::InvalidUtf8 {
                        file: path.to_path_buf(),
                    },
                    _ => ParseError::IoError {
                        file: path.to_path_buf(),
                        error: err.to_string(),
                    },
                };
                return Err(parse_error.into());
            }
        };

        self.parse(arena, &source, &path_str)
    }

    /// Parse multiple files
    pub fn parse_files<'arena>(
        &self,
        arena: &'arena AstArena,
        file_paths: impl IntoIterator<Item = impl AsRef<Path>>,
    ) -> Result<Vec<SourceFile<'arena>>, ParseErrors> {
        let mut source_files = Vec::new();
        let mut all_errors = ParseErrors::new();

        for file_path in file_paths {
            match self.parse_file(arena, file_path) {
                Ok(source_file) => source_files.push(source_file),
                Err(errors) => {
                    all_errors.errors.extend(errors.errors);
                    if all_errors.len() >= self.max_errors {
                        break;
                    }
                }
            }
        }

        if all_errors.is_empty() {
            Ok(source_files)
        } else {
            Err(all_errors)
        }
    }

    /// Check if a string contains valid Solidity syntax (lightweight validation)
    pub fn validate_syntax(&self, source: &str) -> Result<(), ParseErrors> {
        // Use solang-parser directly for validation without arena allocation
        match solang_parser::parse(source, Self::DEFAULT_FILE_ID) {
            Ok(_) => Ok(()),
            Err(errors) => {
                let mut parse_errors = ParseErrors::new();
                for error in errors {
                    let location = ast::SourceLocation::new(
                        "<validation>".into(),
                        ast::Position::start(),
                        ast::Position::start(),
                    );
                    let parse_error = ParseError::syntax_error(format!("{:?}", error), location);
                    parse_errors.push(parse_error);
                }
                Err(parse_errors)
            }
        }
    }

    /// Get parser statistics
    pub fn stats(&self) -> ParserStats {
        ParserStats {
            recovery_enabled: self.enable_recovery,
            max_errors: self.max_errors,
        }
    }
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

/// Parser statistics and configuration
#[derive(Debug, Clone)]
pub struct ParserStats {
    pub recovery_enabled: bool,
    pub max_errors: usize,
}

/// Parse result containing both successful results and any recoverable errors
#[derive(Debug)]
pub struct ParseSession<'arena> {
    pub source_files: Vec<SourceFile<'arena>>,
    pub errors: ParseErrors,
    pub stats: SessionStats,
}

/// Statistics from a parsing session
#[derive(Debug, Clone)]
pub struct SessionStats {
    pub files_parsed: usize,
    pub total_errors: usize,
    pub recovered_errors: usize,
    pub parse_time_ms: u64,
}

impl<'arena> ParseSession<'arena> {
    /// Check if parsing was successful (no fatal errors)
    pub fn is_successful(&self) -> bool {
        !self.source_files.is_empty() || self.errors.was_recovered()
    }

    /// Get all contracts from all parsed files
    pub fn contracts(&self) -> impl Iterator<Item = &ast::Contract<'arena>> {
        self.source_files
            .iter()
            .flat_map(|file| file.contracts.iter())
    }

    /// Get all functions from all contracts
    pub fn functions(&self) -> impl Iterator<Item = &ast::Function<'arena>> {
        self.contracts()
            .flat_map(|contract| contract.functions.iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_creation() {
        let parser = Parser::new();
        assert!(parser.enable_recovery);
        assert_eq!(parser.max_errors, 100);

        let parser = Parser::without_recovery();
        assert!(!parser.enable_recovery);
        assert_eq!(parser.max_errors, 1);
    }

    #[test]
    fn test_parser_configuration() {
        let parser = Parser::new().with_max_errors(50).with_recovery(false);

        assert!(!parser.enable_recovery);
        assert_eq!(parser.max_errors, 50);
    }

    #[test]
    fn test_simple_contract_parsing() {
        let arena = AstArena::new();
        let parser = Parser::new();

        let source = r#"
            pragma solidity ^0.8.0;
            contract SimpleTest {
                uint256 public value;
                function setValue(uint256 _value) public {
                    value = _value;
                }
            }
        "#;

        let result = parser.parse(&arena, source, "test.sol");
        assert!(
            result.is_ok(),
            "Parser should handle simple contract: {:?}",
            result
        );

        let source_file = result.unwrap();
        assert_eq!(source_file.contracts.len(), 1);
        assert_eq!(source_file.contracts[0].name.name, "SimpleTest");
    }

    #[test]
    fn test_syntax_validation() {
        let parser = Parser::new();

        // Valid syntax
        let valid = "contract Test { function test() public {} }";
        assert!(parser.validate_syntax(valid).is_ok());

        // Invalid syntax
        let invalid = "contract Test { function test() public { ";
        assert!(parser.validate_syntax(invalid).is_err());
    }
}
