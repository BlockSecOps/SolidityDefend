use ast::SourceLocation;
use std::path::PathBuf;
use thiserror::Error;

/// Parse error with source location information
#[derive(Error, Debug, Clone)]
pub enum ParseError {
    #[error("Syntax error at {location}: {message}")]
    SyntaxError {
        message: String,
        location: SourceLocation,
    },

    #[error("Unexpected token at {location}: expected {expected}, found {found}")]
    UnexpectedToken {
        expected: String,
        found: String,
        location: SourceLocation,
    },

    #[error("Missing token at {location}: expected {expected}")]
    MissingToken {
        expected: String,
        location: SourceLocation,
    },

    #[error("Solang parser error: {0}")]
    SolangError(String),

    #[error("I/O error reading file {file:?}: {error}")]
    IoError { file: PathBuf, error: String },

    #[error("Invalid UTF-8 in file {file:?}")]
    InvalidUtf8 { file: PathBuf },

    #[error("File not found: {file:?}")]
    FileNotFound { file: PathBuf },

    #[error("Arena allocation failed")]
    ArenaAllocationFailed,
}

impl ParseError {
    /// Create a syntax error at the given location
    pub fn syntax_error(message: impl Into<String>, location: SourceLocation) -> Self {
        Self::SyntaxError {
            message: message.into(),
            location,
        }
    }

    /// Create an unexpected token error
    pub fn unexpected_token(
        expected: impl Into<String>,
        found: impl Into<String>,
        location: SourceLocation,
    ) -> Self {
        Self::UnexpectedToken {
            expected: expected.into(),
            found: found.into(),
            location,
        }
    }

    /// Create a missing token error
    pub fn missing_token(expected: impl Into<String>, location: SourceLocation) -> Self {
        Self::MissingToken {
            expected: expected.into(),
            location,
        }
    }

    /// Get the source location of this error, if available
    pub fn location(&self) -> Option<&SourceLocation> {
        match self {
            ParseError::SyntaxError { location, .. } => Some(location),
            ParseError::UnexpectedToken { location, .. } => Some(location),
            ParseError::MissingToken { location, .. } => Some(location),
            _ => None,
        }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            ParseError::SyntaxError { .. } => true,
            ParseError::UnexpectedToken { .. } => true,
            ParseError::MissingToken { .. } => true,
            ParseError::SolangError(_) => false,
            ParseError::IoError { .. } => false,
            ParseError::InvalidUtf8 { .. } => false,
            ParseError::FileNotFound { .. } => false,
            ParseError::ArenaAllocationFailed => false,
        }
    }
}

/// Result type for parser operations
pub type ParseResult<T> = Result<T, ParseError>;

/// Multiple parse errors with recovery information
#[derive(Debug, Clone)]
pub struct ParseErrors {
    pub errors: Vec<ParseError>,
    pub recovered: bool,
}

impl ParseErrors {
    /// Create a new empty error collection
    pub fn new() -> Self {
        Self {
            errors: Vec::new(),
            recovered: false,
        }
    }

    /// Add an error to the collection
    pub fn push(&mut self, error: ParseError) {
        self.errors.push(error);
    }

    /// Check if there are any errors
    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }

    /// Get the number of errors
    pub fn len(&self) -> usize {
        self.errors.len()
    }

    /// Mark as recovered after error handling
    pub fn mark_recovered(&mut self) {
        self.recovered = true;
    }

    /// Check if parsing was successfully recovered
    pub fn was_recovered(&self) -> bool {
        self.recovered
    }
}

impl Default for ParseErrors {
    fn default() -> Self {
        Self::new()
    }
}

impl From<ParseError> for ParseErrors {
    fn from(error: ParseError) -> Self {
        let mut errors = Self::new();
        errors.push(error);
        errors
    }
}
