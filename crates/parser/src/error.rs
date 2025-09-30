// Parse error handling - implementation pending
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Parse error: {0}")]
    Generic(String),
}

pub type ParseResult<T> = Result<T, ParseError>;
