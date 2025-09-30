pub mod arena;
pub mod error;
pub mod recovery;

pub use arena::ArenaParser;
pub use error::{ParseError, ParseResult};

/// Parser module for Solidity source code with arena allocation and error recovery.
pub struct Parser {
    // Implementation will be added in T008
}
