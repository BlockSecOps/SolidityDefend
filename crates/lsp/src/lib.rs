pub mod code_actions;
pub mod diagnostics;
pub mod hover;
pub mod server;

// Re-export main server functionality
pub use server::{SolidityDefendLanguageServer, start_lsp_server};
