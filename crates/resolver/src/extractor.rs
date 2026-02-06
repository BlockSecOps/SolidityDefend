//! Import extraction from Solidity source files
//!
//! Parses Solidity import statements using regex.

use crate::{Import, ImportKind, ImportedSymbol};
use regex::Regex;

/// Extracts imports from Solidity source code
pub struct ImportExtractor {
    // Regex patterns for different import types
    simple_import: Regex,
    named_import: Regex,
    aliased_import: Regex,
    wildcard_import: Regex,
}

impl Default for ImportExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl ImportExtractor {
    /// Create a new import extractor
    pub fn new() -> Self {
        // Simple import: import "path";
        let simple_import = Regex::new(r#"^\s*import\s+["']([^"']+)["']\s*;"#)
            .expect("Invalid simple import regex");

        // Named import: import {A, B as C} from "path";
        let named_import = Regex::new(r#"^\s*import\s+\{([^}]+)\}\s+from\s+["']([^"']+)["']\s*;"#)
            .expect("Invalid named import regex");

        // Aliased import: import "path" as X;
        let aliased_import = Regex::new(r#"^\s*import\s+["']([^"']+)["']\s+as\s+(\w+)\s*;"#)
            .expect("Invalid aliased import regex");

        // Wildcard import: import * as X from "path";
        let wildcard_import =
            Regex::new(r#"^\s*import\s+\*\s+as\s+(\w+)\s+from\s+["']([^"']+)["']\s*;"#)
                .expect("Invalid wildcard import regex");

        Self {
            simple_import,
            named_import,
            aliased_import,
            wildcard_import,
        }
    }

    /// Extract all imports from source code
    pub fn extract(&self, source: &str) -> Vec<Import> {
        let mut imports = Vec::new();

        for (line_idx, line) in source.lines().enumerate() {
            let line_num = line_idx + 1;

            // Skip comments (basic handling)
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
                continue;
            }

            // Try each import pattern
            if let Some(import) = self.try_extract_named(line, line_num) {
                imports.push(import);
            } else if let Some(import) = self.try_extract_wildcard(line, line_num) {
                imports.push(import);
            } else if let Some(import) = self.try_extract_aliased(line, line_num) {
                imports.push(import);
            } else if let Some(import) = self.try_extract_simple(line, line_num) {
                imports.push(import);
            }
        }

        imports
    }

    fn try_extract_simple(&self, line: &str, line_num: usize) -> Option<Import> {
        self.simple_import.captures(line).map(|caps| Import {
            path: caps[1].to_string(),
            kind: ImportKind::Simple,
            line: line_num,
        })
    }

    fn try_extract_named(&self, line: &str, line_num: usize) -> Option<Import> {
        self.named_import.captures(line).map(|caps| {
            let symbols_str = &caps[1];
            let symbols = parse_named_symbols(symbols_str);

            Import {
                path: caps[2].to_string(),
                kind: ImportKind::Named(symbols),
                line: line_num,
            }
        })
    }

    fn try_extract_aliased(&self, line: &str, line_num: usize) -> Option<Import> {
        self.aliased_import.captures(line).map(|caps| Import {
            path: caps[1].to_string(),
            kind: ImportKind::Aliased(caps[2].to_string()),
            line: line_num,
        })
    }

    fn try_extract_wildcard(&self, line: &str, line_num: usize) -> Option<Import> {
        self.wildcard_import.captures(line).map(|caps| Import {
            path: caps[2].to_string(),
            kind: ImportKind::Wildcard(caps[1].to_string()),
            line: line_num,
        })
    }
}

/// Parse named import symbols (e.g., "A, B as C, D")
fn parse_named_symbols(symbols_str: &str) -> Vec<ImportedSymbol> {
    symbols_str
        .split(',')
        .filter_map(|s| {
            let s = s.trim();
            if s.is_empty() {
                return None;
            }

            // Check for "X as Y" pattern
            if let Some(idx) = s.find(" as ") {
                let name = s[..idx].trim().to_string();
                let alias = s[idx + 4..].trim().to_string();
                Some(ImportedSymbol {
                    name,
                    alias: Some(alias),
                })
            } else {
                Some(ImportedSymbol {
                    name: s.to_string(),
                    alias: None,
                })
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_simple_import() {
        let extractor = ImportExtractor::new();
        let source = r#"
pragma solidity ^0.8.0;

import "./Token.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
"#;

        let imports = extractor.extract(source);
        assert_eq!(imports.len(), 2);

        assert_eq!(imports[0].path, "./Token.sol");
        assert_eq!(imports[0].kind, ImportKind::Simple);

        assert_eq!(
            imports[1].path,
            "@openzeppelin/contracts/token/ERC20/ERC20.sol"
        );
        assert_eq!(imports[1].kind, ImportKind::Simple);
    }

    #[test]
    fn test_extract_named_import() {
        let extractor = ImportExtractor::new();
        let source = r#"
import {ERC20, IERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Ownable as OZ_Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
"#;

        let imports = extractor.extract(source);
        assert_eq!(imports.len(), 2);

        if let ImportKind::Named(symbols) = &imports[0].kind {
            assert_eq!(symbols.len(), 2);
            assert_eq!(symbols[0].name, "ERC20");
            assert!(symbols[0].alias.is_none());
            assert_eq!(symbols[1].name, "IERC20");
        } else {
            panic!("Expected Named import");
        }

        if let ImportKind::Named(symbols) = &imports[1].kind {
            assert_eq!(symbols.len(), 1);
            assert_eq!(symbols[0].name, "Ownable");
            assert_eq!(symbols[0].alias, Some("OZ_Ownable".to_string()));
        } else {
            panic!("Expected Named import");
        }
    }

    #[test]
    fn test_extract_aliased_import() {
        let extractor = ImportExtractor::new();
        let source = r#"
import "./Utils.sol" as Utils;
"#;

        let imports = extractor.extract(source);
        assert_eq!(imports.len(), 1);

        assert_eq!(imports[0].path, "./Utils.sol");
        assert_eq!(imports[0].kind, ImportKind::Aliased("Utils".to_string()));
    }

    #[test]
    fn test_extract_wildcard_import() {
        let extractor = ImportExtractor::new();
        let source = r#"
import * as OpenZeppelin from "@openzeppelin/contracts/index.sol";
"#;

        let imports = extractor.extract(source);
        assert_eq!(imports.len(), 1);

        assert_eq!(imports[0].path, "@openzeppelin/contracts/index.sol");
        assert_eq!(
            imports[0].kind,
            ImportKind::Wildcard("OpenZeppelin".to_string())
        );
    }

    #[test]
    fn test_skip_comments() {
        let extractor = ImportExtractor::new();
        let source = r#"
// import "commented.sol";
/* import "block-commented.sol"; */
import "./actual.sol";
"#;

        let imports = extractor.extract(source);
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].path, "./actual.sol");
    }

    #[test]
    fn test_line_numbers() {
        let extractor = ImportExtractor::new();
        let source = r#"pragma solidity ^0.8.0;

import "./First.sol";

import "./Second.sol";
"#;

        let imports = extractor.extract(source);
        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].line, 3);
        assert_eq!(imports[1].line, 5);
    }
}
