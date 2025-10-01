use std::collections::HashMap;
use tower_lsp::lsp_types::*;
use serde::{Deserialize, Serialize};

/// Hover documentation provider for SolidityDefend LSP
/// Provides rich documentation, security information, and contextual help

#[derive(Debug)]
pub struct HoverProvider {
    /// Documentation database
    docs: DocumentationDatabase,
    /// Security knowledge base
    security_kb: SecurityKnowledgeBase,
    /// Configuration for hover behavior
    config: HoverConfig,
}

#[derive(Debug, Clone)]
pub struct HoverConfig {
    /// Enable security warnings in hover
    pub show_security_info: bool,
    /// Enable documentation links
    pub show_documentation_links: bool,
    /// Enable code examples
    pub show_code_examples: bool,
    /// Maximum hover content length
    pub max_content_length: usize,
    /// Preferred markup format
    pub markup_format: MarkupKind,
    /// Enable diagnostic context
    pub show_diagnostic_context: bool,
}

impl Default for HoverConfig {
    fn default() -> Self {
        Self {
            show_security_info: true,
            show_documentation_links: true,
            show_code_examples: true,
            max_content_length: 2000,
            markup_format: MarkupKind::Markdown,
            show_diagnostic_context: true,
        }
    }
}

impl HoverProvider {
    /// Create a new hover provider
    pub fn new(config: HoverConfig) -> Self {
        Self {
            docs: DocumentationDatabase::new(),
            security_kb: SecurityKnowledgeBase::new(),
            config,
        }
    }

    /// Get hover information for a position in a document
    pub async fn get_hover(
        &self,
        document: &DocumentState,
        position: Position,
        context: &HoverContext,
    ) -> Result<Option<Hover>, HoverError> {
        // This will fail until hover implementation is ready
        Err(HoverError::NotImplemented(
            "Hover information generation not implemented".to_string()
        ))
    }

    /// Get security-specific hover information
    pub async fn get_security_hover(
        &self,
        document: &DocumentState,
        position: Position,
        diagnostics: &[Diagnostic],
    ) -> Result<Option<HoverContent>, HoverError> {
        // This will fail until security hover is implemented
        Err(HoverError::NotImplemented(
            "Security hover information not implemented".to_string()
        ))
    }

    /// Get documentation for a symbol
    pub fn get_symbol_documentation(&self, symbol: &Symbol) -> Option<SymbolDocumentation> {
        self.docs.get_documentation(symbol)
    }

    /// Get security information for a vulnerability
    pub fn get_vulnerability_info(&self, vulnerability_id: &str) -> Option<VulnerabilityInfo> {
        self.security_kb.get_vulnerability_info(vulnerability_id)
    }
}

/// Context information for hover requests
#[derive(Debug, Clone)]
pub struct HoverContext {
    pub diagnostics: Vec<Diagnostic>,
    pub symbols: Vec<Symbol>,
    pub workspace_symbols: Vec<WorkspaceSymbol>,
    pub cursor_context: CursorContext,
}

#[derive(Debug, Clone)]
pub struct CursorContext {
    pub word_at_cursor: Option<String>,
    pub line_content: String,
    pub surrounding_lines: Vec<String>,
    pub token_type: Option<TokenType>,
}

#[derive(Debug, Clone)]
pub enum TokenType {
    Keyword,
    Identifier,
    Type,
    Function,
    Variable,
    Modifier,
    Event,
    Operator,
    Comment,
    String,
    Number,
}

/// Represents a symbol in the code
#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind,
    pub location: Location,
    pub detail: Option<String>,
    pub documentation: Option<String>,
    pub type_info: Option<TypeInfo>,
}

#[derive(Debug, Clone)]
pub struct TypeInfo {
    pub type_name: String,
    pub is_array: bool,
    pub is_mapping: bool,
    pub key_type: Option<String>,
    pub value_type: Option<String>,
}

/// Hover content structure
#[derive(Debug, Clone)]
pub struct HoverContent {
    pub title: String,
    pub description: String,
    pub code_example: Option<String>,
    pub security_info: Option<SecurityInfo>,
    pub documentation_links: Vec<DocumentationLink>,
    pub related_diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone)]
pub struct SecurityInfo {
    pub severity: SecuritySeverity,
    pub description: String,
    pub mitigation: String,
    pub cwe_references: Vec<u32>,
    pub examples: Vec<SecurityExample>,
}

#[derive(Debug, Clone)]
pub enum SecuritySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone)]
pub struct SecurityExample {
    pub title: String,
    pub vulnerable_code: String,
    pub secure_code: String,
    pub explanation: String,
}

#[derive(Debug, Clone)]
pub struct DocumentationLink {
    pub title: String,
    pub url: String,
    pub description: Option<String>,
}

/// Documentation database for Solidity constructs
#[derive(Debug)]
pub struct DocumentationDatabase {
    /// Built-in Solidity documentation
    solidity_docs: HashMap<String, SymbolDocumentation>,
    /// Custom documentation entries
    custom_docs: HashMap<String, SymbolDocumentation>,
}

impl DocumentationDatabase {
    pub fn new() -> Self {
        let mut solidity_docs = HashMap::new();

        // Add built-in Solidity documentation - these will fail until implemented
        Self::add_builtin_docs(&mut solidity_docs);

        Self {
            solidity_docs,
            custom_docs: HashMap::new(),
        }
    }

    fn add_builtin_docs(docs: &mut HashMap<String, SymbolDocumentation>) {
        // Add documentation for built-in types
        docs.insert("address".to_string(), SymbolDocumentation {
            name: "address".to_string(),
            summary: "Ethereum address type (20 bytes)".to_string(),
            description: "The address type comes in two flavours: address and address payable. The difference is that address payable can receive Ether.".to_string(),
            parameters: vec![],
            returns: None,
            examples: vec![
                CodeExample {
                    title: "Address declaration".to_string(),
                    code: "address public owner;\naddress payable public recipient;".to_string(),
                    description: "Declaring address variables".to_string(),
                },
            ],
            security_notes: Some("Always validate addresses and check for zero address".to_string()),
            links: vec![
                DocumentationLink {
                    title: "Solidity Documentation - Address Type".to_string(),
                    url: "https://docs.soliditylang.org/en/latest/types.html#address".to_string(),
                    description: None,
                },
            ],
        });

        docs.insert("msg.sender".to_string(), SymbolDocumentation {
            name: "msg.sender".to_string(),
            summary: "Address of the account that sent the current transaction".to_string(),
            description: "msg.sender represents the address that directly called the current function. In the context of external transactions, this is the EOA (Externally Owned Account) that initiated the transaction.".to_string(),
            parameters: vec![],
            returns: Some("address - The sender's address".to_string()),
            examples: vec![
                CodeExample {
                    title: "Access control with msg.sender".to_string(),
                    code: r#"modifier onlyOwner() {
    require(msg.sender == owner, "Not the owner");
    _;
}"#.to_string(),
                    description: "Using msg.sender for access control".to_string(),
                },
            ],
            security_notes: Some("Be aware that msg.sender can be manipulated in delegatecall contexts".to_string()),
            links: vec![],
        });

        docs.insert("selfdestruct".to_string(), SymbolDocumentation {
            name: "selfdestruct".to_string(),
            summary: "Destroys the current contract and sends its funds to the specified address".to_string(),
            description: "⚠️ SECURITY WARNING: selfdestruct is a dangerous operation that permanently destroys a contract.".to_string(),
            parameters: vec![
                ParameterDoc {
                    name: "recipient".to_string(),
                    type_name: "address payable".to_string(),
                    description: "Address to receive the contract's remaining Ether".to_string(),
                },
            ],
            returns: None,
            examples: vec![
                CodeExample {
                    title: "Dangerous usage".to_string(),
                    code: "selfdestruct(payable(msg.sender)); // DANGEROUS!".to_string(),
                    description: "This allows anyone to destroy the contract".to_string(),
                },
                CodeExample {
                    title: "Safer usage".to_string(),
                    code: r#"modifier onlyOwner() {
    require(msg.sender == owner, "Not the owner");
    _;
}

function emergencyDestroy() external onlyOwner {
    selfdestruct(payable(owner));
}"#.to_string(),
                    description: "Adding access control to selfdestruct".to_string(),
                },
            ],
            security_notes: Some("⚠️ CRITICAL: Always add proper access control before using selfdestruct. Consider using a withdrawal pattern instead.".to_string()),
            links: vec![
                DocumentationLink {
                    title: "Solidity Documentation - selfdestruct".to_string(),
                    url: "https://docs.soliditylang.org/en/latest/introduction-to-smart-contracts.html#deactivate-and-self-destruct".to_string(),
                    description: None,
                },
            ],
        });
    }

    pub fn get_documentation(&self, symbol: &Symbol) -> Option<SymbolDocumentation> {
        self.solidity_docs.get(&symbol.name).cloned()
            .or_else(|| self.custom_docs.get(&symbol.name).cloned())
    }

    pub fn add_custom_documentation(&mut self, name: String, doc: SymbolDocumentation) {
        self.custom_docs.insert(name, doc);
    }
}

impl Default for DocumentationDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct SymbolDocumentation {
    pub name: String,
    pub summary: String,
    pub description: String,
    pub parameters: Vec<ParameterDoc>,
    pub returns: Option<String>,
    pub examples: Vec<CodeExample>,
    pub security_notes: Option<String>,
    pub links: Vec<DocumentationLink>,
}

#[derive(Debug, Clone)]
pub struct ParameterDoc {
    pub name: String,
    pub type_name: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct CodeExample {
    pub title: String,
    pub code: String,
    pub description: String,
}

/// Security knowledge base for vulnerability information
#[derive(Debug)]
pub struct SecurityKnowledgeBase {
    vulnerabilities: HashMap<String, VulnerabilityInfo>,
}

impl SecurityKnowledgeBase {
    pub fn new() -> Self {
        let mut vulnerabilities = HashMap::new();

        // Add built-in vulnerability information
        Self::add_builtin_vulnerabilities(&mut vulnerabilities);

        Self { vulnerabilities }
    }

    fn add_builtin_vulnerabilities(vulns: &mut HashMap<String, VulnerabilityInfo>) {
        vulns.insert("reentrancy".to_string(), VulnerabilityInfo {
            id: "reentrancy".to_string(),
            name: "Reentrancy Attack".to_string(),
            description: "A reentrancy attack occurs when external contract calls are made before state changes are finalized, allowing the called contract to re-enter the function and potentially drain funds.".to_string(),
            severity: VulnerabilitySeverity::Critical,
            cwe_ids: vec![691, 862],
            mitigation: "Use the checks-effects-interactions pattern: perform checks first, then effects (state changes), then interactions (external calls). Consider using reentrancy guards.".to_string(),
            examples: vec![
                VulnerabilityExample {
                    title: "Vulnerable withdrawal function".to_string(),
                    vulnerable_code: r#"function withdraw(uint amount) public {
    require(balances[msg.sender] >= amount);
    msg.sender.call{value: amount}(""); // External call before state change
    balances[msg.sender] -= amount; // State change after external call
}"#.to_string(),
                    secure_code: r#"function withdraw(uint amount) public {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount; // State change before external call
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}"#.to_string(),
                    explanation: "Move state changes before external calls to prevent reentrancy".to_string(),
                },
            ],
            references: vec![
                VulnerabilityReference {
                    title: "SWC-107: Reentrancy".to_string(),
                    url: "https://swcregistry.io/docs/SWC-107".to_string(),
                },
            ],
        });

        vulns.insert("missing-access-control".to_string(), VulnerabilityInfo {
            id: "missing-access-control".to_string(),
            name: "Missing Access Control".to_string(),
            description: "Functions that modify state or perform sensitive operations lack proper access control, allowing unauthorized users to execute them.".to_string(),
            severity: VulnerabilitySeverity::High,
            cwe_ids: vec![284, 862],
            mitigation: "Add proper access control modifiers such as onlyOwner, role-based access control, or other authorization mechanisms.".to_string(),
            examples: vec![
                VulnerabilityExample {
                    title: "Function without access control".to_string(),
                    vulnerable_code: r#"function setOwner(address newOwner) external {
    owner = newOwner; // Anyone can change the owner!
}"#.to_string(),
                    secure_code: r#"modifier onlyOwner() {
    require(msg.sender == owner, "Not the owner");
    _;
}

function setOwner(address newOwner) external onlyOwner {
    require(newOwner != address(0), "Invalid address");
    owner = newOwner;
}"#.to_string(),
                    explanation: "Add onlyOwner modifier to restrict function access".to_string(),
                },
            ],
            references: vec![
                VulnerabilityReference {
                    title: "SWC-105: Unprotected Ether Withdrawal".to_string(),
                    url: "https://swcregistry.io/docs/SWC-105".to_string(),
                },
            ],
        });
    }

    pub fn get_vulnerability_info(&self, id: &str) -> Option<VulnerabilityInfo> {
        self.vulnerabilities.get(id).cloned()
    }

    pub fn add_vulnerability_info(&mut self, info: VulnerabilityInfo) {
        self.vulnerabilities.insert(info.id.clone(), info);
    }
}

impl Default for SecurityKnowledgeBase {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct VulnerabilityInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: VulnerabilitySeverity,
    pub cwe_ids: Vec<u32>,
    pub mitigation: String,
    pub examples: Vec<VulnerabilityExample>,
    pub references: Vec<VulnerabilityReference>,
}

#[derive(Debug, Clone)]
pub enum VulnerabilitySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone)]
pub struct VulnerabilityExample {
    pub title: String,
    pub vulnerable_code: String,
    pub secure_code: String,
    pub explanation: String,
}

#[derive(Debug, Clone)]
pub struct VulnerabilityReference {
    pub title: String,
    pub url: String,
}

/// Hover content formatter
pub struct HoverFormatter {
    config: HoverConfig,
}

impl HoverFormatter {
    pub fn new(config: HoverConfig) -> Self {
        Self { config }
    }

    /// Format hover content as LSP Hover
    pub fn format_hover(&self, content: &HoverContent) -> Result<Hover, HoverError> {
        // This will fail until hover formatting is implemented
        Err(HoverError::NotImplemented(
            "Hover formatting not implemented".to_string()
        ))
    }

    /// Format symbol documentation
    pub fn format_symbol_docs(&self, docs: &SymbolDocumentation) -> String {
        let mut content = String::new();

        // Title
        content.push_str(&format!("## {}\n\n", docs.name));

        // Summary
        content.push_str(&format!("{}\n\n", docs.summary));

        // Description
        if !docs.description.is_empty() {
            content.push_str(&format!("{}\n\n", docs.description));
        }

        // Parameters
        if !docs.parameters.is_empty() {
            content.push_str("### Parameters\n\n");
            for param in &docs.parameters {
                content.push_str(&format!("- `{}` (`{}`): {}\n", param.name, param.type_name, param.description));
            }
            content.push('\n');
        }

        // Returns
        if let Some(returns) = &docs.returns {
            content.push_str(&format!("### Returns\n\n{}\n\n", returns));
        }

        // Examples
        if !docs.examples.is_empty() && self.config.show_code_examples {
            content.push_str("### Examples\n\n");
            for example in &docs.examples {
                content.push_str(&format!("**{}**\n\n```solidity\n{}\n```\n\n{}\n\n",
                    example.title, example.code, example.description));
            }
        }

        // Security notes
        if let Some(security_notes) = &docs.security_notes {
            if self.config.show_security_info {
                content.push_str(&format!("### ⚠️ Security Notes\n\n{}\n\n", security_notes));
            }
        }

        // Links
        if !docs.links.is_empty() && self.config.show_documentation_links {
            content.push_str("### Documentation\n\n");
            for link in &docs.links {
                content.push_str(&format!("- [{}]({})\n", link.title, link.url));
            }
        }

        content
    }

    /// Format vulnerability information
    pub fn format_vulnerability_info(&self, info: &VulnerabilityInfo) -> String {
        let mut content = String::new();

        // Title with severity
        let severity_emoji = match info.severity {
            VulnerabilitySeverity::Critical => "🔴",
            VulnerabilitySeverity::High => "🟠",
            VulnerabilitySeverity::Medium => "🟡",
            VulnerabilitySeverity::Low => "🔵",
            VulnerabilitySeverity::Info => "ℹ️",
        };

        content.push_str(&format!("## {} {} - {:?}\n\n", severity_emoji, info.name, info.severity));

        // Description
        content.push_str(&format!("{}\n\n", info.description));

        // CWE references
        if !info.cwe_ids.is_empty() {
            content.push_str("### CWE References\n\n");
            for cwe_id in &info.cwe_ids {
                content.push_str(&format!("- [CWE-{}](https://cwe.mitre.org/data/definitions/{}.html)\n", cwe_id, cwe_id));
            }
            content.push('\n');
        }

        // Mitigation
        content.push_str(&format!("### Mitigation\n\n{}\n\n", info.mitigation));

        // Examples
        if !info.examples.is_empty() && self.config.show_code_examples {
            content.push_str("### Examples\n\n");
            for example in &info.examples {
                content.push_str(&format!("**{}**\n\n", example.title));
                content.push_str("Vulnerable code:\n```solidity\n");
                content.push_str(&example.vulnerable_code);
                content.push_str("\n```\n\nSecure code:\n```solidity\n");
                content.push_str(&example.secure_code);
                content.push_str(&format!("\n```\n\n{}\n\n", example.explanation));
            }
        }

        content
    }
}

/// Placeholder for document state
#[derive(Debug, Clone)]
pub struct DocumentState {
    pub uri: Url,
    pub text: String,
    pub version: i32,
    pub language_id: String,
}

/// Errors that can occur during hover operations
#[derive(Debug, thiserror::Error)]
pub enum HoverError {
    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Documentation not found: {0}")]
    DocumentationNotFound(String),

    #[error("Formatting error: {0}")]
    FormattingError(String),

    #[error("Context error: {0}")]
    ContextError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hover_config_defaults() {
        let config = HoverConfig::default();

        assert!(config.show_security_info);
        assert!(config.show_documentation_links);
        assert!(config.show_code_examples);
        assert_eq!(config.max_content_length, 2000);
        assert_eq!(config.markup_format, MarkupKind::Markdown);
        assert!(config.show_diagnostic_context);
    }

    #[test]
    #[should_panic(expected = "Hover information generation not implemented")]
    fn test_hover_generation_fails() {
        let provider = HoverProvider::new(HoverConfig::default());
        let document = DocumentState {
            uri: Url::parse("file:///test.sol").unwrap(),
            text: "contract Test {}".to_string(),
            version: 1,
            language_id: "solidity".to_string(),
        };

        let position = Position { line: 0, character: 5 };
        let context = HoverContext {
            diagnostics: vec![],
            symbols: vec![],
            workspace_symbols: vec![],
            cursor_context: CursorContext {
                word_at_cursor: Some("Test".to_string()),
                line_content: "contract Test {}".to_string(),
                surrounding_lines: vec![],
                token_type: Some(TokenType::Identifier),
            },
        };

        // This should fail because hover generation is not implemented
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            provider.get_hover(&document, position, &context).await.unwrap();
        });
    }

    #[test]
    fn test_documentation_database() {
        let db = DocumentationDatabase::new();

        // Should have built-in documentation
        let address_symbol = Symbol {
            name: "address".to_string(),
            kind: SymbolKind::TYPE_PARAMETER,
            location: Location {
                uri: Url::parse("file:///test.sol").unwrap(),
                range: Range {
                    start: Position { line: 0, character: 0 },
                    end: Position { line: 0, character: 7 },
                },
            },
            detail: None,
            documentation: None,
            type_info: None,
        };

        let docs = db.get_documentation(&address_symbol);
        assert!(docs.is_some());

        let address_docs = docs.unwrap();
        assert_eq!(address_docs.name, "address");
        assert!(address_docs.summary.contains("Ethereum address"));
    }

    #[test]
    fn test_security_knowledge_base() {
        let kb = SecurityKnowledgeBase::new();

        let reentrancy_info = kb.get_vulnerability_info("reentrancy");
        assert!(reentrancy_info.is_some());

        let info = reentrancy_info.unwrap();
        assert_eq!(info.name, "Reentrancy Attack");
        assert!(matches!(info.severity, VulnerabilitySeverity::Critical));
        assert!(!info.examples.is_empty());
    }

    #[test]
    fn test_hover_formatter() {
        let formatter = HoverFormatter::new(HoverConfig::default());

        let docs = SymbolDocumentation {
            name: "testFunction".to_string(),
            summary: "A test function".to_string(),
            description: "This is a test function for demonstration".to_string(),
            parameters: vec![
                ParameterDoc {
                    name: "value".to_string(),
                    type_name: "uint256".to_string(),
                    description: "The input value".to_string(),
                },
            ],
            returns: Some("bool - Success status".to_string()),
            examples: vec![],
            security_notes: Some("Ensure input validation".to_string()),
            links: vec![],
        };

        let formatted = formatter.format_symbol_docs(&docs);

        assert!(formatted.contains("## testFunction"));
        assert!(formatted.contains("A test function"));
        assert!(formatted.contains("### Parameters"));
        assert!(formatted.contains("### Returns"));
        assert!(formatted.contains("### ⚠️ Security Notes"));
    }

    #[test]
    fn test_vulnerability_info_formatting() {
        let formatter = HoverFormatter::new(HoverConfig::default());

        let vuln_info = VulnerabilityInfo {
            id: "test-vuln".to_string(),
            name: "Test Vulnerability".to_string(),
            description: "A test vulnerability".to_string(),
            severity: VulnerabilitySeverity::High,
            cwe_ids: vec![123, 456],
            mitigation: "Apply proper fixes".to_string(),
            examples: vec![],
            references: vec![],
        };

        let formatted = formatter.format_vulnerability_info(&vuln_info);

        assert!(formatted.contains("🟠 Test Vulnerability"));
        assert!(formatted.contains("High"));
        assert!(formatted.contains("CWE-123"));
        assert!(formatted.contains("### Mitigation"));
    }
}