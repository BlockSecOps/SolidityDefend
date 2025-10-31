//! Transient Storage Misuse Detector
//!
//! Detects incorrect usage of transient storage for data that should persist across transactions.
//!
//! ## Problem
//!
//! Developers may mistakenly use transient storage for data that needs to persist, causing
//! critical state loss between transactions.
//!
//! ## Vulnerability Examples
//!
//! ```solidity
//! contract MisuseExample {
//!     // ❌ BAD: User balances in transient storage!
//!     mapping(address => uint256) transient public balances;
//!
//!     function deposit() public payable {
//!         balances[msg.sender] += msg.value;
//!         // Lost at end of transaction!
//!     }
//!
//!     function withdraw() public {
//!         // Always zero in a new transaction!
//!         uint256 amount = balances[msg.sender];
//!         // ...
//!     }
//! }
//! ```
//!
//! ## Detection Strategy
//!
//! Flag transient storage used for:
//! 1. User balances, allowances, ownership
//! 2. Contract configuration (owner, paused state)
//! 3. Accounting data (totalSupply, reserves)
//! 4. State that's read by view functions
//!
//! Severity: MEDIUM
//! Category: Logic

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use super::has_transient_storage_declarations;

pub struct TransientStorageMisuseDetector {
    base: BaseDetector,
}

impl TransientStorageMisuseDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("transient-storage-misuse".to_string()),
                "Transient Storage Misuse".to_string(),
                "Detects persistent data incorrectly stored in transient storage, causing state loss".to_string(),
                vec![DetectorCategory::Logic],
                Severity::Medium,
            ),
        }
    }

    fn check_contract(&self, ctx: &AnalysisContext) -> Vec<(String, u32, Severity, String)> {
        let mut issues = Vec::new();
        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Find transient variable declarations
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let line_lower = line.to_lowercase();

            if !line_lower.contains("transient") {
                continue;
            }

            // Skip comments
            if line_lower.trim_start().starts_with("//") || line_lower.trim_start().starts_with("/*") {
                continue;
            }

            let var_name_lower = line_lower.to_lowercase();

            // Check for suspicious variable names suggesting persistent data
            let suspicious_keywords = [
                ("balance", "User balances should persist across transactions"),
                ("allowance", "Token allowances must persist"),
                ("owner", "Ownership data must be permanent"),
                ("paused", "Pause state should persist"),
                ("totalsupply", "Token supply must be permanent"),
                ("reserve", "Reserve amounts should persist"),
                ("debt", "Debt tracking must persist"),
                ("deposit", "Deposit amounts should persist"),
                ("stake", "Staking amounts must persist"),
                ("reward", "Rewards should persist"),
                ("locked", "Lock state must persist"),
                ("nonce", "Nonces might need to persist (check if used across transactions)"),
            ];

            for (keyword, reason) in suspicious_keywords.iter() {
                if var_name_lower.contains(keyword) {
                    issues.push((
                        format!("Suspicious use of transient storage for '{}' - data may need to persist", keyword),
                        (line_num + 1) as u32,
                        Severity::High,
                        format!(
                            "Transient storage is cleared at transaction end:\n\
                             \n\
                             {}\n\
                             \n\
                             Current (WRONG for persistent data):\n\
                             {} transient public {};  // Lost at end of transaction!\n\
                             \n\
                             If this data needs to persist, use regular storage:\n\
                             {} public {};  // ✅ Persists across transactions\n\
                             \n\
                             Transient storage is ONLY for:\n\
                             - Temporary computation state within single transaction\n\
                             - Reentrancy locks\n\
                             - Gas-efficient temporary caches\n\
                             - State that's never read in subsequent transactions\n\
                             \n\
                             If you're SURE this should be transient, add a comment:\n\
                             // TRANSIENT OK: Only used within single transaction\n\
                             {} transient public {};",
                            reason,
                            line.split("transient").next().unwrap_or("uint256"),
                            keyword,
                            line.split("transient").next().unwrap_or("uint256"),
                            keyword,
                            line.split("transient").next().unwrap_or("uint256"),
                            keyword
                        )
                    ));
                    break;  // One issue per line
                }
            }

            // Check if transient variable is read in view functions
            if line_lower.contains("public") || line_lower.contains("external") {
                let var_name = extract_variable_name(line);
                if !var_name.is_empty() && is_read_in_view_functions(&var_name, &source_lower) {
                    issues.push((
                        format!("Transient variable '{}' read in view function - will always return 0", var_name),
                        (line_num + 1) as u32,
                        Severity::High,
                        format!(
                            "View functions execute in their own context - transient storage appears empty:\n\
                             \n\
                             contract Example {{\n\
                                 uint256 transient public {};  // ❌ Transient\n\
                                 \n\
                                 function viewValue() public view returns (uint256) {{\n\
                                     return {};  // Always returns 0!\n\
                                 }}\n\
                             }}\n\
                             \n\
                             Fix: Use regular storage for data accessed by view functions\n\
                             uint256 public {};  // ✅ Regular storage",
                            var_name, var_name, var_name
                        )
                    ));
                }
            }
        }

        issues
    }
}

// Helper to extract variable name from declaration
fn extract_variable_name(line: &str) -> String {
    let parts: Vec<&str> = line.split_whitespace().collect();
    for (i, part) in parts.iter().enumerate() {
        if *part == "transient" && i + 1 < parts.len() {
            // Get next word after "transient", strip visibility and semicolon
            let name = parts.iter().skip(i + 1).find(|p| {
                !p.contains("public") && !p.contains("private") && !p.contains("internal") && !p.contains("external")
            }).unwrap_or(&"");
            return name.trim_matches(|c: char| !c.is_alphanumeric()).to_string();
        }
    }
    String::new()
}

fn is_read_in_view_functions(var_name: &str, source: &str) -> bool {
    // Simple heuristic: check if variable is referenced in "view" or "pure" functions
    let parts: Vec<&str> = source.split("function").collect();
    for part in parts.iter().skip(1) {
        if part.contains("view") || part.contains("pure") {
            if part.contains(var_name) {
                return true;
            }
        }
    }
    false
}

impl Default for TransientStorageMisuseDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for TransientStorageMisuseDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn is_enabled(&self) -> bool {
        self.base.enabled
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        if !has_transient_storage_declarations(ctx) {
            return Ok(findings);
        }

        for (title, line, severity, remediation) in self.check_contract(ctx) {
            let finding = self
                .base
                .create_finding_with_severity(ctx, title, line, 0, 20, severity)
                .with_fix_suggestion(remediation);

            findings.push(finding);
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
