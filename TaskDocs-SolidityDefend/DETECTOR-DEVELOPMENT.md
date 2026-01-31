# Detector Development Guide

Guide for adding new vulnerability detectors to SolidityDefend.

## Architecture Overview

```
crates/detectors/src/
├── lib.rs              # Detector registry
├── detector.rs         # Base trait and types
├── types.rs            # Finding, Severity, etc.
├── utils.rs            # Shared utilities
├── <category>/         # Detector categories
│   ├── mod.rs
│   └── <detector>.rs
└── tests/              # Integration tests
```

## Creating a New Detector

### 1. Choose Category

Select the appropriate category directory:

| Category | Purpose |
|----------|---------|
| `access_control/` | Permission and authorization |
| `defi_advanced/` | DeFi-specific vulnerabilities |
| `eip7702/` | EIP-7702 account abstraction |
| `flash_loan/` | Flash loan attacks |
| `mev/` | MEV and frontrunning |
| `oracle/` | Price oracle issues |
| `proxy/` | Proxy and upgrade patterns |
| `reentrancy/` | Reentrancy variants |
| `validation/` | Input validation |

### 2. Create Detector File

```rust
// crates/detectors/src/<category>/<detector_name>.rs

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for <vulnerability description>
pub struct MyNewDetector {
    base: BaseDetector,
}

impl Default for MyNewDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MyNewDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("my-new-detector".to_string()),
                "My New Detector".to_string(),
                "Detects <vulnerability description>".to_string(),
                vec![DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }
}

impl Detector for MyNewDetector {
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
        let source = &ctx.source_code;

        // FP Reduction: Skip safe patterns
        // ... (see FP-REDUCTION.md)

        // Detection logic
        for function in ctx.get_functions() {
            if let Some(issue) = self.check_vulnerability(function, ctx) {
                let finding = self.base.create_finding(
                    ctx,
                    format!("Issue in '{}': {}", function.name.name, issue),
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(XXX)  // Appropriate CWE
                .with_fix_suggestion("Fix suggestion here");

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl MyNewDetector {
    fn check_vulnerability(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        // Implementation
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = MyNewDetector::new();
        assert_eq!(detector.name(), "My New Detector");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }
}
```

### 3. Register Detector

Add to category's `mod.rs`:

```rust
mod my_new_detector;
pub use my_new_detector::MyNewDetector;
```

Add to `lib.rs` registry:

```rust
pub fn all_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        // ... existing detectors
        Box::new(my_category::MyNewDetector::new()),
    ]
}
```

### 4. Add Tests

Create test file with vulnerable and safe contracts:

```rust
// crates/detectors/tests/my_new_detector_test.rs

#[test]
fn test_detects_vulnerability() {
    let vulnerable = r#"
        pragma solidity ^0.8.0;
        contract Vulnerable {
            // Vulnerable code
        }
    "#;

    let findings = analyze(vulnerable);
    assert!(!findings.is_empty());
}

#[test]
fn test_safe_code() {
    let safe = r#"
        pragma solidity ^0.8.0;
        contract Safe {
            // Safe code
        }
    "#;

    let findings = analyze(safe);
    assert!(findings.is_empty());
}
```

## Detection Patterns

### Source Code Analysis

```rust
// Check for specific patterns in source
let has_pattern = source.contains("delegatecall")
    || source.contains("selfdestruct");
```

### AST Traversal

```rust
// Iterate over functions
for function in ctx.get_functions() {
    let func_source = self.get_function_source(function, ctx);
    // Analyze function
}

// Iterate over contracts
for contract in ctx.get_contracts() {
    // Analyze contract
}
```

### Function Source Extraction

```rust
fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
    let start = function.location.start().line();
    let end = function.location.end().line();

    let source_lines: Vec<&str> = ctx.source_code.lines().collect();
    if start < source_lines.len() && end < source_lines.len() {
        source_lines[start..=end].join("\n")
    } else {
        String::new()
    }
}
```

## CWE Mapping

Common CWE assignments:

| Issue Type | CWE |
|------------|-----|
| Reentrancy | 841 |
| Access Control | 284 |
| Integer Overflow | 190 |
| Uninitialized Storage | 824, 457 |
| Improper Validation | 20 |
| Signature Issues | 347 |
| DoS | 400 |

## Severity Guidelines

| Severity | Criteria |
|----------|----------|
| Critical | Direct fund loss, contract takeover |
| High | Significant security impact |
| Medium | Security concern, should fix |
| Low | Best practice violation |
| Info | Informational, code quality |

## Checklist

- [ ] Detector implements `Detector` trait
- [ ] FP reduction for known safe patterns
- [ ] Appropriate severity level
- [ ] CWE mapping included
- [ ] Fix suggestion provided
- [ ] Unit tests for detection
- [ ] Unit tests for false positives
- [ ] Registered in `lib.rs`
- [ ] Documentation in `docs/detectors/`
