use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for PUSH0 stack assumption vulnerabilities
///
/// EIP-3855 introduced PUSH0 opcode in Shanghai upgrade.
/// Issues include:
/// 1. Contracts compiled for PUSH0 won't work on pre-Shanghai chains
/// 2. Inline assembly assuming specific stack layouts may break
/// 3. Gas calculations assuming old PUSH1 0 gas cost are wrong
///
/// Vulnerable patterns:
/// ```solidity
/// // Cross-chain deployment issue
/// // Compiled with Shanghai+ compiler, deployed to pre-Shanghai chain
///
/// // Gas calculation issue
/// assembly {
///     // Old: PUSH1 0 costs 3 gas
///     // New: PUSH0 costs 2 gas
///     let gasNeeded := mul(iterations, 3) // Wrong if PUSH0 used
/// }
/// ```
pub struct Push0StackAssumptionDetector {
    base: BaseDetector,
}

impl Default for Push0StackAssumptionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Push0StackAssumptionDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("push0-stack-assumption"),
                "PUSH0 Stack Assumption".to_string(),
                "Detects potential issues with PUSH0 opcode (EIP-3855) compatibility. \
                 Contracts compiled with Shanghai+ compiler may not work on older chains, \
                 and gas calculations may be incorrect."
                    .to_string(),
                vec![DetectorCategory::BestPractices],
                Severity::Low,
            ),
        }
    }

    /// Check for cross-chain deployment concerns
    fn find_cross_chain_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // Check for multi-chain indicators - must be specific
        // Avoid matching generic L1/L2 references (e.g., "level1", "level2")
        let is_multi_chain = source.contains("block.chainid")
            || source.contains("CrossChain")
            || source.contains("multichain")
            || source.contains("Multichain")
            || source.contains("LayerZero")
            || source.contains("Axelar")
            || source.contains("Wormhole")
            || source.contains("chainSelector")
            || source.contains("destChain")
            || source.contains("srcChain")
            || (source.contains("L1") && source.contains("L2") && source.contains("bridge"));

        if !is_multi_chain {
            return findings;
        }

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Check pragma for version that might generate PUSH0
            if trimmed.starts_with("pragma solidity") {
                // Check if version >= 0.8.20 (Shanghai compiler)
                if trimmed.contains("0.8.20")
                    || trimmed.contains("0.8.21")
                    || trimmed.contains("0.8.22")
                    || trimmed.contains("0.8.23")
                    || trimmed.contains("0.8.24")
                    || trimmed.contains("0.8.25")
                    || trimmed.contains("^0.8.20")
                    || trimmed.contains(">=0.8.20")
                {
                    findings.push((
                        line_num as u32 + 1,
                        "Solidity >=0.8.20 generates PUSH0 - may not work on pre-Shanghai chains"
                            .to_string(),
                    ));
                }
            }
        }

        findings
    }

    /// Check for assembly with potential PUSH0 issues
    fn find_assembly_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let mut in_assembly = false;

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }

            // Track assembly blocks
            if trimmed.contains("assembly") && trimmed.contains("{") {
                in_assembly = true;
            }
            if in_assembly && trimmed.contains("}") && !trimmed.contains("{") {
                in_assembly = false;
            }

            if in_assembly {
                // Check for hardcoded gas calculations that might assume PUSH1 0
                if (trimmed.contains("gas()") || trimmed.contains("gasleft()"))
                    && (trimmed.contains("mul(") || trimmed.contains("add("))
                {
                    // Look for magic number 3 (old PUSH1 0 cost)
                    if trimmed.contains(", 3)") || trimmed.contains("3,") {
                        findings.push((
                            line_num as u32 + 1,
                            "gas calculation may assume PUSH1 cost (3 gas) instead of PUSH0 (2 gas)"
                                .to_string(),
                        ));
                    }
                }

                // Check for stack depth assumptions
                if trimmed.contains("mload(0x40)") || trimmed.contains("mstore(0x40") {
                    // These are common patterns, but flag if there are complex stack ops
                    if source.contains("swap") && source.contains("dup") {
                        findings.push((
                            line_num as u32 + 1,
                            "complex stack operations may have different behavior with PUSH0"
                                .to_string(),
                        ));
                    }
                }
            }
        }

        findings
    }

    /// Check for potential EVM version issues
    fn find_evm_version_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Check for EVM version comments or configurations
            if trimmed.contains("evmVersion")
                || trimmed.contains("evm_version")
                || trimmed.contains("target: ")
            {
                if trimmed.contains("paris")
                    || trimmed.contains("london")
                    || trimmed.contains("berlin")
                {
                    findings.push((
                        line_num as u32 + 1,
                        "pre-Shanghai EVM version specified - PUSH0 not available".to_string(),
                    ));
                }
            }

            // Check for explicit PUSH1 0 in Yul
            if trimmed.contains("verbatim") {
                findings.push((
                    line_num as u32 + 1,
                    "verbatim assembly may need updating for PUSH0 optimization".to_string(),
                ));
            }
        }

        findings
    }

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for Push0StackAssumptionDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn is_enabled(&self) -> bool {
        self.base.enabled
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        // Check for cross-chain deployment issues
        let cross_chain_issues = self.find_cross_chain_issues(source);
        for (line, issue) in cross_chain_issues {
            let message = format!(
                "PUSH0 compatibility issue in contract '{}': {}. \
                 PUSH0 (EIP-3855) is only available post-Shanghai (March 2023). \
                 Pre-Shanghai chains will reject this bytecode.",
                contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(682) // CWE-682: Incorrect Calculation
                .with_confidence(Confidence::Medium)
                .with_fix_suggestion(
                    "For cross-chain compatibility:\n\n\
                     1. Use --evm-version paris (or earlier) in compiler settings\n\
                     2. Or use Solidity < 0.8.20 which doesn't generate PUSH0\n\
                     3. Or verify all target chains support Shanghai/PUSH0\n\n\
                     Example foundry.toml:\n\
                     [profile.default]\n\
                     evm_version = \"paris\""
                        .to_string(),
                );

            findings.push(finding);
        }

        // Check for assembly issues
        let assembly_issues = self.find_assembly_issues(source);
        for (line, issue) in assembly_issues {
            let message = format!(
                "Potential PUSH0 assembly issue in contract '{}': {}.",
                contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(682) // CWE-682: Incorrect Calculation
                .with_confidence(Confidence::Low)
                .with_fix_suggestion(
                    "Review assembly gas calculations. PUSH0 costs 2 gas vs \
                     PUSH1 0 which costs 3 gas. Update hardcoded gas values if needed."
                        .to_string(),
                );

            findings.push(finding);
        }

        // Check for EVM version issues
        let evm_issues = self.find_evm_version_issues(source);
        for (line, issue) in evm_issues {
            let message = format!(
                "EVM version consideration in contract '{}': {}.",
                contract_name, issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 1, 50)
                .with_cwe(682) // CWE-682: Incorrect Calculation
                .with_confidence(Confidence::Low)
                .with_fix_suggestion(
                    "Ensure EVM version matches deployment target. \
                     Shanghai+ enables PUSH0 optimization."
                        .to_string(),
                );

            findings.push(finding);
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = Push0StackAssumptionDetector::new();
        assert_eq!(detector.name(), "PUSH0 Stack Assumption");
        assert_eq!(detector.default_severity(), Severity::Low);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_cross_chain_detection() {
        let detector = Push0StackAssumptionDetector::new();

        let multi_chain = r#"
            pragma solidity ^0.8.20;
            contract MultiChain {
                function getChainId() external view returns (uint256) {
                    return block.chainid;
                }
            }
        "#;
        let issues = detector.find_cross_chain_issues(multi_chain);
        assert!(!issues.is_empty());
    }
}
