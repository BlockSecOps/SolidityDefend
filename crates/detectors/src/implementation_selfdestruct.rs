use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for selfdestruct in implementation contracts
///
/// If an implementation contract contains selfdestruct and can be called directly,
/// an attacker can destroy the implementation, bricking all proxy contracts.
/// This is the vulnerability behind the $150M Parity wallet freeze.
///
/// Vulnerable pattern:
/// ```solidity
/// contract Implementation {
///     function destroy() public {
///         selfdestruct(payable(msg.sender)); // Bricks all proxies!
///     }
/// }
/// ```
pub struct ImplementationSelfdestructDetector {
    base: BaseDetector,
}

impl Default for ImplementationSelfdestructDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ImplementationSelfdestructDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("implementation-selfdestruct"),
                "Implementation Contract Contains selfdestruct".to_string(),
                "Detects implementation contracts with selfdestruct that could brick all proxies. \
                 This was the root cause of the $150M Parity wallet freeze."
                    .to_string(),
                vec![DetectorCategory::Upgradeable, DetectorCategory::Logic],
                Severity::Critical,
            ),
        }
    }

    /// Check if contract appears to be an implementation
    fn is_likely_implementation(&self, source: &str) -> bool {
        source.contains("Initializable")
            || source.contains("Upgradeable")
            || source.contains("initialize")
            || source.contains("_disableInitializers")
            || source.contains("UUPSUpgradeable")
            || source.contains("TransparentUpgradeable")
    }

    /// Check for selfdestruct or suicide calls
    fn has_selfdestruct(&self, source: &str) -> bool {
        source.contains("selfdestruct(") || source.contains("suicide(")
    }

    /// Find the line number of selfdestruct
    fn find_selfdestruct_line(&self, source: &str) -> Option<u32> {
        for (line_num, line) in source.lines().enumerate() {
            if line.contains("selfdestruct(") || line.contains("suicide(") {
                return Some((line_num + 1) as u32);
            }
        }
        None
    }

    /// Check if selfdestruct is protected by access control
    fn selfdestruct_has_protection(&self, source: &str) -> bool {
        // Find the function containing selfdestruct
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            if line.contains("selfdestruct(") || line.contains("suicide(") {
                // Look backwards for function definition and modifiers
                let mut func_start = i;
                for j in (0..i).rev() {
                    if lines[j].contains("function ") {
                        func_start = j;
                        break;
                    }
                }

                // Check lines from function start to selfdestruct for protection
                let func_section = lines[func_start..=i].join("\n");

                // Check for access control
                if func_section.contains("onlyOwner")
                    || func_section.contains("onlyAdmin")
                    || func_section.contains("require(msg.sender ==")
                    || func_section.contains("require(msg.sender==")
                    || func_section.contains("hasRole(")
                    || func_section.contains("_checkOwner()")
                    || func_section.contains("internal")
                    || func_section.contains("private")
                {
                    return true;
                }
            }
        }
        false
    }

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for ImplementationSelfdestructDetector {
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        // Check if this looks like an implementation contract
        if !self.is_likely_implementation(source) {
            return Ok(findings);
        }

        // Check for selfdestruct
        if !self.has_selfdestruct(source) {
            return Ok(findings);
        }

        // Check if it's protected
        let is_protected = self.selfdestruct_has_protection(source);

        let confidence = if is_protected {
            Confidence::Low // Has some protection but still risky
        } else {
            Confidence::High
        };

        let line = self
            .find_selfdestruct_line(source)
            .unwrap_or(ctx.contract.name.location.start().line() as u32);

        let message = if is_protected {
            format!(
                "Implementation contract '{}' contains selfdestruct with access control. \
                 While protected, selfdestruct in implementations is dangerous. \
                 If an attacker gains access control, all proxies will be bricked.",
                contract_name
            )
        } else {
            format!(
                "Implementation contract '{}' contains unprotected selfdestruct. \
                 An attacker can destroy the implementation, permanently bricking all proxy contracts. \
                 This was the root cause of the $150M Parity wallet freeze.",
                contract_name
            )
        };

        let finding = self
            .base
            .create_finding(ctx, message, line, 0, 12) // "selfdestruct" length
            .with_cwe(284) // CWE-284: Improper Access Control
            .with_cwe(670) // CWE-670: Always-Incorrect Control Flow Implementation
            .with_swc("SWC-106")
            .with_confidence(confidence)
            .with_fix_suggestion(
                "Remove selfdestruct from implementation contracts entirely. \
                 If you need emergency functionality:\n\n\
                 1. Use a pause mechanism instead of selfdestruct\n\
                 2. Implement upgrades to migrate to a new implementation\n\
                 3. If selfdestruct is absolutely necessary, add multi-sig + timelock protection\n\n\
                 Note: Post-Dencun, selfdestruct only deletes storage in same-tx creation."
                    .to_string(),
            );

        findings.push(finding);

        let findings = crate::utils::filter_fp_findings(findings, ctx);
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
        let detector = ImplementationSelfdestructDetector::new();
        assert_eq!(
            detector.name(),
            "Implementation Contract Contains selfdestruct"
        );
        assert_eq!(detector.default_severity(), Severity::Critical);
    }

    #[test]
    fn test_has_selfdestruct() {
        let detector = ImplementationSelfdestructDetector::new();
        assert!(detector.has_selfdestruct("selfdestruct(payable(owner))"));
        assert!(detector.has_selfdestruct("suicide(owner)")); // Legacy
        assert!(!detector.has_selfdestruct("transfer(owner)"));
    }

    #[test]
    fn test_selfdestruct_protection() {
        let detector = ImplementationSelfdestructDetector::new();

        let protected = r#"
            function destroy() public onlyOwner {
                selfdestruct(payable(owner));
            }
        "#;
        assert!(detector.selfdestruct_has_protection(protected));

        let unprotected = r#"
            function destroy() public {
                selfdestruct(payable(msg.sender));
            }
        "#;
        assert!(!detector.selfdestruct_has_protection(unprotected));
    }
}
