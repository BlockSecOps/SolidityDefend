use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for transparent proxy admin issues
///
/// In transparent proxies, the admin cannot call implementation functions
/// (they are routed to admin-only functions). This can cause issues if:
/// 1. Admin tries to interact with implementation (calls fail silently)
/// 2. Admin address is used for both admin and user operations
/// 3. Admin function selectors clash with implementation
pub struct TransparentProxyAdminIssuesDetector {
    base: BaseDetector,
}

impl Default for TransparentProxyAdminIssuesDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl TransparentProxyAdminIssuesDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("transparent-proxy-admin-issues"),
                "Transparent Proxy Admin Issues".to_string(),
                "Detects potential issues with transparent proxy admin patterns including \
                 selector conflicts and admin routing problems"
                    .to_string(),
                vec![DetectorCategory::Upgradeable, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }

    /// Check if contract is a transparent proxy
    fn is_transparent_proxy(&self, source: &str) -> bool {
        source.contains("TransparentUpgradeableProxy")
            || source.contains("TransparentProxy")
            || (source.contains("_admin()") && source.contains("_fallback()"))
            || (source.contains("ifAdmin") && source.contains("delegatecall"))
    }

    /// Check for admin-related issues
    fn find_admin_issues(&self, source: &str) -> Vec<(u32, String)> {
        let mut issues = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            // Check for admin calling implementation functions
            if line.contains("admin.call(") || line.contains("admin.delegatecall(") {
                issues.push((
                    (i + 1) as u32,
                    "Admin address used for delegatecall - admin cannot call implementation functions in transparent proxy pattern".to_string()
                ));
            }

            // Check for missing ifAdmin modifier on admin functions
            if (line.contains("function upgradeTo")
                || line.contains("function changeAdmin")
                || line.contains("function admin()"))
                && !line.contains("ifAdmin")
                && source.contains("TransparentUpgradeableProxy")
            {
                issues.push((
                    (i + 1) as u32,
                    "Admin function may be missing ifAdmin modifier".to_string(),
                ));
            }

            // Check for potential admin address reuse
            if line.contains("admin = msg.sender") && source.contains("initialize") {
                issues.push((
                    (i + 1) as u32,
                    "Setting admin to msg.sender in initializer - admin should be separate from users".to_string()
                ));
            }
        }

        issues
    }

    /// Check for implementation contracts that might conflict
    fn check_implementation_conflicts(&self, source: &str) -> Vec<(u32, String)> {
        let mut issues = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // If this is an implementation, check for admin-like functions
        if source.contains("Initializable") || source.contains("Upgradeable") {
            for (i, line) in lines.iter().enumerate() {
                // Functions that could clash with transparent proxy admin
                let clash_patterns = [
                    ("function admin(", "admin()"),
                    ("function upgradeTo(", "upgradeTo(address)"),
                    ("function implementation(", "implementation()"),
                ];

                for (pattern, name) in &clash_patterns {
                    if line.contains(*pattern) {
                        issues.push((
                            (i + 1) as u32,
                            format!(
                                "Function '{}' in implementation will be unreachable by admin in transparent proxy pattern",
                                name
                            ),
                        ));
                    }
                }
            }
        }

        issues
    }

    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for TransparentProxyAdminIssuesDetector {
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

        // Check transparent proxy specific issues
        if self.is_transparent_proxy(source) {
            let issues = self.find_admin_issues(source);

            for (line, issue_desc) in issues {
                let message = format!("Transparent proxy '{}': {}", contract_name, issue_desc);

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 0, 20)
                    .with_cwe(436) // CWE-436: Interpretation Conflict
                    .with_confidence(Confidence::Medium)
                    .with_fix_suggestion(
                        "Ensure admin operations and user operations use separate addresses. \
                         The admin address can only call admin functions, not implementation functions."
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        // Check implementation contracts for conflicts
        let conflicts = self.check_implementation_conflicts(source);
        for (line, issue_desc) in conflicts {
            let message = format!(
                "Implementation contract '{}': {}",
                contract_name, issue_desc
            );

            let finding = self
                .base
                .create_finding(ctx, message, line, 0, 20)
                .with_cwe(436)
                .with_confidence(Confidence::Low)
                .with_fix_suggestion(
                    "Rename functions that clash with transparent proxy admin functions. \
                     Consider using UUPS pattern if implementation needs these function names."
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
        let detector = TransparentProxyAdminIssuesDetector::new();
        assert_eq!(detector.name(), "Transparent Proxy Admin Issues");
        assert_eq!(detector.default_severity(), Severity::High);
    }

    #[test]
    fn test_is_transparent_proxy() {
        let detector = TransparentProxyAdminIssuesDetector::new();
        assert!(detector.is_transparent_proxy("contract MyProxy is TransparentUpgradeableProxy {"));
        assert!(!detector.is_transparent_proxy("contract MyToken {"));
    }
}
