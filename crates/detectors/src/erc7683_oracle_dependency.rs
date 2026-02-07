//! ERC-7683 Oracle Dependency Risk Detector

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct OracleDependencyDetector {
    base: BaseDetector,
}

impl OracleDependencyDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("erc7683-oracle-dependency".to_string()),
                "ERC-7683 Oracle Dependency".to_string(),
                "Detects risky oracle dependencies in cross-chain settlements".to_string(),
                vec![DetectorCategory::CrossChain, DetectorCategory::Oracle],
                Severity::High,
            ),
        }
    }

    fn is_erc7683_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code.to_lowercase();
        (source.contains("fillorder") || source.contains("settle"))
            && (source.contains("crosschain") || source.contains("bridge"))
    }

    fn check_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Vec<(String, Severity, String)> {
        let mut issues = Vec::new();
        let name = function.name.name.to_lowercase();

        if !name.contains("fill") && !name.contains("settle") {
            return issues;
        }

        let source = &ctx.source_code.to_lowercase();

        let uses_oracle = source.contains("latestrounddata")
            || source.contains("getprice")
            || source.contains("oracle.")
            || source.contains("pricefeed");

        if !uses_oracle {
            return issues;
        }

        let validates_staleness = source.contains("updatedat") && source.contains("timestamp");
        let has_circuit_breaker = (source.contains("price") && source.contains("max"))
            || (source.contains("price") && source.contains("min"));

        if !validates_staleness {
            issues.push((
                format!(
                    "Oracle used without staleness check in '{}'",
                    function.name.name
                ),
                Severity::High,
                "Add: require(block.timestamp - updatedAt <= MAX_DELAY);".to_string(),
            ));
        }

        if !has_circuit_breaker {
            issues.push((
                format!(
                    "Missing price bounds validation in '{}'",
                    function.name.name
                ),
                Severity::High,
                "Add: require(price >= MIN_PRICE && price <= MAX_PRICE);".to_string(),
            ));
        }

        issues
    }
}

impl Default for OracleDependencyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for OracleDependencyDetector {
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        if !self.is_erc7683_contract(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            for (title, severity, remediation) in self.check_function(function, ctx) {
                let finding = self
                    .base
                    .create_finding_with_severity(
                        ctx,
                        title,
                        function.name.location.start().line() as u32,
                        0,
                        20,
                        severity,
                    )
                    .with_cwe(829) // CWE-829: Inclusion of Functionality from Untrusted Control Sphere
                    .with_cwe(20) // CWE-20: Improper Input Validation
                    .with_fix_suggestion(remediation);
                findings.push(finding);
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
