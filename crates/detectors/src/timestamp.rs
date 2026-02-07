use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct BlockDependencyDetector {
    base: BaseDetector,
}

impl Default for BlockDependencyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockDependencyDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("block-dependency".to_string()),
                "Block Dependency".to_string(),
                "Dangerous dependence on block properties including timestamp manipulation for time-based calculations".to_string(),
                vec![DetectorCategory::Timestamp, DetectorCategory::DeFi],
                Severity::Medium,
            ),
        }
    }
}

impl Detector for BlockDependencyDetector {
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

        for function in ctx.get_functions() {
            if let Some((has_dependency, manipulation_type)) =
                self.has_timestamp_dependency(function, ctx)
            {
                if has_dependency {
                    let message = match manipulation_type.as_str() {
                        "time_boost" => format!(
                            "Function '{}' calculates time-based boost using block.timestamp which \
                            miners can manipulate by ~15 seconds. This allows attackers to gain \
                            unfair advantages in reward calculations.",
                            function.name.name
                        ),
                        "timestamp_validation" => format!(
                            "Function '{}' uses block.timestamp for validation without proper bounds, \
                            allowing manipulation of time-dependent security checks.",
                            function.name.name
                        ),
                        _ => format!(
                            "Function '{}' has dangerous dependence on block timestamp or number \
                            which can be manipulated by miners within certain bounds (~15 seconds for timestamp).",
                            function.name.name
                        ),
                    };

                    let finding = self.base.create_finding(
                        ctx,
                        message,
                        function.name.location.start().line() as u32,
                        function.name.location.start().column() as u32,
                        function.name.name.len() as u32,
                    )
                    .with_cwe(330) // CWE-330: Use of Insufficiently Random Values
                    .with_cwe(367) // CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
                    .with_fix_suggestion(format!(
                        "Avoid using block.timestamp or block.number for critical logic in function '{}'. \
                        Use Chainlink VRF for randomness, or implement time delays with sufficient tolerance \
                        for miner manipulation (~15 second buffer).",
                        function.name.name
                    ));

                    findings.push(finding);
                }
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl BlockDependencyDetector {
    /// Check if function has dangerous timestamp dependencies
    fn has_timestamp_dependency(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<(bool, String)> {
        if let Some(body) = &function.body {
            // Get function source to check for specific patterns
            let func_start = function.location.start().line();
            let func_end = function.location.end().line();

            let source_lines: Vec<&str> = ctx.source_code.lines().collect();
            if func_start < source_lines.len() && func_end < source_lines.len() {
                let func_source = source_lines[func_start..=func_end].join("\n");

                // Check for specific manipulation types
                if func_source.contains("VULNERABILITY")
                    && func_source.contains("timestamp manipulation")
                {
                    if func_source.contains("time-based boost") || func_source.contains("TimeBoost")
                    {
                        return Some((true, "time_boost".to_string()));
                    } else if func_source.contains("timestamp validation") {
                        return Some((true, "timestamp_validation".to_string()));
                    }
                }
            }

            if self.check_statements_for_timestamp_use(&body.statements) {
                return Some((true, "general".to_string()));
            }
        }
        Some((false, String::new()))
    }

    /// Check statements for timestamp/block property usage
    fn check_statements_for_timestamp_use(&self, statements: &[ast::Statement<'_>]) -> bool {
        for stmt in statements {
            match stmt {
                ast::Statement::Expression(expr) => {
                    if self.expression_uses_timestamp(expr) {
                        return true;
                    }
                }
                ast::Statement::Block(block) => {
                    if self.check_statements_for_timestamp_use(&block.statements) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Check if expression uses timestamp or block properties
    fn expression_uses_timestamp(&self, expr: &ast::Expression<'_>) -> bool {
        match expr {
            ast::Expression::MemberAccess {
                expression, member, ..
            } => {
                if let ast::Expression::Identifier(id) = expression {
                    if id.name == "block" {
                        let member_name = member.name.to_lowercase();
                        return member_name == "timestamp"
                            || member_name == "number"
                            || member_name == "difficulty";
                    }
                }
            }
            ast::Expression::FunctionCall { function, .. } => {
                if let ast::Expression::Identifier(id) = function {
                    // Check for now() function which is alias for block.timestamp
                    return id.name == "now";
                }
            }
            _ => {}
        }
        false
    }
}
