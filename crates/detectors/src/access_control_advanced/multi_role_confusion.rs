//! Multi-Role Confusion Detector
//!
//! Detects functions with contradictory role requirements and inconsistent access
//! patterns across similar functions.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct MultiRoleConfusionDetector {
    base: BaseDetector,
}

impl MultiRoleConfusionDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("multi-role-confusion".to_string()),
                "Multi-Role Confusion".to_string(),
                "Detects contradictory role requirements and inconsistent access patterns".to_string(),
                vec![DetectorCategory::AccessControl],
                Severity::High,
            ),
        }
    }
}

impl Default for MultiRoleConfusionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for MultiRoleConfusionDetector {
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
        let lower = ctx.source_code.to_lowercase();

        // Check for multiple role definitions
        let role_count = lower.matches("bytes32 public constant").count()
            + lower.matches("bytes32 private constant").count();

        if role_count < 2 {
            return Ok(findings);
        }

        // Pattern 1: Functions with multiple onlyRole modifiers
        if lower.contains("onlyrole") {
            // Check for potential overlapping roles on same storage variables
            let has_balance_setter = lower.contains("balance[")
                || lower.contains("balances[")
                || lower.contains("_balance");

            let has_multiple_setters = lower.matches("function set").count() > 1
                || lower.matches("function update").count() > 1;

            if has_balance_setter && has_multiple_setters {
                let finding = self.base.create_finding(
                    ctx,
                    "Multiple functions modify same storage with different role requirements - verify role separation is intentional".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Ensure clear separation of duties - same storage should not be modifiable by multiple unrelated roles".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: Inconsistent access control on paired functions
        let has_pause_unpause = lower.contains("function pause") && lower.contains("function unpause");
        let has_lock_unlock = lower.contains("function lock") && lower.contains("function unlock");

        if has_pause_unpause || has_lock_unlock {
            let finding = self.base.create_finding(
                ctx,
                "Paired functions (pause/unpause, lock/unlock) found - verify both require same or compatible roles".to_string(),
                1,
                1,
                ctx.source_code.len() as u32,
            )
            .with_fix_suggestion(
                "Paired functions should have consistent access control (same role for both or hierarchical roles)".to_string()
            );

            findings.push(finding);
        }

        // Pattern 3: Role without clear purpose
        if role_count > 3 {
            let has_role_documentation = lower.contains("/// @dev role")
                || lower.contains("// role for")
                || lower.contains("* role");

            if !has_role_documentation {
                let finding = self.base.create_finding(
                    ctx,
                    "Multiple roles defined without documentation - unclear role hierarchy and purpose".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Document each role's purpose and which functions it can access to prevent confusion".to_string()
                );

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
