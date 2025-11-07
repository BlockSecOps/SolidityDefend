//! Logic Error Patterns Detector (OWASP 2025)
//!
//! Detects common logic errors that led to $63.8M in losses in 2024-2025:
//! - Division before multiplication (precision loss)
//! - Faulty reward distribution
//! - Rounding errors in calculations

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct LogicErrorPatternsDetector {
    base: BaseDetector,
}

impl LogicErrorPatternsDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("logic-error-patterns".to_string()),
                "Logic Error Patterns".to_string(),
                "Detects division before multiplication and faulty reward calculations".to_string(),
                vec![DetectorCategory::BestPractices, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }
}

impl Default for LogicErrorPatternsDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for LogicErrorPatternsDetector {
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

        // Check for division before multiplication patterns
        if source.contains("/") && source.contains("*") {
            // Look for patterns like: (a / b) * c or a / b * c
            if source.contains("/ ") && source.contains(" * ") {
                let finding = self.base.create_finding_with_severity(
                    ctx,
                    "Potential division before multiplication - causes precision loss (OWASP 2025)".to_string(),
                    1,
                    0,
                    20,
                    Severity::High,
                ).with_fix_suggestion(
                    "❌ PRECISION LOSS ($63.8M in losses):\n\
                     uint256 reward = (amount / totalSupply) * rewardRate;\n\
                     // Result: 0 if amount < totalSupply!\n\
                     \n\
                     ✅ CORRECT ORDER:\n\
                     uint256 reward = (amount * rewardRate) / totalSupply;\n\
                     // Maximizes precision, multiply before divide\n\
                     \n\
                     ✅ BEST: Use fixed-point math:\n\
                     uint256 reward = (amount * rewardRate * 1e18) / totalSupply / 1e18;\n\
                     \n\
                     Real incidents:\n\
                     - Cork Protocol: $11M (May 2025) - Division rounding\n\
                     - SIR.trading: $355K (March 2025) - Reward calculation\n\
                     - Multiple 2024 incidents: $63.8M total".to_string()
                );
                findings.push(finding);
            }
        }

        // Check for reward distribution patterns
        let has_reward = source.contains("reward") || source.contains("Reward");
        let has_division = source.contains("/");
        let has_balance = source.contains("balance") || source.contains("Balance");

        if has_reward && has_division && has_balance {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    "Reward distribution logic detected - verify precision and rounding"
                        .to_string(),
                    1,
                    0,
                    20,
                    Severity::Medium,
                )
                .with_fix_suggestion(
                    "Common reward distribution errors:\n\
                 \n\
                 1. Integer division truncation:\n\
                    ❌ reward = balance / users;  // Loses remainder\n\
                    ✅ reward = balance * 1e18 / users / 1e18;\n\
                 \n\
                 2. Accumulating rounding errors:\n\
                    ❌ Track individual rewards that sum != total\n\
                    ✅ Use lastUser = total - sum(others)\n\
                 \n\
                 3. Division before multiplication:\n\
                    ❌ (balance / total) * multiplier\n\
                    ✅ (balance * multiplier) / total\n\
                 \n\
                 4. Missing remainder handling:\n\
                    uint256 perUser = total / userCount;\n\
                    uint256 remainder = total % userCount;\n\
                    // Handle remainder explicitly!"
                        .to_string(),
                );
            findings.push(finding);
        }

        // Check for percentage calculations
        if (source.contains("percent") || source.contains("Percent") || source.contains("%"))
            && source.contains("/")
        {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    "Percentage calculation - verify order of operations for precision".to_string(),
                    1,
                    0,
                    20,
                    Severity::Medium,
                )
                .with_fix_suggestion(
                    "Percentage calculations require careful ordering:\n\
                 \n\
                 ❌ WRONG (precision loss):\n\
                 uint256 fee = (amount / 10000) * feePercent;\n\
                 \n\
                 ✅ CORRECT:\n\
                 uint256 fee = (amount * feePercent) / 10000;\n\
                 \n\
                 ✅ BEST (with basis points):\n\
                 uint256 constant BASIS_POINTS = 10000;\n\
                 uint256 fee = (amount * feeBasisPoints) / BASIS_POINTS;\n\
                 \n\
                 Example: 250 basis points = 2.5%\n\
                 amount = 1000, feeBasisPoints = 250\n\
                 fee = (1000 * 250) / 10000 = 25 ✅\n\
                 \n\
                 WRONG order:\n\
                 fee = (1000 / 10000) * 250 = 0 * 250 = 0 ❌"
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
