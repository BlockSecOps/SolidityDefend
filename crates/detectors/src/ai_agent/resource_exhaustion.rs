//! AI Agent Resource Exhaustion Detector

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use anyhow::Result;
use std::any::Any;

pub struct AIAgentResourceExhaustionDetector {
    base: BaseDetector,
}

impl AIAgentResourceExhaustionDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("ai-agent-resource-exhaustion".to_string()),
                "AI Agent Resource Exhaustion".to_string(),
                "Detects computational DOS attacks via resource exhaustion".to_string(),
                vec![DetectorCategory::Logic],
                Severity::Medium,
            ),
        }
    }
}

impl Default for AIAgentResourceExhaustionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for AIAgentResourceExhaustionDetector {
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

        let lower = ctx.source_code.to_lowercase();

        if lower.contains("aicompute") || lower.contains("inference") || lower.contains("modelrun")
        {
            let has_gas_limit = lower.contains("gasleft()") || lower.contains("gas limit");
            let has_rate_limit = lower.contains("ratelimit") || lower.contains("cooldown");

            if !has_gas_limit && !has_rate_limit {
                findings.push(self.base.create_finding(
                    ctx,
                    "AI computation lacks gas/rate limits - resource exhaustion possible".to_string(),
                    1, 1, ctx.source_code.len() as u32,
                ).with_fix_suggestion("Add rate limiting: require(lastCall[msg.sender] + COOLDOWN < block.timestamp)".to_string()));
            }
        }
        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
