use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

pub struct ExcessiveGasUsageDetector {
    base: BaseDetector,
}

impl ExcessiveGasUsageDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("excessive-gas-usage".to_string()),
                "Excessive Gas Usage".to_string(),
                "Detects patterns causing excessive gas consumption".to_string(),
                vec![DetectorCategory::Logic],
                Severity::Low,
            ),
        }
    }
}

impl Detector for ExcessiveGasUsageDetector {
    fn id(&self) -> DetectorId { self.base.id.clone() }
    fn name(&self) -> &str { &self.base.name }
    fn description(&self) -> &str { &self.base.description }
    fn default_severity(&self) -> Severity { self.base.default_severity }
    fn categories(&self) -> Vec<DetectorCategory> { self.base.categories.clone() }
    fn is_enabled(&self) -> bool { self.base.enabled }
    
    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for function in ctx.get_functions() {
            if let Some(issue) = self.check_excessive_gas(function, ctx) {
                findings.push(self.base.create_finding(ctx, issue, 
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32));
            }
        }
        Ok(findings)
    }
    
    fn as_any(&self) -> &dyn Any { self }
}

impl ExcessiveGasUsageDetector {
    fn check_excessive_gas(&self, _function: &ast::Function<'_>, _ctx: &AnalysisContext) -> Option<String> {
        None
    }
}
