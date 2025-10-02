use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

pub struct SandwichAttackDetector { base: BaseDetector }
pub struct FrontRunningDetector { base: BaseDetector }

impl SandwichAttackDetector {
    pub fn new() -> Self {
        Self { base: BaseDetector::new(DetectorId("sandwich-attack".to_string()), "Sandwich Attack".to_string(), "Vulnerable to sandwich attacks".to_string(), vec![DetectorCategory::MEV], Severity::Medium) }
    }
}

impl FrontRunningDetector {
    pub fn new() -> Self {
        Self { base: BaseDetector::new(DetectorId("front-running".to_string()), "Front Running".to_string(), "Vulnerable to front-running attacks".to_string(), vec![DetectorCategory::MEV], Severity::Medium) }
    }
}

impl Detector for SandwichAttackDetector {
    fn id(&self) -> DetectorId { self.base.id.clone() }
    fn name(&self) -> &str { &self.base.name }
    fn description(&self) -> &str { &self.base.description }
    fn default_severity(&self) -> Severity { self.base.default_severity }
    fn categories(&self) -> Vec<DetectorCategory> { self.base.categories.clone() }
    fn is_enabled(&self) -> bool { self.base.enabled }
    fn detect(&self, _ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> { Ok(Vec::new()) }
    fn as_any(&self) -> &dyn Any { self }
}

impl Detector for FrontRunningDetector {
    fn id(&self) -> DetectorId { self.base.id.clone() }
    fn name(&self) -> &str { &self.base.name }
    fn description(&self) -> &str { &self.base.description }
    fn default_severity(&self) -> Severity { self.base.default_severity }
    fn categories(&self) -> Vec<DetectorCategory> { self.base.categories.clone() }
    fn is_enabled(&self) -> bool { self.base.enabled }
    fn detect(&self, _ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> { Ok(Vec::new()) }
    fn as_any(&self) -> &dyn Any { self }
}
