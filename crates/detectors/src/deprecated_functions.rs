use anyhow::Result;
use std::any::Any;
use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

pub struct DeprecatedFunctionsDetector {
    base: BaseDetector,
}

impl DeprecatedFunctionsDetector {
    pub fn new() -> Self {
        Self { base: BaseDetector::new(
            DetectorId("deprecated-functions".to_string()),
            "Deprecated Functions".to_string(),
            "Detects use of deprecated functions".to_string(),
            vec![DetectorCategory::Logic], Severity::Low) }
    }
}

impl Detector for DeprecatedFunctionsDetector {
    fn id(&self) -> DetectorId { self.base.id.clone() }
    fn name(&self) -> &str { &self.base.name }
    fn description(&self) -> &str { &self.base.description }
    fn default_severity(&self) -> Severity { self.base.default_severity }
    fn categories(&self) -> Vec<DetectorCategory> { self.base.categories.clone() }
    fn is_enabled(&self) -> bool { self.base.enabled }
    fn detect(&self, _ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> { Ok(Vec::new()) }
    fn as_any(&self) -> &dyn Any { self }
}
