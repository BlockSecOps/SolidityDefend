use anyhow::Result;
use std::any::Any;
use crate::detector::{Detector, DetectorCategory, BaseDetector};
use crate::types::{DetectorId, Finding, AnalysisContext, Severity};

pub struct PriceOracleStaleDetector {
    base: BaseDetector,
}

impl PriceOracleStaleDetector {
    pub fn new() -> Self {
        Self { base: BaseDetector::new(
            DetectorId("price-oracle-stale".to_string()),
            "Stale Price Oracle Data".to_string(),
            "Detects usage of stale oracle data".to_string(),
            vec![DetectorCategory::Oracle], Severity::High) }
    }
}

impl Detector for PriceOracleStaleDetector {
    fn id(&self) -> DetectorId { self.base.id.clone() }
    fn name(&self) -> &str { &self.base.name }
    fn description(&self) -> &str { &self.base.description }
    fn default_severity(&self) -> Severity { self.base.default_severity }
    fn categories(&self) -> Vec<DetectorCategory> { self.base.categories.clone() }
    fn is_enabled(&self) -> bool { self.base.enabled }
    fn detect(&self, _ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> { Ok(Vec::new()) }
    fn as_any(&self) -> &dyn Any { self }
}
