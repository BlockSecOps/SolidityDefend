use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for beacon proxy single point of failure
///
/// Detects patterns where beacon proxy architectures create centralization risks.
/// If a beacon contract is compromised or destroyed, all proxies relying on it fail.
///
/// Vulnerable patterns:
/// ```solidity
/// contract Factory {
///     address immutable beacon; // Single point of failure
///     function createClone() external {
///         BeaconProxy proxy = new BeaconProxy(beacon, "");
///     }
/// }
/// ```
pub struct BeaconSinglePointOfFailureDetector {
    base: BaseDetector,
}

impl Default for BeaconSinglePointOfFailureDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BeaconSinglePointOfFailureDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("beacon-single-point-of-failure"),
                "Beacon Single Point of Failure".to_string(),
                "Detects beacon proxy patterns that create single points of failure. \
                 If the beacon contract is compromised, deleted, or has a bug, all proxies \
                 pointing to it will be affected simultaneously."
                    .to_string(),
                vec![
                    DetectorCategory::Upgradeable,
                    DetectorCategory::AccessControl,
                ],
                Severity::High,
            ),
        }
    }

    /// Check if contract is a beacon factory
    fn is_beacon_factory(&self, source: &str) -> bool {
        (source.contains("BeaconProxy") || source.contains("UpgradeableBeacon"))
            && (source.contains("create") || source.contains("clone") || source.contains("deploy"))
    }

    /// Check for immutable beacon address pattern
    fn has_immutable_beacon(&self, source: &str) -> Option<u32> {
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if (trimmed.contains("immutable") || trimmed.contains("constant"))
                && (trimmed.contains("beacon") || trimmed.contains("Beacon"))
                && trimmed.contains("address")
            {
                return Some(line_num as u32 + 1);
            }
        }
        None
    }

    /// Check for multiple beacon proxy creations from same beacon
    fn _has_multiple_proxy_creations(&self, source: &str) -> Option<(u32, u32)> {
        let lines: Vec<&str> = source.lines().collect();
        let mut creation_lines = Vec::new();

        for (line_num, line) in lines.iter().enumerate() {
            if line.contains("new BeaconProxy") || line.contains("BeaconProxy(") {
                creation_lines.push(line_num as u32 + 1);
            }
        }

        if creation_lines.len() > 1 {
            Some((creation_lines[0], creation_lines.len() as u32))
        } else {
            None
        }
    }

    /// Check for beacon without upgrade timelock
    fn has_beacon_without_timelock(&self, source: &str) -> Option<u32> {
        let lines: Vec<&str> = source.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            // Look for upgradeTo in beacon context without timelock
            if trimmed.contains("function upgradeTo")
                || trimmed.contains("function upgrade")
                || trimmed.contains("_upgradeTo")
            {
                // Check if there's a timelock reference nearby
                let context_start = if line_num > 10 { line_num - 10 } else { 0 };
                let context_end = std::cmp::min(line_num + 20, lines.len());
                let context: String = lines[context_start..context_end].join("\n");

                if !context.contains("timelock")
                    && !context.contains("TimeLock")
                    && !context.contains("delay")
                    && !context.contains("Delay")
                {
                    return Some(line_num as u32 + 1);
                }
            }
        }
        None
    }

    /// Check if contract uses UpgradeableBeacon
    fn is_beacon_contract(&self, source: &str) -> bool {
        source.contains("UpgradeableBeacon")
            || source.contains("IBeacon")
            || source.contains("implementation() external")
    }

    /// Get contract name
    fn get_contract_name(&self, ctx: &AnalysisContext) -> String {
        ctx.contract.name.name.to_string()
    }
}

impl Detector for BeaconSinglePointOfFailureDetector {
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

        let source = &ctx.source_code;
        let contract_name = self.get_contract_name(ctx);

        // Check for beacon factory patterns
        if self.is_beacon_factory(source) {
            // Check for immutable beacon
            if let Some(line) = self.has_immutable_beacon(source) {
                let message = format!(
                    "Factory contract '{}' stores beacon address as immutable. If the beacon \
                     contract is compromised, self-destructs, or has a bug, the factory will \
                     be permanently broken with no recovery mechanism.",
                    contract_name
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 1, 30)
                    .with_cwe(284) // CWE-284: Improper Access Control
                    .with_confidence(Confidence::High)
                    .with_fix_suggestion(
                        "Consider making the beacon address upgradeable with proper access control:\n\n\
                         address public beacon;\n\n\
                         function setBeacon(address newBeacon) external onlyOwner {\n\
                             require(IBeacon(newBeacon).implementation() != address(0));\n\
                             beacon = newBeacon;\n\
                         }\n\n\
                         Or implement a fallback beacon mechanism."
                            .to_string(),
                    );

                findings.push(finding);
            }
        }

        // Check for beacon contracts without timelock
        if self.is_beacon_contract(source) {
            if let Some(line) = self.has_beacon_without_timelock(source) {
                let message = format!(
                    "Beacon contract '{}' allows immediate upgrades without a timelock. \
                     Malicious or accidental upgrades will immediately affect all proxy contracts \
                     using this beacon, with no time for users to react.",
                    contract_name
                );

                let finding = self
                    .base
                    .create_finding(ctx, message, line, 1, 30)
                    .with_cwe(284) // CWE-284: Improper Access Control
                    .with_confidence(Confidence::Medium)
                    .with_fix_suggestion(
                        "Add a timelock to beacon upgrades:\n\n\
                         uint256 public constant UPGRADE_DELAY = 2 days;\n\
                         address public pendingImplementation;\n\
                         uint256 public upgradeTimestamp;\n\n\
                         function proposeUpgrade(address newImpl) external onlyOwner {\n\
                             pendingImplementation = newImpl;\n\
                             upgradeTimestamp = block.timestamp + UPGRADE_DELAY;\n\
                         }\n\n\
                         function executeUpgrade() external {\n\
                             require(block.timestamp >= upgradeTimestamp);\n\
                             _upgradeTo(pendingImplementation);\n\
                         }"
                        .to_string(),
                    );

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = BeaconSinglePointOfFailureDetector::new();
        assert_eq!(detector.name(), "Beacon Single Point of Failure");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_is_beacon_factory() {
        let detector = BeaconSinglePointOfFailureDetector::new();

        let factory_code = r#"
            contract Factory {
                function createProxy() external {
                    new BeaconProxy(beacon, "");
                }
            }
        "#;
        assert!(detector.is_beacon_factory(factory_code));

        let non_factory = r#"
            contract SimpleToken {
                function transfer() external {}
            }
        "#;
        assert!(!detector.is_beacon_factory(non_factory));
    }

    #[test]
    fn test_immutable_beacon() {
        let detector = BeaconSinglePointOfFailureDetector::new();

        let vulnerable = r#"
            contract Factory {
                address immutable beacon;
            }
        "#;
        assert!(detector.has_immutable_beacon(vulnerable).is_some());

        let safe = r#"
            contract Factory {
                address public beacon;
            }
        "#;
        assert!(detector.has_immutable_beacon(safe).is_none());
    }

    #[test]
    fn test_is_beacon_contract() {
        let detector = BeaconSinglePointOfFailureDetector::new();

        assert!(detector.is_beacon_contract("contract X is UpgradeableBeacon {}"));
        assert!(detector.is_beacon_contract("contract X is IBeacon {}"));
        assert!(!detector.is_beacon_contract("contract SimpleToken {}"));
    }
}
