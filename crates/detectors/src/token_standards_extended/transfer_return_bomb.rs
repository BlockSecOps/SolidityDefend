//! ERC-20 Transfer Return Bomb Detector
//!
//! Detects return data bombs that can cause DOS via excessive return data size.
//! Malicious ERC-20 tokens can return huge amounts of data to exhaust gas.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct ERC20TransferReturnBombDetector {
    base: BaseDetector,
}

impl ERC20TransferReturnBombDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("erc20-transfer-return-bomb".to_string()),
                "ERC-20 Transfer Return Bomb".to_string(),
                "Detects return data bombs in ERC-20 token interactions".to_string(),
                vec![DetectorCategory::DeFi],
                Severity::Medium,
            ),
        }
    }
}

impl Default for ERC20TransferReturnBombDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for ERC20TransferReturnBombDetector {
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

        // Check for token transfers
        let has_transfer = lower.contains("transfer(")
            || lower.contains("transferfrom(")
            || lower.contains("ierc20");

        if !has_transfer {
            return Ok(findings);
        }

        // Pattern 1: Unchecked return data size from transfer
        let has_token_call = lower.contains(".transfer(") || lower.contains(".transferfrom(");

        if has_token_call {
            let uses_returndatasize =
                lower.contains("returndatasize") || lower.contains("returndata.length");

            let has_size_limit =
                lower.contains("require(returndatasize") || lower.contains("if (returndatasize");

            if !uses_returndatasize || !has_size_limit {
                let finding = self.base.create_finding(
                    ctx,
                    "Token transfer lacks return data size validation - vulnerable to return bomb DOS".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Check returndatasize() and reject if excessive (>64 bytes): require(returndatasize() <= 64)".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: Using low-level call for transfers without gas limit
        if has_token_call {
            let uses_call = lower.contains(".call(") || lower.contains(".call{");

            if uses_call {
                let has_gas_limit = lower.contains(".call{gas:") || lower.contains("gasleft()");

                if !has_gas_limit {
                    let finding = self.base.create_finding(
                        ctx,
                        "Low-level call to token without gas limit - return bomb can exhaust all gas".to_string(),
                        1,
                        1,
                        ctx.source_code.len() as u32,
                    )
                    .with_fix_suggestion(
                        "Specify gas limit for calls: token.call{gas: 100000}(abi.encodeWithSelector(...))".to_string()
                    );

                    findings.push(finding);
                }
            }
        }

        // Pattern 3: Copying return data without size check
        if has_token_call {
            let copies_returndata =
                lower.contains("returndatacopy") || lower.contains("abi.decode(returndata");

            if copies_returndata {
                let finding = self.base.create_finding(
                    ctx,
                    "Return data copied without size validation - DOS via excessive return data".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Validate returndatasize before copying: require(returndatasize() <= MAX_SIZE)".to_string()
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
