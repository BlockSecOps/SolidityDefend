//! ERC-721 Enumeration DOS Detector
//!
//! Detects enumeration gas bombs in ERC-721 implementations.
//! Unbounded loops over token ownership can cause DOS.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct ERC721EnumerationDosDetector {
    base: BaseDetector,
}

impl ERC721EnumerationDosDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("erc721-enumeration-dos".to_string()),
                "ERC-721 Enumeration DOS".to_string(),
                "Detects enumeration gas bombs in ERC-721 implementations".to_string(),
                vec![DetectorCategory::DeFi],
                Severity::Medium,
            ),
        }
    }
}

impl Default for ERC721EnumerationDosDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for ERC721EnumerationDosDetector {
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

        // Check for ERC-721 enumerable
        let is_erc721_enum = lower.contains("ierc721enumerable")
            || lower.contains("erc721enumerable")
            || (lower.contains("tokenofownerbyindex") && lower.contains("tokenbyindex"));

        if !is_erc721_enum {
            return Ok(findings);
        }

        // Pattern 1: tokenOfOwnerByIndex in unbounded loop
        if lower.contains("tokenofownerbyindex") {
            let has_loop = lower.contains("for (")
                || lower.contains("while");

            let has_balance_loop = lower.contains("balanceof")
                && has_loop;

            if has_balance_loop {
                let finding = self.base.create_finding(
                    ctx,
                    "Loop over owner's tokens using balanceOf - gas bomb if owner has many tokens".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add maximum iteration limit or use off-chain enumeration with pagination".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 2: totalSupply iteration without bounds
        if lower.contains("totalsupply") {
            let has_total_supply_loop = lower.contains("for (uint")
                && lower.contains("totalsupply");

            if has_total_supply_loop {
                let finding = self.base.create_finding(
                    ctx,
                    "Loop iterating over totalSupply - unbounded gas cost as collection grows".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Avoid on-chain enumeration of entire collection; use events and off-chain indexing".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 3: No pagination in enumeration functions
        let has_enum_function = lower.contains("function getalltokens")
            || lower.contains("function getownertokens")
            || lower.contains("function listtokens");

        if has_enum_function {
            let has_pagination = lower.contains("offset")
                || lower.contains("limit")
                || lower.contains("pagesize");

            if !has_pagination {
                let finding = self.base.create_finding(
                    ctx,
                    "Token enumeration function lacks pagination - can exceed block gas limit".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Add pagination parameters: function getTokens(uint256 offset, uint256 limit)".to_string()
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
