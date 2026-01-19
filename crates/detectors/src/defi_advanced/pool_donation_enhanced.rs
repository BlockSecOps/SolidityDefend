//! Pool Donation Attack Enhanced Detector
//!
//! Detects advanced pool donation attacks where an attacker:
//! 1. Becomes the first depositor in an empty pool/vault
//! 2. Donates tokens directly to the pool (not through deposit function)
//! 3. Inflates the share price to make small deposits round down to zero shares
//! 4. Steals subsequent depositors' funds
//!
//! This enhanced version specifically targets:
//! - ERC-4626 vault share inflation attacks
//! - AMM pool initialization vulnerabilities
//! - Missing virtual/dead shares protection
//! - Unprotected share price calculations

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils::is_test_contract;

pub struct PoolDonationEnhancedDetector {
    base: BaseDetector,
}

impl PoolDonationEnhancedDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("pool-donation-enhanced".to_string()),
                "Pool Donation Attack Enhanced".to_string(),
                "Detects advanced pool donation attacks including ERC-4626 share inflation and first-depositor manipulation vulnerabilities".to_string(),
                vec![DetectorCategory::DeFi, DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }
}

impl Default for PoolDonationEnhancedDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for PoolDonationEnhancedDetector {
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
        let source = &ctx.source_code;
        let lower = source.to_lowercase();

        // Phase 9 FP Reduction: Skip test contracts
        if is_test_contract(ctx) {
            return Ok(findings);
        }

        // Check for OpenZeppelin ERC4626 implementation which has built-in protection
        // OZ uses _decimalsOffset for virtual shares/assets protection
        let is_oz_erc4626 = source.contains("@openzeppelin")
            || source.contains("openzeppelin-contracts")
            || lower.contains("_decimalsoffset")
            || lower.contains("erc4626upgradeable")
            || (lower.contains("openzeppelin") && lower.contains("erc4626"));

        // If using OpenZeppelin's ERC4626, it has built-in protection
        if is_oz_erc4626 {
            return Ok(findings); // OZ implementation is battle-tested
        }

        // Check if contract uses balance for calculations (used in multiple checks)
        let uses_balance = lower.contains("balanceof(address(this))")
            || lower.contains("this.balance")
            || lower.contains("totalassets");

        // Check for ERC-4626 vault implementation
        let is_erc4626 = lower.contains("erc4626")
            || (lower.contains("deposit") && lower.contains("shares"))
            || lower.contains("converttoassets")
            || lower.contains("converttoshares");

        if is_erc4626 {
            // Check for initial share protection
            let has_initial_shares = lower.contains("initial_shares")
                || lower.contains("minimum_shares")
                || lower.contains("dead_shares")
                || lower.contains("virtual_shares")
                || lower.contains("virtual_assets")
                || lower.contains("_decimalsoffset"); // OZ pattern

            if !has_initial_shares {
                let finding = self.base.create_finding(
                    ctx,
                    "ERC-4626 vault lacks initial share protection - vulnerable to share inflation attack".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Mint initial dead shares or use virtual shares/assets in share calculation to prevent first-depositor manipulation. Consider using OpenZeppelin's ERC4626 which has built-in protection.".to_string()
                );

                findings.push(finding);
            }
        }

        // Check for share calculation vulnerable to donation
        let has_share_calc = lower.contains("shares =")
            || lower.contains("return shares")
            || lower.contains("converttoshares");

        if has_share_calc && uses_balance {
            // Check for protection against direct transfers
            let has_donation_protection = lower.contains("virtual_balance")
                || lower.contains("stored_balance")
                || lower.contains("accounted_balance")
                || lower.contains("require(totalsupply");

            if !has_donation_protection {
                let finding = self.base.create_finding(
                    ctx,
                    "Share calculation uses contract balance directly - vulnerable to donation attack via direct transfer".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Track balances internally instead of using balanceOf(), or use virtual assets/shares in calculations".to_string()
                );

                findings.push(finding);
            }
        }

        // Check for minimum deposit amount
        let has_deposit = lower.contains("function deposit")
            || lower.contains("function mint")
            || lower.contains("addliquidity");

        if has_deposit {
            let has_minimum = lower.contains("minimum_deposit")
                || lower.contains("min_deposit")
                || lower.contains("require(amount >=")
                || lower.contains("require(shares >");

            if !has_minimum {
                let finding = self.base.create_finding(
                    ctx,
                    "No minimum deposit requirement - small deposits may round down to zero shares".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Enforce minimum deposit amount or minimum shares minted to prevent rounding attacks".to_string()
                );

                findings.push(finding);
            }
        }

        // Check for pool initialization protection
        let has_initialization = lower.contains("initialize")
            || lower.contains("init")
            || (lower.contains("constructor") && has_deposit);

        if has_initialization {
            let has_init_protection = lower.contains("require(totalsupply() == 0")
                || lower.contains("require(!initialized")
                || lower.contains("initializer")
                || lower.contains("minimum_liquidity");

            let has_init_deposit = lower.contains("initial_deposit")
                || lower.contains("bootstrap_deposit")
                || lower.contains("seed_liquidity");

            if !has_init_protection && !has_init_deposit {
                let finding = self.base.create_finding(
                    ctx,
                    "Pool initialization lacks protection - first depositor can manipulate initial share price".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Require minimum initial deposit, mint dead shares on initialization, or use time-delayed activation".to_string()
                );

                findings.push(finding);
            }
        }

        // Check for preview functions that might be manipulated
        let has_preview = lower.contains("previewdeposit")
            || lower.contains("previewmint")
            || lower.contains("previewredeem");

        if has_preview && uses_balance {
            let has_preview_protection = lower.contains("// note:")
                || lower.contains("// warning:")
                || lower.contains("unchecked");

            if !has_preview_protection {
                let finding = self.base.create_finding(
                    ctx,
                    "Preview functions use manipulable balance - can be exploited for front-running attacks".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Document that preview functions are manipulable via donations, or use stored balances instead".to_string()
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
