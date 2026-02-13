//! MEV Priority Gas Auction Detector
//!
//! Detects PGA (Priority Gas Auction) vulnerable functions.
//! Gas wars occur when multiple parties compete for same opportunity.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct MEVPriorityGasAuctionDetector {
    base: BaseDetector,
}

impl MEVPriorityGasAuctionDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("mev-priority-gas-auction".to_string()),
                "MEV Priority Gas Auction".to_string(),
                "Detects PGA-vulnerable functions causing gas wars".to_string(),
                vec![DetectorCategory::MEV],
                Severity::Medium,
            ),
        }
    }
}

impl Default for MEVPriorityGasAuctionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for MEVPriorityGasAuctionDetector {
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

        let lower = crate::utils::get_contract_source(ctx).to_lowercase();

        // FP Reduction: Only analyze contracts whose own functions are PGA-susceptible.
        // This prevents cross-contract FPs in multi-contract files.
        let contract_func_names: Vec<String> = ctx
            .contract
            .functions
            .iter()
            .map(|f| f.name.name.to_lowercase())
            .collect();
        let contract_has_pga_fn = contract_func_names.iter().any(|n| {
            n.contains("liquidat")
                || n.contains("arbitrage")
                || n.contains("rebalance")
                || n.contains("mint")
                || n.contains("flash")
        });
        if !contract_has_pga_fn {
            return Ok(findings);
        }

        // FP Reduction: Only check contracts with explicit PGA-susceptible functions.
        // Require at least one strong indicator (explicit function names).
        let has_pga_function = lower.contains("function liquidate")
            || lower.contains("function executeliquidation")
            || lower.contains("function arbitrage")
            || lower.contains("function executearbitrage")
            || lower.contains("function rebalance")
            || lower.contains("function flasharbitrage")
            || (lower.contains("function mint")
                && (lower.contains("maxsupply") || lower.contains("max_supply")));
        if !has_pga_function {
            return Ok(findings);
        }

        // Pattern 1: First-come-first-served minting — ONLY flag for NFT-style mints
        // with explicit supply caps, not for ERC20/vault/AMM mints.
        // Require maxSupply/maxMint cap pattern to indicate FCFS competition.
        let has_fcfs_mint = lower.contains("function mint")
            && (lower.contains("maxsupply")
                || lower.contains("max_supply")
                || lower.contains("maxmint")
                || lower.contains("mintlimit")
                || lower.contains("require(totalsupply() + amount <= "))
            && !lower.contains("onlyminter")
            && !lower.contains("onlyowner")
            && !lower.contains("onlyadmin")
            && !lower.contains("hasrole")
            && !lower.contains("whitelist")
            && !lower.contains("allowlist")
            && !lower.contains("reserve0")
            && !lower.contains("getreserves")
            && !lower.contains("function swap");

        if has_fcfs_mint {
            let finding = self.base.create_finding(
                ctx,
                "First-come-first-served mint with supply cap - creates PGA where users bid up gas to mint first".to_string(),
                1,
                1,
                ctx.source_code.len() as u32,
            )
            .with_fix_suggestion(
                "Use commit-reveal, whitelist, or fair launch mechanism instead of FCFS".to_string()
            );
            findings.push(finding);
        }

        // Pattern 2: Liquidation rewards to caller
        // FP Reduction: Require explicit reward/bonus payout to msg.sender in liquidation
        let has_liquidation = lower.contains("function liquidate")
            || lower.contains("function liquidateposition")
            || lower.contains("function executeliquidation");
        if has_liquidation {
            // Require EXPLICIT reward/bonus transfer to caller (not just keyword presence)
            let rewards_caller = lower.contains("msg.sender")
                && (lower.contains("liquidationbonus")
                    || lower.contains("liquidationreward")
                    || lower.contains("liquidationincentive")
                    || (lower.contains("bonus") && lower.contains("transfer(msg.sender")));

            let has_liquidation_access_control = lower.contains("onlykeeper")
                || lower.contains("onlyliquidator")
                || lower.contains("whitelistedliquidator")
                || lower.contains("onlyowner");

            if rewards_caller && !has_liquidation_access_control {
                let finding = self.base.create_finding(
                    ctx,
                    "Liquidation rewards go to caller - creates PGA where bots compete with gas price".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Use Dutch auction for liquidation bonus or distribute rewards over time".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 3: Arbitrage opportunities for anyone
        // FP Reduction: Require explicit arbitrage function names, not just buy+sell keywords
        let has_arbitrage = lower.contains("function arbitrage")
            || lower.contains("function executearbitrage")
            || lower.contains("function rebalance")
            || lower.contains("function flasharbitrage");

        if has_arbitrage {
            let is_public = lower.contains("external") || lower.contains("public");
            // FP Reduction: Skip only if dedicated keeper/bot access control
            // (onlyOwner is not sufficient — owner-operated arbitrage is still PGA-susceptible)
            let has_keeper_access_control = lower.contains("onlykeeper")
                || lower.contains("onlybot")
                || lower.contains("onlyoperator");
            // Also check if non-arbitrage token transfers exist (likely not a PGA target)
            let has_safe_transfer_pattern = lower.contains("safetransfer(")
                && !lower.contains("swap(")
                && !lower.contains("getamountout");

            if is_public && !has_keeper_access_control && !has_safe_transfer_pattern {
                let finding = self.base.create_finding(
                    ctx,
                    "Public arbitrage function - creates PGA as bots compete for profit".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Capture MEV for protocol via auction mechanism or restrict to specific keepers".to_string()
                );

                findings.push(finding);
            }
        }

        // Pattern 4: Time-sensitive operations
        let has_time_sensitive =
            lower.contains("deadline") || lower.contains("expires") || lower.contains("validuntil");

        if has_time_sensitive {
            let is_first_wins =
                lower.contains("require(!executed") || lower.contains("require(!claimed");

            if is_first_wins {
                let finding = self.base.create_finding(
                    ctx,
                    "Time-sensitive first-winner operation - creates PGA as users race before deadline".to_string(),
                    1,
                    1,
                    ctx.source_code.len() as u32,
                )
                .with_fix_suggestion(
                    "Use commit-reveal or randomized selection instead of first-wins pattern".to_string()
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
