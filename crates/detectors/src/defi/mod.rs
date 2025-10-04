//! DeFi-specific vulnerability detectors
//!
//! This module contains detectors specifically designed for DeFi protocols,
//! including flash loan vulnerabilities, MEV attacks, and protocol-specific risks.

pub mod flash_loan;
pub mod mev;
pub mod price_manipulation;
pub mod liquidity_attacks;
pub mod governance_attacks;

pub use flash_loan::FlashLoanDetector;
pub use mev::MEVDetector;
pub use price_manipulation::PriceManipulationDetector;
pub use liquidity_attacks::LiquidityAttackDetector;
pub use governance_attacks::GovernanceAttackDetector;

use crate::types::{DetectorResult, AnalysisContext, Severity};

/// Trait for DeFi-specific vulnerability detectors
pub trait DeFiDetector {
    /// Detect DeFi-specific vulnerabilities in the given context
    fn detect_defi_vulnerabilities(&self, ctx: &AnalysisContext) -> Vec<DetectorResult>;

    /// Get the detector name
    fn name(&self) -> &'static str;

    /// Get detector description
    fn description(&self) -> &'static str;

    /// Get detector severity level
    fn severity(&self) -> Severity;

    /// Check if this detector applies to the given contract type
    fn applies_to_contract(&self, ctx: &AnalysisContext) -> bool;
}

/// Common DeFi patterns and utilities
pub struct DeFiPatterns;

impl DeFiPatterns {
    /// Check if contract uses flash loans
    pub fn uses_flash_loans(ctx: &AnalysisContext) -> bool {
        // Look for flash loan function signatures
        let flash_loan_signatures = [
            "flashLoan",
            "flashBorrow",
            "flashSwap",
            "flashBorrowAndCall",
            "onFlashLoan",
            "receiveFlashLoan",
        ];

        for _func in &ctx.contract.functions {
            for signature in &flash_loan_signatures {
                if _func.name.as_str().contains(signature) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if contract interacts with AMM protocols
    pub fn interacts_with_amm(ctx: &AnalysisContext) -> bool {
        let amm_signatures = [
            "swapExactTokensForTokens",
            "swapTokensForExactTokens",
            "addLiquidity",
            "removeLiquidity",
            "getAmountsOut",
            "getAmountsIn",
            "sync",
            "skim",
        ];

        for _func in &ctx.contract.functions {
            for signature in &amm_signatures {
                if _func.name.as_str().contains(signature) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if contract has oracle dependencies
    pub fn has_oracle_dependencies(ctx: &AnalysisContext) -> bool {
        let oracle_signatures = [
            "getPrice",
            "latestRoundData",
            "decimals",
            "latestAnswer",
            "getReserves",
            "token0",
            "token1",
        ];

        for _func in &ctx.contract.functions {
            for signature in &oracle_signatures {
                if _func.name.as_str().contains(signature) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if contract manages significant value
    pub fn manages_significant_value(ctx: &AnalysisContext) -> bool {
        // Look for state variables that suggest value management
        let value_indicators = [
            "balance",
            "totalSupply",
            "reserve",
            "liquidity",
            "collateral",
            "debt",
            "stake",
            "deposit",
        ];

        for state_var in &ctx.contract.state_variables {
            for indicator in &value_indicators {
                if state_var.name.to_lowercase().contains(indicator) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if contract has time-dependent logic
    pub fn has_time_dependencies(ctx: &AnalysisContext) -> bool {
        let time_indicators = [
            "block.timestamp",
            "now",
            "block.number",
            "deadline",
            "expiry",
            "duration",
        ];

        // This would need to be integrated with the AST analysis
        // For now, check function and variable names
        for _func in &ctx.contract.functions {
            for indicator in &time_indicators {
                if ctx.source_code.contains(indicator) {
                    return true;
                }
            }
        }

        false
    }
}