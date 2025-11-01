//! MEV Protection Enhanced Security Detectors
//!
//! This module provides enhanced MEV (Maximal Extractable Value) protection analysis
//! addressing $320M+ in MEV extraction from 2024.
//!
//! ## Detectors (4 total)
//!
//! 1. **mev-sandwich-vulnerable-swaps** (HIGH)
//!    - Unprotected DEX swaps
//!    - Real-world: $320M+ MEV extraction
//!
//! 2. **mev-backrun-opportunities** (MEDIUM)
//!    - Backrunnable state changes
//!    - Real-world: Arbitrage opportunities
//!
//! 3. **mev-priority-gas-auction** (MEDIUM)
//!    - PGA-vulnerable functions
//!    - Real-world: Gas wars and failed transactions
//!
//! 4. **mev-toxic-flow-exposure** (MEDIUM)
//!    - AMM toxic flow risks
//!    - Real-world: Informed order flow exploitation

pub mod sandwich_vulnerable;
pub mod backrun_opportunities;
pub mod priority_gas_auction;
pub mod toxic_flow;

// Re-export detectors
pub use sandwich_vulnerable::MEVSandwichVulnerableDetector;
pub use backrun_opportunities::MEVBackrunOpportunitiesDetector;
pub use priority_gas_auction::MEVPriorityGasAuctionDetector;
pub use toxic_flow::MEVToxicFlowDetector;
