//! AI Agent Security Detectors
//!
//! This module provides security analysis for AI-powered autonomous contracts
//! and AI agent systems interacting with smart contracts.
//!
//! ## Detectors (4 total)
//!
//! 1. **ai-agent-prompt-injection** (HIGH)
//!    - Prompt injection in AI contracts
//!    - Real-world: Malicious prompt manipulation
//!
//! 2. **ai-agent-decision-manipulation** (HIGH)
//!    - AI decision manipulation
//!    - Real-world: Oracle/input poisoning
//!
//! 3. **autonomous-contract-oracle-dependency** (MEDIUM)
//!    - Oracle dependency in autonomous contracts
//!    - Real-world: Single point of failure
//!
//! 4. **ai-agent-resource-exhaustion** (MEDIUM)
//!    - Resource exhaustion attacks
//!    - Real-world: Computational DOS

pub mod decision_manipulation;
pub mod oracle_dependency;
pub mod prompt_injection;
pub mod resource_exhaustion;

// Re-export detectors
pub use decision_manipulation::AIAgentDecisionManipulationDetector;
pub use oracle_dependency::AutonomousContractOracleDependencyDetector;
pub use prompt_injection::AIAgentPromptInjectionDetector;
pub use resource_exhaustion::AIAgentResourceExhaustionDetector;
