//! Advanced Access Control Security Detectors
//!
//! This module provides advanced security analysis for access control vulnerabilities,
//! addressing $953.2M in losses from access control issues in 2024 alone (67% of total losses).
//!
//! ## Detectors (5 total)
//!
//! 1. **role-hierarchy-bypass** (CRITICAL)
//!    - Detects role hierarchy violations in OpenZeppelin AccessControl
//!    - Real-world: KiloEx DEX $7M loss (2024)
//!
//! 2. **time-locked-admin-bypass** (CRITICAL)
//!    - Detects timelock circumvention and missing delay enforcement
//!    - Real-world: Instant rug pulls despite timelock promises
//!
//! 3. **multi-role-confusion** (HIGH)
//!    - Detects functions with contradictory role requirements
//!    - Real-world: Inconsistent access enforcement
//!
//! 4. **privilege-escalation-paths** (HIGH)
//!    - Detects indirect paths to gain higher privileges
//!    - Real-world: Function chains that escalate access
//!
//! 5. **guardian-role-centralization** (MEDIUM)
//!    - Detects guardian/emergency roles with excessive power
//!    - Real-world: Single point of failure, rug pull risk

pub mod role_hierarchy_bypass;
pub mod time_locked_admin_bypass;
pub mod multi_role_confusion;
pub mod privilege_escalation_paths;
pub mod guardian_role_centralization;

// Re-export detectors
pub use role_hierarchy_bypass::RoleHierarchyBypassDetector;
pub use time_locked_admin_bypass::TimeLockedAdminBypassDetector;
pub use multi_role_confusion::MultiRoleConfusionDetector;
pub use privilege_escalation_paths::PrivilegeEscalationPathsDetector;
pub use guardian_role_centralization::GuardianRoleCentralizationDetector;
