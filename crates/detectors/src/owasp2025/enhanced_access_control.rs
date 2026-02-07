//! Enhanced Access Control Detector (OWASP 2025)
//!
//! Detects role management flaws and privilege escalation risks.
//! Access control failures led to $953M in losses in 2024.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct EnhancedAccessControlDetector {
    base: BaseDetector,
}

impl EnhancedAccessControlDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("enhanced-access-control".to_string()),
                "Enhanced Access Control".to_string(),
                "Detects role management flaws and privilege escalation ($953M impact)".to_string(),
                vec![
                    DetectorCategory::AccessControl,
                    DetectorCategory::BestPractices,
                ],
                Severity::Critical,
            ),
        }
    }
}

impl Default for EnhancedAccessControlDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for EnhancedAccessControlDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
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

        // Check for role-based access control
        let has_roles =
            source.contains("role") || source.contains("Role") || source.contains("AccessControl");

        // Check for grant/revoke functions
        let has_grant = source.contains("grant") || source.contains("Grant");
        let has_revoke = source.contains("revoke") || source.contains("Revoke");

        // Check for protection on grant/revoke
        let has_admin_check = source.contains("onlyAdmin")
            || source.contains("onlyOwner")
            || source.contains("hasRole")
            || source.contains("ADMIN");

        if has_roles && (has_grant || has_revoke) && !has_admin_check {
            let finding = self.base.create_finding_with_severity(
                ctx,
                "Role grant/revoke without admin protection - privilege escalation risk ($953M)".to_string(),
                1,
                0,
                20,
                Severity::Critical,
            ).with_fix_suggestion(
                "🚨 CRITICAL: Access control failures caused $953M in losses (2024)\n\
                 \n\
                 ❌ VULNERABLE - Anyone can grant roles:\n\
                 function grantRole(bytes32 role, address account) public {\n\
                     roles[role][account] = true;  // No protection!\n\
                 }\n\
                 \n\
                 ✅ PROTECTED - Only admin can grant:\n\
                 bytes32 public constant ADMIN_ROLE = keccak256(\"ADMIN_ROLE\");\n\
                 \n\
                 modifier onlyRole(bytes32 role) {\n\
                     require(hasRole(role, msg.sender), \"Missing role\");\n\
                     _;\n\
                 }\n\
                 \n\
                 function grantRole(\n\
                     bytes32 role,\n\
                     address account\n\
                 ) public onlyRole(ADMIN_ROLE) {\n\
                     require(account != address(0), \"Zero address\");\n\
                     require(!hasRole(role, account), \"Already has role\");\n\
                     roles[role][account] = true;\n\
                     emit RoleGranted(role, account, msg.sender);\n\
                 }\n\
                 \n\
                 function revokeRole(\n\
                     bytes32 role,\n\
                     address account\n\
                 ) public onlyRole(ADMIN_ROLE) {\n\
                     require(hasRole(role, account), \"No such role\");\n\
                     roles[role][account] = false;\n\
                     emit RoleRevoked(role, account, msg.sender);\n\
                 }\n\
                 \n\
                 ✅ BEST - Use OpenZeppelin AccessControl:\n\
                 import \"@openzeppelin/contracts/access/AccessControl.sol\";\n\
                 \n\
                 contract MyContract is AccessControl {\n\
                     bytes32 public constant MINTER_ROLE = keccak256(\"MINTER_ROLE\");\n\
                     \n\
                     constructor() {\n\
                         _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);\n\
                     }\n\
                     \n\
                     function mint(address to, uint256 amount) \n\
                         public \n\
                         onlyRole(MINTER_ROLE) \n\
                     {\n\
                         _mint(to, amount);\n\
                     }\n\
                 }".to_string()
            );
            findings.push(finding);
        }

        // Check for owner transfer without 2-step
        let has_owner = source.contains("owner") || source.contains("Owner");
        let has_transfer = source.contains("transferOwner") || source.contains("setOwner");
        let has_two_step = source.contains("pendingOwner") || source.contains("acceptOwner");

        if has_owner && has_transfer && !has_two_step {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    "Single-step ownership transfer - use 2-step transfer to prevent mistakes"
                        .to_string(),
                    1,
                    0,
                    20,
                    Severity::High,
                )
                .with_fix_suggestion(
                    "❌ DANGEROUS - Single-step ownership transfer:\n\
                 function transferOwnership(address newOwner) public onlyOwner {\n\
                     owner = newOwner;  // What if newOwner is wrong address?\n\
                 }\n\
                 // Risk: Typo in address = permanent loss of control\n\
                 \n\
                 ✅ SAFE - Two-step ownership transfer:\n\
                 address public owner;\n\
                 address public pendingOwner;\n\
                 \n\
                 // Step 1: Current owner nominates new owner\n\
                 function transferOwnership(address newOwner) public onlyOwner {\n\
                     require(newOwner != address(0), \"Zero address\");\n\
                     pendingOwner = newOwner;\n\
                     emit OwnershipTransferStarted(owner, newOwner);\n\
                 }\n\
                 \n\
                 // Step 2: New owner must accept\n\
                 function acceptOwnership() public {\n\
                     require(msg.sender == pendingOwner, \"Not pending owner\");\n\
                     address oldOwner = owner;\n\
                     owner = pendingOwner;\n\
                     pendingOwner = address(0);\n\
                     emit OwnershipTransferred(oldOwner, owner);\n\
                 }\n\
                 \n\
                 ✅ BEST - Use OpenZeppelin Ownable2Step:\n\
                 import \"@openzeppelin/contracts/access/Ownable2Step.sol\";\n\
                 \n\
                 contract MyContract is Ownable2Step {\n\
                     // Automatically has 2-step transfer\n\
                 }\n\
                 \n\
                 Benefits of 2-step:\n\
                 - New owner must prove they control the address\n\
                 - Prevents typos in addresses\n\
                 - Allows cancellation before acceptance\n\
                 - New owner can verify contract state first"
                        .to_string(),
                );
            findings.push(finding);
        }

        // Check for missing role admin
        if has_roles && !source.contains("AdminRole") && !source.contains("DEFAULT_ADMIN") {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    "Role-based access without admin role - who can grant/revoke roles?"
                        .to_string(),
                    1,
                    0,
                    20,
                    Severity::Medium,
                )
                .with_fix_suggestion(
                    "Every role should have a clear admin hierarchy:\n\
                 \n\
                 ✅ DEFINE ROLE HIERARCHY:\n\
                 bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;\n\
                 bytes32 public constant MINTER_ROLE = keccak256(\"MINTER_ROLE\");\n\
                 bytes32 public constant PAUSER_ROLE = keccak256(\"PAUSER_ROLE\");\n\
                 bytes32 public constant UPGRADER_ROLE = keccak256(\"UPGRADER_ROLE\");\n\
                 \n\
                 mapping(bytes32 => bytes32) private roleAdmin;\n\
                 \n\
                 constructor() {\n\
                     // Set up role hierarchy\n\
                     _setRoleAdmin(MINTER_ROLE, DEFAULT_ADMIN_ROLE);\n\
                     _setRoleAdmin(PAUSER_ROLE, DEFAULT_ADMIN_ROLE);\n\
                     _setRoleAdmin(UPGRADER_ROLE, DEFAULT_ADMIN_ROLE);\n\
                     \n\
                     // Grant admin to deployer\n\
                     _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);\n\
                 }\n\
                 \n\
                 function grantRole(bytes32 role, address account) public {\n\
                     // Only role admin can grant this role\n\
                     require(\n\
                         hasRole(roleAdmin[role], msg.sender),\n\
                         \"Not role admin\"\n\
                     );\n\
                     _grantRole(role, account);\n\
                 }\n\
                 \n\
                 ✅ BEST PRACTICE - Document role hierarchy:\n\
                 /**\n\
                  * Role Hierarchy:\n\
                  * - DEFAULT_ADMIN_ROLE (0x00)\n\
                  *   └─ Can grant/revoke all roles\n\
                  *   └─ Should be multi-sig or governance\n\
                  * \n\
                  * - MINTER_ROLE\n\
                  *   └─ Can mint tokens\n\
                  *   └─ Granted to: Staking contract, Rewards contract\n\
                  * \n\
                  * - PAUSER_ROLE\n\
                  *   └─ Can pause/unpause contract\n\
                  *   └─ Granted to: Emergency multi-sig\n\
                  */"
                    .to_string(),
                );
            findings.push(finding);
        }

        // Check for tx.origin in access control
        if source.contains("tx.origin") && (source.contains("require") || source.contains("if")) {
            let finding = self
                .base
                .create_finding_with_severity(
                    ctx,
                    "tx.origin used in access control - vulnerable to phishing attacks".to_string(),
                    1,
                    0,
                    20,
                    Severity::High,
                )
                .with_fix_suggestion(
                    "❌ NEVER use tx.origin for access control:\n\
                 function withdraw() public {\n\
                     require(tx.origin == owner, \"Not owner\");\n\
                     // Vulnerable to phishing!\n\
                 }\n\
                 \n\
                 Attack scenario:\n\
                 1. Attacker deploys malicious contract\n\
                 2. Owner calls attacker contract\n\
                 3. Attacker contract calls victim.withdraw()\n\
                 4. tx.origin is still owner, check passes!\n\
                 5. Funds drained\n\
                 \n\
                 ✅ ALWAYS use msg.sender:\n\
                 function withdraw() public {\n\
                     require(msg.sender == owner, \"Not owner\");\n\
                     // Safe: msg.sender is immediate caller\n\
                 }\n\
                 \n\
                 The difference:\n\
                 - msg.sender: Immediate caller (can be contract)\n\
                 - tx.origin: Original EOA that started the transaction\n\
                 \n\
                 Valid use of tx.origin:\n\
                 - Reject contract calls: require(tx.origin == msg.sender)\n\
                 - But NEVER for access control decisions"
                        .to_string(),
                );
            findings.push(finding);
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
