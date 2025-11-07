//! EIP-7702 Initialization Front-Running Detector
//!
//! Detects unprotected initialization in EIP-7702 delegate contracts that can be front-run
//! for account takeover.
//!
//! **CRITICAL**: $1.54M lost in August 2025 single attack via initialization front-running.
//!
//! ## Attack Scenario
//!
//! ```solidity
//! contract VulnerableDelegate {
//!     address public owner;
//!
//!     // ❌ VULNERABLE: Anyone can call first
//!     function initialize(address _owner) public {
//!         require(owner == address(0), "Already initialized");
//!         owner = _owner;
//!     }
//!
//!     function execute(address target, bytes calldata data) public {
//!         require(msg.sender == owner);
//!         target.call(data);
//!     }
//! }
//!
//! // Attack:
//! // 1. User signs EIP-7702 authorization for VulnerableDelegate
//! // 2. Attacker front-runs with initialize(attackerAddress)
//! // 3. Attacker now owns user's EOA delegation
//! // 4. Attacker drains all assets
//! ```
//!
//! Severity: CRITICAL
//! Category: AccessControl

use anyhow::Result;
use std::any::Any;

use super::is_eip7702_delegate;
use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct EIP7702InitFrontrunDetector {
    base: BaseDetector,
}

impl EIP7702InitFrontrunDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("eip7702-init-frontrun".to_string()),
                "EIP-7702 Initialization Front-Running".to_string(),
                "Detects unprotected initialization vulnerable to front-running attacks in EIP-7702 delegates ($1.54M August 2025 loss)".to_string(),
                vec![DetectorCategory::AccessControl],
                Severity::Critical,
            ),
        }
    }

    fn check_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Vec<(String, Severity, String)> {
        let mut issues = Vec::new();

        let func_name = &function.name.name.to_lowercase();

        // Check for initialization functions
        if !func_name.contains("init")
            && !func_name.contains("setup")
            && !func_name.contains("configure")
        {
            return issues;
        }

        let func_text = if let Some(body) = &function.body {
            ctx.source_code[body.location.start().offset()..body.location.end().offset()]
                .to_string()
        } else {
            return issues;
        };

        let func_lower = func_text.to_lowercase();

        // Check if function is protected
        let has_owner_check = func_lower.contains("msg.sender")
            && (func_lower.contains("owner") || func_lower.contains("admin"));

        let has_modifier = !function.modifiers.is_empty();

        let is_external_or_public = matches!(
            function.visibility,
            ast::Visibility::Public | ast::Visibility::External
        );

        // Vulnerable if: external/public + no protection + sets important state
        let sets_owner = func_lower.contains("owner") && func_lower.contains("=");
        let sets_important_state =
            sets_owner || func_lower.contains("initialized") || func_lower.contains("admin");

        if is_external_or_public && !has_owner_check && !has_modifier && sets_important_state {
            issues.push((
                format!("Unprotected initialization in '{}' - vulnerable to front-running takeover ($1.54M August 2025 attack)", function.name.name),
                Severity::Critical,
                format!(
                    "EIP-7702 Front-Running Attack:\n\
                     \n\
                     Current code (VULNERABLE):\n\
                     function {}(...) public {{\n\
                         require(owner == address(0));\n\
                         owner = newOwner;  // ❌ Attacker can front-run!\n\
                     }}\n\
                     \n\
                     Attack sequence:\n\
                     1. User signs EIP-7702 authorization\n\
                     2. Attacker sees authorization in mempool\n\
                     3. Attacker front-runs with initialize(attackerAddress)\n\
                     4. User's delegation is now controlled by attacker\n\
                     5. Attacker drains all assets\n\
                     \n\
                     Fix 1: Authorization-based initialization\n\
                     function initialize(address _owner, bytes memory signature) public {{\n\
                         require(owner == address(0));\n\
                         \n\
                         // ✅ Verify user signed this specific initialization\n\
                         bytes32 hash = keccak256(abi.encodePacked(_owner, address(this)));\n\
                         address signer = ECDSA.recover(hash, signature);\n\
                         require(signer == _owner, \"Invalid signature\");\n\
                         \n\
                         owner = _owner;\n\
                     }}\n\
                     \n\
                     Fix 2: Constructor initialization (if possible)\n\
                     constructor(address _owner) {{\n\
                         owner = _owner;  // ✅ Set during deployment\n\
                     }}\n\
                     \n\
                     Fix 3: Factory pattern with immediate initialization\n\
                     contract DelegateFactory {{\n\
                         function createDelegate() public returns (address) {{\n\
                             Delegate delegate = new Delegate(msg.sender);\n\
                             return address(delegate);\n\
                         }}\n\
                     }}\n\
                     \n\
                     Fix 4: Commit-reveal with time-lock\n\
                     mapping(bytes32 => uint256) public commitments;\n\
                     \n\
                     function commitInit(bytes32 commitment) public {{\n\
                         commitments[commitment] = block.timestamp;\n\
                     }}\n\
                     \n\
                     function initialize(address _owner, bytes32 salt) public {{\n\
                         bytes32 commitment = keccak256(abi.encodePacked(_owner, salt));\n\
                         require(commitments[commitment] > 0, \"No commitment\");\n\
                         require(block.timestamp >= commitments[commitment] + 10 minutes);\n\
                         \n\
                         owner = _owner;\n\
                     }}\n\
                     \n\
                     Real-World Loss: $1.54M (August 2025)",
                    function.name.name
                )
            ));
        }

        issues
    }
}

impl Default for EIP7702InitFrontrunDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for EIP7702InitFrontrunDetector {
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

        if !is_eip7702_delegate(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            for (title, severity, remediation) in self.check_function(function, ctx) {
                let finding = self
                    .base
                    .create_finding_with_severity(
                        ctx,
                        title,
                        function.name.location.start().line() as u32,
                        0,
                        20,
                        severity,
                    )
                    .with_fix_suggestion(remediation);

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
