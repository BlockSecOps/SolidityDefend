//! Metamorphic Contract Detection
//!
//! Detects contracts that implement the metamorphic contract pattern using CREATE2 + SELFDESTRUCT,
//! which allows changing contract code at the same address, bypassing immutability assumptions.

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct MetamorphicContractDetector {
    base: BaseDetector,
}

impl MetamorphicContractDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("metamorphic-contract".to_string()),
                "Metamorphic Contract Detection".to_string(),
                "Detects metamorphic contract patterns (CREATE2 + SELFDESTRUCT) that enable changing contract code at the same address".to_string(),
                vec![
                    DetectorCategory::Metamorphic,
                    DetectorCategory::Deployment,
                    DetectorCategory::Logic,
                ],
                Severity::Critical,
            ),
        }
    }

    fn check_metamorphic_patterns(&self, ctx: &AnalysisContext) -> Vec<(String, u32, String)> {
        let mut findings = Vec::new();
        let source = &ctx.source_code;
        let source_lower = source.to_lowercase();

        // Early exit if no CREATE2 or SELFDESTRUCT
        let has_create2 = source_lower.contains("create2");
        let has_selfdestruct =
            source_lower.contains("selfdestruct")
            || source_lower.contains("suicide")
            || (source_lower.contains("function destroy") && source_lower.contains("external"))
            || (source_lower.contains("function kill") && source_lower.contains("external"))
            || (source_lower.contains("function terminate") && source_lower.contains("external"));

        if !has_create2 && !has_selfdestruct {
            return findings;
        }

        // Check for legitimate factory patterns (skip if present)
        let has_salt_commitment = (source_lower.contains("salthash") || source_lower.contains("saltcommitment"))
            && (source_lower.contains("mapping") || source_lower.contains("timestamp"));

        let has_factory_pattern = source_lower.contains("factory")
            || (source_lower.contains("deploy") && source_lower.contains("function"))
            || source_lower.contains("counterfactual");

        let has_access_control = source_lower.contains("onlyowner")
            || (source_lower.contains("require") && source_lower.contains("msg.sender"))
            || source_lower.contains("ownable")
            || source_lower.contains("accesscontrol");

        let has_selfdestruct_timelock = source_lower.contains("selfdestruct")
            && source_lower.contains("timestamp")
            && (source_lower.contains("delay") || source_lower.contains("days") || source_lower.contains("hours"));

        // If it's a legitimate factory with proper security, skip most checks
        let is_legitimate_factory = has_factory_pattern
            && has_access_control
            && (has_salt_commitment || !has_selfdestruct || has_selfdestruct_timelock);

        if is_legitimate_factory {
            return findings; // Legitimate deterministic deployment factory
        }

        // Pattern 1: Full metamorphic pattern (CREATE2 + SELFDESTRUCT in constructor)
        if has_create2 && has_selfdestruct {
            let has_constructor_selfdestruct = source_lower.contains("constructor")
                && (source_lower.contains("selfdestruct") || source_lower.contains("suicide"));

            if has_constructor_selfdestruct {
                findings.push((
                    "CRITICAL: Metamorphic contract pattern detected (CREATE2 + constructor SELFDESTRUCT)".to_string(),
                    0,
                    "This enables changing contract code at same address: (1) Deploy with CREATE2, (2) SELFDESTRUCT in constructor, (3) Redeploy different code at same address. This breaks immutability assumptions and trust models.".to_string(),
                ));
            }

            // Even without constructor, combination is suspicious
            if !has_constructor_selfdestruct {
                findings.push((
                    "Contract uses both CREATE2 and SELFDESTRUCT (metamorphic risk)".to_string(),
                    0,
                    "Combination of CREATE2 and SELFDESTRUCT enables metamorphic contracts. Document if intentional. Consider: (1) Remove SELFDESTRUCT, (2) Add transparency about upgrade mechanism, (3) Implement upgrade delays/governance".to_string(),
                ));
            }
        }

        // Pattern 2: Factory that deploys contracts with SELFDESTRUCT
        if has_create2 {
            // Check if the deployed bytecode contains SELFDESTRUCT
            let deploys_selfdestruct_code = source_lower.contains("create2")
                && (source_lower.contains("bytecode")
                    || source_lower.contains("initcode")
                    || source_lower.contains("creationcode"))
                && (source_lower.contains("selfdestruct") || source_lower.contains("suicide"));

            if deploys_selfdestruct_code {
                findings.push((
                    "CREATE2 factory deploys contracts with SELFDESTRUCT (metamorphic factory)".to_string(),
                    0,
                    "Factory enables metamorphic contracts by deploying SELFDESTRUCT-capable contracts via CREATE2. Add: (1) Disclosure of metamorphic capability, (2) Governance over redeployments, (3) Event emission on each deployment".to_string(),
                ));
            }
        }

        // Pattern 3: CREATE2 with same salt reuse capability
        if has_create2 {
            let allows_salt_reuse = source_lower.contains("create2")
                && !source_lower.contains("usedsalts")
                && !source_lower.contains("deployedsalts")
                && !(source_lower.contains("require") && source_lower.contains("salt"));

            if allows_salt_reuse && has_selfdestruct {
                findings.push((
                    "CREATE2 allows salt reuse with SELFDESTRUCT present (address reuse risk)".to_string(),
                    0,
                    "Prevent salt reuse: mapping(bytes32 => bool) public usedSalts; require(!usedSalts[salt], \"Salt reused\"); This prevents metamorphic redeploy at same address.".to_string(),
                ));
            }
        }

        // Pattern 4: Delegatecall to CREATE2-deployed contract
        if source_lower.contains("delegatecall") && has_create2 {
            findings.push((
                "Delegatecall to CREATE2-deployed contract (code replacement risk)".to_string(),
                0,
                "If target was deployed via CREATE2 and can SELFDESTRUCT, attacker can replace logic. Validate: (1) Target codehash matches expected, (2) Target cannot be destroyed, (3) Use upgradeable proxy pattern instead".to_string(),
            ));
        }

        // Pattern 5: SELFDESTRUCT with CREATE2 address calculation
        if has_selfdestruct && has_create2 {
            let calculates_create2_address = source_lower.contains("keccak256")
                && source_lower.contains("0xff")
                && (source_lower.contains("salt") || source_lower.contains("bytecode"));

            if calculates_create2_address {
                findings.push((
                    "Calculates CREATE2 address with SELFDESTRUCT present (metamorphic setup)".to_string(),
                    0,
                    "Address calculation + SELFDESTRUCT suggests metamorphic pattern preparation. Document: (1) Purpose of address calculation, (2) Upgrade mechanism, (3) User notifications before code changes".to_string(),
                ));
            }
        }

        // Pattern 6: Factory with destroy function for CREATE2 deployed contracts
        if has_create2 {
            let has_destroy_function = (source_lower.contains("function destroy")
                || source_lower.contains("function kill")
                || source_lower.contains("function terminate"))
                && (source_lower.contains("selfdestruct") || source_lower.contains("suicide"));

            if has_destroy_function {
                findings.push((
                    "Factory with destroy function for CREATE2 contracts (metamorphic capability)".to_string(),
                    0,
                    "Destroy function on CREATE2-deployed contracts enables metamorphism. Add: (1) Strict access control, (2) Timelock on destruction, (3) Clear documentation of upgrade process, (4) User consent mechanism".to_string(),
                ));
            }
        }

        // Pattern 7: Init code that self-destructs
        if has_create2 {
            let has_init_selfdestruct = (source_lower.contains("initcode")
                || source_lower.contains("creationcode"))
                && source_lower.contains("selfdestruct");

            if has_init_selfdestruct {
                findings.push((
                    "Deployment init code contains SELFDESTRUCT (metamorphic deployment)".to_string(),
                    0,
                    "Init code with SELFDESTRUCT is classic metamorphic pattern: deploys to address then self-destructs, allowing redeploy. This is intentional metamorphism - ensure users are aware.".to_string(),
                ));
            }
        }

        // Pattern 8: No codehash validation after CREATE2
        if has_create2 {
            // Look for actual codehash validation patterns, not just comments
            let has_codehash_validation = (source_lower.contains(".codehash") || source_lower.contains("extcodehash"))
                && (source_lower.contains("require") || source_lower.contains("assert") || source_lower.contains("=="));

            if !has_codehash_validation && has_selfdestruct {
                findings.push((
                    "CREATE2 without codehash validation (metamorphic code swap undetected)".to_string(),
                    0,
                    "Validate deployed code: bytes32 expectedHash = keccak256(bytecode); require(address(deployed).codehash == expectedHash, \"Unexpected code\"); Prevents deploying different code than expected.".to_string(),
                ));
            }
        }

        // Pattern 9: Proxy pointing to CREATE2 address with SELFDESTRUCT
        if (source_lower.contains("implementation") || source_lower.contains("proxy"))
            && has_create2
            && has_selfdestruct
        {
            findings.push((
                "Proxy pattern combined with CREATE2 + SELFDESTRUCT (metamorphic proxy risk)".to_string(),
                0,
                "Implementation can be destroyed and replaced via metamorphism. Use: (1) Standard upgradeable proxy (EIP-1967), (2) Implementation immutability guarantee, (3) Governance-controlled upgrades only".to_string(),
            ));
        }

        // Pattern 10: Registry of CREATE2 addresses with SELFDESTRUCT capability
        if has_create2 {
            let has_registry = source_lower.contains("mapping")
                && (source_lower.contains("deployed") || source_lower.contains("contracts"))
                && source_lower.contains("address");

            if has_registry && has_selfdestruct {
                findings.push((
                    "Registry of CREATE2-deployed contracts with SELFDESTRUCT (metamorphic tracking needed)".to_string(),
                    0,
                    "Registry should track: (1) Deployment timestamp, (2) Codehash at deployment, (3) Whether contract was destroyed, (4) Redeployment count. Emit events on all state changes.".to_string(),
                ));
            }
        }

        findings
    }
}

impl Default for MetamorphicContractDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for MetamorphicContractDetector {
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

        let issues = self.check_metamorphic_patterns(ctx);

        for (message, line_offset, remediation) in issues {
            let severity = if message.contains("CRITICAL")
                || message.contains("constructor SELFDESTRUCT")
                || message.contains("metamorphic factory")
            {
                Severity::Critical
            } else if message.contains("metamorphic risk")
                || message.contains("code replacement risk")
                || message.contains("address reuse risk")
            {
                Severity::High
            } else {
                Severity::Medium
            };

            let finding = self
                .base
                .create_finding_with_severity(ctx, message, line_offset, 0, 20, severity)
                .with_fix_suggestion(remediation)
                .with_cwe(913); // CWE-913: Improper Control of Dynamically-Managed Code Resources

            findings.push(finding);
        }

        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::test_utils::*;

    #[test]
    fn test_detector_properties() {
        let detector = MetamorphicContractDetector::new();
        assert_eq!(detector.id().to_string(), "metamorphic-contract");
        assert_eq!(detector.name(), "Metamorphic Contract Detection");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_detects_constructor_selfdestruct_with_create2() {
        let detector = MetamorphicContractDetector::new();
        let source = r#"
            contract MetamorphicInit {
                constructor() {
                    // Deploy actual contract logic, then self-destruct
                    selfdestruct(payable(msg.sender));
                }
            }

            contract Factory {
                function deploy(bytes32 salt) external {
                    address deployed;
                    bytes memory bytecode = type(MetamorphicInit).creationCode;
                    assembly {
                        deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
                    }
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
        assert!(result
            .iter()
            .any(|f| f.message.contains("CRITICAL") && f.message.contains("constructor")));
    }

    #[test]
    fn test_detects_create2_with_selfdestruct_combination() {
        let detector = MetamorphicContractDetector::new();
        let source = r#"
            contract Vulnerable {
                function deploy(bytes32 salt, bytes memory bytecode) external {
                    address deployed;
                    assembly {
                        deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
                    }
                }

                function destroy() external {
                    selfdestruct(payable(msg.sender));
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
        assert!(result
            .iter()
            .any(|f| f.message.contains("CREATE2 and SELFDESTRUCT")));
    }

    #[test]
    fn test_detects_salt_reuse_with_selfdestruct() {
        let detector = MetamorphicContractDetector::new();
        let source = r#"
            contract Factory {
                function deploy(bytes32 salt, bytes memory bytecode) external {
                    address deployed;
                    assembly {
                        deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
                    }
                }

                function destroyDeployed(address target) external {
                    IDestroyable(target).destroy();
                }
            }

            interface IDestroyable {
                function destroy() external;
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
        assert!(result
            .iter()
            .any(|f| f.message.contains("salt reuse") || f.message.contains("address reuse")));
    }

    #[test]
    fn test_detects_delegatecall_to_create2() {
        let detector = MetamorphicContractDetector::new();
        let source = r#"
            contract Proxy {
                address public implementation;

                function deploy(bytes32 salt, bytes memory bytecode) external {
                    assembly {
                        implementation := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
                    }
                }

                fallback() external payable {
                    address impl = implementation;
                    assembly {
                        calldatacopy(0, 0, calldatasize())
                        let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
                        returndatacopy(0, 0, returndatasize())
                        switch result
                        case 0 { revert(0, returndatasize()) }
                        default { return(0, returndatasize()) }
                    }
                }
            }

            contract Implementation {
                function destroy() external {
                    selfdestruct(payable(msg.sender));
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
        assert!(result
            .iter()
            .any(|f| f.message.contains("Delegatecall") || f.message.contains("code replacement")));
    }

    #[test]
    fn test_detects_create2_address_calculation() {
        let detector = MetamorphicContractDetector::new();
        let source = r#"
            contract Factory {
                function computeAddress(bytes32 salt, bytes32 bytecodeHash)
                    public
                    view
                    returns (address)
                {
                    return address(uint160(uint256(keccak256(abi.encodePacked(
                        bytes1(0xff),
                        address(this),
                        salt,
                        bytecodeHash
                    )))));
                }

                function deploy(bytes32 salt, bytes memory bytecode) external {
                    address deployed;
                    assembly {
                        deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
                    }
                }

                function destroyContract(address target) external {
                    IDestroyable(target).destroy();
                }
            }

            interface IDestroyable {
                function destroy() external;
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
        assert!(result
            .iter()
            .any(|f| f.message.contains("Calculates CREATE2 address")));
    }

    #[test]
    fn test_detects_factory_destroy_function() {
        let detector = MetamorphicContractDetector::new();
        let source = r#"
            contract Factory {
                function deploy(bytes32 salt, bytes memory bytecode) external returns (address) {
                    address deployed;
                    assembly {
                        deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
                    }
                    return deployed;
                }

                function destroy(address target) external {
                    IContract(target).selfDestruct();
                }
            }

            interface IContract {
                function selfDestruct() external;
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
        assert!(result
            .iter()
            .any(|f| f.message.contains("destroy function")));
    }

    #[test]
    fn test_detects_no_codehash_validation() {
        let detector = MetamorphicContractDetector::new();
        let source = r#"
            contract Factory {
                function deploy(bytes32 salt, bytes memory bytecode) external returns (address) {
                    address deployed;
                    assembly {
                        deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
                    }
                    // No codehash validation!
                    return deployed;
                }

                function terminate() external {
                    selfdestruct(payable(msg.sender));
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(!result.is_empty());
        assert!(result
            .iter()
            .any(|f| f.message.contains("codehash validation")));
    }

    #[test]
    fn test_safe_create2_without_selfdestruct() {
        let detector = MetamorphicContractDetector::new();
        let source = r#"
            contract SafeFactory {
                mapping(bytes32 => bool) public usedSalts;

                function deploy(bytes32 salt, bytes memory bytecode) external returns (address) {
                    require(!usedSalts[salt], "Salt already used");
                    usedSalts[salt] = true;

                    address deployed;
                    assembly {
                        deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
                    }

                    require(deployed != address(0), "Deployment failed");

                    // Validate codehash
                    bytes32 expectedHash = keccak256(bytecode);
                    bytes32 actualHash;
                    assembly {
                        actualHash := extcodehash(deployed)
                    }
                    require(actualHash == expectedHash, "Unexpected code");

                    return deployed;
                }
            }
        "#;

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        // Should have no findings or minimal findings since no SELFDESTRUCT
        assert!(result.is_empty() || result.len() < 2);
    }
}
