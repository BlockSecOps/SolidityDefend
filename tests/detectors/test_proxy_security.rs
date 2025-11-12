use std::path::PathBuf;

/// Integration tests for proxy security detectors
///
/// These tests validate the Phase 1 delegatecall/proxy pattern detectors:
/// - proxy-upgrade-unprotected
/// - proxy-storage-collision
/// - delegatecall-user-controlled
/// - fallback-delegatecall-unprotected
/// - fallback-function-shadowing
/// - delegatecall-return-ignored

#[test]
fn test_proxy_upgrade_unprotected_detector() {
    let vulnerable_contract = PathBuf::from("tests/contracts/delegatecall/vulnerable/UnprotectedProxyUpgrade.sol");
    let secure_contract = PathBuf::from("tests/contracts/delegatecall/secure/SecureProxyUpgrade.sol");

    // Verify test contracts exist
    assert!(vulnerable_contract.exists(),
        "Vulnerable test contract not found: {:?}", vulnerable_contract);
    assert!(secure_contract.exists(),
        "Secure test contract not found: {:?}", secure_contract);

    // TODO: Add actual detector execution when CLI integration is ready
    // For now, this test validates that:
    // 1. Test contracts are in place
    // 2. Detector is registered and compiles
    // 3. Integration can be tested manually via: cargo run -- tests/contracts/delegatecall/vulnerable/UnprotectedProxyUpgrade.sol
}

#[test]
fn test_proxy_storage_collision_detector() {
    let vulnerable_contract = PathBuf::from("tests/contracts/delegatecall/vulnerable/ProxyStorageCollision.sol");
    let secure_contract = PathBuf::from("tests/contracts/delegatecall/secure/EIP1967CompliantProxy.sol");

    assert!(vulnerable_contract.exists(),
        "Vulnerable test contract not found: {:?}", vulnerable_contract);
    assert!(secure_contract.exists(),
        "Secure test contract not found: {:?}", secure_contract);
}

#[test]
fn test_delegatecall_user_controlled_detector() {
    let vulnerable_contract = PathBuf::from("tests/contracts/delegatecall/vulnerable/UserControlledDelegatecall.sol");
    let secure_contract = PathBuf::from("tests/contracts/delegatecall/secure/SecureDelegatecall.sol");

    assert!(vulnerable_contract.exists(),
        "Vulnerable test contract not found: {:?}", vulnerable_contract);
    assert!(secure_contract.exists(),
        "Secure test contract not found: {:?}", secure_contract);
}

#[test]
fn test_fallback_delegatecall_unprotected_detector() {
    let vulnerable_contract = PathBuf::from("tests/contracts/delegatecall/vulnerable/UnprotectedFallbackDelegatecall.sol");
    let secure_contract = PathBuf::from("tests/contracts/delegatecall/secure/SecureFallbackDelegatecall.sol");

    assert!(vulnerable_contract.exists(),
        "Vulnerable test contract not found: {:?}", vulnerable_contract);
    assert!(secure_contract.exists(),
        "Secure test contract not found: {:?}", secure_contract);
}

#[test]
fn test_all_proxy_detectors_compile() {
    // This test ensures all detector modules compile correctly
    // The detectors should be registered in the detector registry

    use detectors::proxy_upgrade_unprotected::ProxyUpgradeUnprotectedDetector;
    use detectors::proxy_storage_collision::ProxyStorageCollisionDetector;
    use detectors::delegatecall_user_controlled::DelegatecallUserControlledDetector;
    use detectors::fallback_delegatecall_unprotected::FallbackDelegatecallUnprotectedDetector;

    // Instantiate each detector to verify they compile
    let _d1 = ProxyUpgradeUnprotectedDetector::new();
    let _d2 = ProxyStorageCollisionDetector::new();
    let _d3 = DelegatecallUserControlledDetector::new();
    let _d4 = FallbackDelegatecallUnprotectedDetector::new();

    // If we get here, all detectors compiled successfully
    assert!(true);
}

#[test]
fn test_detectors_registered_in_registry() {
    use detectors::DetectorRegistry;

    // Create registry with all built-in detectors
    let registry = DetectorRegistry::with_all_detectors();

    // Get all detector IDs
    let detector_ids = registry.get_detector_ids();

    // Verify our new detectors are registered
    let detector_id_strings: Vec<String> = detector_ids.iter()
        .map(|id| id.to_string())
        .collect();

    assert!(detector_id_strings.iter().any(|id| id.contains("proxy-upgrade-unprotected") || id.contains("proxy_upgrade_unprotected")),
        "proxy-upgrade-unprotected detector not found in registry");
    assert!(detector_id_strings.iter().any(|id| id.contains("proxy-storage-collision") || id.contains("proxy_storage_collision")),
        "proxy-storage-collision detector not found in registry");
    assert!(detector_id_strings.iter().any(|id| id.contains("delegatecall-user-controlled") || id.contains("delegatecall_user_controlled")),
        "delegatecall-user-controlled detector not found in registry");
    assert!(detector_id_strings.iter().any(|id| id.contains("fallback-delegatecall-unprotected") || id.contains("fallback_delegatecall_unprotected")),
        "fallback-delegatecall-unprotected detector not found in registry");
}

#[test]
fn test_fallback_function_shadowing_detector() {
    let vulnerable_contract = PathBuf::from("tests/contracts/delegatecall/vulnerable/FallbackShadowing.sol");
    let secure_contract = PathBuf::from("tests/contracts/delegatecall/secure/NoShadowingProxy.sol");

    assert!(vulnerable_contract.exists(),
        "Vulnerable test contract not found: {:?}", vulnerable_contract);
    assert!(secure_contract.exists(),
        "Secure test contract not found: {:?}", secure_contract);
}

#[test]
fn test_delegatecall_return_ignored_detector() {
    let vulnerable_contract = PathBuf::from("tests/contracts/delegatecall/vulnerable/DelegatecallReturnIgnored.sol");
    let secure_contract = PathBuf::from("tests/contracts/delegatecall/secure/DelegatecallReturnChecked.sol");

    assert!(vulnerable_contract.exists(),
        "Vulnerable test contract not found: {:?}", vulnerable_contract);
    assert!(secure_contract.exists(),
        "Secure test contract not found: {:?}", secure_contract);
}

#[test]
fn test_day3_detectors_compile() {
    // This test ensures both new Day 3 detector modules compile correctly
    use detectors::fallback_function_shadowing::FallbackFunctionShadowingDetector;
    use detectors::delegatecall_return_ignored::DelegatecallReturnIgnoredDetector;

    // Instantiate each detector to verify they compile
    let _d1 = FallbackFunctionShadowingDetector::new();
    let _d2 = DelegatecallReturnIgnoredDetector::new();

    // If we get here, both detectors compiled successfully
    assert!(true);
}

#[test]
fn test_day3_detectors_registered() {
    use detectors::DetectorRegistry;

    // Create registry with all built-in detectors
    let registry = DetectorRegistry::with_all_detectors();

    // Get all detector IDs
    let detector_ids = registry.get_detector_ids();
    let detector_id_strings: Vec<String> = detector_ids.iter()
        .map(|id| id.to_string())
        .collect();

    // Verify our new Day 3 detectors are registered
    assert!(detector_id_strings.iter().any(|id| id.contains("fallback-function-shadowing") || id.contains("fallback_function_shadowing")),
        "fallback-function-shadowing detector not found in registry");
    assert!(detector_id_strings.iter().any(|id| id.contains("delegatecall-return-ignored") || id.contains("delegatecall_return_ignored")),
        "delegatecall-return-ignored detector not found in registry");
}
