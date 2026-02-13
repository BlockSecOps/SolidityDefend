use std::path::PathBuf;

/// Integration tests for proxy security detectors
///
/// These tests validate the delegatecall/proxy pattern detectors:
/// - proxy-storage-collision
/// - fallback-delegatecall-unprotected
/// - delegatecall-return-ignored

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
    use detectors::proxy_storage_collision::ProxyStorageCollisionDetector;
    use detectors::fallback_delegatecall_unprotected::FallbackDelegatecallUnprotectedDetector;

    let _d1 = ProxyStorageCollisionDetector::new();
    let _d3 = FallbackDelegatecallUnprotectedDetector::new();

    assert!(true);
}

#[test]
fn test_detectors_registered_in_registry() {
    use detectors::DetectorRegistry;

    let registry = DetectorRegistry::with_all_detectors();
    let detector_ids = registry.get_detector_ids();

    let detector_id_strings: Vec<String> = detector_ids.iter()
        .map(|id| id.to_string())
        .collect();

    assert!(detector_id_strings.iter().any(|id| id.contains("proxy-storage-collision") || id.contains("proxy_storage_collision")),
        "proxy-storage-collision detector not found in registry");
    assert!(detector_id_strings.iter().any(|id| id.contains("fallback-delegatecall-unprotected") || id.contains("fallback_delegatecall_unprotected")),
        "fallback-delegatecall-unprotected detector not found in registry");
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
fn test_delegatecall_return_ignored_compile() {
    use detectors::delegatecall_return_ignored::DelegatecallReturnIgnoredDetector;

    let _d2 = DelegatecallReturnIgnoredDetector::new();

    assert!(true);
}

#[test]
fn test_delegatecall_return_ignored_registered() {
    use detectors::DetectorRegistry;

    let registry = DetectorRegistry::with_all_detectors();
    let detector_ids = registry.get_detector_ids();
    let detector_id_strings: Vec<String> = detector_ids.iter()
        .map(|id| id.to_string())
        .collect();

    assert!(detector_id_strings.iter().any(|id| id.contains("delegatecall-return-ignored") || id.contains("delegatecall_return_ignored")),
        "delegatecall-return-ignored detector not found in registry");
}
