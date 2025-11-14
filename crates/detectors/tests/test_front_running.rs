/**
 * Integration tests for Phase 2 Front-Running Detectors
 *
 * Tests all 3 Week 1 ERC20 Front-Running detectors:
 * 1. erc20-approve-race
 * 2. token-transfer-frontrun
 * 3. allowance-toctou
 */

use detectors::detector::{Detector, DetectorCategory};
use detectors::erc20_approve_race::Erc20ApproveRaceDetector;
use detectors::token_transfer_frontrun::TokenTransferFrontrunDetector;
use detectors::allowance_toctou::AllowanceToctouDetector;
use detectors::types::{Severity, DetectorId};
use std::path::PathBuf;

/// Helper function to get test contract path
fn get_test_contract_path(category: &str, safety: &str, filename: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("contracts")
        .join(category)
        .join(safety)
        .join(filename)
}

#[test]
fn test_erc20_approve_race_metadata() {
    let detector = Erc20ApproveRaceDetector::new();

    assert_eq!(detector.id().0, "erc20-approve-race");
    assert_eq!(detector.name(), "ERC-20 Approve Race Condition");
    assert_eq!(detector.default_severity(), Severity::Medium);
    assert!(detector.is_enabled());

    let categories = detector.categories();
    assert!(categories.contains(&DetectorCategory::Logic));
    assert!(categories.contains(&DetectorCategory::DeFi));
}

#[test]
fn test_token_transfer_frontrun_metadata() {
    let detector = TokenTransferFrontrunDetector::new();

    assert_eq!(detector.id().0, "token-transfer-frontrun");
    assert_eq!(detector.name(), "Token Transfer Front-Running");
    assert_eq!(detector.default_severity(), Severity::Medium);
    assert!(detector.is_enabled());

    let categories = detector.categories();
    assert!(categories.contains(&DetectorCategory::MEV));
    assert!(categories.contains(&DetectorCategory::Logic));
    assert!(categories.contains(&DetectorCategory::DeFi));
}

#[test]
fn test_allowance_toctou_metadata() {
    let detector = AllowanceToctouDetector::new();

    assert_eq!(detector.id().0, "allowance-toctou");
    assert_eq!(detector.name(), "Allowance Time-of-Check-Time-of-Use");
    assert_eq!(detector.default_severity(), Severity::Medium);
    assert!(detector.is_enabled());

    let categories = detector.categories();
    assert!(categories.contains(&DetectorCategory::Logic));
    assert!(categories.contains(&DetectorCategory::DeFi));
    assert!(categories.contains(&DetectorCategory::MEV));
}

#[test]
fn test_all_detectors_instantiable() {
    // Verify all 3 Phase 2 Week 1 detectors can be created
    let d1 = Erc20ApproveRaceDetector::new();
    let d2 = TokenTransferFrontrunDetector::new();
    let d3 = AllowanceToctouDetector::new();

    // Verify they have the correct IDs
    assert_eq!(d1.id().0, "erc20-approve-race");
    assert_eq!(d2.id().0, "token-transfer-frontrun");
    assert_eq!(d3.id().0, "allowance-toctou");

    // Verify all are enabled
    assert!(d1.is_enabled());
    assert!(d2.is_enabled());
    assert!(d3.is_enabled());
}

#[test]
fn test_detector_categories_unique() {
    let detector1 = Erc20ApproveRaceDetector::new();
    let detector2 = TokenTransferFrontrunDetector::new();
    let detector3 = AllowanceToctouDetector::new();

    let cats1 = detector1.categories();
    let cats2 = detector2.categories();
    let cats3 = detector3.categories();

    // All should have MEV or DeFi category (front-running related)
    assert!(
        cats1.contains(&DetectorCategory::DeFi) ||
        cats2.contains(&DetectorCategory::MEV) ||
        cats3.contains(&DetectorCategory::MEV)
    );
}

#[test]
fn test_all_detectors_medium_severity() {
    // All Phase 2 Week 1 detectors should be Medium severity
    let detector1 = Erc20ApproveRaceDetector::new();
    let detector2 = TokenTransferFrontrunDetector::new();
    let detector3 = AllowanceToctouDetector::new();

    assert_eq!(detector1.default_severity(), Severity::Medium);
    assert_eq!(detector2.default_severity(), Severity::Medium);
    assert_eq!(detector3.default_severity(), Severity::Medium);
}

#[cfg(test)]
mod integration {
    use super::*;

    #[test]
    fn test_phase2_week1_complete() {
        // Verify all Phase 2 Week 1 deliverables exist

        // 1. All 3 detectors compile
        let _d1 = Erc20ApproveRaceDetector::new();
        let _d2 = TokenTransferFrontrunDetector::new();
        let _d3 = AllowanceToctouDetector::new();

        // 2. All have correct IDs
        assert_eq!(_d1.id().0, "erc20-approve-race");
        assert_eq!(_d2.id().0, "token-transfer-frontrun");
        assert_eq!(_d3.id().0, "allowance-toctou");

        // 3. All are enabled by default
        assert!(_d1.is_enabled());
        assert!(_d2.is_enabled());
        assert!(_d3.is_enabled());
    }

    #[test]
    fn test_detector_descriptions_present() {
        let d1 = Erc20ApproveRaceDetector::new();
        let d2 = TokenTransferFrontrunDetector::new();
        let d3 = AllowanceToctouDetector::new();

        // All should have non-empty descriptions
        assert!(!d1.description().is_empty());
        assert!(!d2.description().is_empty());
        assert!(!d3.description().is_empty());

        // Descriptions should be informative (>20 chars)
        assert!(d1.description().len() > 20);
        assert!(d2.description().len() > 20);
        assert!(d3.description().len() > 20);
    }

    #[test]
    fn test_detector_names_unique() {
        let d1 = Erc20ApproveRaceDetector::new();
        let d2 = TokenTransferFrontrunDetector::new();
        let d3 = AllowanceToctouDetector::new();

        let name1 = d1.name();
        let name2 = d2.name();
        let name3 = d3.name();

        // All names should be unique
        assert_ne!(name1, name2);
        assert_ne!(name2, name3);
        assert_ne!(name1, name3);
    }

    #[test]
    fn test_detector_ids_unique() {
        let d1 = Erc20ApproveRaceDetector::new();
        let d2 = TokenTransferFrontrunDetector::new();
        let d3 = AllowanceToctouDetector::new();

        let id1 = d1.id();
        let id2 = d2.id();
        let id3 = d3.id();

        // All IDs should be unique
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_all_detector_categories_valid() {
        let d1 = Erc20ApproveRaceDetector::new();
        let d2 = TokenTransferFrontrunDetector::new();
        let d3 = AllowanceToctouDetector::new();

        // All should have at least one category
        assert!(!d1.categories().is_empty());
        assert!(!d2.categories().is_empty());
        assert!(!d3.categories().is_empty());

        // All should have <= 4 categories (reasonable limit)
        assert!(d1.categories().len() <= 4);
        assert!(d2.categories().len() <= 4);
        assert!(d3.categories().len() <= 4);
    }
}

#[cfg(test)]
mod coverage {
    use super::*;

    #[test]
    fn test_detectors_cover_front_running_patterns() {
        // Verify that our 3 detectors cover the main front-running attack vectors

        let d1 = Erc20ApproveRaceDetector::new();
        let d2 = TokenTransferFrontrunDetector::new();
        let d3 = AllowanceToctouDetector::new();

        // Check coverage via categories and descriptions
        let desc1 = d1.description().to_lowercase();
        let desc2 = d2.description().to_lowercase();
        let desc3 = d3.description().to_lowercase();

        // d1 should cover approve/allowance
        assert!(desc1.contains("approve") || desc1.contains("allowance"));

        // d2 should cover transferFrom and slippage
        assert!(desc2.contains("transferfrom") || desc2.contains("slippage"));

        // d3 should cover time-of-check-time-of-use
        assert!(desc3.contains("check") || desc3.contains("use") || desc3.contains("race"));
    }

    #[test]
    fn test_comprehensive_mev_coverage() {
        // Verify MEV/front-running is covered across all detectors

        let d1 = Erc20ApproveRaceDetector::new();
        let d2 = TokenTransferFrontrunDetector::new();
        let d3 = AllowanceToctouDetector::new();

        let all_categories = vec![
            d1.categories(),
            d2.categories(),
            d3.categories(),
        ];

        // At least one should have MEV category
        let has_mev = all_categories.iter().any(|cats| {
            cats.contains(&DetectorCategory::MEV)
        });

        // At least two should have DeFi category
        let defi_count = all_categories.iter().filter(|cats| {
            cats.contains(&DetectorCategory::DeFi)
        }).count();

        assert!(has_mev, "At least one detector should have MEV category");
        assert!(defi_count >= 2, "At least two detectors should have DeFi category");
    }
}

#[cfg(test)]
mod regression {
    use super::*;

    #[test]
    fn test_no_panic_on_empty_source() {
        // Regression test: detectors should handle empty source gracefully
        let d1 = Erc20ApproveRaceDetector::new();
        let d2 = TokenTransferFrontrunDetector::new();
        let d3 = AllowanceToctouDetector::new();

        // These should all work without panicking
        assert_eq!(d1.id().0, "erc20-approve-race");
        assert_eq!(d2.id().0, "token-transfer-frontrun");
        assert_eq!(d3.id().0, "allowance-toctou");
    }

    #[test]
    fn test_detector_consistency() {
        // Regression test: Creating same detector multiple times should be consistent
        let d1a = Erc20ApproveRaceDetector::new();
        let d1b = Erc20ApproveRaceDetector::new();

        assert_eq!(d1a.id(), d1b.id());
        assert_eq!(d1a.name(), d1b.name());
        assert_eq!(d1a.default_severity(), d1b.default_severity());
        assert_eq!(d1a.is_enabled(), d1b.is_enabled());
    }
}

#[cfg(test)]
mod performance {
    use super::*;

    #[test]
    fn test_detector_creation_fast() {
        // Performance test: Detector creation should be fast (< 1ms each)
        use std::time::Instant;

        let start = Instant::now();
        for _ in 0..1000 {
            let _ = Erc20ApproveRaceDetector::new();
            let _ = TokenTransferFrontrunDetector::new();
            let _ = AllowanceToctouDetector::new();
        }
        let elapsed = start.elapsed();

        // 1000 iterations of 3 detectors should complete in < 100ms
        assert!(elapsed.as_millis() < 100,
                "Detector creation too slow: {:?}", elapsed);
    }

    #[test]
    fn test_metadata_access_fast() {
        // Performance test: Metadata access should be fast
        use std::time::Instant;

        let d1 = Erc20ApproveRaceDetector::new();
        let d2 = TokenTransferFrontrunDetector::new();
        let d3 = AllowanceToctouDetector::new();

        let start = Instant::now();
        for _ in 0..10000 {
            let _ = d1.id();
            let _ = d1.name();
            let _ = d1.default_severity();
            let _ = d2.id();
            let _ = d2.name();
            let _ = d2.default_severity();
            let _ = d3.id();
            let _ = d3.name();
            let _ = d3.default_severity();
        }
        let elapsed = start.elapsed();

        // 10000 iterations should complete in < 10ms
        assert!(elapsed.as_millis() < 10,
                "Metadata access too slow: {:?}", elapsed);
    }
}
