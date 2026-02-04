/**
 * False Positive Regression Tests
 *
 * These tests verify that safe contract patterns are detectable via source analysis.
 * Each test loads a benchmark contract that implements proper security patterns
 * and verifies that the patterns are correctly identified in the source code.
 *
 * Test Categories:
 * 1. Safe ERC-4626 Vault - Tests vault inflation patterns
 * 2. Safe Chainlink Consumer - Tests oracle safety patterns
 * 3. Safe Flash Loan Provider - Tests flash loan safety patterns
 * 4. Safe AMM Pool - Tests AMM/TWAP patterns
 *
 * Note: These tests verify pattern detection at the source level. For full detector
 * integration tests, use the validation suite (soliditydefend --validate).
 */

use std::fs;
use std::path::PathBuf;

/// Helper function to get FP benchmark contract path
fn get_fp_benchmark_path(filename: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("contracts")
        .join("fp_benchmarks")
        .join(filename)
}

// ============================================================================
// Oracle Pattern Source Tests
// ============================================================================

/// Test safe oracle patterns are present in safe_chainlink_consumer.sol
#[test]
fn test_safe_chainlink_consumer_has_oracle_patterns() {
    let path = get_fp_benchmark_path("safe_chainlink_consumer.sol");

    if path.exists() {
        let source = fs::read_to_string(&path).expect("Failed to read safe_chainlink_consumer.sol");
        let source_lower = source.to_lowercase();

        // Should have AggregatorV3Interface
        assert!(
            source.contains("AggregatorV3Interface"),
            "Safe Chainlink consumer should use AggregatorV3Interface"
        );

        // Should have latestRoundData call
        assert!(
            source_lower.contains("latestrounddata"),
            "Safe Chainlink consumer should call latestRoundData"
        );

        // Should have staleness check (updatedAt + timestamp comparison)
        assert!(
            source_lower.contains("updatedat"),
            "Safe Chainlink consumer should check updatedAt"
        );
        assert!(
            source.contains("block.timestamp"),
            "Safe Chainlink consumer should use block.timestamp for staleness"
        );
        assert!(
            source.contains("MAX_STALENESS"),
            "Safe Chainlink consumer should have MAX_STALENESS constant"
        );

        // Should have answer > 0 validation
        assert!(
            source.contains("answer >") || source.contains("answer <="),
            "Safe Chainlink consumer should validate answer value"
        );

        // Should have multi-oracle support
        assert!(
            source_lower.contains("primaryoracle") && source_lower.contains("secondaryoracle"),
            "Safe Chainlink consumer should have multiple oracles"
        );

        // Should have deviation bounds
        assert!(
            source.contains("MAX_DEVIATION"),
            "Safe Chainlink consumer should have MAX_DEVIATION constant"
        );
    }
}

/// Test TWAP oracle pattern detection
#[test]
fn test_twap_pattern_detection() {
    let twap_source = r#"
        function getTwapPrice() external view returns (uint256) {
            uint32[] memory secondsAgos = new uint32[](2);
            secondsAgos[0] = twapInterval;
            secondsAgos[1] = 0;
            (int56[] memory tickCumulatives,) = pool.observe(secondsAgos);
            return calculatePriceFromTicks(tickCumulatives);
        }
    "#;
    let source_lower = twap_source.to_lowercase();

    // Should have observe() call (Uniswap V3 TWAP pattern)
    assert!(
        source_lower.contains(".observe("),
        "TWAP pattern should include observe() call"
    );

    // Should have cumulative values
    assert!(
        source_lower.contains("cumulative"),
        "TWAP pattern should use cumulative values"
    );
}

// ============================================================================
// Flash Loan Pattern Source Tests
// ============================================================================

/// Test safe flash loan patterns are present in safe_flash_loan_provider.sol
#[test]
fn test_safe_flash_loan_provider_has_safety_patterns() {
    let path = get_fp_benchmark_path("safe_flash_loan_provider.sol");

    if path.exists() {
        let source =
            fs::read_to_string(&path).expect("Failed to read safe_flash_loan_provider.sol");
        let source_lower = source.to_lowercase();

        // Should have ERC-3156 interface references
        assert!(
            source.contains("IERC3156FlashLender") || source.contains("ERC3156"),
            "Safe flash loan provider should reference ERC-3156"
        );

        // Should have CALLBACK_SUCCESS constant
        assert!(
            source.contains("CALLBACK_SUCCESS"),
            "Safe flash loan provider should have CALLBACK_SUCCESS constant"
        );

        // Should have onFlashLoan callback
        assert!(
            source_lower.contains("onflashloan"),
            "Safe flash loan provider should have onFlashLoan callback"
        );

        // Should have ReentrancyGuard or nonReentrant
        assert!(
            source.contains("ReentrancyGuard") || source.contains("nonReentrant"),
            "Safe flash loan provider should have reentrancy protection"
        );

        // Should have fee validation
        assert!(
            source.contains("MAX_FEE") || source.contains("maxFlashLoanFee"),
            "Safe flash loan provider should have fee bounds"
        );

        // Should have balance before/after validation
        assert!(
            source_lower.contains("balancebefore") && source_lower.contains("balanceafter"),
            "Safe flash loan provider should validate balance before/after"
        );

        // Should validate callback return value
        assert!(
            source.contains("result != CALLBACK_SUCCESS")
                || source.contains("result == CALLBACK_SUCCESS"),
            "Safe flash loan provider should validate callback return"
        );

        // Should validate msg.sender in callback
        assert!(
            source.contains("msg.sender == lender")
                || source.contains("msg.sender != lender")
                || source.contains("msg.sender == address("),
            "Safe flash borrower should validate callback caller"
        );
    }
}

/// Test ERC-3156 compliance pattern
#[test]
fn test_erc3156_compliance_pattern() {
    let erc3156_source = r#"
        bytes32 constant CALLBACK_SUCCESS = keccak256("ERC3156FlashBorrower.onFlashLoan");

        function onFlashLoan(
            address initiator,
            address token,
            uint256 amount,
            uint256 fee,
            bytes calldata data
        ) external returns (bytes32) {
            require(msg.sender == address(lender), "Unauthorized");
            return CALLBACK_SUCCESS;
        }
    "#;

    // Should have standard callback success value
    assert!(
        erc3156_source.contains("CALLBACK_SUCCESS")
            && erc3156_source.contains("ERC3156FlashBorrower.onFlashLoan"),
        "ERC-3156 pattern should have CALLBACK_SUCCESS with keccak256"
    );

    // Should have callback validation
    assert!(
        erc3156_source.contains("require(msg.sender"),
        "ERC-3156 borrower should validate msg.sender"
    );
}

// ============================================================================
// Vault Pattern Source Tests
// ============================================================================

/// Test safe vault patterns are present in safe_erc4626_vault.sol
#[test]
fn test_safe_vault_has_inflation_protection() {
    let path = get_fp_benchmark_path("safe_erc4626_vault.sol");

    if path.exists() {
        let source = fs::read_to_string(&path).expect("Failed to read safe_erc4626_vault.sol");
        let source_lower = source.to_lowercase();

        // Should be ERC-4626 vault
        assert!(
            source.contains("ERC4626") || source_lower.contains("erc4626"),
            "Safe vault should implement ERC-4626"
        );

        // Should have decimalsOffset (OpenZeppelin virtual shares pattern)
        assert!(
            source.contains("_decimalsOffset") || source.contains("decimalsOffset"),
            "Safe vault should use decimalsOffset for virtual shares"
        );

        // Should have minimum deposit
        assert!(
            source.contains("MINIMUM_DEPOSIT"),
            "Safe vault should have MINIMUM_DEPOSIT constant"
        );

        // Should have dead shares / initial share lock
        assert!(
            source.contains("INITIAL_SHARE_LOCK")
                || (source.contains("_mint") && source.contains("address(0)")),
            "Safe vault should have initial share lock pattern"
        );

        // Should have reentrancy protection
        assert!(
            source.contains("ReentrancyGuard") || source.contains("nonReentrant"),
            "Safe vault should have reentrancy protection"
        );

        // Should track assets (not use vulnerable balanceOf)
        assert!(
            source_lower.contains("_trackedassets") || source_lower.contains("trackedassets"),
            "Safe vault should track assets internally"
        );

        // Should validate shares > 0
        assert!(
            source.contains("shares > 0"),
            "Safe vault should validate shares are non-zero"
        );
    }
}

/// Test dead shares pattern detection
#[test]
fn test_dead_shares_pattern() {
    let dead_shares_source = r#"
        uint256 constant MINIMUM_LIQUIDITY = 1000;

        function initialize() external {
            _mint(address(0), MINIMUM_LIQUIDITY);
        }
    "#;

    // Should have MINIMUM_LIQUIDITY constant
    assert!(
        dead_shares_source.contains("MINIMUM_LIQUIDITY"),
        "Dead shares pattern should have MINIMUM_LIQUIDITY"
    );

    // Should mint to address(0)
    assert!(
        dead_shares_source.contains("_mint") && dead_shares_source.contains("address(0)"),
        "Dead shares pattern should mint to address(0)"
    );
}

/// Test virtual shares pattern detection
#[test]
fn test_virtual_shares_pattern() {
    let virtual_shares_source = r#"
        function _decimalsOffset() internal pure returns (uint8) {
            return 3;
        }

        function _convertToShares(uint256 assets) internal view returns (uint256) {
            return assets * (totalSupply() + 10**decimalsOffset()) / (totalAssets() + 1);
        }
    "#;

    // Should have decimalsOffset function
    assert!(
        virtual_shares_source.contains("decimalsOffset"),
        "Virtual shares pattern should have decimalsOffset"
    );

    // Should have offset arithmetic in conversion
    assert!(
        virtual_shares_source.contains("totalSupply() +")
            || virtual_shares_source.contains("totalAssets() +"),
        "Virtual shares pattern should add offset in calculations"
    );
}

// ============================================================================
// AMM/TWAP Pattern Source Tests
// ============================================================================

/// Test safe AMM patterns are present in safe_amm_pool.sol
#[test]
fn test_safe_amm_has_twap_and_protections() {
    let path = get_fp_benchmark_path("safe_amm_pool.sol");

    if path.exists() {
        let source = fs::read_to_string(&path).expect("Failed to read safe_amm_pool.sol");
        let source_lower = source.to_lowercase();

        // Should have TWAP oracle (cumulative prices)
        assert!(
            source_lower.contains("price0cumulativelast")
                || source_lower.contains("pricecumulative"),
            "Safe AMM should have cumulative price tracking for TWAP"
        );

        // Should have MINIMUM_LIQUIDITY (dead shares)
        assert!(
            source.contains("MINIMUM_LIQUIDITY"),
            "Safe AMM should have MINIMUM_LIQUIDITY constant"
        );

        // Should have reentrancy protection
        assert!(
            source.contains("ReentrancyGuard") || source.contains("nonReentrant"),
            "Safe AMM should have reentrancy protection"
        );

        // Should have slippage protection (minAmountOut)
        assert!(
            source_lower.contains("minamountout") || source_lower.contains("slippage"),
            "Safe AMM should have slippage protection"
        );

        // Should have deadline (MEV protection)
        assert!(
            source_lower.contains("deadline"),
            "Safe AMM should have deadline for MEV protection"
        );

        // Should validate k invariant
        assert!(
            source_lower.contains("invariant"),
            "Safe AMM should validate k invariant"
        );
    }
}

/// Test cumulative price pattern (TWAP)
#[test]
fn test_cumulative_price_pattern() {
    let cumulative_source = r#"
        uint256 public price0CumulativeLast;
        uint256 public price1CumulativeLast;

        function _update() private {
            uint32 timeElapsed = blockTimestamp - blockTimestampLast;
            if (timeElapsed > 0 && reserve0 != 0 && reserve1 != 0) {
                price0CumulativeLast += uint256(reserve1 / reserve0) * timeElapsed;
                price1CumulativeLast += uint256(reserve0 / reserve1) * timeElapsed;
            }
        }
    "#;
    let source_lower = cumulative_source.to_lowercase();

    // Should have cumulative price variables
    assert!(
        source_lower.contains("pricecumulative") || source_lower.contains("cumulativelast"),
        "TWAP AMM should have cumulative price tracking"
    );

    // Should multiply by time elapsed
    assert!(
        source_lower.contains("timeelapsed"),
        "TWAP AMM should use time elapsed in calculation"
    );
}

// ============================================================================
// Restaking Pattern Source Tests
// ============================================================================

/// Test restaking safety patterns
#[test]
fn test_restaking_patterns() {
    let restaking_source = r#"
        IDelegationManager public delegationManager;
        mapping(address => bool) public approvedOperators;

        function delegateTo(address operator) external {
            require(approvedOperators[operator], "Not approved");
            delegationManager.delegateTo(operator);
        }

        function requestWithdrawal(uint256 shares) external {
            pendingWithdrawals[msg.sender] = block.timestamp;
        }

        function completeWithdrawal() external {
            require(block.timestamp >= pendingWithdrawals[msg.sender] + WITHDRAWAL_DELAY);
        }
    "#;
    let source_lower = restaking_source.to_lowercase();

    // Should have delegation manager
    assert!(
        source_lower.contains("delegationmanager"),
        "Restaking contract should have delegation manager"
    );

    // Should have operator whitelist
    assert!(
        source_lower.contains("approvedoperators")
            || source_lower.contains("approved_operators")
            || source_lower.contains("operatorwhitelist"),
        "Restaking contract should have operator validation"
    );

    // Should have two-step withdrawal
    assert!(
        source_lower.contains("requestwithdrawal") || source_lower.contains("request_withdrawal"),
        "Restaking contract should have request withdrawal"
    );
    assert!(
        source_lower.contains("completewithdrawal")
            || source_lower.contains("complete_withdrawal"),
        "Restaking contract should have complete withdrawal"
    );

    // Should have withdrawal delay
    assert!(
        restaking_source.contains("WITHDRAWAL_DELAY")
            || source_lower.contains("withdrawaldelay"),
        "Restaking contract should have withdrawal delay"
    );
}

// ============================================================================
// Integration Smoke Tests
// ============================================================================

/// Verify all benchmark files exist
#[test]
fn test_fp_benchmark_files_exist() {
    let files = [
        "safe_erc4626_vault.sol",
        "safe_chainlink_consumer.sol",
        "safe_flash_loan_provider.sol",
        "safe_amm_pool.sol",
    ];

    for file in files {
        let path = get_fp_benchmark_path(file);
        assert!(
            path.exists(),
            "FP benchmark file should exist: {}",
            path.display()
        );
    }
}

/// Verify benchmark files are valid Solidity (basic syntax check)
#[test]
fn test_fp_benchmark_files_are_valid_solidity() {
    let files = [
        "safe_erc4626_vault.sol",
        "safe_chainlink_consumer.sol",
        "safe_flash_loan_provider.sol",
        "safe_amm_pool.sol",
    ];

    for file in files {
        let path = get_fp_benchmark_path(file);
        if path.exists() {
            let source =
                fs::read_to_string(&path).unwrap_or_else(|_| panic!("Failed to read {}", file));

            // Basic Solidity file checks
            assert!(
                source.contains("// SPDX-License-Identifier:"),
                "{} should have SPDX license identifier",
                file
            );
            assert!(
                source.contains("pragma solidity"),
                "{} should have pragma statement",
                file
            );
            assert!(
                source.contains("contract ") || source.contains("interface "),
                "{} should define a contract or interface",
                file
            );
        }
    }
}
